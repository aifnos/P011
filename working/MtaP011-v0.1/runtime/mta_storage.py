# -*- coding: utf-8 -*-
"""Confined, bounded ZIP receive storage; no archive extract/extractall calls.

Only explicitly supplied existing user directories are allowed. Each receive
uses a new private result directory. Individual files appear atomically; the
result is reported only after all entries and CRCs have been checked. A failed
or cancelled receive removes only directories this object created.
"""
import os
import re
import shutil
import stat
import struct
import tempfile
import zipfile

from mta_protocol import validate_task_id

MAX_FILES = 256
MAX_TOTAL_BYTES = 512 * 1024 * 1024
MAX_FILE_BYTES = 256 * 1024 * 1024
RESERVE_BYTES = 16 * 1024 * 1024
CHUNK_BYTES = 65536
_RESERVED = re.compile(r"^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)", re.I)


class StorageError(ValueError):
    pass


class TransferCancelled(StorageError):
    pass


def _positive_limit(value, label, allow_zero=False):
    if isinstance(value, bool) or not isinstance(value, int) or value < (0 if allow_zero else 1):
        raise StorageError("invalid " + label)
    return value


def _check_no_symlinks(path):
    cursor = os.path.abspath(path)
    while True:
        if os.path.islink(cursor):
            raise StorageError("symbolic links are not permitted")
        if os.name == "nt" and os.path.lexists(cursor):
            attributes = getattr(os.lstat(cursor), "st_file_attributes", 0)
            if attributes & 0x400:  # FILE_ATTRIBUTE_REPARSE_POINT, including junctions
                raise StorageError("reparse paths are not permitted")
        parent = os.path.dirname(cursor)
        if parent == cursor:
            break
        cursor = parent


def validate_member_name(name):
    if not isinstance(name, str) or not name or len(name.encode("utf-8")) > 1024:
        raise StorageError("invalid ZIP member name")
    if "\\" in name or name.startswith("/") or "\x00" in name:
        raise StorageError("unsafe ZIP path")
    parts = name.rstrip("/").split("/")
    if not parts or len(parts) > 16:
        raise StorageError("ZIP path depth limit")
    for part in parts:
        if (not part or part in (".", "..") or len(part.encode("utf-8")) > 240 or
                part[-1:] in (".", " ") or _RESERVED.match(part) or
                any(ord(char) < 32 or char in ':<>"|?*' for char in part)):
            raise StorageError("unsafe ZIP path")
    return parts


def free_bytes(root):
    # shutil.disk_usage is available in Python 3.5 and works on Windows/Linux.
    return shutil.disk_usage(root).free


class SafeZipReceiver(object):
    def __init__(self, root, max_files=MAX_FILES, max_total_bytes=MAX_TOTAL_BYTES,
                 max_file_bytes=MAX_FILE_BYTES, reserve_bytes=RESERVE_BYTES,
                 free_space=None):
        if not isinstance(root, str) or not os.path.isabs(root):
            raise StorageError("an explicit absolute user root is required")
        root = os.path.abspath(root)
        if not os.path.isdir(root):
            raise StorageError("user root must already exist")
        # A filesystem root, home root, or system directory is not an incoming
        # user directory. This includes Windows drive roots.
        if os.path.dirname(root) == root:
            raise StorageError("filesystem root is not a receive directory")
        if root == os.path.abspath(os.path.expanduser("~")):
            raise StorageError("home root is not a receive directory")
        if os.name != "nt" and root in ("/usr", "/etc", "/var", "/bin", "/sbin", "/root", "/tmp", "/home"):
            raise StorageError("system root is not a receive directory")
        _check_no_symlinks(root)
        self.root = root
        self.max_files = _positive_limit(max_files, "file count limit")
        self.max_total_bytes = _positive_limit(max_total_bytes, "total byte limit", True)
        self.max_file_bytes = _positive_limit(max_file_bytes, "file byte limit", True)
        self.reserve_bytes = _positive_limit(reserve_bytes, "reserve bytes", True)
        self._free_space = free_space or free_bytes

    def _cancel(self, cancelled):
        if cancelled is not None and cancelled():
            raise TransferCancelled("receive cancelled")

    def _space(self, needed):
        if self._free_space(self.root) < needed + self.reserve_bytes:
            raise StorageError("insufficient free space")

    def _validate_infos(self, infos):
        if len(infos) > self.max_files * 4 + 32:
            raise StorageError("ZIP entry count limit")
        files = []
        declared_size = 0
        names = set()
        files_seen = set()
        directories_seen = set()
        prefix_spellings = {}
        for info in infos:
            parts = validate_member_name(info.filename)
            normalized = "/".join(parts).casefold()
            for index in range(1, len(parts) + 1):
                spelling = "/".join(parts[:index])
                folded = spelling.casefold()
                if folded in prefix_spellings and prefix_spellings[folded] != spelling:
                    raise StorageError("case-colliding ZIP path component")
                prefix_spellings[folded] = spelling
            if normalized in names:
                raise StorageError("duplicate or case-colliding ZIP member")
            names.add(normalized)
            mode = (info.external_attr >> 16) & 0xffff
            kind = stat.S_IFMT(mode)
            is_directory = info.filename.endswith("/")
            if kind not in (0, stat.S_IFREG, stat.S_IFDIR):
                raise StorageError("ZIP links and special files are not permitted")
            if kind == stat.S_IFDIR and not is_directory:
                raise StorageError("inconsistent ZIP directory")
            if kind == stat.S_IFREG and is_directory:
                raise StorageError("inconsistent ZIP file")
            if info.flag_bits & 1:
                raise StorageError("encrypted ZIP entries are not supported")
            if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                raise StorageError("unsupported ZIP compression")
            if info.file_size < 0 or info.file_size > self.max_file_bytes:
                raise StorageError("ZIP file size limit")
            if is_directory:
                if info.file_size != 0:
                    raise StorageError("ZIP directory has data")
                directories_seen.add(normalized)
                continue
            files_seen.add(normalized)
            files.append((info, parts))
            declared_size += info.file_size
            if len(files) > self.max_files or declared_size > self.max_total_bytes:
                raise StorageError("ZIP receive limit")
        for name in names:
            bits = name.split("/")
            for index in range(1, len(bits)):
                if "/".join(bits[:index]) in files_seen:
                    raise StorageError("ZIP file/directory collision")
        if files_seen.intersection(directories_seen) or not files:
            raise StorageError("ZIP has no safe files")
        return files, declared_size

    def _check_zip_directory(self, zip_path):
        # ZipFile eagerly materializes the central directory. Bound its size
        # and entry count *before* that allocation to avoid metadata-only DoS.
        with open(zip_path, "rb") as source:
            source.seek(0, 2)
            size = source.tell()
            source.seek(max(0, size - 65557))
            tail = source.read(65557)
        position = tail.rfind(b"PK\x05\x06")
        if position < 0 or position + 22 > len(tail):
            raise StorageError("missing ZIP end record")
        values = struct.unpack("<4s4H2LH", tail[position:position + 22])
        signature, disk, start_disk, disk_entries, entries, directory_size, offset, comment = values
        if position + 22 + comment != len(tail):
            raise StorageError("invalid ZIP end record")
        if disk != 0 or start_disk != 0 or disk_entries != entries or entries == 65535 or offset == 4294967295:
            raise StorageError("multi-disk and ZIP64 archives are not supported")
        entry_limit = self.max_files * 4 + 32
        if entries > entry_limit or directory_size > entry_limit * 4096:
            raise StorageError("ZIP directory metadata limit")
        if offset + directory_size > size - (len(tail) - position):
            raise StorageError("invalid ZIP directory offset")

    def receive(self, zip_path, task_id, cancelled=None, progress=None,
                expected_files=None, expected_bytes=None):
        """Return verified files/bytes, never a success based on request metadata.

        progress receives actual extracted byte count and declared total.
        The ZIP remains owned by the caller; this method never deletes it.
        """
        validate_task_id(task_id)
        if not isinstance(zip_path, str) or not os.path.isabs(zip_path):
            raise StorageError("an absolute ZIP path is required")
        _check_no_symlinks(zip_path)
        if not os.path.isfile(zip_path):
            raise StorageError("ZIP input is not a regular file")
        if os.path.getsize(zip_path) > self.max_total_bytes + 1024 * 1024:
            raise StorageError("ZIP input byte limit")
        if expected_files is not None:
            _positive_limit(expected_files, "expected files")
        if expected_bytes is not None:
            _positive_limit(expected_bytes, "expected bytes", True)
        _check_no_symlinks(self.root)
        self._cancel(cancelled)
        self._check_zip_directory(zip_path)
        staging = None
        result_dir = None
        try:
            with zipfile.ZipFile(zip_path, "r") as archive:
                files, declared = self._validate_infos(archive.infolist())
                if expected_files is not None and expected_files != len(files):
                    raise StorageError("ZIP count differs from confirmed request")
                if expected_bytes is not None and expected_bytes != declared:
                    raise StorageError("ZIP size differs from confirmed request")
                self._space(declared)
                staging = tempfile.mkdtemp(prefix=".mta-stage-", dir=self.root)
                os.chmod(staging, 0o700)
                actual_total = 0
                relative_paths = []
                for info, parts in files:
                    self._cancel(cancelled)
                    self._space(info.file_size)
                    directory = os.path.join(staging, *parts[:-1]) if len(parts) > 1 else staging
                    if not os.path.isdir(directory):
                        os.makedirs(directory, 0o700)
                    output = os.path.join(directory, parts[-1])
                    # Exclusive creation. ZIP permissions are never preserved.
                    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    file_total = 0
                    with os.fdopen(fd, "wb") as target:
                        with archive.open(info, "r") as source:
                            while True:
                                self._cancel(cancelled)
                                chunk = source.read(CHUNK_BYTES)
                                if not chunk:
                                    break
                                file_total += len(chunk)
                                actual_total += len(chunk)
                                if (file_total > info.file_size or file_total > self.max_file_bytes or
                                        actual_total > declared or actual_total > self.max_total_bytes):
                                    raise StorageError("actual extracted byte limit")
                                self._space(len(chunk))
                                target.write(chunk)
                                if progress is not None:
                                    progress(actual_total, declared)
                        target.flush()
                        os.fsync(target.fileno())
                    if file_total != info.file_size:
                        raise StorageError("actual ZIP member size mismatch")
                    relative_paths.append(os.path.join(*parts))
                if actual_total != declared:
                    raise StorageError("actual ZIP total mismatch")
                self._cancel(cancelled)
                _check_no_symlinks(self.root)
                # mkdtemp reserves an entirely new private result namespace.
                # Atomic file renames go only into this owned namespace, never
                # into an existing user directory with potentially equal names.
                result_dir = tempfile.mkdtemp(prefix="received-", dir=self.root)
                os.chmod(result_dir, 0o700)
                committed = []
                for relative in relative_paths:
                    self._cancel(cancelled)
                    target = os.path.join(result_dir, relative)
                    directory = os.path.dirname(target)
                    if not os.path.isdir(directory):
                        os.makedirs(directory, 0o700)
                    if os.path.lexists(target):
                        raise StorageError("result collision")
                    os.rename(os.path.join(staging, relative), target)
                    committed.append(target)
                # Report only after every file/CRC passed. Empty directories
                # have no content and are intentionally not published.
                self._cancel(cancelled)
                shutil.rmtree(staging)
                staging = None
                result = {"taskId": task_id, "directory": result_dir,
                          "files": committed, "fileCount": len(committed), "totalSize": actual_total}
                result_dir = None  # ownership is now handed to the caller
                return result
        except (zipfile.BadZipFile, zipfile.LargeZipFile, EOFError, RuntimeError) as error:
            raise StorageError("invalid or unsupported ZIP")
        finally:
            for owned in (staging, result_dir):
                if owned is not None:
                    # Only our exact generated directory is removed, never root
                    # or a path derived from an archive member/taskId.
                    shutil.rmtree(owned)
