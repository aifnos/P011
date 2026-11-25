# -*- coding: utf-8 -*-
"""Confined, bounded ZIP receive storage; no archive extract/extractall calls.

Only explicitly supplied existing user directories are allowed. Each receive
uses a new private result directory. Individual files appear atomically; the
result is reported only after all entries and CRCs have been checked. A failed
or cancelled receive removes only directories this object created. POSIX path
syscalls use explicit UTF-8 bytes; public paths remain strictly decoded str.

receive-directory-fd-v1 adds an optional mechanical held-directory lane on
POSIX. It is not a target UID, network, RF, or restore admission. The original
unbound Windows/path behavior remains separate. Bound cleanup never traverses
or recursively deletes a pathname tree; only original created entries qualify.
"""
import errno
import math
import os
import re
import shutil
import stat
import struct
import tempfile
import time
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


def native_name(value):
    """Encode valid public names explicitly; never depend on a POSIX locale."""
    return value.encode('utf-8') if os.name == 'posix' and isinstance(value, str) else value


def _public_name(value):
    """Strictly decode native bytes without publishing surrogate names."""
    return value.decode('utf-8') if isinstance(value, bytes) else value


def _check_no_symlinks(path):
    cursor = os.path.abspath(native_name(path))
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
    return shutil.disk_usage(native_name(root)).free


class SafeZipReceiver(object):
    def __init__(self, root, max_files=MAX_FILES, max_total_bytes=MAX_TOTAL_BYTES,
                 max_file_bytes=MAX_FILE_BYTES, reserve_bytes=RESERVE_BYTES,
                 free_space=None, directory_binding=None):
        if not isinstance(root, str) or not os.path.isabs(root):
            raise StorageError("an explicit absolute user root is required")
        root = os.path.abspath(root)
        if not os.path.isdir(native_name(root)):
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
        self.directory_binding = directory_binding
        self._binding_original = directory_binding
        self._bound_rows, self._bound_entries, self._bound_cleanup_errors = [], [], []
        self._bound_started = self._bound_complete = self._bound_close_called = False
        self._bound_failure, self._root_fd = None, None
        self._durable_result = None
        if directory_binding is not None:
            if type(directory_binding) is not DirectoryBinding or directory_binding.root != self.root:
                raise StorageError("an original same-root DirectoryBinding is required")
            self._root_fd = directory_binding.fd()


    def _binding_current(self, cancelled=None):
        if (type(self.directory_binding) is not DirectoryBinding or
                self.directory_binding is not self._binding_original or
                self.root != self.directory_binding.root):
            raise StorageError("original receive directory binding changed")
        self._cancel(cancelled)
        self.directory_binding.check()
        if self.directory_binding.fd() != self._root_fd:
            raise StorageError("original receive directory descriptor changed")
        # Every still-live owned directory is checked both by FD and by its
        # parent/name. This rejects renamed or symlink-substituted staging.
        for entry in self._bound_entries:
            if (entry['kind'] == 'file' and entry['created'] and not entry['removed'] and
                    _identity(os.stat(entry['name'], dir_fd=entry['parent'],
                                      follow_symlinks=False)) != entry['identity']):
                raise StorageError("owned receive file replaced")
            if entry['kind'] == 'directory' and entry['created'] and not entry['removed']:
                row = entry['row']
                if (row['closed'] or row['unknown'] or
                        _identity(os.fstat(row['fd_original'])) != entry['identity'] or
                        _identity(os.stat(entry['name'], dir_fd=entry['parent'],
                                          follow_symlinks=False)) != entry['identity']):
                    raise StorageError("owned receive directory replaced")
        return self._root_fd

    def durable_result(self):
        """Historical durable publication, not success/closure/peer authority.

        Only the bound lane records this after actual CRC, directory binding
        and fsync checks. A fresh plain copy cannot renew a cap or imply that
        the directory is currently intact. Late failure/cancel remains failure.
        """
        value = self._durable_result
        if value is None:
            return None
        task, directory, files, count, size = value
        return dict(taskId=task, directory=directory, files=list(files),
                    fileCount=count, totalSize=size, peer_ack_verified=False)

    def _bound_space(self, needed):
        fd = self._binding_current()
        if self._free_space is free_bytes:
            observed = os.fstatvfs(fd)
            available = observed.f_bavail * observed.f_frsize
        else:
            # Explicit HOST/application quota callback, never a directory grant.
            available = self._free_space(self.root)
            self._binding_current()
        if available < needed + self.reserve_bytes:
            raise StorageError("insufficient free space")

    def _new_bound_entry(self, parent, name, kind):
        entry = dict(parent=parent, name=name, kind=kind, created=False,
                     identity=None, row=None, removed=False, remove_called=False,
                     remove_error=None, published=False, creation_called=False,
                     creation_returned=False, creation_unknown=False)
        self._bound_entries.append(entry)  # Before each mutating factory.
        return entry

    def _bound_directory(self, parent, name):
        self._binding_current()
        entry = self._new_bound_entry(parent, name, 'directory')
        entry['creation_called'] = entry['creation_unknown'] = True
        try:
            os.mkdir(name, 0o700, dir_fd=parent)
        except OSError as error:
            if type(error.errno) is int and 1 <= error.errno <= 4095:
                entry['creation_unknown'] = False
            raise  # No existing-name adoption.
        entry['creation_returned'] = entry['created'] = True
        entry['creation_unknown'] = False
        # Keep observed inode before open; keep returned FD before later checks.
        entry['identity'] = _identity(os.stat(name, dir_fd=parent, follow_symlinks=False))
        row = _fd_row('owned_directory')
        entry['row'] = row
        self._bound_rows.append(row)
        row['called'], row['closed'], row['unknown'] = True, False, True
        value = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                        getattr(os, 'O_CLOEXEC', 0), dir_fd=parent)
        row['fd'] = row['fd_original'] = value
        row['returned'] = True
        row['identity'] = _identity(os.fstat(value))
        if (row['identity'] != entry['identity'] or not stat.S_ISDIR(row['identity'][2]) or
                stat.S_IMODE(row['identity'][2]) != 0o700):
            raise StorageError("new private directory identity differs")
        os.set_inheritable(value, False)
        if os.get_inheritable(value):
            raise StorageError("owned directory descriptor is inheritable")
        row['unknown'] = False
        self._binding_current()
        return entry

    def _bound_tree(self, root_entry, parts):
        parent = root_entry
        for part in parts:
            name = native_name(part)
            found = [value for value in self._bound_entries
                     if value['kind'] == 'directory' and value['parent'] == parent['row']['fd_original']
                     and value['name'] == name and value['created'] and not value['removed']]
            if found:
                if len(found) != 1:
                    raise StorageError("ambiguous owned directory")
                parent = found[0]
                self._binding_current()
            else:
                parent = self._bound_directory(parent['row']['fd_original'], name)
        return parent

    def _bound_output(self, directory, name):
        self._binding_current()
        parent = directory['row']['fd_original']
        entry = self._new_bound_entry(parent, name, 'file')
        row = _fd_row('owned_file')
        entry['row'] = row
        self._bound_rows.append(row)
        entry['creation_called'] = entry['creation_unknown'] = True
        row['called'], row['closed'], row['unknown'] = True, False, True
        try:
            value = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW |
                            getattr(os, 'O_CLOEXEC', 0), 0o600, dir_fd=parent)
        except OSError as error:
            if type(error.errno) is int and 1 <= error.errno <= 4095:
                row['closed'], row['unknown'] = True, False
                entry['creation_unknown'] = False
            raise
        row['fd'] = row['fd_original'] = value
        row['returned'] = True
        entry['creation_returned'] = entry['created'] = True
        entry['creation_unknown'] = False
        row['identity'] = entry['identity'] = _identity(os.fstat(value))
        if not stat.S_ISREG(row['identity'][2]) or stat.S_IMODE(row['identity'][2]) != 0o600:
            raise StorageError("new private file identity differs")
        os.set_inheritable(value, False)
        if os.get_inheritable(value):
            raise StorageError("owned file descriptor is inheritable")
        row['unknown'] = False
        self._binding_current()
        return entry

    def _bound_remove(self, entry):
        if not entry['created'] or entry['removed'] or entry['published']:
            return True
        if entry['remove_called'] or entry['identity'] is None:
            return False
        entry['remove_called'] = True
        try:
            # Cleanup does not renew or depend on active cap. It only operates
            # on the still-held original parent, never an absolute path tree.
            expected_parent = (self.directory_binding.rows[-1]['identity']
                               if entry['parent'] == self._root_fd else
                               next(value['identity'] for value in self._bound_rows
                                    if value['fd_original'] == entry['parent'] and
                                    not value['closed'] and not value['unknown']))
            if _identity(os.fstat(entry['parent'])) != expected_parent:
                raise StorageError("cleanup original parent changed")
            if _identity(os.stat(entry['name'], dir_fd=entry['parent'],
                                  follow_symlinks=False)) != entry['identity']:
                raise StorageError("cleanup owned entry changed")
            if entry['kind'] == 'directory':
                os.rmdir(entry['name'], dir_fd=entry['parent'])
            else:
                os.unlink(entry['name'], dir_fd=entry['parent'])
            entry['removed'] = True
            return True
        except BaseException as error:
            entry['remove_error'] = error
            self._bound_cleanup_errors.append(error)
            return False

    def _bound_cleanup(self):
        good = True
        for entry in reversed(self._bound_entries):
            if not self._bound_remove(entry):
                good = False
        for row in reversed(self._bound_rows):
            if not _close_original(row):
                good = False
                if row['close_error'] is not None:
                    self._bound_cleanup_errors.append(row['close_error'])
        return good

    def _check_zip_handle(self, source):
        # Same original handle for bounded EOCD parsing and ZipFile.
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
        source.seek(0)
        return size

    def _receive_bound(self, zip_path, task_id, cancelled, progress,
                       expected_files, expected_bytes, archive_resource):
        if self._bound_started:
            raise StorageError("bound receiver already used")
        self._bound_started = True
        owned_archive = None
        archive_row = None
        try:
            validate_task_id(task_id)
            self._binding_current(cancelled)
            if expected_files is not None:
                _positive_limit(expected_files, "expected files")
            if expected_bytes is not None:
                _positive_limit(expected_bytes, "expected bytes", True)
            if archive_resource is not None:
                if (type(archive_resource) is not DownloadFile or
                        archive_resource.binding is not self.directory_binding or
                        zip_path != archive_resource.path):
                    raise StorageError("foreign original archive resource")
                self.directory_binding.download_current(archive_resource)
                source = archive_resource.handle  # Borrow, never close here.
                archive_row = archive_resource.row
                source.flush()
            else:
                owned_archive = self.directory_binding.open_archive(zip_path)
                source = owned_archive.handle
                archive_row = owned_archive.row
            before = _file_signature(os.fstat(archive_row['fd_original']))
            if before[6] > self.max_total_bytes + 1024 * 1024:
                raise StorageError("ZIP input byte limit")
            self._binding_current(cancelled)
            self._check_zip_handle(source)
            self._binding_current(cancelled)
            with zipfile.ZipFile(source, 'r') as archive:
                files, declared = self._validate_infos(archive.infolist())
                if expected_files is not None and expected_files != len(files):
                    raise StorageError("ZIP count differs from confirmed request")
                if expected_bytes is not None and expected_bytes != declared:
                    raise StorageError("ZIP size differs from confirmed request")
                self._bound_space(declared)
                stage = self._bound_directory(self._root_fd, _random_leaf(b'.mta-stage-'))
                extracted = []
                total = 0
                for info, parts in files:
                    self._binding_current(cancelled)
                    self._bound_space(info.file_size)
                    directory = self._bound_tree(stage, parts[:-1])
                    entry = self._bound_output(directory, native_name(parts[-1]))
                    count = 0
                    with archive.open(info, 'r') as member:
                        while True:
                            self._binding_current(cancelled)
                            chunk = member.read(CHUNK_BYTES)
                            if not chunk:
                                break
                            count += len(chunk)
                            total += len(chunk)
                            if (count > info.file_size or count > self.max_file_bytes or
                                    total > declared or total > self.max_total_bytes):
                                raise StorageError("actual extracted byte limit")
                            self._bound_space(len(chunk))
                            offset = 0
                            while offset < len(chunk):
                                self._binding_current(cancelled)
                                amount = os.write(entry['row']['fd_original'], chunk[offset:])
                                if type(amount) is not int or not 0 < amount <= len(chunk) - offset:
                                    raise StorageError("unknown or short file write result")
                                offset += amount
                                self._binding_current(cancelled)
                            if progress is not None:
                                progress(total, declared)
                    if count != info.file_size:
                        raise StorageError("actual ZIP member size mismatch")
                    self._binding_current(cancelled)
                    os.fsync(entry['row']['fd_original'])
                    self._binding_current(cancelled)
                    if not _close_original(entry['row']):
                        raise StorageError("owned output descriptor close unknown")
                    extracted.append((parts, entry))
                if total != declared:
                    raise StorageError("actual ZIP total mismatch")
                if _file_signature(os.fstat(archive_row['fd_original'])) != before:
                    raise StorageError("original archive changed during receive")
                result_dir = self._bound_directory(self._root_fd, _random_leaf(b'received-'))
                committed, result_entries = [], [result_dir]
                for parts, origin in extracted:
                    self._binding_current(cancelled)
                    directory = self._bound_tree(result_dir, parts[:-1])
                    target = self._new_bound_entry(directory['row']['fd_original'],
                                                   native_name(parts[-1]), 'file')
                    target['creation_called'] = target['creation_unknown'] = True
                    if _identity(os.stat(origin['name'], dir_fd=origin['parent'],
                                          follow_symlinks=False)) != origin['identity']:
                        raise StorageError("original staging file changed")
                    # Hard-link publication is exclusive/no-clobber. Never use
                    # rename over a foreign target, and never traverse symlinks.
                    os.link(origin['name'], target['name'], src_dir_fd=origin['parent'],
                            dst_dir_fd=target['parent'], follow_symlinks=False)
                    target['creation_returned'] = target['created'] = True
                    target['creation_unknown'] = False
                    target['identity'] = origin['identity']
                    self._binding_current(cancelled)
                    if _identity(os.stat(target['name'], dir_fd=target['parent'],
                                          follow_symlinks=False)) != target['identity']:
                        raise StorageError("new result file changed")
                    if not self._bound_remove(origin):
                        raise StorageError("original staging cleanup unknown")
                    committed.append(os.path.join(self.root, _public_name(result_dir['name']), *parts))
                # Remove staging only. Result ownership changes only after all
                # CRCs, bytes and original directory relationships pass.
                result_dirs = [entry for entry in self._bound_entries
                               if entry['kind'] == 'directory' and
                               _entry_below(entry, result_dir, self._bound_entries)]
                result_files = [entry for entry in self._bound_entries
                                if entry['kind'] == 'file' and
                                any(entry['parent'] == value['row']['fd_original'] for value in result_dirs)]
                result_entries = result_dirs + result_files
                result_ids = set(id(value) for value in result_entries)
                for entry in reversed(self._bound_entries):
                    if id(entry) not in result_ids and not self._bound_remove(entry):
                        raise StorageError("staging directory cleanup unknown")
                for entry in reversed(result_dirs):
                    self._binding_current(cancelled)
                    os.fsync(entry['row']['fd_original'])
                    self._binding_current(cancelled)
                os.fsync(self._root_fd)
                self._binding_current(cancelled)
                for entry in result_entries:
                    entry['published'] = True
                # Retain the actual durable point before fallible close/cancel.
                # This never turns the following failure into a successful run.
                self._durable_result = (task_id,
                    os.path.join(self.root, _public_name(result_dir['name'])),
                    tuple(committed), len(committed), total)
                for row in reversed(self._bound_rows):
                    if not _close_original(row):
                        # Published names remain; do not invent successful commit.
                        raise StorageError("owned directory close unknown")
                self._cancel(cancelled)
                self.directory_binding.check()
                self._bound_complete = True
                return dict(taskId=task_id,
                            directory=os.path.join(self.root, _public_name(result_dir['name'])),
                            files=committed, fileCount=len(committed), totalSize=total)
        except BaseException as error:
            self._bound_failure = error
            self._bound_cleanup()
            raise
        finally:
            if owned_archive is not None:
                if not self.directory_binding.close_archive(owned_archive):
                    failure = owned_archive.row['close_error'] or StorageError("archive close unknown")
                    self._bound_cleanup_errors.append(failure)
                    if self._bound_failure is None:
                        self._bound_failure = failure
                        raise failure

    def close(self):
        """Close only this receiver's entries/FDs, never its borrowed binding."""
        if self.directory_binding is None:
            return True
        if self._bound_close_called:
            return not self.lifecycle_status()['resource_pending']
        self._bound_close_called = True
        self._bound_cleanup()
        return not self.lifecycle_status()['resource_pending']

    def lifecycle_status(self):
        if self.directory_binding is None:
            return dict(resource_pending=False, failure=False, rows=0, entries=0)
        pending = (bool(self._bound_cleanup_errors) or
                   any(entry['creation_unknown'] for entry in self._bound_entries) or
                   any(not row['closed'] or row['unknown'] for row in self._bound_rows) or
                   any(entry['created'] and not entry['removed'] and not entry['published']
                       for entry in self._bound_entries))
        return dict(resource_pending=pending, failure=self._bound_failure is not None,
                    rows=len(self._bound_rows), entries=len(self._bound_entries))

    def _cancel(self, cancelled):
        if cancelled is not None and cancelled():
            raise TransferCancelled("receive cancelled")

    def _space(self, needed):
        if self.directory_binding is not None:
            return self._bound_space(needed)
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
        with open(native_name(zip_path), "rb") as source:
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
                expected_files=None, expected_bytes=None, archive_resource=None):
        """Return verified files/bytes, never a success based on request metadata.

        progress receives actual extracted byte count and declared total.
        The ZIP remains owned by the caller; this method never deletes it.
        """
        if self.directory_binding is not None:
            return self._receive_bound(zip_path, task_id, cancelled, progress,
                                       expected_files, expected_bytes, archive_resource)
        if archive_resource is not None:
            raise StorageError("archive resource requires an original directory binding")
        validate_task_id(task_id)
        if not isinstance(zip_path, str) or not os.path.isabs(zip_path):
            raise StorageError("an absolute ZIP path is required")
        _check_no_symlinks(zip_path)
        if not os.path.isfile(native_name(zip_path)):
            raise StorageError("ZIP input is not a regular file")
        if os.path.getsize(native_name(zip_path)) > self.max_total_bytes + 1024 * 1024:
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
            with open(native_name(zip_path), "rb") as zip_source, zipfile.ZipFile(zip_source, "r") as archive:
                files, declared = self._validate_infos(archive.infolist())
                if expected_files is not None and expected_files != len(files):
                    raise StorageError("ZIP count differs from confirmed request")
                if expected_bytes is not None and expected_bytes != declared:
                    raise StorageError("ZIP size differs from confirmed request")
                self._space(declared)
                staging = _public_name(tempfile.mkdtemp(prefix=native_name(".mta-stage-"), dir=native_name(self.root)))
                os.chmod(native_name(staging), 0o700)
                actual_total = 0
                relative_paths = []
                for info, parts in files:
                    self._cancel(cancelled)
                    self._space(info.file_size)
                    directory = os.path.join(staging, *parts[:-1]) if len(parts) > 1 else staging
                    if not os.path.isdir(native_name(directory)):
                        os.makedirs(native_name(directory), 0o700)
                    output = os.path.join(directory, parts[-1])
                    # Exclusive creation. ZIP permissions are never preserved.
                    fd = os.open(native_name(output), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
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
                result_dir = _public_name(tempfile.mkdtemp(prefix=native_name("received-"), dir=native_name(self.root)))
                os.chmod(native_name(result_dir), 0o700)
                committed = []
                for relative in relative_paths:
                    self._cancel(cancelled)
                    target = os.path.join(result_dir, relative)
                    directory = os.path.dirname(target)
                    if not os.path.isdir(native_name(directory)):
                        os.makedirs(native_name(directory), 0o700)
                    if os.path.lexists(native_name(target)):
                        raise StorageError("result collision")
                    os.rename(native_name(os.path.join(staging, relative)), native_name(target))
                    committed.append(target)
                # Report only after every file/CRC passed. Empty directories
                # have no content and are intentionally not published.
                self._cancel(cancelled)
                shutil.rmtree(native_name(staging))
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
                    shutil.rmtree(native_name(owned))




def _identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid)


def _same_inode(left, right):
    return (left[0], left[1], stat.S_IFMT(left[2])) == (right[0], right[1], stat.S_IFMT(right[2]))


def _fd_row(role):
    return dict(role=role, fd=None, fd_original=None, identity=None,
                called=False, returned=False, closed=True, unknown=False,
                close_called=False, close_return=None, close_error=None,
                ebadf=None, handle=None, handle_original=None,
                transfer_called=False, transfer_returned=False)


def _close_original(row):
    if row['closed'] and not row['unknown']:
        return True
    if row['close_called']:
        return False
    if row['transfer_called'] and (not row['transfer_returned'] or row['handle_original'] is None):
        # fdopen may have consumed/closed/reused the numeric FD before raising.
        # An unreturned transfer cannot be cleaned by guessing raw ownership.
        row['unknown'] = True
        return False
    if (not row['returned'] or row['fd'] is not row['fd_original'] or
            row['identity'] is None):
        row['unknown'] = True
        return False
    row['close_called'] = True
    try:
        if not _same_inode(_identity(os.fstat(row['fd_original'])), row['identity']):
            raise StorageError("original descriptor identity changed")
        if row['handle'] is not None:
            if row['handle'] is not row['handle_original']:
                raise StorageError("original file wrapper changed")
            value = row['handle_original'].close()
        else:
            value = os.close(row['fd_original'])
        row['close_return'] = value
        if value is not None:
            raise StorageError("unexpected descriptor close result")
        if row['handle_original'] is not None and not row['handle_original'].closed:
            raise StorageError("original wrapper not closed")
        try:
            os.fstat(row['fd_original'])
        except OSError as error:
            if type(error.errno) is not int or error.errno != errno.EBADF:
                raise
            row['ebadf'] = error
        else:
            raise StorageError("original descriptor still open")
        row['closed'], row['unknown'] = True, False
        return True
    except BaseException as error:
        row['close_error'], row['unknown'] = error, True
        return False


class DownloadFile(object):
    """Private original file/wrapper record, not an admission receipt."""
    def __init__(self, binding, name, role):
        self.binding, self.name, self.role = binding, name, role
        self.path = os.path.join(binding.root, _public_name(name))
        self.row = _fd_row(role)
        self._originals = (binding, name, role, self.path, self.row)
        self.created = False
        self.remove_attempted, self.removed, self.remove_error = False, False, None

    @property
    def handle(self):
        return self.row['handle_original']


class DirectoryBinding(object):
    """Mechanical POSIX directory-FD owner; no target UID/RF authentication.

    All ancestors must already exist. Their original FD identities and
    parent/name relationships are retained; the absolute cap is never renewed.
    The receiver borrows this object and never closes its directory chain.
    Unsupported dir_fd APIs fail closed, never fall back to absolute writes.
    """
    def __init__(self, root, absolute_until, clock=None):
        self.rows, self.downloads, self.archives, self.initializations = [], [], [], []
        self.failure, self.cleanup_errors = None, []
        self._close_called, self._closed = False, False
        if (os.name != 'posix' or not isinstance(root, str) or not os.path.isabs(root) or
                os.path.abspath(root) != root or os.path.dirname(root) == root or
                any(part in ('', '.', '..') for part in root.split('/')[1:])):
            raise StorageError("an existing absolute POSIX receive directory is required")
        if (type(absolute_until) is not float or not math.isfinite(absolute_until) or
                absolute_until <= 0 or (clock is not None and not callable(clock))):
            raise StorageError("invalid original directory deadline")
        required = (os.open, os.stat, os.mkdir, os.unlink, os.rmdir, os.link)
        if (not hasattr(os, 'O_DIRECTORY') or not hasattr(os, 'O_NOFOLLOW') or
                not all(function in os.supports_dir_fd for function in required)):
            raise StorageError("POSIX directory descriptor operations unavailable")
        self._root, self._until = root, absolute_until
        self.clock = time.monotonic if clock is None else clock
        self._period = (self._until, self.clock)
        self.last = None
        self._row_originals = None
        try:
            self._now()
            parts = root.split('/')[1:]
            for index, component in enumerate(['/'] + parts):
                self._now()
                row = _fd_row('directory')
                row['component'] = component
                row['parent'] = self.rows[-1] if self.rows else None
                self.rows.append(row)  # Retain before the actual open factory.
                flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, 'O_CLOEXEC', 0)
                row['called'], row['closed'], row['unknown'] = True, False, True
                try:
                    fd = (os.open(b'/', flags) if index == 0 else
                          os.open(native_name(component), flags, dir_fd=row['parent']['fd_original']))
                except OSError as error:
                    if type(error.errno) is int and 1 <= error.errno <= 4095:
                        row['closed'], row['unknown'] = True, False
                    raise
                row['fd'] = row['fd_original'] = fd  # Before fstat/cap checks.
                row['returned'] = True
                row['identity'] = _identity(os.fstat(fd))
                if not stat.S_ISDIR(row['identity'][2]):
                    raise StorageError("held node is not a directory")
                os.set_inheritable(fd, False)
                if os.get_inheritable(fd):
                    raise StorageError("directory descriptor is inheritable")
                row['unknown'] = False
                self._now()
            self._row_originals = tuple(self.rows)
            self.check()
        except BaseException as error:
            self.failure = error
            self.close()
            # Retain the owner even if construction failed with unknown inventory.
            try:
                error.directory_binding = self
            except BaseException:
                pass
            raise

    @property
    def root(self):
        return self._root

    @property
    def absolute_until(self):
        return self._until

    def _now(self):
        if self.clock is not self._period[1] or self._until is not self._period[0]:
            raise StorageError("original directory period changed")
        now = self.clock()
        if (type(now) is not float or not math.isfinite(now) or
                (self.last is not None and now < self.last) or now >= self._until):
            raise StorageError("receive directory deadline expired or clock regressed")
        self.last = now
        return now

    def _current(self, active):
        if self._close_called or self._closed or self.failure is not None:
            raise StorageError("directory binding unavailable")
        if (self._row_originals is None or len(self.rows) != len(self._row_originals) or
                any(row is not original for row, original in zip(self.rows, self._row_originals))):
            raise StorageError("original directory inventory changed")
        if active:
            self._now()
        for row in self._row_originals:
            if (not row['returned'] or row['closed'] or row['unknown'] or
                    row['fd'] is not row['fd_original'] or
                    _identity(os.fstat(row['fd_original'])) != row['identity']):
                raise StorageError("held directory identity changed")
            observed = (os.stat(b'/', follow_symlinks=False) if row['parent'] is None else
                        os.stat(native_name(row['component']),
                                dir_fd=row['parent']['fd_original'], follow_symlinks=False))
            if _identity(observed) != row['identity']:
                raise StorageError("receive directory or ancestor replaced")
        if active:
            self._now()
        return self.rows[-1]['fd_original']

    def check(self):
        self._current(True)
        return self

    def fd(self):
        return self._current(True)

    def identity_rows(self):
        return tuple((row['component'],) + row['identity']
                     for row in self.rows if row['identity'] is not None)

    def ensure_private_child(self, name):
        """Only Received; no ancestor creation, adoption repair, chmod or chown."""
        if type(name) is not str or name != 'Received':
            raise StorageError("only the fixed Received child may be initialized")
        parent_fd = self.fd()
        ticket = dict(parent=self, name=name, called=False, returned=False,
                      created=False, identity=None, child=None, child_returned=False, error=None)
        self.initializations.append(ticket)
        try:
            try:
                observed = os.stat(b'Received', dir_fd=parent_fd, follow_symlinks=False)
            except OSError as error:
                if type(error.errno) is not int or error.errno != errno.ENOENT:
                    raise
                self.check()
                ticket['called'] = True
                os.mkdir(b'Received', 0o700, dir_fd=parent_fd)
                ticket['returned'], ticket['created'] = True, True
                observed = os.stat(b'Received', dir_fd=parent_fd, follow_symlinks=False)
            expected = _identity(observed)
            ticket['identity'] = expected
            if (not stat.S_ISDIR(expected[2]) or stat.S_IMODE(expected[2]) != 0o700 or
                    expected[3:5] != self.rows[-1]['identity'][3:5]):
                raise StorageError("Received child type, mode or owner differs")
            self.check()
            child = DirectoryBinding.__new__(DirectoryBinding)
            ticket['child'] = child
            DirectoryBinding.__init__(child, os.path.join(self.root, name),
                                      self._until, clock=self.clock)
            ticket['child_returned'] = True
            if (child.identity_rows()[:-1] != self.identity_rows() or
                    child.rows[-1]['identity'] != expected):
                raise StorageError("original Received relationship changed")
            self.check()
            child.check()
            return child
        except BaseException as error:
            ticket['error'] = error
            if ticket['child'] is not None:
                ticket['child'].close()
            raise

    def _open_file(self, name, role, flags, mode=0o600):
        if (type(name) is not bytes or not name or b'/' in name or b'\x00' in name or
                name in (b'.', b'..')):
            raise StorageError("invalid bound leaf")
        name.decode('utf-8')
        resource = DownloadFile(self, name, role)
        inventory = self.downloads if role == 'download' else self.archives
        inventory.append(resource)
        row = resource.row
        fd = self.fd()
        row['called'], row['closed'], row['unknown'] = True, False, True
        try:
            value = os.open(name, flags | os.O_NOFOLLOW | getattr(os, 'O_CLOEXEC', 0),
                            mode, dir_fd=fd)
        except OSError as error:
            if type(error.errno) is int and 1 <= error.errno <= 4095:
                row['closed'], row['unknown'] = True, False
            raise
        row['fd'] = row['fd_original'] = value
        row['returned'] = True
        resource.created = role == 'download'
        row['identity'] = _identity(os.fstat(value))
        if not stat.S_ISREG(row['identity'][2]):
            raise StorageError("bound archive is not a regular file")
        os.set_inheritable(value, False)
        if os.get_inheritable(value):
            raise StorageError("bound file descriptor is inheritable")
        row['unknown'] = False
        self.check()
        row['transfer_called'], row['unknown'] = True, True
        handle = os.fdopen(value, 'w+b' if role == 'download' else 'rb')
        row['handle'] = row['handle_original'] = handle
        row['transfer_returned'] = True
        if handle is None or handle.closed or handle.fileno() != value:
            raise StorageError("original file wrapper transfer unknown")
        row['unknown'] = False
        self.check()
        return resource

    def create_download(self):
        name = b'.mta-download-' + os.urandom(12).hex().encode('ascii') + b'.zip'
        try:
            return self._open_file(name, 'download', os.O_RDWR | os.O_CREAT | os.O_EXCL)
        except BaseException:
            if self.downloads:
                _close_original(self.downloads[-1].row)
            raise

    def _file_original(self, resource, role):
        inventory = self.downloads if role == 'download' else self.archives
        if (type(resource) is not DownloadFile or resource.binding is not self or
                resource.role != role or not any(value is resource for value in inventory) or
                resource.binding is not resource._originals[0] or
                resource.name is not resource._originals[1] or
                resource.role is not resource._originals[2] or
                resource.path is not resource._originals[3] or
                resource.row is not resource._originals[4]):
            raise StorageError("foreign bound file resource")
        return resource.row

    def download_current(self, resource):
        row = self._file_original(resource, 'download')
        self.check()
        if (not resource.created or not row['returned'] or row['closed'] or row['unknown'] or
                row['fd'] is not row['fd_original'] or row['handle'] is not row['handle_original'] or
                row['handle_original'] is None or row['handle_original'].closed or
                row['handle_original'].fileno() != row['fd_original'] or
                _identity(os.fstat(row['fd_original'])) != row['identity'] or
                _identity(os.stat(resource.name, dir_fd=self.rows[-1]['fd_original'],
                                  follow_symlinks=False)) != row['identity']):
            raise StorageError("original download resource changed")
        self.check()
        return resource

    def close_download(self, resource):
        return _close_original(self._file_original(resource, 'download'))

    def remove_download(self, resource):
        row = self._file_original(resource, 'download')
        if resource.removed or not resource.created:
            return True
        if resource.remove_attempted or not row['closed'] or row['unknown'] or row['identity'] is None:
            return False
        resource.remove_attempted = True
        try:
            fd = self._current(False)
            if _identity(os.stat(resource.name, dir_fd=fd, follow_symlinks=False)) != row['identity']:
                raise StorageError("original download name changed")
            os.unlink(resource.name, dir_fd=fd)
            resource.removed = True
            return True
        except BaseException as error:
            resource.remove_error = error
            self.cleanup_errors.append(error)
            return False

    def open_archive(self, zip_path):
        if (type(zip_path) is not str or not os.path.isabs(zip_path) or
                os.path.dirname(zip_path) != self.root):
            raise StorageError("bound ZIP must be a direct child of the receive directory")
        try:
            return self._open_file(native_name(os.path.basename(zip_path)), 'archive',
                                   os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0))
        except BaseException:
            if self.archives:
                _close_original(self.archives[-1].row)
            raise

    def close_archive(self, resource):
        return _close_original(self._file_original(resource, 'archive'))

    def close(self):
        if self._close_called:
            return self._closed
        # Remove owned download names while original directory FDs are live.
        for resource in self.archives:
            if not _close_original(resource.row) and resource.row['close_error'] is not None:
                self.cleanup_errors.append(resource.row['close_error'])
        for resource in self.downloads:
            if not _close_original(resource.row):
                if resource.row['close_error'] is not None:
                    self.cleanup_errors.append(resource.row['close_error'])
            elif resource.created and not resource.removed and not self.remove_download(resource):
                pass
        self._close_called = True
        for row in reversed(self.rows):
            if not _close_original(row) and row['close_error'] is not None:
                self.cleanup_errors.append(row['close_error'])
        self._closed = (not self.cleanup_errors and
            all(row['closed'] and not row['unknown'] for row in self.rows) and
            all(value.row['closed'] and not value.row['unknown'] for value in self.archives) and
            all(value.row['closed'] and not value.row['unknown'] and (not value.created or value.removed)
                for value in self.downloads) and
            all(value['error'] is None or value['child'] is None or value['child'].closed()
                for value in self.initializations))
        return self._closed

    def closed(self):
        return self._closed

def _file_signature(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size,
            getattr(value, 'st_mtime_ns', value.st_mtime),
            getattr(value, 'st_ctime_ns', value.st_ctime))


def _random_leaf(prefix):
    return prefix + os.urandom(12).hex().encode('ascii')


def _entry_below(entry, root, entries):
    current = entry
    seen = set()
    while id(current) not in seen:
        if current is root:
            return True
        seen.add(id(current))
        parents = [value for value in entries if value['kind'] == 'directory' and
                   value['row'] is not None and
                   value['row']['fd_original'] == current['parent'] and value is not current]
        if len(parents) != 1:
            return False
        current = parents[0]
    return False
