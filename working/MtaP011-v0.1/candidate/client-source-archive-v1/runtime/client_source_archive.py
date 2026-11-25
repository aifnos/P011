"""Conditional source archive for exactly two human-authorized CLIENT trees.

verify() is readonly. archive() additionally requires the original verified
inventory returned before PC backup. No service/Owner/Boot, journal contents,
flock, signals, RF, deletion, overwrite, chmod or rollback. A fresh proc scan
observes exe/argv and only matching actor FD links: no global exclusion proof.
Source trees are renamed intact into one new root-owned0700 archive bucket.
Unknown inventories/FDs stop activity; known originals still close on expiry.
"""
import errno
import hashlib
import os
import re
import stat
import sys
import time

from expected_source import EXPECTED
import client_source_proc_readonly as proc_source

ROOT_NAME = 'p011-mta-client-rfinit'
ARCHIVE_PREFIX = 'p011-mta-client-source-archive-v1-'
SECONDS = 30.0
MAX_ENTRIES = 4096
DIRECTORIES = ('', 'runtime', 'native', 'ctrl')


def metadata(raw):
    return tuple(getattr(raw, key) for key in ('st_dev', 'st_ino', 'st_mode',
        'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def moved_identity(raw):
    # Linux rename may change the source directory ctime, not its mtime.
    return raw[:8]


class SourceArchive:
    def __init__(self):
        self.started = time.monotonic()
        self.until = self.started + SECONDS
        self.rows, self.anchors, self.run_rows, self.directory_rows = [], [], [], []
        self.file_records, self.events = [], []
        self.client = self.tmp = self.bucket = None
        self.initial = self.after = self.proc = None
        self.reason, self.error = 'not_started', None
        self.mutations_started = self.archive_created = False
        self.rename_called = self.rename_returned = self.rename_verified = 0
        self.verified = self.archive_verified = False

    def check(self):
        if time.monotonic() >= self.until: raise ValueError('archive_deadline')
        if any(row['fd'] is not None and row['metadata'] is None for row in self.rows):
            raise ValueError('descriptor_unknown')

    def edge(self, row, width=9):
        self.check()
        before = row['metadata']
        if (metadata(os.fstat(row['fd']))[:width] != before[:width] or
                metadata(os.stat(row['name'], dir_fd=row['parent'], follow_symlinks=False))[:width] != before[:width]):
            raise ValueError('entry_changed')
        return row['fd']

    def open_directory(self, parent, name, mode):
        self.check()
        row = dict(parent=parent, name=name, fd=None, metadata=None,
                   close_called=False, closed=False)
        self.rows.append(row)
        row['fd'] = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                            os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=parent)
        if any(other is not row and other['fd'] == row['fd'] and not other['closed'] for other in self.rows):
            for other in self.rows:
                if other['fd'] == row['fd']: other['metadata'] = None
            raise ValueError('descriptor_collision')
        raw = os.fstat(row['fd']); row['metadata'] = metadata(raw)
        if (not stat.S_ISDIR(raw.st_mode) or raw.st_uid != 0 or raw.st_gid != 0 or
                stat.S_IMODE(raw.st_mode) != mode or raw.st_nlink < 1):
            raise ValueError('directory_metadata')
        self.edge(row); return row

    def close_row(self, row):
        if row['fd'] is None: row['closed'] = True; return
        if row['close_called'] or row['metadata'] is None: return
        row['close_called'] = True
        try:
            if metadata(os.fstat(row['fd']))[:5] != row['metadata'][:5]: return
            os.close(row['fd'])
            try: os.fstat(row['fd'])
            except OSError as error: row['closed'] = error.errno == errno.EBADF
        except OSError: pass

    def names(self, row, expected):
        fd = self.edge(row)
        names = os.listdir(fd)
        if len(names) > MAX_ENTRIES or sorted(names) != sorted(expected):
            raise ValueError('inventory_unknown')
        self.edge(row); return names

    def prepare(self):
        if sys.platform != 'linux' or os.geteuid() != 0: raise ValueError('unsupported_platform')
        root = self.open_directory(None, '/', 0o755); self.anchors.append(root)
        var = self.open_directory(root['fd'], 'var', 0o755); self.anchors.append(var)
        volatile = self.open_directory(var['fd'], 'volatile', 0o1777); self.anchors.append(volatile)
        self.tmp = self.open_directory(volatile['fd'], 'tmp', 0o1777); self.anchors.append(self.tmp)
        self.client = self.open_directory(self.tmp['fd'], ROOT_NAME, 0o700)
        self.names(self.client, tuple(name for name, rows in EXPECTED))
        for name, specs in EXPECTED:
            run = self.open_directory(self.client['fd'], name, 0o700)
            self.run_rows.append((name, run))
            directories = {'': run}
            for child in DIRECTORIES[1:]:
                directories[child] = self.open_directory(run['fd'], child, 0o700)
            self.directory_rows.append((name, directories))
            for relative, row in directories.items():
                wanted = [path.split('/')[-1] for path, size, sha, mode in specs
                          if ('/' not in path and relative == '') or
                             ('/' in path and path.split('/')[0] == relative)]
                if relative == '': wanted += list(DIRECTORIES[1:])
                self.names(row, wanted)

    def read_file(self, directory, name, size, sha, mode):
        self.check()
        parent = self.edge(directory)
        row = dict(parent=parent, name=name, fd=None, metadata=None,
                   close_called=False, closed=False)
        self.rows.append(row)
        try:
            row['fd'] = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC |
                               os.O_NONBLOCK, dir_fd=parent)
            if any(other is not row and other['fd'] == row['fd'] and not other['closed'] for other in self.rows):
                for other in self.rows:
                    if other['fd'] == row['fd']: other['metadata'] = None
                raise ValueError('descriptor_collision')
            raw = os.fstat(row['fd']); row['metadata'] = metadata(raw)
            if (not stat.S_ISREG(raw.st_mode) or stat.S_IMODE(raw.st_mode) != mode or
                    raw.st_uid != 0 or raw.st_gid != 0 or raw.st_nlink != 1 or raw.st_size != size):
                raise ValueError('file_metadata')
            self.edge(row)
            digest, count = hashlib.sha256(), 0
            while count <= size:
                self.check(); block = os.read(row['fd'], min(65536, size + 1 - count))
                if type(block) is not bytes: raise ValueError('read_unknown')
                count += len(block); digest.update(block)
                if not block: break
            self.edge(row)
            if count != size or digest.hexdigest() != sha: raise ValueError('source_fingerprint')
            return [list(row['metadata']), sha]
        finally:
            self.close_row(row)
            if not row['closed']: raise ValueError('file_close_pending')

    def inspect(self):
        self.check()
        inventory = dict(anchor_metadata=[list(row['metadata'][:5]) for row in self.anchors],
            client_metadata=list(self.client['metadata']),
            root_names=sorted(name for name, specs in EXPECTED), runs=[])
        for (name, specs), (held_name, directories) in zip(EXPECTED, self.directory_rows):
            if name != held_name: raise ValueError('binding_unknown')
            files = []
            for relative, size, sha, mode in specs:
                branch, leaf = relative.split('/', 1) if '/' in relative else ('', relative)
                item = self.read_file(directories[branch], leaf, size, sha, mode)
                files.append([relative] + item)
            for relative, row in directories.items():
                wanted = [path.split('/')[-1] for path, size, sha, mode in specs
                    if ('/' not in path and relative == '') or
                       ('/' in path and path.split('/')[0] == relative)]
                self.names(row, wanted + (list(DIRECTORIES[1:]) if relative == '' else []))
            inventory['runs'].append([name,
                [[relative, list(directories[relative]['metadata'])] for relative in DIRECTORIES], files])
        for row in self.anchors: self.edge(row, 5)
        self.names(self.client, tuple(name for name, specs in EXPECTED))
        # Fresh final per-file stat, after every other original has been read.
        for name, dirs, files in inventory['runs']:
            held = next(rows for held_name, rows in self.directory_rows if held_name == name)
            for relative, saved, sha in files:
                branch, leaf = relative.split('/', 1) if '/' in relative else ('', relative)
                if list(metadata(os.stat(leaf, dir_fd=self.edge(held[branch]), follow_symlinks=False))) != saved:
                    raise ValueError('source_tail_changed')
        self.check(); return inventory

    def collision_check(self):
        self.check(); self.proc = proc_source.observe(); self.check()
        value = self.proc
        if (type(value) is not dict or value.get('reason') != 'observed' or
                not all(value.get(key) is True for key in ('roots_stable', 'proc_inventory_stable',
                    'proc_scan_complete', 'locks_complete', 'resources_closed')) or
                any(value.get(key) != 0 for key in ('matching_actor_count', 'matching_fd_links',
                    'fd_unknown_count', 'matching_lock_count', 'proc_unknown_count')) or
                value.get('fresh_lock_identity_count') != 1 or value.get('all_process_fds_scanned') is not False):
            raise ValueError('current_occupancy_unknown')
        lock = next(files for name, dirs, files in self.initial['runs'] if name == EXPECTED[0][0])
        saved = next(saved for relative, saved, sha in lock if relative == 'journal.lock')
        lock_rows = value.get('private_lock_metadata')
        if type(lock_rows) is not list or len(lock_rows) != 1 or list(lock_rows[0]['metadata']) != saved:
            raise ValueError('lock_identity_changed')

    def absent(self, directory, name):
        self.check()
        try: os.stat(name, dir_fd=directory['fd'], follow_symlinks=False)
        except OSError as error:
            if error.errno == errno.ENOENT: return
            raise
        raise ValueError('destination_exists')

    def move(self, token, baseline):
        if type(token) is not str or re.fullmatch('[0-9a-f]{24}', token) is None:
            raise ValueError('archive_name')
        if type(baseline) is not dict or self.initial != baseline:
            raise ValueError('backup_inventory_changed')
        self.collision_check()
        if self.inspect() != baseline: raise ValueError('source_changed_after_proc')
        bucket_name = ARCHIVE_PREFIX + token
        self.absent(self.tmp, bucket_name)
        for row in self.anchors: self.edge(row, 5)
        self.check(); self.mutations_started = True
        event = dict(kind='mkdir', called=True, returned=False, name=bucket_name)
        self.events.append(event)
        os.mkdir(bucket_name, 0o700, dir_fd=self.tmp['fd']); event['returned'] = True
        self.archive_created = True
        self.bucket = self.open_directory(self.tmp['fd'], bucket_name, 0o700)
        if self.bucket['metadata'][0] != self.client['metadata'][0]: raise ValueError('different_filesystem')
        self.names(self.bucket, ())
        for run_name, specs in EXPECTED: self.absent(self.bucket, run_name)
        for run_name, row in self.run_rows:
            # Check the held source and both destination names before either
            # move; no overwrite and no fallback if any inventory changes.
            self.check()
            for anchor in self.anchors: self.edge(anchor, 5)
            self.edge(self.client, 5); self.edge(self.bucket, 5); self.edge(row)
            self.absent(self.bucket, run_name)
            event = dict(kind='rename', name=run_name, called=True, returned=False, verified=False)
            self.events.append(event); self.rename_called += 1
            os.rename(run_name, run_name, src_dir_fd=self.client['fd'], dst_dir_fd=self.bucket['fd'])
            event['returned'] = True; self.rename_returned += 1
            after = metadata(os.stat(run_name, dir_fd=self.bucket['fd'], follow_symlinks=False))
            current = metadata(os.fstat(row['fd']))
            if moved_identity(after) != moved_identity(row['metadata']) or current != after:
                raise ValueError('renamed_identity_changed')
            self.absent(self.client, run_name)
            # Rebind only after this original inode is actually observed at
            # the new edge. Keep original/pre-move metadata in initial.
            row['parent'], row['metadata'] = self.bucket['fd'], after
            event['verified'] = True; self.rename_verified += 1
        # Parent mtime/ctime changed by exactly the new children/moves.
        self.client['metadata'] = metadata(os.fstat(self.client['fd']))
        self.bucket['metadata'] = metadata(os.fstat(self.bucket['fd']))
        self.names(self.client, ())
        self.names(self.bucket, tuple(name for name, specs in EXPECTED))
        after_runs = []
        for (name, specs), (held_name, directories) in zip(EXPECTED, self.directory_rows):
            files = []
            for relative, size, sha, mode in specs:
                branch, leaf = relative.split('/', 1) if '/' in relative else ('', relative)
                item = self.read_file(directories[branch], leaf, size, sha, mode)
                saved = next(rows for original_name, dirs, rows in baseline['runs'] if original_name == name)
                original = next(value for path, value, pin in saved if path == relative)
                if item[0] != original: raise ValueError('moved_file_changed')
                files.append([relative] + item)
            for relative in DIRECTORIES:
                row = directories[relative]; self.edge(row)
                before = next(value for original_name, dirs, rows in baseline['runs'] if original_name == name
                              for path, value in dirs if path == relative)
                if moved_identity(row['metadata']) != moved_identity(tuple(before)):
                    raise ValueError('moved_directory_changed')
            after_runs.append([name, [[path, list(directories[path]['metadata'])] for path in DIRECTORIES], files])
        self.check(); os.fsync(self.client['fd']); self.check()
        os.fsync(self.bucket['fd']); self.check(); os.fsync(self.tmp['fd']); self.check()
        self.after = dict(bucket_name=bucket_name, bucket_metadata=list(self.bucket['metadata']), runs=after_runs)
        self.archive_verified = True

    def run(self, token=None, baseline=None):
        try:
            self.prepare(); self.initial = self.inspect()
            if token is None:
                self.collision_check()
                if self.inspect() != self.initial: raise ValueError('source_changed_after_proc')
                self.verified = True; self.reason = 'verified_readonly'
            else:
                self.move(token, baseline); self.verified = True; self.reason = 'archived'
        except Exception as error:
            self.error = str(error) if type(error) is ValueError else type(error).__name__
            self.reason = 'archive_partial' if self.mutations_started else 'verification_refused'
        finally:
            for row in reversed(self.rows): self.close_row(row)
        return dict(reason=self.reason, verified=self.verified, archive_verified=self.archive_verified,
            archive_created=self.archive_created, device_mutations=self.mutations_started,
            rename_called=self.rename_called, rename_returned=self.rename_returned,
            rename_verified=self.rename_verified, resources_closed=all(row['closed'] for row in self.rows),
            all_process_fds_scanned=False, exclusive_lease=False, restoration_verified=False,
            receive_admission=False, radio_operations=False,
            private_inventory=self.initial, private_after=self.after, private_proc=self.proc,
            private_events=self.events, private_error=self.error)


def verify(): return SourceArchive().run()


def archive(token, original_inventory): return SourceArchive().run(token, original_inventory)
