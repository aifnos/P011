"""Bounded metadata-only CLIENT-history observation, never admission/recovery.

Fixed physical root only; no Owner/Boot/Provider, journal contents, /proc actors,
locks, subprocess, RF, writes, removal or archive. Unknown entries stay unknown.
Names/full stat data remain private; public fields contain finite counts only.
This first sampler establishes actual directory shape before format decisions.
"""
import errno
import os
import stat
import sys
import time

ROOT_NAME = 'p011-mta-client-rfinit'
PENDING_NAME = 'p011-mta-p2p-device.pending'
MAX_ENTRIES, MAX_RUNS, MAX_CHILDREN = 64, 8, 64
CLASSES = ('entry_unknown', 'regular_entry', 'symlink_entry', 'other_entry',
           'run_directory', 'run_unreadable')


def _meta(raw):
    return tuple(getattr(raw, key) for key in ('st_dev', 'st_ino', 'st_mode', 'st_uid',
        'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def _kind(raw):
    if stat.S_ISDIR(raw.st_mode): return 'directory'
    if stat.S_ISREG(raw.st_mode): return 'regular'
    if stat.S_ISLNK(raw.st_mode): return 'symlink'
    return 'other'


def _category(name):
    if name == 'journal.json': return 'journal_name_only'
    if name == 'journal.lock': return 'journal_lock_name_only'
    if name in ('device.lock', 'current', 'pending'): return 'coordination_name_only'
    return 'other_name'


class Observation:
    def __init__(self):
        self.until = time.monotonic() + 10.0
        self.rows, self.entries = [], []
        self.reason = 'not_started'
        self.root_empty = None
        self.root_stable = False
        self.pending = 'unknown'
        self.pending_metadata = None
        self.total_names = 0

    def check(self):
        if time.monotonic() >= self.until: raise ValueError('observation_deadline')

    def open_directory(self, parent, name, private=False):
        self.check()
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK | os.O_DIRECTORY
        row = dict(fd=None, parent=parent, name=name, metadata=None, close_called=False,
                   closed=False, error=None)
        self.rows.append(row)
        try:
            row['fd'] = os.open(name, flags, dir_fd=parent)
            raw = os.fstat(row['fd']); row['metadata'] = _meta(raw)
            if (not stat.S_ISDIR(raw.st_mode) or raw.st_uid != 0 or raw.st_gid != 0 or
                    private and stat.S_IMODE(raw.st_mode) != 0o700):
                raise ValueError('unsafe_directory')
            entry = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if _meta(entry) != row['metadata']: raise ValueError('directory_changed')
            self.check()
            return row
        except (OSError, ValueError) as error:
            row['error'] = type(error).__name__
            raise

    def names(self, row, limit):
        self.check(); before = _meta(os.fstat(row['fd']))
        names = os.listdir(row['fd'])
        if (len(names) > limit or any(type(name) is not str or not name or
                name in ('.', '..') or '/' in name or '\x00' in name for name in names)):
            raise ValueError('directory_budget')
        if _meta(os.fstat(row['fd'])) != before: raise ValueError('directory_changed')
        self.total_names += len(names)
        return sorted(names), before

    def run(self):
        try:
            if sys.platform != 'linux' or os.geteuid() != 0: raise ValueError('unsupported_platform')
            root = self.open_directory(None, '/')
            var = self.open_directory(root['fd'], 'var')
            volatile = self.open_directory(var['fd'], 'volatile')
            tmp = self.open_directory(volatile['fd'], 'tmp')
            try:
                pending = os.stat(PENDING_NAME, dir_fd=tmp['fd'], follow_symlinks=False)
                self.pending_metadata = _meta(pending)
                self.pending = 'symlink' if stat.S_ISLNK(pending.st_mode) else 'present'
            except OSError as error:
                if error.errno != errno.ENOENT: raise
                self.pending = 'absent_snapshot'
            try: client = self.open_directory(tmp['fd'], ROOT_NAME, private=True)
            except OSError as error:
                if error.errno != errno.ENOENT: raise
                self.reason = 'client_root_missing'; return
            names, root_meta = self.names(client, MAX_ENTRIES)
            self.root_empty = not names
            runs = 0
            for name in names:
                self.check()
                entry = dict(name=name, classification='entry_unknown', metadata=None,
                             kind='unknown', children=None, children_stable=False, error=None)
                self.entries.append(entry)
                try:
                    raw = os.stat(name, dir_fd=client['fd'], follow_symlinks=False)
                    entry['metadata'] = _meta(raw); entry['kind'] = _kind(raw)
                    if entry['kind'] != 'directory':
                        entry['classification'] = dict(regular='regular_entry', symlink='symlink_entry',
                                                       other='other_entry')[entry['kind']]
                        continue
                    if runs >= MAX_RUNS: continue
                    runs += 1
                    run = self.open_directory(client['fd'], name, private=True)
                    children, run_meta = self.names(run, MAX_CHILDREN)
                    entry['children'] = []
                    for child in children:
                        self.check()
                        raw = os.stat(child, dir_fd=run['fd'], follow_symlinks=False)
                        entry['children'].append(dict(name=child, category=_category(child),
                                                      kind=_kind(raw), metadata=_meta(raw)))
                    tail, tail_meta = self.names(run, MAX_CHILDREN)
                    entry['children_stable'] = tail == children and tail_meta == run_meta
                    for child in entry['children']:
                        if _meta(os.stat(child['name'], dir_fd=run['fd'], follow_symlinks=False)) != tuple(child['metadata']):
                            entry['children_stable'] = False
                    if _meta(os.stat(name, dir_fd=client['fd'], follow_symlinks=False)) != tuple(entry['metadata']):
                        entry['children_stable'] = False
                    entry['classification'] = 'run_directory' if entry['children_stable'] else 'run_unreadable'
                except (OSError, ValueError) as error:
                    entry['classification'] = 'run_unreadable' if entry['kind'] == 'directory' else 'entry_unknown'
                    entry['error'] = type(error).__name__
            tail, tail_meta = self.names(client, MAX_ENTRIES)
            self.root_stable = tail == names and tail_meta == root_meta
            for row in self.rows:
                if row['metadata'] is None: continue
                current = _meta(os.fstat(row['fd']))
                edge = _meta(os.stat(row['name'], dir_fd=row['parent'], follow_symlinks=False))
                if current[:5] != row['metadata'][:5] or edge[:5] != row['metadata'][:5]:
                    self.root_stable = False
            self.reason = 'observed' if self.root_stable else 'history_changed'
        except (OSError, ValueError): self.reason = 'observation_unknown'
        finally: self.close()

    def close(self):
        # Known original FDs are once-closed even after the observation expires.
        # An open with no returned FD is not a resource. Missing metadata/reused
        # FD never authorizes blind close; public resources_closed stays False.
        for row in reversed(self.rows):
            if row['fd'] is None: row['closed'] = True; continue
            if row['close_called'] or row['metadata'] is None: continue
            row['close_called'] = True
            try:
                if _meta(os.fstat(row['fd']))[:5] != row['metadata'][:5]: continue
                os.close(row['fd'])
                try: os.fstat(row['fd'])
                except OSError as error: row['closed'] = error.errno == errno.EBADF
            except OSError: pass

    def result(self):
        counts = dict((key, 0) for key in CLASSES)
        for entry in self.entries: counts[entry['classification']] += 1
        return dict(reason=self.reason, root_empty=self.root_empty, root_stable=self.root_stable,
            pending=self.pending, entry_count=len(self.entries), counts=counts,
            resources_closed=all(row['closed'] for row in self.rows),
            full_journal_schema_validated=False, actor_tasks_verified=False,
            active_session_verified=False, restoration_verified=False,
            receive_admission=False, device_mutations=False, radio_operations=False,
            private_entries=self.entries, private_pending_metadata=self.pending_metadata)


def observe():
    value = Observation(); value.run(); return value.result()
