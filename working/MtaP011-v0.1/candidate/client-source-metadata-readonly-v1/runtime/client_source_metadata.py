"""Read only four metadata JSON files in two previously observed CLIENT dirs.

No arbitrary path, journals, user files, source execution, proc actor reads,
locks, mutation, recovery, RF or admission. Declared fields are DATA only.
Full JSON bytes/names/stat are private; summaries contain safe schema labels.
"""
import errno
import hashlib
import os
import re
import stat
import sys
import time
import p011_json as J

ROOT_NAME = 'p011-mta-client-rfinit'
RUNS = (
    ('client-2d974ccd59518cb1db491aa3f1601d2f',
     (('candidate_1', 'candidate.json'), ('deployment_1', 'deployment.json'))),
    ('client-e87c63218bf64fb28df191ead67122a1',
     (('candidate_2', 'candidate.json'), ('static_source_2', 'static-source.json'))),
)
MAX_FILE = 8192
STATUS_KEYS = ('ready', 'not_ready', 'complete', 'source_only', 'static_only',
               'runtime_ready', 'rf_ready', 'rf_started', 'receive_ready')


def meta(raw):
    return tuple(getattr(raw, key) for key in ('st_dev', 'st_ino', 'st_mode', 'st_uid',
        'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def summary(tag, value):
    if type(value) is not dict or len(value) > 64: raise ValueError('metadata_object')
    keys = sorted(key for key in value if type(key) is str and
        re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]{0,63}', key) is not None)
    def label(key):
        text = value.get(key)
        if type(text) is str and re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]{0,95}', text) is not None:
            return text
        return None
    version = value.get('version')
    return dict(tag=tag, schema=label('schema'), kind=label('kind'), keys=keys,
        withheld_key_count=len(value) - len(keys),
        version=version if type(version) is int and 0 <= version <= 1000 else None,
        declared_status=dict((key, value[key]) for key in STATUS_KEYS
                             if key in value and type(value[key]) is bool),
        full_schema_validated=False, readiness_verified=False)


class Observation:
    def __init__(self):
        self.until = time.monotonic() + 10.0
        self.rows, self.private_files, self.private_ctrl, self.summaries = [], [], [], []
        self.reason = 'not_started'
        self.roots_stable = False
        self.ctrl_socket_count = self.ctrl_entry_count = 0

    def check(self):
        if time.monotonic() >= self.until: raise ValueError('observation_deadline')

    def open(self, parent, name, directory=False):
        self.check()
        row = dict(parent=parent, name=name, fd=None, metadata=None, close_called=False, closed=False)
        self.rows.append(row)
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
        if directory: flags |= os.O_DIRECTORY
        row['fd'] = os.open(name, flags, dir_fd=parent)
        raw = os.fstat(row['fd']); row['metadata'] = meta(raw)
        if (raw.st_uid != 0 or raw.st_gid != 0 or
                directory and not stat.S_ISDIR(raw.st_mode) or
                not directory and not stat.S_ISREG(raw.st_mode)):
            raise ValueError('metadata_type')
        if meta(os.stat(name, dir_fd=parent, follow_symlinks=False)) != row['metadata']:
            raise ValueError('entry_changed')
        self.check()
        return row

    def names(self, row, limit):
        self.check(); before = meta(os.fstat(row['fd']))
        names = os.listdir(row['fd'])
        if len(names) > limit or any(type(name) is not str or not name or
                name in ('.', '..') or '/' in name or '\x00' in name for name in names):
            raise ValueError('directory_budget')
        if meta(os.fstat(row['fd'])) != before: raise ValueError('directory_changed')
        return sorted(names), before

    def read_metadata(self, parent, tag, name):
        row = self.open(parent, name)
        if not 0 < row['metadata'][6] <= MAX_FILE: raise ValueError('metadata_budget')
        private = dict(tag=tag, metadata=row['metadata'], sha256=None, raw=None)
        self.private_files.append(private)
        parts, count = [], 0
        while True:
            self.check(); block = os.read(row['fd'], min(4096, MAX_FILE + 1 - count))
            count += len(block)
            if count > MAX_FILE: raise ValueError('metadata_budget')
            parts.append(block)
            if not block: break
        raw = b''.join(parts)
        private['sha256'] = hashlib.sha256(raw).hexdigest()
        private['raw'] = raw.decode('utf-8', 'strict')
        if (len(raw) != row['metadata'][6] or meta(os.fstat(row['fd'])) != row['metadata'] or
                meta(os.stat(name, dir_fd=parent, follow_symlinks=False)) != row['metadata']):
            raise ValueError('metadata_changed')
        self.summaries.append(summary(tag, J.loads(private['raw'])))

    def ctrl(self, run):
        ctrl = self.open(run['fd'], 'ctrl', directory=True)
        names, before = self.names(ctrl, 16)
        rows = []
        self.private_ctrl.append(rows)
        for name in names:
            self.check(); raw = os.stat(name, dir_fd=ctrl['fd'], follow_symlinks=False)
            rows.append(dict(name=name, metadata=meta(raw), socket=stat.S_ISSOCK(raw.st_mode)))
            self.ctrl_entry_count += 1; self.ctrl_socket_count += int(stat.S_ISSOCK(raw.st_mode))
        tail, after = self.names(ctrl, 16)
        if tail != names or after != before: raise ValueError('ctrl_changed')
        for row in rows:
            if meta(os.stat(row['name'], dir_fd=ctrl['fd'], follow_symlinks=False)) != row['metadata']:
                raise ValueError('ctrl_changed')

    def run(self):
        try:
            if sys.platform != 'linux' or os.geteuid() != 0: raise ValueError('unsupported_platform')
            root = self.open(None, '/', True)
            var = self.open(root['fd'], 'var', True)
            volatile = self.open(var['fd'], 'volatile', True)
            tmp = self.open(volatile['fd'], 'tmp', True)
            client = self.open(tmp['fd'], ROOT_NAME, True)
            names, initial = self.names(client, 64)
            if any(name not in names for name, unused in RUNS): raise ValueError('observed_run_missing')
            for name, files in RUNS:
                run = self.open(client['fd'], name, True)
                if stat.S_IMODE(run['metadata'][2]) != 0o700: raise ValueError('run_mode')
                for tag, file_name in files: self.read_metadata(run['fd'], tag, file_name)
                self.ctrl(run)
            tail, final = self.names(client, 64)
            self.roots_stable = tail == names and final == initial
            for row in self.rows:
                if row['metadata'] is None: continue
                current = meta(os.fstat(row['fd']))
                edge = meta(os.stat(row['name'], dir_fd=row['parent'], follow_symlinks=False))
                directory = stat.S_ISDIR(row['metadata'][2])
                width = 5 if directory else 9
                if current[:width] != row['metadata'][:width] or edge[:width] != row['metadata'][:width]:
                    self.roots_stable = False
            self.reason = 'observed' if self.roots_stable else 'metadata_changed'
        except (OSError, ValueError, UnicodeError): self.reason = 'observation_unknown'
        finally: self.close()

    def close(self):
        for row in reversed(self.rows):
            if row['fd'] is None: row['closed'] = True; continue
            if row['close_called'] or row['metadata'] is None: continue
            row['close_called'] = True
            try:
                if meta(os.fstat(row['fd']))[:5] != row['metadata'][:5]: continue
                os.close(row['fd'])
                try: os.fstat(row['fd'])
                except OSError as error: row['closed'] = error.errno == errno.EBADF
            except OSError: pass

    def result(self):
        return dict(reason=self.reason, roots_stable=self.roots_stable,
            metadata_file_count=len(self.private_files), decoded_count=len(self.summaries),
            ctrl_socket_count=self.ctrl_socket_count, ctrl_entry_count=self.ctrl_entry_count,
            resources_closed=all(row['closed'] for row in self.rows), summaries=self.summaries,
            private_files=self.private_files, private_ctrl=self.private_ctrl,
            active_session_verified=False, restoration_verified=False, receive_admission=False,
            device_mutations=False, radio_operations=False, full_schema_validated=False)


def observe():
    value = Observation(); value.run(); return value.result()
