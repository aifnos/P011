"""Bounded original CLIENT-source collision observation; no recovery/admission.

Fixed two previously sampled directories, fresh held metadata each time. /proc
exe/argv are checked for directory references; only matching actors' fd links
are inspected. /proc/locks is DATA, not a flock request or ownership receipt.
No journal/user contents, subprocess, signals, locks, RF or filesystem writes.
Names, paths, PID, cmdline and lock rows remain private. Incomplete != absent.
"""
import errno
import os
import re
import stat
import sys
import time

RUN_NAMES = ('client-2d974ccd59518cb1db491aa3f1601d2f',
             'client-e87c63218bf64fb28df191ead67122a1')
PHYSICAL_ROOT = '/var/volatile/tmp/p011-mta-client-rfinit'
ALIAS_ROOT = '/tmp/p011-mta-client-rfinit'
MAX_PROCESSES, MAX_FDS, MAX_CMDLINE, MAX_LOCKS = 512, 128, 4096, 65536


def meta(raw):
    return tuple(getattr(raw, key) for key in ('st_dev', 'st_ino', 'st_mode', 'st_uid',
        'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def referenced(value, paths):
    if type(value) is bytes:
        return any(path.encode('utf-8') in value for path in paths)
    return type(value) is str and any(path in value for path in paths)


def stat_identity(raw, pid):
    end = raw.rindex(b')'); fields = raw[end + 2:].split()
    if int(raw.split(b' ', 1)[0]) != pid or len(fields) < 20: raise ValueError('proc_stat')
    return int(fields[19]), fields[0], int(fields[6])


class Observation:
    def __init__(self):
        self.until = time.monotonic() + 10.0
        self.rows, self.anchors, self.run_rows, self.lock_rows = [], [], [], []
        self.private_actors, self.private_locks, self.private_failures = [], [], []
        self.reason = 'not_started'
        self.roots_stable = self.proc_inventory_stable = False
        self.process_limit_hit = self.proc_scan_complete = self.locks_complete = False
        self.process_count = self.process_observed_count = self.proc_unknown_count = 0
        self.matching_actor_count = self.matching_fd_links = self.fd_unknown_count = 0
        self.matching_lock_count = 0

    def check(self):
        if time.monotonic() >= self.until: raise ValueError('observation_deadline')
        if any(row['fd'] is not None and row['metadata'] is None for row in self.rows):
            raise ValueError('descriptor_unknown')

    def open(self, parent, name, directory=False, private=False):
        self.check()
        row = dict(parent=parent, name=name, fd=None, metadata=None,
                   close_called=False, closed=False)
        self.rows.append(row)
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
        if directory: flags |= os.O_DIRECTORY
        row['fd'] = os.open(name, flags, dir_fd=parent)
        raw = os.fstat(row['fd']); row['metadata'] = meta(raw)
        if (directory and not stat.S_ISDIR(raw.st_mode) or
                not directory and not stat.S_ISREG(raw.st_mode) or
                private and (raw.st_uid != 0 or raw.st_gid != 0 or stat.S_IMODE(raw.st_mode) != 0o700)):
            raise ValueError('entry_type')
        if meta(os.stat(name, dir_fd=parent, follow_symlinks=False)) != row['metadata']:
            raise ValueError('entry_changed')
        self.check(); return row

    def close_row(self, row):
        if row['fd'] is None: row['closed'] = True; return
        if row['close_called'] or row['metadata'] is None: return
        row['close_called'] = True
        try:
            if meta(os.fstat(row['fd']))[:5] != row['metadata'][:5]: return
            os.close(row['fd'])
            try: os.fstat(row['fd'])
            except OSError as error: row['closed'] = error.errno == errno.EBADF
        except OSError: pass

    def read(self, parent, name, limit):
        row = self.open(parent, name)
        try:
            parts, count = [], 0
            while count < limit:
                self.check(); block = os.read(row['fd'], min(4096, limit - count))
                count += len(block); parts.append(block)
                if not block: break
            if meta(os.fstat(row['fd']))[:5] != row['metadata'][:5]: raise ValueError('proc_file_changed')
            raw = b''.join(parts)
            return raw, count < limit
        finally: self.close_row(row)

    def names(self, row):
        self.check(); before = meta(os.fstat(row['fd']))
        names = os.listdir(row['fd'])
        if any(type(name) is not str or not name or name in ('.', '..') or
               '/' in name or '\x00' in name for name in names): raise ValueError('names_unknown')
        if meta(os.fstat(row['fd'])) != before: raise ValueError('directory_changed')
        return names, before

    def actor(self, proc, name, paths):
        pid = int(name); row = None
        item = dict(pid=pid, start=None, exe=None, command=None, matched=False,
                    fd_links=[], fd_complete=False, error=None)
        try:
            row = self.open(proc['fd'], name, True)
            raw, complete = self.read(row['fd'], 'stat', 4096)
            if not complete: raise ValueError('proc_stat_budget')
            identity = stat_identity(raw, pid); item['start'] = identity[0]
            command, cmd_complete = self.read(row['fd'], 'cmdline', MAX_CMDLINE)
            if not cmd_complete: raise ValueError('proc_cmdline_budget')
            try: exe = os.readlink('exe', dir_fd=row['fd'])
            except OSError as error:
                # Kernel threads/zombies with empty argv have no userspace exe.
                # This is a local nonrunning observation, not ownership closure.
                if error.errno == errno.ENOENT and not command and (identity[1] in (b'Z', b'X') or identity[2] & 0x200000):
                    exe = None
                else: raise
            after, complete = self.read(row['fd'], 'stat', 4096)
            if not complete or stat_identity(after, pid)[0] != identity[0]: raise ValueError('proc_identity_changed')
            item['exe'], item['command'] = exe, command
            item['matched'] = referenced(exe, paths) or referenced(command, paths)
            self.process_observed_count += 1
            if not item['matched']: return
            self.matching_actor_count += 1
            self.private_actors.append(item)
            fd_dir = None
            try:
                fd_dir = self.open(row['fd'], 'fd', True)
                names, unused = self.names(fd_dir)
                if len(names) > MAX_FDS: raise ValueError('proc_fd_budget')
                for fd_name in names:
                    self.check()
                    if not fd_name.isdigit(): raise ValueError('proc_fd_name')
                    link = os.readlink(fd_name, dir_fd=fd_dir['fd'])
                    if referenced(link, paths):
                        item['fd_links'].append((int(fd_name), link)); self.matching_fd_links += 1
                item['fd_complete'] = True
            except (OSError, ValueError) as error:
                self.fd_unknown_count += 1; item['error'] = type(error).__name__
            finally:
                if fd_dir is not None: self.close_row(fd_dir)
            last, complete = self.read(row['fd'], 'stat', 4096)
            if not complete or stat_identity(last, pid)[0] != identity[0]: raise ValueError('proc_identity_changed')
        except (OSError, ValueError, IndexError, OverflowError) as error:
            self.proc_unknown_count += 1
            self.private_failures.append(dict(pid=pid, error=type(error).__name__))
            if item['matched']: item['error'] = type(error).__name__
        finally:
            if row is not None: self.close_row(row)

    def locks(self, proc):
        raw, complete = self.read(proc['fd'], 'locks', MAX_LOCKS)
        self.locks_complete = complete
        for line in raw.splitlines():
            self.check()
            fields = line.split()
            if not fields: continue
            matches = [re.fullmatch(br'([0-9a-fA-F]+):([0-9a-fA-F]+):([0-9]+)', field) for field in fields]
            matches = [match for match in matches if match is not None]
            if len(matches) != 1: self.locks_complete = False; continue
            match = matches[0]
            identity = (int(match.group(1), 16), int(match.group(2), 16), int(match.group(3)))
            if any(identity == row['device_inode'] for row in self.lock_rows):
                self.matching_lock_count += 1; self.private_locks.append(line.decode('ascii', 'replace'))

    def run(self):
        try:
            if sys.platform != 'linux' or os.geteuid() != 0: raise ValueError('unsupported_platform')
            root = self.open(None, '/', True); self.anchors.append(root)
            var = self.open(root['fd'], 'var', True); self.anchors.append(var)
            volatile = self.open(var['fd'], 'volatile', True); self.anchors.append(volatile)
            tmp = self.open(volatile['fd'], 'tmp', True); self.anchors.append(tmp)
            client = self.open(tmp['fd'], 'p011-mta-client-rfinit', True, True); self.anchors.append(client)
            for name in RUN_NAMES:
                run = self.open(client['fd'], name, True, True); self.run_rows.append(run)
                try:
                    lock = os.stat('journal.lock', dir_fd=run['fd'], follow_symlinks=False)
                    if not stat.S_ISREG(lock.st_mode) or lock.st_uid != 0: raise ValueError('lock_metadata')
                    self.lock_rows.append(dict(parent=run['fd'], name='journal.lock', metadata=meta(lock),
                        device_inode=(os.major(lock.st_dev), os.minor(lock.st_dev), lock.st_ino)))
                except OSError as error:
                    if error.errno != errno.ENOENT: raise
            paths = tuple(prefix + '/' + name for prefix in (PHYSICAL_ROOT, ALIAS_ROOT) for name in RUN_NAMES)
            proc = self.open(root['fd'], 'proc', True)
            names, unused = self.names(proc)
            names = sorted((name for name in names if name.isdigit()), key=int)
            self.process_count = len(names); self.process_limit_hit = len(names) > MAX_PROCESSES
            for name in names[:MAX_PROCESSES]: self.check(); self.actor(proc, name, paths)
            self.locks(proc)
            tail, unused = self.names(proc)
            self.proc_inventory_stable = sorted((name for name in tail if name.isdigit()), key=int) == names
            self.proc_scan_complete = (not self.process_limit_hit and self.proc_unknown_count == 0 and
                self.process_observed_count == self.process_count and self.proc_inventory_stable)
            self.roots_stable = True
            for row in self.anchors + self.run_rows:
                current = meta(os.fstat(row['fd']))
                edge = meta(os.stat(row['name'], dir_fd=row['parent'], follow_symlinks=False))
                width = 9 if row in self.run_rows or row is client else 5
                if current[:width] != row['metadata'][:width] or edge[:width] != row['metadata'][:width]:
                    self.roots_stable = False
            for row in self.lock_rows:
                if meta(os.stat(row['name'], dir_fd=row['parent'], follow_symlinks=False)) != row['metadata']:
                    self.roots_stable = False
            self.reason = 'observed' if self.roots_stable else 'roots_changed'
        except (OSError, ValueError, IndexError, OverflowError): self.reason = 'observation_unknown'
        finally:
            for row in reversed(self.rows): self.close_row(row)

    def result(self):
        return dict(reason=self.reason, roots_stable=self.roots_stable,
            proc_inventory_stable=self.proc_inventory_stable, proc_scan_complete=self.proc_scan_complete,
            process_limit_hit=self.process_limit_hit, process_count=self.process_count,
            process_observed_count=self.process_observed_count, proc_unknown_count=self.proc_unknown_count,
            matching_actor_count=self.matching_actor_count, matching_fd_links=self.matching_fd_links,
            fd_unknown_count=self.fd_unknown_count, locks_complete=self.locks_complete,
            matching_lock_count=self.matching_lock_count, fresh_lock_identity_count=len(self.lock_rows),
            all_process_fds_scanned=False, resources_closed=all(row['closed'] for row in self.rows),
            active_session_verified=False, restoration_verified=False, receive_admission=False,
            device_mutations=False, radio_operations=False,
            private_actors=self.private_actors, private_locks=self.private_locks,
            private_failures=self.private_failures, private_lock_metadata=self.lock_rows)


def observe():
    value = Observation(); value.run(); return value.result()
