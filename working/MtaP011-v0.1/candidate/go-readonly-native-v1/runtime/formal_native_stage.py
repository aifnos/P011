"""Fixed readonly-native-v1 files-only stage; no Boot/Owner/helper execution.

One native-only bounded batch preserves the original decoded 4 MiB limit.
Imports/default main do not stage. Explicit stage() accepts only fixed immutable
byte payloads. Existing complete inventories are re-read, not adopted by receipt.
Conflicts and partial publications remain untouched. No CLIENT/pending reads,
RF, scan, helper spawn, restoration grant, overwrite, deletion or permission repair.
"""
import errno
import hashlib
import math
import os
import stat
import sys
import threading
import time

RAW_LIMIT = 4 * 1024 * 1024
MAX_SECONDS = 120.0
PROFILE_TOTALS = (('native', 2, 113296),)
SERVICE_PARENTS = ()
PROFILE_FILES = (
    ('native', '/var/volatile/tmp/p011-mta-go-readonly-native-v1', (
        ('native/mta-bluez-helper', 65832, '179fd01f737acd30c7e903d6925217d9e0467400187614189d06a4cffdc44363', 320),
        ('native/mta-network-helper', 47464, 'ef3b904ef1017b6f0011b1e2cfcadbc98f9e8026933153ff0291699f32c525e6', 320),
    )),
)








































_PROFILE_FILES_ORIGINAL = PROFILE_FILES
_RETAINED = None


class StageError(ValueError):
    def __init__(self, code):
        self.code = code
        ValueError.__init__(self, code)


def fail(code):
    raise StageError(code) from None


def meta(value):
    return tuple(getattr(value, name) for name in
                 ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
                  'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def identity(value):
    return value[:5]


class FixedStage(object):
    def __init__(self, profile, original_until):
        self.rows = self._rows_original = []
        self.edges = self._edges_original = []
        self.creations = self._creations_original = []
        self.failures = []
        self.first_error = None
        self.close_failure = None
        self.profile = self._profile_original = profile
        choices = [row for row in PROFILE_FILES if type(profile) is str and row[0] == profile]
        if len(choices) != 1:
            fail('profile')
        if type(original_until) is not float or not math.isfinite(original_until) or not 0 < original_until < 1e12:
            fail('deadline')
        self.spec = self._spec_original = choices[0]
        self.until = self._until_original = original_until
        self.worker = self._worker_original = threading.current_thread()
        self.pid = self._pid_original = os.getpid()
        self.clock = self._clock_original = time.monotonic
        self.last = self.issued = None
        self.alias_original = None
        self.called = self.ended = self.complete = self.close_called = self.closed = False
        self.raws = None
        self.base = self.var = self.volatile = self.tmp = None
        self.snapshots = []
        self.service_parent_facts = []
        self.created_files = self.created_directories = 0
        self.existing_complete = False

    def context(self):
        if (self.rows is not self._rows_original or self.edges is not self._edges_original or
                self.creations is not self._creations_original or self.spec is not self._spec_original or
                PROFILE_FILES is not _PROFILE_FILES_ORIGINAL or self.until is not self._until_original or
                self.profile is not self._profile_original or self.profile != self.spec[0] or
                self.clock is not self._clock_original or self.clock is not time.monotonic or
                self.worker is not self._worker_original or threading.current_thread() is not self.worker or
                self.pid != self._pid_original or os.getpid() != self.pid):
            fail('original_changed')

    def now(self):
        self.context()
        value = self.clock()
        if (type(value) not in (int, float) or not math.isfinite(value) or
                not 0 <= value < 1e12 or self.last is not None and value < self.last or value >= self.until):
            fail('deadline')
        self.last = float(value)
        return self.last

    def platform(self):
        if (sys.platform != 'linux' or sys.byteorder != 'little' or os.geteuid() != 0 or
                os.uname()[4] != 'armv7l' or tuple(sys.version_info[:3]) != (3, 5, 5) or
                sys.flags.optimize or os.O_NOFOLLOW != 0x8000 or os.O_CLOEXEC != 0x80000):
            fail('platform')

    def payload(self, value):
        expected = self.spec[2]
        total = next(row for row in PROFILE_TOTALS if row[0] == self.profile)
        if (type(value) is not tuple or len(value) != total[1] or len(expected) != total[1] or
                sum(row[1] for row in expected) != total[2] or not 0 < total[2] <= RAW_LIMIT):
            fail('payload')
        retained = []
        for item, pin in zip(value, expected):
            self.now()
            if (type(item) is not tuple or len(item) != 2 or item[0] != pin[0] or
                    type(item[1]) is not bytes or len(item[1]) != pin[1] or
                    hashlib.sha256(item[1]).hexdigest() != pin[2]):
                fail('payload')
            retained.append(item)
        self.raws = tuple(retained)

    def aliases(self):
        self.now()
        result = []
        for path, target in (('/tmp', '/var/tmp'), ('/var/tmp', '/var/volatile/tmp')):
            observed = meta(os.lstat(path))
            if (observed[2] != stat.S_IFLNK | 0o777 or observed[3:6] != (0, 0, 1) or
                    observed[6] != len(target) or os.readlink(path) != target):
                fail('alias')
            result.append((path, observed, target))
        value = tuple(result)
        if self.alias_original is None:
            self.alias_original = value
        elif value != self.alias_original:
            fail('alias_changed')
        self.now()

    def open_row(self, parent, name, flags, mode, kind):
        self.now()
        self.edges_current()
        if kind == 'file':
            flags |= os.O_NONBLOCK
        row = dict(parent=parent, name=name, flags=flags, mode=mode, kind=kind,
                   fd=None, original_fd=None, metadata=None, original_identity=None,
                   open_called=False, returned=False, no_fd=False, unknown=True,
                   close_called=False, close_return=None, close_error=None, closed=False,
                   ebadf=False, failure=None, raw_sha=None)
        self.rows.append(row)
        row['open_called'] = True
        try:
            fd = os.open(name, flags | os.O_NOFOLLOW | os.O_CLOEXEC, mode,
                         dir_fd=None if parent is None else parent['fd'])
            row['fd'] = row['original_fd'] = fd
            row['returned'] = True
            if type(fd) is not int or fd < 0:
                fail('descriptor_unknown')
            observed = meta(os.fstat(fd))
            row['metadata'] = observed
            row['original_identity'] = identity(observed)
            collisions = [old for old in self._rows_original if old is not row and
                          old['returned'] and not old['closed'] and old['fd'] == fd]
            if collisions:
                error = StageError('descriptor_unknown')
                for original in collisions + [row]:
                    original['unknown'] = True
                    if original['failure'] is None:
                        original['failure'] = error
                raise error
            row['unknown'] = False
            self.now()
            return row
        except OSError as error:
            row['failure'] = error
            if (row['returned'] is False and row['fd'] is None and
                    type(error.errno) is int and 1 <= error.errno <= 4095):
                row['no_fd'] = row['closed'] = True
                row['unknown'] = False
            raise
        except BaseException as error:
            row['failure'] = error
            raise

    def close_row(self, row):
        try:
            self.context()
            if not any(row is original for original in self._rows_original):
                return False
            if row['close_called']:
                return row['closed'] is True and row['unknown'] is False
            if row['no_fd']:
                return row['returned'] is False and row['fd'] is None and row['unknown'] is False and row['closed'] is True
            if (row['unknown'] or not row['returned'] or row['fd'] is not row['original_fd'] or
                    row['original_identity'] is None):
                return False
            row['close_called'] = True
            current = meta(os.fstat(row['fd']))
            if identity(current) != row['original_identity']:
                fail('close_identity')
            row['close_return'] = os.close(row['fd'])
            try:
                os.fstat(row['fd'])
            except OSError as error:
                row['close_error'] = error
                row['ebadf'] = type(error.errno) is int and error.errno == errno.EBADF
                row['closed'] = row['close_return'] is None and row['ebadf']
            if row['closed'] is not True:
                row['unknown'] = True
        except BaseException as error:
            row['unknown'] = True
            row['failure'] = error
            self.failures.append(error)
            if self.close_failure is None:
                self.close_failure = error
        return row['closed'] is True and row['unknown'] is False

    def directory(self, parent, name, mode):
        self.now()
        before = meta(os.stat(name, dir_fd=None if parent is None else parent['fd'], follow_symlinks=False))
        if (before[2] != stat.S_IFDIR | mode or before[3:5] != (0, 0) or before[5] < 1):
            fail('directory_policy')
        row = self.open_row(parent, name, os.O_RDONLY | os.O_DIRECTORY, mode, 'directory')
        if identity(row['metadata']) != identity(before):
            fail('directory_changed')
        self.edges.append((parent, name, row))
        self.edges_current()
        return row

    def edges_current(self):
        self.context()
        self.aliases_current()
        for parent, name, row in self._edges_original:
            if (row['unknown'] or row['closed'] or row['close_called'] or row['fd'] is not row['original_fd'] or
                    parent is not row['parent'] or name != row['name']):
                fail('directory_changed')
            current = meta(os.fstat(row['fd']))
            path = meta(os.stat(name, dir_fd=None if parent is None else parent['fd'], follow_symlinks=False))
            if (identity(current) != row['original_identity'] or identity(path) != row['original_identity'] or
                    current[2] != stat.S_IFDIR | row['mode'] or current[3:5] != (0, 0)):
                fail('directory_changed')

    def aliases_current(self):
        if self.alias_original is None:
            return
        for path, original, target in self.alias_original:
            if meta(os.lstat(path)) != original or os.readlink(path) != target:
                fail('alias_changed')

    def names(self, row):
        self.now()
        self.edges_current()
        os.lseek(row['fd'], 0, os.SEEK_SET)
        names = os.listdir(row['fd'])
        if type(names) is not list or any(type(name) is not str for name in names):
            fail('inventory_unknown')
        self.now()
        self.edges_current()
        return tuple(sorted(names))

    def present(self, parent, name):
        self.now()
        self.edges_current()
        try:
            value = meta(os.stat(name, dir_fd=parent['fd'], follow_symlinks=False))
        except OSError as error:
            if type(error.errno) is int and error.errno == errno.ENOENT:
                self.now()
                return None
            raise
        self.now()
        return value

    def tree_names(self, pins):
        children = {}
        for path, size, sha, mode in pins:
            parts = path.split('/')
            if len(parts) > 2 or any(not part or part in ('.', '..') for part in parts):
                fail('fixed_path')
            children.setdefault('', set()).add(parts[0])
            if len(parts) == 2:
                children.setdefault(parts[0], set()).add(parts[1])
        return dict((key, tuple(sorted(value))) for key, value in children.items())

    def read_file(self, parent, name, pin):
        self.now()
        self.edges_current()
        before = meta(os.stat(name, dir_fd=parent['fd'], follow_symlinks=False))
        if (before[2] != stat.S_IFREG | pin[3] or before[3:6] != (0, 0, 1) or before[6] != pin[1]):
            fail('file_policy')
        row = self.open_row(parent, name, os.O_RDONLY, pin[3], 'file')
        primary = None
        try:
            if row['metadata'] != before:
                fail('file_changed')
            count = 0
            digest = hashlib.sha256()
            while count <= pin[1]:
                self.now()
                data = os.read(row['fd'], min(65536, pin[1] + 1 - count))
                if type(data) is not bytes:
                    fail('read_unknown')
                self.now()
                digest.update(data)
                count += len(data)
                if not data:
                    break
            row['raw_sha'] = digest.hexdigest()
            if (count != pin[1] or row['raw_sha'] != pin[2] or meta(os.fstat(row['fd'])) != before or
                    meta(os.stat(name, dir_fd=parent['fd'], follow_symlinks=False)) != before):
                fail('file_changed')
            self.edges_current()
        except BaseException as error:
            primary = row['failure'] = error
        finally:
            if self.close_row(row) is not True and primary is None:
                primary = StageError('file_close')
        if primary is not None:
            raise primary
        return before

    def inspect(self, spec):
        name = spec[1].rsplit('/', 1)[1]
        observed = self.present(self.tmp, name)
        if observed is None:
            return None
        root = self.directory(self.tmp, name, 0o700)
        expected = self.tree_names(spec[2])
        if self.names(root) != expected['']:
            fail('existing_conflict')
        directories = {'': root}
        for child in ('runtime', 'native'):
            if child in expected:
                directories[child] = self.directory(root, child, 0o700)
                if self.names(directories[child]) != expected[child]:
                    fail('existing_conflict')
        files = []
        for pin in spec[2]:
            parent_name, _, basename = pin[0].rpartition('/')
            files.append((pin[0], self.read_file(directories[parent_name], basename, pin)))
        self.edges_current()
        for key, row in directories.items():
            if self.names(row) != expected[key]:
                fail('existing_changed')
        for path, original in files:
            self.now()
            parent_name, _, basename = path.rpartition('/')
            current = meta(os.stat(basename, dir_fd=directories[parent_name]['fd'], follow_symlinks=False))
            if current != original:
                fail('file_changed')
        self.edges_current()
        return (root['original_identity'], tuple((key, row['original_identity']) for key, row in sorted(directories.items())),
                tuple(files))

    def create_directory(self, parent, name):
        self.now()
        self.edges_current()
        if self.present(parent, name) is not None:
            fail('existing_changed')
        ticket = dict(parent=parent, name=name, kind='directory', called=True,
                      returned=False, unknown=True, error=None, row=None)
        self.creations.append(ticket)
        try:
            returned = os.mkdir(name, 0o700, dir_fd=parent['fd'])
            ticket['returned'] = returned is None
            ticket['unknown'] = returned is not None
            if returned is not None:
                fail('mkdir_return')
            self.created_directories += 1
            self.now()
            ticket['row'] = self.directory(parent, name, 0o700)
            self.edges_current()
            if os.fsync(parent['fd']) is not None:
                fail('sync_return')
            return ticket['row']
        except BaseException as error:
            ticket['error'] = error
            raise

    def write_file(self, parent, name, pin, raw):
        self.now()
        self.edges_current()
        ticket = dict(parent=parent, name=name, kind='file', called=True,
                      returned=False, unknown=True, error=None, row=None)
        self.creations.append(ticket)
        row = None
        primary = None
        try:
            row = self.open_row(parent, name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, pin[3], 'file')
            ticket['row'] = row
            ticket['returned'] = True
            ticket['unknown'] = False
            self.created_files += 1
            before = row['metadata']
            if before[2:7] != (stat.S_IFREG | pin[3], 0, 0, 1, 0):
                fail('new_file_policy')
            count = 0
            while count < len(raw):
                self.now()
                self.edges_current()
                if (meta(os.fstat(row['fd'])) != row['metadata'] or
                        meta(os.stat(name, dir_fd=parent['fd'], follow_symlinks=False)) != row['metadata']):
                    fail('file_changed')
                returned = os.write(row['fd'], raw[count:count + 65536])
                if type(returned) is not int or not 1 <= returned <= min(65536, len(raw) - count):
                    fail('write_return')
                count += returned
                row['metadata'] = meta(os.fstat(row['fd']))
                if row['metadata'][:6] != before[:6] or row['metadata'][6] != count:
                    fail('file_changed')
                self.now()
                self.edges_current()
            if os.fsync(row['fd']) is not None:
                fail('sync_return')
            row['metadata'] = meta(os.fstat(row['fd']))
            if self.read_file(parent, name, pin) != row['metadata']:
                fail('readback_changed')
            self.edges_current()
        except BaseException as error:
            primary = ticket['error'] = error
            if row is not None:
                row['failure'] = error
        finally:
            if row is not None and self.close_row(row) is not True and primary is None:
                primary = StageError('file_close')
        if primary is not None:
            raise primary

    def parents(self):
        self.aliases()
        self.base = self.directory(None, '/', 0o755)
        self.var = self.directory(self.base, 'var', 0o755)
        self.volatile = self.directory(self.var, 'volatile', 0o1777)
        self.tmp = self.directory(self.volatile, 'tmp', 0o1777)

    def service_parents(self):
        prepared = []
        for name in SERVICE_PARENTS:
            observed = self.present(self.tmp, name)
            existing = observed is not None
            row = self.directory(self.tmp, name, 0o700) if existing else None
            names = self.names(row) if existing else ()
            # These are future work parents, not owned historical job contents.
            # Retain and compare inventory names; never open/remove their children.
            prepared.append((name, row, existing, names))
        # Both fixed existing nodes are authenticated before either is created.
        for name, row, existing, names in prepared:
            if existing:
                if self.names(row) != names:
                    fail('service_parent_changed')
            elif self.present(self.tmp, name) is not None:
                fail('service_parent_changed')
        for name, row, existing, names in prepared:
            if not existing:
                row = self.create_directory(self.tmp, name)
                if self.names(row) != ():
                    fail('service_parent_changed')
            self.service_parent_facts.append((name, row, existing, names))
        self.edges_current()

    def service_parents_current(self):
        for name, row, existing, names in self.service_parent_facts:
            if self.names(row) != names:
                fail('service_parent_changed')

    def close(self):
        if self.close_called:
            return self.closed
        self.close_called = True
        good = True
        for row in reversed(self._rows_original):
            good = self.close_row(row) and good
        self.closed = good and all(ticket['unknown'] is False for ticket in self._creations_original)
        return self.closed

    def stage(self, fixed_raws):
        if self.called or self.close_called:
            fail('once')
        self.called = True
        try:
            self.platform()
            issued = self.now()
            self.issued = issued
            if not 0 < self.until - issued <= MAX_SECONDS:
                fail('deadline')
            self.payload(fixed_raws)
            self.parents()
            prior = []
            if self.profile == 'ordinary':
                for spec in PROFILE_FILES[:2]:
                    value = self.inspect(spec)
                    if value is None:
                        fail('prerequisite_missing')
                    prior.append((spec, value))
                    self.snapshots.append((spec, value))
            before = self.inspect(self.spec)
            self.snapshots.append((self.spec, before))
            self.existing_complete = before is not None
            # Repeat every prior/current actual inventory before any write.
            for spec, value in prior:
                if self.inspect(spec) != value:
                    fail('prerequisite_changed')
            if self.inspect(self.spec) != before:
                fail('existing_changed')
            if self.profile == 'ordinary':
                self.service_parents()
            if before is None:
                root = self.create_directory(self.tmp, self.spec[1].rsplit('/', 1)[1])
                directories = {'': root}
                expected = self.tree_names(self.spec[2])
                for child in ('runtime', 'native'):
                    if child in expected:
                        directories[child] = self.create_directory(root, child)
                for pin, item in zip(self.spec[2], self.raws):
                    parent_name, _, basename = pin[0].rpartition('/')
                    self.write_file(directories[parent_name], basename, pin, item[1])
                for row in directories.values():
                    self.now()
                    self.edges_current()
                    if os.fsync(row['fd']) is not None:
                        fail('sync_return')
            after = self.inspect(self.spec)
            if after is None or before is not None and after != before:
                fail('existing_changed')
            for spec, value in prior:
                if self.inspect(spec) != value:
                    fail('prerequisite_changed')
            self.service_parents_current()
            self.edges_current()
            self.now()
            self.complete = True
        except BaseException as error:
            if self.first_error is None:
                self.first_error = error
            self.failures.append(error)
            raise
        finally:
            self.ended = True
            self.close()
        if self.closed is not True:
            fail('close_pending')
        return self

    def result(self):
        return dict(kind='formal-send-stage-v1-files-only', profile=self.profile,
                    stage_complete=self.complete and self.closed and self.first_error is None,
                    resource_pending=not self.closed, staging_pending=bool(self.creations) and not self.complete,
                    original_fds=len(self.rows), original_fds_closed=sum(row['closed'] is True for row in self.rows),
                    created_files=self.created_files, created_directories=self.created_directories,
                    existing_complete=self.existing_complete, prerequisites=max(0, len(self.snapshots) - 1),
                    service_parent_count=len(self.service_parent_facts), receive=False, send=False,
                    boot=False, owner=False, helper=False, rf=False, restoration=False, phone=False)


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    return 0 if not args else 2


if __name__ == '__main__':
    raise SystemExit(main())
