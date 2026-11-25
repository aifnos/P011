"""Independent, read-only ConnMan observations for the receive finalizer.

Python 3.5 / P011 Linux only. A pinned ARM executable is opened once and
executed through that original descriptor, never a shell or browser argument.
Observations and raw output contain private service/address data. They are not
admission or restoration certificates: the caller must also authenticate its
original operation, CLIENT Parent, radio and storage/resource closure.
"""
import hashlib
import math
import os
import re
import stat
import subprocess
import threading
import time

import p011_json


SCHEMA = 'p011-connman-network-baseline-v1'
_OWNER = re.compile(r'^:[0-9]+\.[0-9]+$')
_UUID = re.compile(r'^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$')
_SHA = re.compile(r'^[0-9a-f]{64}$')
_PATH = re.compile(r'^/[A-Za-z0-9_/]+$')
_BOOL_PROPERTIES = ('auto_connect', 'favorite', 'immutable')
_IP_PROPERTIES = ('ipv4', 'ipv6', 'ipv4_configuration', 'ipv6_configuration')
_DNS_PROPERTIES = ('nameservers', 'nameservers_configuration')
_STATES = ('idle', 'association', 'configuration', 'ready', 'online', 'disconnect', 'failure')


class NetworkObservationError(ValueError):
    def __init__(self, code):
        self.code = code
        ValueError.__init__(self, code)


def _fail(code):
    raise NetworkObservationError(code)


def _integer(value, low, high):
    return type(value) is int and low <= value <= high


def _string(value, limit=256):
    return (type(value) is str and len(value) <= limit and
            not any(ord(char) < 32 or 0xd800 <= ord(char) <= 0xdfff for char in value))


def _presence(row, validator):
    if (type(row) is not dict or set(row) != {'present', 'value'} or
            type(row['present']) is not bool):
        _fail('network_presence')
    if not row['present']:
        if row['value'] is not None:
            _fail('network_presence')
        return (False, None)
    return (True, validator(row['value']))


def _boolean(value):
    if type(value) is not bool:
        _fail('network_boolean')
    return value


def _ip(value, ipv6=False):
    allowed = {'Method', 'Address', 'Gateway'}
    allowed.update({'PrefixLength', 'Privacy'} if ipv6 else {'Netmask'})
    if type(value) is not dict or not set(value).issubset(allowed):
        _fail('network_ip_fields')
    for key, item in value.items():
        if key == 'PrefixLength':
            if not _integer(item, 0, 128):
                _fail('network_ip_value')
        elif not _string(item):
            _fail('network_ip_value')
    return tuple(sorted(value.items()))


def _dns(value):
    if type(value) is not list or len(value) > 32 or not all(_string(item) for item in value):
        _fail('network_dns')
    # Ordering is significant: do not sort or turn the actual list into a set.
    return tuple(value)


def normalize(observation):
    """Strict immutable DATA; absent, empty, null and unknown are different."""
    if (type(observation) is not dict or observation.get('event') != 'network_observation' or
            observation.get('network_schema') != SCHEMA):
        _fail('network_schema')
    for field in ('ok', 'identity_known', 'technologies_known', 'services_known',
                  'bus_closed', 'proc_files_closed'):
        if observation.get(field) is not True:
            _fail('network_unknown')
    if observation.get('profile_bytes_observed') is not False or observation.get('reason') != 'ok':
        _fail('network_scope')
    owner, boot, exe, digest = (observation.get(name) for name in
        ('connman_owner', 'boot_id', 'connman_exe', 'connman_exe_sha256'))
    pid, start = observation.get('connman_pid'), observation.get('connman_start')
    if (not _string(owner, 64) or _OWNER.fullmatch(owner) is None or
            not _string(boot, 36) or _UUID.fullmatch(boot) is None or
            not _string(exe, 512) or not exe.startswith('/') or
            not _string(digest, 64) or _SHA.fullmatch(digest) is None or
            not _integer(pid, 1, 2**31-1) or not _integer(start, 1, 2**63-1)):
        _fail('network_identity')
    technologies, services = observation.get('technologies'), observation.get('services')
    if type(technologies) is not list or len(technologies) > 8:
        _fail('network_technologies')
    tech_rows = []
    for row in technologies:
        if (type(row) is not dict or set(row) != {'path', 'powered'} or
                not _string(row['path'], 512) or _PATH.fullmatch(row['path']) is None or
                not row['path'].startswith('/net/connman/technology/') or
                type(row['powered']) is not bool):
            _fail('network_technology_fields')
        tech_rows.append((row['path'], row['powered']))
    if len({row[0] for row in tech_rows}) != len(tech_rows):
        _fail('network_technology_duplicate')
    if type(services) is not list or len(services) > 128:
        _fail('network_services')
    service_rows = []
    expected = {'path', 'state'} | set(_BOOL_PROPERTIES + _IP_PROPERTIES + _DNS_PROPERTIES)
    for row in services:
        if (type(row) is not dict or set(row) != expected or
                not _string(row['path'], 512) or _PATH.fullmatch(row['path']) is None or
                not row['path'].startswith('/net/connman/service/') or
                type(row['state']) is not str or row['state'] not in _STATES):
            _fail('network_service_fields')
        props = tuple(_presence(row[key], _boolean) for key in _BOOL_PROPERTIES)
        ips = tuple(_presence(row[key], lambda value, v6=('ipv6' in key): _ip(value, v6))
                    for key in _IP_PROPERTIES)
        dns = tuple(_presence(row[key], _dns) for key in _DNS_PROPERTIES)
        service_rows.append((row['path'], row['state'], props, ips, dns))
    if len({row[0] for row in service_rows}) != len(service_rows):
        _fail('network_service_duplicate')
    return (SCHEMA, owner, pid, start, boot, exe, digest,
            tuple(sorted(tech_rows)), tuple(sorted(service_rows)))


class NetworkObservation(object):
    """Original per-call inventory; repr intentionally hides private data."""
    def __init__(self, owner, phase_until):
        self._owner = owner
        self.phase_until = phase_until
        self.valid = False
        self.baseline = None
        self.error = None
        self.raw_stdout = self.raw_stderr = None
        self._ticket = {'fd': None, 'fd_open_called': False, 'fd_open_resolved': False,
            'fd_closed': False, 'spawn_called': False, 'spawn_resolved': False,
            'process': None, 'stdout': None, 'stderr': None, 'reaped': False,
            'finished': False, 'close_error': False}

    def __repr__(self):
        return '<NetworkObservation valid=%r error=%r>' % (self.valid, self.error)

    def resources_closed(self):
        ticket = self._ticket
        if not ticket['finished'] or ticket['close_error']:
            return False
        if ticket['fd_open_called'] and not ticket['fd_open_resolved']:
            return False
        if ticket['fd'] is not None and not ticket['fd_closed']:
            return False
        if ticket['spawn_called']:
            if not ticket['spawn_resolved'] or ticket['process'] is None or not ticket['reaped']:
                return False
            if any(stream is None or stream.closed is not True for stream in
                   (ticket['stdout'], ticket['stderr'])):
                return False
        return True


class NetworkObserver(object):
    """Pure construction, synchronous original calls, no renewed deadline."""
    def __init__(self, binary_path, binary_size, binary_sha256, lifetime_until, clock=time.monotonic):
        # First assignments permit a retained partial constructor to prove that
        # it has performed no IO; a bare __new__ object remains unknown.
        self._calls = []
        self._active = False
        self._lock = threading.Lock()
        self._initialized = False
        if (not _string(binary_path, 512) or not binary_path.startswith('/') or
                '\x00' in binary_path or not _integer(binary_size, 52, 1048576) or
                not _string(binary_sha256, 64) or _SHA.fullmatch(binary_sha256) is None or
                type(lifetime_until) is not float or not math.isfinite(lifetime_until) or
                not 0 < lifetime_until < 2**53 or not callable(clock)):
            _fail('observer_configuration')
        self.binary_path, self.binary_size, self.binary_sha256 = binary_path, binary_size, binary_sha256
        self.lifetime_until, self.clock = lifetime_until, clock
        self._original_spec = (binary_path, binary_size, binary_sha256, lifetime_until, clock)
        self._initialized = True

    def _remaining(self, until):
        now = self.clock()
        if type(now) is not float or not math.isfinite(now) or now >= until:
            _fail('observer_deadline')
        return until - now

    def observe(self, phase_until):
        if not self._initialized or not self._lock.acquire(False):
            _fail('observer_busy')
        observed = NetworkObservation(self, phase_until)
        self._calls.append(observed)  # Before first clock, open or Popen.
        self._active = True
        ticket = observed._ticket
        until = None
        try:
            if (type(phase_until) is not float or not math.isfinite(phase_until) or
                    not 0 < phase_until <= self.lifetime_until or
                    self._original_spec != (self.binary_path, self.binary_size, self.binary_sha256,
                                            self.lifetime_until, self.clock)):
                _fail('observer_deadline')
            now = self.clock()
            if type(now) is not float or not math.isfinite(now):
                _fail('observer_clock')
            until = min(phase_until, self.lifetime_until, now + 10.0)
            self._remaining(until)
            ticket['fd_open_called'] = True
            try:
                # P011 ARM constants; do not reuse x86 O_NOFOLLOW values.
                ticket['fd'] = os.open(self.binary_path, 0x88000)
                ticket['fd_open_resolved'] = True
            except OSError:
                ticket['fd_open_resolved'] = True  # open returned no descriptor.
                raise
            fd = ticket['fd']
            before = os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_gid != 0 or
                    stat.S_IMODE(before.st_mode) != 0o700 or before.st_size != self.binary_size):
                _fail('observer_binary_identity')
            raw, digest = bytearray(), hashlib.sha256()
            while True:
                self._remaining(until)
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                raw.extend(chunk)
                digest.update(chunk)
                if len(raw) > self.binary_size:
                    _fail('observer_binary_limit')
            after = os.fstat(fd)
            identity = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_uid,
                                     item.st_gid, item.st_size, item.st_mtime, item.st_ctime)
            if (identity(before) != identity(after) or len(raw) != self.binary_size or
                    digest.hexdigest() != self.binary_sha256 or raw[:5] != b'\x7fELF\x01' or
                    raw[5] != 1 or raw[18:20] != b'\x28\x00'):
                _fail('observer_binary_identity')
            # Reserve closure time from the same original cap, never renew it.
            seconds = min(8.0, self._remaining(until) - 1.0)
            if seconds <= 0:
                _fail('observer_deadline')
            ticket['spawn_called'] = True
            process = subprocess.Popen(['/proc/self/fd/%d' % fd, '--observe'],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                close_fds=True, pass_fds=(fd,))
            ticket['process'], ticket['spawn_resolved'] = process, True
            ticket['stdout'], ticket['stderr'] = process.stdout, process.stderr
            observed.raw_stdout, observed.raw_stderr = process.communicate(timeout=seconds)
            ticket['reaped'] = process.returncode is not None
            self._remaining(until)
            if process.returncode != 0 or observed.raw_stderr:
                _fail('observer_native_exit')
            if not 0 < len(observed.raw_stdout) <= 65536:
                _fail('observer_output_limit')
            # Always use the bundled strict codec; duplicate keys are rejected.
            data = p011_json.loads(observed.raw_stdout.decode('utf-8', 'strict'))
            observed.baseline = normalize(data)
            self._remaining(until)
        except NetworkObservationError as error:
            observed.error = error.code
        except subprocess.TimeoutExpired:
            observed.error = 'observer_timeout'
        except BaseException:
            observed.error = 'observer_io_error'
        finally:
            process = ticket['process']
            if process is not None and not ticket['reaped']:
                try:
                    # Only the original readonly child. No PID search/global kill.
                    process.kill()
                    budget = self._remaining(until)
                    observed.raw_stdout, observed.raw_stderr = process.communicate(timeout=budget)
                    ticket['reaped'] = process.returncode is not None
                except BaseException:
                    ticket['close_error'] = True
            for stream in (ticket['stdout'], ticket['stderr']):
                if stream is not None:
                    try:
                        stream.close()
                    except BaseException:
                        ticket['close_error'] = True
            if ticket['fd'] is not None:
                try:
                    os.close(ticket['fd'])
                    ticket['fd_closed'] = True
                except BaseException:
                    ticket['close_error'] = True
            ticket['finished'] = True
            self._active = False
            self._lock.release()
        if observed.error is None:
            try:
                self._remaining(until)  # Parsing and actual closure use the original cap too.
            except NetworkObservationError as error:
                observed.error = error.code
            except BaseException:
                observed.error = 'observer_clock'
        observed.valid = (observed.error is None and observed.baseline is not None and
                          observed.resources_closed())
        return observed

    def resources_closed(self):
        try:
            return (type(self._calls) is list and self._active is False and
                    all(type(item) is NetworkObservation and item._owner is self and
                        item.resources_closed() for item in self._calls))
        except BaseException:
            return False

    def close(self):
        # No new IO or time window. A live synchronous call is not borrowed.
        return self.resources_closed()


def compare_observations(before, after):
    """Original closed calls plus strict DATA, not independent RF authority."""
    try:
        return (type(before) is NetworkObservation and type(after) is NetworkObservation and
                before is not after and type(before._owner) is NetworkObserver and
                before._owner is after._owner and before in before._owner._calls and
                after in before._owner._calls and before.valid is True and after.valid is True and
                before.baseline is not None and before.baseline == after.baseline and
                before.resources_closed() and after.resources_closed() and
                before._owner.resources_closed())
    except BaseException:
        return False
