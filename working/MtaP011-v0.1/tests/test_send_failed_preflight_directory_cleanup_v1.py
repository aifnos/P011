"""One affected Owner cleanup method, explicit syscall/Parent/Directory models.

This is not Linux close, P011, Parent child execution, RF, startup or restoration
evidence. Only selected actual Owner definitions are compiled; historical suites
and module main are not executed. _now/_boot_roles and preflight probes are seams.
"""
import ast
import errno
import hashlib
import json
import math
from pathlib import Path
import sys
import threading
import types
import unittest

BASE = Path(__file__).resolve().parents[1]
MOTHER = 'candidate/formal-send-filecenter-deploy-v6/runtime/mta_client_service_owner.py'
CANDIDATE = 'candidate/formal-send-failed-preflight-close-v1/runtime/mta_client_service_owner.py'
DELTA = 'candidate/formal-send-failed-preflight-close-v1/exactsource-delta.json'
INPUT_ROWS = (
    (MOTHER, 89599, 'f8f2bca88915d372ba685024bf995e9d746491559d5c981e83ff1a1e3d6ddea0'),
    (CANDIDATE, 103872, '97155c28caab79f579f4549439dabfe959dc9093a159238deee5f0157a62176e'),
    (DELTA, 33671, '3643fc150d922268ce27a0d22c1b7392857572961b77a8eec74fc4360cb206f6'))
CHANGED = ('__init__', '_prepare_send_trial', '_close_directories')
ADDED = ('_failed_preflight_closed_receipt', '_failed_preflight_directory_release_closed')
SELECTED = ('__init__', '_context', '_prepare_send_trial', '_close_directories',
    '_directory_definitions_current', '_directory_inventory_closed', '_filecenter_closed',
    '_http_passively_closed', '_socket_receipt', '_socket_receipt_closed',
    '_service_closed', '_closed', 'status') + ADDED
SELECTOR = 'FailedPreflightCleanup.test_actual_owner_failed_preflight_directory_release'
MARKER = 'HOST_FAILED_PREFLIGHT_DIRECTORY_CLEANUP_V1_PASS'


def need(value, code):
    if value is not True:
        raise ValueError(code)


def method_map(raw):
    tree = ast.parse(raw.decode('ascii'))
    cls = [v for v in tree.body if isinstance(v, ast.ClassDef) and
           v.name == 'FixedStateServiceOwner']
    need(len(cls) == 1, 'owner_class')
    return tree, cls[0], {v.name: v for v in cls[0].body if isinstance(v, ast.FunctionDef)}


def source_contract(inputs):
    for key, size, pin in INPUT_ROWS:
        raw = inputs[key]
        need((len(raw), hashlib.sha256(raw).hexdigest()) == (size, pin), 'source_pin')
    old, new = inputs[MOTHER], inputs[CANDIDATE]
    delta = json.loads(inputs[DELTA].decode('ascii'))
    need(delta['origin'] == list(INPUT_ROWS[0]) and
         delta['candidate'] == list(INPUT_ROWS[1]) and
         delta['changed_original_methods'] == list(CHANGED) and
         delta['new_private_methods'] == list(ADDED) and
         delta['replacement_count'] == 4, 'delta_contract')
    forward = old
    for row in delta['replacements']:
        before, after = row['before'].encode('ascii'), row['after'].encode('ascii')
        need(row['count'] == 1 and forward.count(before) == 1, 'forward_unique')
        forward = forward.replace(before, after, 1)
    need(forward == new, 'full_forward')
    reverse = new
    for row in reversed(delta['replacements']):
        before, after = row['before'].encode('ascii'), row['after'].encode('ascii')
        need(reverse.count(after) == 1, 'reverse_unique')
        reverse = reverse.replace(after, before, 1)
    need(reverse == old, 'full_reverse')
    ot, oc, om = method_map(old)
    nt, nc, nm = method_map(new)
    need(set(nm) == set(om) | set(ADDED), 'method_set')
    old_lines, new_lines = old.splitlines(keepends=True), new.splitlines(keepends=True)
    for name in om:
        if name in CHANGED:
            continue
        a, b = om[name], nm[name]
        need(ast.dump(a, include_attributes=False) == ast.dump(b, include_attributes=False) and
             b''.join(old_lines[a.lineno-1:a.end_lineno]) ==
             b''.join(new_lines[b.lineno-1:b.end_lineno]), 'unchanged_method')
    # Entire inverse includes every global, helper, original close/PASS and main.
    normalized = ast.parse(reverse.decode('ascii'))
    need(ast.dump(normalized, include_attributes=True) ==
         ast.dump(ot, include_attributes=True), 'whole_ast_inverse')
    funcs = [v for v in ast.walk(ast.parse(Path(__file__).read_bytes()))
             if isinstance(v, ast.FunctionDef) and v.name.startswith('test_')]
    need(len(funcs) == 1 and funcs[0].name == SELECTOR.split('.')[1], 'one_method')
    return dict(changed_original_methods=list(CHANGED), new_private_methods=list(ADDED),
                whole_byte_inverse=True, whole_ast_inverse=True,
                business_closed_status_close_start_unchanged=True)


class ClockModel:
    def __init__(self):
        self.calls = 0
    def __call__(self):
        self.calls += 1
        return 100.0


class SyscallModel:
    def __init__(self):
        self.calls = []
        self.live = set()
        self.path = types.SimpleNamespace(isabs=lambda unused: True)
    def pid(self):
        self.calls.append(('pid',))
        return 900
    def urandom(self, n):
        self.calls.append(('urandom', n))
        return b'0' * n
    def fstat(self, fd):
        self.calls.append(('fstat', fd))
        if fd not in self.live:
            raise OSError(errno.EBADF, 'HOST descriptor model')
        return object()
    def close(self, fd):
        self.calls.append(('close', fd))
        need(fd in self.live, 'model_double_close')
        self.live.remove(fd)


class ProcessModel:
    def __init__(self):
        self.pid, self.returncode = 901, 1
        self.calls = []
    def poll(self):
        self.calls.append('poll')
        raise AssertionError('Parent poll must not run')
    def wait(self, unused=None):
        self.calls.append('wait')
        raise AssertionError('Parent wait must not run')


class PipeModel:
    closed = True
    def __init__(self):
        self.calls = []
    def fileno(self):
        self.calls.append('fileno')
        raise AssertionError('pipe fileno must not run')
    def close(self):
        self.calls.append('close')
        raise AssertionError('pipe close must not run')


class RegistryModel:
    def __init__(self):
        self.ready, self.calls = True, 0
    def lifecycle_status(self):
        self.calls += 1
        return {'closure_verified': self.ready}


PARENT_MODEL = """
class _LinuxIo:
    pass
def _bound_original():
    raise AssertionError('Parent binding method must not run')
class ReadonlyDataParent:
    def __init__(self, *args):
        self.__dict__.update(make_cache(args))
    def collect(self):
        self.failure = failure
        raise failure
    def close(self):
        forbidden.append('close')
        raise AssertionError('Parent close must not run')
    def _context(self):
        forbidden.append('_context')
        raise AssertionError('Parent context must not run')
    def _row_original(self, *args):
        forbidden.append('_row_original')
        raise AssertionError('Parent row method must not run')
    def _process_current(self):
        forbidden.append('_process_current')
        raise AssertionError('Parent process method must not run')
    def _eofs_current(self):
        forbidden.append('_eofs_current')
        raise AssertionError('Parent EOF method must not run')
    def _closed_facts(self):
        forbidden.append('_closed_facts')
        raise AssertionError('Parent closed method must not run')
"""

STATE_MODEL = """
class State:
    def __init__(self):
        self.closing = self.ready = self.probes_ready = True
        self.operation = None
        self.registry = RegistryModel()
        self.probe_actors = []
        self.bluetooth_probe_actor = object()
        self.bluetooth_caps = {'powered': True}
        self._network_observer_spec_original = None
    def close(self, *args, **kwargs):
        raise AssertionError('State close not selected')
    def closed(self):
        self.registry.calls += 0
        return self.ready
    def _probes_closed(self):
        return self.probes_ready
    def _close_probes(self, *args, **kwargs):
        raise AssertionError('State close probes not selected')
    def _go_local_closed(self, *args):
        raise AssertionError('GO not selected')
    def _go_restoration_current(self, *args):
        raise AssertionError('GO not selected')
    def _go_send_admitted(self):
        return False
def _probe_result(*args):
    return True
"""

DIRECTORY_MODEL = """
class DirectoryBinding:
    def __init__(self, root, until, *, clock, count, first):
        self._root, self._until, self.clock = root, until, clock
        self.failure = None
        self.cleanup_errors, self.downloads, self.archives, self.initializations = [], [], [], []
        self.rows = [dict(fd=n, fd_original=n, closed=False, unknown=False, close_error=None)
                     for n in range(first, first+count)]
        self._row_originals = tuple(self.rows)
        self._closed = False
        for row in self.rows:
            io.live.add(row['fd'])
    def _current(self):
        raise AssertionError('Directory current not selected')
    def _now(self):
        raise AssertionError('Directory clock not selected')
    def check(self):
        raise AssertionError('Directory check not selected')
    def identity_rows(self):
        raise AssertionError('Directory identities not selected')
    def ensure_private_child(self, *args):
        raise AssertionError('Directory initializer not selected')
    def close(self):
        closes.append(self)
        for row in reversed(self.rows):
            io.close(row['fd_original'])
            row['closed'] = True
        self._closed = True
    def closed(self):
        return self._closed
    @property
    def root(self):
        return self._root
    @property
    def absolute_until(self):
        return self._until
"""


class Fixture:
    """Only actual Owner selected definitions; every syscall/child/directory modeled."""
    def __init__(self, raw):
        self.clock, self.io = ClockModel(), SyscallModel()
        self.forbidden, self.directory_closes = [], []
        self.failure = RuntimeError('HOST modeled nonzero Parent child')
        self.modules = {}
        self.time = types.SimpleNamespace(monotonic=self.clock)
        boot = types.ModuleType('mta_client_receive_boot')
        exec('class BootSourceLoader: pass', boot.__dict__)
        loader = boot.BootSourceLoader()
        loader._original_until, loader.clock, loader.modules = 1000.0, self.clock, self.modules
        self.boot, self.loader = boot, loader
        self.modules['mta_client_receive_boot'] = boot
        parent = types.ModuleType('mta_go_readonly_parent')
        parent.__dict__.update(time=self.time, subprocess=types.SimpleNamespace(Popen=ProcessModel),
            failure=self.failure, forbidden=self.forbidden, make_cache=self.make_cache)
        exec(PARENT_MODEL, parent.__dict__)
        self.parent_module = parent
        self.modules[parent.__name__] = parent
        service = types.ModuleType('mta_service')
        service.__dict__['RegistryModel'] = RegistryModel
        exec(STATE_MODEL, service.__dict__)
        self.modules[service.__name__] = service
        normalize = types.ModuleType('mta_receive_radio_baseline')
        normalize.normalize = lambda unused: None
        self.modules[normalize.__name__] = normalize
        directory = types.ModuleType('mta_storage')
        directory.__dict__.update(io=self.io, closes=self.directory_closes)
        exec(DIRECTORY_MODEL, directory.__dict__)
        self.modules[directory.__name__] = directory
        own = types.ModuleType('mta_client_service_owner')
        own.__dict__.update(types=types, math=math, errno=errno, threading=threading,
            os=self.io, sys=types.SimpleNamespace(modules=self.modules), time=self.time)
        tree, cls, methods = method_map(raw)
        # No runtime imports, no entire module execution, no historical fixture/main.
        selected = [v for v in tree.body if isinstance(v, ast.FunctionDef) and v.name in ('_fail', '_finite')]
        selected += [v for v in tree.body if isinstance(v, ast.ClassDef) and v.name == 'ServiceOwnerError']
        chosen = [methods[name] for name in SELECTED if name in methods]
        selected.append(ast.ClassDef(name=cls.name, bases=cls.bases, keywords=[],
            body=chosen, decorator_list=[]))
        code = ast.fix_missing_locations(ast.Module(body=selected, type_ignores=[]))
        own.__dict__.update(USER_ROOT='/mnt/data/p011-toolbox/user', _LinuxIo=type('UnusedIO', (), {}))
        exec(compile(code, '<actual-selected-owner>', 'exec'), own.__dict__)
        self.modules[own.__name__] = own
        self.own_module = own
        owner = own.FixedStateServiceOwner(loader, loader._original_until, _io=self.io, send_trial_requested=True)
        self.owner = owner
        # Explicit fixture seams: startup, source validation and RF are NOT tested.
        owner._now = lambda: 100.0
        owner._boot_roles = lambda: None
        owner.started = owner.state_called = owner.state_complete = True
        owner.service = service
        owner.service_type = owner._service_type_original = service.State
        names = ('__init__', 'close', 'closed', '_probes_closed', '_close_probes',
                 '_go_local_closed', '_go_restoration_current')
        owner.service_methods = owner._service_methods_original = {n: getattr(service.State, n) for n in names}
        owner.state = owner._state_original = service.State()
        owner.probe_rows = owner.state.probe_actors
        owner.paths = ('/mnt/data/p011-toolbox/user', '/HOST/bluez', '/HOST/network')
        owner.assets.extend(dict(closed=True, unknown=False) for unused in range(71))
        owner.state_close_called, owner.state_close_return, owner.stop_called = True, True, True
        owner.directory_module, owner.directory_type = directory, directory.DirectoryBinding
        names = ('__init__', '_current', '_now', 'check', 'identity_rows', 'ensure_private_child',
                 'close', 'closed', 'root', 'absolute_until')
        owner.directory_methods = owner._directory_methods_original = {
            n: getattr(directory.DirectoryBinding, n) for n in names}
        user = directory.DirectoryBinding(owner.paths[0], owner.original_until, clock=owner.clock, count=5, first=40)
        received = directory.DirectoryBinding(owner.paths[0]+'/Received', owner.original_until,
                                              clock=owner.clock, count=6, first=50)
        owner.user_directory = owner._user_directory_original = user
        owner.received_directory = owner._received_directory_original = received
        child = dict(child=received, error=None, child_returned=True)
        user.initializations.append(child)
        for binding in (user, received):
            owner.directory_tickets.append(dict(complete=True, failure=None, value=binding,
                rows=binding.rows, row_originals=binding._row_originals, initialization=child))
        self.sealed_before_owner_failure = False
        try:
            owner._prepare_send_trial()
        except RuntimeError as error:
            need(error is self.failure, 'original_prepare_exception')
            self.sealed_before_owner_failure = (owner.failure is None and
                getattr(owner, 'send_preflight_close_receipt', None) is not None)
            # Exact real order: prepare finally seal, THEN Owner.start catch assignment.
            owner.failure = error
            owner.failures.append(error)
        else:
            raise AssertionError('prepare should preserve failure')
        owner.close_called = True

    def make_cache(self, args):
        process = ProcessModel()
        rows = []
        for index in range(9):
            raw = PipeModel() if index >= 7 else None
            meta = tuple(range(7 if raw else 9))
            fd = 100+index
            row = dict(closed=True, unknown=False, close_called=True, close_return=None,
                close_failure=None, fd=fd, fd_original=fd, metadata=meta, metadata_original=meta,
                pipe=raw is not None, close_error=OSError(errno.EBADF, 'HOST cached model'),
                raw=raw, raw_original=raw, raw_type=type(raw),
                raw_methods=(PipeModel.fileno, PipeModel.close) if raw else None,
                close_method=raw.close if raw else None)
            rows.append(row)
        pipes = tuple(rows[-2:])
        process.stdout, process.stderr = (r['raw'] for r in pipes)
        for row, role in zip(pipes, ('stdout', 'stderr')):
            row.update(role=role, eof=True)
            row['eof_ticket'] = (process, process.pid, row, row['raw'],
                                 row['fd_original'], row['metadata_original'], b'')
        methods = (process.poll, process.wait)
        pt = dict(process=process, called=True, returned=True, unknown=False, field_errors=[],
            wait_called=True, waited=True, reaped=True, wait_error=None, wait_return=process.returncode,
            pid=process.pid, pipes=pipes, stdout=process.stdout, stderr=process.stderr)
        wait = (process, process.pid, methods[1], process.returncode, pipes[0]['eof_ticket'], pipes[1]['eof_ticket'])
        pt['wait_ticket'] = pt['wait_ticket_original'] = wait
        io = self.parent_module._LinuxIo()
        fields = ('pid', 'stdout', 'stderr')
        data = dict(failure=None, attempted=True, ended=True, close_attempted=True, closed=True,
            unknown=False, cleanup_error=None, close_errors=[], result=None, report=None,
            result_original=None, worker=threading.current_thread(), clock=self.clock, clock_original=self.clock,
            io=io, io_original=io, io_class_original=type(io), arguments_original=args,
            rows=rows, rows_original=rows, row_history=list(rows), process=process, process_original=process,
            process_attempt=pt, process_attempt_original=pt, process_pid=process.pid, pid=900,
            process_methods=methods, process_methods_original=methods,
            process_fields=fields, process_fields_original=fields)
        data['row_history_original'] = data['row_history']
        data.update(zip(('task_id', 'native_epoch', 'operation_epoch', 'task_until', 'service_until'), args))
        return data

    def counters(self):
        parent = self.owner.send_preflight_parent
        return (self.clock.calls, tuple(parent.process.calls), tuple(self.forbidden),
                tuple((tuple(r['raw'].calls) if r['pipe'] else ()) for r in parent.rows),
                tuple(self.io.calls), len(self.directory_closes))


class FailedPreflightCleanup(unittest.TestCase):
    def test_actual_owner_failed_preflight_directory_release(self):
        inputs = {key: (BASE/key).read_bytes() for key, unused_size, unused_pin in INPUT_ROWS}
        source_contract(inputs)
        cases = 0
        # Old actual method still refuses the modeled cold failure, no old suite.
        original = Fixture(inputs[MOTHER])
        self.assertFalse(original.owner._close_directories())
        self.assertEqual(len(original.directory_closes), 0)
        self.assertTrue(original.owner.send_preflight_ticket['unknown'])
        cases += 1
        current = Fixture(inputs[CANDIDATE])
        owner, parent = current.owner, current.owner.send_preflight_parent
        self.assertTrue(current.sealed_before_owner_failure)
        before = current.counters()
        self.assertIsNotNone(owner._failed_preflight_closed_receipt())
        self.assertTrue(owner._close_directories())
        after = current.counters()
        self.assertEqual(after[:4], before[:4])  # no clock/Parent/pipe method calls
        self.assertEqual(after[5]-before[5], 2)
        new_calls = after[4][len(before[4]):]
        self.assertEqual(sum(r[0] == 'close' for r in new_calls), 11)
        self.assertEqual(sum(r[0] == 'fstat' for r in new_calls), 11)
        self.assertEqual(set(r[0] for r in new_calls), {'close', 'fstat'})
        self.assertTrue(owner.directory_close_complete)
        self.assertIs(owner.failure, current.failure)
        self.assertIs(parent.failure, current.failure)
        self.assertTrue(owner.send_preflight_ticket['unknown'])
        self.assertIsNone(owner.send_preflight_report)
        self.assertFalse(owner._service_closed())
        self.assertFalse(owner._closed())
        status = owner.status()
        self.assertTrue(status['resource_pending'])
        self.assertFalse(status['service_resources_closed'])
        self.assertTrue(status['directory_resources_closed'])
        once = current.counters()
        self.assertTrue(owner._close_directories())
        self.assertEqual(current.counters(), once)
        cases += 1

        mutations = (
            ('no_receipt', lambda f: setattr(f.owner, 'send_preflight_close_receipt', None)),
            ('receipt_not_original', lambda f: setattr(f.owner, '_send_preflight_close_receipt_original', object())),
            ('binding_not_original', lambda f: setattr(f.owner, '_send_preflight_close_binding_original', object())),
            ('owner_error_changed', lambda f: setattr(f.owner, 'failure', RuntimeError('different'))),
            ('parent_error_changed', lambda f: setattr(f.owner.send_preflight_parent, 'failure', RuntimeError('different'))),
            ('parent_closed_false', lambda f: setattr(f.owner.send_preflight_parent, 'closed', False)),
            ('parent_unknown', lambda f: setattr(f.owner.send_preflight_parent, 'unknown', True)),
            ('parent_not_ended', lambda f: setattr(f.owner.send_preflight_parent, 'ended', False)),
            ('parent_cleanup_error', lambda f: setattr(f.owner.send_preflight_parent, 'cleanup_error', RuntimeError())),
            ('parent_close_errors', lambda f: f.owner.send_preflight_parent.close_errors.append(RuntimeError())),
            ('row_unknown', lambda f: f.owner.send_preflight_parent.rows[0].update(unknown=True)),
            ('row_wrong_ebadf', lambda f: f.owner.send_preflight_parent.rows[0].update(close_error=OSError(errno.EIO, 'model'))),
            ('row_replaced', lambda f: f.owner.send_preflight_parent.rows.__setitem__(0, dict(f.owner.send_preflight_parent.rows[0]))),
            ('wait_not_reaped', lambda f: f.owner.send_preflight_parent.process_attempt.update(reaped=False)),
            ('wait_error', lambda f: f.owner.send_preflight_parent.process_attempt.update(wait_error=RuntimeError())),
            ('wait_ticket_changed', lambda f: f.owner.send_preflight_parent.process_attempt.update(wait_ticket=())),
            ('returncode_changed', lambda f: setattr(f.owner.send_preflight_parent.process, 'returncode', 2)),
            ('pipe_no_eof', lambda f: f.owner.send_preflight_parent.rows[7].update(eof=False)),
            ('pipe_eof_changed', lambda f: f.owner.send_preflight_parent.rows[7].update(eof_ticket=())),
            ('parent_method_changed', lambda f: setattr(f.parent_module.ReadonlyDataParent, '_closed_facts', lambda self: True)),
            ('parent_namespace_changed', lambda f: f.modules.__setitem__('mta_go_readonly_parent', types.ModuleType('foreign'))),
            ('parent_clock_changed', lambda f: setattr(f.owner.send_preflight_parent, 'clock', object())),
            ('ticket_parent_changed', lambda f: f.owner.send_preflight_ticket.update(returned=object())),
            ('ticket_collect_return', lambda f: f.owner.send_preflight_ticket.update(collect_return={})),
            ('state_not_closed', lambda f: setattr(f.owner.state, 'ready', False)),
            ('registry_not_closed', lambda f: setattr(f.owner.state.registry, 'ready', False)),
            ('probes_not_closed', lambda f: setattr(f.owner.state, 'probes_ready', False)),
            ('asset_unknown', lambda f: f.owner.assets[0].update(unknown=True)),
            ('cleanup_expired', lambda f: setattr(f.owner, 'cleanup_deadline_expired', True)),
            ('cleanup_clock_error', lambda f: setattr(f.owner, 'cleanup_clock_failure', RuntimeError())),
            ('state_close_not_returned', lambda f: setattr(f.owner, 'state_close_return', False)),
            ('server_attempted', lambda f: setattr(f.owner, 'server_called', True)),
            ('trial_present', lambda f: setattr(f.owner, 'send_trial', object())),
            ('filecenter_present', lambda f: setattr(f.owner, 'filecenter_ticket', {})),
            ('operation_present', lambda f: setattr(f.owner.state, 'operation', object())),
            ('not_cold_start', lambda f: setattr(f.owner, 'start_complete', True)),
            ('not_send_profile', lambda f: setattr(f.owner, 'send_trial_requested', False)),
            ('directory_definition_changed', lambda f: setattr(f.owner.directory_type, 'close', lambda self: None)),
        )
        for label, mutate in mutations:
            with self.subTest(label=label):
                fixture = Fixture(inputs[CANDIDATE])
                self.assertTrue(fixture.sealed_before_owner_failure)
                mutate(fixture)
                before = fixture.counters()
                self.assertFalse(fixture.owner._close_directories())
                after = fixture.counters()
                self.assertEqual(after, before)
                self.assertFalse(fixture.owner.directory_close_called)
                self.assertTrue(fixture.owner.send_preflight_ticket['unknown'])
                cases += 1
        print(MARKER + ' methods=1 cases=%d models=true physical_os=false old_suite=0' % cases)


if __name__ == '__main__':
    if sys.argv[1:] != [SELECTOR]:
        raise SystemExit('fixed single method required')
    suite = unittest.TestSuite([FailedPreflightCleanup(SELECTOR.split('.')[1])])
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)

