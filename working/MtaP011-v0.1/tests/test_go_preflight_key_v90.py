"""One new HOST90 affected method; SOURCE only, never RF admission.

All twelve fixed source files are read and verified before definition execution.
Codec85/Packet87 and the five new v90 definitions execute complete source, not
extracted functions. RO DATA and GO Snapshot classes remain separate domains.
New v90 producer/validator/Launch/comparator success paths are never replaced;
one deny-only instance-method substitution checks retained-method rejection.

Parent89.collect is an explicit source-local ancestry model: it constructs real
Packet DATA but supplies synthetic process/pipe/EOF/reap/closed records. The
original Parent context/definition/process/EOF/closed predicates still consume
those records. No Parent collect algorithm, observer helper, source FD, child,
ARM executable, or prior test method is run. Prepared/State/accounting/Native
and Store reserve are declared inert ancestry; reserve records the boundary and
raises before publication/RF. Pub's fixture seal is local DATA, not a production
bundle seal. Its original production BUNDLE_MANIFEST_SHA remains None on disk.
An already-issued 20-second publication slice is modeled, not reimplemented as
an authority producer. These cases prove new consumers do not renew that cap.

No whole Native/GO flow, business transfer, restoration, phone, device or State
admission is exercised. ROOT owns the first AST and execution, not this author.
"""
import builtins
import hashlib
import os
from pathlib import Path
import stat
import sys
import threading
import types
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCES = (
    ('json', 'runtime/p011_json.py', 8061,
     'fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88'),
    ('ip', 'runtime/mta_ip.py', 22049,
     '1fa5e72817772285fd966f52c57af105950ff0d3b6ea49b202983aebfbab40c5'),
    ('go_core', 'candidate/client-session-v28/runtime/mta_p2p_client_init.py', 69966,
     '178bd8a491e9e5ec03e8da3bce780f8e8e8c1c8781bfeaca7d8c3bac59fa364b'),
    ('ro_core', 'candidate/client-parent-cap-v33/runtime/mta_p2p_client_init.py', 71315,
     'd3b51493d3ae778aeb72c1304dc50e5a6221428f7775bc7a28d15a3f19abeaaa'),
    ('codec', 'candidate/go-send-observer-v85/runtime/mta_snapshot_data.py', 17217,
     'cb5e8f16c78cc4c879a8986dd9c2ab8ed5e6c055f105baad3ce60eb9a10d2a26'),
    ('packet', 'candidate/go-send-observer-entry-v87/runtime/mta_observer_packet.py', 13223,
     '6f2c882058ee30a630ac30e1a5b4e9277d04ee2e71c108b58966a0574bf74e7a'),
    ('parent', 'candidate/go-send-observer-parent-v89/runtime/mta_go_readonly_parent.py', 41562,
     '68a95f868d18c5fc007d711e5f165ee9d564c776119c23edba8c02f83fba47ff'),
    ('deployment', 'candidate/go-send-preflight-key-v90/runtime/mta_go_deployment.py', 26543,
     'e8dc91c0a44a48d6cecf066257e79185fe590385f98300d01835edddb8114efe'),
    ('bridge', 'candidate/go-send-preflight-key-v90/runtime/mta_go_send_bridge.py', 84603,
     '454bf63707c6a947b4267e7097de8ccff0d44b12b57b1b86b7f42a67956bba5a'),
    ('executor', 'candidate/go-send-preflight-key-v90/runtime/mta_go_executor.py', 57481,
     'f2d724f8402a86490c23a698614eec7b9e8cbd1b2720e92d9b96a84192c08444'),
    ('bootstrap', 'candidate/go-send-preflight-key-v90/runtime/mta_go_bootstrap.py', 31964,
     '93bc97ccb9d83d5727c2f528f0a2934f09d8cae093591821a9bf5ad60f425697'),
    ('publication', 'candidate/go-send-preflight-key-v90/runtime/mta_go_send_publication.py', 45133,
     '1f9d4f771d998d24677a6bc276526acaa96362a2ed508595690ad6ba19173f96'),
)
MARKER = ('HOST90_PREFLIGHT_KEY new_methods=1 old_methods=0 cases=9 '
          'pure_codec=true ancestry_models=true device=false phone=false\n')


def _read_sources():
    raw = {}
    for role, path, size, pin in SOURCES:
        value = (ROOT / path).read_bytes()
        if len(value) != size or hashlib.sha256(value).hexdigest() != pin:
            raise AssertionError('fixed HOST90 source changed')
        raw[role] = value
    return raw


def _definition(name, raw, domain, filename):
    module = types.ModuleType(name)
    module.__file__ = filename
    def private_import(target, globals=None, locals=None, fromlist=(), level=0):
        if level:
            raise AssertionError('relative definition import')
        if target in domain:
            return domain[target]
        if target.startswith(('mta_', 'p011_')):
            raise AssertionError('unlisted definition import')
        return builtins.__import__(target, globals, locals, fromlist, level)
    module.__dict__['__builtins__'] = dict(vars(builtins), __import__=private_import)
    domain[name] = module
    exec(compile(raw, filename, 'exec'), module.__dict__)
    return module


class _Clock(object):
    def __init__(self): self.value, self.calls = 1.0, 0
    def __call__(self):
        self.calls += 1
        return self.value


class _ForbiddenIo(object):
    def __init__(self): self.calls = []
    def fail(self, *unused, **ignored):
        self.calls.append('io')
        raise AssertionError('HOST90 unexpected platform operation')
    def pid(self): return os.getpid()  # HOST identity only, not an ARM actor.


class _OsProjection(object):
    def __init__(self, guard): self.guard = guard
    def getpid(self): return os.getpid()
    def getppid(self): return 9876  # Synthetic F parent, never a Proc observation.
    def __getattr__(self, name):
        if name in ('open', 'read', 'write', 'close', 'stat', 'lstat', 'fstat',
                    'mkdir', 'listdir', 'chmod', 'fchmod', 'fsync', 'lseek',
                    'urandom', 'readlink', 'fork', 'waitpid', 'kill', 'pipe'):
            return self.guard.fail
        return getattr(os, name)


class _ModelPipe(object):
    def __init__(self): self.closed = True
    def fileno(self): raise AssertionError('no inherited FD in this model')
    def close(self): raise AssertionError('closed fixture must not perform IO')


class _ModelProcess(object):
    def __init__(self, out, err):
        self.pid, self.returncode = 90090, 0
        self.stdout, self.stderr = out, err
        self.poll_calls = self.wait_calls = 0
    def poll(self):
        self.poll_calls += 1
        raise AssertionError('ancestral poll must not run')
    def wait(self, timeout=None):
        self.wait_calls += 1
        raise AssertionError('ancestral wait must not run')


class _StopAfterReserve(RuntimeError): pass


def _snapshot(domain, changed=None):
    core, ip = domain['mta_p2p_client_init'], domain['mta_ip']
    actors = tuple(core.Actor(pid, start + (1 if changed == 'actor' and pid == 101 else 0),
        exe, digit * 64, ((pid, start + (1 if changed == 'actor' and pid == 101 else 0), 'S'),))
        for pid, start, exe, digit in ((101, 1001, '/usr/bin/Z03', 'a'),
            (202, 2002, '/usr/bin/control_engine', 'b'), (303, 3003, '/usr/bin/weston', 'c')))
    station = core.Origin(0, 0x101, 3, 'wlan0', 2)
    route = ip.RouteRecord(0, 0, 254, 2, 0, 1, 0, 3, 0xc0a83201,
                          8 if changed == 'route' else 7, 0xc0a83209, ())
    rules = (ip.RuleRecord(0, 255), ip.RuleRecord(32766, 254), ip.RuleRecord(32767, 253))
    return core.Snapshot('01234567-89ab-cdef-0123-456789abcdef',
        tuple(sorted(core.STOCK_PINS)), actors, station, 'd' * 64, 2412,
        (station,), ip.IpSnapshot((), (route,), rules), (), (), True)


def _data_domain(raw):
    domain = {}
    roles = (('p011_json', 'json'), ('mta_ip', 'ip'), ('mta_p2p_client_init', 'ro_core'),
             ('mta_snapshot_data', 'codec'), ('mta_observer_packet', 'packet'))
    for name, role in roles:
        _definition(name, raw[role], domain,
                    '/var/volatile/tmp/p011-mta-go-observer-v85/runtime/' + name + '.py')
    return domain


def _packet(domain, binding):
    codec, packet = domain['mta_snapshot_data'], domain['mta_observer_packet']
    snapshot_raw = codec.encode_snapshot(_snapshot(domain))
    result = dict(schema='p011-go-preflight-data-v85', binding=tuple(sorted(binding.items())),
        snapshot_raw=snapshot_raw, stable_key_sha256=codec.decode_snapshot(snapshot_raw).key_sha,
        helper_raw=tuple((row[0], b'{"data":true}\n', b'') for row in packet.HELPERS),
        lock_metadata=(1, 2, stat.S_IFREG | 0o600, 0, 0, 1, 0, 10, 20),
        source_manifest_sha256=packet.SOURCE_MANIFEST_SHA, source_count=38,
        active_until=binding['until'], cleanup_until=binding['cleanup_until'],
        rf_requested=False, restoration_verified=False, production_admitted=False)
    encoded = packet.encode_result(result)
    reader = packet.ObserverPacketReader()
    reader.feed(encoded)
    value = reader.finish()
    return value, reader


class _Fixture(object):
    """Fresh isolated definitions; all non-v90 environmental seams are models."""
    def __init__(self, raw):
        self.raw, self.clock, self.io = raw, _Clock(), _ForbiddenIo()
        self.ro = _data_domain(raw)
        self.go = {}
        for name, role in (('p011_json', 'json'), ('mta_ip', 'ip'),
                ('mta_p2p_client_init', 'go_core'), ('mta_snapshot_data', 'codec')):
            _definition(name, raw[role], self.go, '/fixture-go/' + name + '.py')
        self.sources = _definition('mta_go_deployment', raw['deployment'], self.go,
            '/var/volatile/tmp/p011-mta-go-send-v76-assets/runtime/mta_go_deployment.py')
        self.bridges = _definition('mta_go_send_bridge', raw['bridge'], self.go, '/fixture-go/bridge.py')
        self.executor = _definition('mta_go_executor', raw['executor'], self.go, '/fixture-go/executor.py')
        for name in self.sources.MODULES:
            if name not in self.go:
                self.go[name] = types.ModuleType(name)  # Explicit inert ancestry definitions.
        self._ancestry_types()
        self.bootstrap = _definition('mta_go_bootstrap', raw['bootstrap'], self.go, '/fixture-go/bootstrap.py')
        self.parent = _definition('mta_go_readonly_parent', raw['parent'], self.go, '/fixture-parent.py')
        self.parent.time = types.SimpleNamespace(monotonic=self.clock)
        self.parent._LinuxIo = type('ModelParentIo90', (), {
            'pid': lambda unused: os.getpid(),
            '__getattr__': lambda unused, name: self.io.fail})
        self.collect_calls = 0
        self.collect_error = None
        fixture = self
        def collect_model(owner):
            """Not Parent89 collect: explicit records for the new Pub consumer."""
            fixture.collect_calls += 1
            if fixture.collect_error is not None:
                raise fixture.collect_error
            owner.pid = os.getpid()
            owner.attempted = owner.ended = owner.close_attempted = owner.closed = True
            owner.active_until, owner.cleanup_until = 31.0, 36.0
            owner.period_original = (owner.active_until, owner.cleanup_until)
            owner.nonce_raw = bytes.fromhex('a' * 32)
            binding = dict(nonce=owner.nonce_raw.hex(), task_id=owner.task_id,
                native_epoch=owner.native_epoch, operation_epoch=owner.operation_epoch,
                until=owner.active_until, cleanup_until=owner.cleanup_until)
            owner.binding = owner.binding_original = tuple((name, binding[name]) for name in fixture.parent._BIND_KEYS)
            report, reader = _packet(fixture.ro, binding)
            owner.result = owner.report = owner.result_original = report
            owner.reader = owner.reader_original = reader
            owner.python_sha256 = 'b' * 64  # Synthetic current-read Python DATA, not an ELF role.
            owner.modules.update(fixture.ro)
            for name, size, pin in fixture.parent.SOURCE_PINS:
                module = owner.modules[name]
                role = {'p011_json': 'json', 'mta_ip': 'ip', 'mta_p2p_client_init': 'ro_core',
                        'mta_snapshot_data': 'codec', 'mta_observer_packet': 'packet'}[name]
                functions = tuple((k, v) for k, v in module.__dict__.items()
                                  if type(v) in (types.FunctionType, type))
                owner.module_originals.append((name, module, module.__dict__, raw[role], functions))
            packet = fixture.ro['mta_observer_packet']
            owner.packet_functions = owner.packet_functions_original = (
                packet, packet.ObserverPacketReader, packet.ObserverPacketReader.feed,
                packet.ObserverPacketReader.finish, packet.ObserverPacketData)
            out, err = _ModelPipe(), _ModelPipe()
            process = _ModelProcess(out, err)
            owner.process = owner.process_original = process
            owner.process_pid = process.pid
            owner.process_fields = owner.process_fields_original = ('pid', 'stdout', 'stderr')
            owner.process_methods = owner.process_methods_original = (process.poll, process.wait)
            for index, pipe in enumerate((out, err)):
                fd, meta = 700 + index, (1, 10 + index, stat.S_IFIFO | 0o600, 0, 0, 1, 0)
                row = dict(raw=pipe, raw_original=pipe, fd=fd, fd_original=fd,
                    metadata=meta, metadata_original=meta, closed=True, unknown=False,
                    close_failure=None, eof=True)
                row['eof_ticket'] = (process, process.pid, row, pipe, fd, meta, b'')
                owner.rows.append(row); owner.row_history.append(row)
            ticket = dict(process=process, pid=process.pid, stdout=out, stderr=err,
                pipes=tuple(owner.rows), called=True, returned=True, unknown=False,
                waited=True, reaped=True, wait_called=True, wait_return=process.returncode,
                wait_error=None, field_errors=[])
            ticket['wait_ticket'] = ticket['wait_ticket_original'] = (
                process, process.pid, owner.process_methods[1], process.returncode,
                owner.rows[0]['eof_ticket'], owner.rows[1]['eof_ticket'])
            owner.process_attempt = owner.process_attempt_original = ticket
            return report
        # Only the old collect/environment boundary is modeled. Its actual
        # _context/_definitions_current/_process_current/_eofs_current and
        # _closed_facts methods are NOT patched; new Pub retains these originals.
        self.parent.ReadonlyDataParent.collect = collect_model
        self.go['mta_service'] = types.ModuleType('mta_service')
        self.go['mta_service'].State = type('ModelState90', (), {})
        self.go['mta_service'].Operation = type('ModelOperation90', (), {})
        prep = types.ModuleType('mta_send_preparation')
        exec('class _Fd: pass\n'
             'def validate_send_request(value): raise AssertionError("no preparation flow")\n'
             'class PreparedSend:\n'
             ' def __init__(self): pass\n'
             ' def prepare(self): return validate_send_request(None)\n'
             ' def _selection_current(self, active): raise AssertionError("no selection IO")\n', prep.__dict__)
        self.go['mta_send_preparation'] = prep
        self.pub_module = _definition('mta_go_send_publication', raw['publication'], self.go, '/fixture-pub.py')
        self.pub_module.time = types.SimpleNamespace(monotonic=self.clock)
        for module in (self.parent, self.sources, self.pub_module, self.bridges, self.executor):
            module.os = _OsProjection(self.io)
            module.__dict__['__builtins__']['open'] = self.io.fail
        self.parent.subprocess = self.bridges.subprocess = types.SimpleNamespace(Popen=self.io.fail)
        self.parent.select = self.bridges.select = self.executor.select = types.SimpleNamespace(select=self.io.fail)
        self.state = self.go['mta_service'].State()
        self.operation = self.go['mta_service'].Operation()
        self.prepared = prep.PreparedSend()
        self.until, self.service_until = 60.0, 80.0
        self.task, self.epoch = 'c' * 32, 3
        session = types.SimpleNamespace(_worker=threading.current_thread(), _task_deadline=self.until)
        self.state.operation, self.state.session = self.operation, session
        self.state.native_epoch, self.state.registry = self.epoch, object()
        self.state._service_until_original = self.state._original_service_until = self.service_until
        op = self.operation
        op.session, op.epoch, op.kind = session, self.epoch, 'go_send'
        op.go_worker, op.go_until, op.cancelled = threading.current_thread(), self.until, threading.Event()
        p = self.prepared
        p.until, p.task_id, p.worker, p.clock = self.until, self.task, op.go_worker, self.clock
        p.closed, p.prepared = False, True
        p.selection = types.SimpleNamespace(_registry=self.state.registry)
        op.send_selection = op.go_selection_original = p.selection
        op.send_prepared = p
        self.pub = self.pub_module.FixedGoSendPublication(self.state, op, p)
        op.send_publication = self.pub
        self._deployment()

    def _ancestry_types(self):
        self.go['mta_client_proc'].ProcObservation = type('ModelProcObservation90', (), {})
        self.go['mta_client_proc'].ProcReader = type('ModelProcReader90', (), {})
        self.go['mta_client_store'].DurableClientInitStore = type('ModelAccounting90', (), {})
        self.go['mta_go_native'].NativeGoResources = type('ModelNative90', (), {})
        self.go['mta_go_native'].GoBaselineObservation = type('ModelBaseline90', (), {})
        self.go['mta_go_bootstrap_store'].GoBootstrapStore = type('ModelStore90', (), {})
        self.go['mta_go_process_owner'].GoDirectChildOwner = type('ModelLauncher90', (), {})

    def _deployment(self):
        s = self.sources
        source_pins = dict(s.NEUTRAL_PINS)
        tree = dict(version=1, run_token='e' * 32, candidate_sha='f' * 64,
            task_id=self.task, ifname='mtaeeeeeeee', python_sha='b' * 64,
            sources=[[name, source_pins.get(name, '1' * 64)] for name in s.MODULES],
            baseline_manifest=[[path, pin] for path, pin in self.go['mta_p2p_client_init'].STOCK_PINS] +
                              [['/usr/sbin/wpa_cli', '2' * 64]])
        self.manifest_tree = tree
        manifest = s.GoManifest(tree, tree['run_token'])
        loader = s.GoDeploymentLoader(manifest.run_token, '9' * 64, self.until, repr(self.until), _clock=self.clock)
        loader.owner = types.SimpleNamespace(unknown=False, rows=[])
        loader.modules = {name: self.go[name] for name in s.MODULES}
        loader.original_modules = tuple((name, loader.modules[name]) for name in s.MODULES)
        deployment = s.LoadedGoDeployment(loader, manifest, loader.modules, {}, loader.expected, loader._specs, 'parent_files')
        loader.value = deployment
        self.loader, self.deployment = loader, deployment
        self.pub.loader, self.pub.deployment = loader, deployment

    def collect(self):
        self.pub_module.BUNDLE_MANIFEST_SHA = '5' * 64  # This isolated model seal is NOT production.
        report = self.pub.preflight_network()
        self.pub_module.BUNDLE_MANIFEST_SHA = None
        return report

    def published_ancestry(self):
        # Explicit prior local-publication facts; no old FS/writer methods run.
        self.pub.called = self.pub.closed = self.pub.local_consume_called = True
        self.pub.prepare_until = 21.0

    def bridge(self):
        b = object.__new__(self.bridges.GoSendBridge)
        b.state, b.operation, b.prepared, b.deployment = self.state, self.operation, self.prepared, self.deployment
        b.worker, b.clock, b.until = self.pub.worker, self.clock, self.until
        b.nonce = 'd' * 32
        b.binding = dict(run=self.deployment.manifest.run_token, manifest=self.deployment.manifest_sha,
            task=self.task, nonce=b.nonce, native_epoch=self.epoch, operation_epoch=self.epoch,
            until=repr(self.until), parent_pid=os.getpid())
        b.file_ids = ('fixture-file-id',)
        b._originals = (b.state, b.operation, b.prepared, b.deployment, self.loader, b.worker, b.binding)
        b.process = b._process_original = None
        b._preflight_called_v90 = b._preflight_returned_v90 = False
        for name in ('source', 'originals', 'pub', 'data', 'raw', 'error'):
            setattr(b, '_preflight_' + name + '_v90', None)
        self.operation.send_bridge, self.operation.send_file_ids = b, b.file_ids
        self.bridges.sys = types.SimpleNamespace(modules={'mta_go_send_publication': self.pub_module})
        return b

    def live(self, changed=None, terminal=None):
        self.collect(); self.published_ancestry()
        b = self.bridge()
        data = b._preflight_start_v90()
        # A private F deployment/Entry is a declared ancestor, not a running F.
        fdep = self.sources.LoadedGoDeployment(self.loader, self.deployment.manifest, self.loader.modules,
            {}, self.loader.expected, self.loader._specs, 'f_entry')
        self.loader.value = fdep
        entry = self.executor.GoEntrySource(fdep, self.until, repr(self.until), '--go-bootstrap', self.clock)
        self.executor._ENTRY_INVENTORY.append(entry)
        accounting = self.go['mta_client_store'].DurableClientInitStore()
        reader = self.go['mta_client_proc'].ProcReader()
        mutex, epoch = threading.RLock(), object()
        budget = types.SimpleNamespace(_store=accounting, _mutex=mutex, _epoch=epoch, _readers=[reader])
        budget._context = lambda: None  # Explicit inert accounting context, no RF authority.
        for name, value in dict(_attempted=False, _opened=False, _current_locks=None, _canonical=None,
                _marker=None, _resource_budget_v23=budget, _proc_reader=reader,
                _proc_reader_original_v24=reader, _clock=self.clock, _mutex=mutex, _epoch=epoch,
                _io_deadline=4.0).items(): setattr(accounting, name, value)
        reader._bound_budget_v24 = reader._resource_budget_v24 = budget
        entry.accounting, entry.reader, entry.budget = accounting, reader, budget
        entry.accounting_ticket = dict(unknown=False, creator=type(accounting), returned=accounting)
        entry.boot = _snapshot(self.go).boot
        channel = object.__new__(self.bridges.SendTaskChannel)
        channel.entry, channel.rows, channel.stop = entry, [], False
        channel.archive_handle, channel.context = object(), object()
        binding = dict(b.binding, parent_pid=9876)
        channel.start = dict(kind='START', seq=1, binding=binding, data={'preflight': data})
        channel.poll = types.MethodType(lambda current: current.stop, channel)  # Old inherited-pipe model.
        parent_observation = self.go['mta_client_proc'].ProcObservation()
        core = self.go['mta_p2p_client_init']
        parent_observation.actor = core.Actor(9876, 888, self.sources.PYTHON, 'a' * 64, ((9876, 888, 'S'),))
        for name, value in dict(kind='live_actor', same_boot=True, boot=entry.boot, passes=2,
                               resource_pending=False, file_count=1, closed_count=1).items():
            setattr(parent_observation, name, value)
        launch = self.executor.GoSendLaunch(entry, channel, parent_observation, self.executor._SEND_LAUNCH_TOKEN)
        entry.send_launch = entry._send_launch_original = launch
        self.executor._ENTRY_INVENTORY.append(launch)
        owner = object.__new__(self.bootstrap.GoBootstrap)
        owner.deployment, owner.entry, owner.clock, owner.until, owner.worker = fdep, entry, self.clock, entry.until, entry.worker
        native = self.go['mta_go_native'].NativeGoResources()
        store = self.go['mta_go_bootstrap_store'].GoBootstrapStore()
        launcher = self.go['mta_go_process_owner'].GoDirectChildOwner()
        owner.store, owner.native, owner.launcher = store, native, launcher
        store.owner, native.owner, launcher.runtime = owner, owner, owner
        store._native_original, store._launcher_original = native, launcher
        owner._originals = (fdep, entry, self.clock, owner.until, owner.worker, store, native, launcher)
        self.loader.runtime = owner
        owner.send_launch = owner._send_launch_original = launch
        owner._send_launch_selected, owner.started, owner.restore_attempted = True, False, False
        owner.stop_requested, owner.failure, owner.last = False, None, None
        native.observations, native.baseline = [], None
        self.reserve_calls, self.observe_caps = [], []
        fixture = self
        def observe(scope):
            fixture.observe_caps.append(scope)
            observation = fixture.go['mta_go_native'].GoBaselineObservation()
            observation.native, observation.owner, observation.until = native, owner, owner.until
            observation.snapshot = _snapshot(fixture.go, changed)
            native.baseline = observation; native.observations.append(observation)
            if terminal == 'expiry': fixture.clock.value = scope
            if terminal == 'cancel': channel.stop = True
            return observation
        def reserve(baseline):
            fixture.reserve_calls.append(baseline)
            raise _StopAfterReserve('boundary only, not a reservation')
        native.observe_baseline, store.reserve = observe, reserve
        self.entry, self.launch, self.owner, self.native, self.channel = entry, launch, owner, native, channel
        return owner


class GoPreflightKey90Test(unittest.TestCase):
    def test_preflight_data_and_reserve_key_gate(self):
        raw = _read_sources()
        completed = []
        def refusal(call, kind, reason):
            with self.assertRaises(kind) as seen: call()
            self.assertEqual(str(seen.exception), reason)
            return seen.exception

        # 1: Actual pure Packet DATA and new Pub/Bridge handoff, ancestry model.
        with self.subTest(domain='original_handoff'):
            f = _Fixture(raw)
            report = f.collect()
            self.assertIs(type(report), f.ro['mta_observer_packet'].ObserverPacketData)
            self.assertIs(f.pub.observer_report, f.pub.observer_owner.result_original)
            self.assertTrue(f.parent.ReadonlyDataParent._closed_facts(f.pub.observer_owner))
            self.assertEqual(1, f.collect_calls)
            f.published_ancestry(); b = f.bridge()
            data = b._preflight_start_v90()
            self.assertIs(data, f.pub.observer_start_data)
            self.assertIs(b._preflight_current_v90(), data)
            self.assertIs(f.bridges._preflight_data(data, b.binding), data)
            self.assertNotEqual(data['observer_nonce'], b.binding['nonce'])
            self.assertEqual(report.snapshot.key_sha, data['key_sha256'])
            self.assertEqual('60.0', data['task_until'])
            self.assertEqual(21.0, f.pub.prepare_until)
            self.assertEqual((False, False), (f.pub.status()['production_admitted'],
                                             f.pub.status()['native_restore_verified']))
            self.assertEqual((0, 0), (f.pub.observer_owner.process.poll_calls, f.pub.observer_owner.process.wait_calls))
            self.assertEqual([], f.io.calls)
            completed.append('original_handoff')

        # 2: New Pub requires SAME report/type and the original EOF/reap/close.
        for fault, reason in (
                ('report', 'publication_observer_original_pending'),
                ('foreign', 'publication_observer_original_pending'),
                ('eof', 'parent_missing_eof'), ('reap', 'publication_observer_inventory_pending'),
                ('wait_ticket', 'publication_observer_inventory_pending'),
                ('closed', 'publication_observer_inventory_pending'),
                ('unknown', 'publication_observer_original_pending')):
            with self.subTest(domain='parent_originals', fault=fault):
                f = _Fixture(raw); f.collect(); owner = f.pub.observer_owner
                if fault == 'report': owner.report = object()
                elif fault == 'foreign': f.pub.observer_report = object()
                elif fault == 'eof': owner.rows[0]['eof'] = False
                elif fault == 'reap': owner.process_attempt['reaped'] = False
                elif fault == 'wait_ticket': owner.process_attempt['wait_ticket'] = tuple(list(owner.process_attempt['wait_ticket']))
                elif fault == 'closed': owner.rows[0]['closed'] = False
                elif fault == 'unknown': owner.unknown = True
                kind = f.parent.ReadonlyParentError if fault == 'eof' else f.pub_module.GoSendPublicationError
                refusal(f.pub._observer_current, kind, reason)
                self.assertEqual(1, f.collect_calls)
                self.assertEqual((0, 0), (owner.process.poll_calls, owner.process.wait_calls))
        completed.append('parent_originals')

        # 3: New Pub maps the original observer period/nonce/source DATA.
        for fault, reason in (
                ('nonce', 'publication_observer_binding_changed'),
                ('period', 'parent_period_changed'), ('manifest', 'publication_observer_data_changed'),
                ('count', 'publication_observer_data_changed'), ('task', 'publication_observer_task_changed')):
            with self.subTest(domain='mapping', fault=fault):
                f = _Fixture(raw); f.collect(); owner = f.pub.observer_owner
                if fault == 'nonce': owner.nonce_raw = b'wrong-nonce-data!'
                elif fault == 'period': owner.cleanup_until = 37.0
                elif fault == 'manifest': object.__setattr__(owner.report, 'source_manifest_sha256', '1' * 64)
                elif fault == 'count': object.__setattr__(owner.report, 'source_count', 37)
                elif fault == 'task': f.state._service_until_original = f.state._original_service_until = 81.0
                kind = f.parent.ReadonlyParentError if fault == 'period' else f.pub_module.GoSendPublicationError
                refusal(f.pub._observer_current, kind, reason)
                self.assertEqual(1, f.collect_calls)
        completed.append('mapping')

        # 4: Production seal remains absent; expired ancestor cap never renews.
        with self.subTest(domain='once_original_cap'):
            f = _Fixture(raw)
            self.assertIsNone(f.pub_module.BUNDLE_MANIFEST_SHA)
            refusal(f.pub.preflight_network, f.pub_module.GoSendPublicationError,
                    'publication_observer_unsealed_or_reused')
            self.assertEqual(0, f.collect_calls)
            f.collect(); f.published_ancestry()
            original = f.pub.prepare_until
            f.clock.value = original
            refusal(lambda: f.pub.preflight_start_data(f.deployment), f.pub_module.GoSendPublicationError,
                    'publication_stopped')
            self.assertIs(f.pub.prepare_until, original)
            self.assertFalse(f.pub.observer_consumed)
            self.assertEqual(1, f.collect_calls)
            self.assertEqual([], f.io.calls)
        with self.subTest(domain='once_original_cap', phase='producer_error'):
            f = _Fixture(raw)
            original_error = RuntimeError('modeled ancestor collection error')
            f.collect_error = original_error
            f.pub_module.BUNDLE_MANIFEST_SHA = '5' * 64  # Fixture only, not production.
            seen = refusal(f.pub.publish, RuntimeError, 'modeled ancestor collection error')
            self.assertIs(seen, original_error)
            self.assertIs(f.pub.failure, original_error)
            self.assertIs(f.pub.observer_failure, original_error)
            self.assertIs(f.pub.observer_attempt['error'], original_error)
            self.assertFalse(f.pub.called)
            self.assertIsNone(f.pub.token)
            self.assertIsNone(f.pub.prepare_until)
            self.assertEqual([], f.pub.mutations)
            self.assertEqual([], f.io.calls)
        completed.append('once_original_cap')

        # 5: New bounded primitive validator, not a replay of Packet85 cases.
        f = _Fixture(raw); f.collect(); f.published_ancestry(); b = f.bridge()
        valid = f.pub.observer_start_data
        mutations = (
            ('bool', 'source_count', True, 'preflight_data_invalid'),
            ('large', 'task_id', 'x' * 97, 'preflight_data_limit'),
            ('pin', 'source_manifest_sha256', '0' * 64, 'preflight_data_binding'),
            ('count', 'source_count', 37, 'preflight_data_binding'),
            ('key', 'key_sha256', 'z' * 64, 'preflight_data_binding'),
            ('task', 'task_id', '2' * 32, 'preflight_data_binding'),
            ('epoch', 'operation_epoch', 4, 'preflight_data_binding'),
            ('time', 'observer_until', '31', 'preflight_time_invalid'),
            ('order', 'observer_cleanup_until', '30.0', 'preflight_period_invalid'),
            ('taskcap', 'task_until', '61.0', 'preflight_period_invalid'),
        )
        for name, key, value, reason in mutations:
            with self.subTest(domain='bounded_data', fault=name):
                bad = dict(valid); bad[key] = value
                refusal(lambda: f.bridges._preflight_data(bad, b.binding), f.bridges.SendBridgeError, reason)
        with self.subTest(domain='bounded_data', fault='foreign'):
            touched = []
            class Foreign(object):
                def __repr__(self): touched.append('repr'); raise AssertionError('foreign repr')
                def __str__(self): touched.append('str'); raise AssertionError('foreign str')
                def __bool__(self): touched.append('bool'); raise AssertionError('foreign bool')
            bad = dict(valid); bad['key_sha256'] = Foreign()
            refusal(lambda: f.bridges._preflight_data(bad, b.binding), f.bridges.SendBridgeError, 'preflight_data_invalid')
            self.assertEqual([], touched)
            self.assertLessEqual(len(f.bridges._preflight_wire_v90(valid)), 2048)
            oversized = dict(valid)
            for name in f.bridges._PREFLIGHT_KEYS_V90 - {'source_count', 'native_epoch', 'operation_epoch'}:
                oversized[name] = '\u6d4b' * 96  # Pure framing model, not real snapshot size.
            refusal(lambda: f.bridges._preflight_wire_v90(oversized), f.bridges.SendBridgeError,
                    'preflight_data_limit')
        completed.append('bounded_data')

        # 6: Actual Bridge once/source/method/data continuity; never recollect.
        for fault, reason in (
                ('once', 'preflight_start_once'), ('source', 'preflight_source_changed'),
                ('method', 'preflight_method_changed'), ('data', 'preflight_data_changed')):
            with self.subTest(domain='bridge_originals', fault=fault):
                f = _Fixture(raw); f.collect(); f.published_ancestry(); b = f.bridge()
                b._preflight_start_v90(); original = b._preflight_raw_v90
                if fault == 'source': f.bridges.sys.modules['mta_go_send_publication'] = types.ModuleType('foreign')
                elif fault == 'method': f.pub.preflight_start_data = types.MethodType(lambda *args: None, f.pub)
                elif fault == 'data': f.pub.observer_start_data['key_sha256'] = '4' * 64
                target = b._preflight_start_v90 if fault == 'once' else b._preflight_current_v90
                refusal(target, f.bridges.SendBridgeError, reason)
                self.assertIs(b._preflight_raw_v90, original)
                self.assertEqual(1, f.collect_calls)
        completed.append('bridge_originals')

        # 7: Actual F constructor/current and new Loader codec pin DATA gate.
        with self.subTest(domain='launch_source'):
            f = _Fixture(raw); f.live()
            self.assertIs(f.launch.preflight, f.channel.start['data']['preflight'])
            self.assertIsNone(f.launch.is_current(f.entry))
            f.launch.preflight['key_sha256'] = '6' * 64
            refusal(lambda: f.launch.is_current(f.entry), f.sources.GoSourceError, 'send_preflight_changed')
            g = _Fixture(raw)
            tree = dict(g.manifest_tree, sources=[list(row) for row in g.manifest_tree['sources']])
            row = next(row for row in tree['sources'] if row[0] == 'mta_snapshot_data')
            row[1] = '7' * 64
            refusal(lambda: g.sources.GoManifest(tree, tree['run_token']), g.sources.GoSourceError, 'source_graph_invalid')
            h = _Fixture(raw); h.live()
            h.loader.failure = h.sources.GoSourceError('fixture source failure')
            refusal(lambda: h.launch.is_current(h.entry), h.sources.GoSourceError, 'foreign_source_deployment')
        completed.append('launch_source')

        # 8: Actual key digest/comparator inside actual prepare_live, reserve0
        # on changed valid GO Snapshot; successful boundary stops before RF.
        for changed in (None, 'route', 'actor'):
            with self.subTest(domain='reserve_key_gate', changed=changed):
                f = _Fixture(raw); owner = f.live(changed)
                if changed is None:
                    refusal(owner.prepare_live, _StopAfterReserve, 'boundary only, not a reservation')
                    self.assertEqual(1, len(f.reserve_calls))
                    self.assertIs(f.reserve_calls[0], f.native.baseline)
                    self.assertIs(type(f.native.baseline.snapshot), f.go['mta_p2p_client_init'].Snapshot)
                    self.assertEqual(f.launch.preflight['key_sha256'],
                                     f.go['mta_snapshot_data'].key_digest(f.native.baseline.snapshot))
                else:
                    error = refusal(owner.prepare_live, f.sources.GoSourceError, 'send_preflight_baseline_changed')
                    self.assertIs(owner.failure, error)
                    self.assertEqual([], f.reserve_calls)
                self.assertEqual([16.0], f.observe_caps)
                self.assertEqual(60.0, owner.until)
                self.assertEqual(16.0, f.entry.accounting._io_deadline)
                self.assertEqual([], f.io.calls)
        completed.append('reserve_key_gate')

        # 9: End gate after real pure digest work, no reserve/cap extension;
        # exact wrong-domain Snapshot and altered codec class method refused.
        for terminal in ('expiry', 'cancel'):
            with self.subTest(domain='terminal_before_reserve', terminal=terminal):
                f = _Fixture(raw); owner = f.live(terminal=terminal)
                error = refusal(owner.prepare_live, f.sources.GoSourceError, 'stop_requested')
                self.assertIs(owner.failure, error)
                self.assertTrue(owner.stop_requested)
                self.assertEqual([], f.reserve_calls)
                self.assertEqual([16.0], f.observe_caps)
                self.assertEqual(16.0, f.entry.accounting._io_deadline)
                self.assertEqual(60.0, owner.until)
        with self.subTest(domain='terminal_before_reserve', terminal='foreign_domain'):
            f = _Fixture(raw); f.live()
            baseline = f.go['mta_go_native'].GoBaselineObservation()
            baseline.native, baseline.owner, baseline.until = f.native, f.owner, f.owner.until
            baseline.snapshot = _snapshot(f.ro)
            f.native.baseline = baseline; f.native.observations.append(baseline)
            refusal(lambda: f.launch.check_preflight_baseline_v90(f.entry, baseline),
                    f.sources.GoSourceError, 'send_preflight_baseline_not_original')
            self.assertEqual([], f.reserve_calls)
        with self.subTest(domain='terminal_before_reserve', terminal='codec_original'):
            f = _Fixture(raw); f.live()
            f.go['mta_p2p_client_init'].Snapshot.key = lambda *unused: ()
            refusal(f.owner.prepare_live, f.go['mta_snapshot_data'].SnapshotDataError, 'fixed_domain_changed')
            self.assertEqual([], f.reserve_calls)
        completed.append('terminal_before_reserve')

        self.assertEqual(9, len(completed))
        sys.stdout.write(MARKER)


if __name__ == '__main__':
    unittest.main()
