"""One isolated r2 HOST original-parent-cap -> first durable issuance boundary.

Actual TransferSession task/worker threads, Handoff owner checks, Parent cap
capture, argv/canonical parsers, Core/TwoPhase preparation and Store publication
execute. Clock, State admission/helper/crypto preconditions, filesystem/Proc and
observation Provider are explicit models. Owner constructor PID is a fixed
HOST exact-int model on the actual worker; real getpid/other OS IO stay denied.
No physical PID or native launch proof is claimed. No crypto operation or full State
business/factory runs. A bind_session callback stops at the actual prepared
publication, before any launch, CREATE, control socket or RF operation. This is
not Parent.start/main dispatch, full F/35-algorithm receive, restore, P011 or phone
evidence. Production receive admission and the old Bridge/F pin remain blocked.
All old fixture TestCase methods remain unselected; no quota or cap is enlarged.
"""
import ast
import builtins
from contextlib import ExitStack
import hashlib
import importlib
import json
from pathlib import Path
import sys
import threading
import time
import types
import unittest
from unittest import mock


BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE / 'tests'))
PLAN = 'host/client_parent_cap_v33_source_manifest.json'
PLAN_SHA = '2b13ba05acb3dd4984f7d2c5740349f4d90f1980ebde4014aa63f62a515f721a'
PLAN_BYTES = 8080
PREVIOUS_PLAN_SHA = '80b9a606f69c25b45387ea7dc640708d50dfafe16f8e1c9b6978645af6451b96'
# Read the frozen old wrapper's literal definition inventory, never import or
# run it. Its transitive helpers only define synthetic IO/records here.
DEPENDENCY_PLAN = 'host/client_receive_executor_v32_check.py'
DEPENDENCY_PLAN_SHA = 'dbaac6524147818b763f78f234c87793e7bada5a4759a0ac90828c41ccdc348f'
DEPENDENCY_PLAN_BYTES = 24766
EXTRA_INPUTS = (
    ('mta_crypto', 'runtime/mta_crypto.py',
     '6fde6a60ec327895938a59990c4734a923dd5ff68bd5ee6979791df9a607e516', 15274),
    ('mta_transfer_session', 'runtime/mta_transfer_session.py',
     '402f1b41e9b2f0b1f6a8ba0092a4b2fa96ef25782d1d805b4eb160ed7de28e16', 19442),
    ('mta_client_connect_handoff', 'candidate/client-connect-v13/runtime/mta_client_connect_handoff.py',
     'aeade54eac7ed055936d7004087aa2a30a731ee7742365080cbd037264a58cc4', 10533),
    ('HOST_Operation', 'candidate/client-state-integration-v32/runtime/mta_service.py',
     'c27a6978fb91fd414da96c57577e7030e059583bc10aad40b26dd0924505a2ab', 57929),
)


def fixed(path, digest, size):
    raw = (BASE / path).read_bytes()
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError('HOST fixed input changed')
    return raw


def inputs_and_fixture_definitions():
    plan = json.loads(fixed(PLAN, PLAN_SHA, PLAN_BYTES))
    if (set(plan) != {'schema', 'previous_manifest_sha256', 'sources'} or
            plan['schema'] != 'client-parent-cap-v33-host' or
            plan['previous_manifest_sha256'] != PREVIOUS_PLAN_SHA):
        raise ValueError('HOST cap graph changed')
    rows = plan['sources']
    if len(rows) != 35 or len({row['module'] for row in rows}) != 35:
        raise ValueError('HOST cap graph changed')
    inputs = [(row['module'], fixed(row['path'], row['sha256'], row['bytes'])) for row in rows]
    extras = [(name, fixed(path, digest, size)) for name, path, digest, size in EXTRA_INPUTS]
    tree = ast.parse(fixed(DEPENDENCY_PLAN, DEPENDENCY_PLAN_SHA, DEPENDENCY_PLAN_BYTES))
    inventories = [ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == 'FIXTURE_INPUTS' for target in node.targets)]
    if len(inventories) != 1 or len(inventories[0]) != 70:
        raise ValueError('HOST fixture inventory changed')
    for path, digest, size in inventories[0]: fixed(path, digest, size)
    # Definitions only; these old modules may initialize private legacy types,
    # but neither make_full nor an old TestCase method is called.
    full = importlib.import_module('test_client_full_lifecycle_v24')
    importlib.import_module('test_client_durable_connect_v19')
    importlib.import_module('test_client_proc')
    importlib.import_module('test_client_process_owner')
    return inputs, extras, full


def private_domain(inputs, extras):
    modules, actual_import = {}, builtins.__import__
    def private_import(name, *args, **kwargs):
        if name.startswith(('mta_', 'p011_')):
            if name not in modules: raise ImportError('private cap definition unavailable')
            return modules[name]
        return actual_import(name, *args, **kwargs)
    for name, raw in inputs + extras:
        tree = ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
        if name == 'HOST_Operation':
            selected = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'Operation']
            if len(selected) != 1: raise ValueError('HOST Operation definition changed')
            module = types.ModuleType(name)
            module.threading = threading
            modules[name] = module
            # Only the pinned native Operation ClassDef: do not import State or
            # activate its admission/startup helpers.
            exec(compile(ast.Module(body=selected, type_ignores=[]), 'HOST-pinned-Operation', 'exec'), module.__dict__)
            continue
        if any(isinstance(node, ast.Assert) for node in ast.walk(tree)):
            raise ValueError('target assertion changed')
        module = types.ModuleType(name)
        module.__file__ = 'HOST-parent-cap-v33-r2/' + name + '.py'
        module.__dict__['__builtins__'] = dict(vars(builtins), __import__=private_import)
        modules[name] = module
        exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    if tuple(name for name, unused in inputs) != modules['mta_client_executor'].MODULES:
        raise ValueError('HOST cap module order changed')
    return modules


def forbidden_platform(stack):
    # Real PC Thread.start/join and bounded sleeps belong to the Session seam.
    # All actual process, network/RF, platform-file or native-crypto IO is denied.
    for target in ('socket.socket', 'socket.create_connection', 'subprocess.Popen', 'ctypes.CDLL',
            'os.open', 'os.read', 'os.write', 'os.close', 'os.fstat', 'os.stat', 'os.lstat',
            'os.listdir', 'os.readlink', 'os.getpid', 'os.fork', 'os.execve', 'os.kill',
            'os.waitpid', 'os.system', 'os.urandom', 'os.mkdir', 'os.unlink', 'os.rename', 'os.fsync'):
        stack.enter_context(mock.patch(target, side_effect=AssertionError('actual platform forbidden'), create=True))


class ConstructorOnlyPidModel(object):
    """Default native Owner ctor OS dependency only; not a physical PID oracle."""
    def __init__(self, worker):
        self.worker, self.calls = worker, 0
    def getpid(self):
        if threading.current_thread() is not self.worker:
            raise AssertionError('HOST constructor PID worker changed')
        self.calls += 1
        return 123  # Explicit fixed HOST exact-int PID, not os.getpid().
    def __getattr__(self, unused_name):
        raise AssertionError('HOST constructor-only OS access forbidden')


class ParentCapV33R2Tests(unittest.TestCase):
    def test_actual_worker_parent_original_cap_first_durable_issuance_boundary(self):
        inputs, extras, full = inputs_and_fixture_definitions()
        with ExitStack() as stack:
            forbidden_platform(stack)
            modules = private_domain(inputs, extras)
        fixture, proc_helpers, unused_owner_helpers = full.setup_definitions(modules)
        core, stores, phases, proc, provider_module, f, codec, budgets = (modules[name] for name in
            ('mta_p2p_client_init', 'mta_client_store', 'mta_client_two_phase_lease', 'mta_client_proc',
             'mta_client_linux_provider', 'mta_client_executor', 'mta_client_journal_codec', 'mta_client_resource_budget'))
        sessions, crypto, h, Operation = (modules['mta_transfer_session'], modules['mta_crypto'],
            modules['mta_client_connect_handoff'], modules['HOST_Operation'].Operation)
        io = fixture.Io()
        io.clock.value = 10.125
        clock = io.clock
        sessions.time = types.SimpleNamespace(monotonic=clock, sleep=time.sleep)
        # Entropy and crypto readiness are explicit pure prerequisites; this
        # method performs no encryption, decrypt, key generation or GATT event.
        h.os = types.SimpleNamespace(urandom=lambda size: b'\x19' * size)
        crypto_owner = object()
        actual_crypto = object.__new__(crypto.OpenSslCrypto)
        actual_crypto._lib = crypto_owner
        actual_key = crypto.KeyPair('HOST-not-used-as-a-public-key', None, crypto_owner)
        original_task = Operation(None, 8, 'receive')
        worker_errors, worker_result = [], []
        saved_stores = []
        worker_finished = threading.Event()
        sentinel = type('PublicationBoundary', (BaseException,), {})

        def task(session):
            try:
                with ExitStack() as stack:
                    forbidden_platform(stack)
                    # The native default ctor retains its own original OS
                    # object. Only that private-domain object's ctor getpid is
                    # modeled; the global real OS tripwires remain installed.
                    constructor_pid = ConstructorOnlyPidModel(session._worker)
                    stack.enter_context(mock.patch.object(
                        modules['mta_client_process_owner'], 'os', constructor_pid))
                    self.assertIs(threading.current_thread(), session._worker)
                    self.assertEqual(310.125, session._task_deadline)
                    task_deadline = session._task_deadline
                    handoff_deadline = 220.12345678912345

                    def owned_parent(parent_clock=None, task_until=task_deadline):
                        op = Operation(None, 8, 'receive')
                        helper = types.SimpleNamespace(thread=threading.Thread(target=lambda: None), closed=False)
                        op.session, op.helper, op.crypto, op.key = session, helper, actual_crypto, actual_key
                        op.stage = 'advertising'
                        state = types.SimpleNamespace(lock=threading.RLock(), operation=op, session=session,
                            worker=session._worker, helper=helper, crypto=actual_crypto, key=actual_key,
                            native_epoch=8, receive_available=True, closing=False, discoverable=True)
                        session._task_deadline = task_until  # Explicit independent task-input model.
                        handoff = h.ReceiveConnectHandoff(state, op, handoff_deadline, _clock=clock)
                        parent = f.ParentExecutor(_clock=clock if parent_clock is None else parent_clock,
                            _handoff=handoff, _handoff_type=h.ReceiveConnectHandoff,
                            _handoff_codec=modules['mta_client_control_frame'])
                        return parent, handoff, state, op

                    parent, handoff, state, op = owned_parent()
                    cap = parent._capture_parent_cap_v33()
                    self.assertEqual(handoff_deadline, cap)
                    facts = parent._parent_cap_facts_v33
                    self.assertIs(facts[0], handoff); self.assertIs(facts[1], session)
                    self.assertEqual((task_deadline, handoff_deadline), facts[2:4])
                    self.assertIs(facts[4], clock); self.assertIs(facts[5], op)
                    self.assertEqual((8, 8), facts[6:])
                    text = parent._parent_until_text_v33
                    self.assertEqual(repr(cap), text)
                    self.assertEqual(cap, f._parent_until_text_v33_value(text))
                    parent._handoff_current(handoff)
                    dep = types.SimpleNamespace(manifest=fixture.manifest(), manifest_sha='1' * 64)
                    argv = f._argv(dep, '--execute-client-init', '300.0', text)
                    self.assertEqual(('--parent-until', text), argv[-2:])
                    actor = core.Actor(123, 300, dep.manifest.python_exe,
                        hashlib.sha256(b''.join(value.encode('ascii') + b'\0' for value in argv)).hexdigest(),
                        ((123, 300, 'S'),))
                    f._entry_identity(actor, dep, '--execute-client-init', '300.0', text)
                    with self.assertRaises(f.ExecutorError):
                        f._entry_identity(actor, dep, '--execute-client-init', '300.0', repr(cap + 1.0))
                    for invalid in ('220.123456789123450', 'nan', 'inf', 'True', '', ' 220.12345678912345'):
                        with self.subTest(canonical_text=invalid):
                            with self.assertRaises(f.ExecutorError): f._parent_until_text_v33_value(invalid)
                    with self.assertRaises(f.ExecutorError): f._argv(dep, '--watchdog', text, text)

                    # Pure actual Provider assembly keeps the original cap in
                    # the exact formal Store before any preparation IO.
                    assembled = provider_module.assemble(dep.manifest, _connect_binding=fixture.binding(),
                        _parent_until_v33=cap)
                    native_provider, pure_store, unused_owner, unused_bridge, unused_lease = assembled
                    self.assertIs(unused_owner._os, constructor_pid)
                    self.assertIs(unused_owner._worker_v30, session._worker)
                    self.assertEqual(123, unused_owner._pid_v30)
                    self.assertEqual(cap, pure_store.parent_until_v33(core.FORMAL_SESSION_PROFILE))
                    self.assertIs(pure_store._session_profile, core.FORMAL_SESSION_PROFILE)
                    self.assertFalse(pure_store._opened); self.assertFalse(pure_store._attempted)
                    self.assertEqual([], pure_store._coordination._inventory)
                    self.assertEqual([], pure_store._files._inventory)
                    self.assertIsNone(pure_store._session_issued_v28)
                    self.assertIs(budgets.SOURCE_PROFILE.counts, budgets.FORMAL_PROFILE.counts)
                    self.assertIs(budgets.SOURCE_PROFILE.payload_bytes, budgets.FORMAL_PROFILE.payload_bytes)

                    # Independent failures never restore a poisoned Handoff.
                    for case in ('wrong_clock', 'worker', 'state_owner', 'epoch', 'task_drift', 'handoff_drift', 'text_drift'):
                        with self.subTest(owner_case=case):
                            candidate, bound, owner_state, owner_op = owned_parent()
                            candidate._capture_parent_cap_v33()
                            if case == 'wrong_clock': candidate.clock = lambda: clock()
                            elif case == 'worker': owner_state.worker = threading.Thread(target=lambda: None)
                            elif case == 'state_owner': owner_state.operation = Operation(None, 8, 'receive')
                            elif case == 'epoch': owner_state.native_epoch += 1
                            elif case == 'task_drift': session._task_deadline += 1.0
                            elif case == 'handoff_drift': bound.deadline += 1.0
                            else: candidate._parent_until_text_v33 = repr(cap + 1.0)
                            with self.assertRaises((f.ExecutorError, h.HandoffError)):
                                candidate._handoff_current(bound)
                    for bad in (True, float('inf'), float('nan'), -1.0, 0.0):
                        with self.subTest(nonfinite=type(bad).__name__):
                            with self.assertRaises(f.ExecutorError): f._parent_cap_v33(bad)
                            with self.assertRaises(core.ClientInitError):
                                core._parent_until_v33(core.FORMAL_SESSION_PROFILE, bad)
                    candidate, bound, unused_state, unused_op = owned_parent(task_until=clock())
                    with self.assertRaisesRegex(f.ExecutorError, '^deadline$'): candidate._capture_parent_cap_v33()
                    candidate, bound, unused_state, unused_op = owned_parent()
                    clock.value = handoff_deadline
                    with self.assertRaisesRegex(h.HandoffError, '^expired$'): candidate._capture_parent_cap_v33()
                    clock.value = 10.125
                    session._task_deadline = task_deadline

                    class NoFileIo:
                        def __init__(self): self.calls = []
                        def validate(self): self.calls.append('validate')
                        def __getattr__(self, name):
                            def prohibited(*args):
                                self.calls.append(name)
                                raise AssertionError('expired loader performed file IO')
                            return prohibited
                    no_files = NoFileIo()
                    loader = f.DeploymentLoader('a' * 32, '1' * 64, _io=no_files, _clock=clock,
                        _parent_until_v33=clock())
                    with self.assertRaisesRegex(f.ExecutorError, '^deadline$'): loader.load()
                    self.assertEqual(['validate'], no_files.calls)
                    self.assertEqual([], loader.owner.rows)

                    # Native Store/TwoPhase prefix, modeled observations only.
                    # Exact bind callback is the stop seam, not a success flag.
                    identity, baseline = core.Identity('a' * 64), fixture.baseline()
                    class ObservationProvider(phases.TwoPhaseClientInitProvider):
                        def __init__(self): self.calls, self.prior = [], []
                        def executor(self, until):
                            self.calls.append(('executor', until))
                            return core.ExecutorProof('owner', fixture.SELF, False)
                        def snapshot(self, until):
                            self.calls.append(('snapshot', until)); return baseline
                        def caps(self, until):
                            self.calls.append(('caps', until))
                            return {'complete': True, 'phys': ({'index': baseline.station.phy,
                                'iftypes': (2, 8), 'software_iftypes': (), 'unknown_constraints': (),
                                'combinations': ({'max_interfaces': 2, 'num_channels': 1, 'radar_widths': 0,
                                    'radar_regions': 0, 'beacon_match': False,
                                    'limits': ({'types': (2,), 'max': 1}, {'types': (8,), 'max': 1})},)},)}
                        def original_actors(self, value, until):
                            self.calls.append(('actors_model', until)); return value is baseline
                        def read_prior(self, store, locks, original, until):
                            self.prior.append((store, locks, original, original, until)); return original
                        def authenticate_prior(self, store, locks, original, value, until):
                            if not any(a is store and b is locks and c is original and d is value and e == until
                                    for a, b, c, d, e in self.prior): raise AssertionError('unissued model prior')
                            return None
                        def register(self, *args): raise AssertionError('boundary crossed launch registration')
                        def register_interface(self, *args): raise AssertionError('boundary crossed RF registration')
                        def create_client(self, *args): raise AssertionError('boundary crossed CREATE')
                    model_provider = ObservationProvider()
                    fs = proc_helpers.FakeFs()
                    store = stores.DurableClientInitStore(fixture.old.TOKEN, identity,
                        _coordination_io=io, _files_io=io, _pending_io=io, _clock=clock,
                        _proc_reader=proc.ProcReader(_fs=fs, _clock=clock), _prior_reader=model_provider,
                        _session_profile=core.FORMAL_SESSION_PROFILE, _parent_until_v33=cap)
                    saved_stores.append(store)
                    child_owner = modules['mta_client_process_owner'].DirectChildOwner(_clock=clock)
                    bridge = phases.DirectChildLaunchBridge(store, child_owner, native_provider.specs())
                    lease = phases.TwoPhaseClientInitLease(model_provider, store, identity, clock, bridge)
                    publication = []
                    def stop_at_publication(record):
                        self.assertIs(record, lease.record)
                        self.assertIs(record, store._canonical.journal)
                        self.assertEqual('prepared', record.stage)
                        self.assertEqual(min(record.issued_at + 300.0, cap), record.deadline)
                        self.assertEqual(cap, record.deadline)
                        issuance = store._session_issued_v28
                        self.assertEqual((core.FORMAL_SESSION_PROFILE, 'formal300', record.issued_at, cap), issuance)
                        self.assertTrue(store.session_issued_v28(record, core.FORMAL_SESSION_PROFILE, cap))
                        reread = store.current(lease.locks)
                        self.assertIsNot(reread, record)
                        self.assertTrue(core._same_journal(reread, record))
                        self.assertTrue(store.session_issued_v28(reread, core.FORMAL_SESSION_PROFILE, cap))
                        copied = codec.decode_journal(codec.encode_journal(reread))
                        self.assertFalse(store.session_issued_v28(copied, core.FORMAL_SESSION_PROFILE, cap))
                        self.assertIs(issuance, store._session_issued_v28)
                        # Native generation/parser preserve original float.
                        specs = native_provider.specs(record.deadline)
                        watchdog = next(spec for spec in specs if spec.role == 'watchdog')
                        self.assertEqual(('--until', repr(cap)), watchdog.argv[-2:])
                        self.assertEqual(cap, f._watchdog_until_text_v33(watchdog.argv[-1]))
                        actor_watch = core.Actor(124, 301, watchdog.exe, watchdog.argv_sha, ((124, 301, 'S'),))
                        f._entry_identity(actor_watch, dep, '--watchdog', watchdog.argv[-1])
                        wrong = core.Journal(identity, 'prepared', baseline, cap + 1.0,
                            session_profile='formal300', issued_at=record.issued_at)
                        with self.assertRaises(stores.DurableStoreError): store._transition(wrong)
                        self.assertFalse(store.session_issued_v28(record, core.FORMAL_SESSION_PROFILE, cap + 1.0))
                        with self.assertRaises(core.ClientInitError): record.replace(deadline=cap + 1.0)
                        publication.append((record, reread, issuance, watchdog))
                        raise sentinel()
                    bridge.bind_session = stop_at_publication
                    before = clock()
                    with self.assertRaises(sentinel): lease.start(300)
                    self.assertEqual(1, len(publication))
                    self.assertEqual([min(before + 20.0, cap)] * len(model_provider.calls),
                        [until for unused_name, until in model_provider.calls])
                    self.assertIs(publication[0][2], store._session_issued_v28)
                    self.assertEqual([], bridge._operations); self.assertEqual([], child_owner._tickets)
                    self.assertEqual([], lease.launches); self.assertEqual({}, lease.handles)
                    self.assertFalse(lease.cleanup_complete); self.assertFalse(lease.normal_restored)
                    self.assertFalse(store.status()['production_provider'])
                    self.assertFalse(store.status()['receive_available'])
                    # No caller-shaped renewal, profile expansion or expiry IO.
                    with self.assertRaises(stores.DurableStoreError):
                        stores.DurableClientInitStore(fixture.old.TOKEN, identity, _parent_until_v33=cap)
                    with self.assertRaises(core.ClientInitError):
                        core._session_deadline_v33(core.TRIAL_SESSION_PROFILE, before, cap)
                    self.assertEqual(before + 20.0, core._session_deadline_v33(core.TRIAL_SESSION_PROFILE, before))
                    self.assertEqual(before + 300.0,
                        core._session_deadline_v33(core.FORMAL_SESSION_PROFILE, before, before + 1000.0))
                    empty_io, empty_provider = fixture.Io(), ObservationProvider()
                    empty_io.clock.value = cap
                    expired_store = stores.DurableClientInitStore(fixture.old.TOKEN, identity,
                        _coordination_io=empty_io, _files_io=empty_io, _pending_io=empty_io,
                        _clock=empty_io.clock, _session_profile=core.FORMAL_SESSION_PROFILE, _parent_until_v33=cap)
                    saved_stores.append(expired_store)
                    expired_owner = modules['mta_client_process_owner'].DirectChildOwner(_clock=empty_io.clock)
                    expired_bridge = phases.DirectChildLaunchBridge(expired_store, expired_owner, native_provider.specs())
                    expired_lease = phases.TwoPhaseClientInitLease(empty_provider, expired_store, identity,
                        empty_io.clock, expired_bridge)
                    with self.assertRaisesRegex(core.ClientInitError, '^expired$'): expired_lease.start(300)
                    self.assertEqual([], empty_io.opened); self.assertEqual([], empty_provider.calls)
                    self.assertIsNone(expired_store._session_issued_v28)
                    # Pure retained-pointer tamper fails without issuing again.
                    original = store._parent_until_v33
                    store._parent_until_v33 = float(str(original))
                    self.assertIsNot(store._parent_until_v33, original)
                    with self.assertRaises(stores.DurableStoreError):
                        store.parent_until_v33(core.FORMAL_SESSION_PROFILE)
                    store._parent_until_v33 = original
                    self.assertIs(publication[0][2], store._session_issued_v28)
                    self.assertEqual(3, constructor_pid.calls)
                    self.assertIs(child_owner._os, constructor_pid)
                    self.assertIs(expired_owner._os, constructor_pid)
                    worker_result.append((session._task_deadline, cap, publication[0][0].deadline))
            except BaseException as error:
                worker_errors.append(error)
            finally:
                try:
                    with ExitStack() as stack:
                        forbidden_platform(stack)
                        for saved in saved_stores: saved.close()  # Local model FDs; not marker clear or restore.
                except BaseException as error:
                    worker_errors.append(error)
                finally:
                    worker_finished.set()
            return sessions.Outcome(None, False, False)

        # Actual native Session.start chooses and starts its original PC worker.
        # Refuse the extra stage explicitly; no closure/restore claim is made.
        session = sessions.TransferSession(task, lambda unused: False, original_task,
            extra_actor_close=lambda unused: False, task_timeout=300, finalize_timeout=1,
            cancelled=original_task.cancelled)
        original_task.session = session
        session.start()
        self.assertTrue(worker_finished.wait(20), 'HOST cap worker did not finish')
        session._worker.join(2)
        for row in session._attempts: row['thread'].join(2)
        self.assertFalse(session._worker.is_alive())
        self.assertTrue(all(not row['thread'].is_alive() for row in session._attempts))
        if worker_errors: raise worker_errors[0]
        self.assertEqual([(310.125, 220.12345678912345, 220.12345678912345)], worker_result)
        self.assertFalse(session.closed())
        self.assertFalse(session.status()['restore_verified'])
        self.assertTrue(actual_key.closed is False)
        actual_key.close()  # No native key material was allocated by this model.


if __name__ == '__main__': unittest.main()
