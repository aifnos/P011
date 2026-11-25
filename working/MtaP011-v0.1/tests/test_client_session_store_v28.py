"""One new HOST Store/session stage; no full F/lease/IP/device execution.

Only Core/Codec/Budget/Store replace the frozen v27 29-definition graph here.
The later dynamic-IP module and the formal Provider/F assembly are not tested.
Pinned fixture definitions are reused, never old TestCase methods. Actual
native Store acquire, publication, Proc marker observation, current readback
and cleanup checkpoints execute over separate synthetic FakeIO/FakeFs domains.
All resource/Store calls run under OS tripwires. Pure fixture definition imports
and their SOURCE Path.resolve precede those tripwires; they grant no lifecycle.
This is not a 300-second capacity/wall proof, restoration or transfer result.
"""
import ast
import builtins
from contextlib import ExitStack
import hashlib
import importlib
import json
from pathlib import Path
import sys
import types
import unittest
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE / 'tests'))
PLAN = 'host/client_completion_v27_source_manifest.json'
PLAN_SHA = 'd1a3435c3f021a10c618d2967e2682791832f9f024902df71a05ce058e1b1213'
REPLACEMENTS = {
    'mta_p2p_client_init': ('178bd8a491e9e5ec03e8da3bce780f8e8e8c1c8781bfeaca7d8c3bac59fa364b', 69966),
    'mta_client_journal_codec': ('2ffeca6b59498c9e2dfa4b9906bbe55db909d5d5e1d448fa0c795490996fe14a', 17450),
    'mta_client_resource_budget': ('56d6dbe2370279b1572a563e67fd3313bf942c0baa78fbd8e36cd973ba09839e', 16215),
    'mta_client_store': ('cd8702343bd7b954c10f136dfbdcb8ff5ee13218a900d06dc8e972f6b19fad3b', 70817),
}
FIXTURES = {
    'tests/test_client_full_lifecycle_v24.py': '95ab61699cdf0e5efcd2a057d7c3d6d6a36d3843ee2fd45a9c27d3fea217119e',
    'tests/test_client_durable_connect_v19.py': 'f92ab1be262d6da641e4cc3306f218f44d1c500f70c35d0352017cbae396bab1',
    'tests/test_client_proc.py': 'fad1f4e86dd7cb6f17f8254865b75cc9389d19f89aefd8332de9ccc8d1c9c6bc',
    'tests/test_client_journal_codec.py': '33750c02cabfcce7bff46390744ae94bee43ec9ab8e6c7827365075070b3f385',
    'tests/test_client_process_owner.py': 'dcc33004cae2a69b8bcbc3f9646fc9311c9b5dcd2da38bce045686ace14228b2',
}


def fixed(relative, digest, count=None):
    raw = (BASE / relative).read_bytes()
    if hashlib.sha256(raw).hexdigest() != digest or count is not None and len(raw) != count:
        raise ValueError('HOST fixed input changed')
    return raw


def inputs_and_definitions():
    rows = json.loads(fixed(PLAN, PLAN_SHA).decode('utf-8'))['sources']
    if len(rows) != 29 or len({row['module'] for row in rows}) != 29:
        raise ValueError('HOST frozen graph changed')
    inputs = []
    for row in rows:
        name = row['module']
        if name in REPLACEMENTS:
            digest, count = REPLACEMENTS[name]
            relative = 'candidate/client-session-v28/runtime/' + name + '.py'
        else:
            relative, digest, count = row['path'], row['sha256'], row['bytes']
        inputs.append((name, fixed(relative, digest, count)))
    for relative, digest in FIXTURES.items(): fixed(relative, digest)
    full = importlib.import_module('test_client_full_lifecycle_v24')
    importlib.import_module('test_client_durable_connect_v19')
    importlib.import_module('test_client_proc')
    importlib.import_module('test_client_process_owner')
    return inputs, full


def private_domain(inputs):
    modules, original_import = {}, builtins.__import__
    def private_import(name, *args, **kwargs):
        if name.startswith(('mta_', 'p011_')):
            if name not in modules: raise ImportError('private definition unavailable')
            return modules[name]
        return original_import(name, *args, **kwargs)
    for name, raw in inputs:
        tree = ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
        if any(isinstance(node, ast.Assert) for node in ast.walk(tree)):
            raise ValueError('target assertion changed')
        module = types.ModuleType(name)
        module.__file__ = 'HOST-v28-store-stage/' + name + '.py'
        module.__dict__['__builtins__'] = dict(vars(builtins), __import__=private_import)
        modules[name] = module
        exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    if tuple(modules) != modules['mta_client_executor'].MODULES:
        raise ValueError('HOST frozen stage order changed')
    return modules


def tripwires(stack):
    for name in ('socket.socket', 'socket.create_connection', 'subprocess.Popen',
            'ctypes.CDLL', 'os.open', 'os.read', 'os.write', 'os.close', 'os.fstat',
            'os.stat', 'os.lstat', 'os.listdir', 'os.readlink', 'os.getpid',
            'os.fork', 'os.execve', 'os.kill', 'os.waitpid', 'os.system', 'os.urandom',
            'os.mkdir', 'os.unlink', 'os.rename', 'os.fsync',
            'threading.Thread.start', 'time.sleep'):
        stack.enter_context(mock.patch(name,
            side_effect=AssertionError('actual OS forbidden'), create=True))


class SessionStoreV28Tests(unittest.TestCase):
    def test_native_store_fixed_profiles_issuance_readback_and_expired_cleanup(self):
        inputs, full = inputs_and_definitions()
        with ExitStack() as stack:
            tripwires(stack)
            modules = private_domain(inputs)
        # Original fixture definitions include SOURCE Path.resolve only. No
        # make_full/start/restore/old TestCase method is invoked here.
        fixture, proc_helpers, unused_owner_helpers = full.setup_definitions(modules)
        with ExitStack() as stack:
            tripwires(stack)
            core, codec, budgets, stores, proc = (modules[name] for name in
                ('mta_p2p_client_init', 'mta_client_journal_codec',
                 'mta_client_resource_budget', 'mta_client_store', 'mta_client_proc'))
            identity, base = core.Identity('a' * 64), fixture.baseline()
            trial = stores.DurableClientInitStore(fixture.old.TOKEN, identity)
            self.assertIs(trial._session_profile, core.TRIAL_SESSION_PROFILE)
            self.assertIs(trial._resource_budget_v23._profile, budgets.SOURCE_PROFILE)
            self.assertFalse(trial._attempted); self.assertFalse(trial._opened)
            self.assertEqual([], trial._coordination._inventory)
            self.assertEqual([], trial._files._inventory)
            for invalid in ('formal300', {}, types.SimpleNamespace(name='formal300'), object()):
                with self.assertRaises(stores.DurableStoreError):
                    stores.DurableClientInitStore(fixture.old.TOKEN, identity, _session_profile=invalid)
            self.assertIs(budgets.SOURCE_PROFILE.counts, budgets.FORMAL_PROFILE.counts)
            self.assertIs(budgets.SOURCE_PROFILE.payload_bytes, budgets.FORMAL_PROFILE.payload_bytes)

            io, fs = fixture.Io(), proc_helpers.FakeFs()
            clock, profile = io.clock, core.FORMAL_SESSION_PROFILE
            store = stores.DurableClientInitStore(fixture.old.TOKEN, identity,
                _coordination_io=io, _files_io=io, _pending_io=io,
                _proc_reader=proc.ProcReader(_fs=fs, _clock=clock), _clock=clock,
                _session_profile=profile)
            self.assertIs(store._session_profile_original_v28, profile)
            self.assertIs(store._resource_budget_v23._profile, budgets.FORMAL_PROFILE)
            self.assertIs(store._resource_budget_v23._session_profile, profile)
            self.assertEqual([], io.opened)
            issued_at, active_until = float(clock()), float(clock()) + 300.0
            with self.assertRaises(stores.DurableStoreError): store._begin_io(active_until)
            self.assertEqual([], io.opened)  # No published original can approve numeric 300.
            try:
                locks = store.acquire(identity, clock() + 3.0)
                journal = core.Journal(identity, 'prepared', base, active_until,
                    session_profile=profile.name, issued_at=issued_at)
                journal = store.commit(locks, journal)
                issuance = store._session_issued_v28
                self.assertEqual((profile, profile.name, issued_at, active_until), issuance)
                self.assertIs(journal, store._canonical.journal)
                self.assertTrue(store.session_issued_v28(journal, profile, active_until))
                before = list(io.ops)
                clone = codec.decode_journal(codec.encode_journal(journal))
                self.assertTrue(core._same_journal(clone, journal))
                self.assertFalse(store.session_issued_v28(clone, profile, active_until))
                self.assertEqual(before, io.ops)  # Issuance helper is pure, not a read/permission.
                clock.value += 1.0
                reread = store.current(locks)
                self.assertIsNot(reread, journal)
                self.assertTrue(core._same_journal(reread, journal))
                self.assertIs(issuance, store._session_issued_v28)
                self.assertTrue(store.session_issued_v28(journal, profile, active_until))
                self.assertTrue(store.session_issued_v28(reread, profile, active_until))
                store._begin_io(active_until)
                self.assertEqual(min(clock() + 3.0, active_until), store._io_deadline)
                self.assertEqual(clock() + 5.0, store._budget_slice(active_until, 5.0))
                with self.assertRaises(stores.DurableStoreError): store._begin_io(active_until + 1.0)
                renewed = core.Journal(identity, 'prepared', base, active_until + 1.0,
                    session_profile=profile.name, issued_at=issued_at + 1.0)
                with self.assertRaises(stores.DurableStoreError): store._transition(renewed)
                self.assertIs(issuance, store._session_issued_v28)

                # Exact independent cleanup scope, not an active-session renewal.
                clock.value = active_until + 1.0
                with self.assertRaises(stores.DurableStoreError): store._begin_io(active_until)
                cleanup_until = clock() + 60.0
                store._recovery_deadline = cleanup_until
                budget = store._resource_budget_v23
                budget.cancel(); store._resource_lane_v23 = budgets.CLEANUP
                cleaned = store.commit(locks, reread.replace(stage='cleanup_intent'))
                cleaned = store.commit(locks, cleaned.replace(stage='cleanup_verified'))
                self.assertEqual('cleanup_verified', cleaned.stage)
                self.assertEqual((profile.name, issued_at, active_until),
                    (cleaned.session_profile, cleaned.issued_at, cleaned.deadline))
                self.assertIs(issuance, store._session_issued_v28)
                store._begin_disk(cleanup_until)
                self.assertEqual(clock() + 3.0, store._io_deadline)
                self.assertEqual(clock() + 5.0, store._budget_slice(cleanup_until, 5.0))
                self.assertTrue(budget.status()['network_cancelled'])
                self.assertFalse(store.status()['production_provider'])
                self.assertFalse(store.status()['send_available'])
                self.assertFalse(store.status()['receive_available'])
            finally:
                store.close()  # Local original resources only, not restore/marker clear.
            self.assertFalse(io.handles); self.assertFalse(fs.live)
            self.assertTrue(store._proc_reader.history_closed())

            # No quota refund or lost original after a settled producer; profile
            # pointer drift remains cancelled even if the pointer is restored.
            bound = trial._resource_budget_v23
            credit = bound.reserve(budgets.PREPARATION_NETWORK, 'COLLECTOR', 1)
            original = object()
            bound.started(credit); bound.returned(credit, original, (b'x',))
            self.assertTrue(bound.settle(credit))
            self.assertIs(bound._rows[0]['original'], original)
            self.assertIs(credit._session_profile, core.TRIAL_SESSION_PROFILE)
            self.assertIs(credit._profile, budgets.SOURCE_PROFILE)
            self.assertEqual(1, bound.status()['original_count'])
            self.assertEqual((1, 0), bound.status()['retained_payload_bytes'])
            trial._session_profile = core.FORMAL_SESSION_PROFILE
            with self.assertRaises(budgets.ResourceBudgetError):
                bound.reserve(budgets.PREPARATION_NETWORK, 'COLLECTOR')
            trial._session_profile = core.TRIAL_SESSION_PROFILE
            with self.assertRaises(budgets.ResourceBudgetError):
                bound.reserve(budgets.PREPARATION_NETWORK, 'COLLECTOR')
            self.assertTrue(bound.status()['owner_changed'])
            self.assertTrue(bound.status()['network_cancelled'])
            self.assertEqual(1, bound.status()['original_count'])


if __name__ == '__main__': unittest.main()
