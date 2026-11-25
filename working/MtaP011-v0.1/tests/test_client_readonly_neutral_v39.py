"""One unique v39 pure readonly owner ctor/neutral HOST boundary.

The unchanged v37 35-definition graph plus fixed readonly leaf are loaded from
private bytes. Actual native Store ctor, ResourceBudget and bind_reader execute.
Only actual PC getpid/current_thread and explicitly fixed clock1 facts are used;
all file/network/child, Store active/open/acquire/prepare and collector/Proc read
entries are tripwires. No ARM platform shim, collect(), observation, ready fact,
close/restore proof, F/Parent/State admission, RF/device/phone or physical PASS.
Fresh mutated ownership/cap/profile inputs are denial fixtures only; no unknown
is cleared and no native fields/budget/permission are fabricated on a positive.
"""
import ast
import builtins
from contextlib import ExitStack
import hashlib
import json
import os
import threading
from pathlib import Path
import types
import unittest
from unittest import mock


BASE = Path(__file__).resolve().parents[1]
PLAN = 'host/client_integrated_v37_source_manifest.json'
PLAN_SHA = '4b9ea54997194ca895a3459cf88cd715b2ccc05e46c55b533920f8182314d07a'
PLAN_BYTES = 8077
PREVIOUS_PLAN_SHA = '2b13ba05acb3dd4984f7d2c5740349f4d90f1980ebde4014aa63f62a515f721a'
LEAF = 'candidate/client-readonly-baseline-v39/runtime/mta_client_readonly_baseline.py'
LEAF_SHA = 'cd4c3ef940ef12783dd0b91aba2805a4f4cbe50f2fe2bdccbddaa1db32f4b7ff'
LEAF_BYTES = 13811
LEAF_MODULE = 'mta_client_readonly_baseline'


def fixed(relative, digest, size):
    raw = (BASE / relative).read_bytes()
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError('HOST fixed source changed')
    return raw


def source_inputs():
    plan = json.loads(fixed(PLAN, PLAN_SHA, PLAN_BYTES))
    if (set(plan) != {'schema', 'previous_manifest_sha256', 'sources'} or
            plan['schema'] != 'client-integrated-v37-host' or
            plan['previous_manifest_sha256'] != PREVIOUS_PLAN_SHA):
        raise ValueError('HOST source graph changed')
    rows = plan['sources']
    if len(rows) != 35 or len({row['module'] for row in rows}) != 35:
        raise ValueError('HOST source graph changed')
    return [(row['module'], fixed(row['path'], row['sha256'], row['bytes'])) for row in rows] + [
        (LEAF_MODULE, fixed(LEAF, LEAF_SHA, LEAF_BYTES))]


def definitions(inputs):
    modules, original_import = {}, builtins.__import__
    def private_import(name, *args, **kwargs):
        if name.startswith(('mta_', 'p011_')):
            if name not in modules: raise ImportError('HOST unplanned private source')
            return modules[name]
        return original_import(name, *args, **kwargs)
    for name, raw in inputs:
        tree = ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
        if any(isinstance(node, ast.Assert) for node in ast.walk(tree)):
            raise ValueError('HOST target assertion changed')
        module = types.ModuleType(name)
        module.__file__ = 'HOST-readonly-neutral-v39/' + name + '.py'
        module.__dict__['__builtins__'] = dict(vars(builtins), __import__=private_import)
        modules[name] = module
        exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    if (tuple(name for name, unused in inputs[:-1]) != modules['mta_client_executor'].MODULES or
            inputs[-1][0] != LEAF_MODULE or tuple(modules) != tuple(name for name, unused in inputs)):
        raise ValueError('HOST source order changed')
    return modules


def platform_tripwires(stack):
    for name in ('socket.socket', 'socket.create_connection', 'subprocess.Popen',
            'ctypes.CDLL', 'os.open', 'os.read', 'os.write', 'os.close', 'os.fstat',
            'os.stat', 'os.lstat', 'os.listdir', 'os.readlink', 'os.uname', 'os.geteuid',
            'os.fork', 'os.execve', 'os.kill', 'os.waitpid', 'os.system', 'os.urandom',
            'os.mkdir', 'os.unlink', 'os.rename', 'os.fsync',
            'threading.Thread.start', 'time.sleep'):
        stack.enter_context(mock.patch(name,
            side_effect=AssertionError('HOST actual platform forbidden'), create=True))


class ClientReadonlyNeutralV39Tests(unittest.TestCase):
    def test_native_readonly_ctor_neutral_budget_originals_and_ownership_denials_are_io_free(self):
        inputs = source_inputs()
        actual_pid, actual_worker = os.getpid(), threading.current_thread()
        with ExitStack() as stack:
            platform_tripwires(stack)
            modules = definitions(inputs)
            leaf = modules[LEAF_MODULE]
            core, stores, budgets, proc = (modules[name] for name in
                ('mta_p2p_client_init', 'mta_client_store', 'mta_client_resource_budget', 'mta_client_proc'))
            self.assertEqual(PLAN_SHA, leaf.SOURCE_MANIFEST_SHA)
            calls = {'store_ctor': [], 'bind_reader': [], 'context': [], 'forbidden': []}
            actual_store_ctor = stores.DurableClientInitStore.__init__
            actual_bind = budgets.ResourceBudget.bind_reader
            actual_context = budgets.ResourceBudget._context
            def observe_store(store, *args, **kwargs):
                calls['store_ctor'].append(store)
                return actual_store_ctor(store, *args, **kwargs)
            def observe_bind(budget, reader):
                calls['bind_reader'].append((budget, reader))
                return actual_bind(budget, reader)
            def observe_context(budget):
                calls['context'].append(budget)
                return actual_context(budget)
            stack.enter_context(mock.patch.object(stores.DurableClientInitStore, '__init__', observe_store))
            stack.enter_context(mock.patch.object(budgets.ResourceBudget, 'bind_reader', observe_bind))
            stack.enter_context(mock.patch.object(budgets.ResourceBudget, '_context', observe_context))
            def forbidden(*unused, **unused_kwargs):
                calls['forbidden'].append(True)
                raise AssertionError('HOST active/read/platform entry forbidden')
            # Pure constructors/bind/context are ORIGINAL algorithms. Only
            # out-of-scope active/read entries are forbidden, never fake success.
            for target, names in (
                    (leaf.ReadonlyBaselineOwner, ('collect', '_platform', '_pending_absent')),
                    (leaf._ReadonlyArmIo, ('validate', 'open', 'read', 'fstat', 'stat', 'close',
                        'listdir', 'socket', 'readable', 'spawn')),
                    (stores.DurableClientInitStore, ('acquire', 'current', 'commit', 'finish', 'close')),
                    (stores.ClientPreparationStore, ('open', 'prepare_initial', 'close')),
                    (modules['mta_client_files'].ClientJournalFiles, ('open', 'commit', 'read_current', 'close')),
                    (modules['mta_client_coordination'].ClientCoordination, ('acquire', 'close')),
                    (modules['mta_client_baseline'].BaselineCollector, ('collect', 'close')),
                    (proc.ProcReader, ('read_self', 'read_actor', 'read_absence'))):
                for name in names:
                    stack.enter_context(mock.patch.object(target, name, forbidden))
            def owner():
                clock_calls = []
                def clock():
                    clock_calls.append(True)
                    return 1.0
                value = leaf.ReadonlyBaselineOwner('a' * 32, 31.0, _clock=clock)
                return value, clock_calls
            native, clock_calls = owner()
            self.assertIs(type(native), leaf.ReadonlyBaselineOwner)
            self.assertEqual(native.pid, actual_pid)
            self.assertIs(native.worker, actual_worker)
            self.assertEqual(native.issued_at, 1.0)
            self.assertEqual(native.until, 31.0)
            self.assertIs(native.until, native._original_until)
            self.assertEqual(30.0, native.until - native.issued_at)
            self.assertEqual([True], clock_calls)
            self.assertIs(type(native.identity), core.Identity)
            self.assertEqual(native.identity.candidate_sha, PLAN_SHA)
            self.assertIs(type(native.reader), proc.ProcReader)
            self.assertIs(type(native.store), stores.DurableClientInitStore)
            self.assertIs(type(native.budget), budgets.ResourceBudget)
            self.assertIs(type(native.io), leaf._ReadonlyArmIo)
            self.assertIs(native.io.owner, native)
            self.assertIs(calls['store_ctor'][-1], native.store)
            self.assertEqual(len(calls['store_ctor']), 1)
            self.assertEqual(len(calls['bind_reader']), 1)
            self.assertIs(calls['bind_reader'][0][0], native.budget)
            self.assertIs(calls['bind_reader'][0][1], native.reader)
            self.assertIs(native.store._resource_budget_v23, native.budget)
            self.assertIs(native.store._proc_reader_original_v24, native.reader)
            self.assertIs(native.store._proc_reader, native.reader)
            self.assertIs(native.reader._bound_budget_v24, native.budget)
            self.assertIs(native.reader._resource_budget_v24, native.budget)
            self.assertEqual([native.reader], native.budget._readers)
            self.assertIs(native.budget._store, native.store)
            self.assertIs(native.budget._mutex, native.store._mutex)
            self.assertIs(native.budget._epoch, native.store._epoch)
            self.assertIs(native.budget._profile, budgets.SOURCE_PROFILE)
            self.assertIs(native.store._session_profile, core.TRIAL_SESSION_PROFILE)
            self.assertIsNone(native.budget._provider)
            before_context, before_clock = len(calls['context']), len(clock_calls)
            self.assertIsNone(native._neutral())
            self.assertEqual(before_context + 1, len(calls['context']))
            self.assertIs(calls['context'][-1], native.budget)
            self.assertEqual(before_clock, len(clock_calls))  # Neutral does not read/renew time.
            state = native.budget.status()
            self.assertEqual(((0,) * len(budgets.KINDS),) * 2, state['counts'])
            self.assertEqual((0, 0), state['retained_payload_bytes'])
            self.assertEqual((0, 0), state['inflight_payload_bytes'])
            self.assertEqual(0, state['original_count'])
            self.assertEqual(0, state['active_producers'])
            self.assertFalse(state['resource_pending'])
            self.assertFalse(state['network_authorized'])
            self.assertFalse(native.store._attempted)
            self.assertFalse(native.store._opened)
            self.assertFalse(native.store._unknown)
            self.assertIsNone(native.store._current_locks)
            self.assertIsNone(native.store._canonical)
            self.assertIsNone(native.store._marker)
            self.assertIsNone(native.store._binding)
            self.assertIsNone(native.store._session_issued_v28)
            self.assertEqual([], native.store._records)
            self.assertEqual([], native.reader._history)
            self.assertEqual([], native.reader._fd_refs)
            self.assertEqual([], native.reader._raw)
            status_before_clock = len(clock_calls)
            projection = native.status()
            self.assertEqual(status_before_clock, len(clock_calls))
            self.assertFalse(projection['neutral_store_opened'])
            self.assertFalse(projection['attempted'])
            self.assertFalse(projection['ended'])
            self.assertFalse(projection['read_success'])
            for flag in ('staging_attempted', 'rf_requested', 'restoration_verified',
                    'source_factory_ready', 'send_available', 'receive_available', 'phone_tested'):
                self.assertIs(projection[flag], False)
            self.assertEqual(0, projection['full_native_rounds'])
            self.assertEqual([], calls['forbidden'])
            def denied(callback, code):
                with self.assertRaises(leaf.ReadonlyBaselineError) as caught:
                    callback()
                self.assertIs(type(caught.exception), leaf.ReadonlyBaselineError)
                self.assertEqual((code,), caught.exception.args)
            # Each modified original is a fresh DENIAL input only. No live
            # read, proof, unknown cleanup or resource history is rewritten.
            neutral_cases = ('foreign_store', 'foreign_reader', 'foreign_budget', 'provider',
                'profile', 'epoch', 'reader_budget', 'store_opened', 'locks', 'canonical')
            for case in neutral_cases:
                with self.subTest(neutral_case=case):
                    victim, unused_clock = owner()
                    if case == 'foreign_store': victim.store = object()
                    elif case == 'foreign_reader': victim.reader = object()
                    elif case == 'foreign_budget': victim.budget = object()
                    elif case == 'provider': victim.budget._provider = object()
                    elif case == 'profile': victim.budget._profile = budgets.FORMAL_PROFILE
                    elif case == 'epoch': victim.store._epoch = object()
                    elif case == 'reader_budget': victim.reader._bound_budget_v24 = object()
                    elif case == 'store_opened': victim.store._opened = True
                    elif case == 'locks': victim.store._current_locks = object()
                    elif case == 'canonical': victim.store._canonical = object()
                    before = len(calls['context'])
                    denied(victim._neutral, 'readonly_owner')
                    self.assertEqual(before, len(calls['context']))
                    self.assertFalse(victim.attempted)
                    self.assertFalse(victim.read_success)
            for case in ('worker', 'pid', 'cap', 'expired', 'regressed'):
                with self.subTest(owner_case=case):
                    victim, unused_clock = owner()
                    if case == 'worker':
                        victim.worker = threading.Thread(target=lambda: None)  # NEVER started.
                        callback, code = victim._neutral, 'readonly_worker'
                    elif case == 'pid':
                        victim.pid = actual_pid + 1
                        callback, code = victim._neutral, 'readonly_worker'
                    elif case == 'cap':
                        victim.until += 1.0
                        callback, code = victim.now, 'readonly_cap_changed'
                    elif case == 'expired':
                        victim._clock = lambda: victim.until
                        callback, code = victim.now, 'readonly_expired'
                    else:
                        victim._clock = lambda: .5
                        callback, code = victim.now, 'readonly_clock'
                    before = len(calls['context'])
                    denied(callback, code)
                    self.assertEqual(before, len(calls['context']))
                    self.assertFalse(victim.attempted)
                    self.assertFalse(victim.read_success)
            # Invalid ctor inputs reject before native Store/budget creation.
            before = len(calls['store_ctor'])
            for token, until, code in (('x' * 32, 31.0, 'readonly_config'),
                    ('a' * 32, True, 'readonly_config'), ('a' * 32, 32.0, 'readonly_config'),
                    ('a' * 32, 1.0, 'readonly_expired')):
                with self.subTest(ctor_code=code, invalid_until=until):
                    denied(lambda: leaf.ReadonlyBaselineOwner(token, until, _clock=lambda: 1.0), code)
            self.assertEqual(before, len(calls['store_ctor']))
            self.assertEqual([], calls['forbidden'])
            self.assertFalse(native.attempted)
            self.assertFalse(native.read_success)
            self.assertEqual([], native.reader._history)
            self.assertEqual(((0,) * len(budgets.KINDS),) * 2, native.budget.status()['counts'])


if __name__ == '__main__': unittest.main()
