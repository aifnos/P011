"""New synthetic v21 HOST budget checks; no old suite, OS IO or real producer."""
import ast
from contextlib import ExitStack
import hashlib
import importlib.util
from pathlib import Path
import socket
import sys
import threading
import unittest
from unittest import mock

BASE = Path(__file__).absolute().parents[1]
ORIGINAL = BASE / 'runtime/mta_dhcp_client.py'
ORIGINAL_SHA = 'd8b44be21cd60e6d897943b4e13c0b9267ab216def429ad6a16b7ba6b50d1814'
CANDIDATE = BASE / 'candidate/client-dhcp-v21/runtime/mta_dhcp_client.py'
sys.path.insert(0, str(BASE / 'runtime'))
from tests import test_dhcp_client as old_fixture
from tests import test_dhcp_client_core as wire_fixture
spec = importlib.util.spec_from_file_location('isolated_dhcp_budget_v21', str(CANDIDATE))
d = importlib.util.module_from_spec(spec); spec.loader.exec_module(d)


def context(**changes):
    values = dict(boot_id='00000000-0000-0000-0000-000000000001', task_epoch=1,
        native_epoch=2, phy=0, wdev=7, ifindex=9, ifname='mta1234abcd', mac=wire_fixture.MAC,
        deadline=100., receipt_id='a' * 64)
    values.update(changes)
    return d.ClientAssociation(**values)


def proof(ctx, **changes):
    values = dict(context=ctx, boot_id=ctx.boot_id, task_epoch=ctx.task_epoch,
        native_epoch=ctx.native_epoch, phy=ctx.phy, wdev=ctx.wdev, ifindex=ctx.ifindex,
        ifname=ctx.ifname, iftype=8, association_verified=True, owner_verified=True,
        receipt_fsynced=True, persistent_readback_verified=True, baseline_verified=True,
        ipv4_unconfigured=True)
    values.update(changes)
    return d.AssociationProof(**values)


class Harness(object):
    def __init__(self, deadline=100., **changes):
        self.ctx = context(deadline=deadline); self.now = 1.; self.clock_steps = []
        self.cancelled = False; self.delay = 0.; self.index_delay = 0.; self.created = []
        self.calls = []; self.indices = []; self.owner = threading.RLock()
        self.raw = old_fixture.FakeSocket(); self.raw.queue = []
        self.current_proof = proof(self.ctx); self.on_proof = None
        def factory(*args): self.created.append(args); return self.raw
        values = dict(context=self.ctx, proof_callback=self.fresh, cancelled=lambda: self.cancelled,
            ownership_lock=self.owner, clock=self.clock, socket_factory=factory,
            if_nametoindex=self.index, xid=wire_fixture.XID)
        values.update(changes)
        self.client = d.DhcpSocketClient(**values)

    def clock(self):
        if self.clock_steps: self.now = self.clock_steps.pop(0)
        return self.now

    def fresh(self, ctx, budget):
        self.calls.append((ctx, budget, self.owner._is_owned()))
        self.now += self.delay
        if self.on_proof: self.on_proof()
        return self.current_proof

    def index(self, name):
        self.indices.append((name, self.owner._is_owned()))
        self.now += self.index_delay
        return 9

    def reserved(self):
        creator = object(); thread = threading.Thread(target=lambda: None)
        ticket = self.client.reserve_runner(thread, creator)
        return ticket, creator


def closed_proof(client, ctx, ticket, creator, generation, budget):
    return d.RunnerClosedProof(client, ctx, ticket, creator, generation, True)


class DhcpBudgetV21Tests(unittest.TestCase):
    def setUp(self):
        stack = self.enterContext(ExitStack())
        for name in ('os.open', 'os.mkdir', 'os.unlink', 'os.kill', 'os.system', 'socket.socket',
                'subprocess.Popen', 'subprocess.run', 'threading.Thread.start', 'time.sleep'):
            stack.enter_context(mock.patch(name, side_effect=AssertionError('no actual OS/producer')))
        stack.enter_context(mock.patch.object(socket, 'CMSG_SPACE',
            lambda size: 16 + ((size + 7) // 8) * 8, create=True))

    def test_original_pin_full_reverse_only_three_methods_core_close_run_inventory_unchanged(self):
        self.assertEqual(ORIGINAL_SHA, hashlib.sha256(ORIGINAL.read_bytes()).hexdigest())
        old = ORIGINAL.read_text(encoding='utf-8'); new = CANDIDATE.read_text(encoding='utf-8')
        old_tree = ast.parse(old, feature_version=(3, 5)); new_tree = ast.parse(new, feature_version=(3, 5))
        def methods(tree):
            owner = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'DhcpSocketClient')
            return dict((n.name, n) for n in owner.body if isinstance(n, ast.FunctionDef))
        before = methods(old_tree); after = methods(new_tree)
        self.assertEqual(set(before), set(after))
        changed = set(name for name in before if ast.dump(before[name]) != ast.dump(after[name]))
        self.assertEqual({'__init__', '_guard', 'confirm_runner_closed'}, changed)
        reverse = new
        for name in changed:
            source = ''.join(new.splitlines(True)[after[name].lineno - 1:after[name].end_lineno])
            original = ''.join(old.splitlines(True)[before[name].lineno - 1:before[name].end_lineno])
            self.assertEqual(1, reverse.count(source)); reverse = reverse.replace(source, original, 1)
        self.assertEqual(old, reverse)
        for name in ('close', '_dispose', 'run', 'status', 'poll', 'open', 'candidate', '_basic', '_send'):
            self.assertEqual(ast.dump(before[name]), ast.dump(after[name]))
        for name, marker in (('_guard', '            expected = tuple('),
                ('confirm_runner_closed', '            with self._lock:\n                valid = ')):
            old_method = ''.join(old.splitlines(True)[before[name].lineno - 1:before[name].end_lineno])
            new_method = ''.join(new.splitlines(True)[after[name].lineno - 1:after[name].end_lineno])
            self.assertEqual(old_method[old_method.index(marker):], new_method[new_method.index(marker):])
        self.assertEqual('13c03d181139fd9ead7ff3bf2bcbb4930669f1e795b17360da85834dc345e9fa',
            hashlib.sha256((BASE / 'runtime/mta_dhcp_client_core.py').read_bytes()).hexdigest())
        self.assertIs(d.core, old_fixture.adapter.core)
        self.assertFalse(any(isinstance(n, ast.Assert) for n in ast.walk(new_tree)))
        ast.parse(Path(__file__).read_text(encoding='utf-8'), feature_version=(3, 5))

    def test_defaults_reject_slow_fresh_before_factory_and_invalid_budgets(self):
        h = Harness(); h.delay = 4.17
        self.assertEqual((.2, .2, .2), (h.client._proof_seconds, h.client._lock_seconds, d.POLL_SECONDS))
        with self.assertRaisesRegex(d.DhcpSocketClientError, 'proof_budget'): h.client.open()
        self.assertEqual(.2, h.calls[0][1]); self.assertFalse(h.created)
        self.assertEqual(0, h.client._proofs); self.assertTrue(h.client.close())
        for key, values in (('proof_seconds', (True, None, '5', 0, .199, 10.001, float('nan'), float('inf'), 10 ** 1000)),
                ('lock_seconds', (False, None, '.2', 0, .0009, .201, float('nan'), float('inf'), 10 ** 1000))):
            for value in values:
                with self.subTest(key=key, value=value):
                    with self.assertRaisesRegex(d.DhcpSocketClientError, 'invalid_time'): Harness(**{key: value})
        for values in ({'proof_seconds': .2, 'lock_seconds': .001}, {'proof_seconds': 10, 'lock_seconds': .2}):
            self.assertTrue(Harness(**values).client.close())
        with self.assertRaises(TypeError): Harness(poll_seconds=5)

    def test_explicit_five_accepts_synthetic_417_fresh_current_allocation_then_expiry_no_renewal(self):
        h = Harness(deadline=20., proof_seconds=5, lock_seconds=.05); h.delay = 4.17
        h.client._core.start(1.)
        h.client._core.accept_offer(wire_fixture.response(), 2.)
        allocation = h.client._core.accept_ack(wire_fixture.response(d.wire.ACK), 3.)
        h.now = 3.; value = h.client.candidate()
        self.assertIs(allocation, value.allocation); self.assertAlmostEqual(7.17, h.now)
        self.assertEqual(5., h.calls[0][1]); self.assertTrue(h.calls[0][2]); self.assertTrue(h.indices[0][1])
        self.assertEqual(20., h.ctx.deadline); self.assertEqual(20., allocation.usable_until)
        self.assertFalse(value.interface_configured); self.assertFalse(value.endpoint_verified)
        calls = len(h.calls); h.now = h.ctx.deadline
        with self.assertRaisesRegex(d.DhcpSocketClientError, 'expired'): h.client.candidate()
        self.assertEqual(calls, len(h.calls)); self.assertTrue(h.client.close())
        fresh_open = Harness(proof_seconds=5); fresh_open.delay = 4.17
        fresh_open.client.open(); self.assertEqual(.2, fresh_open.raw.timeout)
        self.assertEqual(1, len(fresh_open.created)); self.assertEqual(1, len(fresh_open.raw.sent))
        self.assertTrue(fresh_open.client.close())

    def test_remaining_deadline_clamps_fresh_and_closure_and_index_cost_stays_in_budget(self):
        h = Harness(deadline=10., proof_seconds=5); h.now = 9.9; h.delay = .05
        with h.client._guard(h.client._generation): pass
        self.assertAlmostEqual(.1, h.calls[0][1]); self.assertEqual(10., h.ctx.deadline)
        h.client.close()
        overrun = Harness(deadline=10., proof_seconds=5); overrun.now = 9.9; overrun.delay = .11
        with self.assertRaisesRegex(d.DhcpSocketClientError, 'expired'):
            with overrun.client._guard(overrun.client._generation): self.fail('late proof cannot authorize')
        self.assertAlmostEqual(.1, overrun.calls[0][1]); self.assertTrue(overrun.client.close())
        index = Harness(); index.delay = .15; index.index_delay = .10
        with self.assertRaisesRegex(d.DhcpSocketClientError, 'proof_budget'):
            with index.client._guard(index.client._generation): self.fail('index is part of proof cost')
        self.assertTrue(index.indices[0][1]); self.assertTrue(index.client.close())
        for cost, expected in ((.05, True), (.11, False)):
            closure = Harness(deadline=10., proof_seconds=5); ticket, creator = closure.reserved()
            self.assertFalse(closure.client.close()); closure.now = 9.9; budgets = []
            def completed(client, ctx, row, owner, generation, budget):
                budgets.append(budget); closure.now += cost
                self.assertTrue(closure.owner._is_owned())
                return closed_proof(client, ctx, row, owner, generation, budget)
            self.assertEqual(expected, closure.client.confirm_runner_closed(ticket, creator, completed, recovery_deadline=10.))
            self.assertAlmostEqual(.1, budgets[0]); self.assertEqual(expected, closure.client.close())

    def test_synthetic_lock_cost_is_separate_pre_post_cancel_generation_and_strict_fields(self):
        h = Harness(proof_seconds=5, lock_seconds=.2); h.clock_steps = [1., 1.15]; h.delay = 4.17
        with h.client._guard(h.client._generation): pass
        self.assertAlmostEqual(5.32, h.now); self.assertEqual(5., h.calls[0][1])
        self.assertIs(type(h.owner), d._RLOCK_TYPE); self.assertTrue(h.calls[0][2]); self.assertTrue(h.indices[0][1])
        self.assertFalse(h.owner._is_owned()); self.assertTrue(h.client.close())
        for mode, reason in (('cancel', 'cancelled'), ('generation', 'closed'), ('expiry', 'expired')):
            changed = Harness(proof_seconds=5)
            def invalidate():
                if mode == 'cancel': changed.cancelled = True
                elif mode == 'generation': changed.client._generation += 1
                else: changed.now = changed.ctx.deadline
            changed.on_proof = invalidate
            with self.assertRaisesRegex(d.DhcpSocketClientError, reason):
                with changed.client._guard(changed.client._generation): self.fail('invalidated proof cannot authorize')
            self.assertFalse(changed.created); self.assertEqual(0, changed.client._proofs)
            self.assertFalse(changed.owner._is_owned()); self.assertTrue(changed.client.close())
        changes = (None, {'context': context()}, {'boot_id': 'OTHER'}, {'task_epoch': True}, {'native_epoch': 3},
            {'phy': True}, {'wdev': 8}, {'ifindex': 8}, {'ifname': 'wlan0'}, {'iftype': True},
            {'association_verified': 1}, {'owner_verified': False}, {'receipt_fsynced': False},
            {'persistent_readback_verified': False}, {'baseline_verified': False}, {'ipv4_unconfigured': False})
        for fields in changes:
            invalid = Harness(proof_seconds=5)
            invalid.current_proof = True if fields is None else proof(invalid.ctx, **fields)
            with self.assertRaisesRegex(d.DhcpSocketClientError, 'proof_unverified'): invalid.client.open()
            self.assertFalse(invalid.created); self.assertTrue(invalid.client.close())
        invalid = Harness(proof_seconds=5, if_nametoindex=lambda name: True)
        with self.assertRaisesRegex(d.DhcpSocketClientError, 'proof_unverified'): invalid.client.open()
        self.assertFalse(invalid.created); self.assertTrue(invalid.client.close())

    def test_closure_separate_budget_original_actor_identity_dead_thread_and_generation_guards(self):
        for budget, cost, expected in ((.2, 4.17, False), (5, 4.17, True)):
            h = Harness(proof_seconds=budget, lock_seconds=.05); ticket, creator = h.reserved()
            self.assertFalse(h.client.close()); observed = []
            def completed(client, ctx, row, owner, generation, seconds):
                observed.append((seconds, h.owner._is_owned())); h.now += cost
                return closed_proof(client, ctx, row, owner, generation, seconds)
            self.assertEqual(expected, h.client.confirm_runner_closed(ticket, creator, completed))
            self.assertEqual((float(budget), True), observed[0]); self.assertEqual(expected, h.client.close())
        h = Harness(proof_seconds=5); ticket, creator = h.reserved(); h.client.close()
        wrong = (lambda *args: True,
            lambda c, ctx, row, owner, gen, secs: d.RunnerClosedProof(object(), ctx, row, owner, gen, True),
            lambda c, ctx, row, owner, gen, secs: d.RunnerClosedProof(c, context(), row, owner, gen, True),
            lambda c, ctx, row, owner, gen, secs: d.RunnerClosedProof(c, ctx, row._replace(generation=10), owner, gen, True),
            lambda c, ctx, row, owner, gen, secs: d.RunnerClosedProof(c, ctx, row, object(), gen, True),
            lambda c, ctx, row, owner, gen, secs: d.RunnerClosedProof(c, ctx, row, owner, True, True),
            lambda c, ctx, row, owner, gen, secs: d.RunnerClosedProof(c, ctx, row, owner, gen - 1, True),
            lambda c, ctx, row, owner, gen, secs: d.RunnerClosedProof(c, ctx, row, owner, gen, 1))
        for callback in wrong:
            self.assertFalse(h.client.confirm_runner_closed(ticket, creator, callback))
            self.assertIs(ticket, h.client._ticket); self.assertFalse(h.client.close())
        never = mock.Mock(side_effect=AssertionError('actor not closed'))
        h.client._runner_active = True
        self.assertFalse(h.client.confirm_runner_closed(ticket, creator, never)); h.client._runner_active = False
        with mock.patch.object(ticket.thread, 'is_alive', return_value=True):
            self.assertFalse(h.client.confirm_runner_closed(ticket, creator, never))
        never.assert_not_called()
        def changed_generation(client, ctx, row, owner, generation, seconds):
            client._generation += 1
            return closed_proof(client, ctx, row, owner, generation, seconds)
        self.assertFalse(h.client.confirm_runner_closed(ticket, creator, changed_generation))
        self.assertIs(ticket, h.client._ticket); self.assertFalse(h.client.close())

    def test_close_unknown_factory_original_fd_reference_and_inventory_never_cleared_by_runner_proof(self):
        h = Harness(socket_factory=mock.Mock(side_effect=OSError('PRIVATE_FACTORY')))
        ticket, creator = h.reserved()
        with self.assertRaisesRegex(d.DhcpSocketClientError, 'socket_open_failed'): h.client.open()
        self.assertFalse(h.client.close()); self.assertTrue(h.client._factory_unknown)
        self.assertTrue(h.client.confirm_runner_closed(ticket, creator, closed_proof))
        self.assertFalse(h.client.close()); self.assertTrue(h.client.status()['factory_resources_unknown'])
        self.assertFalse(h.client.status()['socket_close_verified'])
        h = Harness(proof_seconds=5); ticket, creator = h.reserved(); h.client.open(); h.raw.action = 'close_fail'
        self.assertFalse(h.client.close()); self.assertIs(h.raw, h.client._pending_close[0])
        self.assertTrue(h.client.confirm_runner_closed(ticket, creator, closed_proof))
        self.assertFalse(h.client.close()); self.assertIs(h.raw, h.client._pending_close[0])
        h.raw.action = None; self.assertTrue(h.client.close()); self.assertEqual(-1, h.raw.fd)
        for key in ('send_available', 'receive_available', 'interface_configured', 'endpoint_verified'):
            self.assertFalse(h.client.status()[key])

    def test_deadline_consumed_during_lock_or_before_closure_never_calls_producer(self):
        h = Harness(deadline=2., proof_seconds=5); h.clock_steps = [1.95, 2.05]
        with self.assertRaisesRegex(d.DhcpSocketClientError, 'expired'):
            with h.client._guard(h.client._generation): self.fail('lock cost exhausted context')
        self.assertFalse(h.calls); self.assertFalse(h.indices); self.assertFalse(h.created)
        self.assertFalse(h.owner._is_owned()); self.assertEqual(0, h.client._proofs); self.assertTrue(h.client.close())
        h = Harness(deadline=2., proof_seconds=5); ticket, creator = h.reserved(); h.client.close(); h.now = 2.
        never = mock.Mock(side_effect=AssertionError('expired closure budget'))
        self.assertFalse(h.client.confirm_runner_closed(ticket, creator, never, recovery_deadline=2.)); never.assert_not_called()
        self.assertIs(ticket, h.client._ticket); self.assertFalse(h.client.close()); self.assertEqual(0, h.client._proofs)
        source = CANDIDATE.read_text(encoding='utf-8')
        self.assertEqual(1, source.count('timeout=min(self._lock_seconds,self.context.deadline - lock_start)'))
        self.assertEqual(1, source.count('budget = min(self._proof_seconds,self.context.deadline - start)'))
        self.assertIn('min(self._lock_seconds,recovery_deadline - lock_start)', source)
        self.assertIn('min(self._proof_seconds,recovery_deadline - start)', source)

    def test_association_expired_closure_uses_independent_trusted_recovery_deadline_or_short_default(self):
        for recovery in (None, 8.):
            h = Harness(deadline=2., proof_seconds=5); ticket, creator = h.reserved()
            self.assertFalse(h.client.close()); h.now = 3.; observed = []
            def completed(client, ctx, row, owner, generation, seconds):
                observed.append((seconds, h.owner._is_owned())); h.now += 4.17
                return closed_proof(client, ctx, row, owner, generation, seconds)
            self.assertTrue(h.client.confirm_runner_closed(ticket, creator, completed, recovery_deadline=recovery))
            self.assertEqual((5., True), observed[0]); self.assertEqual(2., h.ctx.deadline)
            self.assertFalse(h.created); self.assertTrue(h.client.close())
            self.assertFalse(h.client.status()['send_available']); self.assertFalse(h.client.status()['receive_available'])
        h = Harness(deadline=2., proof_seconds=5); ticket, creator = h.reserved(); h.client.close(); h.now = 3.
        never = mock.Mock(side_effect=AssertionError('invalid recovery cannot call producer'))
        for invalid in (True, False, '4', float('nan'), float('inf'), 10 ** 1000, 0., 2., 3., 63.001):
            with self.subTest(invalid=invalid):
                self.assertFalse(h.client.confirm_runner_closed(ticket, creator, never, recovery_deadline=invalid))
                self.assertIs(ticket, h.client._ticket); self.assertEqual(0, h.client._proofs)
                self.assertFalse(h.client.close())
        never.assert_not_called()
        h.clock_steps = [3., 4.05]
        self.assertFalse(h.client.confirm_runner_closed(ticket, creator, never, recovery_deadline=4.))
        never.assert_not_called(); self.assertFalse(h.owner._is_owned()); self.assertEqual(0, h.client._proofs)
        h = Harness(deadline=2., proof_seconds=5); ticket, creator = h.reserved(); h.client.close(); h.now = 3.; budgets = []
        def exceeds_recovery(client, ctx, row, owner, generation, seconds):
            budgets.append(seconds); h.now = 4.
            return closed_proof(client, ctx, row, owner, generation, seconds)
        self.assertFalse(h.client.confirm_runner_closed(ticket, creator, exceeds_recovery, recovery_deadline=4.))
        self.assertEqual([1.], budgets); self.assertIs(ticket, h.client._ticket); self.assertFalse(h.client.close())
        self.assertEqual(2., h.ctx.deadline)


if __name__ == '__main__': unittest.main()
