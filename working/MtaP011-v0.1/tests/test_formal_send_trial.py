"""New HOST phase contracts, actual Gate and unstarted actual Session78.

Owner, State, assets, readonly Parent and packet ledgers are explicit models.
No Parent IO, Native, startup collector, task worker, finalizer or RF runs.
Canonical module names and target __file__ values below are HOST fixtures,
not authentication evidence for a real target deployment.
"""
import ast
import hashlib
from pathlib import Path
import sys
import threading
import time
import types
import unittest


ROOT = Path(__file__).resolve().parents[1]
GATE = 'candidate/formal-send-v1/runtime/mta_send_trial.py'
SESSION = 'candidate/go-send-state-v78/runtime/mta_transfer_session.py'
TARGET = '/tmp/p011-mta-formal-send-v1/runtime/'
SESSION_PIN = (20633, 'e7321ad446318f96bf84b1a94f0e5e3c76b1e973e28826f1c2514527b6967859')
GATE_PIN = (22034, 'd54e8f94621cb86484f8303a603f11ce05dfad3e2231f3bb202bc5ff9ecd95d4')
CANONICAL = ('mta_send_trial', 'mta_service', 'mta_client_service_owner', 'mta_go_readonly_parent')


class Fixture:
    """Ledger models plus actual Python mutex/Event/unstarted Session objects."""
    def __init__(self, requested=True, expired=False, asset_delta=0):
        raw = (ROOT / SESSION).read_bytes()
        assert (len(raw), hashlib.sha256(raw).hexdigest()) == SESSION_PIN
        self.session_module = types.ModuleType('HOST_actual_session78')
        self.session_module.__file__ = str(ROOT / SESSION)
        exec(compile(raw, self.session_module.__file__, 'exec'), self.session_module.__dict__)
        self.service = types.ModuleType('mta_service')
        self.service.__file__ = TARGET + 'mta_service.py'
        exec('class State:\n def _probes_closed(self): return True\nclass Operation: pass\n',
             self.service.__dict__)
        self.service.TransferSession = self.session_module.TransferSession
        self.owner_module = types.ModuleType('mta_client_service_owner')
        self.owner_module.__file__ = TARGET + 'mta_client_service_owner.py'
        exec('class FixedStateServiceOwner: pass\nclass _LinuxIo: pass\n', self.owner_module.__dict__)
        self.parent_module = types.ModuleType('mta_go_readonly_parent')
        self.parent_module.__file__ = TARGET + 'mta_go_readonly_parent.py'
        exec('class ReadonlyDataParent: pass\nclass PacketModel: pass\n', self.parent_module.__dict__)
        self.gate_module = types.ModuleType('mta_send_trial')
        self.gate_module.__file__ = TARGET + 'mta_send_trial.py'
        for name, module in (('mta_service', self.service), ('mta_client_service_owner', self.owner_module),
                             ('mta_go_readonly_parent', self.parent_module), ('mta_send_trial', self.gate_module)):
            sys.modules[name] = module
        gate_raw = (ROOT / GATE).read_bytes()
        assert (len(gate_raw), hashlib.sha256(gate_raw).hexdigest()) == GATE_PIN
        ast.parse(gate_raw, feature_version=(3, 5))
        exec(compile(gate_raw, self.gate_module.__file__, 'exec'), self.gate_module.__dict__)
        until = time.monotonic() + (-1.0 if expired else 30.0)
        self.state = self.service.State()
        self.state.native_epoch = 0
        self.state._original_service_until = self.state._service_until_original = until
        self.state.probe_actors = []
        self.state.operation = self.state.session = None
        self.state.closing = self.state.wifi_restore_pending = self.state.radio_restore_pending = False
        self.owner = self.owner_module.FixedStateServiceOwner()
        owner = self.owner
        owner.state = self.state
        owner.worker = threading.current_thread()
        owner.clock = time.monotonic
        owner.original_until = owner.until = until
        owner.send_trial_requested = owner._send_trial_requested_original = requested
        owner.started = owner.state_complete = True
        owner.server_called = owner.stop_called = owner.close_called = False
        owner.io = owner.original_io = self.owner_module._LinuxIo()
        owner.loader = types.SimpleNamespace(_original_until=until, clock=time.monotonic,
            modules={'mta_send_trial': self.gate_module, 'mta_go_readonly_parent': self.parent_module})
        owner.assets = [dict(path='HOST_ASSET_' + str(index), fd=index, metadata=(index,),
            raw=b'HOST_MODEL_BYTES', attempted=True, closed=True, unknown=False, failure=None)
            for index in range(71 + asset_delta)]
        owner.probe_rows = self.state.probe_actors
        owner.send_preflight_parent = owner.send_preflight_report = owner.send_preflight_ticket = None
        if requested:
            parent = self.parent_module.ReadonlyDataParent()
            report = self.parent_module.PacketModel()
            report.source_count = 38
            report.source_manifest_sha256 = '8e7882aed5237eb4a2a704bee36bd8a8bdf930c079efae20a90d7dfc26a89b60'
            parent.worker = owner.worker
            parent.clock = time.monotonic
            parent.service_until = parent.task_until = until
            parent.closed = parent.ended = parent.close_attempted = True
            parent.unknown = False
            parent.failure = None
            parent.result = parent.report = parent.result_original = report
            parent.reader = parent.reader_original = types.SimpleNamespace(value=report, ended=True, failure=None)
            parent.packet_functions_original = (None, None, None, None, self.parent_module.PacketModel)
            parent.rows = parent.rows_original = [dict(unknown=False, closed=True, close_failure=None)
                                                  for unused in range(9)]
            parent.row_history = parent.row_history_original = list(parent.rows)
            parent.process = parent.process_original = types.SimpleNamespace(returncode=0)
            parent.process_pid = 950000
            parent.process_methods = (lambda: None, lambda: None)
            parent.close_errors = []
            pipes = []
            for index in range(2):
                row = dict(eof=True, closed=True, unknown=False, close_failure=None,
                    raw_original=types.SimpleNamespace(closed=True), fd_original=100 + index,
                    metadata_original=(index,))
                row['eof_ticket'] = (parent.process, parent.process_pid, row, row['raw_original'],
                                     row['fd_original'], row['metadata_original'], b'')
                pipes.append(row)
            parent.rows[-2:] = pipes
            parent.row_history[:] = parent.rows
            wait_ticket = (parent.process, parent.process_pid, parent.process_methods[1],
                           parent.process.returncode, pipes[0]['eof_ticket'], pipes[1]['eof_ticket'])
            parent.process_attempt = parent.process_attempt_original = dict(returned=True, unknown=False,
                wait_called=True, reaped=True, waited=True, wait_return=0, wait_error=None,
                wait_ticket=wait_ticket, wait_ticket_original=wait_ticket,
                pipes=pipes)
            parent.binding_original = (('HOST_BINDING',),)
            parent.period_original = (until, until + 60.0)
            owner.send_preflight_parent = parent
            owner.send_preflight_report = report
            owner.send_preflight_ticket = dict(partial=parent, returned=parent, constructed=True,
                ended=True, unknown=False, failure=None, collect_return=report)
        cls = self.gate_module.FixedSendTrial
        self.gate = cls.__new__(cls)
        owner.send_trial = owner._send_trial_original = self.gate
        self.state._send_trial = self.state._send_trial_original = self.gate
        owner.send_trial_ticket = dict(partial=self.gate, creator=cls, constructor_called=True,
                                      constructed=False, ended=False)
        cls.__init__(self.gate, owner, requested)
        owner.send_trial_ticket['constructed'] = owner.send_trial_ticket['ended'] = True

    def operation(self, kind='go_send', epoch=1):
        op = self.service.Operation()
        op.kind, op.epoch, op.session = kind, epoch, None
        op.cancelled = threading.Event()
        self.state.operation = op
        self.state.native_epoch = epoch
        return op

    def attach(self, op, direction='send', cancelled=None, until=None):
        session = self.service.TransferSession(lambda value: None, lambda value: True,
            lease_owner=op, extra_actor_close=lambda value: True,
            cancelled=op.cancelled if cancelled is None else cancelled,
            direction=direction, absolute_until=self.owner.until if until is None else until)
        op.session = self.state.session = session
        return session


class SendTrialTests(unittest.TestCase):
    def test_new_fixed_send_phase_contracts(self):
        saved = {name: sys.modules.get(name) for name in CANONICAL}
        cases = []

        def case(name, callback):
            with self.subTest(contract=name):
                callback()
            cases.append(name)
            print('HOST_SEND_TRIAL_CASE=' + name)

        try:
            def unrequested():
                f = Fixture(requested=False)
                self.assertFalse(f.gate.available(f.state))
                self.assertIsNone(f.owner.send_preflight_parent)
                f.gate.revoke(f.state, 'owner_closed')
                self.assertTrue(f.gate.closed(f.state))
            case('default_unrequested_closed', unrequested)

            def phases():
                f = Fixture()
                self.assertTrue(f.gate.available(f.state))
                op = f.operation()
                self.assertIs(f.gate.claim(f.state, op), op)
                self.assertFalse(f.gate.available(f.state))
                session = f.attach(op)
                self.assertFalse(hasattr(session, 'owner'))
                self.assertFalse(hasattr(session, 'direction'))
                self.assertIs(f.gate.attach_session(f.state, op, session), session)
                self.assertTrue(f.gate.allows(f.state, op))
                self.assertFalse(session._worker.is_alive())
                self.assertTrue(all(not row['thread'].is_alive() for row in session._attempts))
                f.gate.revoke(f.state, 'owner_closed')
                self.assertFalse(f.gate.allows(f.state, op))
                self.assertTrue(f.gate.closed(f.state))
                self.assertEqual(f.gate.claim_count, 1)
            case('actual_session78_and_phase_separation', phases)

            def duplicate():
                f = Fixture(); op = f.operation(); f.gate.claim(f.state, op)
                with self.assertRaises(f.gate_module.SendTrialError):
                    f.gate.claim(f.state, op)
                session = f.attach(op); f.gate.attach_session(f.state, op, session)
                with self.assertRaises(f.gate_module.SendTrialError):
                    f.gate.attach_session(f.state, op, session)
                self.assertEqual(f.gate.claim_count, 1)
            case('no_second_claim_or_attach', duplicate)

            def bad_claim(kind, epoch):
                f = Fixture(); op = f.operation(kind, epoch)
                with self.assertRaises(f.gate_module.SendTrialError): f.gate.claim(f.state, op)
                self.assertEqual(f.gate.claim_count, 0)
            case('foreign_kind_refused', lambda: bad_claim('receive', 1))
            case('foreign_epoch_refused', lambda: bad_claim('go_send', 2))

            def foreign_op():
                f = Fixture(); f.operation(); other = self.service_operation(f)
                with self.assertRaises(f.gate_module.SendTrialError): f.gate.claim(f.state, other)
            case('foreign_operation_refused', foreign_op)

            def invalid_session(field):
                f = Fixture(); op = f.operation(); f.gate.claim(f.state, op)
                session = f.attach(op, direction='receive' if field == 'direction' else 'send',
                    cancelled=threading.Event() if field == 'cancel' else None,
                    until=f.owner.until + 1.0 if field == 'deadline' else None)
                with self.assertRaises(f.gate_module.SendTrialError):
                    f.gate.attach_session(f.state, op, session)
            case('wrong_session_direction_refused', lambda: invalid_session('direction'))
            case('foreign_cancel_event_refused', lambda: invalid_session('cancel'))
            case('extended_session_cap_refused', lambda: invalid_session('deadline'))

            def mutate_asset():
                f = Fixture(); f.owner.assets[0]['raw'] = b'CHANGED_HOST_MODEL'
                self.assertFalse(f.gate.available(f.state))
            case('asset_mutation_refused', mutate_asset)

            def bad_count():
                with self.assertRaisesRegex(ValueError, 'send_trial_assets_unknown'):
                    Fixture(asset_delta=1)
            case('asset_inventory_count_refused', bad_count)

            def mutate_parent():
                f = Fixture(); f.owner.send_preflight_parent.process_attempt['wait_return'] = 1
                self.assertFalse(f.gate.available(f.state))
            case('original_preflight_mutation_refused', mutate_parent)

            def worker_changed():
                f = Fixture(); op = f.operation(); f.gate.claim(f.state, op)
                session = f.attach(op); f.gate.attach_session(f.state, op, session)
                session._worker = threading.Thread()
                self.assertFalse(f.gate.allows(f.state, op))
            case('original_worker_changed_refused', worker_changed)

            def cancel():
                f = Fixture(); op = f.operation(); f.gate.claim(f.state, op)
                session = f.attach(op); f.gate.attach_session(f.state, op, session)
                op.cancelled.set(); self.assertFalse(f.gate.allows(f.state, op))
                f.gate.revoke(f.state, 'cancelled'); self.assertTrue(f.gate.closed(f.state))
            case('cancel_and_passive_revoke', cancel)

            def stopped():
                f = Fixture(); f.owner.stop_called = True
                self.assertFalse(f.gate.available(f.state))
                f.gate.revoke(f.state, 'owner_stopped'); self.assertTrue(f.gate.closed(f.state))
            case('owner_stop_and_close_without_io', stopped)

            def expired():
                f = Fixture(expired=True); self.assertFalse(f.gate.available(f.state))
                f.gate.revoke(f.state, 'expired'); self.assertTrue(f.gate.closed(f.state))
            case('expired_revoke_does_not_renew', expired)

            def source_changed():
                f = Fixture(); sys.modules['mta_service'] = types.ModuleType('HOST_foreign')
                self.assertFalse(f.gate.available(f.state))
            case('canonical_source_changed_refused', source_changed)

            def false_grants():
                f = Fixture(); op = f.operation(); f.gate.claim(f.state, op)
                session = f.attach(op); f.gate.attach_session(f.state, op, session)
                facts = f.gate.public_facts(f.state)
                self.assertTrue(facts['preparation_authorized'])
                for key in ('native_started_verified', 'production_admitted', 'restoration_verified'):
                    self.assertIs(facts[key], False)
            case('claimed_preparation_is_not_native_grant', false_grants)
        finally:
            for name, module in saved.items():
                if module is None: sys.modules.pop(name, None)
                else: sys.modules[name] = module
        self.assertEqual(len(cases), 18)
        print('FORMAL_SEND_TRIAL_CONTRACTS=18')

    @staticmethod
    def service_operation(f):
        op = f.service.Operation()
        op.kind, op.epoch, op.session = 'go_send', 1, None
        op.cancelled = threading.Event()
        return op


if __name__ == '__main__':
    unittest.main(verbosity=2)
