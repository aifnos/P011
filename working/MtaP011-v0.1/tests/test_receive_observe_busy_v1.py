"""One focused HOST RLock/thread test; no receiver/RF/ACK actor is replaced."""
import importlib.util
from pathlib import Path
import threading
import time
import types
import unittest

BASE = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('observe_busy_host',
    BASE / 'candidate/receive-advertise-smoke-v2/runtime/advertise_smoke_session.py')
HOOK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HOOK)


class LockObservationTest(unittest.TestCase):
    def test_busy_retry_deadline_and_identity_refusal(self):
        # Only the observer's plain local fields are supplied. No helper,
        # advertising, native event, Session start, Trial or restoration model.
        State = type('HostStateFields', (), {})
        Operation = type('HostOperationFields', (), {})
        Session = type('HostSessionFields', (), {})
        state, op, session = State(), Operation(), Session()
        session._worker = threading.current_thread()
        op.kind, op.session, op.epoch, op.stage = 'receive', session, 1, 'connecting'
        op.client_handoff = op.client_bridge = op.helper = None
        op.cancelled, op.actor_unknown = threading.Event(), False
        state.operation, state.session, state.worker = op, session, session._worker
        state.native_epoch, state.state, state.discoverable = 1, 'connecting', False
        state.helper = state.request = None
        state.event_counts, state.lock = {}, threading.RLock()
        owner = types.SimpleNamespace(state=state, _state_original=state,
            service=types.SimpleNamespace(State=State, Operation=Operation, TransferSession=Session))
        component = types.SimpleNamespace(owner=owner, until=time.monotonic() + 3, check=lambda: None)
        flags = dict(listen_seen=False, advertising_seen=False, peer_activity_seen=False, native_failure_seen=False)
        ready, release = threading.Event(), threading.Event()
        def holder():
            with state.lock:
                ready.set()
                release.wait(2)
        thread = threading.Thread(target=holder)
        thread.start(); self.assertTrue(ready.wait(1))
        timer = threading.Timer(.22, release.set)
        timer.start()
        started = time.monotonic()
        rows = []
        try:
            reason = HOOK.observe_window(component, started, started + .38, rows, flags)
        finally:
            release.set(); thread.join(1); timer.join(1)
        self.assertEqual(reason, 'advert_not_observed')
        self.assertGreaterEqual(HOOK._OBSERVATION_BUSY_COUNT, 1)
        self.assertTrue(rows)
        self.assertTrue(all(not row['advertising'] and row['event_counts'] == (0, 0, 0, 0, 0, 0) for row in rows))
        print('HOST_BUSY_THEN_READABLE_SECONDS=%.6f' % (time.monotonic() - started))

        # A real other thread holds the lock beyond the shortened HOST window.
        ready.clear(); release.clear()
        thread = threading.Thread(target=holder)
        thread.start(); self.assertTrue(ready.wait(1))
        started = time.monotonic(); rows = []
        try:
            reason = HOOK.observe_window(component, started, started + .25, rows, flags)
            elapsed = time.monotonic() - started
        finally:
            release.set(); thread.join(1)
        self.assertEqual(reason, 'advert_not_observed')
        self.assertEqual(rows, [])
        self.assertFalse(flags['advertising_seen'])
        self.assertLess(elapsed, .40)
        print('HOST_ALL_BUSY_WINDOW_SECONDS=%.6f' % elapsed)

        owner._state_original = object()
        with self.assertRaisesRegex(ValueError, 'original_receive_inventory_unknown'):
            HOOK.observe(component)
        self.assertTrue(state.lock.acquire(False))
        state.lock.release()


if __name__ == '__main__':
    unittest.main(verbosity=2)
