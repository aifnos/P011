"""HOST-only Wi-Fi wrapper contracts using private in-process process fixtures.

No ConnMan calls, scans, wireless changes, actual credentials or P011 access.
"""
import io
from pathlib import Path
import queue
import sys
import threading
import tempfile
import os
import unittest
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE / 'runtime'))
import p011_json as json
from mta_protocol import P2pInfo
import mta_wifi as wifi


class FakeStdout:
    def __init__(self):
        self.lines = queue.Queue()
        self.closed = False

    def add(self, event):
        self.lines.put((json.dumps(event) + '\n').encode('utf-8'))

    def readline(self, maximum):
        return self.lines.get(timeout=2)

    def close(self):
        self.closed = True


class FakeStdin:
    def __init__(self, process):
        self.process = process
        self.closed = False

    def write(self, wire):
        value = json.loads(wire.decode('ascii'))
        self.process.commands.append(value)
        if value['cmd'] == 'prepare':
            self.process.stdout.add({'event': 'prepared', 'ok': True, 'networkUntouched': True, 'snapshotCaptured': True})
        elif value['cmd'] == 'receive':
            self.process.stdout.add({'event': 'connecting', 'ok': True})
            if self.process.fail:
                self.process.stdout.add({'event': 'error', 'ok': False, 'reason': 'TARGET_PROFILE_OWNERSHIP_NOT_PROVEN'})
            else:
                self.process.stdout.add({'event': 'connected', 'ok': True, 'address': '192.168.49.2', 'gateway': self.process.gateway})
        elif value['cmd'] == 'restore':
            self.process.stdout.add({'event': 'restoring', 'ok': True})
            self.process.stdout.add({'event': 'restored', 'ok': self.process.verified, 'originalNetworkRestored': self.process.verified, 'temporaryProfileRemoved': self.process.verified})
            self.process.returncode = 0
            self.process.stdout.lines.put(b'')
        return len(wire)

    def flush(self):
        pass

    def close(self):
        self.closed = True


class FakeProcess:
    def __init__(self, fail=False, gateway='192.168.49.1', verified=True):
        self.stdout = FakeStdout()
        self.stdin = FakeStdin(self)
        self.commands = []
        self.fail = fail
        self.gateway = gateway
        self.verified = verified
        self.returncode = None
        self.killed = False

    def poll(self):
        return self.returncode

    def kill(self):
        self.killed = True


class WifiTests(unittest.TestCase):
    def setUp(self):
        # Filesystem ownership is exercised separately on POSIX. This class
        # uses private process fixtures and never touches production paths.
        self.pending = mock.patch.object(wifi.WifiBackend, '_refresh_pending', lambda self: None)
        self.directory = mock.patch.object(wifi.WifiBackend, '_ensure_journal_dir', lambda self: None)
        self.pending.start(); self.directory.start()
        self.addCleanup(self.pending.stop); self.addCleanup(self.directory.stop)

    def info(self):
        return P2pInfo('HOST-fixture', 'fixture-password', '02:00:00:00:00:01', 58888)

    def test_explicit_consent_before_process(self):
        backend = wifi.WifiBackend('/not-installed')
        with mock.patch.object(backend, '_spawn') as spawn:
            with self.assertRaises(wifi.WifiUnavailable):
                backend.receive(self.info())
            spawn.assert_not_called()

    def test_credentials_not_in_argv_and_no_shell(self):
        backend = wifi.WifiBackend('/host-fixture/helper')
        with mock.patch.object(wifi.os.path, 'isfile', return_value=True), mock.patch.object(wifi.os, 'access', return_value=True), mock.patch.object(wifi.subprocess, 'Popen') as popen:
            backend._spawn('--receive')
            args, kwargs = popen.call_args
            self.assertEqual(args[0], [backend.helper_path, '--receive'])
            self.assertNotIn('shell', kwargs)
            self.assertEqual(kwargs['stderr'], wifi.subprocess.DEVNULL)

    def test_real_gateway_and_verified_context_restore(self):
        backend = wifi.WifiBackend('/host-fixture/helper')
        process = FakeProcess()
        with mock.patch.object(backend, '_spawn', return_value=process):
            with backend.receive(self.info(), consented=True, timeout=20) as lease:
                self.assertEqual(lease.gateway, '192.168.49.1')
                self.assertEqual(lease.local_ip, '192.168.49.2')
                with self.assertRaises(wifi.WifiUnavailable):
                    backend.receive(self.info(), consented=True, timeout=20)
            self.assertTrue(lease.closed and lease.restored)
            self.assertFalse(process.killed)
            self.assertEqual(process.commands[0]['cmd'], 'prepare')
            self.assertEqual(process.commands[1]['cmd'], 'receive')
            self.assertEqual(process.commands[1]['consented'], True)
            self.assertNotIn('psk', process.commands[1])
            self.assertNotIn('ssid', process.commands[1])
            self.assertEqual(process.commands[-1], {'cmd': 'restore'})
            self.assertTrue(backend._lease_lock.acquire(False))
            backend._lease_lock.release()

    def test_connection_failure_still_restores(self):
        backend = wifi.WifiBackend('/host-fixture/helper')
        process = FakeProcess(fail=True)
        with mock.patch.object(backend, '_spawn', return_value=process):
            with self.assertRaisesRegex(wifi.WifiUnavailable, '归属'):
                backend.receive(self.info(), consented=True, timeout=20)
        self.assertEqual(process.commands[-1], {'cmd': 'restore'})
        self.assertFalse(process.killed)

    def test_bad_gateway_is_not_guessed_and_restores(self):
        backend = wifi.WifiBackend('/host-fixture/helper')
        process = FakeProcess(gateway='')
        with mock.patch.object(backend, '_spawn', return_value=process):
            with self.assertRaises(wifi.WifiError):
                backend.receive(self.info(), consented=True, timeout=20)
        self.assertEqual(process.commands[-1], {'cmd': 'restore'})

    def test_cancellation_before_mutation(self):
        backend = wifi.WifiBackend('/host-fixture/helper')
        with mock.patch.object(backend, '_spawn') as spawn:
            with self.assertRaises(wifi.WifiCancelled):
                backend.receive(self.info(), cancelled=lambda: True, consented=True)
            spawn.assert_not_called()

    def test_restore_failure_is_not_success(self):
        backend = wifi.WifiBackend('/host-fixture/helper')
        process = FakeProcess(verified=False)
        with mock.patch.object(backend, '_spawn', return_value=process):
            with self.assertRaises(wifi.WifiRestoreError):
                with backend.receive(self.info(), consented=True, timeout=20):
                    pass
            self.assertFalse(backend.capabilities()['receive'])
            with self.assertRaises(wifi.WifiRestoreError):
                backend.receive(self.info(), consented=True, timeout=20)

    def test_ap_p2p_unavailable_and_no_spawn(self):
        backend = wifi.WifiBackend('/host-fixture/helper')
        with mock.patch.object(backend, '_spawn') as spawn:
            for name in ('send_lease', 'create_p2p_lease', 'create_ap_lease'):
                with self.assertRaises(wifi.WifiUnavailable):
                    getattr(backend, name)()
            spawn.assert_not_called()

    def test_no_helper_capability_is_false(self):
        result = wifi.WifiBackend('/not-installed').capabilities()
        self.assertFalse(result['receive'])
        self.assertFalse(result['send'])
        self.assertFalse(result['p2pVerified'])

    def test_repr_and_unknown_error_do_not_leak(self):
        info = wifi.NetworkInfo.from_p2p_info(self.info())
        self.assertNotIn('fixture', repr(info))
        self.assertNotIn('private-network-password', wifi._reason({'reason': 'private-network-password'}))

    def test_invalid_or_encrypted_credentials_do_not_spawn(self):
        backend = wifi.WifiBackend('/host-fixture/helper')
        with mock.patch.object(backend, '_spawn') as spawn:
            for value in ({'ssid': 'bad'}, {'ssid': 'HOST', 'psk': 'short', 'mac': '02:00:00:00:00:01', 'port': 1234}, 'shell arbitrary'):
                with self.assertRaises(wifi.WifiError):
                    backend.receive(value, consented=True, timeout=20)
            spawn.assert_not_called()

    def test_ipv4_validation(self):
        for value in ('', '192.168.1.999', '192.168.01.1', '0.0.0.0', 'example.com', '::1', '1.2.3.4\"bad'):
            with self.assertRaises(wifi.WifiError):
                wifi._ipv4(value)
        self.assertEqual(wifi._ipv4('10.42.0.1'), '10.42.0.1')

    def test_native_mutations_remain_narrow(self):
        source = (BASE / 'native' / 'mta_network.c').read_text(encoding='utf-8')
        for forbidden in ('system(', 'popen(', 'killall', 'SetProperty\", g_variant_new(\"(sv)\", \"Powered', 'wpa_cli', 'Tethering'):
            self.assertNotIn(forbidden, source)
        self.assertIn('find(l->before, candidate->path)', source)
        self.assertIn('TARGET_PROFILE_OWNERSHIP_NOT_PROVEN', source)
        self.assertIn('signal(SIGPIPE, SIG_IGN)', source)
        self.assertIn('#define MTA_PROFILE_ROOT "/var/lib/connman"', source)
        self.assertIn('same_profile(l)', source)

    def test_prepare_reuses_process_before_credentials(self):
        backend = wifi.WifiBackend('/host-fixture/helper')
        process = FakeProcess()
        with mock.patch.object(backend, '_spawn', return_value=process) as spawn:
            prepared = backend.prepare(timeout=30)
            self.assertTrue(prepared.prepared)
            self.assertEqual([c['cmd'] for c in process.commands], ['prepare'])
            self.assertNotIn('consented', process.commands[0])
            self.assertEqual(backend.status(), {'restorePending': False, 'recoveryLocked': False, 'prepared': True, 'reason': ''})
            self.assertIs(backend.prepare(), prepared)
            lease = backend.receive(self.info(), consented=True, timeout=20)
            self.assertIs(prepared, lease)
            spawn.assert_called_once_with('--prepare')
            self.assertTrue(lease.restore())

    def test_private_begin_prepare_reserves_exact_owner_without_spawning(self):
        backend=wifi.WifiBackend('/host-fixture/helper');process=FakeProcess()
        with mock.patch.object(backend,'_spawn',return_value=process) as spawn:
            lease=backend.begin_prepare(timeout=30)
            self.assertIs(backend._active_lease,lease);self.assertIsNone(lease.process);spawn.assert_not_called()
            lease.prepare();self.assertTrue(lease.prepared);self.assertIs(backend.prepare(),lease)
            self.assertTrue(lease.restore());self.assertFalse(lease.reader.is_alive())
            self.assertTrue(process.stdin.closed);self.assertTrue(process.stdout.closed)

    def test_reserved_prepare_spawn_exception_retains_unknown_lease(self):
        backend=wifi.WifiBackend('/host-fixture/helper');lease=backend.begin_prepare()
        with mock.patch.object(backend,'_spawn',side_effect=KeyboardInterrupt('HOST_PRIVATE_SPAWN')):
            with self.assertRaises(KeyboardInterrupt):lease.prepare()
        self.assertIs(backend._active_lease,lease);self.assertTrue(lease._spawn_unknown)
        self.assertFalse(lease.restore());self.assertFalse(lease.actors_closed())
        self.assertTrue(backend.status()['recoveryLocked'])

    def test_reserved_reader_created_then_start_interrupt_is_not_closed_proof(self):
        backend=wifi.WifiBackend('/host-fixture/helper');lease=backend.begin_prepare();process=FakeProcess()
        original=threading.Thread.start
        def interrupted(thread):original(thread);raise KeyboardInterrupt('HOST_PRIVATE_READER_START')
        with mock.patch.object(backend,'_spawn',return_value=process),mock.patch.object(threading.Thread,'start',interrupted):
            with self.assertRaises(KeyboardInterrupt):lease.prepare()
        lease.reader.join(2);self.assertFalse(lease.reader.is_alive());self.assertTrue(lease._reader_unknown)
        self.assertFalse(lease.restore());self.assertIs(backend._active_lease,lease)
        self.assertFalse(lease.actors_closed());self.assertFalse(process.killed)

    def test_prepare_only_can_cancel_without_network_restore_claim(self):
        backend = wifi.WifiBackend('/host-fixture/helper')
        process = FakeProcess()
        with mock.patch.object(backend, '_spawn', return_value=process):
            lease = backend.prepare()
            process.verified = True
            self.assertTrue(backend.restore_active())
            self.assertEqual([c['cmd'] for c in process.commands], ['prepare', 'restore'])

    def test_native_untouched_restored_is_accepted(self):
        self.assertTrue(wifi._restored({'event': 'restored', 'ok': True, 'networkUntouched': True, 'temporaryProfileRemoved': True}))
        self.assertFalse(wifi._restored({'event': 'restored', 'ok': True, 'temporaryProfileRemoved': True}))

    def test_recovery_timeout_keeps_actor_and_blocks_second_recover(self):
        backend = wifi.WifiBackend('/host-fixture/helper')
        backend._pending = ['/host-fixture/lease-1-2.ini']
        process = mock.Mock()
        process.pid = 123
        process.poll.return_value = None
        process.communicate.side_effect = wifi.subprocess.TimeoutExpired('fixed-helper', 40)
        with mock.patch.object(backend, '_spawn', return_value=process) as spawn, mock.patch.object(wifi, '_process_start', return_value=456):
            self.assertFalse(backend.recover_pending())
            self.assertIs(backend._recovery_actor['process'], process)
            self.assertEqual(backend._recovery_actor['start'], 456)
            self.assertTrue(backend.status()['recoveryLocked'])
            self.assertFalse(backend.recover_pending())
            spawn.assert_called_once_with('--recover')
            process.kill.assert_not_called()
            with self.assertRaises(wifi.WifiRestoreError): backend.prepare()

    def test_recovery_popen_interrupt_retains_unknown_start_without_second_spawn(self):
        backend=wifi.WifiBackend('/host-fixture/helper');backend._pending=['/host-fixture/lease-1-2.ini']
        with mock.patch.object(backend,'_spawn',side_effect=KeyboardInterrupt('HOST_PRIVATE_RECOVERY_START')) as spawn:
            self.assertFalse(backend.recover_pending());self.assertTrue(backend._recovery_spawn_unknown)
            self.assertTrue(backend.status()['recoveryLocked']);self.assertFalse(backend.recover_pending())
            spawn.assert_called_once_with('--recover')

    def test_recovery_communicate_interrupt_keeps_exact_handle_and_original_pipes(self):
        backend=wifi.WifiBackend('/host-fixture/helper');backend._pending=['/host-fixture/lease-1-2.ini'];process=mock.Mock()
        process.pid=123;process.poll.return_value=None;process.communicate.side_effect=KeyboardInterrupt('HOST_PRIVATE_RECOVERY_COMMUNICATE')
        stdin=process.stdin;stdout=process.stdout
        with mock.patch.object(backend,'_spawn',return_value=process) as spawn,mock.patch.object(wifi,'_process_start',return_value=456):
            self.assertFalse(backend.recover_pending());actor=backend._recovery_actor
            self.assertIs(actor['process'],process);self.assertIs(actor['stdin'],stdin);self.assertIs(actor['stdout'],stdout)
            self.assertIsNone(process.stdin);self.assertFalse(backend.recover_pending());spawn.assert_called_once()
            process.kill.assert_not_called();self.assertTrue(backend.status()['restorePending'])

    def test_closed_failed_old_lease_without_journal_cannot_invent_recovery(self):
        backend=wifi.WifiBackend('/host-fixture/helper');lease=backend.begin_prepare()
        process=FakeProcess();process.returncode=0;process.stdin.closed=True;process.stdout.closed=True
        lease.process=process;lease.closed=True;lease.restored=False;lease._spawn_claimed=True;lease._spawn_resolved=True
        self.assertTrue(lease.actors_closed());backend._restore_failed=True
        with mock.patch.object(backend,'_spawn') as spawn:
            self.assertFalse(backend.recover_pending());spawn.assert_not_called()
        self.assertIs(backend._active_lease,lease);self.assertFalse(lease.restored);self.assertTrue(backend.status()['restorePending'])

    def test_existing_recovery_native_success_still_requires_exact_two_pipes_closed(self):
        backend=wifi.WifiBackend('/host-fixture/helper');process=FakeProcess();process.returncode=0
        process.communicate=mock.Mock(return_value=(b'HOST_NATIVE_RESTORE_PROOF',None))
        actor={'process':process,'path':'/host-fixture/lease-1-2.ini','stdin':process.stdin,'stdout':process.stdout,'pid':123,'start':456}
        backend._recovery_actor=actor;backend._restore_failed=True
        with mock.patch.object(backend,'_recovery_confirmed',return_value=True),mock.patch.object(backend,'_spawn') as spawn:
            self.assertFalse(backend.recover_pending());self.assertIs(backend._recovery_actor,actor)
            process.stdin.closed=True;self.assertFalse(backend.recover_pending())
            process.stdout.closed=True;self.assertTrue(backend.recover_pending());spawn.assert_not_called()
        self.assertIsNone(backend._recovery_actor);self.assertFalse(backend.status()['restorePending'])


@unittest.skipIf(os.name == 'nt', 'POSIX ownership/mode tests run in host Linux fixture')
class JournalTests(unittest.TestCase):
    def test_existing_journal_requires_recovery_no_new_prepare(self):
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o700)
            path = Path(directory) / 'lease-1-2.ini'
            path.write_text('[Lease]\nVersion=1\n', encoding='ascii')
            os.chmod(str(path), 0o600)
            backend = wifi.WifiBackend('/not-installed', journal_dir=directory)
            self.assertTrue(backend.status()['restorePending'])
            with mock.patch.object(backend, '_spawn') as spawn:
                with self.assertRaises(wifi.WifiRestoreError): backend.prepare()
                spawn.assert_not_called()

    def test_symlink_journal_locks_and_is_not_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o700)
            outside = Path(directory) / 'outside'
            outside.write_text('private', encoding='ascii')
            os.symlink(str(outside), str(Path(directory) / 'lease-1-2.ini'))
            backend = wifi.WifiBackend('/not-installed', journal_dir=directory)
            self.assertTrue(backend.status()['recoveryLocked'])
            self.assertFalse(backend.recover_pending())
            self.assertEqual(outside.read_text(), 'private')


if __name__ == '__main__':
    unittest.main(verbosity=2)
