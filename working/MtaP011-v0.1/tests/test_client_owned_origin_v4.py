"""Restore-only isolated source; actual codec/Store over FakeIO, no RF.

The synthetic already-saved actors/cleanup callback are not actual init/reap.
Positive coverage intentionally stops at default missing restore producer, so
it proves exact argument/DELETE dispatch, never a completed restore or clear.
"""
import ast
import errno
import hashlib
import importlib.util
import os
import stat
import sys
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE / 'runtime'))
sys.path.insert(0, str(BASE / 'tests'))
import mta_client_linux_provider as original
import mta_client_coordination as coordination
import mta_client_files as files
import mta_client_pending as pending
import mta_client_journal_codec as codec
import mta_client_store as stores
import mta_client_process_owner as processes
import mta_p2p_client_init as core
from test_client_linux_provider import ClosedProc, Collector
from test_client_files import TOKEN, RUN, PENDING
from test_durable_client_store import StoreIo
from test_client_pending import Reader
from test_client_journal_codec import baseline, IDENTITY, OWNED

PATH = BASE / 'candidate/client-owned-origin-v4/runtime/mta_client_linux_provider.py'
spec = importlib.util.spec_from_file_location('owned_origin_v4_provider', str(PATH))
p = importlib.util.module_from_spec(spec); spec.loader.exec_module(p)


def manifest(module):
    return module.ProviderManifest({'version': 1, 'run_token': TOKEN, 'candidate_sha': 'a' * 64,
        'ifname': OWNED.name, 'baseline_manifest': core.STOCK_PINS + ((module.baseline.CLI, 'b' * 64),),
        'status_manifest': {'daemon_exe': '/usr/sbin/wpa_supplicant', 'daemon_sha256': 'c' * 64,
            'endpoint': '/var/run/wpa_supplicant/wlan0', 'real_uid': 0, 'real_gid': 0,
            'namespace_kind': 'namespaces_disabled_cgroup_mnt', 'config_sha256': 'd' * 64},
        'wpa_exe': RUN + '/wpa_supplicant', 'wpa_sha': core.WPA_SHA,
        'python_exe': '/usr/bin/python3.5', 'python_sha': 'e' * 64,
        'executor_path': RUN + '/mta_client_executor.py', 'executor_sha': 'f' * 64}, _manifest_sha256='1' * 64)


class Io(StoreIo):
    def open(self, path, flags): return self._open(path, flags, 0)
    def fstat(self, fd):
        value = StoreIo.fstat(self, fd); value.st_rdev = 0; return value
    def pid(self): return 123


class Proc(ClosedProc):
    def read_self(self):
        value = core.Actor(123, 300, '/usr/bin/python3', 'b' * 64, ((123, 300, 'S'),))
        return self.observation(value)


class OwnedOriginTests(unittest.TestCase):
    def setUp(self):
        for module in (p, original):
            module._OWNERS[:] = []
            self.addCleanup(lambda module=module: module._OWNERS.__setitem__(slice(None), []))
        for target in ('socket.socket', 'subprocess.Popen', 'ctypes.CDLL', 'os.open', 'os.kill', 'os.waitpid'):
            patcher = mock.patch(target, side_effect=AssertionError('actual OS forbidden'), create=True)
            patcher.start(); self.addCleanup(patcher.stop)
        for cls in (coordination._LinuxIo, files._LinuxIo, pending._LinuxIo):
            patcher = mock.patch.object(cls, 'open_root', side_effect=AssertionError('actual root forbidden'))
            patcher.start(); self.addCleanup(patcher.stop)
    def make(self, module=p):
        io, reader = Io(), Reader(); reader.boot = baseline().boot
        store = stores.DurableClientInitStore(TOKEN, IDENTITY, _coordination_io=io,
            _files_io=io, _pending_io=io, _proc_reader=reader, _clock=io.clock)
        self.addCleanup(store.close)
        provider = module.LinuxClientInitProvider(manifest(module), _io=io, _clock=io.clock,
            _proc_factory=lambda **kw: Proc(io, **kw), _collector_factory=Collector)
        owner = processes.DirectChildOwner(_clock=io.clock)
        bridge = module.LinuxDirectChildLaunchBridge(store, owner, provider.specs(), provider)
        lease = module.LinuxClientInitLease(provider, store, IDENTITY, io.clock, bridge)
        provider.attach(store, owner, bridge, lease)
        locks = store.acquire(IDENTITY, 3)
        record = store.commit(locks, core.Journal(IDENTITY, 'prepared', baseline(), 10))
        tickets, actors = {}, {}
        for role, pid in (('watchdog', 200), ('controller', 300)):
            launch = bridge.specs[role]
            tickets[role] = core.Ticket(('1' if role == 'watchdog' else '2') * 32, role, baseline().boot, launch.exe, launch.argv_sha)
            actors[role] = core.Actor(pid, 30, launch.exe, launch.argv_sha, ((pid, 30, 'S'),))
        interface = core.InterfaceTicket(baseline().boot, 0, OWNED.name, 1, 900)
        changes = (dict(stage='watchdog_intent', watchdog_ticket=tickets['watchdog']),
            dict(stage='watchdog_saved', watchdog=actors['watchdog']),
            dict(stage='interface_intent', interface_ticket=interface), dict(stage='interface_owned', owned=OWNED),
            dict(stage='controller_intent', controller_ticket=tickets['controller']),
            dict(stage='controller_saved', controller=actors['controller']), dict(stage='client_init_ready', ready=True))
        for change in changes: record = store.commit(locks, record.replace(**change))
        self.assertIsNot(record.owned, OWNED)
        self.assertEqual(record.owned.key(), OWNED.key())
        provider._owned, provider._self, provider._boot = OWNED, reader.actor, baseline().boot
        provider._baseline_record = baseline()
        b = baseline()
        provider.fake_snapshot = core.Snapshot(b.boot, b.stock_hashes, b.stock_actors, b.station,
            b.station_state_sha, b.station_frequency, b.interfaces + (OWNED,), b.ipv4,
            b.ipv6_addresses, b.ipv6_routes, b.station_completed)
        provider._kernel.interfaces = lambda deadline: provider.fake_snapshot.interfaces
        actions, arguments = [], []
        def request(family, command, attributes, flags, deadline):
            self.assertEqual(8, command); self.assertEqual(module._attr(153, __import__('struct').pack('<Q', OWNED.wdev)), attributes)
            actions.append(command); provider.fake_snapshot = baseline(); return []
        provider._kernel.request, provider._kernel.family = request, 30
        # Deliberate SYNTHETIC child closure, not a wait/reap or kernel proof.
        bridge.cleanup = lambda *args: True
        bridge.verify_closed = lambda: True
        old_ready = provider.cleanup_origin_ready
        def ready(owned, deadline): arguments.append(owned); return old_ready(owned, deadline)
        provider.cleanup_origin_ready = ready
        lease.record, lease.locks = record, locks
        store.active_return(locks, record)
        return lease, provider, store, io, actions, arguments
    def assert_no_reclaim(self, lease, store, io, actions):
        self.assertFalse(lease.restore()['cleanup_complete'])
        self.assertEqual([], actions); self.assertIn(PENDING, io.nodes)
        self.assertFalse(store._finish_sealed)
        self.assertEqual(0, io.counts.get(('unlink', PENDING), 0))
    def test_actual_codec_clone_old_blocks_new_dispatches_exact_original(self):
        old = self.make(original); self.assert_no_reclaim(old[0], old[2], old[3], old[4])
        self.assertNotEqual([], old[5]); self.assertIsNot(old[5][0], OWNED)
        lease, provider, store, io, actions, arguments = self.make()
        before = codec.decode_journal(codec.encode_journal(lease.record))
        self.assertIsNot(before.owned, OWNED); self.assertEqual(before.owned.key(), OWNED.key())
        result = lease.restore()
        self.assertEqual([8], actions); self.assertTrue(arguments)
        self.assertTrue(all(value is provider._owned for value in arguments))
        self.assertFalse(result['cleanup_complete']); self.assertIn(PENDING, io.nodes)
        self.assertFalse(store._finish_sealed)  # Default producer intentionally absent.
        self.assertFalse(result['send_available']); self.assertFalse(result['receive_available'])
    def test_issued_missing_unknown_or_non_origin_never_dispatch_or_clear(self):
        for invalid in (None, object(), True):
            p._OWNERS[:] = []
            lease, provider, store, io, actions, arguments = self.make(); provider._owned = invalid
            self.assert_no_reclaim(lease, store, io, actions); self.assertEqual([], arguments)
    def test_full_origin_mismatch_each_dimension_never_reclaims(self):
        values = ((1, OWNED.wdev, OWNED.ifindex, OWNED.name, 8),
            (0, OWNED.wdev + 1, OWNED.ifindex, OWNED.name, 8),
            (0, OWNED.wdev, OWNED.ifindex + 1, OWNED.name, 8),
            (0, OWNED.wdev, OWNED.ifindex, 'mta00000000', 8),
            (0, OWNED.wdev, OWNED.ifindex, OWNED.name, 2))
        for args in values:
            p._OWNERS[:] = []
            lease, provider, store, io, actions, arguments = self.make(); provider._owned = core.Origin(*args)
            self.assert_no_reclaim(lease, store, io, actions); self.assertEqual([], arguments)
    def test_fresh_kernel_origin_changed_gate_not_relaxed(self):
        lease, provider, store, io, actions, arguments = self.make()
        changed = core.Origin(OWNED.phy, OWNED.wdev, OWNED.ifindex, OWNED.name, 2)
        provider._kernel.interfaces = lambda deadline: baseline().interfaces + (changed,)
        self.assert_no_reclaim(lease, store, io, actions)
        self.assertEqual([OWNED], arguments)
    def test_full_original_baseline_and_same_boot_still_required(self):
        for boot, state in (('00000000-0000-0000-0000-000000000000', baseline().station_state_sha),
                            (baseline().boot, '0' * 64)):
            p._OWNERS[:] = []
            lease, provider, store, io, actions, arguments = self.make(); b = provider.fake_snapshot
            provider.fake_snapshot = core.Snapshot(boot, b.stock_hashes, b.stock_actors, b.station,
                state, b.station_frequency, b.interfaces, b.ipv4, b.ipv6_addresses, b.ipv6_routes, True)
            self.assert_no_reclaim(lease, store, io, actions); self.assertEqual([], arguments)
    def test_exact_six_line_diff_original_and_connection_copy_unchanged_python35(self):
        before = (BASE / 'runtime/mta_client_linux_provider.py').read_text(encoding='utf-8')
        after = PATH.read_text(encoding='utf-8')
        addition = ("                if owned is not None:\n"
            "                    # Durable readback is a value object, not the CREATE owner.\n"
            "                    issued = self.provider._owned\n"
            "                    if type(issued) is not core.Origin or type(owned) is not core.Origin or issued.key() != owned.key():\n"
            "                        core._fail('origin_changed')\n"
            "                    owned = issued\n")
        self.assertEqual(1, after.count(addition)); self.assertEqual(before.rstrip('\n'), after.replace(addition, '').rstrip('\n'))
        ast.parse(after, feature_version=(3, 5)); ast.parse(Path(__file__).read_text(encoding='utf-8'), feature_version=(3, 5))
        self.assertEqual('8996ae6aa82e48170514f61fc301a83532cf28a20f385153ff41c1e68b236544', hashlib.sha256((BASE / 'runtime/mta_client_linux_provider.py').read_bytes()).hexdigest())
        self.assertEqual('41459a480e9d78924a792bd881d25cd0696d64f0637a9d4b9be06083af09d25b', hashlib.sha256((BASE / 'candidate/client-connection/runtime/mta_client_linux_provider.py').read_bytes()).hexdigest())


if __name__ == '__main__': unittest.main()
