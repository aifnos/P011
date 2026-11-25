"""New local-MAC SOURCE/Fake tests only. No DHCP/AssociationProof/OS/RF."""
import ast
import hashlib
from pathlib import Path
import sys
import unittest

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE / 'tests'))
import test_client_kernel_provider_v15 as old

load, fixture = old.prior.load, old.prior.fixture
ROOT = BASE / 'candidate/client-association-v16/runtime'
V15 = BASE / 'candidate/client-kernel-connect-v15/runtime'
k = load('association_mac_v16_kernel', ROOT / 'mta_client_kernel_proof.py')
c = load('association_mac_v16_connection', ROOT / 'mta_client_connection.py', {'mta_client_kernel_proof': k})
# The Provider is the frozen v15 bytes, merely loaded in the exact new typed
# kernel/connection domain. No patch, replacement definition or fake issuer.
p = load('association_mac_v16_frozen_provider', V15 / 'mta_client_linux_provider.py',
    {'mta_client_kernel_proof': k, 'mta_client_connection': c, 'mta_client_tmp_alias': old.prior.alias})
manifest = fixture(old.manifest, {'p': p})
LOCAL = b'\x02\x66\x77\x88\x99\xaa'
CHANGED = b'\x02\x66\x77\x88\x99\xab'


def packets(macs=(LOCAL,) * 3, flagged=0, duplicate=False):
    faces = []
    for mac in macs:
        value = old.interface()
        if mac is not None:
            field = old.wire.attr(6, mac, flagged); value += field
            if duplicate: value += field
        faces.append(value)
    return old.kernel_fixture.packets(faces, [[old.station()], [old.station()]])


class AssociationMacV16Tests(unittest.TestCase):
    setUp = fixture(old.KernelProviderV15Tests.setUp, {'p': p})
    _make = fixture(old.KernelProviderV15Tests._make, {'p': p, 'c': c, 'manifest': manifest})
    make = fixture(old.KernelProviderV15Tests.make, {'p': p, 'c': c, 'k': k, 'packets': packets})
    connect = fixture(old.KernelProviderV15Tests.connect, {'c': c})
    closed = old.KernelProviderV15Tests.closed
    reject = fixture(old.KernelProviderV15Tests.reject, {'c': c})
    def reader(self, values):
        io = old.KernelIo(values); owner = object()
        reader = k.ClientKernelReader(old.old.OWNED, old.old.baseline().boot, owner, old.EPOCH,
            _io=io, _clock=lambda: 1.0, _proc_factory=lambda **kw: p.proc.ProcReader(_fs=old.proc_fs(), **kw),
            _checkpoint=lambda: False, _deadline=5.0)
        return reader, io, owner
    def test_actual_get_interface_local_mac_private_only_all_three_raw_preserved(self):
        reader, io, owner = self.reader(packets()); result = reader.read()
        self.assertEqual(LOCAL, result.private_fields()['local_mac'])
        self.assertTrue(result.public_summary()['local_mac_observed'])
        self.assertNotEqual(LOCAL, result.private_fields()['stations'][0][0])
        self.assertIsNone(reader.authenticate(owner, old.EPOCH, result))
        field = old.wire.attr(6, LOCAL)
        self.assertEqual(3, sum(value == field for value in reader.unassessed_attributes))
        self.assertEqual(6, len(reader.raw_requests)); self.assertFalse(io.live)
        self.assertTrue(reader.status()['resources_closed']); self.assertEqual(1, io.raw.close_count)
        self.assertNotIn('66', repr(result)); self.assertNotIn('local_mac', str(result.public_summary()).replace('local_mac_observed', ''))
        self.assertFalse(result.public_summary()['ip_verified'])
        with self.assertRaises(AttributeError): result._local_mac = CHANGED
    def test_missing_mac_retains_unknown_not_a_guessed_address(self):
        reader, io, owner = self.reader(packets((None,) * 3)); result = reader.read()
        self.assertIsNone(result.private_fields()['local_mac'])
        self.assertFalse(result.public_summary()['local_mac_observed'])
        self.assertIsNone(reader.authenticate(owner, old.EPOCH, result))
        self.assertTrue(reader.status()['resources_closed']); self.assertFalse(io.live)
    def test_bad_mac_length_zero_multicast_flags_duplicate_actual_parser_rejects(self):
        cases = ((b'', 0, False), (LOCAL[:-1], 0, False), (LOCAL + b'x', 0, False),
            (b'\0' * 6, 0, False), (b'\x01' + LOCAL[1:], 0, False), (LOCAL, 0x8000, False),
            (LOCAL, 0x4000, False), (LOCAL, 0, True))
        for mac, flags, duplicate in cases:
            with self.subTest(size=len(mac), flags=flags, duplicate=duplicate):
                reader, io, owner = self.reader(packets((mac,) * 3, flags, duplicate))
                with self.assertRaises(k.KernelReadError) as error: reader.read()
                self.assertIn(error.exception.code, ('attribute_format', 'attribute_duplicate'))
                self.assertTrue(reader.status()['resources_closed']); self.assertFalse(io.live)
                self.assertEqual(1, io.raw.close_count); self.assertIsNone(reader._observation)
    def test_three_get_mac_change_or_mixed_missing_rejects_with_all_originals_closed(self):
        for macs in ((LOCAL, CHANGED, LOCAL), (LOCAL, LOCAL, CHANGED), (None, LOCAL, None)):
            with self.subTest(missing=macs[0] is None):
                reader, io, owner = self.reader(packets(macs))
                with self.assertRaises(k.KernelReadError) as error: reader.read()
                self.assertEqual('interface_changed', error.exception.code)
                self.assertEqual(6, len(reader.raw_requests)); self.assertFalse(io.live)
                self.assertTrue(reader.status()['resources_closed'])
    def test_connection_actual_status_address_matches_local_not_bssid_ble_go(self):
        lease, provider, store, io, kernels, caps = self.make()
        first = self.connect(lease); second = lease.read_connection(first)
        self.assertIs(type(second), c.ConnectionObservation); self.assertEqual(4, len(kernels))
        self.assertTrue(all(value.private_fields()['local_mac'] == LOCAL for value in second._kernels))
        self.assertEqual(LOCAL, second._statuses[0].private_fields()['address'])
        self.assertNotEqual(LOCAL, second._statuses[0].private_fields()['bssid'])
        self.assertNotEqual(LOCAL, provider._connection.peer_mac)
        self.closed(provider); self.assertFalse(second.public_summary()['endpoint_verified'])
    def test_connection_missing_kernel_mac_rejects_despite_completed_status(self):
        lease, provider, store, io, kernels, caps = self.make(rows=packets((None,) * 3))
        self.reject(lease, 'kernel_unverified'); self.closed(provider)
        self.assertTrue(all(row['value']._local_mac is None for row in provider._kernel_readers))
    def test_connection_local_mac_different_from_authenticated_status_rejects(self):
        lease, provider, store, io, kernels, caps = self.make(rows=packets((CHANGED,) * 3))
        self.reject(lease, 'kernel_unverified'); self.closed(provider)
    def test_two_round_mac_change_with_status_agreeing_each_round_still_rejects(self):
        lease, provider, store, io, kernels, caps = self.make(rows=lambda n: packets(((LOCAL if n == 0 else CHANGED),) * 3))
        count = [0]
        def command(raw, value):
            if value == b'STATUS':
                count[0] += 1
                if count[0] == 2: io.status_wire = old.old.CONNECTED.replace(b'address=02:66:77:88:99:aa', b'address=02:66:77:88:99:ab')
        io.command_hook = command
        # Existing two STATUS full equality fails before the private MAC key;
        # both actual new kernel values are nevertheless preserved and closed.
        self.reject(lease, 'status_mismatch'); self.assertEqual(2, len(kernels)); self.closed(provider)
        self.assertEqual([LOCAL, CHANGED], [row['value']._local_mac for row in provider._kernel_readers])
    def test_readback_local_mac_changed_keeps_old_result_and_new_observation_inventory(self):
        lease, provider, store, io, kernels, caps = self.make(rows=lambda n: packets(((LOCAL if n < 2 else CHANGED),) * 3))
        first = self.connect(lease)
        io.status_wire = old.old.CONNECTED.replace(b'address=02:66:77:88:99:aa', b'address=02:66:77:88:99:ab')
        with self.assertRaises(c.ConnectionError) as error: lease.read_connection(first)
        self.assertEqual('kernel_mismatch', error.exception.code)
        op = provider._connection
        self.assertTrue(op.failed); self.assertIs(op.result, first)
        self.assertEqual('kernel_mismatch', op.reason)
        self.assertEqual(2, len(op.observations)); self.assertEqual(CHANGED, op.observations[-1]._kernels[0]._local_mac)
        self.assertEqual(4, len(kernels)); self.closed(provider)
    def test_exact_source_inverse_and_all_unchanged_methods_python35(self):
        source = (ROOT / 'mta_client_kernel_proof.py').read_text(encoding='utf-8')
        mac_block = ("    local_mac = None\n    if 6 in fields:  # Linux v4.14 NL80211_ATTR_MAC / wdev_address, not peer MAC.\n"
            "        flags, raw, unused = fields[6]\n        if flags or type(raw) is not bytes or len(raw) != 6 or not any(raw) or raw[0] & 1:\n"
            "            _fail('attribute_format')\n        local_mac = raw\n")
        replacements = ((mac_block, ''), ('return (role, frequency), extra, local_mac', 'return (role, frequency), extra'),
            ("'_stations', '_reason', '_local_mac')", "'_stations', '_reason')"),
            ('stations, reason, local_mac):', 'stations, reason):'),
            ("('_stations', stations), ('_reason', reason), ('_local_mac', local_mac)):", "('_stations', stations), ('_reason', reason)):"),
            ("            'local_mac_observed': self._local_mac is not None,\n", ''),
            ("'stations': self._stations, 'local_mac': self._local_mac}", "'stations': self._stations}"),
            ('channels, stations, local_macs = [], [], []', 'channels, stations = [], []'),
            ('channel, extra, local_mac = _interface', 'channel, extra = _interface'),
            ('                    local_macs.append(local_mac)\n', ''),
            ("                if any(mac != local_macs[0] for mac in local_macs[1:]): _fail('interface_changed')\n", ''),
            ('stations[0] or (), reason, local_macs[0])', 'stations[0] or (), reason)'))
        for new, prior in replacements:
            self.assertEqual(1, source.count(new), new); source = source.replace(new, prior, 1)
        self.assertEqual((V15 / 'mta_client_kernel_proof.py').read_text(encoding='utf-8'), source)
        self.assertEqual('f16af6f1db74c9e6d74d2e56e6b469cf1ed589f27d3a1d5b4f897220cdeeb334', hashlib.sha256(source.encode()).hexdigest())
        source = (ROOT / 'mta_client_connection.py').read_text(encoding='utf-8')
        replacements = (("        local_mac = fields['local_mac']\n        if type(local_mac) is not bytes or local_mac != status.get('address'): _fail('kernel_unverified')\n", ''),
            ("fields['channel'], rows, local_mac", "fields['channel'], rows"),
            ("                result = self._observe_connection()\n                if result._kernels[0].private_fields()['local_mac'] != observation._kernels[0].private_fields()['local_mac']:\n                    self.reason = 'kernel_mismatch'\n                    _fail('kernel_mismatch')\n                self.result = result; return result", "                result = self._observe_connection(); self.result = result; return result"))
        for new, prior in replacements:
            self.assertEqual(1, source.count(new), new); source = source.replace(new, prior, 1)
        self.assertEqual((V15 / 'mta_client_connection.py').read_text(encoding='utf-8'), source)
        self.assertEqual('4a561d8d385fc71870c6d46653b7855b304c854ca10f102f31d174096fd7f2d1', hashlib.sha256(source.encode()).hexdigest())
        self.assertEqual('9e6b32141c8b1698edcc45e5459080168afe804c0bece1f5445bf8a355678136', hashlib.sha256((V15 / 'mta_client_linux_provider.py').read_bytes()).hexdigest())
        for path in (ROOT / 'mta_client_kernel_proof.py', ROOT / 'mta_client_connection.py', Path(__file__)):
            ast.parse(path.read_text(encoding='utf-8'), feature_version=(3, 5))
        self.assertFalse(p.LinuxClientInitProvider().status()['receive_available'])


if __name__ == '__main__': unittest.main()
