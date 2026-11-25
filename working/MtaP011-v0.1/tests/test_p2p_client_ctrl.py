"""Pure HOST synthetic control bytes; no socket, WPA, RF or target access."""
import ast
import hashlib
import pathlib
import sys
import unittest
from unittest import mock

PROJECT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / 'runtime'))
import mta_p2p_client_ctrl as ctrl

NAME = b'mta1234abcd'
SSID = b'DIRECT-host-fixture'
KEY = bytes(range(32))
MAC = b'02:11:22:33:44:55'


def credentials(ssid=SSID):
    return ctrl.ClientCredentials(ssid, raw_psk=KEY)


def status(ssid=SSID, state=b'COMPLETED', updates=None, omit=(), extra=b''):
    fields = {
        b'bssid': MAC, b'freq': b'2412', b'ssid': ctrl._ssid_text(ssid),
        b'id': b'4', b'mode': b'station', b'pairwise_cipher': b'CCMP',
        b'group_cipher': b'CCMP', b'key_mgmt': b'WPA2-PSK', b'wpa_state': state,
        b'address': b'02:11:22:33:44:56', b'p2p_device_address': MAC,
        b'uuid': b'01234567-89ab-cdef-0123-456789abcdef',
    }
    if updates:
        fields.update(updates)
    for key in omit:
        fields.pop(key, None)
    return b''.join(key + b'=' + value + b'\n' for key, value in fields.items()) + extra


def group(ssid=SSID, name=NAME, role=b'client', key=True, extras=b'', prefix=b'<3>'):
    return (prefix + b'P2P-GROUP-STARTED ' + name + b' ' + role + b' ssid="' +
            ctrl._ssid_text(ssid) + b'" freq=2412' +
            (b' psk=' + KEY.hex().encode('ascii') if key else b'') +
            b' go_dev_addr=' + MAC + b' [PERSISTENT]' + extras)


class CodecTests(unittest.TestCase):
    def rejected(self, code, function, *args, **kwargs):
        with self.assertRaises(ctrl.CtrlCodecError) as caught:
            function(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)
        self.assertEqual(caught.exception.args, (code,))
        self.assertEqual(str(caught.exception), code)
        return caught.exception

    def test_credentials_repr_and_immutable(self):
        item = credentials()
        self.assertEqual(str(item), '<P2pClientPrivate redacted>')
        self.assertNotIn(SSID.decode(), repr(item))
        self.assertNotIn(KEY.hex(), repr(item))
        with self.assertRaises(AttributeError):
            item._psk = b'x' * 32
        with self.assertRaises(TypeError):
            vars(item)

    def test_passphrase_known_wpa2_derivation(self):
        item = ctrl.ClientCredentials(b'IEEE', passphrase=b'password')
        expected = 'f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e'
        self.assertEqual(item._psk.hex(), expected)
        self.assertNotIn('password', repr(item))

    def test_passphrase_special_bytes_never_quoted_into_command(self):
        secret = b'quote" slash\\ spaces'
        item = ctrl.ClientCredentials(SSID, passphrase=secret)
        wire = ctrl.network_commands(0, item)[1].private_bytes()
        self.assertNotIn(secret, wire)
        self.assertEqual(len(wire.split(b' ')[-1]), 64)

    def test_credential_and_ssid_exact_boundary_octets(self):
        for password in (b'a' * 8, b'a' * 63):
            self.assertEqual(len(ctrl.ClientCredentials(b'x', passphrase=password)._psk), 32)
        for sample in (b'x', bytes(range(32)), bytes(range(224, 256))):
            item = credentials(sample)
            self.assertEqual(ctrl.parse_status(status(ssid=sample), item).private_fields()['ssid'], sample)
            self.assertEqual(ctrl.parse_group_started(group(ssid=sample), NAME, item).private_fields()['ssid'], sample)

    def test_credential_lengths_and_types(self):
        for ssid in (b'', b'a' * 33, 'ssid', bytearray(b'ssid'), True):
            self.rejected('invalid_credentials', ctrl.ClientCredentials, ssid, raw_psk=KEY)
        for key in (b'', b'a' * 31, b'a' * 33, KEY.hex().encode(), bytearray(KEY)):
            self.rejected('invalid_credentials', ctrl.ClientCredentials, SSID, raw_psk=key)
        for password in (b'a' * 7, b'a' * 64, b'1234567\n', b'1234567\x80', 'password'):
            self.rejected('invalid_credentials', ctrl.ClientCredentials, SSID, passphrase=password)

    def test_credentials_require_exactly_one_key_form(self):
        self.rejected('invalid_credentials', ctrl.ClientCredentials, SSID)
        self.rejected('invalid_credentials', ctrl.ClientCredentials, SSID,
                      passphrase=b'password', raw_psk=KEY)

    def test_missing_and_failed_kdf_are_fixed_unsupported(self):
        with mock.patch.object(hashlib, 'pbkdf2_hmac', None):
            self.rejected('unsupported_kdf', ctrl.ClientCredentials, SSID, passphrase=b'password')
        with mock.patch.object(hashlib, 'pbkdf2_hmac', side_effect=ValueError('fixture-secret')):
            error = self.rejected('unsupported_kdf', ctrl.ClientCredentials, SSID,
                                  passphrase=b'password')
            self.assertNotIn('fixture-secret', repr(error))

    def test_fixed_global_config_no_ctrlpath_or_save(self):
        wire = ctrl.client_config().private_bytes()
        self.assertEqual(wire, b'ap_scan=1\np2p_no_group_iface=1\n')
        self.assertNotIn(b'update_config', wire)
        self.assertNotIn(b'ctrl_interface', wire)

    def test_fixed_commands_and_redacted_wire(self):
        self.assertEqual(ctrl.add_network_command().private_bytes(), b'ADD_NETWORK')
        self.assertEqual(ctrl.status_command().private_bytes(), b'STATUS')
        commands = ctrl.network_commands(2, credentials())
        fields = [item.private_bytes().split(b' ')[2] for item in commands]
        self.assertEqual(fields, [b'ssid', b'psk', b'proto', b'key_mgmt', b'pairwise',
                                  b'group', b'mode', b'disabled'])
        self.assertEqual(commands[0].private_bytes(), b'SET_NETWORK 2 ssid ' + SSID.hex().encode())
        self.assertEqual(commands[-1].private_bytes(), b'SET_NETWORK 2 disabled 2')
        self.assertEqual(ctrl.group_add_command(2).private_bytes(), b'P2P_GROUP_ADD persistent=2')
        self.assertTrue(all(b'\n' not in item.private_bytes() for item in commands))
        self.assertTrue(all(KEY.hex() not in repr(item) for item in commands))

    def test_network_id_exact_real_reply_grammar(self):
        for value in (0, 1, ctrl.MAX_NETWORK_ID):
            self.assertEqual(ctrl.parse_add_network_reply(str(value).encode() + b'\n'), value)
        for reply in (b'01\n', b'-1\n', b'2147483648\n', b'1\r\n', b'1\n2\n', b' 1\n', b'1'):
            with self.assertRaises(ctrl.CtrlCodecError):
                ctrl.parse_add_network_reply(reply)
        self.rejected('invalid_bytes', ctrl.parse_add_network_reply, '1\n')

    def test_no_command_passthrough_or_bool_network_id(self):
        for value in (True, False, -1, ctrl.MAX_NETWORK_ID + 1, b'1', '1;DISCONNECT', 1.0):
            self.rejected('invalid_network_id', ctrl.group_add_command, value)
            self.rejected('invalid_network_id', ctrl.network_commands, value, credentials())
        with self.assertRaises(TypeError):
            ctrl.network_commands(1, credentials(), b'bssid')
        with self.assertRaises(TypeError):
            ctrl.group_add_command(1, b'freq=2412')

    def test_ok_is_only_control_acceptance(self):
        self.assertIs(ctrl.parse_ok_reply(b'OK\n'), True)
        self.assertIs(ctrl.parse_ok_reply(b'FAIL\n'), False)
        for reply in (b'OK\r\n', b'OK ', b'FAIL-X', b'OK\n\n'):
            with self.assertRaises(ctrl.CtrlCodecError):
                ctrl.parse_ok_reply(reply)

    def test_status_completed_and_temporary_id(self):
        report = ctrl.parse_status(status(), credentials())
        self.assertTrue(report.public_summary()['ctrl_completed'])
        self.assertTrue(report.public_summary()['ctrl_wpa2_ccmp'])
        self.assertFalse(report.public_summary()['ctrl_client_role'])
        self.assertEqual(report.private_fields()['id'], 4)
        self.assertNotIn('associationVerified', report.public_summary())
        self.assertEqual(report.public_summary()['evidence'], 'control_fields_only')

    def test_status_disconnected_is_not_completion(self):
        report = ctrl.parse_status(b'wpa_state=SCANNING\naddress=' + MAC + b'\n', credentials())
        self.assertFalse(report.public_summary()['ctrl_completed'])
        self.assertFalse(report.public_summary()['ctrl_ssid_matches'])

    def test_status_all_known_states_and_invalid_state(self):
        for state_name in ctrl.STATES:
            item = ctrl.parse_status(status(state=state_name), credentials())
            self.assertEqual(item.public_summary()['ctrl_state'], state_name.decode())
        self.rejected('invalid_field', ctrl.parse_status, status(state=b'UNKNOWN'), credentials())

    def test_status_truncated_and_missing_completed_fields(self):
        self.rejected('invalid_frame', ctrl.parse_status, status()[:-1], credentials())
        for field in (b'ssid', b'id', b'mode', b'bssid', b'freq', b'address', b'key_mgmt'):
            self.rejected('missing_field', ctrl.parse_status, status(omit=(field,)), credentials())

    def test_status_duplicates_unknown_and_secret_fields(self):
        self.rejected('duplicate_field', ctrl.parse_status,
                      status(extra=b'wpa_state=COMPLETED\n'), credentials())
        for field in (b'new_official_field', b'passphrase', b'id_str'):
            self.rejected('unsupported_status_field', ctrl.parse_status,
                          status(extra=field + b'=private-fixture\n'), credentials())

    def test_status_security_mismatch_not_relaxed(self):
        for field, value in ((b'key_mgmt', b'WPA-PSK'), (b'group_cipher', b'TKIP'),
                             (b'pairwise_cipher', b'CCMP TKIP')):
            self.rejected('security_mismatch', ctrl.parse_status,
                          status(updates={field: value}), credentials())
        self.rejected('role_mismatch', ctrl.parse_status, status(updates={b'mode': b'P2P GO'}), credentials())

    def test_status_wrong_ssid_and_literal_quoted_ssid(self):
        self.rejected('ssid_mismatch', ctrl.parse_status, status(ssid=b'different'), credentials())
        self.rejected('invalid_ssid_encoding', ctrl.parse_status,
                      status(updates={b'ssid': b'"' + SSID + b'"'}), credentials())

    def test_status_and_group_source_escaped_ssid_match_separately(self):
        sample = b'a"\\\n\r\t\x1b\x00\x80= space'
        expected = b'a\\"\\\\\\n\\r\\t\\e\\x00\\x80= space'
        self.assertEqual(ctrl._ssid_text(sample), expected)
        first = ctrl.parse_status(status(ssid=sample), credentials(sample))
        second = ctrl.parse_group_started(group(ssid=sample), NAME, credentials(sample))
        self.assertEqual(first.private_fields()['ssid'], sample)
        self.assertEqual(second.private_fields()['ssid'], sample)

    def test_ssid_noncanonical_unknown_or_short_escapes_rejected(self):
        for text in (b'\\x41', b'\\x0', b'\\xAF', b'\\101', b'\\q', b'abc\\', b'\\x22'):
            self.rejected('invalid_ssid_encoding', ctrl.parse_status,
                          status(updates={b'ssid': text}), credentials())

    def test_status_nul_cr_free_line_and_length(self):
        for wire in (status() + b'\x00', status().replace(b'\n', b'\r\n'),
                     status() + b'free text\n', b'wpa_state=\n'):
            with self.assertRaises(ctrl.CtrlCodecError):
                ctrl.parse_status(wire, credentials())
        self.rejected('invalid_length', ctrl.parse_status, b'x' * 4097, credentials())
        self.rejected('invalid_bytes', ctrl.parse_status, bytearray(status()), credentials())

    def test_status_optional_fields_are_bounded_source_whitelist(self):
        extra = (b'pmf=1\nmgmt_group_cipher=AES-128-CMAC\nwifi_generation=4\n'
                 b'max_nss_rx=1\nmax_nss_tx=1\nchannel_width=20\nieee80211ac=1\n'
                 b'bss_max_idle_period=1\nssid_verified=1\nbigtk_set=1\nip_address=10.70.4.31\n')
        report = ctrl.parse_status(status(extra=extra), credentials())
        self.assertTrue(report.public_summary()['optional_ip_reported'])
        self.assertNotIn('10.70', repr(report))
        for field, value in ((b'uuid', b'01234567-89ab-cdef-0123-456789abcde-'),
                             (b'freq', b'0'), (b'id', b'04'), (b'channel_width', b'13'),
                             (b'address', b'03:11:22:33:44:55')):
            self.rejected('invalid_field', ctrl.parse_status, status(updates={field: value}), credentials())

    def test_group_client_role_interface_and_no_keys_retained(self):
        item = ctrl.parse_group_started(group(), NAME, credentials())
        self.assertTrue(item.public_summary()['ctrl_client_role'])
        self.assertTrue(item.public_summary()['ctrl_key_matches'])
        self.assertFalse(item.public_summary()['ctrl_completed'])
        self.assertNotIn('psk', item.private_fields())
        self.assertNotIn('passphrase', item.private_fields())
        self.assertNotIn('event', item.private_fields())

    def test_group_without_key_is_only_ssid_role_report(self):
        item = ctrl.parse_group_started(group(key=False), NAME, credentials())
        self.assertFalse(item.public_summary()['ctrl_key_reported'])
        self.assertFalse(item.public_summary()['ctrl_key_matches'])

    def test_group_priority_and_global_prefix(self):
        for priority in b'012345':
            event = b'IFNAME=' + NAME + b' <' + bytes((priority,)) + b'>' + group(prefix=b'')
            self.assertTrue(ctrl.parse_group_started(event, NAME, credentials()).public_summary()['ctrl_client_role'])
        self.assertTrue(ctrl.parse_group_started(group(prefix=b'') + b'\n', NAME,
                                                credentials()).public_summary()['ctrl_client_role'])
        for prefix in (b'<6>', b'<33>', b'<x>', b'<3> ', b'<3><3>'):
            with self.assertRaises(ctrl.CtrlCodecError):
                ctrl.parse_group_started(group(prefix=prefix), NAME, credentials())

    def test_group_wrong_role_ifname_and_owned_name(self):
        self.rejected('role_mismatch', ctrl.parse_group_started, group(role=b'GO'), NAME, credentials())
        self.rejected('interface_mismatch', ctrl.parse_group_started, group(name=b'mta1234abce'), NAME, credentials())
        self.rejected('interface_mismatch', ctrl.parse_group_started,
                      b'IFNAME=wlan0 ' + group(), NAME, credentials())
        for name in (b'wlan0', b'mta1234abcD', b'mta1234abcdx', NAME.decode()):
            self.rejected('invalid_owned_name', ctrl.parse_group_started, group(), name, credentials())

    def test_group_duplicates_unknown_and_missing(self):
        for extra in (b' freq=2412', b' [PERSISTENT]', b' go_dev_addr=' + MAC):
            self.rejected('duplicate_field', ctrl.parse_group_started, group(extras=extra), NAME, credentials())
        self.rejected('unsupported_event_field', ctrl.parse_group_started,
                      group(extras=b' official_future=secret'), NAME, credentials())
        wire = group().replace(b' go_dev_addr=' + MAC, b'')
        self.rejected('missing_field', ctrl.parse_group_started, wire, NAME, credentials())

    def test_group_missing_fields_bad_frequency_and_no_mac_identity_claim(self):
        for field in (b'freq=2412 ', b'ssid="' + SSID + b'" '):
            self.rejected('missing_field', ctrl.parse_group_started,
                          group().replace(field, b''), NAME, credentials())
        for value in (b'0', b'65536', b'02412', b'2412.0', b'true'):
            self.rejected('invalid_field', ctrl.parse_group_started,
                          group().replace(b'freq=2412', b'freq=' + value), NAME, credentials())
        item = ctrl.parse_group_started(group().replace(MAC, b'00:00:00:00:00:00'), NAME, credentials())
        self.assertEqual(item.private_fields()['go_dev_addr'], b'\x00' * 6)
        self.assertNotIn('peerVerified', item.public_summary())

    def test_group_str_and_mutable_wire_rejected(self):
        for event in (group().decode(), bytearray(group()), memoryview(group()), None):
            self.rejected('invalid_bytes', ctrl.parse_group_started, event, NAME, credentials())
        self.rejected('invalid_credentials', ctrl.parse_group_started, group(), NAME, {})

    def test_group_wrong_key_and_mac_never_leak_in_error(self):
        wire = group().replace(KEY.hex().encode(), b'0' * 64)
        error = self.rejected('key_mismatch', ctrl.parse_group_started, wire, NAME, credentials())
        self.assertNotIn(SSID.decode(), repr(error))
        self.assertNotIn(MAC.decode(), repr(error))
        for value in (b'zz' * 32, b'0' * 63, b'A' * 64):
            self.rejected('invalid_field', ctrl.parse_group_started,
                          group().replace(KEY.hex().encode(), value), NAME, credentials())

    def test_group_raw_passphrase_spaces_and_backslash(self):
        secret = b'synthetic \\ password'
        item = ctrl.ClientCredentials(SSID, passphrase=secret)
        wire = group(key=False, extras=b' passphrase="' + secret + b'"')
        report = ctrl.parse_group_started(wire, NAME, item)
        self.assertTrue(report.public_summary()['ctrl_key_matches'])
        self.assertNotIn(secret.decode(), repr(report))
        self.assertNotIn('passphrase', report.private_fields())

    def test_group_psk_and_passphrase_both_must_match(self):
        secret = b'password'
        item = ctrl.ClientCredentials(SSID, passphrase=secret)
        wire = group().replace(KEY.hex().encode(), item._psk.hex().encode()) + b' passphrase="password"'
        self.assertTrue(ctrl.parse_group_started(wire, NAME, item).public_summary()['ctrl_key_matches'])
        self.rejected('key_mismatch', ctrl.parse_group_started,
                      wire.replace(b'passphrase="password"', b'passphrase="otherpass"'), NAME, item)

    def test_group_injection_truncation_quote_and_double_space(self):
        for wire in (group() + b'\nDISCONNECT', group() + b'\x00', group() + b'\r\n',
                     group().replace(b'ssid="', b'ssid='), group().replace(b'" freq', b' freq'),
                     group().replace(b' freq=', b'  freq='), group() + b' ',
                     group(key=False) + b' passphrase="bad"suffix'):
            with self.assertRaises(ctrl.CtrlCodecError):
                ctrl.parse_group_started(wire, NAME, credentials())
        self.rejected('invalid_length', ctrl.parse_group_started, b'x' * 1025, NAME, credentials())

    def test_group_ip_report_is_private_not_endpoint(self):
        wire = group(extras=b' ip_addr=10.70.4.31 ip_mask=255.255.255.0 go_ip_addr=10.70.4.9')
        item = ctrl.parse_group_started(wire, NAME, credentials())
        summary = item.public_summary()
        self.assertTrue(summary['optional_ip_reported'])
        for token in ('10.70', SSID.decode(), KEY.hex(), MAC.decode(), NAME.decode(), '2412'):
            self.assertNotIn(token, repr(item))
            self.assertNotIn(token, repr(summary))
        self.assertNotIn('endpointVerified', summary)
        self.assertNotIn('dhcpLeaseVerified', summary)

    def test_group_ip_triplet_partial_and_invalid(self):
        self.rejected('missing_field', ctrl.parse_group_started, group(extras=b' ip_addr=10.70.4.31'), NAME, credentials())
        for local, mask, go in ((b'10.70.4.31', b'255.0.255.0', b'10.70.4.9'),
                                (b'10.70.4.31', b'255.255.255.0', b'10.71.4.9'),
                                (b'10.70.4.0', b'255.255.255.0', b'10.70.4.9'),
                                (b'10.70.4.31', b'255.255.255.0', b'10.70.4.31'),
                                (b'224.1.2.3', b'255.255.255.0', b'224.1.2.4'),
                                (b'10.070.4.31', b'255.255.255.0', b'10.70.4.9')):
            self.rejected('invalid_ip_profile', ctrl.parse_group_started,
                          group(extras=b' ip_addr=' + local + b' ip_mask=' + mask + b' go_ip_addr=' + go),
                          NAME, credentials())

    def test_report_private_copy_does_not_mutate_pins_or_summary(self):
        item = ctrl.parse_group_started(group(), NAME, credentials())
        private = item.private_fields()
        private['ssid'] = b'changed'
        self.assertEqual(item.private_fields()['ssid'], SSID)
        summary = item.public_summary()
        summary['ctrl_client_role'] = False
        self.assertTrue(item.public_summary()['ctrl_client_role'])
        with self.assertRaises(AttributeError):
            item._fields = ()

    def test_public_report_has_only_fixed_enum_and_bool_keys(self):
        reports = (ctrl.parse_status(status(), credentials()),
                   ctrl.parse_group_started(group(), NAME, credentials()))
        for report in reports:
            summary = report.public_summary()
            self.assertEqual(set(summary), {'report_kind', 'evidence', 'ctrl_state',
                'ctrl_completed', 'ctrl_client_role', 'ctrl_ssid_matches', 'ctrl_wpa2_ccmp',
                'ctrl_key_reported', 'ctrl_key_matches', 'optional_ip_reported'})
            for key, value in summary.items():
                if key not in ('report_kind', 'evidence', 'ctrl_state'):
                    self.assertIs(type(value), bool)
            self.assertEqual(summary['evidence'], 'control_fields_only')

    def test_reprs_nested_containers_and_fixed_error_codes(self):
        items = [credentials(), ctrl.network_commands(1, credentials()),
                 ctrl.parse_status(status(), credentials()),
                 ctrl.parse_group_started(group(), NAME, credentials())]
        for token in (SSID.decode(), KEY.hex(), MAC.decode(), NAME.decode()):
            self.assertNotIn(token, repr(items))
        self.assertEqual(str(ctrl.CtrlCodecError('secret-free-text')), 'invalid_codec_code')

    def test_source_python35_and_no_network_process_or_logging(self):
        source = (PROJECT / 'runtime/mta_p2p_client_ctrl.py').read_text(encoding='utf-8')
        tree = ast.parse(source, feature_version=(3, 5))
        imports = {item.name for node in ast.walk(tree) if isinstance(node, ast.Import)
                   for item in node.names}
        self.assertEqual(imports, {'binascii', 'hashlib', 'hmac'})
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                self.assertNotIn(node.func.id, ('print', 'open', 'eval', 'exec', 'compile'))
        self.assertNotIn('SAVE_CONFIG', source)
        self.assertNotIn('update_config=', source)


if __name__ == '__main__':
    unittest.main(verbosity=2)
