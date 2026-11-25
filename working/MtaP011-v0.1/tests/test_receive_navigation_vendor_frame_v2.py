"""One affected HOST parser method; fixture boundaries plus pinned actual log."""
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

BASE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('fixed_vendor_parser_test', BASE / 'host/receive_navigation_vendor_frame_v2.py')
parser = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parser)
LOG = ('results/formal-receive-filecenter-navigation-classification-v2-navigation-test-20261005-150952-dc89384f/'
       'private-raw/ui-logs/candidate.stderr.raw')


class VendorFrameTests(unittest.TestCase):
    def test_affected_frame_contract(self):
        observed = ('ready_observed', 'button_ready_observed', 'cancel_confirmed_observed',
                    'fresh_status_approved_observed', 'files_page_observed',
                    'received_listing_observed', 'stable_observed')
        forbidden = ('business_start_action_issued', 'file_opened', 'media_played', 'restoration_verified')
        value = dict(schema='navigation_qttest_v1', outcome='pass', code='received_page_stable', click_count=1)
        value.update({key: True for key in observed}); value.update({key: False for key in forbidden})
        payload = json.dumps(value, sort_keys=True, separators=(',', ':')).encode('ascii')
        plain = parser.MARKER + b' ' + payload + b'\n'
        prefix = b' [10-05 15:10:49:176] [NavigationTest.qml] [37] '
        vendor = prefix + plain[:-1] + b' \n'
        colored = b'\x1b[37m' + vendor[:-1] + b'\x1b[0m\n'
        actual = (BASE / LOG).read_bytes()
        self.assertEqual((len(actual), hashlib.sha256(actual).hexdigest()),
            (19860, '4f4610b655049fbbe4d7c4ee8cac7295832616b067d11069ad62f7d4ab0dbeea'))
        valid = (plain, b'qml: ' + plain, b'\x1b[31m' + plain[:-1] + b'\x1b[0m\n', vendor, colored,
                 colored.replace(b'\n', b'\r\n'), colored.replace(b'\n', b'\r\r\n'),
                 b'unrelated\n' + colored + b'unrelated\n', actual,
                 vendor.replace(b'10-05', b'02-29'))
        for index, raw in enumerate(valid):
            with self.subTest(valid=index):
                self.assertEqual(parser.navigation_receipt(raw), value)
        malformed = [b'', 'not bytes', plain + plain, colored + plain, plain[:-1], vendor[:-1],
            colored.replace(b'\x1b[37m', b'\x1b[31m'), colored.replace(b'\x1b[0m', b''),
            vendor.replace(b' [37]', b' [19]'), vendor.replace(b' [37]', b' [037]'),
            vendor.replace(b'NavigationTest.qml', b'Unknown.qml'),
            vendor.replace(b'NavigationTest.qml', b'path/NavigationTest.qml'),
            vendor.replace(b'NavigationTest.qml] [37]', b'FormalEntry.qml] [19]'),
            vendor.replace(b'10-05', b'13-05'), vendor.replace(b'10-05', b'00-05'),
            vendor.replace(b'10-05', b'04-31'), vendor.replace(b'10-05', b'02-30'),
            vendor.replace(b'10-05', b'10-00'), vendor.replace(b'15:10:49', b'24:10:49'),
            vendor.replace(b'15:10:49', b'15:60:49'), vendor.replace(b'15:10:49', b'15:10:60'),
            vendor.replace(b':176]', b':17]'), vendor.replace(b':176]', b':1760]'),
            vendor.replace(b'P011_MTA', b'P011_\x1b[37mMTA'),
            vendor.replace(b'"schema"', b'"\x1b[37mschema"'), vendor.replace(b'} \n', b'}  \n'),
            vendor.replace(b'} \n', b'}\n'), vendor.replace(b' [10', b'\t[10'),
            vendor.replace(b' [37] ', b' [37]\r'), b'x' * 4194305,
            vendor.replace(b'{', b'{"click_count":1,', 1), vendor + b'P011_M\x1b[37mTA NAVIGATION_QTTEST_V1 {}\n']
        malformed.extend((parser.MARKER + b'\x1b[2K ' + payload + b'\n',
            b'\x1b[2K' + plain, b'\x1b[99m' + plain[:-1] + b'\x1b[0m\n',
            b'qml:\x1b[2K ' + plain, plain.replace(b' {', b' \x1b[2K{'),
            b'\x1b[31m' + plain, plain[:-1] + b'\x1b[0m\n',
            b'\x1b[31m\x1b[37m' + plain[:-1] + b'\x1b[0m\n'))
        for key in observed + forbidden:
            changed = dict(value); changed[key] = not value[key]
            malformed.append(prefix + parser.MARKER + b' ' + json.dumps(changed).encode('ascii') + b' \n')
        for key in observed + forbidden:
            changed = dict(value); changed[key] = int(value[key])
            malformed.append(prefix + parser.MARKER + b' ' + json.dumps(changed).encode('ascii') + b' \n')
        for change in ({'click_count': 0}, {'click_count': 2}, {'click_count': True}, {'outcome': 'fail'},
                       {'schema': 'other'}, {'code': 'other'}, {'extra': True}):
            changed = dict(value); changed.update(change)
            malformed.append(prefix + parser.MARKER + b' ' + json.dumps(changed).encode('ascii') + b' \n')
        changed = dict(value); del changed['stable_observed']
        malformed.append(prefix + parser.MARKER + b' ' + json.dumps(changed).encode('ascii') + b' \n')
        malformed.append(prefix + parser.MARKER + b' {"padding":"' + b'x' * 2048 + b'"} \n')
        malformed.append(b'x' * 2305 + vendor)
        changed = dict(value); changed['outcome'] = 'fail'; changed['code'] = 'qttest_unavailable'
        entry = vendor.replace(payload, json.dumps(changed).encode('ascii')).replace(
            b'NavigationTest.qml] [37]', b'FormalEntry.qml] [19]')
        with self.assertRaisesRegex(ValueError, 'navigation_frame_refused'):
            parser.navigation_receipt(entry)
        for index, raw in enumerate(malformed):
            with self.subTest(refusal=index):
                with self.assertRaises(ValueError):
                    parser.navigation_receipt(raw)
        self.assertEqual((BASE / LOG).read_bytes(), actual)


if __name__ == '__main__':
    unittest.main(verbosity=2)
