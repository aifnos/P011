"""Actual frozen 23-source private module graph; pure HOST operations only.

This runs class/module definitions, not a Loader filesystem admission, State,
process, Wi-Fi connection or restoration. OS/radio actions are forbidden.
"""
import builtins
import hashlib
import importlib.util
from pathlib import Path
import types
import unittest
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('private_v14_graph_checker',
    str(BASE / 'host/client_connect_v14_source_check.py'))
check = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check)


class ActualGraphV14Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        rows = check.verify()
        cls.modules = {}
        original_import = builtins.__import__
        def pinned_import(name, globals=None, locals=None, fromlist=(), level=0):
            if name.startswith(('mta_', 'p011_')):
                if level or name not in cls.modules:
                    raise AssertionError('unloaded private graph dependency')
                return cls.modules[name]
            if level:
                raise AssertionError('relative private graph dependency')
            return original_import(name, globals, locals, fromlist, level)
        with mock.patch('subprocess.Popen.__init__', side_effect=AssertionError('process forbidden')), \
                mock.patch('socket.socket', side_effect=AssertionError('socket forbidden')), \
                mock.patch('os.open', side_effect=AssertionError('open forbidden')), \
                mock.patch('os.kill', side_effect=AssertionError('signal forbidden')), \
                mock.patch('os.system', side_effect=AssertionError('shell forbidden')):
            for row in rows:
                raw = (BASE / row['path']).read_bytes()
                if hashlib.sha256(raw).hexdigest() != row['sha256']:
                    raise AssertionError('frozen source changed before import')
                module = types.ModuleType(row['module'])
                module.__file__ = str(BASE / row['path'])
                module.__dict__['__builtins__'] = dict(vars(builtins), __import__=pinned_import)
                cls.modules[row['module']] = module
                exec(compile(raw, module.__file__, 'exec'), module.__dict__)

    def test_actual_23_dependencies_share_one_private_type_domain(self):
        m = self.modules
        self.assertEqual(len(m), 23)
        self.assertIs(m['mta_protocol'].json, m['p011_json'])
        self.assertIs(m['mta_client_control_frame'].protocol, m['mta_protocol'])
        self.assertIs(m['mta_client_connection'].protocol, m['mta_protocol'])
        self.assertIs(m['mta_client_connection'].core, m['mta_p2p_client_init'])
        self.assertIs(m['mta_client_connection'].ctrl, m['mta_p2p_client_ctrl'])
        self.assertIs(m['mta_client_linux_provider'].connection, m['mta_client_connection'])
        self.assertIs(m['mta_client_linux_provider'].phases, m['mta_client_two_phase_lease'])
        self.assertIs(m['mta_client_linux_provider'].core, m['mta_p2p_client_init'])
        self.assertEqual(m['mta_client_executor'].MODULES, tuple(name for name, unused in check.EXPECTED))

    def test_actual_provider_and_parent_defaults_construct_without_io_and_remain_unavailable(self):
        with mock.patch('subprocess.Popen.__init__', side_effect=AssertionError('process forbidden')), \
                mock.patch('socket.socket', side_effect=AssertionError('socket forbidden')), \
                mock.patch('os.open', side_effect=AssertionError('open forbidden')):
            provider = self.modules['mta_client_linux_provider'].LinuxClientInitProvider()
            parent = self.modules['mta_client_executor'].ParentExecutor()
            child = self.modules['mta_client_executor'].ClientExecutor()
            self.assertFalse(provider.status()['send_available'])
            self.assertFalse(provider.status()['receive_available'])
            self.assertFalse(parent.status()['done'])
            self.assertFalse(child.status()['ip_ready'])

    def test_actual_codec_to_connection_credential_types_without_network(self):
        m = self.modules
        codec, protocol, connection = (m[name] for name in
            ('mta_client_control_frame', 'mta_protocol', 'mta_client_connection'))
        binding = codec.ControlBinding({'version': 1, 'run_token': 'a' * 32,
            'candidate_sha': 'b' * 64, 'operation_id': 'local-fixture-op',
            'native_epoch': 2, 'operation_epoch': 2, 'gatt_session': 3,
            'nonce': 'c' * 32, 'receive_consent': True})
        info = protocol.P2pInfo('DIRECT-fixture', 'fixture-passphrase',
            '02:11:22:33:44:55', 12345, sender_id='remote-hint')
        decoder = codec.ControlFrameDecoder(binding)
        decoder.feed(codec.encode_connect(binding, info))
        request = decoder.take_connect()
        actual = request.private_info()
        self.assertIs(type(actual), protocol.P2pInfo)
        credentials, unused_mac, port = connection._info(actual)
        self.assertIs(type(credentials), m['mta_p2p_client_ctrl'].ClientCredentials)
        self.assertEqual(port, 12345)
        self.assertEqual(actual.id, 'remote-hint')
        self.assertNotEqual(actual.id, binding.private_metadata()['operation_id'])
        decoder.feed(codec.CANCEL)
        with self.assertRaises(codec.ControlFrameError):
            request.private_info()


if __name__ == '__main__':
    unittest.main()
