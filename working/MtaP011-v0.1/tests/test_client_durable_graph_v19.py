"""New actual version5 durable 24-source domain; HOST definitions, no OS/RF."""
import builtins
import hashlib
import importlib.util
from pathlib import Path
import types
import unittest
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('private_v19_graph_checker',
    str(BASE / 'host/client_durable_connect_v19_source_check.py'))
check = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check)


class DurableGraphV19Tests(unittest.TestCase):
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
                    raise AssertionError('source changed before private import')
                module = types.ModuleType(row['module'])
                module.__file__ = str(BASE / row['path'])
                module.__dict__['__builtins__'] = dict(vars(builtins), __import__=pinned_import)
                cls.modules[row['module']] = module
                exec(compile(raw, module.__file__, 'exec'), module.__dict__)

    def test_actual_version5_codec_store_connection_f_domain_and_pure_ctor(self):
        m = self.modules
        self.assertEqual(24, len(m))
        self.assertEqual(tuple(m), m['mta_client_executor'].MODULES)
        core = m['mta_p2p_client_init']
        self.assertEqual(5, core.VERSION)
        for name in ('mta_client_journal_codec', 'mta_client_store',
                'mta_client_connection', 'mta_client_linux_provider', 'mta_client_kernel_proof'):
            self.assertIs(core, m[name].core)
        self.assertIs(m['mta_client_journal_codec'], m['mta_client_store'].codec)
        self.assertTrue(any(value is m['mta_client_control_frame']
            for value in vars(m['mta_client_connection']).values()))
        with mock.patch('subprocess.Popen.__init__', side_effect=AssertionError('process forbidden')), \
                mock.patch('socket.socket', side_effect=AssertionError('socket forbidden')), \
                mock.patch('os.open', side_effect=AssertionError('open forbidden')):
            provider = m['mta_client_linux_provider'].LinuxClientInitProvider()
            self.assertIs(provider._kernel_factory, m['mta_client_kernel_proof'].ClientKernelReader)
            self.assertFalse(provider.status()['send_available'])
            self.assertFalse(provider.status()['receive_available'])


if __name__ == '__main__':
    unittest.main()
