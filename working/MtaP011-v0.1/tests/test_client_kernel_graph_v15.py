"""Only new actual 24-source kernel type domain; HOST definitions, no OS/RF."""
import builtins
import hashlib
import importlib.util
from pathlib import Path
import types
import unittest
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('private_v15_graph_checker',
    str(BASE / 'host/client_kernel_connect_v15_source_check.py'))
check = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check)


class KernelGraphV15Tests(unittest.TestCase):
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

    def test_new_kernel_domain_provider_default_factory_and_pure_24_source_construct(self):
        m = self.modules
        kernel = m['mta_client_kernel_proof']
        self.assertEqual(24, len(m))
        self.assertIs(kernel.core, m['mta_p2p_client_init'])
        self.assertIs(kernel.proc, m['mta_client_proc'])
        self.assertIs(kernel.wire, m['mta_client_caps_transport'])
        self.assertTrue(any(value is kernel for value in vars(m['mta_client_connection']).values()))
        self.assertTrue(any(value is kernel for value in vars(m['mta_client_linux_provider']).values()))
        self.assertEqual(tuple(m), m['mta_client_executor'].MODULES)
        with mock.patch('subprocess.Popen.__init__', side_effect=AssertionError('process forbidden')), \
                mock.patch('socket.socket', side_effect=AssertionError('socket forbidden')), \
                mock.patch('os.open', side_effect=AssertionError('open forbidden')):
            provider = m['mta_client_linux_provider'].LinuxClientInitProvider()
            self.assertIs(provider._kernel_factory, kernel.ClientKernelReader)
            callbacks = []
            def checkpoint():
                callbacks.append(True)
                return False
            origin = kernel.core.Origin(0, 9, 7, 'mta12345678', 8)
            reader = kernel.ClientKernelReader(origin,
                '11111111-1111-1111-1111-111111111111', object(), 17,
                _checkpoint=checkpoint, _deadline=100.0)
            self.assertEqual([], callbacks)
            self.assertFalse(reader.status()['attempted'])
            self.assertEqual((), reader.closed_receipts)
            self.assertFalse(reader.status()['production_available'])


if __name__ == '__main__':
    unittest.main()
