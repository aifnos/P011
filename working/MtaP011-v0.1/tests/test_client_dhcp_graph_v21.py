"""New actual v21 28-definition HOST domain; no OS IO, RF or old suites."""
import builtins
from contextlib import ExitStack
import hashlib
import importlib.util
import json
from pathlib import Path
import types
import unittest
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('private_v21_graph_checker',
    str(BASE / 'host/client_dhcp_v21_source_check.py'))
check = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check)


def _forbidden(stack):
    for name in ('subprocess.Popen.__init__', 'socket.socket', 'os.open',
            'os.kill', 'os.system', 'os.mkdir', 'os.unlink',
            'threading.Thread.start', 'time.sleep'):
        stack.enter_context(mock.patch(name, side_effect=AssertionError('actual OS forbidden')))


class ClientDhcpGraphV21Tests(unittest.TestCase):
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
        with ExitStack() as stack:
            _forbidden(stack)
            for row in rows:
                raw = (BASE / row['path']).read_bytes()
                if hashlib.sha256(raw).hexdigest() != row['sha256']:
                    raise AssertionError('source changed before private import')
                module = types.ModuleType(row['module'])
                module.__file__ = str(BASE / row['path'])
                module.__dict__['__builtins__'] = dict(vars(builtins), __import__=pinned_import)
                cls.modules[row['module']] = module
                exec(compile(raw, module.__file__, 'exec'), module.__dict__)

    def test_actual_28_domain_exact_types_but_formal_f_remains_24(self):
        m = self.modules
        self.assertEqual(28, len(m))
        self.assertEqual(tuple(m)[:24], m['mta_client_executor'].MODULES)
        self.assertEqual(tuple(m)[24:], tuple(row[0] for row in check.ADDITIONS))
        self.assertIs(m['mta_dhcp'], m['mta_dhcp_client_core'].wire)
        self.assertIs(m['mta_dhcp'], m['mta_dhcp_client'].wire)
        self.assertIs(m['mta_dhcp_client_core'], m['mta_dhcp_client'].core)
        for name in ('mta_dhcp_client', 'mta_client_linux_provider', 'mta_client_connection'):
            self.assertTrue(any(value is m[name] for value in vars(m['mta_client_dora']).values()))
        with ExitStack() as stack:
            _forbidden(stack)
            provider = m['mta_client_linux_provider'].LinuxClientInitProvider()
            self.assertFalse(provider.status()['send_available'])
            self.assertFalse(provider.status()['receive_available'])

    def test_pinned_base_manifest_cannot_accept_changed_second_read_rows(self):
        # Synthetic PC verifier return drift, not an actual filesystem race.
        manifest = json.loads((BASE / 'host/client_durable_connect_v19_source_manifest.json').read_text(encoding='utf-8'))
        changed = [dict(row) for row in manifest['sources']]
        changed[0]['sha256'] = '0' * 64
        fake_helper = ('def verify():\n    return ' + repr(changed) + '\n').encode('utf-8')
        original_read = check._raw
        def controlled_read(relative, pin):
            if relative == 'host/client_durable_connect_v19_source_check.py':
                return fake_helper
            return original_read(relative, pin)
        with ExitStack() as stack:
            _forbidden(stack)
            stack.enter_context(mock.patch.object(check, '_raw', side_effect=controlled_read))
            with self.assertRaisesRegex(ValueError, 'base_graph_invalid'):
                check._base_rows()


if __name__ == '__main__':
    unittest.main()
