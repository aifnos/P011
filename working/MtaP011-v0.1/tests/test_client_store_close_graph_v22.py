"""New actual 28-source HOST domain, replacing Store only; no old methods."""
import builtins
from contextlib import ExitStack
import hashlib
import importlib.util
from pathlib import Path
import types
import unittest
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('private_v22_graph_checker',
    str(BASE / 'host/client_store_close_v22_source_check.py'))
check = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check)


def blocked(stack):
    for name in ('subprocess.Popen.__init__', 'socket.socket', 'ctypes.CDLL', 'os.open',
            'os.kill', 'os.waitpid', 'os.system', 'os.mkdir', 'os.unlink',
            'threading.Thread.start', 'time.sleep'):
        stack.enter_context(mock.patch(name, side_effect=AssertionError('actual OS forbidden')))


class ClientStoreCloseGraphV22Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows, cls.modules = check.verify(), {}
        original = builtins.__import__
        def private_import(name, globals=None, locals=None, fromlist=(), level=0):
            if name.startswith(('mta_', 'p011_')):
                if level or name not in cls.modules: raise AssertionError('private graph dependency')
                return cls.modules[name]
            if level: raise AssertionError('relative graph dependency')
            return original(name, globals, locals, fromlist, level)
        with ExitStack() as stack:
            blocked(stack)
            for row in cls.rows:
                raw = (BASE / row['path']).read_bytes()
                if len(raw) != row['bytes'] or hashlib.sha256(raw).hexdigest() != row['sha256']:
                    raise AssertionError('source changed before HOST private import')
                module = types.ModuleType(row['module']); module.__file__ = str(BASE / row['path'])
                module.__dict__['__builtins__'] = dict(vars(builtins), __import__=private_import)
                cls.modules[row['module']] = module
                exec(compile(raw, module.__file__, 'exec'), module.__dict__)

    def test_actual_28_store_identity_and_pure_ctor_not_formal_f_rewire(self):
        m = self.modules
        self.assertEqual(28, len(m))
        self.assertEqual(tuple(m)[:24], m['mta_client_executor'].MODULES)
        self.assertEqual(str(BASE / check.NEW_PATH), m['mta_client_store'].__file__)
        self.assertIs(m['mta_client_linux_provider'].stores, m['mta_client_store'])
        self.assertIs(m['mta_client_store'].coordination, m['mta_client_coordination'])
        self.assertIs(m['mta_client_store'].core, m['mta_p2p_client_init'])
        self.assertIs(m['mta_client_dora'].linux, m['mta_client_linux_provider'])
        with ExitStack() as stack:
            blocked(stack)
            identity = m['mta_p2p_client_init'].Identity('a' * 64)
            store = m['mta_client_store'].DurableClientInitStore('1' * 32, identity)
            self.assertEqual([], store._coordination._inventory)
            self.assertEqual([], store._files._inventory)
            self.assertFalse(store._attempted)
            provider = m['mta_client_linux_provider'].LinuxClientInitProvider()
            self.assertFalse(provider.status()['send_available'])
            self.assertFalse(provider.status()['receive_available'])

    def test_pinned_previous_manifest_extras_reject_verifier_return_drift(self):
        # Synthetic PC helper return drift only; no real filesystem race.
        changed = [dict(row) for row in self.rows]
        index = next(i for i, row in enumerate(changed) if row['module'] == check.OLD_STORE['module'])
        changed[index] = dict(check.OLD_STORE)
        changed[24]['sha256'] = '0' * 64
        fake = ('def verify():\n    return ' + repr(changed) + '\n').encode('utf-8')
        read = check._raw
        def synthetic(relative, pin):
            if relative == 'host/client_dhcp_v21_source_check.py': return fake
            return read(relative, pin)
        with ExitStack() as stack:
            blocked(stack)
            stack.enter_context(mock.patch.object(check, '_raw', side_effect=synthetic))
            with self.assertRaisesRegex(ValueError, 'base_graph_changed'): check.verify()


if __name__ == '__main__': unittest.main()
