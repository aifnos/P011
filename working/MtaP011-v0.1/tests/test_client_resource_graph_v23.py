"""Only new frozen v23 graph/tooling methods; actual OS/target entry blocked."""
import ast
import builtins
from contextlib import ExitStack
import hashlib
import importlib.util
from pathlib import Path
import types
import unittest
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
path = BASE / 'host/client_resource_v23_source_check.py'
if hashlib.sha256(path.read_bytes()).hexdigest() != '97e746b9df86774163f2957b6df41ddd28f4918d5ae0b94d2b9d7798de35e23d':
    raise ValueError('new PC checker drift')
spec = importlib.util.spec_from_file_location('private_v23_graph_checker', str(path))
check = importlib.util.module_from_spec(spec); spec.loader.exec_module(check)


def blocked(stack):
    for name in ('socket.socket', 'subprocess.Popen', 'ctypes.CDLL', 'os.open', 'os.kill',
            'os.waitpid', 'os.system', 'threading.Thread.start', 'time.sleep'):
        stack.enter_context(mock.patch(name, side_effect=AssertionError('actual OS forbidden'), create=True))


class ClientResourceGraphV23Tests(unittest.TestCase):
    def test_actual_pinned_29_domain_lazy_identity_and_pure_ctor_not_formal_loader(self):
        rows, modules, original = check.verify(), {}, builtins.__import__
        def private_import(name, *args, **kwargs):
            if name.startswith(('mta_', 'p011_')):
                if name not in modules: raise AssertionError('private dependency not loaded')
                return modules[name]
            return original(name, *args, **kwargs)
        with ExitStack() as stack:
            blocked(stack)
            for row in rows:
                raw = (BASE / row['path']).read_bytes()
                if len(raw) != row['bytes'] or hashlib.sha256(raw).hexdigest() != row['sha256']:
                    raise AssertionError('source drift before HOST import')
                module = types.ModuleType(row['module']); module.__file__ = str(BASE / row['path'])
                module.__dict__['__builtins__'] = dict(vars(builtins), __import__=private_import)
                modules[row['module']] = module
                exec(compile(raw, module.__file__, 'exec'), module.__dict__)
            self.assertEqual(29, len(modules))
            identity = modules['mta_p2p_client_init'].Identity('a' * 64)
            store = modules['mta_client_store'].DurableClientInitStore('1' * 32, identity)
            budget = store._resource_budget_v23
            self.assertIs(type(budget), modules['mta_client_resource_budget'].ResourceBudget)
            self.assertIs(store._files._resource_budget_v23, budget)
            self.assertIs(modules['mta_client_linux_provider'].stores, modules['mta_client_store'])
            self.assertIs(modules['mta_client_dora'].linux, modules['mta_client_linux_provider'])
            provider = modules['mta_client_linux_provider'].LinuxClientInitProvider()
            budget.bind_provider(provider)
            self.assertIs(provider._resource_budget_v23, budget)
            self.assertEqual([], store._files._inventory)
            self.assertEqual([], store._coordination._inventory)
            self.assertFalse(store._attempted)
            self.assertFalse(provider.status()['send_available'])
            self.assertEqual(24, len(modules['mta_client_executor'].MODULES))
            self.assertEqual(32 * 1024 * 1024, budget._profile.payload_limit('CLEANUP'))

    def test_previous_return_drift_and_unlisted_lazy_forward_import_are_refused(self):
        rows = check.verify()
        previous = [dict(r) for r in rows if r['module'] != 'mta_client_resource_budget']
        previous[0]['sha256'] = '0' * 64
        fake = ('def verify():\n    return ' + repr(previous) + '\n').encode('utf-8')
        read = check._raw
        def substitute(relative, pin):
            return fake if relative == 'host/client_store_close_v22_source_check.py' else read(relative, pin)
        with ExitStack() as stack:
            blocked(stack)
            stack.enter_context(mock.patch.object(check, '_raw', side_effect=substitute))
            with self.assertRaisesRegex(ValueError, 'previous_graph_changed'): check.verify()
        for text in ('class ResourceBudget:\n def __init__(self):\n  import mta_client_linux_provider\n',
                'class ResourceBudget:\n def unrelated(self):\n  import mta_client_store\n'):
            with self.assertRaisesRegex(ValueError, 'dependency_order'):
                check._dependencies(ast.parse(text), 'mta_client_resource_budget', set())
        inherited = 'class ClientJournalFiles:\n def _pending_absent(self):\n  from mta_client_pending import OwnedMarkerBinding\n'
        check._dependencies(ast.parse(inherited), 'mta_client_files', set())
        with self.assertRaisesRegex(ValueError, 'dependency_order'):
            check._dependencies(ast.parse(inherited.replace('OwnedMarkerBinding', 'UnexpectedOtherSymbol')),
                'mta_client_files', set())


if __name__ == '__main__': unittest.main()
