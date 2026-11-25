"""One affected HOST Thread trace test; no old receiver graph/ADB/RF executed.

Fixture namespaces contain actual Python functions and exceptions, not native
events, Owner/Scope replacements or fake restoration receipts. This is only
tracer framing/timing/identity evidence, not P011 or phone acceptance.
"""
import importlib.util
from pathlib import Path
import sys
import threading
import types
import unittest


BASE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    'host_trace_definitions',
    BASE / 'candidate/receive-handoff-trace-v1/runtime/handoff_trace.py')
trace = importlib.util.module_from_spec(spec)
spec.loader.exec_module(trace)


class ThreadTraceTest(unittest.TestCase):
    def test_real_thread_source_filter_refusal_foreign_hook_and_overflow(self):
        self.assertIsNone(sys.gettrace())
        self.assertIsNone(threading._trace_hook)
        module = types.ModuleType('mta_protocol')
        exec("class ProtocolError(ValueError): pass\n"
             "def _base64(value):\n"
             " raise ProtocolError('private-fixture-value-must-not-be-retained')\n",
             module.__dict__)
        modules = {'mta_protocol': module}
        class HostFixtureTrace(trace.TraceOwner):
            # Test-only selector override; the production run_fixed has no
            # selector injection and uses the retained original loader modules.
            def original_modules(self):
                return modules
        phone = types.SimpleNamespace(_RETAINED=None)
        def launch(function, count=1):
            observed = []
            def worker():
                for number in range(count):
                    try:
                        function(number)
                    except module.ProtocolError:
                        observed.append(True)
            child = threading.Thread(target=worker)
            child.start()
            child.join(2)
            self.assertFalse(child.is_alive())
            self.assertEqual(len(observed), count)
        owner = HostFixtureTrace(phone)
        try:
            owner.install()
            launch(module._base64)
            self.assertEqual(len(owner.events), 1)
            self.assertEqual(owner.events[0]['kind'], 'ProtocolError')
            self.assertEqual(owner.events[0]['function'], '_base64')
            self.assertIsNone(owner.events[0]['code'])
            self.assertNotIn('private-fixture', repr(owner.public()))
            self.assertEqual(set(owner.events[0]),
                             {'kind', 'code', 'module', 'function', 'line'})
            # The identical code object under another globals dictionary is
            # not the selected source namespace, even with the same module name.
            foreign_namespace = {'__name__': 'mta_protocol',
                                 'ProtocolError': module.ProtocolError}
            foreign = types.FunctionType(module._base64.__code__, foreign_namespace)
            launch(foreign)
            self.assertEqual(len(owner.events), 1)
        finally:
            owner.close_trace()
        self.assertTrue(owner.restored)
        self.assertFalse(owner.unknown)
        self.assertIsNone(threading._trace_hook)
        self.assertIsNone(sys.gettrace())
        owner = HostFixtureTrace(phone)
        try:
            owner.install()
            launch(module._base64, trace.MAX_EVENTS + 1)
        finally:
            owner.close_trace()
        self.assertEqual(len(owner.events), trace.MAX_EVENTS)
        self.assertTrue(owner.overflow)
        self.assertTrue(owner.unknown)
        self.assertIn('event_overflow', owner.failures)
        # Refuse an existing hook and preserve it exactly.
        def external(frame, event, argument):
            return None
        threading.settrace(external)
        owner = HostFixtureTrace(phone)
        try:
            with self.assertRaises(ValueError):
                owner.install()
            owner.close_trace()
            self.assertIs(threading._trace_hook, external)
            self.assertIn('existing_trace', owner.failures)
        finally:
            if threading._trace_hook is external:
                threading.settrace(None)
        # A later foreign hook is unknown, never overwritten by close_trace.
        owner = HostFixtureTrace(phone)
        try:
            owner.install()
            threading.settrace(external)
            owner.close_trace()
            self.assertIs(threading._trace_hook, external)
            self.assertFalse(owner.restored)
            self.assertTrue(owner.unknown)
            self.assertIn('hook_changed', owner.failures)
        finally:
            if threading._trace_hook is external:
                threading.settrace(None)
        # A tracer's own selector/projection failure is visible but cannot
        # replace the original function's actual exception in the worker.
        class BrokenHostTrace(HostFixtureTrace):
            def original_modules(self):
                return object()
        owner = BrokenHostTrace(phone)
        try:
            owner.install()
            launch(module._base64)
        finally:
            owner.close_trace()
        self.assertTrue(owner.unknown)
        self.assertIn('projection_failed', owner.failures)
        self.assertEqual(owner.events, [])
        self.assertIsNone(threading._trace_hook)


if __name__ == '__main__':
    unittest.main(verbosity=2)
