"""One HOST exception-frame test; no receiver/actor/RF model is executed."""
import importlib.util
from pathlib import Path
import types
import unittest

BASE = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('startup_inner_error_host',
    BASE / 'candidate/receive-startup-inner-v1/runtime/startup_inner_error.py')
HOOK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HOOK)


class FrameProjectionTest(unittest.TestCase):
    def test_original_frame_positive_and_negative(self):
        # This is only an actual HOST exception with a masked rethrow. It does
        # not substitute a BaselineCollector, RF actor or hardware observation.
        module = types.ModuleType('mta_client_baseline')
        exec('def collect(self):\n'
             ' error=None\n'
             ' try:\n'
             '  raise OSError(13,"private-value-not-exported")\n'
             ' except BaseException as caught:\n'
             '  error=caught\n'
             ' raise ValueError("io_error") from None\n', module.__dict__)
        collector = object()
        try:
            module.collect(collector)
        except ValueError as error:
            outer = error
        row = HOOK.extract_inner(outer, module.collect, collector,
                                 {'mta_client_baseline': module.__dict__})
        self.assertEqual(row, dict(kind='PermissionError', errno=13,
                                  trace=(('mta_client_baseline', 'collect', 4),)))
        self.assertNotIn('private-value', repr(row))
        self.assertIsNone(HOOK.extract_inner(outer, module.collect, object(),
                                            {'mta_client_baseline': module.__dict__}))
        self.assertIsNone(HOOK.extract_inner(outer, module.collect, collector,
                                            {'mta_client_baseline': {}}))


if __name__ == '__main__':
    unittest.main(verbosity=2)
