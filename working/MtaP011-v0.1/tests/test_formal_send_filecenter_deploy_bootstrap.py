"""Focused Linux HOST close-consumer test, not staging or ARM admission.

The new builder assembles a fixed wrapper in memory. Its actual passive
consumer checks a real nonzero FD opened and once-closed by the actual new
FixedStage helpers. Only the surrounding program ticket is an explicit HOST
model; no Stage.stage, Boot, Owner, timer, native, device or RF is invoked.
"""
import errno
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import time
import types
import unittest


BASE = Path(__file__).resolve().parents[1]


class BootstrapCloseTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == 'linux', 'requires actual Linux no-follow FD helpers')
    def test_real_nonzero_fd_errno9_consumption(self):
        path = BASE / 'host/formal_send_filecenter_deploy_source_check.py'
        spec = importlib.util.spec_from_file_location('formal_deploy_builder_host_test', path)
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)  # PC builder definitions only; main is not called.
        stage_raw = builder.read_fixed(*builder.STAGE)
        base_wrapper = builder.read_fixed(*builder.BASE_BOOTSTRAP)
        profiles = ('sender', 'observer', 'ordinary')
        programs = tuple((profile, b'pass\n') for profile in profiles)
        wires = tuple((profile, b'HOST_MODEL_WIRE\n') for profile in profiles)
        data_raw, wrapper_raw = builder.bootstrap_parts(programs, wires, base_wrapper)
        data_name = 'formal_send_stage_bootstrap_programs'
        previous = sys.modules.get(data_name)
        data = types.ModuleType(data_name)
        data.__file__ = '<formal-send-stage-bootstrap-programs-v1>'
        data._fixed_source_raw = data_raw
        exec(compile(data_raw, data.__file__, 'exec'), data.__dict__)
        sys.modules[data_name] = data
        wrapper = types.ModuleType('formal_deploy_bootstrap_close_host_test')
        wrapper.__file__ = '<new-deploy-bootstrap-host-test>'
        stage_module = types.ModuleType('formal_deploy_stage_close_host_test')
        stage_module.__file__ = '<fixed-stdin-stage>'
        original = None
        fixture_path = None
        fixture_fd = None
        try:
            exec(compile(wrapper_raw, wrapper.__file__, 'exec'), wrapper.__dict__)
            exec(compile(stage_raw, stage_module.__file__, 'exec'), stage_module.__dict__)
            original = stage_module.FixedStage('ordinary', float(time.monotonic() + 30.0))
            fixture_fd, fixture_path = tempfile.mkstemp(prefix='mta-deploy-close-host-')
            os.close(fixture_fd)
            fixture_fd = None
            # Actual production helpers create/retain the original row and errno9.
            row = original.open_row(None, fixture_path, os.O_RDWR, 0o600, 'file')
            self.assertGreater(row['original_fd'], 2)
            self.assertTrue(original.close())
            actual_error = row['close_error']
            self.assertIsInstance(actual_error, OSError)
            self.assertEqual(actual_error.errno, errno.EBADF)
            with self.assertRaises(OSError) as closed:
                os.fstat(row['original_fd'])
            self.assertEqual(closed.exception.errno, errno.EBADF)
            namespace = dict(PROFILE='ordinary', STAGE_PIN=builder.STAGE[1:],
                _constructor_complete=True, _module=stage_module, _RETAINED=original,
                source=stage_raw, _result=original.result())
            # This is explicitly a HOST program ancestry model, not run_fixed evidence.
            ticket = dict(exec_called=True, namespace=namespace, namespace_original=namespace,
                profile='ordinary', worker=original.worker, pid=original.pid,
                stage_module=None, stage=None, stage_source=None)
            self.assertTrue(wrapper.original_stage_closed(ticket))
            row['close_error'] = None
            self.assertFalse(wrapper.original_stage_closed(ticket))
            row['close_error'] = OSError(errno.EPERM, 'HOST fault model')
            self.assertFalse(wrapper.original_stage_closed(ticket))
            row['close_error'] = actual_error
            self.assertTrue(wrapper.original_stage_closed(ticket))
            self.assertIs(ticket['stage'], original)
            self.assertIs(ticket['stage_source'], stage_raw)
            self.assertFalse(namespace['_result']['stage_complete'])
            self.assertFalse(namespace['_result']['rf'])
            self.assertEqual(original.created_files, 0)
            print('DEPLOY_BOOTSTRAP_CLOSE_CONTRACTS=4', flush=True)
        finally:
            if original is not None and not original.close_called:
                original.close()
            if fixture_fd is not None:
                os.close(fixture_fd)
            if fixture_path is not None:
                os.unlink(fixture_path)  # Only the exact tempfile created above.
            if previous is None:
                sys.modules.pop(data_name, None)
            else:
                sys.modules[data_name] = previous


if __name__ == '__main__':
    unittest.main()
