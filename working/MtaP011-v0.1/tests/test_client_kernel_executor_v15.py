"""Only v15 graph/epoch increments over frozen HOST fixtures; no device/OS."""
import ast
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE / 'tests'))


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


with mock.patch.dict(sys.modules):
    fixture = load('private_v15_executor_fixture',
        BASE / 'tests/test_client_connect_executor_v14.py')
    f = load('private_v15_executor',
        BASE / 'candidate/client-kernel-connect-v15/runtime/mta_client_executor.py')
fixture.f = fixture.ff.f = f


class KernelExecutorV15Tests(unittest.TestCase):
    source_fixture = fixture.Tests.source_fixture

    def setUp(self):
        fixture.Tests.setUp(self)

    def test_new_24_loader_graph_keeps_old_relative_order_and_kernel_slot(self):
        old_names = ('p011_json', 'mta_ip', 'mta_client_tmp_alias', 'mta_p2p_client_init',
            'mta_client_proc', 'mta_client_caps', 'mta_client_caps_transport',
            'mta_client_baseline', 'mta_client_journal_codec', 'mta_client_coordination',
            'mta_client_files', 'mta_client_pending', 'mta_client_store',
            'mta_client_process_owner', 'mta_client_launch_registration',
            'mta_client_two_phase_lease', 'mta_p2p_client_ctrl', 'mta_client_wpa_status',
            'mta_protocol', 'mta_client_control_frame', 'mta_client_connection',
            'mta_client_linux_provider', 'mta_client_executor')
        self.assertEqual(24, len(f.MODULES))
        self.assertEqual(old_names, tuple(n for n in f.MODULES if n != 'mta_client_kernel_proof'))
        self.assertLess(f.MODULES.index('mta_client_kernel_proof'),
            f.MODULES.index('mta_client_connection'))
        loader = self.source_fixture()
        deployment = loader.load()
        self.assertIsNone(loader.authenticate(deployment))
        # The current F source is hashed/read but not recursively re-executed.
        self.assertEqual(set(f.MODULES[:-1]), set(deployment.modules))
        self.assertEqual(28, len(loader.owner.rows))
        self.assertTrue(all(row['closed'] for row in loader.owner.rows))
        ast.parse(Path(f.__file__).read_text(encoding='utf-8'), feature_version=(3, 5))

    def test_f_passes_only_original_binding_epoch_to_connection_and_retains_it(self):
        deployment, state = fixture.ff.deployment(self.io)
        metadata = dict(fixture.fields(), native_epoch=17, operation_epoch=17)
        deployment.manifest.candidate_sha = metadata['candidate_sha']
        binding = fixture.codec.ControlBinding(metadata)
        deployment.connect_binding = binding
        deployment.modules['mta_client_control_frame'] = fixture.codec
        deployment.modules['mta_client_connection'] = type('PrivateFixture', (), {
            'ConnectionObservation': fixture.ConnectionObservation})
        original = deployment.modules['mta_client_linux_provider'].assemble
        calls = []
        def assemble(manifest):
            values = original(manifest)
            def connect(info, _checkpoint, _operation_epoch):
                calls.append((info, _checkpoint, _operation_epoch))
                self.assertFalse(_checkpoint())
                self.io.buffers[0].append(fixture.codec.CANCEL)
                return fixture.ConnectionObservation()
            values[4].connect_p2p = connect
            return values
        deployment.modules['mta_client_linux_provider'].assemble = assemble
        self.io.buffers[0] = [fixture.codec.encode_connect(binding, fixture.info())]
        child = f.ClientExecutor(deployment, self.io, self.clock,
            _environ={'P011_CLIENT_EXECUTABLE_FD': '60'})
        frames = []
        child.emit = frames.append
        result = child.run()
        self.assertEqual(1, len(calls))
        self.assertIs(type(calls[0][2]), int)
        self.assertEqual(17, calls[0][2])
        self.assertEqual(calls[0][2], child.connection_ticket['operation_epoch'])
        self.assertIs(child.connect_request.binding, binding)
        self.assertFalse(child.connection_ticket['unknown'])
        self.assertTrue(result['done'])
        self.assertTrue(child.assembly[4].restored)
        self.assertNotIn('operation_epoch', frames[-1])
        self.assertFalse(result['association_verified'])
        self.assertFalse(result['ip_ready'])


if __name__ == '__main__':
    unittest.main()
