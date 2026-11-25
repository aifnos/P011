"""One new HOST DATA stage-projection contract; no native/phone evidence.

Only the actual new pure projection and strict HOST parser execute. Fixtures
are DATA holders, not a production Owner/Factory/Handoff, authorization receipt
or radio replacement. No crypto, old graph/suite, ADB or device is imported.
"""
import importlib.util
from pathlib import Path
import types
import unittest


BASE = Path(__file__).resolve().parents[1]


def definition(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def data_fixture():
    protocol = types.ModuleType('stage_contract_protocol_DATA')
    executor = types.ModuleType('stage_contract_executor_DATA')
    factory_module = types.ModuleType('stage_contract_factory_DATA')
    service = types.ModuleType('stage_contract_service_DATA')

    class PlainData(object):
        def __getattribute__(self, name):
            raise AssertionError('plaintext attributes must never be read')
    class HandoffData(object):
        pass
    class BridgeData(object):
        pass
    class FactoryData(object):
        def __call__(self, *unused):
            raise AssertionError('factory must not execute')
    class AttemptData(object):
        pass
    class DeploymentData(object):
        pass
    class LoaderData(object):
        def authenticate(self, *unused):
            raise AssertionError('loader must not authenticate')

    protocol.P2pInfo = PlainData
    executor.LoadedDeployment, executor.DeploymentLoader = DeploymentData, LoaderData
    factory_module.FixedReceiveDeploymentFactory = FactoryData
    factory_module._PublicationAttempt = AttemptData
    service.ReceiveConnectHandoff, service.StateClientBridge = HandoffData, BridgeData
    # Only the fixture method's globals identity is consumed; it is never called.
    HandoffData.decrypt = types.FunctionType((lambda self: None).__code__, {'protocol': protocol})
    session, worker = object(), object()
    state = types.SimpleNamespace(worker=worker)
    op = types.SimpleNamespace(session=session)
    handoff = HandoffData()
    handoff.state, handoff.operation, handoff.session, handoff.worker = state, op, session, worker
    handoff._plain = None
    factory = FactoryData()
    factory._active, factory._attempts = None, []
    state._trusted_receive_deployment_factory = factory
    bridge = BridgeData()
    bridge.state, bridge.operation, bridge.session, bridge.worker = state, op, session, worker
    bridge.handoff, bridge._factory, bridge._executor = handoff, factory, None
    bridge.deployment = None
    bridge.factory_ticket = dict(started=False, returned=None, authenticated=False)
    owner = types.SimpleNamespace(service=service, factory=factory,
        loader=types.SimpleNamespace(modules={'mta_protocol': protocol,
            'mta_client_executor': executor, 'mta_client_receive_factory': factory_module}))
    return owner, state, op, handoff, bridge, protocol, executor, factory_module


class StageProjectionContractTest(unittest.TestCase):
    def test_actual_stage_refs_types_unknown_and_strict_public_filter(self):
        host = definition('stage_contract_actual_host',
            BASE / 'host/device_receive_handoff_progress_120s_v2_check.py')
        runtime = definition('stage_contract_actual_runtime', BASE / host.RUNTIME_V2[0])
        owner, state, op, handoff, bridge, protocol, executor, factory_module = data_fixture()
        def stage():
            return runtime.stage_progress(owner, state, op, handoff, bridge)
        empty = stage()
        self.assertFalse(empty['stage_unknown'])
        self.assertTrue(all(empty[key] is False for key in host.STAGE_OPTIONAL_BOOL))
        self.assertIsNone(empty['factory_phase'])
        bridge._executor = executor
        bridge.factory_ticket['started'] = True
        handoff._plain = protocol.P2pInfo()
        attempt = factory_module._PublicationAttempt()
        attempt.factory, attempt.handoff, attempt.state = owner.factory, handoff, state
        attempt.operation, attempt.session, attempt.bridge, attempt.worker = op, op.session, bridge, state.worker
        attempt.phase, attempt.ended, attempt.success = 'new', False, False
        owner.factory._active, owner.factory._attempts = attempt, [attempt]
        reading = stage()
        self.assertEqual(reading, dict(executor_exact=True, factory_started=True,
            factory_returned=False, factory_authenticated=False, plain_present=True,
            factory_active_present=True, factory_ended=False, factory_success=False,
            factory_phase='new', stage_unknown=False))
        for phase in ('write', 'loader', 'ended'):
            attempt.phase, attempt.ended = phase, phase == 'ended'
            self.assertEqual(stage()['factory_phase'], phase)
        value = executor.LoadedDeployment()
        loader = executor.DeploymentLoader()
        value.modules, value.loader = {'mta_client_executor': executor}, loader
        loader.modules, loader.value = value.modules, value
        bridge.factory_ticket['returned'] = value
        returned = stage()
        self.assertTrue(returned['factory_returned'])
        self.assertFalse(returned['factory_authenticated'])  # Presence is not authentication.
        bridge.factory_ticket['authenticated'], bridge.deployment = True, value
        attempt.success = True
        self.assertTrue(stage()['factory_authenticated'])
        self.assertTrue(stage()['factory_success'])

        def unknown_fields():
            observed = stage()
            self.assertTrue(observed['stage_unknown'])
            self.assertTrue(all(observed[name] is None for name in host.STAGE_OPTIONAL_BOOL))
            self.assertIsNone(observed['factory_phase'])
        for holder, name, changed in ((bridge, '_executor', object()),
                (bridge, '_factory', object()), (handoff, '_plain', object()),
                (attempt, 'handoff', object()), (attempt, 'phase', 'reading'),
                (attempt, 'ended', 1), (loader, 'value', object())):
            original = getattr(holder, name)
            setattr(holder, name, changed)
            unknown_fields()
            setattr(holder, name, original)
        for key, changed in (('started', 1), ('returned', object()), ('authenticated', 1)):
            original = bridge.factory_ticket[key]
            bridge.factory_ticket[key] = changed
            unknown_fields()
            bridge.factory_ticket[key] = original

        component, trials = {'complete': False}, {'start': None, 'end': None}
        row = dict((name, False) for name in host.OBS_BOOL + host.PROGRESS_BOOL)
        row.update(stage(), worker_alive=True, handoff_received=True, peer_activity=True,
            bridge_started=True, bridge_running=True, decrypt_attempted=True,
            f_process_retained=False, stage='connecting', state='connecting',
            event_counts=(1, 1, 1, 0, 0, 0), elapsed_seconds=25.0)
        data = dict(scope='receive-advertise-cancel-only-v1', complete=False,
            reason='peer_activity_cancelled', flags=dict((name, name == 'peer_activity_seen') for name in host.FLAGS),
            observations=(row,), terminal=None, trials=trials, component=component)
        def parse(changed):
            candidate = dict(data, observations=(changed,))
            return host.parse_smoke(('SMOKE_RESULT=' + repr(candidate) + '\r\r\n').encode('ascii'),
                                    component, 1, trials)
        parsed = parse(row)
        self.assertIsNone(runtime.progress_decision(parsed['observations'][0]))
        unknown = dict(row, **dict((name, None) for name in host.STAGE_OPTIONAL_BOOL))
        unknown.update(stage_unknown=True, factory_phase=None)
        self.assertTrue(parse(unknown)['observations'][0]['stage_unknown'])
        self.assertIsNone(runtime.progress_decision(unknown))
        for changed in (dict(unknown, plain_present=False), dict(unknown, stage_unknown=False),
                dict(row, executor_exact=1), dict(row, factory_phase='address-or-secret'),
                dict(row, forbidden_extra='must-not-export'), dict(row, factory_returned=False),
                dict(row, factory_active_present=False)):
            with self.assertRaises(ValueError):
                parse(changed)
        # PlainData rejects any attribute access, Loader.authenticate/Factory.__call__
        # reject execution. Above PASS, if obtained by ROOT, is HOST DATA only.


if __name__ == '__main__':
    unittest.main(verbosity=2)
