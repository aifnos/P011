"""Generate and read back the complete fixed runtime75 SOURCE carrier on the PC.

This entry has no device mode. It does not execute the carrier, a runtime role,
historical tests/main/verify_inputs, an RF action or a user-file transfer.
"""
import ast
import base64
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import traceback
import types
import uuid
import zlib

BASE = Path(__file__).resolve().parents[1]
DEFINITIONS = ('host/formal_receive_durable_state_v1_definitions.py', 45031,
    'b98c66604bdb250820630f1844e5ea4b0af9bbd260e05388478034e37254e43b')
GENERATION = ('candidate/formal-receive-durable-state-v1/generation.json', 3858,
    '3d4f46e650e8b33e1845cb82180b07c1c82ace9ccb90357c9ed94fb15443b05d')


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def fresh(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        need(stream.write(raw) == len(raw), 'short_write')
    need(path.read_bytes() == raw, 'artifact_readback')


def artifacts():
    path = BASE / 'host/host_artifact_seal_v1.py'
    spec = importlib.util.spec_from_file_location('fixed_host_artifact_seal_v1', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def unpack(encoded, size):
    need(type(encoded) is str, 'carrier_encoding_type')
    decoder = zlib.decompressobj()
    result = decoder.decompress(base64.b64decode(encoded, validate=True), size + 1)
    need(len(result) == size and decoder.eof and not decoder.unused_data and
         not decoder.unconsumed_tail, 'carrier_encoding_size')
    return result


def main():
    need(sys.argv[1:] == [] and sys.platform == 'win32' and
         BASE == Path(r'D:\project\P011\working\MtaP011-v0.1'), 'fixed_pc_source_only')
    out = BASE / 'results' / ('receive-durable-state-v1-source-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    out.mkdir(parents=True, exist_ok=False)
    inputs, facts, error, program = {}, {}, None, None
    sealer = artifacts()
    evidence = sealer.InputEvidence(inputs)

    def retain(pin):
        path, size, sha = pin
        return evidence.read(BASE / path, key=path, pin=(size, sha))

    try:
        evidence.read(Path(__file__), key='host/receive_durable_state_v1_source_check.py')
        evidence.read(BASE / 'host/host_artifact_seal_v1.py', key='host/host_artifact_seal_v1.py')
        evidence.read(BASE / 'HOST_MTA_RECEIVE_DURABLE_STATE_V1_SOURCE_CHECK.cmd',
                      key='HOST_MTA_RECEIVE_DURABLE_STATE_V1_SOURCE_CHECK.cmd')
        definition_raw = retain(DEFINITIONS)
        ast.parse(definition_raw.decode('utf-8'), feature_version=(3, 5))
        definitions = types.ModuleType('fixed_durable_source_interfaces')
        definitions.__file__ = str(BASE / DEFINITIONS[0])
        exec(compile(definition_raw, definitions.__file__, 'exec'), definitions.__dict__)
        need(definitions.STATE_ALIAS == '/tmp/p011-mta-rx-durable-v1' and
             definitions.STATE_ROOT == '/var/volatile/tmp/p011-mta-rx-durable-v1' and
             definitions.PAYLOAD_BYTES == 4191752 and len(definitions.ORIGIN_SOURCE_PINS) == 164,
             'fixed_graph_identity')
        for pin in definitions.ORIGIN_SOURCE_PINS:
            retain(pin)
        for pin in (definitions.MANIFEST, definitions.PRIVATE_MANIFEST, definitions.RUNNER,
                    definitions.CHECKER, definitions.TRANSPORT, GENERATION):
            retain(pin)
        ordinary = definitions.manifest_rows(inputs[definitions.MANIFEST[0]])
        private = definitions.manifest_rows(inputs[definitions.PRIVATE_MANIFEST[0]], private=True)
        payload = ordinary + definitions.HELPERS + private + (definitions.WPA, definitions.MONITOR)
        need(len(ordinary) == len(private) == 35 and len(payload) == 75 and
             len({row[0] for row in payload}) == 75, 'role_inventory')
        for name, path, size, sha in payload + definitions.FILECENTER_SOURCE_PINS:
            retain((path, size, sha))
        need(definitions.verify_inputs(inputs) == 9, 'nine_mechanical_closures')
        total = sum(len(inputs[path]) for name, path, size, sha in payload)
        need(total == 4191752 and total <= 4194304 and
             len(definitions.FILECENTER_SOURCE_PINS) == 9 and
             sum(row[2] for row in definitions.FILECENTER_SOURCE_PINS) == 113690, 'actual_budget')
        helper, checker_raw = definitions.load_checker()
        need(checker_raw == inputs[definitions.CHECKER[0]], 'checker_identity')
        program = definitions.make_source(helper, inputs, payload, False)
        need(type(program) is bytes and len(program) <= 2097152 and
             max(map(len, program.splitlines())) <= 256, 'carrier_budget')
        tree = ast.parse(program.decode('ascii'), feature_version=(3, 5))
        values = {node.targets[0].id: ast.literal_eval(node.value) for node in tree.body
                  if isinstance(node, ast.Assign) and len(node.targets) == 1 and
                  isinstance(node.targets[0], ast.Name) and node.targets[0].id in
                  ('USE_UI', 'RUNNER_PIN', 'RUNNER_ENCODED', 'ARTIFACT_ROWS')}
        need(values['USE_UI'] is False and values['RUNNER_PIN'] == definitions.RUNNER[1:] and
             unpack(values['RUNNER_ENCODED'], definitions.RUNNER[1]) == inputs[definitions.RUNNER[0]],
             'carrier_runner_readback')
        need(len(values['ARTIFACT_ROWS']) == 75, 'carrier_roles')
        for encoded, row in zip(values['ARTIFACT_ROWS'], payload):
            name, path, size, sha = row
            need(encoded[:3] == (name, size, sha) and len(encoded) == 4 and
                 unpack(encoded[3], size) == inputs[path], 'carrier_payload_readback')
        evidence.snapshot(out, lambda name: name)
        fresh(out / 'private-runtime75-target.py', program)
        need(all((BASE / name).read_bytes() == raw and
                 (out / 'private-inputs' / name).read_bytes() == raw for name, raw in inputs.items()),
             'source_changed')
        facts.update(ordinary_roles=35, private_roles=35, payload_roles=75,
            payload_bytes=total, payload_remaining_bytes=4194304-total,
            filecenter_sources=9, filecenter_bytes=113690,
            flat_origin_pins=164, mechanical_closures=9, business_delta_sources=5,
            target_bytes=len(program), target_max_line=max(map(len, program.splitlines())),
            target_sha256=digest(program), carrier_payloads_readback=True,
            source_preserved=True, source_inputs=len(inputs))
    except BaseException as failure:
        error = type(failure).__name__ + ':' + str(failure)
        exception = traceback.format_exc().encode('utf-8')
    try:
        evidence.snapshot(out, lambda name: name)
        if 'exception' in locals():
            fresh(out / 'private-raw/checker-exception.txt', exception)
    except BaseException as failure:
        error = (error + ';' if error else '') + 'evidence_failed:' + type(failure).__name__ + ':' + str(failure)
    passed = error is None
    report = dict(schema='p011-receive-durable-state-v1-source-check', passed=passed,
        error=error, host_exit=0 if passed else 1, remote_exit='NOT_RUN_PC_SOURCE_ONLY',
        evidence_level='COMPLETE_RUNTIME75_SOURCE_ONLY', facts=facts,
        source_graph_verified=passed, runtime_graph_executed=False, business_tests_replayed=0,
        historical_verify_inputs_called=False, old_main_called=False,
        device=False, rf=False, phone=False, gui_worker_connected=False,
        deployed=False, restoration_verified=False, mobile_transfer_verified=False,
        inputs=[dict(path=name, bytes=len(raw), sha256=digest(raw), complete=name not in evidence.partial)
            for name, raw in inputs.items()])
    readme = (b'Complete fixed runtime75 SOURCE only; encoded runner and all75 roles read back.\n'
                      b'No historical tests/main/verify_inputs replay, carrier/runtime execution, P011/RF/phone.\n'
                      b'GUI worker integration, deployment, transfer and restoration remain unverified.\n'
                      b'Exact inputs, exception streams and generated carrier remain private.\n')
    sealed = sealer.seal_result(out, report, readme)
    report = sealed['report']
    print(json.dumps(dict(passed=report['passed'], error=report['error'], facts=facts, result=str(out / 'result.json'),
        zip=str(sealed['archive']) if sealed['archive'] else None,
        zip_sha256=sealed['archive_sha256']), sort_keys=True))
    return sealed['host_exit']


if __name__ == '__main__':
    raise SystemExit(main())
