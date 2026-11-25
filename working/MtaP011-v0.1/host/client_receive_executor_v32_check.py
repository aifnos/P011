"""Fixed first affected v32-r2 automatic F receive PC check; never device.

The unique new native 35-definition algorithm method executes only from a
private fixed byte snapshot. Legacy fixture imports define helper classes and
their old typed domains, but no old TestCase method is selected/invoked.
Borrowed pipes, deployment/Parent admission, process/kernel/RF/TCP/TLS and clock
are explicit HOST models. ZIP/CRC and received PC file bytes are actual.
Pinned stock backup and WPA ELF bytes stay private; no ELF is executed.
"""
import ast
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid
import zipfile


BASE = Path(__file__).resolve().parents[1]
CHECKER = 'host/client_receive_executor_v32_check.py'
TEST = 'tests/test_client_receive_executor_v32_r2.py'
TEST_SHA = '4b3763ca003c01ed8614a02333b69fb649f47739d9d98d34ca0a3bb2b52a1389'
TEST_BYTES = 82721
METHOD = 'ClientReceiveExecutorV32R2Tests.test_actual_f_automatic_receive_bytes_original_cap_and_ordered_cleanup'
PLAN = 'host/client_cancel_v32_r2_source_manifest.json'
PLAN_SHA = 'b5acd21f1a25d4e70ad357afb4ea18e7269381212d3de127e25e713d524641af'
PLAN_BYTES = 8063
PREVIOUS_PLAN_SHA = '80b9a606f69c25b45387ea7dc640708d50dfafe16f8e1c9b6978645af6451b96'
COLLECTOR = 'tests/test_client_actual_collector_v25.py'
COLLECTOR_SHA = 'd3285398a5a6eb6f0b48826dbcfce0281ad97be41a7a1723d7bb0060b346f657'
WPA = 'native/private-p2p-candidate-20261001-v2/mta-wpa-supplicant'
WPA_SHA = 'e069aef76a089215367f502015266e9ce59cf4ebb7d7246974815ff60d67f301'
WPA_BYTES = 1351192
STOCK_ROOT = '06_Firmware/backups/v2.4.0-20260923-162730/files'
STOCK_INPUTS = (
    ('Z03', 'cb8d6a78617d50f64c6adc8056427dd963bc83979cbb04e349275dd8e8ffb62a', 4103844),
    ('control_engine', '364b0bf820799070e89d9362000de4a3796a0e6a2d5f4d657464c6385b8dbd6d', 163184),
    ('zyb_z03_launch.sh', '7bce5379e3cc78e5bd8c04ceb603c88814f24c3a7efd28105ecc3c5849d6a42b', 1913),
)
CHILD_SECONDS = 300

# Six direct dependencies plus their fixed transitive definition imports.
# Some legacy fixtures load a private old graph at import time. These bytes
# are retained solely to define/clone helper types; their tests never run.
FIXTURE_INPUTS = (
    ("candidate/client-association-v16/runtime/mta_client_connection.py", "1eaf385b0921748b84414361b7bd1df06ffcb2489ea8ba567a1428b8b29daa2e", 16118),
    ("candidate/client-association-v16/runtime/mta_client_kernel_proof.py", "4ebfedf198673e3bad2f64a4bd72c581e5d6af24cef83e589b4456d2a38f8ede", 23702),
    ("candidate/client-caps-v7/runtime/mta_p2p_client_init.py", "bb22e43ec191c04624e009539f954a9bcbb7b98520fb32adf6fd4f18f4e8139a", 61503),
    ("candidate/client-connect-v13/runtime/mta_client_control_frame.py", "b20d72f17197132820d3be765cbc2e3c2a41d8256e4bdaeeb5e23f441c065b4f", 11615),
    ("candidate/client-connect-v14/runtime/mta_client_connection.py", "6ea9c395669ccb321011ea195095e3868a3f3d7e3ad5a02cb97cab4d1a591eb0", 13787),
    ("candidate/client-connect-v14/runtime/mta_client_linux_provider.py", "4683e4ddc0e9b41adb44c028fb9dd102a63e3b62180e9f7e011fa1508414218c", 95392),
    ("candidate/client-connection/runtime/mta_client_connection.py", "584a8007b076cb1df41697c690268e0d31dc0148b1eaeff43591403de00d10a4", 12928),
    ("candidate/client-connection/runtime/mta_client_linux_provider.py", "41459a480e9d78924a792bd881d25cd0696d64f0637a9d4b9be06083af09d25b", 81990),
    ("candidate/client-diagnostic-v12/runtime/mta_client_two_phase_lease.py", "03210b8c83df82993a0322398169f1ac42836d52ab8e3add92617c34b9191bad", 26626),
    ("candidate/client-durable-association-v18/runtime/mta_client_journal_codec.py", "a4ddb4691c78bbb1bdc8727a432ca4d6a72dcfe33e7f67ac606f0ced247a86d1", 15921),
    ("candidate/client-durable-association-v18/runtime/mta_client_store.py", "5ee1c184c3511bc3072e87409a88861713bfd249d79584df1d50fc1377964426", 52712),
    ("candidate/client-durable-association-v18/runtime/mta_p2p_client_init.py", "b255e3ac01ae5c39e19b611493da2ddd71115f6afac80732565d012fa72511b4", 65878),
    ("candidate/client-durable-connect-v19/runtime/mta_client_connection.py", "ae2932252bbef16b89e6bf4614c2ebdb1721d507274dbd9b9fe4d9db1d0ff159", 22494),
    ("candidate/client-durable-connect-v19/runtime/mta_client_executor.py", "9e4f0a4cc9c8a39f9e636f54776e0c0eeaef63272e3ac8a5180c08e168016cf2", 68785),
    ("candidate/client-durable-connect-v19/runtime/mta_client_linux_provider.py", "58a55789c5069b06d1e5636113f2e1dc407c5c655c20c4f9519ba30c879e1e71", 115714),
    ("candidate/client-init-nlink2/runtime/mta_client_process_owner.py", "219156a42a6598fb3e6669f191c269bfe3ac75da8f2f95190fb23b3867794b76", 27057),
    ("candidate/client-kernel-connect-v15/runtime/mta_client_connection.py", "4a561d8d385fc71870c6d46653b7855b304c854ca10f102f31d174096fd7f2d1", 15723),
    ("candidate/client-kernel-connect-v15/runtime/mta_client_executor.py", "7f80b5c75e15f2db697ae1d53ce4d33025d0e8b54db2ebf85a3916039d424475", 68903),
    ("candidate/client-kernel-connect-v15/runtime/mta_client_kernel_proof.py", "f16af6f1db74c9e6d74d2e56e6b469cf1ed589f27d3a1d5b4f897220cdeeb334", 23061),
    ("candidate/client-kernel-connect-v15/runtime/mta_client_linux_provider.py", "9e6b32141c8b1698edcc45e5459080168afe804c0bece1f5445bf8a355678136", 104672),
    ("candidate/client-kernel-proof-v13/runtime/mta_client_kernel_proof.py", "14dbe98d59e8319812e62d75907196b78fbde348f40003942476ecb9ee9c0f93", 20077),
    ("candidate/client-readparts-v6/runtime/mta_client_baseline.py", "1df29147a9cface972c9a2f486fee45c0f33d7979c6ad49dd02cdc330fe9dcc1", 29412),
    ("candidate/client-recovery-budget-v8/runtime/mta_client_pending.py", "cfba740700268d5998eb3a91bf7cdc34d893fa8f0083377d716ea98950c3f5af", 42432),
    ("candidate/client-recovery-budget-v8/runtime/mta_client_store.py", "2c1bcd60013e416fe4d0ef961ceef3bc700ceae6bc40c4c079bab0a663b411cb", 50690),
    ("candidate/client-tmp-alias-v11/runtime/mta_client_coordination.py", "930e56d35ebf08d0b1c83fe7ccab843cbe6520ecd68c0799e9a07b2bbe40823f", 35591),
    ("candidate/client-tmp-alias-v11/runtime/mta_client_files.py", "8bb891db2ec7d34a40420aef9633ef1c6798f93788bbe240732b1a0c4624b1f6", 25415),
    ("candidate/client-tmp-alias-v11/runtime/mta_client_tmp_alias.py", "1a4a52bd0bae7add6ae42f66bd9827c43865a0170c666eaab00797d1f45f7f2f", 8827),
    ("host/client_kernel_connect_v15_source_manifest.json", "5c371e8271f72f6a93faddedbc1f25359f935a3877779882618f245152154931", 5488),
    ("runtime/mta_client_baseline.py", "ce8fe17b60964cf9b421296eef033d1dde19f8a4118de12d7f3922133ee13f08", 29121),
    ("runtime/mta_client_caps_transport.py", "df6b4cf3ede6039c684c6b689a8b61ffe1ba5b87259bb4a5581aa5c3ece84420", 19614),
    ("runtime/mta_client_caps.py", "c1792c2294fed5da16ec4a676423fbcbe53d44e9bc4ddadc1bc26fd45afe046c", 11821),
    ("runtime/mta_client_coordination.py", "ea2f27c6920b4dd2cf47e5f71015382bd08dba65ed7eba9927c16f9a219b408d", 32794),
    ("runtime/mta_client_files.py", "d95afa25d82c02592d3e4d5a904a397d0f3c366124f793433131bd3d62342ed3", 22900),
    ("runtime/mta_client_journal_codec.py", "17d362826a90da7fe9d77a82495a34bbc56b4c67aaca608aa5565ee1d3369f73", 14431),
    ("runtime/mta_client_journal_transaction.py", "2783f66edbb545aff8adfaa2f80a77fd957c8ba5b365c90907474244b603dcaa", 22053),
    ("runtime/mta_client_launch_registration.py", "833d46f5717e0b7e9db0c5392a0eb93d812d039b4b946a57d49d5903534a1aa0", 21679),
    ("runtime/mta_client_linux_provider.py", "8996ae6aa82e48170514f61fc301a83532cf28a20f385153ff41c1e68b236544", 73888),
    ("runtime/mta_client_pending.py", "edd6553b847db6dc8e5d2be48256b8e3ee706adca25cbda316bcf28f357ff7cf", 42044),
    ("runtime/mta_client_proc.py", "2f0ef52379be897d47b5cb311ef90f24b5c8a2c283e72780f139a8dd77626591", 25511),
    ("runtime/mta_client_process_owner.py", "0a9a02c79e7e6603f86a7d7618f0b030a3c81d3581423801f22790e923839165", 26812),
    ("runtime/mta_client_store.py", "c6d4c8b7fda8370be83efafe61bfad4a4680ef7a8edba51a89f539c6868594cd", 47498),
    ("runtime/mta_client_two_phase_lease.py", "402cf2decd35aa31b47c07828e5ee14b7dd06bb5429740736fd11a54dfd11005", 22996),
    ("runtime/mta_client_wpa_status.py", "4f0fa75132c8c81427f1d593fdc415b01657b061cd9d1dbcbcde789b52daf742", 39045),
    ("runtime/mta_ip.py", "1fa5e72817772285fd966f52c57af105950ff0d3b6ea49b202983aebfbab40c5", 22049),
    ("runtime/mta_p2p_client_ctrl.py", "793b784f1b39eca18001aa65a1f0d6cdbd6de466dc58b3cf2ada167f71d902b5", 18712),
    ("runtime/mta_p2p_client_init.py", "ec2d927c50bf2946614990bdd9fe1d69ce5538047573d9a4d885a3914b0f85f1", 60748),
    ("runtime/mta_protocol.py", "4f7c2bd46cde114f0a2a0c33b31631aa463f09e71b156d26e34daf2251dd8a57", 17958),
    ("runtime/p011_json.py", "fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88", 8061),
    ("tests/test_client_actual_collector_v25.py", "d3285398a5a6eb6f0b48826dbcfce0281ad97be41a7a1723d7bb0060b346f657", 19057),
    ("tests/test_client_association_mac_v16.py", "255cb4cb604821aa38e9366db845cb3d738943b13e93ad9a890387c34c68a4fc", 12031),
    ("tests/test_client_baseline.py", "f80965117e0b4c4f3471ab5c109fc5034b6342c58e62ffb10d65cbbcfc4b4f80", 26310),
    ("tests/test_client_caps_transport.py", "adbb4e311d36ca85e42a9d625b494457a6fe442483ae9a6145934648ac5da176", 29483),
    ("tests/test_client_caps.py", "f777064c85d0f61229cce96950a08cef12533952ef89008134a86555f41d6281", 17604),
    ("tests/test_client_connect_provider_v14.py", "e007653af661386fb61c0710e162260f634562fdd7c2c2ee8d40b628b41757c9", 17117),
    ("tests/test_client_connection.py", "bc588f3f016d5b97f723266839290331485273638085e4b5fa1b4e153d06dfe6", 21868),
    ("tests/test_client_durable_connect_v19.py", "f92ab1be262d6da641e4cc3306f218f44d1c500f70c35d0352017cbae396bab1", 25213),
    ("tests/test_client_files.py", "fdc138903fb5c78a219b7d1e11d5d02e0443307dc57d450d6fcaabb09ff02ab2", 27409),
    ("tests/test_client_full_lifecycle_v24.py", "95ab61699cdf0e5efcd2a057d7c3d6d6a36d3843ee2fd45a9c27d3fea217119e", 21196),
    ("tests/test_client_journal_codec.py", "33750c02cabfcce7bff46390744ae94bee43ec9ab8e6c7827365075070b3f385", 20542),
    ("tests/test_client_journal_transaction.py", "4c78dbb8c46b165f63801ccabebbd9b670c9602ba7c3fea89016cc17bac06d4a", 24581),
    ("tests/test_client_kernel_proof_v13.py", "84646f200055b57a942560b3c219cb2ba3c32548d0073ca1bf16a3f6e0e68a45", 16287),
    ("tests/test_client_kernel_provider_v15.py", "0fdf5efc0ae7cef11a92c3d11f2d30cea08147bab6aa220fdea4a0be5fed6798", 16377),
    ("tests/test_client_launch_registration.py", "f5a3039c85bc202af06e66c28957d3b14bbd3b8ec4fdabef9b37fa24c21bf8fe", 32133),
    ("tests/test_client_linux_provider.py", "fcde22ad67038ae82604546282082fe8c8a4b08600e3a99c382cbd020a26a37b", 32321),
    ("tests/test_client_pending.py", "bbf890d9989a4b73748cac496149f09782d9fa32491933a272ffa4a0d6cf7e3c", 11482),
    ("tests/test_client_proc.py", "fad1f4e86dd7cb6f17f8254865b75cc9389d19f89aefd8332de9ccc8d1c9c6bc", 35215),
    ("tests/test_client_process_owner.py", "dcc33004cae2a69b8bcbc3f9646fc9311c9b5dcd2da38bce045686ace14228b2", 27984),
    ("tests/test_durable_client_store.py", "c5adeee34196d496f79587ec8662574054ab38b52c04e04aaeca9dfc1f97f1b2", 26458),
    ("tests/test_ip.py", "2338ccdcbbd7173227c2948eee5f76d51c714f1de287f5417038339503892cfc", 30585),
    ("tests/test_p2p_client_init.py", "b07bab5370d4498e8b35914856401d4ea22ce482b5e835c82abac801fc0543b4", 60726),
)


def safe_relative(path):
    return type(path) is str and bool(path) and not path.startswith(('/', '\\')) and \
        '\\' not in path and ':' not in path and \
        all(part not in ('', '.', '..') for part in path.split('/'))


def fixed_at(root, path, sha, size):
    if not safe_relative(path) or type(size) is not int or not 1 <= size <= 8388608 or \
            type(sha) is not str or re.fullmatch('[0-9a-f]{64}', sha) is None:
        raise ValueError('source_changed')
    raw = (root / path).read_bytes()
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != sha:
        raise ValueError('source_changed')
    return raw


def add_input(inputs, root_name, path, raw):
    key = root_name, path
    if key in inputs and inputs[key] != raw:
        raise ValueError('snapshot_identity_conflict')
    inputs[key] = raw
    return raw


def verify(inputs):
    """Parse/hash only; no target/fixture imports and no old method runs."""
    test_raw = add_input(inputs, 'working', TEST, fixed_at(BASE, TEST, TEST_SHA, TEST_BYTES))
    plan_raw = add_input(inputs, 'working', PLAN, fixed_at(BASE, PLAN, PLAN_SHA, PLAN_BYTES))
    plan = json.loads(plan_raw)
    if type(plan) is not dict or set(plan) != {'previous_manifest_sha256', 'schema', 'sources'} or \
            plan['schema'] != 'client-cancel-v32-r2-host' or \
            plan['previous_manifest_sha256'] != PREVIOUS_PLAN_SHA or type(plan['sources']) is not list:
        raise ValueError('graph_changed')
    rows = plan['sources']
    if len(rows) != 35 or any(type(row) is not dict or set(row) != {'module', 'path', 'sha256', 'bytes'}
            for row in rows) or len({row['module'] for row in rows}) != 35:
        raise ValueError('graph_changed')
    graph, stock_pins = None, None
    for row in rows:
        name = row['module']
        if type(name) is not str or re.fullmatch('(?:mta_|p011_)[a-z0-9_]+', name) is None:
            raise ValueError('graph_changed')
        raw = fixed_at(BASE, row['path'], row['sha256'], row['bytes'])
        add_input(inputs, 'working', row['path'], raw)
        tree = ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
        if any(isinstance(node, ast.Assert) for node in ast.walk(tree)):
            raise ValueError('target_assert_changed')
        if name == 'mta_client_executor':
            graph = [ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign) and
                any(isinstance(target, ast.Name) and target.id == 'MODULES' for target in node.targets)]
        if name == 'mta_p2p_client_init':
            stock_pins = [ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign) and
                any(isinstance(target, ast.Name) and target.id == 'STOCK_PINS' for target in node.targets)]
    if graph != [tuple(row['module'] for row in rows)]:
        raise ValueError('executor_graph_changed')
    expected_stock = tuple(('/usr/bin/' + name, sha) for name, sha, unused in STOCK_INPUTS)
    if stock_pins != [expected_stock]:
        raise ValueError('stock_input_binding_changed')
    tree = ast.parse(test_raw.decode('utf-8'))
    methods = [cls.name + '.' + method.name for cls in tree.body if isinstance(cls, ast.ClassDef)
        for method in cls.body if isinstance(method, ast.FunctionDef) and method.name.startswith('test_')]
    if methods != [METHOD]:
        raise ValueError('method_changed')
    constants = {target.id: ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
        for target in node.targets if isinstance(target, ast.Name) and target.id == 'INPUT_PINS'}
    if constants != {'INPUT_PINS': {COLLECTOR: COLLECTOR_SHA, PLAN: PLAN_SHA}}:
        raise ValueError('test_source_binding_changed')
    for path, sha, size in FIXTURE_INPUTS:
        add_input(inputs, 'working', path, fixed_at(BASE, path, sha, size))
    elf = fixed_at(BASE, WPA, WPA_SHA, WPA_BYTES)
    if not elf.startswith(b'\x7fELF'):
        raise ValueError('elf_magic_changed')
    add_input(inputs, 'working', WPA, elf)
    for name, sha, size in STOCK_INPUTS:
        path = STOCK_ROOT + '/' + name
        add_input(inputs, 'project', path, fixed_at(BASE.parents[1], path, sha, size))
    return rows


def snapshot_inputs(output, inputs):
    # Preserve the frozen collector's BASE.parents[1]/06_Firmware topology.
    # Never substitute an absolute live path or rewrite the selected test.
    snapshot = output / 'private-inputs' / 'project'
    child_base = snapshot / 'working' / 'MtaP011-v0.1'
    observations = []
    for (root_name, path), raw in sorted(inputs.items()):
        root = child_base if root_name == 'working' else snapshot
        destination = root / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
        saved = destination.read_bytes()
        if saved != raw:
            raise ValueError('snapshot_changed')
        observations.append({'root': root_name, 'path': path, 'bytes': len(raw),
            'sha256': hashlib.sha256(raw).hexdigest()})
    return child_base, observations


def publish(output, value, stdout, stderr, passed):
    result = (json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2) + '\n').encode('utf-8')
    note = (
        'One unique new affected v32-r2 PC automatic F receive method only, run from a fixed private byte snapshot. '
        'The native 35-source F/INIT/CONNECT/DORA/IP/peer/Transfer/Transport, canonical Store facts and '
        'receive-control parser execute over explicit synthetic OS/RF/kernel/Proc/TCP/TLS/borrowed pipe/clock seams. '
        'Actual PC ZIP parsing, CRC and received file bytes are checked. F and Provider IO are distinct modeled objects. '
        'The fixed collector plus five direct fixture identities and transitive legacy definition inputs are verified '
        'and copied; legacy typed domains are definition imports only and no old TestCase method runs. '
        'Three locally pinned stock backup files and WPA ELF are private input bytes only, never installed or executed. '
        'No actual Parent admission/spawn/wait, deployment Loader, physical F process, Linux socket/RF, '
        'P011 send/receive/restoration or Xiaomi phone compatibility is certified. Original quotas/caps remain unchanged. '
        'Public raw is included only for empty stdout, exact Ran 1/OK stderr, child exit 0 and no timeout. '
        'Failure raw and all input snapshots remain private, with no automatic retry or artifact reconciliation.\n'
    ).encode('ascii')
    (output / 'result.json').write_bytes(result)
    (output / 'README.txt').write_bytes(note)
    archive = output / 'public-result.zip'
    members = ['result.json', 'README.txt'] + (['stdout.raw', 'stderr.raw'] if passed else [])
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr('result.json', result)
        bundle.writestr('README.txt', note)
        if passed:
            bundle.writestr('stdout.raw', stdout)
            bundle.writestr('stderr.raw', stderr)
    with zipfile.ZipFile(archive) as bundle:
        if bundle.namelist() != members or bundle.testzip() is not None or \
                bundle.read('result.json') != result or bundle.read('README.txt') != note or \
                passed and (bundle.read('stdout.raw') != stdout or bundle.read('stderr.raw') != stderr):
            raise ValueError('archive_changed')
    return archive


def main():
    if len(sys.argv) != 1:
        print('PC_ONLY: fixed one new v32-r2 method; no device/path/stage/network arguments')
        return 2
    output = BASE / 'results' / ('client-receive-executor-v32-r2-native-' +
        datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    output.mkdir()
    own = Path(__file__).read_bytes()
    inputs, rows = {('working', CHECKER): own}, []
    source_verified, verification_error = False, None
    verification_started = time.monotonic()
    try:
        rows = verify(inputs)
        source_verified = True
    except (OSError, ValueError, KeyError, TypeError, SyntaxError, UnicodeError):
        verification_error = 'fixed_source_invalid'
    verification_seconds = time.monotonic() - verification_started
    snapshot_error, child_base, input_rows = None, None, []
    try:
        child_base, input_rows = snapshot_inputs(output, inputs)
    except (OSError, ValueError):
        snapshot_error = 'private_snapshot_invalid'
    snapshot_complete = source_verified and snapshot_error is None
    stdout, stderr, code, timeout = b'', b'', None, False
    attempted, invoked, launch_error = False, False, None
    started = time.monotonic()
    if snapshot_complete:
        attempted = True
        child_env = dict(os.environ)
        child_env.pop('PYTHONPATH', None)
        child_env.pop('PYTHONSTARTUP', None)
        try:
            # -I excludes live cwd/user site/PYTHONPATH fallback. The frozen
            # test explicitly adds only its copied fixture/runtime paths.
            child = subprocess.run([sys.executable, '-I', '-B', str(child_base / TEST), '-q', METHOD],
                cwd=str(child_base), env=child_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=CHILD_SECONDS, check=False)
            stdout, stderr, code, invoked = child.stdout, child.stderr, child.returncode, True
        except subprocess.TimeoutExpired as error:
            stdout, stderr, code, timeout, invoked = error.stdout or b'', error.stderr or b'', None, True, True
        except OSError:
            launch_error = 'host_child_not_started'
    elapsed = time.monotonic() - started
    (output / 'stdout.raw').write_bytes(stdout)
    (output / 'stderr.raw').write_bytes(stderr)
    stderr_reviewed = re.fullmatch(
        rb'-{70}\r?\nRan 1 test in [0-9]+\.[0-9]+s\r?\n\r?\nOK\r?\n', stderr) is not None
    passed = invoked and snapshot_complete and launch_error is None and code == 0 and \
        not timeout and stdout == b'' and stderr_reviewed
    value = dict(schema='client-receive-executor-v32-r2-host', selected_method=METHOD,
        selected_method_count=1, original_method_invocations=0, old_test_method_invocations=0,
        new_method_invocations=1 if invoked else 0, method_attempted=attempted, method_invoked=invoked,
        host_exit=code, timeout=timeout, host_child_timeout_seconds=CHILD_SECONDS,
        host_elapsed_seconds=elapsed, source_verification_elapsed_seconds=verification_seconds,
        verification_error=verification_error, snapshot_error=snapshot_error, launch_error=launch_error,
        host_method_passed=passed, source_integrity_verified=source_verified,
        python35_syntax_verified=source_verified, source_count=len(rows), sources=rows,
        source_manifest_sha256=PLAN_SHA, source_manifest_bytes=PLAN_BYTES,
        previous_source_manifest_sha256=PREVIOUS_PLAN_SHA, test_sha256=TEST_SHA, test_bytes=TEST_BYTES,
        checker_sha256=hashlib.sha256(own).hexdigest(), input_snapshot_complete=snapshot_complete,
        input_snapshot_entry_count=len(input_rows), inputs=input_rows,
        child_reads_private_snapshot=invoked, child_python_isolated_mode=True,
        fixture_direct_dependency_count=6, fixture_transitive_input_count=len(FIXTURE_INPUTS),
        fixture_old_domains_definition_imports_only=True,
        native_graph_definition_count=35 if passed else None,
        native_f_algorithm_host_model_invoked=invoked,
        host_automatic_f_receive_model_tested=passed, native_f_algorithm_host_model_tested=passed,
        actual_pc_zip_crc_file_bytes_tested=passed, original_quota_unchanged=True,
        actual_parent_fifo_tested=False, modeled_parent_admission_and_pipe=True,
        runtime_os_metadata_descriptors_modeled=True, rf_kernel_proc_socket_model=True,
        synthetic_clock=True, distinct_f_provider_io_modeled=True,
        physical_f_process_tested=False, deployment_loader_tested=False,
        actual_parent_spawn_wait_tested=False, actual_parent_admission_tested=False,
        actual_tcp_tls_tested=False, actual_linux_platform_tested=False,
        device_accessed=False, rf_requested=False, phone_tested=False,
        p011_send_available=False, p011_receive_available=False, actual_p011_restore_verified=False,
        native_wpa_sha256=WPA_SHA, native_wpa_bytes=WPA_BYTES, native_wpa_executed=False,
        stock_backup_bytes_archived_private=source_verified, stock_backup_device_read=False,
        native_binary_bytes_in_public_zip=False, full_syscall_wall_bound_verified=False,
        full_heap_bound_verified=False, stdout_empty_reviewed=stdout == b'',
        unittest_stderr_reviewed=stderr_reviewed, stdout_sha256=hashlib.sha256(stdout).hexdigest(),
        stderr_sha256=hashlib.sha256(stderr).hexdigest(), public_raw_included=passed,
        public_zip_member_count=4 if passed else 2)
    archive = publish(output, value, stdout, stderr, passed)
    print(json.dumps(dict(selected_method=METHOD, passed=passed, host_exit=code, timeout=timeout,
        elapsed_seconds=elapsed, public_zip_member_count=4 if passed else 2,
        result_zip=str(archive), zip_sha256=hashlib.sha256(archive.read_bytes()).hexdigest()), ensure_ascii=False))
    return 0 if passed else 2 if verification_error or snapshot_error or launch_error else 1


if __name__ == '__main__': raise SystemExit(main())
