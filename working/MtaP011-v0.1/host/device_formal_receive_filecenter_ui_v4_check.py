"""Receiver/FC UI with post-READY, read-only scanout; SOURCE by default.

Only the unique PC carrier-launch call streams its original stdout/stderr.
The original Worker, 20s display lease, 46 facts and restoration gates stay
unchanged except the new exclusive control suffix. A complete live READY
line schedules the frozen held-log/PID watcher, then the pinned DRM reader.
No observer runs during Startup, no input/RF/file action is requested.
"""
import ast
import copy
import hashlib
import json
from pathlib import Path
import time
import types

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_formal_receive_filecenter_ui_v4_check.py'
CMDS = ('HOST_MTA_FORMAL_RECEIVE_FILECENTER_UI_V4_CHECK.cmd',
        'TEST_MTA_FORMAL_RECEIVE_FILECENTER_UI_V4.cmd')
PREVIOUS = ('host/device_formal_receive_filecenter_ui_v3_check.py', 5072,
            'f3788aec0ccc3e09c21328bf75cc75d26114cdc10fee1786038181bd474aaa15')
OLD_WORKER = ('candidate/formal-receive-filecenter-ui-v3/runtime/ui_session.py', 91420,
              'a00c8f863bb75fd65af06cbbc1a32b23322dfada55d0926cc9eedcd668068fa3')
WORKER = ('candidate/formal-receive-filecenter-ui-v4/runtime/ui_session.py', 91420,
          '53465b7cdcd576fa689d5c08e0de38a6c53a360efa76b88563e39f0182382e18')
STREAM = ('host/ready_capture_stream_v2.py', 8040,
          '1dbac1b1c4c164b84f53b323acdace78175b00d838229df0251af9c7a596dc9b')
OLD_STREAM = ('host/ready_capture_stream_v1.py', 6690,
              '0834b4bafd780562cdde847ef6fe0d1a5ed98318fbe00a87adf2a72b3232a34d')
WATCHER = ('host/capture_formal_ui_v7_ready.py', 3650,
           'd3b6934a6b1b1a099345153d615d5cc9ae9c42cb646685187cb8c10e6a5c3c69')
SCANOUT = ('host/capture_ui_scanout_v1.py', 5051,
           '18bddf409d82382319a2ac3fe63125d39314dfc03a9771168737437a9237ab7d')
PROBE = ('host/device_probe.py', 8759,
         'e7a841ec250adb083c643250bae3a6ac07412e775c4bef98f935f6d1c9fa9348')
DRM_PIN = (4120, '2f8baf2c724a69faab9825f3155f79cc9b9a610a13d9967b02221733c2cf281d')
DRM_PATH = BASE.parent / 'BiliP011-v0.1/host/capture_drm_scanout.py'
OLD_SUFFIX = b'-formal-receive-filecenter-ui-v3'
NEW_SUFFIX = b'-formal-receive-filecenter-ui-v4'
SESSION = '1293b528d39ff32746dbe196'


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def fixed(pin):
    raw = (BASE / pin[0]).read_bytes()
    need((len(raw), digest(raw)) == pin[1:], 'ready_capture_pin')
    return raw


def definitions(pin, name):
    raw = fixed(pin)
    value = types.ModuleType(name)
    value.__file__ = str(BASE / pin[0])
    exec(compile(raw, value.__file__, 'exec'), value.__dict__)
    return value, raw


def shape(node):
    return ast.dump(node, include_attributes=False)


def watch_source(raw):
    tree = ast.parse(raw)
    rows = [row for row in tree.body if isinstance(row, ast.Assign) and
            len(row.targets) == 1 and isinstance(row.targets[0], ast.Name) and
            row.targets[0].id == 'WATCH']
    need(len(rows) == 1, 'ready_watch_literal')
    original = ast.literal_eval(rows[0].value)
    old_session = 'a44b98dd639095d9063c9e1a'
    old_suffix = '-formal-send-filecenter-ui-v7'
    need(original.count(old_session) == 2 and original.count(old_suffix) == 1,
         'ready_watch_identity')
    current = original.replace(old_session, SESSION).replace(old_suffix, NEW_SUFFIX.decode('ascii'))
    need(current.replace(SESSION, old_session).replace(NEW_SUFFIX.decode('ascii'), old_suffix) == original,
         'ready_watch_inverse')
    ast.parse(current, feature_version=(3, 5))
    return current


def scanout_main(module, raw):
    """Same pinned DRM algorithm, fixed explicit args; no outer PC helper.

    Keeping its original Adb.python20 call in this callback lets the original
    subprocess.run own timeout/kill/reap. Killing a separate helper could
    leave that helper's ADB child alive; that extra process is not used here.
    """
    tree = ast.parse(raw)
    rows = [row for row in tree.body if isinstance(row, ast.FunctionDef) and row.name == 'main']
    need(len(rows) == 1, 'ready_scanout_main')
    tree = ast.Module(body=rows, type_ignores=[])
    before = copy.deepcopy(tree)
    calls = [row for row in ast.walk(tree) if isinstance(row, ast.Assign) and
             len(row.targets) == 1 and isinstance(row.targets[0], ast.Name) and
             row.targets[0].id == 'args' and isinstance(row.value, ast.Call) and
             shape(row.value.func) == shape(ast.parse('parser.parse_args', mode='eval').body)]
    labels = [row for row in ast.walk(tree) if isinstance(row, ast.Constant) and row.value == 'ui-scanout-v1-']
    need(len(calls) == len(labels) == 1, 'ready_scanout_shape')
    old_call = copy.deepcopy(calls[0].value)
    calls[0].value = ast.Name(id='_READY_ARGS', ctx=ast.Load())
    labels[0].value = 'ui-scanout-ready-v2-'
    final = copy.deepcopy(tree)
    calls[0].value = old_call
    labels[0].value = 'ui-scanout-v1-'
    need(shape(tree) == shape(before), 'ready_scanout_inverse')
    module._READY_ARGS = types.SimpleNamespace(check_device=True)
    exec(compile(ast.fix_missing_locations(final), str(BASE / SELF), 'exec'), module.__dict__)
    return module.main


class ReadyCapture:
    """PC-side observation only; does not grant original Worker acceptance."""
    def __init__(self, stream, probe, watch):
        self.stream, self.probe, self.watch = stream, probe, watch
        self.stream_facts = None
        self.side = dict(requested=False, watch_passed=False, scanout_passed=False,
                         capture_closed=False, error_kind=None, images_private=True,
                         physical_screen_verified=False, input_injected=False,
                         rf_requested=False)

    def facts(self):
        return dict(self.side, stream=self.stream_facts)

    def complete(self):
        return (self.side['requested'] is True and self.side['watch_passed'] is True and
                self.side['scanout_passed'] is True and self.side['capture_closed'] is True and
                self.side['error_kind'] is None and type(self.stream_facts) is dict and
                self.stream_facts['ready_stream_count'] == 1 and
                all(self.stream_facts[key] is True for key in
                    ('host_stream_complete', 'raw_readers_closed', 'stdin_writer_closed', 'callback_closed')) and
                self.stream_facts['callback_failed'] is False)

    def observe(self, transport_id, private):
        self.side['requested'] = True
        until = time.monotonic() + 135.0
        watch_returned = False
        scanout_returned = False
        try:
            # Independent raw directory/index, but the identical selected P011
            # transport. The constructor only enumerates, after actual READY.
            directory = private / 'after-ready-readonly'
            directory.mkdir(exist_ok=False)
            adb = self.probe.Adb(directory)
            need(adb.transport == transport_id, 'ready_transport_changed')
            need(time.monotonic() < until, 'ready_capture_deadline')
            facts = adb.python('fixed-receive-fc-v4-ready-readonly', self.watch, timeout=75)
            watch_returned = True
            self.side['watch_passed'] = (type(facts) is dict and
                set(facts) == {'ready', 'candidate_live', 'watch_fd_closed', 'read_bytes', 'readonly'} and
                all(facts.get(key) is True for key in ('ready', 'candidate_live', 'watch_fd_closed', 'readonly')) and
                type(facts.get('read_bytes')) is int and 0 < facts['read_bytes'] <= 4194304)
            need(self.side['watch_passed'], 'ready_current_candidate_not_observed')
            self.side['watch'] = facts
            need(time.monotonic() < until, 'ready_capture_deadline')
            fixed(PROBE)
            scanout, scanout_raw = definitions(SCANOUT, 'ready_v4_scanout_algorithm')
            drm = DRM_PATH.read_bytes()
            need((len(drm), digest(drm)) == DRM_PIN, 'ready_drm_pin')
            # Same algorithm and target12/HOST20, directly in the PC callback.
            # No extra PC helper process or global sys.argv/stdout mutation.
            def readonly_adb(raw_directory):
                need(time.monotonic() < until, 'ready_capture_deadline')
                current = self.probe.Adb(raw_directory)
                need(current.transport == transport_id, 'ready_scanout_transport_changed')
                return current

            scanout.Adb = readonly_adb
            with (directory / 'scanout.stdout.raw').open('xb') as stdout:
                def private_print(*values, sep=' ', end='\n', flush=False):
                    raw = (sep.join(str(value) for value in values) + end).encode('utf-8')
                    need(stdout.write(raw) == len(raw), 'ready_scanout_short_write')
                    if flush:
                        stdout.flush()
                scanout.print = private_print
                code = scanout_main(scanout, scanout_raw)()
            scanout_returned = True
            with (directory / 'scanout.host-exit').open('x', encoding='ascii') as handle:
                handle.write(str(code))
            need(code == 0 and time.monotonic() < until, 'ready_scanout_failed')
            output = (directory / 'scanout.stdout.raw').read_bytes()
            need(0 < len(output) <= 65536, 'ready_scanout_output_bound')
            rows = output.replace(b'\r\r\n', b'\n').replace(b'\r\n', b'\n').splitlines()
            value = json.loads(rows[-1])
            need(type(value) is dict and value.get('passed') is True, 'ready_scanout_receipt')
            out = Path(value['result_dir']).resolve()
            need(out.parent == (BASE / 'results').resolve() and
                 out.name.startswith('ui-scanout-ready-v2-device-') and
                 Path(value['public_result_zip']).resolve() == out / 'public-result.zip',
                 'ready_scanout_result_binding')
            bundle = (out / 'public-result.zip').read_bytes()
            need(digest(bundle) == value['zip_sha256'], 'ready_scanout_zip_binding')
            report = json.loads((out / 'result.json').read_bytes())
            need(report.get('passed') is True and report.get('device_invoked') is True and
                 report.get('images_private') is True and report.get('framebuffer_written') is False and
                 report.get('drm_master_requested') is False and
                 type(report.get('captured_rows')) is list and 0 < len(report['captured_rows']) <= 16,
                 'ready_scanout_metadata')
            names = [row.get('image_file') for row in report['captured_rows']]
            need(all(type(name) is str and name.startswith('scanout-') and
                     name.endswith('.png') and '/' not in name and '\\' not in name and
                     (out / 'private-raw' / name).is_file() for name in names), 'ready_scanout_images')
            self.side.update(scanout_passed=True, scanout_result_dir=out.name,
                             scanout_zip_sha256=value['zip_sha256'], scanout_image_count=len(names))
        except BaseException as error:
            self.side['error_kind'] = type(error).__name__
            # Full details only in the newly exclusive private side directory.
            import traceback
            path = private / 'after-ready-error.private.txt'
            with path.open('xb') as handle:
                handle.write(traceback.format_exc().encode('utf-8'))
        finally:
            # A failed WATCH or screenshot is not a target closure proof.
            # Only both naturally returned, accepted read-only jobs qualify.
            self.side['capture_closed'] = (watch_returned and scanout_returned and
                self.side['watch_passed'] is True and self.side['scanout_passed'] is True)

    def carrier(self, carrier, adb, private, label, source, timeout):
        # Match the unique original call, including the original810 HOST cap.
        need(label == 'carrier-launch' and timeout in (210, 810), 'ready_stream_call')
        if timeout == 210:
            return carrier.run_carrier(adb, private, label, source, timeout)
        original_run = adb.run
        had_instance = 'run' in adb.__dict__
        original_instance = adb.__dict__.get('run')

        def streamed(label, arguments, timeout=30, input_data=None):
            need(label == 'carrier-launch' and timeout == 810 and input_data is None and
                 type(arguments) is list and len(arguments) == 2 and arguments[0] == 'shell',
                 'ready_stream_original_args')
            need(Path(self.probe.ADB).resolve() == Path('C:/Program Files/ADB/adb.exe').resolve(),
                 'ready_stream_executable')
            adb.index += 1
            stem = '%02d-%s' % (adb.index, label)
            raw, self.stream_facts = self.stream.run_stream(
                [str(self.probe.ADB), '-t', adb.transport] + arguments, private, stem, timeout,
                input_data=input_data, on_ready=lambda: self.observe(adb.transport, private))
            return raw

        adb.run = streamed
        try:
            return carrier.run_carrier(adb, private, label, source, timeout)
        finally:
            if had_instance:
                adb.run = original_instance
            else:
                del adb.run
            need(adb.run == original_run, 'ready_stream_method_restored')


def adapted_main(original, extra_inputs):
    def adapted(raw):
        tree = original(raw)
        before = copy.deepcopy(tree)
        body = tree.body[0].body
        seeds = [row for row in body if isinstance(row, ast.Assign) and len(row.targets) == 1 and
                 isinstance(row.targets[0], ast.Name) and row.targets[0].id == 'inputs']
        labels = [row for row in ast.walk(tree) if isinstance(row, ast.Constant) and
                  row.value == 'formal-receive-filecenter-ui-v3-']
        launch = [row for row in ast.walk(tree) if isinstance(row, ast.Call) and
                  shape(row.func) == shape(ast.parse('carrier.run_carrier', mode='eval').body) and
                  len(row.args) == 5 and isinstance(row.args[2], ast.Constant) and
                  row.args[2].value == 'carrier-launch']
        passes = [row for row in body if isinstance(row, ast.Assign) and len(row.targets) == 1 and
                  isinstance(row.targets[0], ast.Subscript) and
                  isinstance(row.targets[0].value, ast.Name) and row.targets[0].value.id == 'report' and
                  isinstance(row.targets[0].slice, ast.Constant) and row.targets[0].slice.value == 'passed']
        need(len(seeds) == len(labels) == len(launch) == len(passes) == 1 and
             isinstance(seeds[0].value, ast.Dict), 'ready_main_shape')
        old_seed = copy.deepcopy(seeds[0].value)
        old_call = copy.deepcopy(launch[0])
        old_pass = copy.deepcopy(passes[0].value)
        for path, value in extra_inputs.items():
            seeds[0].value.keys.append(ast.Constant(value=path))
            seeds[0].value.values.append(ast.Constant(value=value))
        labels[0].value = 'formal-receive-filecenter-ui-v4-'
        launch[0].func = ast.parse('READY_CAPTURE.carrier', mode='eval').body
        launch[0].args.insert(0, ast.Name(id='carrier', ctx=ast.Load()))
        passes[0].value = ast.BoolOp(op=ast.And(), values=[old_pass, ast.parse(
            "mode != 'ui-smoke' or READY_CAPTURE.complete()", mode='eval').body])
        at = body.index(passes[0])
        side = ast.parse("report['ready_capture'] = READY_CAPTURE.facts()\n").body[0]
        body.insert(at, side)
        final = copy.deepcopy(tree)
        body.remove(side)
        seeds[0].value = old_seed
        labels[0].value = 'formal-receive-filecenter-ui-v3-'
        launch[0].func, launch[0].args = old_call.func, old_call.args
        passes[0].value = old_pass
        need(shape(tree) == shape(before), 'ready_main_inverse')
        return ast.fix_missing_locations(final)
    return adapted


def main():
    previous, previous_raw = definitions(PREVIOUS, 'ready_v4_previous_definitions')
    comparison, comparison_raw = definitions(previous.COMPARISON, 'ready_v4_comparison_definitions')
    original, original_raw = definitions(comparison.ORIGINAL, 'ready_v4_original_definitions')
    worker_raw, old_worker_raw = fixed(WORKER), fixed(OLD_WORKER)
    need(worker_raw.count(NEW_SUFFIX) == old_worker_raw.count(OLD_SUFFIX) == 1 and
         worker_raw.replace(NEW_SUFFIX, OLD_SUFFIX, 1) == old_worker_raw, 'ready_worker_inverse')
    ast.parse(worker_raw, feature_version=(3, 5))
    stream, stream_raw = definitions(STREAM, 'ready_v4_stream_definitions')
    probe, probe_raw = definitions(PROBE, 'ready_v4_probe_definitions')
    watch_raw, scanout_raw = fixed(WATCHER), fixed(SCANOUT)
    scanout_definition, _ = definitions(SCANOUT, 'ready_v4_source_scanout_definitions')
    scanout_main(scanout_definition, scanout_raw)  # Compile only, never SOURCE IO.
    drm_raw = DRM_PATH.read_bytes()
    need((len(drm_raw), digest(drm_raw)) == DRM_PIN, 'ready_source_drm_pin')
    capture = ReadyCapture(stream, probe, watch_source(watch_raw))
    comparison.NEW_CONTROL = "'/var/volatile/tmp/p011-mta-ui-session-' + SESSION + '-formal-receive-filecenter-ui-v4'"
    derived = comparison.comparison_main(original.new_main, original_raw, fixed(comparison.OLD_WORKER))
    derived = previous.retained_main(derived, comparison_raw, fixed(previous.OLD_WORKER))
    inputs = {PREVIOUS[0]: previous_raw, OLD_WORKER[0]: old_worker_raw,
              STREAM[0]: stream_raw, OLD_STREAM[0]: fixed(OLD_STREAM),
              WATCHER[0]: watch_raw, SCANOUT[0]: scanout_raw, PROBE[0]: probe_raw}
    original.SELF, original.CMDS, original.WORKER = SELF, CMDS, WORKER
    original.new_main = adapted_main(derived, inputs)
    original.DIAGNOSTIC_RAW += comparison.INNER_DIAGNOSTIC
    original_definitions = original.definitions

    def bound_definitions(pin, name):
        module, raw = original_definitions(pin, name)
        if pin == original.ORIGIN:
            module.READY_CAPTURE = capture
        return module, raw

    original.definitions = bound_definitions
    return original.main()


if __name__ == '__main__':
    raise SystemExit(main())
