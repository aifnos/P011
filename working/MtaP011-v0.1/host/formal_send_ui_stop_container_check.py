"""One new PC-only sender UI/guardian stop-container interface check.

Selected actual definitions only. The full UI constructor, window, sender,
guardian worker, pipe IO, ACK, audio process and device are NEVER started.
The Audio dependency and now() boundary are explicitly HOST models. The real
bind() creates the callback; report('prepare') must consume its original list.
"""
import ast
import hashlib
import io
import json
import math
import re
import subprocess
import sys
import threading
import time
import types
import unittest
import uuid
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INPUTS = (
    ('candidate/formal-send-filecenter-ui-v1/runtime/ui_session.py', 26218,
     '86793547830cad7dd74262b0611ea3b0ee63c75441efbe135fdcb687973a6d77'),
    ('candidate/formal-send-filecenter-ui-v1/runtime/ui_guardian.py', 43991,
     '27bb19a168a1ba85001a53a213acbb25f83d9d962ffba4d6ef20b99138a013d9'),
)


def selected(tree, names):
    rows = [row for row in tree.body if isinstance(row, (ast.ClassDef, ast.FunctionDef))
            and row.name in names]
    if {row.name for row in rows} != set(names):
        raise ValueError('selected_definition_missing')
    return ast.fix_missing_locations(ast.Module(body=rows, type_ignores=[]))


class StopContainerInterface(unittest.TestCase):
    def test_actual_callback_reads_retained_container(self):
        ui, guard = self.trees
        scope_class = next(row for row in ui.body if isinstance(row, ast.ClassDef)
                           and row.name == '_UiScope')
        ctor = next(row for row in scope_class.body if isinstance(row, ast.FunctionDef)
                    and row.name == '__init__')
        assignment = next(row for row in ctor.body if isinstance(row, ast.Assign) and
                          [ast.unparse(target) for target in row.targets] ==
                          ['self.stopped', 'self._stopped_original'])
        self.assertEqual(ast.dump(assignment.value), ast.dump(ast.List(
            elts=[ast.Constant(value=False)], ctx=ast.Load())))
        run = next(row for row in ui.body if isinstance(row, ast.FunctionDef)
                   and row.name == '_run_prepared')
        calls = [node for node in ast.walk(run) if isinstance(node, ast.Call) and
                 isinstance(node.func, ast.Attribute) and
                 node.func.attr == '_FileCenterGuardianChannel']
        self.assertEqual(len(calls), 1)
        self.assertEqual(ast.unparse(calls[0].args[-1]), 'scope._stopped_original')
        for function in ('_run_prepared', '_close_sender'):
            body = next(row for row in ui.body if isinstance(row, ast.FunctionDef)
                        and row.name == function)
            self.assertEqual(sum(isinstance(node, ast.Call) and
                                 isinstance(node.func, ast.Attribute) and
                                 node.func.attr == 'mark_closing'
                                 for node in ast.walk(body)), 1)
        context = dict(threading=threading, time=time, types=types, re=re,
                       sys=sys, subprocess=subprocess, math=math)
        constants = [row for row in guard.body if isinstance(row, ast.Assign) and
                     any(isinstance(target, ast.Name) and target.id in
                         ('AUDIO_MAX', 'AUDIO_WRAPPER', 'AUDIO_PROGRAMS')
                         for target in row.targets)]
        self.assertEqual(len(constants), 3)
        exec(compile(ast.fix_missing_locations(ast.Module(body=constants, type_ignores=[])),
                     '<actual-guardian-constants>', 'exec'), context)
        exec(compile(selected(guard, ('UiSessionError', 'need',
                                     '_FileCenterGuardianChannel')), '<actual-guardian>', 'exec'), context)
        closer = next(row for row in scope_class.body if isinstance(row, ast.FunctionDef)
                      and row.name == 'mark_closing')
        exec(compile(ast.fix_missing_locations(ast.Module(body=[closer], type_ignores=[])),
                     '<actual-ui-mark-closing>', 'exec'), context)
        # Explicit dependency model, not the real FileCenterAudio constructor.
        module = types.ModuleType('explicit_host_audio_dependency')
        module.GUARDIAN_WRAPPER = context['AUDIO_WRAPPER']
        exec('class FileCenterAudio:\n'
             ' def __init__(self): self.tickets=[]; self._guardian_original=None\n'
             ' def bind_guardian(self,notify): self.guardian_notify=self._guardian_original=notify\n'
             ' def _notify_guardian(self,*args): raise AssertionError("not invoked")\n'
             ' def play(self,*args): raise AssertionError("not invoked")\n'
             ' def stop_audio(self,*args): raise AssertionError("not invoked")\n'
             ' def actors_closed(self): raise AssertionError("not invoked")\n', module.__dict__)
        self.case_sequence = []
        for close in (False, True):
            scope = types.SimpleNamespace(until=600.0, cleanup_until=660.0, closing=False)
            exec(compile(ast.fix_missing_locations(ast.Module(body=[assignment], type_ignores=[])),
                         '<actual-ui-stop-assignment>', 'exec'), {'self': scope})
            original = scope._stopped_original
            audio = module.FileCenterAudio()
            companion = types.SimpleNamespace(audio=audio, state=types.SimpleNamespace(audio=audio))
            channel = context['_FileCenterGuardianChannel'](
                scope, {'fd': 17, 'metadata': ()}, {'fd': 18, 'metadata': ()}, b'',
                {'boot': 'HOST-MODEL'}, {'pid': 1}, {}, original)
            # No pipes/process/clock gate is claimed: only actual report's next
            # stop-container boundary runs. Invalid command stops before IO.
            boundary_calls = []
            channel.now = lambda cleanup=False: boundary_calls.append(cleanup) or 1.0
            channel.bind(audio, module, companion)
            self.assertIs(channel.stopped, original)
            self.assertIs(scope.stopped, original)
            ticket = dict(guardian_required=True, spawn_called=False, process=None,
                          command=(), spawn_command=(), source_fd=17)
            audio.tickets.append(ticket)
            if close:
                context['mark_closing'](scope)
                self.assertTrue(scope.closing)
                self.assertIs(channel.stopped, original)
                self.assertEqual(original, [True])
            with self.assertRaises(context['UiSessionError']) as captured:
                # Original bind-created callback, not a forged invocation receipt.
                audio.guardian_notify('prepare', ticket)
            self.assertEqual(captured.exception.code,
                             'audio_guardian_ticket' if close else 'audio_guardian_command')
            self.assertIs(channel.failure, captured.exception)
            self.assertEqual(boundary_calls, [False])
            self.assertEqual(channel.rows, [])
            self.case_sequence.append('stopped_reject' if close else 'active_container_consumed')


def main():
    destination = ROOT / 'results' / ('formal-send-ui-stop-interface-' +
        time.strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    destination.mkdir(mode=0o700)
    stdout, stderr = io.StringIO(), io.StringIO()
    report = dict(passed=False, checker_exit=1, child_exit='NOT_RUN', remote_exit='NOT_RUN',
                  device_invoked=False, old_methods=0, new_methods=1,
                  full_ui_constructor_invoked=False, sender_invoked=False,
                  guardian_worker_invoked=False, audio_process_invoked=False,
                  pipe_io_invoked=False, ack_verified=False, assets_sealed=False,
                  actual_selected_callback_interface=False,
                  dependencies='explicit HOST Audio and now-boundary models', inputs=[])
    try:
        trees = []
        for index, (path, size, sha) in enumerate(INPUTS):
            raw = (ROOT / path).read_bytes()
            if (len(raw), hashlib.sha256(raw).hexdigest()) != (size, sha):
                raise ValueError('input_pin')
            (destination / ('input-%d.py' % index)).write_bytes(raw)
            report['inputs'].append(dict(path=path, bytes=size, sha256=sha))
            trees.append(ast.parse(raw, feature_version=(3, 5)))
        StopContainerInterface.trees = trees
        case = StopContainerInterface('test_actual_callback_reads_retained_container')
        result = unittest.TextTestRunner(stream=stderr, verbosity=2).run(unittest.TestSuite([case]))
        report['case_sequence'] = getattr(case, 'case_sequence', [])
        report['passed'] = bool(result.wasSuccessful() and result.testsRun == 1 and
            report['case_sequence'] == ['active_container_consumed', 'stopped_reject'])
        report['checker_exit'] = 0 if report['passed'] else 1
        report['actual_selected_callback_interface'] = report['passed']
        for path, size, sha in INPUTS:
            raw = (ROOT / path).read_bytes()
            if (len(raw), hashlib.sha256(raw).hexdigest()) != (size, sha):
                raise ValueError('input_changed')
        report['source_preserved'] = True
    except BaseException as error:
        report['passed'], report['checker_exit'] = False, 1
        report['error_kind'] = type(error).__name__
        stderr.write(str(error) + '\n')
    (destination / 'stdout.raw').write_text(stdout.getvalue(), encoding='utf-8')
    (destination / 'stderr.raw').write_text(stderr.getvalue(), encoding='utf-8')
    result_raw = (json.dumps(report, ensure_ascii=True, sort_keys=True, indent=2)+'\n').encode('utf-8')
    readme = (b'PC ONLY: actual selected stop-container callback boundary.\n'
              b'Audio/clock dependency models; no pipe ACK, worker, RF or device.\n'
              b'Full UI remains unsealed and cannot be deployed.\n')
    (destination / 'result.json').write_bytes(result_raw)
    (destination / 'README.txt').write_bytes(readme)
    with zipfile.ZipFile(destination / 'safe.zip', 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('result.json', result_raw)
        archive.writestr('README.txt', readme)
    print(json.dumps(dict(passed=report['passed'], result=str(destination),
                          checker_exit=report['checker_exit'], device_invoked=False)))
    return report['checker_exit']


if __name__ == '__main__':
    sys.exit(main())
