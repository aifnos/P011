# -*- coding: utf-8 -*-
"""HOST-only safety boundary checks; never uses ADB, real /proc or signals."""
import ast
import copy
import os
import pathlib
import sys
import unittest
from unittest import mock

RUNTIME = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RUNTIME))
import safety


def proc(pid, name, parent=1, start='100', exe=None):
    return {'pid': pid, 'name': name, 'parent': parent, 'starttime': start,
            'exe': exe or '/usr/bin/' + name, 'group': pid, 'session': pid}


def baseline():
    rows = [proc(20, 'Z03', 10), proc(30, 'control_engine', 11), proc(40, 'weston')]
    for row in rows[:2]:
        row['parent_identity'] = proc(row['parent'], 'sh', exe='/bin/busybox')
    return {'schema': 'p011.browser.baseline.v1',
            'hashes': dict((path, 'a' * 64) for path in safety.HASH_PATHS),
            'processes': rows, 'boot_id': '01234567-89ab-cdef-0123-456789abcdef'}


class BaselineBoundaryTests(unittest.TestCase):
    def test_host_probe_schema_and_runtime_snapshot_match(self):
        current = baseline()
        host = copy.deepcopy(current)
        host['schema'] = 'p011.browser.readonly.v1'
        for row in host['processes']:
            parent = row.pop('parent_identity', None)
            row['comm'] = row.pop('name')
            row['ppid'] = row.pop('parent')
            row['starttime'] = int(row['starttime'])
            if parent:
                parent['comm'] = parent.pop('name')
                parent['ppid'] = parent.pop('parent')
                parent['starttime'] = int(parent['starttime'])
                row['parent'] = parent
        self.assertTrue(safety.same_stock(host, current))

    def test_pid_reuse_and_vendor_replacement_fail(self):
        for mutation in ('starttime', 'hash', 'boot'):
            changed = baseline()
            if mutation == 'starttime':
                changed['processes'][0]['starttime'] = '101'
            elif mutation == 'hash':
                changed['hashes']['/usr/bin/Z03'] = 'b' * 64
            else:
                changed['boot_id'] = '11234567-89ab-cdef-0123-456789abcdef'
            self.assertFalse(safety.same_stock(baseline(), changed))

    def test_missing_parent_duplicate_core_and_invalid_hash_reject(self):
        mutations = []
        item = baseline(); del item['processes'][0]['parent_identity']; mutations.append(item)
        item = baseline(); item['processes'].append(copy.deepcopy(item['processes'][0])); mutations.append(item)
        item = baseline(); item['hashes']['/usr/bin/Z03'] += '\n'; mutations.append(item)
        item = baseline(); item['processes'][0]['exe'] = '/tmp/Z03'; mutations.append(item)
        for item in mutations:
            with self.assertRaises(ValueError):
                safety.normalize_snapshot(item)

    def test_environment_never_inherits_sandbox_or_account_flags(self):
        with mock.patch.dict(os.environ, {'QTWEBENGINE_DISABLE_SANDBOX': '1',
                                         'PRIVATE_ACCOUNT_TOKEN': 'do-not-copy'}):
            env = safety.browser_environment('/candidate', '/session', 7, 'wl-shell')
        self.assertNotIn('QTWEBENGINE_DISABLE_SANDBOX', env)
        self.assertNotIn('PRIVATE_ACCOUNT_TOKEN', env)
        self.assertNotIn('--no-sandbox', ' '.join(env.values()))
        self.assertEqual(env['WAYLAND_SOCKET'], '7')
        self.assertTrue(env['HOME'].endswith('/app'))

    def test_offline_no_sandbox_requires_explicit_argument(self):
        env = safety.browser_environment('/candidate', '/session', 7, 'wl-shell', True)
        self.assertEqual(env['QTWEBENGINE_DISABLE_SANDBOX'], '1')
        for flag in ('--disable-background-networking', '--disable-component-update', '--disable-sync'):
            self.assertIn(flag, env['QTWEBENGINE_CHROMIUM_FLAGS'])

    def test_root_browser_and_path_injection_reject(self):
        with self.assertRaises(ValueError):
            safety.validate_child_user(0, 0)
        for suffix in ('-bad\n', '/app/../elsewhere', ''):
            with self.assertRaises(ValueError):
                safety.validate_paths('/mnt/data/p011-browser/candidates/browser-685-' + 'a' * 16 + suffix,
                                      '/mnt/data/p011-browser/sessions/20261020-101010-abcd1234/..')


class SignalBoundaryTests(unittest.TestCase):
    candidate = '/mnt/data/p011-browser/candidates/browser-685-' + 'a' * 16

    def leader(self):
        return proc(100, 'browser', 90, '1000', self.candidate + '/bin/p011-browser-probe')

    def test_reused_leader_never_signals(self):
        leader = self.leader()
        reused = dict(leader, starttime='1001')
        with mock.patch.object(safety, 'identity', return_value=reused), mock.patch.object(safety.os, 'killpg', create=True) as signal_call:
            with self.assertRaises(ValueError):
                safety.signal_owned_group(self.candidate, leader, 15)
            signal_call.assert_not_called()

    def test_unknown_group_executable_never_signals(self):
        leader = self.leader()
        unexpected = proc(101, 'Z03', 100, '1002', '/usr/bin/Z03')
        unexpected.update(group=100, session=100)
        with mock.patch.object(safety, 'identity', return_value=leader), mock.patch.object(safety, 'group_members', return_value=[unexpected]), mock.patch.object(safety.os, 'killpg', create=True) as signal_call:
            with self.assertRaises(ValueError):
                safety.signal_owned_group(self.candidate, leader, 15)
            signal_call.assert_not_called()

    def test_confirmed_private_group_signals_only_its_group(self):
        leader = self.leader()
        with mock.patch.object(safety, 'identity', return_value=leader), mock.patch.object(safety, 'group_members', return_value=[leader]), mock.patch.object(safety.os, 'killpg', create=True) as signal_call:
            observed = safety.signal_owned_group(self.candidate, leader, 15)
        signal_call.assert_called_once_with(100, 15)
        self.assertEqual(observed[0]['pid'], 100)

    def test_member_changed_between_scan_and_signal_rejects(self):
        leader = self.leader()
        changed = dict(leader, starttime='2000')
        with mock.patch.object(safety, 'identity', side_effect=[leader, changed]), mock.patch.object(safety, 'group_members', return_value=[leader]), mock.patch.object(safety.os, 'killpg', create=True) as signal_call:
            with self.assertRaises(ValueError):
                safety.signal_owned_group(self.candidate, leader, 15)
            signal_call.assert_not_called()

    def test_escaped_child_uses_pid_identity_not_its_new_group(self):
        expected = proc(101, 'helper', 100, '1100', self.candidate + '/libexec/QtWebEngineProcess')
        moved = dict(expected, parent=1, group=101, session=101)
        owner = type('Owner', (), {'st_uid': 65534})()
        with mock.patch.object(safety, 'identity', return_value=moved), mock.patch.object(safety.os, 'stat', return_value=owner), mock.patch.object(safety.os, 'kill', create=True) as signal_call:
            answer = safety.signal_owned_pid(self.candidate, expected, 65534, 15)
        signal_call.assert_called_once_with(101, 15)
        self.assertEqual(answer['parent'], 1)

    def test_escaped_child_pid_reuse_never_signals(self):
        expected = proc(101, 'helper', 100, '1100', self.candidate + '/libexec/QtWebEngineProcess')
        reused = dict(expected, starttime='1200')
        owner = type('Owner', (), {'st_uid': 65534})()
        with mock.patch.object(safety, 'identity', return_value=reused), mock.patch.object(safety.os, 'stat', return_value=owner), mock.patch.object(safety.os, 'kill', create=True) as signal_call:
            with self.assertRaises(ValueError):
                safety.signal_owned_pid(self.candidate, expected, 65534, 15)
            signal_call.assert_not_called()

    def test_observed_sets_id_child_is_tracked_by_live_parent(self):
        leader = self.leader()
        helper = proc(101, 'helper', 100, '1100', self.candidate + '/libexec/QtWebEngineProcess')
        helper.update(group=101, session=101)
        tracked = {(leader['pid'], leader['starttime'], leader['exe']): leader}
        owner = type('Owner', (), {'st_uid': 65534})()
        with mock.patch.object(safety, 'identity', return_value=leader), mock.patch.object(safety, 'private_processes', return_value=[helper]), mock.patch.object(safety.os, 'stat', return_value=owner):
            safety.track_descendants(self.candidate, leader, tracked, 65534)
        self.assertIn((101, '1100', helper['exe']), tracked)


class SourceBoundaryTests(unittest.TestCase):
    def test_sources_parse_for_python35_grammar_without_compilation_outputs(self):
        for path in RUNTIME.glob('*.py'):
            # CPython's feature_version enforces the requested old grammar. It
            # does not prove target imports or P011 syscall behavior.
            ast.parse(path.read_text(encoding='utf-8'), feature_version=(3, 5))

    def test_guardian_uses_validated_command_without_shell(self):
        source = (RUNTIME / 'guardian.py').read_text(encoding='utf-8')
        tree = ast.parse(source)
        browser_calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
                         and isinstance(node.func, ast.Attribute) and node.func.attr == 'Popen']
        self.assertEqual(len(browser_calls), 1)
        call = browser_calls[0]
        self.assertIsInstance(call.args[0], ast.Name)
        self.assertEqual(call.args[0].id, 'command')
        self.assertFalse(any(keyword.arg == 'shell' for keyword in call.keywords))


class LeaseBoundaryTests(unittest.TestCase):
    def test_existing_candidate_lease_is_never_removed_or_overwritten(self):
        candidate = '/mnt/data/p011-browser/candidates/browser-685-' + 'a' * 16
        with mock.patch.object(safety, 'control_directory'), mock.patch.object(safety.os, 'mkdir', side_effect=[OSError(17, 'exists'), OSError(17, 'exists')]), mock.patch.object(safety, 'write_new') as write, mock.patch.object(safety.os, 'rmdir') as remove:
            with self.assertRaises(OSError):
                safety.acquire_lease(candidate, '/session')
            write.assert_not_called()
            remove.assert_not_called()

    def test_changed_lease_owner_is_never_unlinked(self):
        with mock.patch.object(safety, 'control_directory'), mock.patch.object(safety, 'read_literal', return_value={'session': 'different'}), mock.patch.object(safety.os, 'unlink') as unlink, mock.patch.object(safety.os, 'rmdir') as remove:
            with self.assertRaises(ValueError):
                safety.release_lease('/lease', {'session': 'ours'})
            unlink.assert_not_called()
            remove.assert_not_called()


if __name__ == '__main__':
    unittest.main()
