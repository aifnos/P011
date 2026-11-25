# -*- coding: utf-8 -*-
"""HOST-only checks for explicit fixed-site scope; no network or device access."""
import ast
import contextlib
import io
import os
import pathlib
import sys
import unittest
from unittest import mock

RUNTIME = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RUNTIME))
import guardian
import safety


class PublicScopeTests(unittest.TestCase):
    def test_pairing_and_scope_mismatch_reject_before_launch(self):
        for offline, site, public in ((False, 'baidu', False),
                                      (False, None, True),
                                      (True, 'bilibili', True),
                                      (False, 'https://www.baidu.com/', True),
                                      (False, 'baidu --url other', True),
                                      (False, '', True)):
            with self.assertRaises(ValueError):
                safety.trial_mode(offline, site, public)
            with self.assertRaises(ValueError):
                guardian.browser_command('/fixed/bin/p011-browser-probe', '/session/app', 30,
                                         offline, site, public)
            with self.assertRaises(ValueError):
                safety.browser_environment('/candidate', '/session', 7, 'wl-shell',
                                           offline, site, public)

    def test_public_argv_only_forwards_supported_label(self):
        for site in ('baidu', 'bilibili'):
            command = guardian.browser_command('/fixed/bin/p011-browser-probe', '/session/app',
                                               30, False, site, True)
            self.assertEqual(command, ['/fixed/bin/p011-browser-probe', '--session',
                                       '/session/app', '--seconds', '30', '--public-site', site])
            self.assertNotIn('--url', command)

    def test_existing_local_mode_retains_qrc_scope_and_default_sandbox(self):
        for offline in (False, True):
            self.assertEqual(guardian.browser_command('/binary', '/session/app', 30, offline),
                             ['/binary', '--session', '/session/app', '--seconds', '30'])
            mode = safety.trial_mode(offline)
            self.assertEqual(mode, {'public_site': None, 'public_no_sandbox': False,
                                    'sandbox_enabled': not offline,
                                    'sandbox_runtime_verified': False,
                                    'offline_local_fixture_only': True})
            env = safety.browser_environment('/candidate', '/session', 7, 'wl-shell', offline)
            self.assertEqual(env.get('QTWEBENGINE_DISABLE_SANDBOX'), '1' if offline else None)

    def test_public_environment_and_metadata_use_fresh_private_profile(self):
        inherited = {'HOME': '/root', 'XDG_CONFIG_HOME': '/original/config',
                     'QTWEBENGINE_DISABLE_SANDBOX': 'evil',
                     'QTWEBENGINE_CHROMIUM_FLAGS': '--user-data-dir=/original --remote-debugging-port=9222',
                     'PRIVATE_ACCOUNT_TOKEN': 'not-in-trial', 'HTTP_PROXY': 'http://original-proxy'}
        with mock.patch.dict(os.environ, inherited):
            for site in ('baidu', 'bilibili'):
                mode = safety.trial_mode(False, site, True)
                self.assertEqual(mode, {'public_site': site, 'public_no_sandbox': True,
                                        'sandbox_enabled': False, 'sandbox_runtime_verified': False,
                                        'offline_local_fixture_only': False})
                env = safety.browser_environment('/candidate', '/new-session', 7, 'wl-shell',
                                                  False, site, True)
                self.assertEqual(env['QTWEBENGINE_DISABLE_SANDBOX'], '1')
                self.assertEqual(env['HOME'], '/new-session/app')
                for key, suffix in (('TMPDIR', 'tmp'), ('XDG_CACHE_HOME', 'cache'),
                                    ('XDG_CONFIG_HOME', 'config'), ('XDG_DATA_HOME', 'data'),
                                    ('XDG_RUNTIME_DIR', 'runtime')):
                    self.assertEqual(env[key], '/new-session/app/' + suffix)
                self.assertNotIn('PRIVATE_ACCOUNT_TOKEN', env)
                self.assertNotIn('HTTP_PROXY', env)
                self.assertNotIn('/original', ' '.join(env.values()))
                self.assertNotIn('remote-debugging', ' '.join(env.values()))

    def parse(self, extra):
        argv = ['guardian.py', '--candidate', '/candidate', '--session', '/session',
                '--baseline', '/session/baseline.py', '--uid', '65534', '--gid', '44'] + extra
        with mock.patch.object(sys, 'argv', argv), mock.patch.object(os, 'geteuid', return_value=0, create=True):
            with contextlib.redirect_stderr(io.StringIO()):
                return guardian.arguments()

    def test_cli_rejects_unpaired_mixed_and_arbitrary_url(self):
        for flags in (['--public-site', 'baidu'], ['--public-no-sandbox'],
                      ['--public-site', 'bilibili', '--public-no-sandbox', '--offline-no-sandbox'],
                      ['--public-site', 'https://www.baidu.com/', '--public-no-sandbox'],
                      ['--url', 'https://www.baidu.com/']):
            with self.assertRaises(SystemExit) as error:
                self.parse(flags)
            self.assertEqual(error.exception.code, 2)

    def test_cli_accepts_explicit_public_pair_and_root_child_still_rejects(self):
        for site in ('baidu', 'bilibili'):
            args = self.parse(['--public-site', site, '--public-no-sandbox'])
            self.assertEqual((args.public_site, args.public_no_sandbox, args.uid, args.gid),
                             (site, True, 65534, 44))
        with self.assertRaises(ValueError):
            safety.validate_child_user(0, 44)

    def test_changed_runtime_sources_keep_python35_grammar(self):
        for name in ('guardian.py', 'supervisor.py', 'safety.py'):
            ast.parse((RUNTIME / name).read_text(encoding='utf-8'), feature_version=(3, 5))


if __name__ == '__main__':
    unittest.main()
