"""One new Linux-root HOST filesystem method, actual frozen FixedStage.

Normal branches use real Linux /tmp, uid/gid, permissions, flags, directory
FDs, monotonic clock and syscalls. Only named adversarial cases use FaultOS;
all non-fault methods still delegate to real os. No platform/aliases/parents/
service_parents/stage, Boot, Owner, payload import/exec, helper, RF or target.
"""
import errno
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import threading
import time
import unittest


BASE = Path(__file__).resolve().parents[1]
STAGE = 'candidate/formal-send-stage-v1/runtime/formal_send_stage.py'
STAGE_PIN = (37382, 'cdb73ecb883ee72a3cb8e45726987b3da2fc7d92fe1cb8c73a0b2de82f743806')
CATALOGS = (
    ('candidate/formal-send-v1/assets/ordinary-source-manifest.json',
     18219, '0aff3d932addb257962cb1aa89857784ddaaec945d34ee75c43e95fab15d2fb1'),
    ('candidate/formal-send-v1/assets/asset-sources.json',
     23552, '27366f2510d07f2dd74eb65533c314f48d7b437bb574744c57203e28746a076a'),
    ('candidate/formal-send-v1/assets/sender-source-manifest.json',
     3677, 'be67d8cec589b4e54235d8205660a67f02a188f23e99251bf2219b35b147f3d5'),
)
TOTALS = (('sender', 27, 2402458), ('observer', 41, 1440449), ('ordinary', 37, 1266713))
CASES = (
    'real_linux_root_flags_without_arm_platform_claim',
    'actual_constructor_context_clock_and_original_profile',
    'sender27_actual_write_readback_and_complete_readonly_recheck',
    'observer41_actual_write_readback_and_complete_readonly_recheck',
    'ordinary37_actual_write_readback_and_complete_readonly_recheck',
    'absent_inventory_inspect_does_not_create',
    'partial_inventory_refused_without_overwrite_or_clear',
    'exclusive_existing_file_refused_bytes_unchanged',
    'nofollow_file_symlink_refused_target_unchanged',
    'nofollow_directory_symlink_refused',
    'changed_directory_edge_refused_original_fd_retained',
    'created_child_metadata_changes_do_not_replace_held_identity',
    'fault_tail_file_metadata_change_is_refused',
    'fault_final_inventory_new_child_is_refused',
    'fault_fstat_unknown_fd_not_closed_by_stager',
    'fault_duplicate_open_fd_marks_both_unknown_without_close',
    'expired_original_deadline_still_closes_known_fds_and_proves_ebadf',
    'changed_row_fd_never_closes_foreign_or_original_descriptor',
    'actual_enoent_no_fd_receipt_and_close_are_bounded',
    'fixed_input_bytes_preserved_and_no_runtime_admission',
)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def read_fixed(name, pin):
    if not isinstance(name, str) or name.startswith(('/', '\\')) or '..' in name.split('/'):
        raise ValueError('fixed_source_path')
    raw = (BASE / name).read_bytes()
    if (len(raw), digest(raw)) != pin:
        raise ValueError('fixed_source_pin')
    return raw


def actual_source():
    raw = read_fixed(STAGE, STAGE_PIN)
    namespace = dict(__name__='formal_send_stage_linux_host_definitions', __file__=str(BASE / STAGE))
    # Entire frozen definitions load, but main's __name__ guard is false. All
    # asset payloads below remain opaque bytes; no asset code/native executes.
    exec(compile(raw, STAGE, 'exec'), namespace)
    return namespace, raw


def payloads(namespace):
    originals = {STAGE:read_fixed(STAGE, STAGE_PIN)}
    catalogs = []
    for path, size, sha in CATALOGS:
        raw = read_fixed(path, (size, sha))
        originals[path] = raw
        catalogs.append(json.loads(raw))
    ordinary, assets, sender_manifest = catalogs
    if (ordinary['source_count'] != 32 or len(ordinary['sources']) != 32 or
            len(ordinary['startup_sources']) != 3 or len(ordinary['helper_sources']) != 3 or
            assets['sender_source_count'] != 25 or len(assets['sender_sources']) != 25 or
            assets['observer_source_count'] != 41 or len(assets['observer_sources']) != 41 or
            sender_manifest['sources'] != [[row['module'], row['bytes'], row['sha256']]
                                           for row in assets['sender_sources']]):
        raise ValueError('fixed_catalog_shape')
    groups = (
        ('sender', assets['sender_root'],
         assets['sender_sources'] + [assets['sender_manifest'], assets['wpa']]),
        ('observer', assets['observer_root'], assets['observer_sources']),
        ('ordinary', '/var/volatile/tmp/p011-mta-formal-send-v1',
         [row for row in ordinary['sources'] if not row['reused_sender_asset']] +
         ordinary['startup_sources'] + ordinary['helper_sources']),
    )
    found = {}
    for group, spec, total in zip(groups, namespace['PROFILE_FILES'], TOTALS):
        profile, root, rows = group
        pins, raws = [], []
        for row in rows:
            target = row.get('physical_target', row['target'])
            if not target.startswith(root + '/'):
                raise ValueError('fixed_target')
            relative = target[len(root) + 1:]
            mode = row.get('mode', '0400')
            mode = int(mode, 8) if type(mode) is str else mode
            pin = (relative, row['bytes'], row['sha256'], mode)
            raw = read_fixed(row['source'], pin[1:3])
            if row['source'] in originals and originals[row['source']] != raw:
                raise ValueError('fixed_source_changed')
            originals[row['source']] = raw
            pins.append(pin); raws.append(raw)
        if ((profile, root, tuple(pins)) != spec or profile != total[0] or
                len(pins) != total[1] or sum(pin[1] for pin in pins) != total[2] or
                not 0 < total[2] <= namespace['RAW_LIMIT']):
            raise ValueError('fixed_profile_mapping')
        found[profile] = tuple(raws)
    if namespace['PROFILE_TOTALS'] != TOTALS or namespace['MAX_SECONDS'] != 120.0:
        raise ValueError('fixed_batch_budget')
    return found, originals


class FaultOS:
    """Named one-operation adversary; all other methods are real os delegates.

    Unknown-fstat and duplicate-open are fault injections, not normal Linux
    return behavior. Real unknown descriptors are retained by the outer HOST
    owner, never falsely closed by the stager.
    """
    def __init__(self, action, trigger, owner):
        self.action, self.trigger, self.owner = action, trigger, owner
        self.called = False
        self.listdir_count = 0
        self.unknown_target = None
    def __getattr__(self, name): return getattr(os, name)
    def open(self, *args, **kwargs):
        if self.action == 'duplicate_open' and not self.called:
            self.called = True
            return self.trigger
        fd = os.open(*args, **kwargs)
        if self.action == 'unknown_fstat':
            self.owner.retain_external_fd(fd)
            self.unknown_target = fd
        return fd
    def fstat(self, fd):
        if self.action == 'unknown_fstat' and fd == self.unknown_target and not self.called:
            self.called = True
            raise OSError(errno.EIO, 'HOST_named_unknown_fstat_fault')
        return os.fstat(fd)
    def listdir(self, fd):
        value = os.listdir(fd)
        self.listdir_count += 1
        if self.action in ('tail_metadata', 'tail_child') and self.listdir_count == 3:
            self.called = True
            self.trigger()
        return value


class HostPrivateTree:
    """External owner of only this newly created Linux temp and known FDs."""
    def __init__(self, namespace):
        self.namespace, self.stages, self.external_fds = namespace, [], []
        self.path = Path(tempfile.mkdtemp(prefix='p011-formal-send-stage-host-', dir='/tmp'))
        self.original = namespace['meta'](os.lstat(str(self.path)))
        if (self.path.parent != Path('/tmp') or not self.path.name.startswith('p011-formal-send-stage-host-') or
                self.original[2] != stat.S_IFDIR | 0o700 or self.original[3:5] != (0, 0)):
            raise ValueError('HOST_private_temp_policy')
        self.sequence = 0
        self.closed = False
    def fixture(self, profile='sender', seconds=120.0):
        self.sequence += 1
        casepath = self.path / ('case-' + str(self.sequence))
        os.mkdir(str(casepath), 0o700)
        until = time.monotonic() + seconds
        stage = self.namespace['FixedStage'](profile, until)
        self.stages.append(stage)  # Original production inventory stays held.
        stage.tmp = stage.directory(None, str(casepath), 0o700)
        return stage, casepath
    def retain_external_fd(self, fd):
        current = self.namespace['meta'](os.fstat(fd))
        if any(row['fd'] == fd and not row['closed'] for row in self.external_fds):
            return
        self.external_fds.append(dict(fd=fd, identity=self.namespace['identity'](current), closed=False))
    def close(self):
        if self.closed: return
        self.namespace['os'] = os
        for stage in reversed(self.stages):
            stage.close()  # Unknown rows remain unknown; never clear originals.
        for row in self.external_fds:
            if row['closed']: continue
            current = self.namespace['meta'](os.fstat(row['fd']))
            if self.namespace['identity'](current) != row['identity']:
                raise ValueError('HOST_external_fd_identity_changed')
            os.close(row['fd'])
            try:
                os.fstat(row['fd'])
            except OSError as error:
                if error.errno != errno.EBADF: raise
                row['closed'] = True
            if not row['closed']: raise ValueError('HOST_external_fd_close_pending')
        # No user/input directory is ever a deletion target. Resolve and check
        # this exact /tmp child and its held identity before recursive cleanup.
        if (self.path.resolve() != self.path or self.path.parent != Path('/tmp') or
                self.namespace['identity'](self.namespace['meta'](os.lstat(str(self.path)))) !=
                self.namespace['identity'](self.original)):
            raise ValueError('HOST_private_temp_identity_changed')
        shutil.rmtree(str(self.path))
        self.closed = not self.path.exists()
        if not self.closed: raise ValueError('HOST_private_temp_cleanup_pending')


class LinuxStageTests(unittest.TestCase):
    def test_new_actual_linux_file_io(self):
        ns, stage_raw = actual_source()
        fixed_payloads, source_originals = payloads(ns)
        seen = []
        def case(name, callback):
            with self.subTest(contract=name): callback()
            seen.append(name)
            print('HOST_SEND_STAGE_LINUX_CASE=' + name)

        def environment():
            self.assertEqual(sys.platform, 'linux')
            self.assertEqual(os.uname().machine, 'x86_64')
            self.assertEqual(os.geteuid(), 0); self.assertEqual(os.getegid(), 0)
            self.assertIn(os.open, os.supports_dir_fd)
            self.assertIn(os.listdir, os.supports_fd)
            self.assertNotEqual(os.O_NOFOLLOW, 0x8000)  # Do not counterfeit ARM.
            self.assertEqual(os.O_NOFOLLOW, 131072)
            self.assertEqual(os.O_CLOEXEC, 524288)
            facts = dict(platform=sys.platform, machine=os.uname().machine,
                python=list(sys.version_info[:3]), euid=os.geteuid(), egid=os.getegid(),
                nofollow=os.O_NOFOLLOW, cloexec=os.O_CLOEXEC,
                arm_platform_checked=False, platform_method_called=False)
            print('LINUX_STAGE_ENV=' + json.dumps(facts, sort_keys=True))
        case(CASES[0], environment)
        # Abort rather than silently run permissions/FS cases as a different uid.
        if sys.platform != 'linux' or os.geteuid() != 0 or os.getegid() != 0:
            raise ValueError('actual_Linux_root_required')
        tree = HostPrivateTree(ns)
        try:
            def ctor():
                stage, path = tree.fixture()
                original = stage.spec
                stage.context()
                now = stage.now()
                self.assertIs(stage.clock, time.monotonic)
                self.assertIs(stage.worker, threading.current_thread())
                self.assertIs(stage.spec, ns['PROFILE_FILES'][0])
                self.assertIs(stage.spec, original)
                self.assertLessEqual(stage.until - now, 120.0)
                self.assertFalse(stage.called); self.assertFalse(stage.complete)
                self.assertEqual(stage.names(stage.tmp), ())
                self.assertIsNone(stage.present(stage.tmp, 'not-present'))
                self.assertTrue(stage.close())
            case(CASES[1], ctor)

            def complete_profile(profile, count):
                stage, path = tree.fixture(profile)
                spec = stage.spec
                root = stage.create_directory(stage.tmp, spec[1].rsplit('/', 1)[1])
                directories = {'':root}
                expected = stage.tree_names(spec[2])
                for child in ('runtime', 'native'):
                    if child in expected:
                        directories[child] = stage.create_directory(root, child)
                for pin, raw in zip(spec[2], fixed_payloads[profile]):
                    parent, _, basename = pin[0].rpartition('/')
                    stage.write_file(directories[parent], basename, pin, raw)
                self.assertEqual(stage.created_files, count)
                self.assertTrue(all(row['metadata'][3:5] == (0, 0) for row in stage.rows if row['returned']))
                before = {pin[0]:ns['meta'](os.stat(str(path / spec[1].rsplit('/', 1)[1] / pin[0]),
                    follow_symlinks=False)) for pin in spec[2]}
                first = stage.inspect(spec)
                second = stage.inspect(spec)
                self.assertEqual(first, second)
                self.assertEqual(len(first[2]), count)
                self.assertIs(stage.spec, spec)
                self.assertEqual(stage.created_files, count)
                for pin in spec[2]:
                    current = ns['meta'](os.stat(str(path / spec[1].rsplit('/', 1)[1] / pin[0]),
                        follow_symlinks=False))
                    self.assertEqual(current, before[pin[0]])
                    self.assertEqual(current[2], stat.S_IFREG | pin[3])
                stage.edges_current()
                self.assertTrue(stage.close())
                self.assertTrue(all(row['closed'] and not row['unknown'] for row in stage.rows))
                self.assertTrue(all(row['ebadf'] for row in stage.rows if row['returned']))
                self.assertFalse(stage.complete)  # Never call production stage().
            case(CASES[2], lambda:complete_profile('sender', 27))
            case(CASES[3], lambda:complete_profile('observer', 41))
            case(CASES[4], lambda:complete_profile('ordinary', 37))

            def absent():
                stage, path = tree.fixture()
                self.assertIsNone(stage.inspect(stage.spec))
                self.assertEqual(stage.names(stage.tmp), ())
                self.assertEqual(stage.created_files + stage.created_directories, 0)
                self.assertTrue(stage.close())
            case(CASES[5], absent)

            def partial():
                stage, path = tree.fixture()
                root = stage.create_directory(stage.tmp, stage.spec[1].rsplit('/', 1)[1])
                actualpath = path / root['name']
                before = ns['meta'](os.stat(str(actualpath), follow_symlinks=False))
                with self.assertRaisesRegex(ValueError, 'existing_conflict'):
                    stage.inspect(stage.spec)
                self.assertEqual(os.listdir(str(actualpath)), [])
                self.assertEqual(ns['meta'](os.stat(str(actualpath), follow_symlinks=False)), before)
                self.assertEqual(stage.created_directories, 1)
                self.assertTrue(stage.close())
                self.assertTrue(actualpath.exists())  # Framework removes only later.
            case(CASES[6], partial)

            def low_file(stage, name, raw=b'HOST-low-level-opaque-data'):
                pin = (name, len(raw), digest(raw), 0o400)
                stage.write_file(stage.tmp, name, pin, raw)
                return pin, raw

            def exclusive():
                stage, path = tree.fixture(); pin, raw = low_file(stage, 'same.bin')
                before = ns['meta'](os.stat(str(path / 'same.bin'), follow_symlinks=False))
                with self.assertRaises(OSError) as failure:
                    stage.write_file(stage.tmp, 'same.bin', pin, b'HOST-cannot-overwrite')
                self.assertEqual(failure.exception.errno, errno.EEXIST)
                self.assertEqual((path / 'same.bin').read_bytes(), raw)
                self.assertEqual(ns['meta'](os.stat(str(path / 'same.bin'), follow_symlinks=False)), before)
                self.assertIsNotNone(stage.creations[-1]['error'])
                self.assertFalse(stage.close())  # Unknown creation remains pending.
                self.assertTrue(stage.creations[-1]['unknown'])
            case(CASES[7], exclusive)

            def symlink_file():
                stage, path = tree.fixture(); pin, raw = low_file(stage, 'target.bin')
                os.symlink('target.bin', 'link.bin', dir_fd=stage.tmp['fd'])
                with self.assertRaises(OSError) as failure:
                    stage.open_row(stage.tmp, 'link.bin', os.O_RDONLY, 0o400, 'file')
                self.assertEqual(failure.exception.errno, errno.ELOOP)
                self.assertEqual((path / 'target.bin').read_bytes(), raw)
                refused = stage.rows[-1]
                self.assertTrue(refused['no_fd']); self.assertFalse(refused['unknown'])
                self.assertTrue(stage.close())
            case(CASES[8], symlink_file)

            def symlink_directory():
                stage, path = tree.fixture()
                stage.create_directory(stage.tmp, 'real')
                os.symlink('real', 'link', dir_fd=stage.tmp['fd'])
                with self.assertRaisesRegex(ValueError, 'directory_policy'):
                    stage.directory(stage.tmp, 'link', 0o700)
                self.assertTrue(stage.close())
            case(CASES[9], symlink_directory)

            def edge_changed():
                stage, path = tree.fixture()
                row = stage.create_directory(stage.tmp, 'child')
                original_fd, original_identity = row['fd'], row['original_identity']
                os.rename('child', 'original-child', src_dir_fd=stage.tmp['fd'], dst_dir_fd=stage.tmp['fd'])
                os.mkdir('child', 0o700, dir_fd=stage.tmp['fd'])
                with self.assertRaisesRegex(ValueError, 'directory_changed'): stage.edges_current()
                self.assertEqual(ns['identity'](ns['meta'](os.fstat(original_fd))), original_identity)
                self.assertTrue(stage.close())
            case(CASES[10], edge_changed)

            def directory_metadata():
                stage, path = tree.fixture()
                original = stage.tmp['original_identity']
                before = ns['meta'](os.fstat(stage.tmp['fd']))
                stage.create_directory(stage.tmp, 'new-child')
                after = ns['meta'](os.fstat(stage.tmp['fd']))
                self.assertNotEqual(before, after)
                self.assertEqual(ns['identity'](after), original)
                stage.edges_current()
                self.assertEqual(stage.names(stage.tmp), ('new-child',))
                self.assertTrue(stage.close())
            case(CASES[11], directory_metadata)

            def small_inventory():
                stage, path = tree.fixture()
                root = stage.create_directory(stage.tmp, stage.spec[1].rsplit('/', 1)[1])
                runtime = stage.create_directory(root, 'runtime')
                pins = []
                for name, raw in (('a.bin',b'HOST-tail-first'), ('b.bin',b'HOST-tail-last')):
                    pin = ('runtime/' + name, len(raw), digest(raw), 0o400)
                    stage.write_file(runtime, name, pin, raw)
                    pins.append(pin)
                # Low-level inspect pins only; stage.spec/PROFILE_FILES remain
                # the unchanged real sender profile. Full105 tested above.
                low_spec = (stage.profile, stage.spec[1], tuple(pins))
                return stage, path, runtime, low_spec

            def tail_metadata():
                stage, path, runtime, low_spec = small_inventory()
                before = os.stat('a.bin', dir_fd=runtime['fd'], follow_symlinks=False)
                def change():
                    os.utime('a.bin', ns=(before.st_atime_ns, before.st_mtime_ns + 1000000000),
                        dir_fd=runtime['fd'], follow_symlinks=False)
                proxy = FaultOS('tail_metadata', change, tree)
                ns['os'] = proxy
                try:
                    with self.assertRaisesRegex(ValueError, 'file_changed'): stage.inspect(low_spec)
                    self.assertTrue(proxy.called)
                finally: ns['os'] = os
                self.assertTrue(stage.close())
            case(CASES[12], tail_metadata)

            def tail_child():
                stage, path, runtime, low_spec = small_inventory()
                def change(): os.mkdir('extra', 0o700, dir_fd=runtime['fd'])
                proxy = FaultOS('tail_child', change, tree)
                ns['os'] = proxy
                try:
                    with self.assertRaisesRegex(ValueError, 'existing_changed'): stage.inspect(low_spec)
                    self.assertTrue(proxy.called)
                finally: ns['os'] = os
                self.assertIn('extra', os.listdir(runtime['fd']))
                self.assertTrue(stage.close())
            case(CASES[13], tail_child)

            def unknown_fstat():
                stage, path = tree.fixture(); low_file(stage, 'unknown.bin')
                proxy = FaultOS('unknown_fstat', None, tree)
                ns['os'] = proxy
                try:
                    with self.assertRaises(OSError) as failure:
                        stage.open_row(stage.tmp, 'unknown.bin', os.O_RDONLY, 0o400, 'file')
                    self.assertEqual(failure.exception.errno, errno.EIO)
                finally: ns['os'] = os
                row = stage.rows[-1]
                self.assertTrue(row['unknown']); self.assertTrue(row['returned'])
                self.assertIs(row['failure'], failure.exception)
                self.assertIsNone(row['original_identity'])
                self.assertFalse(stage.close())
                self.assertFalse(row['close_called']); self.assertFalse(row['closed'])
                self.assertTrue(stat.S_ISREG(os.fstat(row['original_fd']).st_mode))
            case(CASES[14], unknown_fstat)

            def collision():
                stage, path = tree.fixture(); low_file(stage, 'duplicate.bin')
                original = stage.open_row(stage.tmp, 'duplicate.bin', os.O_RDONLY, 0o400, 'file')
                tree.retain_external_fd(original['fd'])
                proxy = FaultOS('duplicate_open', original['fd'], tree)
                ns['os'] = proxy
                try:
                    with self.assertRaisesRegex(ValueError, 'descriptor_unknown'):
                        stage.open_row(stage.tmp, 'duplicate.bin', os.O_RDONLY, 0o400, 'file')
                finally: ns['os'] = os
                added = stage.rows[-1]
                self.assertTrue(original['unknown']); self.assertTrue(added['unknown'])
                self.assertIs(original['failure'], added['failure'])
                self.assertFalse(stage.close())
                self.assertFalse(original['close_called']); self.assertFalse(added['close_called'])
                self.assertTrue(stat.S_ISREG(os.fstat(original['fd']).st_mode))
            case(CASES[15], collision)

            def expired():
                stage, path = tree.fixture(seconds=0.5)
                row = stage.open_row(stage.tmp, 'held.bin', os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o400, 'file')
                until = stage.until
                while time.monotonic() < until: pass  # <=0.5 s real clock; no renewal.
                with self.assertRaisesRegex(ValueError, 'deadline'): stage.now()
                self.assertIs(stage.until, until)
                self.assertTrue(stage.close())
                self.assertTrue(row['ebadf']); self.assertTrue(row['closed'])
                with self.assertRaises(OSError) as failure: os.fstat(row['original_fd'])
                self.assertEqual(failure.exception.errno, errno.EBADF)
            case(CASES[16], expired)

            def changed_fd():
                stage, path = tree.fixture(); low_file(stage, 'one.bin'); low_file(stage, 'two.bin')
                row = stage.open_row(stage.tmp, 'one.bin', os.O_RDONLY, 0o400, 'file')
                original_fd = row['fd']; tree.retain_external_fd(original_fd)
                foreign_fd = os.open(str(path / 'two.bin'), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
                tree.retain_external_fd(foreign_fd)
                row['fd'] = foreign_fd  # Explicit changed-inventory fault, not an admission.
                self.assertFalse(stage.close_row(row)); self.assertFalse(row['close_called'])
                self.assertFalse(stage.close())
                self.assertTrue(stat.S_ISREG(os.fstat(original_fd).st_mode))
                self.assertTrue(stat.S_ISREG(os.fstat(foreign_fd).st_mode))
            case(CASES[17], changed_fd)

            def no_fd():
                stage, path = tree.fixture()
                with self.assertRaises(OSError) as failure:
                    stage.open_row(stage.tmp, 'absent.bin', os.O_RDONLY, 0o400, 'file')
                self.assertEqual(failure.exception.errno, errno.ENOENT)
                row = stage.rows[-1]
                self.assertTrue(row['no_fd']); self.assertTrue(row['closed'])
                self.assertFalse(row['unknown']); self.assertIsNone(row['fd'])
                self.assertTrue(stage.close_row(row)); self.assertTrue(stage.close())
            case(CASES[18], no_fd)

            def unchanged():
                self.assertEqual(read_fixed(STAGE, STAGE_PIN), stage_raw)
                for name, raw in source_originals.items():
                    self.assertEqual((BASE / name).read_bytes(), raw)
                for stage in tree.stages:
                    self.assertIs(stage.spec, stage._spec_original)
                    self.assertIs(stage.clock, time.monotonic)
                    self.assertFalse(stage.called); self.assertFalse(stage.complete)
                    self.assertIsNone(stage.raws); self.assertEqual(stage.service_parent_facts, [])
                self.assertEqual(len(source_originals), 88)
                print('LINUX_STAGE_FIXED_PAYLOAD_ROWS=105')
                print('LINUX_STAGE_FIXED_PROFILE_FILES=27,41,37')
            case(CASES[19], unchanged)
        finally:
            tree.close()
        self.assertTrue(tree.closed)
        self.assertTrue(all(row['closed'] for row in tree.external_fds))
        self.assertEqual(tuple(seen), CASES)
        print('SEND_STAGE_LINUX_CONTRACTS=' + str(len(seen)))


if __name__ == '__main__':
    result = unittest.main(exit=False).result
    child_exit = 0 if result.wasSuccessful() else 1
    print('LINUX_STAGE_CHILD_EXIT=' + str(child_exit))
    raise SystemExit(child_exit)
