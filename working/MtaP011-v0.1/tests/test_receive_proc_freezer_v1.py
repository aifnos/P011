"""One affected HOST method: actual v25/new Proc and Store budget over FakeFs.

Only frozen module definitions and the original FakeFs/metadata/stat helpers
are reused. No previous test method, historical checker main, production
collector, Owner, RF, device, phone, permission or restoration is executed.
"""
from contextlib import ExitStack
import ast
import builtins
import errno
import hashlib
import json
from pathlib import Path
import stat
import sys
import types
import unittest
from unittest import mock


BASE = Path(__file__).resolve().parents[1]
GENERATOR = ('candidate/receive-proc-freezer-v1/generate_proc.py', 8164,
             'c9e725dc092436a7c8fd82d84e38954dabac7cbf1571b2c736fd53fce55faad1')
MANIFEST = ('host/client_proc_history_v24_source_manifest.json', 6940,
            'dcfab972fed81b1a63bafe1a8cae6a2681d2c83d3e666bf10a827c2c7b36f70e')
V25_FIXTURE = ('tests/test_client_proc_absolute_deadline_v25.py', 18536,
               '2852349973865d3a2b09bbd4ac51862d651429a1e31bbcb363e125669b0a61b4')
FS_FIXTURE = ('tests/test_client_proc.py', 35215,
              'fad1f4e86dd7cb6f17f8254865b75cc9389d19f89aefd8332de9ccc8d1c9c6bc')
ORIGINAL = ('candidate/client-proc-deadline-v25/runtime/mta_client_proc.py', 39384,
            'ede5953c33ba4c17d3aecb1fffe8a9358589497b37e3109034d5e1de3eadb3d6')
# Root actually generated and read back these three artifacts before binding.
GENERATED = (
    ('candidate/receive-proc-freezer-v1/runtime/mta_client_proc.py', 39398,
     '2894a8ffb1e361bd1f4785e6da2b0df9e5ee8bff7711e21ee745ae3cd1f9653d'),
    ('candidate/receive-proc-freezer-v1/proc-exactsource-delta.json', 1512,
     '0f047d009c25e068b7e260a53543273cc0ef83233f2f69eebccabbcc32088fc0'),
    ('candidate/receive-proc-freezer-v1/proc-generation.json', 1446,
     'ba1887f08a17f6a04e02a8256719fadb40c2900fc63dbdc243f1cc00753304ad'),
)
MASK = 0x40000000
SELECTOR = 'ReceiveProcFreezerV1Contract.test_actual_reader_single_dynamic_bit_all_identity_paths_and_closed_inventory'
MARKER = 'RECEIVE_PROC_FREEZER_V1_HOST_PASS methods=1 old_methods=0 actual_proc=true actual_budget=true fakefs=true'


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def fixed(row):
    relative, count, expected = row
    path = Path(relative)
    if path.is_absolute() or '..' in path.parts:
        raise ValueError('fixed_relative_source')
    raw = (BASE / relative).read_bytes()
    if (len(raw), digest(raw)) != (count, expected):
        raise ValueError('fixed_source_pin:' + relative)
    return raw


def generator_definitions():
    raw = fixed(GENERATOR)
    tree = ast.parse(raw.decode('ascii'))
    allowed = (ast.Import, ast.ImportFrom, ast.Assign, ast.FunctionDef)
    # Keep only imports, literal/source assignments and functions, never main/if.
    nodes = [node for node in tree.body if isinstance(node, allowed) and
             not (isinstance(node, ast.FunctionDef) and node.name == 'main')]
    namespace = types.ModuleType('freezer_generator_definitions')
    namespace.__file__ = str(BASE / GENERATOR[0])
    exec(compile(ast.Module(body=nodes, type_ignores=[]), namespace.__file__, 'exec'), namespace.__dict__)
    if namespace.SOURCE != ORIGINAL or namespace.BEFORE != '        return self.pid, self.start, self.comm, self.flags, self.ppid\n' or namespace.AFTER != '        return self.pid, self.start, self.comm, self.flags & ~0x40000000, self.ppid\n':
        raise ValueError('single_exact_business_delta')
    return namespace


def input_rows():
    """Pure pinned metadata selection; no old fixture main/domain/test runs."""
    raw = fixed(V25_FIXTURE)
    tree = ast.parse(raw.decode('ascii'))
    assignments = [node for node in tree.body if isinstance(node, ast.Assign) and
                   any(isinstance(target, ast.Name) and target.id == 'REPLACEMENTS' for target in node.targets)]
    if len(assignments) != 1:
        raise ValueError('v25_replacement_data')
    replacements = ast.literal_eval(assignments[0].value)
    if type(replacements) is not dict or set(replacements) != {
            'mta_client_proc', 'mta_client_baseline', 'mta_client_wpa_status', 'mta_client_linux_provider'}:
        raise ValueError('v25_actual_graph_shape')
    manifest = json.loads(fixed(MANIFEST).decode('ascii'))
    rows = manifest['sources']
    if type(rows) is not list or len(rows) != 29 or len({row['module'] for row in rows}) != 29:
        raise ValueError('actual_graph29')
    result = {}
    for row in rows:
        name = row['module']
        if name in replacements:
            expected, count = replacements[name]
            relative = 'candidate/client-proc-deadline-v25/runtime/' + name + '.py'
        else:
            relative, count, expected = row['path'], row['bytes'], row['sha256']
        result[relative] = (relative, count, expected)
    if result.get(ORIGINAL[0]) != ORIGINAL:
        raise ValueError('v25_actual_proc_pin')
    for row in (GENERATOR, MANIFEST, V25_FIXTURE, FS_FIXTURE) + GENERATED:
        result[row[0]] = row
    return tuple(result[key] for key in sorted(result))


def retained_sources():
    return {row[0]: fixed(row) for row in input_rows()}


def blocked(stack):
    for name in ('socket.socket', 'socket.create_connection', 'subprocess.Popen',
            'ctypes.CDLL', 'os.open', 'os.read', 'os.close', 'os.fstat', 'os.lstat',
            'os.listdir', 'os.readlink', 'os.getpid', 'os.fork', 'os.execve',
            'os.kill', 'os.waitpid', 'os.system', 'threading.Thread.start', 'time.sleep'):
        stack.enter_context(mock.patch(name, side_effect=AssertionError('actual OS/RF forbidden'), create=True))


def domain(sources, candidate):
    """Actual frozen v25 graph definitions; only Proc differs in new domain."""
    rows = json.loads(sources[MANIFEST[0]].decode('ascii'))['sources']
    replacement_tree = ast.parse(sources[V25_FIXTURE[0]].decode('ascii'))
    replacement_node = next(node for node in replacement_tree.body if isinstance(node, ast.Assign) and
                            any(isinstance(target, ast.Name) and target.id == 'REPLACEMENTS' for target in node.targets))
    replacements = ast.literal_eval(replacement_node.value)
    modules, real_import = {}, builtins.__import__
    def private_import(name, *args, **kwargs):
        if name.startswith(('mta_', 'p011_')):
            if name not in modules:
                raise ImportError('private actual module unavailable')
            return modules[name]
        return real_import(name, *args, **kwargs)
    for row in rows:
        name = row['module']
        relative = ('candidate/client-proc-deadline-v25/runtime/' + name + '.py'
                    if name in replacements else row['path'])
        if name == 'mta_client_proc' and candidate:
            relative = GENERATED[0][0]
        raw = sources[relative]
        tree = ast.parse(raw.decode('ascii'), feature_version=(3, 5))
        if any(isinstance(node, ast.Assert) for node in ast.walk(tree)):
            raise ValueError('target_assert_forbidden')
        module = types.ModuleType(name)
        module.__file__ = str(BASE / relative)
        module.__dict__['__builtins__'] = dict(vars(builtins), __import__=private_import)
        modules[name] = module
        exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    return modules


def filesystem_definitions(raw, core):
    """Original fixture DATA/functions/FakeFs only; no unittest class/method."""
    tree = ast.parse(raw.decode('ascii'))
    names = {'stat_data', 'meta', 'expected', 'FakeFs'}
    nodes = [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in names or
             isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id in ('BOOT', 'BOOT_PATH') for target in node.targets)]
    if {node.name for node in nodes if isinstance(node, (ast.FunctionDef, ast.ClassDef))} != names:
        raise ValueError('original_fakefs_definitions')
    module = types.ModuleType('original_fakefs_definitions')
    module.__dict__.update(errno=errno, stat=stat, types=types, hashlib=hashlib, c=core)
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(BASE / FS_FIXTURE[0]), 'exec'), module.__dict__)
    return module


class Clock:
    def __init__(self):
        self.value = 1.0
    def __call__(self):
        return self.value


class ReceiveProcFreezerV1Contract(unittest.TestCase):
    def test_actual_reader_single_dynamic_bit_all_identity_paths_and_closed_inventory(self):
        generated = generator_definitions()
        actual = generated.generated_inputs()
        sources = retained_sources()
        self.assertEqual(sources[ORIGINAL[0]], actual[ORIGINAL[0]])
        self.assertEqual(sources[GENERATED[0][0]], actual[GENERATED[0][0]])
        self.assertEqual(generated.build(sources[ORIGINAL[0]]), sources[GENERATED[0][0]])
        cases = []
        with ExitStack() as stack:
            blocked(stack)
            old, new = domain(sources, False), domain(sources, True)
            p = new['mta_client_proc']
            fixture = filesystem_definitions(sources[FS_FIXTURE[0]], new['mta_p2p_client_init'])
            # Pure actual parser/key edge matrix: only this bit is normalized.
            for base in (0, 1, p.PF_KTHREAD, 0x80000000, 0xbfffffff):
                plain = p.parse_stat(fixture.stat_data(flags=base), 42)
                skipped = p.parse_stat(fixture.stat_data(flags=base | MASK), 42)
                before = (plain.flags, skipped.flags)
                self.assertEqual(plain.stable_key(), skipped.stable_key())
                self.assertEqual(before, (plain.flags, skipped.flags))
                self.assertEqual(base, plain.stable_key()[3])
            plain = p.parse_stat(fixture.stat_data(flags=0), 42)
            for bit in range(32):
                if bit == 30:
                    continue
                changed = p.parse_stat(fixture.stat_data(flags=MASK | (1 << bit)), 42)
                self.assertNotEqual(plain.stable_key(), changed.stable_key())
                self.assertEqual(1 << bit, changed.stable_key()[3])
                self.assertEqual(MASK | (1 << bit), changed.flags)
            for name, value in (('pid', 43), ('start', 101), ('comm', b'changed'), ('ppid', 2)):
                changed = plain._replace(**{name: value, 'flags': MASK})
                self.assertNotEqual(plain.stable_key(), changed.stable_key())
            for raw in (fixture.stat_data(flags=-1), fixture.stat_data(flags=1 << 32)):
                with self.assertRaises(p.ProcReadError):
                    p.parse_stat(raw, 42)
            self.assertEqual(120, p.StatIdentity.stable_key.__code__.co_firstlineno)

            def make(modules, fs=None):
                original_fs = filesystem_definitions(sources[FS_FIXTURE[0]], modules['mta_p2p_client_init'])
                fs = original_fs.FakeFs() if fs is None else fs
                clock = Clock()
                reader = modules['mta_client_proc'].ProcReader(_fs=fs, _clock=clock)
                store = modules['mta_client_store'].DurableClientInitStore('1' * 32,
                    modules['mta_p2p_client_init'].Identity('a' * 64), _proc_reader=reader, _clock=clock)
                self.assertIs(reader._bound_budget_v24, store._resource_budget_v23)
                return clock, fs, store, reader, original_fs

            def closed(modules, fs, store, reader, value):
                self.assertIs(value, reader.operation_history[-1].observation)
                self.assertIs(type(value), modules['mta_client_proc'].ProcObservation)
                self.assertIs(value.resource_pending, False)
                self.assertEqual(value.file_count, value.closed_count)
                self.assertFalse(fs.live)
                self.assertEqual(len(fs.opens), len(fs.closed))
                self.assertEqual(len(fs.closed), len(set(fs.closed)))
                self.assertTrue(reader.history_closed())
                self.assertIs(reader._current_generation, None)
                self.assertEqual(0, store._resource_budget_v23.status()['active_producers'])
                generation = reader.operation_history[-1]
                self.assertIs(generation.reader, reader)
                self.assertTrue(generation.ended)
                self.assertFalse(generation.active or generation.unknown or generation.late)
                self.assertEqual(len(generation.tickets), value.file_count)
                self.assertEqual(len(generation.raw), len(value.raw))
                self.assertTrue(all(a is b for a, b in zip(generation.raw, value.raw)))
                self.assertFalse(value.reap_complete)

            def configure(fs, definitions, variant):
                def hook(fs, operation, path, count):
                    if operation != 'open' or not path.endswith('/stat'):
                        return
                    tid = int(path.split('/')[-2])
                    skip = False
                    if variant == 'within_last':
                        skip = path == '/proc/42/stat' and count % 2 == 0
                    elif variant == 'within_leader':
                        skip = path == '/proc/42/task/42/stat'
                    elif variant == 'between_root_and_leader':
                        skip = count >= (3 if path == '/proc/42/stat' else 2)
                    elif variant == 'between_nonleader':
                        skip = path == '/proc/42/task/43/stat' and count == 2
                    fs.files[path] = definitions.stat_data(tid, start=100 if tid == 42 else 101,
                        flags=MASK if skip else 0, threads=2 if variant == 'between_nonleader' else 1)
                fs.hook = hook

            for variant, old_reason in (('within_last', 'pid_identity_changed'),
                    ('within_leader', 'pid_identity_changed'),
                    ('between_root_and_leader', 'observation_changed'),
                    ('between_nonleader', 'observation_changed')):
                for modules, expected in ((old, old_reason), (new, 'live_actor')):
                    with self.subTest(path=variant, candidate=modules is new):
                        definitions = filesystem_definitions(sources[FS_FIXTURE[0]], modules['mta_p2p_client_init'])
                        fs = definitions.FakeFs(tasks=(42, 43) if variant == 'between_nonleader' else (42,))
                        configure(fs, definitions, variant)
                        unused, fs, store, reader, definitions = make(modules, fs)
                        value = reader.read_actor(42, _absolute_deadline=2.0)
                        self.assertEqual(expected, value.reason)
                        closed(modules, fs, store, reader, value)
                        if modules is new:
                            self.assertEqual(('live_actor', 2, True), (value.kind, value.passes, value.same_boot))
                            self.assertTrue(value.actor.live())
                            self.assertEqual(4, fs.call_counts[('lstat', '/proc/42')])
                            flags = [p.parse_stat(row.data, int(row.path.split('/')[-2])).flags
                                for row in value.raw if row.path.endswith('/stat') and type(row.data) is bytes]
                            self.assertIn(0, flags)
                            self.assertIn(MASK, flags)
                            self.assertNotIsInstance(value.actor, modules['mta_p2p_client_init'].ExitProof)
                        cases.append((variant, modules is new, value.reason))

            # The previously short-circuited final directory check must continue.
            for failure in ('directory', 'threads', 'other_flag', 'start', 'comm', 'ppid', 'pid', 'task_set'):
                with self.subTest(negative=failure):
                    unused, fs, store, reader, definitions = make(new)
                    def negative(fs, operation, path, count):
                        if operation == 'open' and path == '/proc/42/stat' and count == 2:
                            options = dict(flags=MASK)
                            if failure == 'threads':
                                options['threads'] = 2
                            if failure == 'other_flag':
                                options['flags'] |= 1
                            if failure == 'start':
                                options['start'] = 101
                            if failure == 'comm':
                                options['comm'] = b'changed'
                            if failure == 'pid':
                                options['pid'] = 43
                            raw = definitions.stat_data(**options)
                            if failure == 'ppid':
                                end = raw.rfind(b') ')
                                fields = raw[end + 2:-1].split(b' ')
                                fields[1] = b'2'
                                raw = raw[:end + 2] + b' '.join(fields) + b'\n'
                            fs.files[path] = raw
                        if failure == 'directory' and operation == 'lstat' and path == '/proc/42' and count == 2:
                            fs.metadata[path] = definitions.meta(stat.S_IFDIR | 0o555, fs.inode(path) + 1, 2)
                        if failure == 'task_set' and operation == 'listdir' and path == '/proc/42/task' and count == 2:
                            fs.dirs.add('/proc/42/task/43')
                    fs.hook = negative
                    value = reader.read_actor(42)
                    expected = {'start': 'pid_reused', 'pid': 'invalid_stat', 'task_set': 'task_directory_changed'}.get(failure, 'pid_identity_changed')
                    self.assertEqual(expected, value.reason)
                    self.assertIsNone(value.actor)
                    closed(new, fs, store, reader, value)
                    if failure == 'directory':
                        self.assertEqual(2, fs.call_counts[('lstat', '/proc/42')])
                        terminal = [r for r in value.raw if r.stage == 'pid_stat' and r.path == '/proc/42' and r.data is None]
                        self.assertEqual(1, len(terminal))
                    cases.append((failure, True, value.reason))

            # All 31 retained bits are also rejected by the actual reader path.
            for bit in range(32):
                if bit == 30:
                    continue
                with self.subTest(actual_reader_retained_flag_bit=bit):
                    unused, fs, store, reader, definitions = make(new)
                    def retained_bit(fs, operation, path, count):
                        if operation == 'open' and path == '/proc/42/stat' and count == 2:
                            fs.files[path] = definitions.stat_data(flags=MASK | (1 << bit))
                    fs.hook = retained_bit
                    value = reader.read_actor(42)
                    self.assertEqual('pid_identity_changed', value.reason)
                    self.assertIsNone(value.actor)
                    closed(new, fs, store, reader, value)
                    cases.append(('retained_flag_bit', True, value.reason))

            # Original aggregate guards still reject changed boot/exe/cmd/tasks.
            for failure in ('boot', 'exe', 'command', 'between_task_set'):
                with self.subTest(aggregate_guard=failure):
                    unused, fs, store, reader, definitions = make(new)
                    def aggregate_change(fs, operation, path, count):
                        if operation != 'open' or path != definitions.BOOT_PATH or count != 3:
                            return
                        if failure == 'boot':
                            fs.files[path] = b'22345678-1234-1234-1234-123456789abc\n'
                        elif failure == 'exe':
                            fs.links['/proc/42/exe'] = '/private/changed'
                        elif failure == 'command':
                            fs.files['/proc/42/cmdline'] = b'/private/changed\0'
                        else:
                            fs.dirs.update(('/proc/42/task/43', '/proc/43'))
                            fs.files['/proc/42/stat'] = definitions.stat_data(flags=MASK, threads=2)
                            fs.files['/proc/42/task/42/stat'] = definitions.stat_data(flags=MASK, threads=2)
                            fs.files['/proc/42/task/43/stat'] = definitions.stat_data(43, start=101, flags=MASK, threads=2)
                    fs.hook = aggregate_change
                    value = reader.read_actor(42)
                    expected = 'boot_changed' if failure == 'boot' else 'task_set_changed' if failure == 'between_task_set' else 'observation_changed'
                    self.assertEqual(expected, value.reason)
                    self.assertIsNone(value.actor)
                    closed(new, fs, store, reader, value)
                    cases.append((failure, True, value.reason))

            # Actual raw PF_KTHREAD/live classification gates remain untouched.
            for failure in ('kernel_mismatch', 'kernel_nonempty', 'kernel_empty', 'dead', 'parked'):
                with self.subTest(classification=failure):
                    fs = fixture.FakeFs(tasks=(42, 43) if failure == 'kernel_mismatch' else (42,),
                        flags=(p.PF_KTHREAD | MASK) if failure in ('kernel_nonempty', 'kernel_empty') else MASK,
                        cmd=b'' if failure == 'kernel_empty' else b'/private/fixture\0argument\0',
                        state='Z' if failure == 'dead' else 'P' if failure == 'parked' else 'S')
                    if failure == 'kernel_mismatch':
                        fs.files['/proc/42/task/43/stat'] = fixture.stat_data(43, start=101,
                            flags=p.PF_KTHREAD | MASK, threads=2)
                    unused, fs, store, reader, unused_defs = make(new, fs)
                    value = reader.read_actor(42)
                    expected = {'kernel_mismatch': 'task_kernel_mismatch', 'kernel_nonempty': 'kernel_cmdline_unexpected',
                        'kernel_empty': 'empty_kernel', 'dead': 'nonlive_task', 'parked': 'unsupported_actor_state'}[failure]
                    self.assertEqual(expected, value.reason)
                    self.assertIsNone(value.actor)
                    closed(new, fs, store, reader, value)
                    cases.append((failure, True, value.reason))

            # Both absence key consumers: current leader plus recorded tasks.
            for path_kind in ('current', 'recorded_task'):
                for modules, expected in ((old, 'observation_changed'), (new, 'pid_present')):
                    with self.subTest(absence=path_kind, candidate=modules is new):
                        unused, fs, store, reader, definitions = make(modules)
                        def absence_flip(fs, operation, path, count):
                            if operation == 'open' and path == '/proc/42/stat':
                                skip = count == 3 if path_kind == 'current' else count == 4
                                fs.files[path] = definitions.stat_data(flags=MASK if skip else 0)
                        fs.hook = absence_flip
                        value = reader.read_absence(definitions.expected(), definitions.BOOT)
                        self.assertEqual(expected, value.reason)
                        self.assertFalse(value.pid_path_absent)
                        self.assertFalse(value.reap_complete)
                        self.assertNotEqual('absence', value.kind)
                        closed(modules, fs, store, reader, value)
                        cases.append(('absence_' + path_kind, modules is new, value.reason))
            for failure in ('leader_reused', 'task_reused'):
                with self.subTest(absence_negative=failure):
                    fs = fixture.FakeFs(tasks=(42, 43))
                    if failure == 'leader_reused':
                        fs.files['/proc/42/stat'] = fixture.stat_data(start=102, flags=MASK, threads=2)
                        fs.files['/proc/42/task/42/stat'] = fixture.stat_data(start=102, flags=MASK, threads=2)
                    else:
                        fs.files['/proc/43/stat'] = fixture.stat_data(43, start=102, flags=MASK, threads=2)
                    unused, fs, store, reader, definitions = make(new, fs)
                    value = reader.read_absence(definitions.expected(tasks=((42, 100, 'S'), (43, 101, 'S'))), definitions.BOOT)
                    self.assertEqual('pid_reused' if failure == 'leader_reused' else 'task_reused', value.reason)
                    self.assertFalse(value.pid_path_absent)
                    closed(new, fs, store, reader, value)
                    cases.append((failure, True, value.reason))

            # A sleeping synthetic clock never relaxes the original outer cap.
            clock, fs, store, reader, definitions = make(new)
            crossed = [False]
            def expire(unused, operation, path, count):
                if operation == 'read' and not crossed[0]:
                    crossed[0] = True
                    clock.value = 2.001
            fs.hook = expire
            value = reader.read_actor(42, _absolute_deadline=2.0)
            self.assertTrue(crossed[0])
            self.assertEqual('deadline', value.reason)
            self.assertIsNone(value.actor)
            closed(new, fs, store, reader, value)
            cases.append(('outer_deadline', True, value.reason))
        self.assertEqual(63, len(cases))
        self.assertEqual(sources, retained_sources())
        self.assertEqual(actual, generated.generated_inputs())
        print(MARKER)
        print('HOST_SCOPE cases=63 flag_bits_retained=31 physical_os=false rf=false phone=false restoration=false')


if __name__ == '__main__':
    if sys.argv[1:] != [SELECTOR]:
        raise SystemExit('only_one_affected_method_allowed')
    suite = unittest.defaultTestLoader.loadTestsFromName(SELECTOR, sys.modules[__name__])
    if suite.countTestCases() != 1:
        raise SystemExit('method_count')
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)
