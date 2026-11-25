"""Independent V2 passive retained evidence, original no-RF startup policy.

Default SOURCE; explicit --check-device. No V1 bridge or old main is called.
Runtime75, Startup10, strict None Trial, PASS, close and original caps remain.
"""
import ast
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import stat
import types

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_receive_startup_retained_v2_check.py'
MOTHER = ('host/device_receive_publication_progress_v1_startup_check.py', 18494,
          'f47479a85dd54dd1e192509dfe125d1da336edae20a4cd607fa24e5cca02dadf')
PROJECTION = ('host/receive_startup_retained_v2_projection.py', 21095,
              'ba0a54148c700ac28c5ee090490696dac0aec419ba440ad7be0642938b7a9912')
CMDS = ('HOST_MTA_RECEIVE_STARTUP_RETAINED_V2_CHECK.cmd', 'TEST_MTA_RECEIVE_STARTUP_RETAINED_V2.cmd')


def metadata(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
            value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def read_fixed(name, pin=None):
    if (type(name) is not str or not name or '\\' in name or
            PurePosixPath(name).is_absolute() or re.fullmatch(r'[A-Za-z0-9_./-]+', name) is None or
            any(part in ('', '.', '..') for part in name.split('/'))):
        raise ValueError('fixed_path')
    path = BASE
    for node in reversed((BASE,) + tuple(BASE.parents)):
        value = node.lstat()
        if (not stat.S_ISDIR(value.st_mode) or stat.S_ISLNK(value.st_mode) or
                getattr(value, 'st_file_attributes', 0) & 0x400): raise ValueError('fixed_ancestor')
    for index, part in enumerate(name.split('/')):
        path = path / part; value = path.lstat()
        if stat.S_ISLNK(value.st_mode) or getattr(value, 'st_file_attributes', 0) & 0x400:
            raise ValueError('fixed_link')
        if index < len(name.split('/')) - 1 and not stat.S_ISDIR(value.st_mode):
            raise ValueError('fixed_ancestor')
    if not stat.S_ISREG(value.st_mode) or not 0 < value.st_size <= 2 * 1024 * 1024:
        raise ValueError('fixed_file')
    before = metadata(value)
    with path.open('rb') as handle:
        opened = metadata(os.fstat(handle.fileno()))
        if os.name == 'nt':
            equal = (opened[:2] == before[:2] and stat.S_IFMT(opened[2]) == stat.S_IFMT(before[2]) and
                     opened[3:6] == before[3:6])
        else: equal = opened == before
        if not equal: raise ValueError('fixed_identity')
        raw = handle.read(2 * 1024 * 1024 + 1)
        if metadata(os.fstat(handle.fileno())) != opened: raise ValueError('fixed_changed')
    if metadata(path.lstat()) != before or len(raw) != before[4]: raise ValueError('fixed_changed')
    if pin is not None and (len(raw), hashlib.sha256(raw).hexdigest()) != pin: raise ValueError('fixed_pin')
    return raw


def derive(raw):
    if (len(raw), hashlib.sha256(raw).hexdigest()) != MOTHER[1:]:
        raise ValueError('fixed_mother_pin')
    replacements = (
        ("SELF = 'host/device_receive_publication_progress_v1_startup_check.py'",
         "SELF = 'host/device_receive_startup_retained_v2_check.py'", 1),
        ("CMDS = ('HOST_MTA_RECEIVE_PUBLICATION_PROGRESS_V1_STARTUP_CHECK.cmd', 'TEST_MTA_RECEIVE_PUBLICATION_PROGRESS_V1_STARTUP.cmd')",
         "CMDS = ('HOST_MTA_RECEIVE_STARTUP_RETAINED_V2_CHECK.cmd', 'TEST_MTA_RECEIVE_STARTUP_RETAINED_V2.cmd')", 1),
        ("'receive-publication-progress-v1-startup-'", "'receive-startup-retained-v2-'", 1),
        ("label = 'receive-publication-progress-v1-startup'", "label = 'receive-startup-retained-v2'", 1),
        ('p011-receive-publication-progress-v1-startup', 'p011-receive-startup-retained-v2', 2),
        ('io_inverse(fixed(IO_DONOR), own)', 'io_inverse(fixed(IO_DONOR), HOST_RAW)', 1),
        ('        pure = pure_startup(fixed(DONOR))',
         '        fixed(MOTHER)\n        projection_raw = fixed(PROJECTION)\n'
         '        pure = pure_startup(fixed(DONOR))\n        pure = attach_projection(pure, projection_raw)', 1),
        ("if __name__ == '__main__':\n    raise SystemExit(main())\n", '', 1))
    current, changes = raw, []
    for before, after, count in replacements:
        before, after = before.encode('ascii'), after.encode('ascii')
        if current.count(before) != count or (after and current.count(after)):
            raise ValueError('finite_forward_anchor')
        current = current.replace(before, after)
        changes.append((before, after, count))
    inverse = current
    for before, after, count in reversed(changes[:-1]):
        if inverse.count(after) != count:
            raise ValueError('finite_reverse_anchor')
        inverse = inverse.replace(after, before)
    guard = changes[-1][0]
    if inverse != raw.replace(guard, b'') or inverse + guard != raw:
        raise ValueError('complete_host_byte_inverse')
    old, tree = ast.parse(raw, feature_version=(3, 5)), ast.parse(current, feature_version=(3, 5))
    if any(isinstance(row, ast.If) for row in tree.body):
        raise ValueError('old_guard_forbidden')
    original_defs = {row.name: ast.get_source_segment(raw.decode('ascii'), row)
                     for row in old.body if isinstance(row, ast.FunctionDef)}
    current_defs = {row.name: ast.get_source_segment(current.decode('ascii'), row)
                    for row in tree.body if isinstance(row, ast.FunctionDef)}
    if set(original_defs) != set(current_defs) or any(
            original_defs[name] != current_defs[name] for name in original_defs if name != 'main'):
        raise ValueError('unchanged_host_definitions')
    return current


def attach_projection(pure, raw):
    if (len(raw), hashlib.sha256(raw).hexdigest()) != PROJECTION[1:]:
        raise ValueError('fixed_projection_pin')
    projection = types.ModuleType('fixed_startup_retained_v2_source')
    exec(compile(raw, str(BASE / PROJECTION[0]), 'exec'), projection.__dict__)
    original_make = pure.make_source

    def make_source(definitions, helpers, inputs, payload):
        original, selected = original_make(definitions, helpers, inputs, payload)
        return original, projection.inject(selected, raw)

    pure.make_source = make_source
    return pure


def prepare():
    raw = read_fixed(MOTHER[0], MOTHER[1:])
    derived = derive(raw)
    value = types.ModuleType('fixed_startup_retained_v2_host')
    value.__file__ = str(BASE / SELF)
    exec(compile(derived, str(BASE / SELF), 'exec'), value.__dict__)
    value.__dict__.update(MOTHER=MOTHER, PROJECTION=PROJECTION,
                          HOST_RAW=derived, attach_projection=attach_projection)
    return value


if __name__ == '__main__':
    raise SystemExit(prepare().main())
