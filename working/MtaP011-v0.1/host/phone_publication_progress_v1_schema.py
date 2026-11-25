"""Five exact publication DATA fields around the frozen original smoke parser.

No original success, READY, trace, Trial, duration or closure predicate changes.
These are retained sample deltas, not live durations or receive permission.
Only the fixed original parser definitions are selected; its main never runs.
"""
import ast
import hashlib
import math
from pathlib import Path
import re
import types

BASE = Path(__file__).resolve().parents[1]
ORIGINAL = ('host/device_receive_handoff_progress_120s_v2_check.py', 39070,
            '2da874a8b53463986882576aac28222663503f64fd16cdbf8a430b8e422ce484')
FIELDS = ('publication_step', 'publication_sources_done', 'publication_sample_elapsed',
          'publication_step_elapsed', 'publication_progress_unknown')
STEPS = ('start', 'io', 'sources', 'wpa', 'json_pin', 'profile', 'received',
         'identity', 'manifest', 'write', 'loader')
CONSTANTS = frozenset(('FLAGS', 'PROGRESS_BOOL', 'STAGE_OPTIONAL_BOOL', 'STAGE_FIELDS',
                       'FACTORY_PHASES', 'OBS_BOOL', 'TERMINAL_BOOL', 'REASONS'))
UNKNOWN = dict((name, None) for name in FIELDS[:-1])
UNKNOWN[FIELDS[-1]] = True


def need(value, code):
    if value is not True:
        raise ValueError(code)


def original_parser(source=None):
    raw = (BASE / ORIGINAL[0]).read_bytes() if source is None else source
    need(type(raw) is bytes and (len(raw), hashlib.sha256(raw).hexdigest()) == ORIGINAL[1:],
         'publication_original_parser_pin')
    parsed = ast.parse(raw.decode('utf-8'))
    chosen = []
    for node in parsed.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and (
                node.targets[0].id in CONSTANTS):
            chosen.append(node)
        elif isinstance(node, ast.FunctionDef) and node.name == 'parse_smoke':
            chosen.append(node)
    need({node.targets[0].id for node in chosen if isinstance(node, ast.Assign)} == CONSTANTS and
         len([node for node in chosen if isinstance(node, ast.FunctionDef)]) == 1 and len(chosen) == 9,
         'publication_original_pure_inventory')
    module = types.ModuleType('fixed_publication_original_smoke_parser')
    module.__file__ = str(BASE / ORIGINAL[0])
    module.__dict__.update(ast=ast, math=math, re=re)
    exec(compile(ast.Module(body=chosen, type_ignores=[]), '<fixed-original-smoke-parser>', 'exec'), module.__dict__)
    need('main' not in module.__dict__ and set(FIELDS).isdisjoint(module.OBS_BOOL + module.PROGRESS_BOOL +
         module.STAGE_FIELDS), 'publication_only_five_new_fields')
    return module


def validate_publication(row):
    """Validate exactly the five DATA values, without changing old stage data."""
    need(type(row) is dict and all(name in row for name in FIELDS) and
         type(row['publication_progress_unknown']) is bool, 'publication_unknown_type')
    if row['publication_progress_unknown']:
        need(all(row[name] is None for name in FIELDS[:-1]), 'publication_unknown_all_none')
        return
    need(row.get('stage_unknown') is False and row.get('factory_active_present') is True,
         'publication_known_requires_original_active')
    step, completed = row['publication_step'], row['publication_sources_done']
    total, elapsed = row['publication_sample_elapsed'], row['publication_step_elapsed']
    need(type(step) is str and step in STEPS and type(completed) is int and 0 <= completed <= 35,
         'publication_step_count')
    if step == 'start':
        need(completed == 0 and total is None and elapsed is None, 'publication_initial_start')
        return
    need((step != 'io' or completed == 0) and
         (step in ('io', 'sources') or completed == 35), 'publication_completion_boundary')
    need(type(total) is float and type(elapsed) is float and math.isfinite(total) and math.isfinite(elapsed) and
         0 <= elapsed <= total <= 300, 'publication_finite_sample_deltas')


def parse_smoke(raw, component, remote, trials, source=None):
    """Strip five fields, delegate every original guard, then restore DATA only."""
    need(type(raw) is bytes, 'publication_raw_bytes')
    original = original_parser(source)
    text = raw.decode('utf-8', 'replace').replace('\r\r\n', '\n').replace('\r\n', '\n')
    matches = list(re.finditer(r'^SMOKE_RESULT=(.*)$', text, re.M))
    need(len(matches) == 1, 'publication_smoke_result_unique')
    match = matches[0]
    value = ast.literal_eval(match.group(1))
    need(type(value) is dict and type(value.get('observations')) is tuple and
         len(value['observations']) <= 320, 'publication_observation_container')
    old_keys = set(original.OBS_BOOL + original.PROGRESS_BOOL + original.STAGE_FIELDS +
                   ('stage', 'state', 'event_counts', 'elapsed_seconds', 'f_process_retained'))
    stripped_rows, data_rows = [], []
    for row in value['observations']:
        need(type(row) is dict and set(row) == old_keys | set(FIELDS), 'publication_observation_exact_fields')
        validate_publication(row)
        data_rows.append(dict((name, row[name]) for name in FIELDS))
        stripped_rows.append(dict((name, row[name]) for name in row if name not in FIELDS))
    stripped = dict(value)
    stripped['observations'] = tuple(stripped_rows)
    delegated = (text[:match.start(1)] + repr(stripped) + text[match.end(1):]).encode('utf-8')
    # This fixed function is the complete original source body, not a subset
    # of its PASS/flags/terminal/remote/component/Trial checks.
    parsed = original.parse_smoke(delegated, component, remote, trials)
    need(parsed == stripped and len(parsed['observations']) == len(data_rows), 'publication_original_result_preserved')
    result = dict(parsed)
    result['observations'] = tuple(dict(row, **data) for row, data in zip(parsed['observations'], data_rows))
    need(result == value, 'publication_only_data_restored')
    return result
