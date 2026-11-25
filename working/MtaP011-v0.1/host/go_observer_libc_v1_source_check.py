"""PC-only four-source observer libc ABI/pin check. Never executes a graph."""
import ast
import datetime
import hashlib
import json
from pathlib import Path
import secrets
import traceback
import zipfile

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/go_observer_libc_v1_source_check.py'
CMD = 'CHECK_MTA_GO_OBSERVER_LIBC_V1_SOURCE.cmd'
ROOT = '/var/volatile/tmp/p011-mta-go-observer-libc-v1'
OLD_ROOT = '/var/volatile/tmp/p011-mta-go-observer-v85'
PREFIX = 'candidate/go-observer-libc-v1/runtime/'
CATALOG = ('candidate/go-observer-libc-v1/assets/observer-source-catalog.json', 15861,
           '8aaadd3f5a32b184bb851b422781ae8038d699d3e9555cb479cd49f4d090648a')
OLD_CATALOG = ('candidate/formal-send-filecenter-deploy-v3/assets/asset-sources.json', 23850,
               '3551b5e546aa27e6d68e664b787ffd500e3992fd6f4d93bc7dc28291021c22fa')
PINS = (
    ('mta_go_readonly_preflight', 64948, '802ad7c3b80ea6e9ea4678a4112bd2ec95be08cff5fe6684e1162f127ae55f44'),
    ('mta_go_readonly_loader', 36543, '8e60e8f86a0cd4a261ca65f657739e9189137cf37dc04f4af1495263ce1b8e56'),
    ('mta_go_readonly_entry', 45310, 'b97328b01617ce1944d3576bb4c0e22160414120c737b336e2509004d0031ffa'),
    ('mta_go_readonly_parent', 52881, 'a950577490c576698b3186efe87c6a8da773b21128f836d51b5b26a7bb5d45d6'),
)
OLD_PINS = (
    ('candidate/go-send-terminal-channel-v94/runtime/mta_go_readonly_preflight.py', 64944,
     '0326d422bec605d279403a61c38b14bfd2f91ab0ae3959e5f647dd46ac067e40'),
    ('candidate/go-send-terminal-channel-v94/runtime/mta_go_readonly_loader.py', 36535,
     '075ae9e1cf7736c87929032d14e36d11bc35b48616376a8c0404c7402489b346'),
    ('candidate/go-send-terminal-channel-v94/runtime/mta_go_readonly_entry.py', 43263,
     'af87658a8a7bdf24f0c363a94a6e71c9cfb150f648e5af007e4e17f5d0fc0868'),
    ('candidate/go-parent-libc-v1/runtime/mta_go_readonly_parent.py', 52873,
     '96873084af32bc8c7fe0c0a236ddb49f4b91b85677b1b9b966fe6c714c03724b'),
)


def need(value, code):
    if value is not True:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def write_new(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        need(stream.write(raw) == len(raw), 'write')


def tree(raw):
    return ast.parse(raw, feature_version=(3, 5))


def class_io(parsed):
    return next(node for node in parsed.body if isinstance(node, ast.ClassDef) and node.name == '_LinuxIo')


def method(cls, name):
    return next(node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name == name)


def dump(node):
    return ast.dump(node, include_attributes=False)


def reverse_text(raw):
    return raw.decode('utf-8').replace('p011-mta-go-observer-libc-v1', 'p011-mta-go-observer-v85')


def source_checks(inputs):
    old = [inputs[row[0]] for row in OLD_PINS]
    new = [inputs[PREFIX + row[0] + '.py'] for row in PINS]
    parsed = [tree(raw) for raw in new]
    for parsed_source in parsed:
        need(not any(isinstance(node, ast.Import) and any(alias.name == 'fcntl' for alias in node.names) or
                     isinstance(node, ast.ImportFrom) and node.module == 'fcntl'
                     for node in ast.walk(parsed_source)), 'fcntl_import')
    need(reverse_text(new[0]).encode('utf-8') == old[0], 'body_business_changed')
    loader = reverse_text(new[1]).replace("('mta_go_readonly_preflight', 64948, '" + PINS[0][2] + "')",
        "('mta_go_readonly_preflight', 64944, '" + OLD_PINS[0][2] + "')")
    need(loader.encode('utf-8') == old[1], 'loader_business_changed')
    parent = reverse_text(new[3]).replace("ENTRY_PIN = ('mta_go_readonly_entry', 45310,\n             '" + PINS[2][2] + "')",
        "ENTRY_PIN = ('mta_go_readonly_entry', 43263,\n             '" + OLD_PINS[2][2] + "')")
    need(parent.encode('utf-8') == old[3], 'parent_business_changed')
    entry = reverse_text(new[2]).replace("('mta_go_readonly_loader', 36543,\n     '" + PINS[1][2] + "')",
        "('mta_go_readonly_loader', 36535,\n     '" + OLD_PINS[1][2] + "')")
    new_entry, old_entry = tree(entry), tree(old[2])
    new_io, old_io = class_io(new_entry), class_io(old_entry)
    changed = {'__init__', 'validate', 'flags', 'set_flags'}
    for node in new_io.body:
        if isinstance(node, ast.FunctionDef) and node.name not in changed:
            need(dump(node) == dump(method(old_io, node.name)), 'entry_other_io_changed')
    need(dump(method(new_io, 'validate').body[0]) == dump(method(old_io, 'validate').body[0]),
         'entry_platform_or_path_changed')
    parent_io = class_io(tree(old[3]))
    need(dump(method(new_io, '__init__')) == dump(method(parent_io, '__init__')), 'entry_retainer_changed')
    new_validate = method(new_io, 'validate')
    parent_validate = method(parent_io, 'validate')
    need([dump(node) for node in new_validate.body[1:]] ==
         [dump(node) for node in parent_validate.body[1:]], 'entry_libc_binding_changed')
    for name in ('flags', 'set_flags'):
        normalized = ast.unparse(method(new_io, name)).replace('observer_', 'parent_').replace(
            'ReadonlyEntryError', 'ReadonlyParentError')
        need(dump(tree(normalized).body[0]) == dump(method(parent_io, name)), 'entry_abi_changed')
    for at, node in enumerate(new_entry.body):
        if node is new_io:
            new_entry.body[at] = old_io
    need(dump(new_entry) == dump(old_entry), 'entry_non_abi_business_changed')
    return dict(new_sources_parsed=4,body_loader_parent_exact_mechanical=True,
                entry_non_abi_ast_unchanged=True,entry_original_platform_path_guard=True,
                entry_fcntl_abi_same_as_fixed_parent=True,abi_syscalls_executed=False)


def main():
    out = BASE/'results'/('go-observer-libc-v1-source-'+datetime.datetime.now().strftime('%Y%m%d-%H%M%S')+'-'+secrets.token_hex(4))
    out.mkdir(parents=True, exist_ok=False)
    inputs = {}
    result = dict(passed=False, source_checked=False, source_preserved=False,
                  device_invoked=False, runtime_executed=False, rf_requested=False,
                  old_tests=0, child_exit='NOT_RUN', remote_exit='NOT_RUN', error_kind=None)
    try:
        for path, size, digest in (CATALOG, OLD_CATALOG) + OLD_PINS + tuple(
                (PREFIX+name+'.py',size,digest) for name,size,digest in PINS):
            raw = (BASE/path).read_bytes()
            need((len(raw),sha(raw)) == (size,digest), 'source_pin')
            inputs[path] = raw
        catalog = json.loads(inputs[CATALOG[0]])
        old_catalog = json.loads(inputs[OLD_CATALOG[0]])
        need(catalog['root'] == ROOT and catalog['alias'] == '/tmp/p011-mta-go-observer-libc-v1' and
             catalog['directories'] == [dict(path=path,mode='0700') for path in (ROOT,ROOT+'/runtime')] and
             catalog['source_count'] == len(catalog['files']) == 41 and catalog['load_count'] == 38 and
             catalog['source_bytes'] == 1442508 and catalog['unchanged_asset_count'] == 38 and
             catalog['active_seconds'] == 30 and catalog['cleanup_seconds'] == 5 and
             catalog['rf_requested'] is False and catalog['native_grant'] is False, 'catalog_shape')
        originals = {row['module']:row for row in old_catalog['observer_sources']}
        new_pins = {name:(size,digest) for name,size,digest in PINS[:3]}
        need(set(originals) == {row['module'] for row in catalog['files']}, 'catalog_roles')
        unchanged = 0
        for row in catalog['files']:
            name = row['module']; original = originals[name]
            expected = new_pins.get(name,(original['bytes'],original['sha256']))
            path = PREFIX+name+'.py' if name in new_pins else original['source']
            need(row['source'] == path and row['target'] == ROOT+'/runtime/'+name+'.py' and
                 (row['bytes'],row['sha256']) == expected and row['mode'] == '0400', 'catalog_row')
            raw = (BASE/path).read_bytes(); need((len(raw),sha(raw)) == expected, 'asset_pin')
            inputs[path] = raw; unchanged += name not in new_pins
        need(unchanged == 38 and sum(row['bytes'] for row in catalog['files']) == 1442508 < 4194304,
             'catalog_budget')
        facts = source_checks(inputs)
        for path in (SELF,CMD):inputs[path] = (BASE/path).read_bytes()
        for path,raw in inputs.items():write_new(out/'private-inputs'/path,raw)
        result.update(source_checked=True,checks=facts,asset_files=41,asset_bytes=1442508,
                      unchanged_assets=38,parent_inlined_separately=True,input_count=len(inputs))
    except BaseException as error:
        result['error_kind'] = type(error).__name__
        write_new(out/'private-host-error.txt',traceback.format_exc().encode('utf-8'))
    try:
        for path,raw in inputs.items():
            if not (out/'private-inputs'/path).exists():
                write_new(out/'private-inputs'/path,raw)
        result['source_preserved'] = bool(inputs) and all((BASE/path).read_bytes() == raw and
            (out/'private-inputs'/path).read_bytes() == raw for path,raw in inputs.items())
    except BaseException:result['source_preserved'] = False
    result['passed'] = result['source_checked'] and result['source_preserved'] and result['error_kind'] is None
    raw = (json.dumps(result,sort_keys=True,indent=2)+'\n').encode('ascii')
    readme = (b'PC SOURCE only: four new sources parsed, libc ABI compared with fixed Parent.\n'
              b'41 isolated assets: three changed, 38 original bytes; Parent is separate.\n'
              b'Original 30+5 and 8096-byte manifest unchanged. No child/graph/RF/device executed.\n')
    write_new(out/'result.json',raw);write_new(out/'README.txt',readme)
    with zipfile.ZipFile(out/'RESULTS.zip','x',zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('result.json',raw);archive.writestr('README.txt',readme)
    print(json.dumps(dict(passed=result['passed'],result_dir=str(out),error_kind=result['error_kind'])))
    return 0 if result['passed'] else 1


if __name__ == '__main__':raise SystemExit(main())
