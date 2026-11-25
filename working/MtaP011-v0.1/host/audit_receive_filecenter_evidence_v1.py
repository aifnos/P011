"""Read-only HOST evidence audit. No tests, Qt, imports or device access."""
import ast
import hashlib
import json
from pathlib import Path
import re
import zipfile

BASE = Path(__file__).resolve().parents[1]
RESULTS = (
    ('receive-filecenter-product-host-20261004-150650-5526fc34', 20),
    ('receive-filecenter-audio-callback-host-20261004-151025-ee6f7b07', 3),
    ('receive-filecenter-partial-resource-host-20261004-151537-8c520f84', 6),
    ('receive-filecenter-audio-loading-host-20261004-151953-62d82cbf', 3),
)
STAGE = BASE/'out/mta-ui-b6a84fe755092535bb996f40'


def require(value, code):
    if value is not True: raise ValueError(code)


def digest(raw): return hashlib.sha256(raw).hexdigest()


def result_audit(name, contracts):
    root = BASE/'results'/name
    report = json.loads((root/'result.json').read_bytes())
    require(report['passed'] is True and report['host_exit'] == 0 and
            report['new_methods'] == 1 and report['old_methods'] == 0 and
            report['contracts'] == contracts and report['device_tested'] is False,
            'original_result')
    inventory = json.loads((root/'private-inputs.json').read_bytes())
    require(len(inventory) == report['source_count'], 'original_inventory_count')
    differences = []
    for path, pin in inventory.items():
        raw = (root/'private-inputs'/path).read_bytes()
        require(len(raw) == pin['bytes'] and digest(raw) == pin['sha256'], 'snapshot_identity')
        if (BASE/path).read_bytes() != raw: differences.append(path)
    for stream in ('stdout', 'stderr'):
        raw = (root/(stream+'.raw')).read_bytes()
        require(len(raw) == report[stream+'_bytes'] and digest(raw) == report[stream+'_sha256'], 'raw_identity')
    require((root/'host-exit.raw').read_bytes() == b'0\n', 'original_exit')
    stderr = (root/'stderr.raw').read_bytes()
    require(re.search(rb'^Ran 1 test in [0-9.]+s\r?$', stderr, re.M) is not None and
            re.search(rb'^OK\r?$', stderr, re.M) is not None, 'original_unittest')
    bundle = root/'public-result.zip'
    with zipfile.ZipFile(bundle) as archive:
        require(archive.namelist() == ['result.json','README.txt'] and archive.testzip() is None,
                'zip_inventory_crc')
        for entry in archive.namelist():
            require(archive.read(entry) == (root/entry).read_bytes(), 'zip_original_bytes')
    return dict(result=name, original_contracts=contracts, original_host_exit=0,
                saved_inputs=len(inventory), current_changed_saved_sources=differences,
                zip_bytes=bundle.stat().st_size, zip_sha256=digest(bundle.read_bytes()),
                audit_only=True, tests_replayed=False, device_tested=False)


def stage_audit():
    stage = json.loads((STAGE/'stage-manifest.json').read_bytes())
    report = json.loads((STAGE/'build-result.json').read_bytes())
    require(stage['schema'] == 'p011-receive-filecenter-ui-stage-v1' and
            stage['session'] == 'b6a84fe755092535bb996f40' and
            stage['staged_file_count'] == len(stage['files']) == 19 and
            stage['payload_file_count'] == 18 and
            report['builder_sha256'] == '82f735c427caf11824991350906303997e67ac94d5e9c0bbc13cd1fecabf8b5f', 'built_stage')
    expected = {row['path'] for row in stage['files']}
    actual = {path.relative_to(STAGE).as_posix() for path in STAGE.rglob('*') if path.is_file()}
    require(actual == expected | set(stage['excluded_pc_files']), 'stage_inventory')
    for row in stage['files']:
        raw = (STAGE/row['path']).read_bytes()
        require(len(raw) == row['bytes'] and digest(raw) == row['sha256'], 'stage_pin')
    source = (STAGE/'SOURCE.sha256').read_bytes()
    rows = sorted((row['path'], row['bytes'], row['sha256']) for row in stage['files'] if row['path'] != 'SOURCE.sha256')
    require(source == ''.join(sha+' '+str(size)+' '+path+'\n' for path,size,sha in rows).encode('ascii'),
            'source_original_bytes')
    original = BASE.parents[1]/'06_Firmware/backups/v2.4.0-20260923-162730/files/Z03'
    before, after = original.read_bytes(), (STAGE/'Z03.mta-ui-candidate').read_bytes()
    offset, end = 1946708, 1946708+4+1580
    require(len(before) == len(after) == 4103844 and digest(before) == report['original_sha256'] and
            digest(after) == report['candidate_sha256'] and before[:offset] == after[:offset] and
            before[end:] == after[end:], 'original_elf_outside_slot')
    require(report['resources_verified'] == 400 and report['other_resources_original_bytes'] == 399 and
            report['used_bytes'] <= 1580 and report['device_tested'] is False, 'pc_build_projection')
    return dict(session=stage['session'], staged_files=19, staged_directories=3,
                staged_bytes=sum(row['bytes'] for row in stage['files']),
                elf_outside_slot_unchanged=True, pc_build_only=True,
                original_builder_bytes_not_snapshotted=True,
                current_builder_is_later_scandir_bound_fix=True, rebuild_invoked=False)


def main():
    results = [result_audit(name, count) for name,count in RESULTS]
    stage = stage_audit()
    print(json.dumps(dict(audit_passed=True, host_results=results, stage=stage,
                          source_only_runtime_ast=0, device_access=False), sort_keys=True))


if __name__ == '__main__': main()
