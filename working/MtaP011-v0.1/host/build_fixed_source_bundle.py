"""PC-only fixed source/assets bundle, SOURCE-authored; not a release or installer.

No candidate import, AST, subprocess, extraction, native build, device access,
START, deployment, service, RF, restoration or admission. A successful run only
proves the fixed bytes were copied and independently read back from this ZIP.
Historical build scripts are archival SOURCE_ONLY materials, never invoked.
"""
import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import traceback
import uuid
import zipfile
import zlib

BASE = Path(__file__).absolute().parents[1]
PLAN = ('host/mta_fixed_source_bundle_v1_inputs.json', 13132,
        'e9f78f37405a5fc22313f43ee358c404b2e15f121dd80056ed4d8e14d9adb259')
CMD = ('HOST_MTA_FIXED_SOURCE_BUNDLE.cmd', 164,
       '57b79d016f01899100ba385253cd2f3b4ac5943417052b8ef7c6b6e13dddc4fa')
SCOPE = 'OFFLINE_FIXED_SOURCE_ASSETS_UNADMITTED'
MAX_FILE, MAX_INPUT_BYTES, MAX_MEMBERS = 8 * 1024 * 1024, 32 * 1024 * 1024, 192
STATE = '/var/volatile/tmp/p011-mta-state-v69'
STATE_ALIAS = '/tmp/p011-mta-state-v69'
GO = '/var/volatile/tmp/p011-mta-go-send-v76-assets'
OBSERVER = '/var/volatile/tmp/p011-mta-go-observer-v85'
GATES = dict(service=False, tested=False, device=False, phone=False,
             admission=False, rf=False, qml_handoff=False,
             restoration_verified=False)
DOMAINS = ('ordinary', 'client_private', 'go_private', 'observer_private')
COUNTS = (30, 35, 25, 41)
NOTES = (
    'Static source/assets only; not a runnable release, installation or device test.',
    'Four HOST source tables are preserved verbatim; none is emitted as a target source-manifest.json.',
    'GO Publication BUNDLE_MANIFEST_SHA remains None; no production seal is issued.',
    'State receive/send admission remains False; packaging does not change any gate.',
    'Parent97/TerminalParent95 launch/pipe-flags paths require target fcntl support: known missing and not adapted/validated here; definition loading is a separate layer.',
    'No current deployment/stager is included; historical ObserverStage97 is excluded.',
    'Observer41 assets and report/load count38 have different roles; neither count is rewritten.',
    'Frontend device/ sources are unattached; no QML handoff, rotation, startup or UI execution.',
    'Native/WPA sources and relink archives are corresponding archival materials, not a license audit, reproducible-build or runtime-dependency verification.',
    'host/build_native.py uses Docker and its --collect accesses ADB; all archived build sources are SOURCE_ONLY_DO_NOT_RUN.',
    'No target Python/vendor libraries, live status/profile, user credentials/private keys, journals/pending/locks, user files, historical results or START scripts are collected; upstream source archives remain exact, unmodified archival bytes.',
    'Catalog target paths/uid/modes are source-contract intentions only, never applied by this builder.',
    'On this Windows Python host, lstat/fstat ctime and executable-extension mode bits differ for unchanged files: cross-channel identity checks retain dev/inode/file-type/nlink/size/mtime; each channel still checks its full metadata before/after, plus exact raw SHA.',
)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2) + '\n').encode('ascii')


def safe_name(value):
    if (type(value) is not str or not value or '\\' in value or
            re.fullmatch(r'[A-Za-z0-9_./-]+', value) is None or
            PurePosixPath(value).is_absolute() or
            any(p in ('', '.', '..') for p in value.split('/'))):
        raise ValueError('Unsafe fixed relative path')
    return value


def no_link(path):
    row = path.lstat()
    if stat.S_ISLNK(row.st_mode) or getattr(row, 'st_file_attributes', 0) & 0x400:
        raise ValueError('Symlink/reparse point refused')
    return row


def fixed_path(relative, file=True):
    safe_name(relative)
    for node in reversed((BASE,) + tuple(BASE.parents)):
        if not stat.S_ISDIR(no_link(node).st_mode):
            raise ValueError('Workspace parent is not a directory')
    path = BASE
    parts = relative.split('/')
    for index, part in enumerate(parts):
        path = path / part
        row = no_link(path)
        if index < len(parts) - 1 or not file:
            if not stat.S_ISDIR(row.st_mode): raise ValueError('Unsafe fixed ancestor')
        elif not stat.S_ISREG(row.st_mode):
            raise ValueError('Fixed input is not a regular file')
    if path.resolve().relative_to(BASE.resolve()).as_posix() != relative:
        raise ValueError('Fixed path identity changed')
    return path


def metadata(row):
    # Reading may legitimately change atime; it is not a source identity field.
    return (row.st_dev, row.st_ino, row.st_mode, row.st_nlink, row.st_size,
            row.st_mtime_ns, row.st_ctime_ns)


def read_fixed(relative, expected=None):
    path = fixed_path(relative)
    before = metadata(path.lstat())
    if not 0 < before[4] <= MAX_FILE: raise ValueError('Fixed input byte limit')
    with path.open('rb') as handle:
        opened = metadata(os.fstat(handle.fileno()))
        # On the verified Windows host, ctime and executable-extension mode
        # bits differ between lstat/fstat for the same file. Compare file type
        # across APIs; keep full mode/ctime in each API's own before/after check.
        if os.name == 'nt':
            same_opened = (opened[:2] == before[:2] and
                           stat.S_IFMT(opened[2]) == stat.S_IFMT(before[2]) and
                           opened[3:6] == before[3:6])
        else:
            same_opened = opened == before
        if not same_opened:
            raise ValueError('Fixed opened file identity changed')
        # Full raw bytes are captured before any output mutation.
        raw = handle.read(MAX_FILE + 1)
        if metadata(os.fstat(handle.fileno())) != opened:
            raise ValueError('Fixed opened file changed while read')
    after = metadata(fixed_path(relative).lstat())
    if before != after or len(raw) != before[4]: raise ValueError('Fixed input changed while read')
    if expected is not None and (len(raw), digest(raw)) != expected:
        raise ValueError('Fixed input pin mismatch')
    return raw, before


def exclusive(folder, relative, raw):
    safe_name(relative)
    path = folder.joinpath(*relative.split('/'))
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as handle: handle.write(raw)
    return path


def module_name(value):
    if type(value) is not str or re.fullmatch(r'[a-z][a-z0-9_]*', value) is None:
        raise ValueError('Invalid fixed module role')
    return value


def role_location(domain, name):
    filename = module_name(name) + '.py'
    if domain == 'ordinary' and name != 'mta_go_deployment':
        return 'payload/state/runtime/' + filename, STATE + '/runtime/' + filename, STATE_ALIAS + '/runtime/' + filename
    if domain in ('ordinary', 'go_private'):
        return 'payload/go-assets/runtime/' + filename, GO + '/runtime/' + filename, GO + '/runtime/' + filename
    if domain == 'client_private':
        return 'payload/state/runtime35/' + filename, STATE + '/runtime35/' + filename, STATE_ALIAS + '/runtime35/' + filename
    if domain == 'observer_private':
        return 'payload/observer/runtime/' + filename, OBSERVER + '/runtime/' + filename, '/tmp/p011-mta-go-observer-v85/runtime/' + filename
    raise ValueError('Unknown fixed definition domain')


def main():
    if len(sys.argv) != 1: raise ValueError('This fixed builder accepts no arguments')
    output = None
    output_created = False
    try:
        plan_raw, plan_meta = read_fixed(PLAN[0], PLAN[1:])
        plan = json.loads(plan_raw.decode('utf-8'))
        if (plan['schema'] != 'p011-fixed-source-bundle-inputs-v1' or
                plan['scope'] != SCOPE or plan['gates'] != GATES or
                plan['no_deployment_or_execution'] is not True or
                (plan['role_rows'], plan['unique_role_sources'], plan['unique_fixed_inputs']) != (131, 80, 115) or
                tuple(t['domain'] for t in plan['tables']) != DOMAINS or
                tuple(t['count'] for t in plan['tables']) != COUNTS or len(plan['extras']) != 31):
            raise ValueError('Fixed bundle plan shape')
        inputs = {PLAN[0]: (plan_raw, plan_meta)}
        members, targets, role_sources = {}, {}, set()
        role_count, extra_counts = 0, {}

        def capture(relative, size, sha):
            safe_name(relative)
            if type(size) is not int or not 0 < size <= MAX_FILE or re.fullmatch('[0-9a-f]{64}', sha) is None:
                raise ValueError('Invalid fixed pin')
            if relative not in inputs: inputs[relative] = read_fixed(relative, (size, sha))
            raw = inputs[relative][0]
            if (len(raw), digest(raw)) != (size, sha): raise ValueError('Conflicting source pin')
            return raw

        def add(member, raw, role, source, target=None, alias=None, mode=None):
            safe_name(member)
            if target is not None:
                if target in targets and targets[target] != member:
                    raise ValueError('Conflicting target/member mapping')
                targets[target] = member
            facts = dict(member=member, bytes=len(raw), sha256=digest(raw),
                         target_path=target, target_alias=alias, intended_mode=mode,
                         intended_uid=0 if target is not None else None, roles=[])
            if member in members:
                old_raw, old = members[member]
                if old_raw != raw or any(old[k] != facts[k] for k in ('target_path', 'target_alias', 'intended_mode', 'intended_uid')):
                    raise ValueError('Member collision is not identical')
                facts = old
            else: members[member] = (raw, facts)
            facts['roles'].append(dict(role=role, source=source))

        for table in plan['tables']:
            raw = capture(table['path'], table['bytes'], table['sha256'])
            data = json.loads(raw.decode('utf-8'))
            rows = data['sources']
            if (data['schema'] != table['schema'] or type(rows) is not list or
                    len(rows) != table['count'] or [r['module'] for r in rows] != table['modules'] or
                    len(set(table['modules'])) != table['count']): raise ValueError('Original role table mismatch')
            add('manifests/' + Path(table['path']).name, raw, 'HOST_SOURCE_TABLE_NOT_TARGET_SEAL', table['path'])
            for row in rows:
                if set(row) != {'module', 'path', 'bytes', 'sha256'}: raise ValueError('Role row shape')
                source_raw = capture(row['path'], row['bytes'], row['sha256'])
                member, target, alias = role_location(table['domain'], row['module'])
                add(member, source_raw, table['domain'] + ':' + row['module'], row['path'], target, alias, '0400')
                role_count += 1; role_sources.add(row['path'])
        for row in plan['extras']:
            raw = capture(row['path'], row['bytes'], row['sha256'])
            kind = row['kind']; extra_counts[kind] = extra_counts.get(kind, 0) + 1
            if kind == 'native':
                name = row['native_name']
                if name not in ('mta-bluez-helper', 'mta-network-helper', 'mta-wpa-supplicant'):
                    raise ValueError('Native name outside whitelist')
                add('payload/state/native/' + name, raw, 'native:state:' + name, row['path'], STATE + '/native/' + name, STATE_ALIAS + '/native/' + name, '0500')
                if name == 'mta-wpa-supplicant':
                    add('payload/go-assets/native/' + name, raw, 'native:go:' + name, row['path'], GO + '/native/' + name, GO + '/native/' + name, '0500')
            elif kind == 'frontend':
                if not row['path'].startswith('device/'): raise ValueError('Frontend path outside whitelist')
                add('frontend/' + row['path'], raw, 'UNATTACHED_FRONTEND_SOURCE_ONLY', row['path'])
            elif kind in ('archival_source', 'wpa_corresponding_material'):
                add('materials/' + row['path'], raw, 'ARCHIVAL_SOURCE_ONLY_DO_NOT_RUN', row['path'])
            else: raise ValueError('Unknown additional input kind')
        if (role_count != 131 or len(role_sources) != 80 or len(inputs) - 1 != 115 or
                extra_counts != dict(native=3, frontend=6, archival_source=9, wpa_corresponding_material=13)):
            raise ValueError('Fixed input count mismatch')
        own = 'host/build_fixed_source_bundle.py'
        inputs[own] = read_fixed(own)
        inputs[CMD[0]] = read_fixed(CMD[0], CMD[1:])
        add('manifests/mta_fixed_source_bundle_v1_inputs.json', plan_raw, 'HOST_BUNDLE_RECIPE_NOT_TARGET_SEAL', PLAN[0])
        add('materials/package-tools/build_fixed_source_bundle.py', inputs[own][0], 'ARCHIVAL_PC_BUILDER_SOURCE_ONLY', own)
        add('materials/package-tools/' + CMD[0], inputs[CMD[0]][0], 'ARCHIVAL_PC_BUILDER_SOURCE_ONLY', CMD[0])
        if len(inputs) != 118 or sum(len(v[0]) for v in inputs.values()) > MAX_INPUT_BYTES:
            raise ValueError('Fixed snapshot byte/count limit')
        catalog = dict(schema='p011-fixed-source-bundle-catalog-v1', scope=SCOPE,
                       gates=GATES, role_rows=131, unique_role_source_files=80,
                       runtime_members=130, native_source_files=3, native_target_members=4,
                       frontend_source_files=6, source_material_files=22,
                       fixed_input_files=115, snapshots=118, candidate_invocations=0,
                       ast_parses=0, deployment_actions=0, target_manifest_seal_issued=False,
                       notes=list(NOTES), catalog_self_and_scope_readme_excluded_from_member_list=True,
                       members=[v[1] for v in members.values()],
                       directory_intentions=[dict(path=p, mode='0700', uid=0) for p in
                           (STATE, STATE + '/runtime', STATE + '/runtime35', STATE + '/native',
                            GO, GO + '/runtime', GO + '/native', OBSERVER, OBSERVER + '/runtime')],
                       inputs=[dict(path=p, bytes=len(v[0]), sha256=digest(v[0])) for p, v in inputs.items()])
        catalog_raw = encoded(catalog)
        add('CATALOG.json', catalog_raw, 'GENERATED_STATIC_CATALOG', None)
        readme = ('# MTA fixed source bundle v1\n\n'
                  '范围：离线固定源资产候选，不是可运行发行、安装器或完整收发验收。\n'
                  '131角色 / 80不同源码；同目标同字节角色合并，跨域源码不可扁平覆盖。\n'
                  '四张HOST原表不等于生产source-manifest封印；Pub seal仍None。\n'
                  '未部署、未启动、未运行测试或AST；service/admission/RF/QMLhandoff/device/phone/restore均False。\n'
                  'payload路径和CATALOG权限只是源契约安装意图，不会自动写设备。\n'
                  'frontend/device保持原六件，未接装；不自动执行任何START、源码构建、helper或PC工具。\n'
                  'materials中的脚本只作历史SOURCE材料；build_native --collect会访问ADB，不得自动运行。\n'
                  '不采集目标Python/vendor链接库、用户文件、现场凭据/私钥、profile/journal/pending/raw；上游源归档保持原字节。\n'
                  'Parent启动/pipe flags路径的目标fcntl依赖尚未适配；没有本次部署器。\n'
                  'ZIP读回只验证打包字节/CRC/SHA，不能签设备准入、真实手机或恢复。\n')
        add('README.md', readme.encode('utf-8'), 'GENERATED_SCOPE_NOTICE', None)
        if len(members) != 171 or len(members) > MAX_MEMBERS:
            raise ValueError('Fixed archive member count')
        result_root = fixed_path('results', file=False)
        output = result_root / ('mta-fixed-source-bundle-v1-' + datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex)
        output.mkdir()  # Exclusive UUID namespace; no existing result is changed.
        output_created = True
        for relative, (raw, _) in inputs.items(): exclusive(output, 'private-inputs/' + relative, raw)
        archive = output / 'mta-fixed-source-bundle-v1.zip'
        with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as bundle:
            for member, (raw, _) in members.items():
                info = zipfile.ZipInfo(member)
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o644) << 16  # Archive data, not installer permissions.
                info.compress_type = zipfile.ZIP_DEFLATED
                bundle.writestr(info, raw)
        with zipfile.ZipFile(archive, 'r') as bundle:
            if bundle.namelist() != list(members) or bundle.testzip() is not None:
                raise ValueError('ZIP membership/CRC failure')
            for member, (raw, _) in members.items():
                info = bundle.getinfo(member); actual = bundle.read(member)
                if actual != raw or info.file_size != len(raw) or info.CRC != zlib.crc32(raw) & 0xffffffff or digest(actual) != digest(raw):
                    raise ValueError('ZIP byte/size/CRC/SHA readback failure')
        # Verify original workspace identity AND exact snapshots after all ZIP IO.
        for relative, (raw, original_meta) in inputs.items():
            current, current_meta = read_fixed(relative, (len(raw), digest(raw)))
            saved = fixed_path('results/' + output.name + '/private-inputs/' + relative).read_bytes()
            if current != raw or current_meta != original_meta or saved != raw:
                raise ValueError('Post-build source/snapshot identity changed')
        result = dict(schema='p011-fixed-source-bundle-result-v1', scope=SCOPE,
                      packaging_passed=True, gates=GATES, role_rows=131,
                      unique_role_sources=80, snapshots=118, archive_members=171,
                      builder_invocations=1, candidate_invocations=0,
                      candidate_runtime_invocations=0, test_invocations=0, native_invocations=0, ast_parses=0,
                      crc_verified=True, all_members_byte_hash_verified=True,
                      source_identity_pre_post_verified=True, archive_bytes=archive.stat().st_size,
                      archive_sha256=digest(archive.read_bytes()), archive_name=archive.name,
                      builder_sha256=digest(inputs[own][0]), cmd_sha256=CMD[2], input_manifest_sha256=PLAN[2])
        exclusive(output, 'result.json', encoded(result))
        print('RESULT=' + str(output / 'result.json'))
        print('SOURCE_BUNDLE=' + str(archive))
        print('ZIP_SHA256=' + result['archive_sha256'])
        return 0
    except BaseException:
        failure = traceback.format_exc().encode('utf-8')
        sys.stderr.buffer.write(failure)
        if output_created:
            # Partial UUID outputs remain recoverable; no cleanup or old-log rewrite.
            try:
                exclusive(output, 'failure.private.txt', failure)
            except BaseException:
                print('PRIVATE_FAILURE_COPY_FAILED_ORIGINAL_STDERR_RETAINED', file=sys.stderr)
        print('FIXED_SOURCE_BUNDLE_FAILED_NO_DEPLOYMENT', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
