#!/usr/bin/env python3
"""Actual host-filesystem alias fixtures; no P011 device or real menu path used."""
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import json

package = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(package / 'runtime'))
spec = importlib.util.spec_from_file_location('test_menu_trial_subject', str(package / 'runtime/menu_trial.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
CURRENT = 'aaaaaaaa-1111-2222-3333-444444444444'
OLD = 'bbbbbbbb-1111-2222-3333-444444444444'
m.boot_id = lambda: CURRENT
rows = []

def fixture(kind, mode='missing', ref=False, canonical=False):
    with tempfile.TemporaryDirectory(prefix='p011-alias-v043-') as temp:
        base = Path(temp)
        realtmp = base/'volatile'/'tmp'; realtmp.mkdir(parents=True)
        tmp = base/'tmp'; tmp.symlink_to(realtmp, target_is_directory=True)
        name = 'p011-menutest-20260915-132436717'
        session = (realtmp if canonical else tmp)/name
        alias = base/'menu';lock = base/'lock'
        m.ROOT = str(realtmp/'p011-menutest-20260915-999999999')
        m.LOGS = str(base/'result'); Path(m.LOGS).mkdir()
        m.P.MENU_LINK, m.P.LOCK = str(alias), str(lock)
        procs = []
        if mode != 'missing':
            (session/'logs').mkdir(parents=True)
            (session/'pages').mkdir()
            if mode != 'unknown':
                (session/'logs/boot-id.txt').write_text(OLD if mode == 'old' else CURRENT)
            if mode == 'done':(session/'logs/finished').write_text('RESTORED\n')
            if mode == 'failed':(session/'logs/finished').write_text('RECOVERY_NEEDS_ATTENTION\n')
        if kind == 'none': pass
        elif kind == 'directory':alias.mkdir();(alias/'keep.txt').write_text('keep')
        elif kind == 'file':alias.write_text('keep')
        elif kind == 'foreign':alias.symlink_to(base/'foreign')
        elif kind == 'relative':alias.symlink_to('tmp/'+name+'/pages')
        elif kind == 'traversal':alias.symlink_to(str(tmp)+'/../tmp/'+name+'/pages')
        elif kind == 'wrong-name':alias.symlink_to(tmp/'p011-menutest-guess'/'pages')
        elif kind == 'wrong-suffix':alias.symlink_to(session/'notpages')
        else:
            alias.symlink_to(session/'pages')
        if kind == 'nonroot':os.lchown(str(alias), 12345, 12345)
        if kind == 'redirect':
            (session/'pages').rmdir();(base/'outside').mkdir();(session/'pages').symlink_to(base/'outside')
        if kind == 'log-redirect':
            (session/'logs/boot-id.txt').unlink();(session/'logs').rmdir()
            (base/'outside').mkdir();(session/'logs').symlink_to(base/'outside')
        if kind == 'bad-boot-file':
            (session/'logs/boot-id.txt').unlink();(session/'logs/boot-id.txt').symlink_to(base/'outside')
        if ref:
            procs.append({'pid': 999998, 'start': 31, 'sid': 999998, 'state': 'S', 'threads': 1,
                          'exe': '/usr/bin/python3.5', 'args': [str(session/'menu_trial.py'), 'guardian']})
        if kind == 'private-child':
            (session/'logs/candidate.ident').write_text('999997 30\n')
            procs.append({'pid':999996,'start':32,'sid':999997,'state':'S','threads':1,
                          'exe':'/usr/lib/QtWebEngineProcess','args':[]})
        out = m.describe_trial_alias(str(alias), '/pages', procs, str(tmp))
        return out, str(alias)

cases = [
 ('absent', 'none','missing',False,False,'absent'),
 ('literal dangling','link','missing',False,False,'remove_dangling_managed_alias'),
 ('canonical dangling','link','missing',False,True,'remove_dangling_managed_alias'),
 ('old literal session','link','old',False,False,'remove_previous_boot_managed_alias'),
 ('old canonical session','link','old',False,True,'remove_previous_boot_managed_alias'),
 ('same boot restored','link','done',False,False,'remove_finished_managed_alias'),
 ('same boot failed','link','failed',False,False,'preserve_unfinished_same_boot_session'),
 ('same boot pending','link','current',False,False,'preserve_unfinished_same_boot_session'),
 ('unknown boot','link','unknown',False,False,'preserve_unknown_boot'),
 ('real dir','directory','missing',False,False,'preserve_non_symlink'),
 ('regular file','file','missing',False,False,'preserve_non_symlink'),
 ('foreign','foreign','missing',False,False,'preserve_wrong_suffix'),
 ('relative','relative','missing',False,False,'preserve_noncanonical_target'),
 ('traversal','traversal','missing',False,False,'preserve_noncanonical_target'),
 ('wrong name','wrong-name','missing',False,False,'preserve_foreign_target'),
 ('wrong suffix','wrong-suffix','missing',False,False,'preserve_wrong_suffix'),
 ('nonroot','nonroot','old',False,False,'preserve_non_root_owned'),
 ('live old session','link','old',True,False,'preserve_live_session'),
 ('live restored session','link','done',True,False,'preserve_live_session'),
 ('page redirect','redirect','old',False,False,'preserve_page_redirect'),
 ('log redirect','log-redirect','old',False,False,'preserve_unsafe_log_directory'),
 ('boot file redirect','bad-boot-file','old',False,False,'preserve_unknown_boot'),
 ('private child','private-child','done',False,False,'preserve_live_session'),
]
for label,kind,mode,ref,canonical,expected in cases:
    out,_=fixture(kind,mode,ref,canonical)
    assert out['decision'] == expected, (label, expected, out)
    rows.append({'case':label,'passed':True,'decision':out['decision']})

# Actual unlink, snapshot, target preservation, and all-or-none conflict behavior.
for block in (False,True):
    with tempfile.TemporaryDirectory(prefix='p011-alias-unlink-') as temp:
        base=Path(temp);tmp=base/'tmp';tmp.mkdir();old=tmp/'p011-menutest-20260915-111111111'
        (old/'logs').mkdir(parents=True);(old/'pages').mkdir();(old/'pages/keep.txt').write_text('preserve target')
        (old/'logs/boot-id.txt').write_text(OLD)
        logs=base/'logs';logs.mkdir();m.ROOT=str(tmp/'p011-menutest-20260915-222222222');m.LOGS=str(logs)
        m.P.MENU_LINK=str(base/'menu');m.P.LOCK=str(base/'lock')
        os.symlink(str(old/'pages'),m.P.MENU_LINK)
        if block:Path(m.P.LOCK).mkdir()
        original = m.describe_trial_alias
        m.describe_trial_alias=lambda a,s,p:original(a,s,p,str(tmp))
        m.processes=lambda:[]
        try:
            if block:
                try:m.cleanup_previous_boot_aliases([]);raise AssertionError('conflict not refused')
                except RuntimeError as e:assert 'already exists' in str(e)
                assert os.path.islink(m.P.MENU_LINK)
                assert Path(m.P.LOCK).is_dir()
            else:
                m.cleanup_previous_boot_aliases([])
                assert not os.path.lexists(m.P.MENU_LINK)
            assert (old/'pages/keep.txt').read_text()=='preserve target'
            report=json.loads((logs/'path-preflight.json').read_text())
            assert report['stock_topology_verified']
            rows.append({'case':'conflict preserves all' if block else 'unlink only managed alias','passed':True})
        finally:m.describe_trial_alias=original

out=package/'tests/v043-alias-results.json'
out.write_text(json.dumps({'scope':'Host filesystem fixtures, no Windows/P011 execution','count':len(rows),
                           'all_passed':True,'cases':rows},ensure_ascii=False,indent=2))
print('PASS',len(rows),'alias cases')
