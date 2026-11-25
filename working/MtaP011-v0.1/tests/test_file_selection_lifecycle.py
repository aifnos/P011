"""Synthetic file-selection IO only; no real file open, socket or device."""
import ast
import errno
import importlib.util
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import types
import unittest
from unittest.mock import patch

BASE=Path(__file__).absolute().parents[1]
sys.path.insert(0,str(BASE/'runtime'))
import mta_files as f
SOURCE=(BASE/'runtime/mta_files.py').read_bytes()
spec=importlib.util.spec_from_file_location('selection_legacy_files_tests',BASE/'tests/test_files.py')
legacy=importlib.util.module_from_spec(spec);spec.loader.exec_module(legacy)


class Handle(object):
    mode='rb'
    def __init__(self,fs,fd):
        self.fs,self.fd=fs,fd;self._closed=False;self.calls=0;self.behavior='normal';self.closed_error=False
    @property
    def closed(self):
        if self.closed_error:raise ValueError('SYNTHETIC_PRIVATE')
        return self._closed
    def fileno(self):
        if self._closed:raise ValueError('closed')
        return self.fd
    def readable(self):return True
    def writable(self):return False
    def read(self):return self.fs.opened[self.fd]['data']
    def close(self):
        self.calls+=1
        if self.behavior=='raise_open':raise OSError(errno.EIO,'SYNTHETIC_PRIVATE')
        if self.behavior=='keep_open':return
        if self.behavior=='bool_only':self._closed=True;return
        self._closed=True;self.fs.close(self.fd)
        if self.behavior=='raise_closed':raise OSError(errno.EIO,'SYNTHETIC_PRIVATE')
        if self.behavior=='interrupt_closed':raise KeyboardInterrupt()
        if self.behavior=='bad_return':return False


class FakeFs(object):
    def __init__(self):
        self.root=os.path.abspath(os.path.join(os.sep,'synthetic-selection-user'))
        self.category=os.path.join(self.root,'Text')
        self.nodes={};self.opened={};self.handles=[];self.close_calls=[];self.open_calls=[]
        self.fd=10;self.ident=100;self.ids=0;self.fstat_calls=[]
        self.open_error=None;self.open_result=None;self.fdopen_behavior=None;self.fstat_errors=[];self.close_error=None
        self.foreign=None
        self.add('a.txt',b'abc');self.add('b.txt',b'def')
    def add(self,name,data,mode=None):
        self.ident+=1
        path=os.path.join(self.category,name)
        self.nodes[path]={'data':data,'mode':stat.S_IFREG|0o600 if mode is None else mode,'inode':self.ident,'stamp':100}
        return path
    def metadata(self,node):
        return types.SimpleNamespace(st_dev=1,st_ino=node['inode'],st_size=len(node['data']),st_mtime_ns=node['stamp'],st_mode=node['mode'])
    def isdir(self,path):return path in (self.root,self.category)
    def islink(self,path):return path in self.nodes and stat.S_ISLNK(self.nodes[path]['mode'])
    def check(self,path):
        if path!=self.root and not path.startswith(self.root+os.sep):raise ValueError('outside synthetic root')
        if self.islink(path):raise ValueError('symlink')
    def walk(self,path,followlinks=False):
        yield path,[],sorted(os.path.basename(p) for p in self.nodes if os.path.dirname(p)==path)
    def lstat(self,path):
        if path not in self.nodes:raise OSError(errno.ENOENT,'synthetic')
        return self.metadata(self.nodes[path])
    def uuid(self):
        self.ids+=1;return types.SimpleNamespace(hex='%032x'%self.ids)
    def open(self,path,flags):
        self.open_calls.append((path,flags))
        if self.open_error:raise self.open_error
        if self.open_result is not None:return self.open_result
        self.fd+=1;self.opened[self.fd]=dict(self.nodes[path]);return self.fd
    def fstat(self,fd):
        self.fstat_calls.append(fd)
        if self.fstat_errors:raise self.fstat_errors.pop(0)
        if fd not in self.opened:raise OSError(errno.EBADF,'synthetic')
        return self.metadata(self.opened[fd])
    def fdopen(self,fd,mode):
        if self.fdopen_behavior=='raise_before':raise OSError(errno.ENOMEM,'SYNTHETIC_PRIVATE')
        if self.fdopen_behavior=='reused_raise':
            self.close(fd);self.opened[fd]={'data':b'FOREIGN','mode':stat.S_IFREG|0o600,'inode':999,'stamp':100}
            raise ValueError('SYNTHETIC_PRIVATE')
        if self.fdopen_behavior=='malformed_none':return None
        if self.fdopen_behavior=='malformed_foreign':return self.foreign
        handle=Handle(self,fd);self.handles.append(handle);return handle
    def close(self,fd):
        self.close_calls.append(fd)
        if self.close_error:raise self.close_error
        if fd not in self.opened:raise OSError(errno.EBADF,'synthetic')
        del self.opened[fd]


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.fs=FakeFs()
        callbacks={'open':self.fs.open,'fstat':self.fs.fstat,'fdopen':self.fs.fdopen,'close':self.fs.close,
            'lstat':self.fs.lstat,'walk':self.fs.walk}
        for name,callback in callbacks.items():
            blocker=patch.object(os,name,side_effect=callback);blocker.start();self.addCleanup(blocker.stop)
        for name in ('mkdir','makedirs','unlink','remove','rmdir','rename','replace','symlink','kill','waitpid','urandom'):
            blocker=patch.object(os,name,side_effect=AssertionError('actual OS forbidden'));blocker.start();self.addCleanup(blocker.stop)
        for target in ('socket.socket','subprocess.run','subprocess.Popen'):
            blocker=patch(target,side_effect=AssertionError('actual external IO forbidden'));blocker.start();self.addCleanup(blocker.stop)
        for name,callback in (('isdir',self.fs.isdir),('islink',self.fs.islink)):
            blocker=patch.object(os.path,name,side_effect=callback);blocker.start();self.addCleanup(blocker.stop)
        for target,callback in ((f,'_check_no_symlinks'),):
            blocker=patch.object(target,callback,side_effect=self.fs.check);blocker.start();self.addCleanup(blocker.stop)
        blocker=patch.object(f.uuid,'uuid4',side_effect=self.fs.uuid);blocker.start();self.addCleanup(blocker.stop)
        self.registry=f.FileRegistry(self.fs.root)
    def rows(self):return self.registry.list_files()
    def select(self,count=1):return self.registry.open_selection([r['id'] for r in self.rows()[:count]])
    def pending(self):
        status=self.registry.lifecycle_status();self.assertTrue(status['resource_pending']);self.assertFalse(status['closure_verified'])
        before=list(self.fs.open_calls)
        with self.assertRaises(ValueError):self.registry.open_selection([r['id'] for r in self.rows()])
        self.assertEqual(before,self.fs.open_calls)
        self.assertNotIn('SYNTHETIC_PRIVATE',json.dumps(status));self.assertNotIn(self.fs.root,json.dumps(status))
        return status
    def assert_repeat_no_io(self,selection):
        before=(list(self.fs.close_calls),list(self.fs.fstat_calls),[h.calls for h in self.fs.handles])
        with self.assertRaises(ValueError):selection.close()
        self.assertEqual(before,(self.fs.close_calls,self.fs.fstat_calls,[h.calls for h in self.fs.handles]))

    def test_python35_syntax_and_exact_status_without_user_data(self):
        ast.parse(SOURCE.decode('utf-8'),feature_version=(3,5))
        selection=self.select();status=selection.lifecycle_status()
        self.assertEqual({'resource_count','open_attempt_count','close_attempted_count','wrapper_closed_count','fd_closed_count','unknown_count','resource_pending','closure_verified','close_requested','selection_closed'},set(status))
        for key in ('resource_count','open_attempt_count','close_attempted_count','wrapper_closed_count','fd_closed_count','unknown_count'):self.assertIs(type(status[key]),int)
        for key in ('resource_pending','closure_verified','close_requested','selection_closed'):self.assertIs(type(status[key]),bool)
        self.assertFalse(status['closure_verified']);selection.close();self.assertTrue(selection.lifecycle_status()['closure_verified'])
    def test_normal_two_original_handles_close_and_repeat_is_idle(self):
        selection=self.select(2);self.assertEqual(6,selection.total_bytes)
        selection.close();self.assertEqual({},self.fs.opened)
        self.assertTrue(selection.closed);self.assertEqual([1,1],[h.calls for h in self.fs.handles])
        before=(list(self.fs.close_calls),list(self.fs.fstat_calls));selection.close();self.assertEqual(before,(self.fs.close_calls,self.fs.fstat_calls))
        self.assertTrue(self.registry.lifecycle_status()['closure_verified'])
    def test_fstat_error_closes_raw_once_before_wrapper(self):
        self.fs.fstat_errors=[OSError(errno.EIO,'SYNTHETIC_PRIVATE')]
        with self.assertRaises(OSError):self.select()
        self.assertEqual([11],self.fs.close_calls);self.assertEqual({},self.fs.opened)
        self.assertEqual([],self.fs.handles);self.assertTrue(self.registry.lifecycle_status()['closure_verified'])
    def test_initial_ebadf_does_not_close_unknown_or_reused_number(self):
        self.fs.fstat_errors=[OSError(errno.EBADF,'synthetic')]
        with self.assertRaises(OSError):self.select()
        self.assertEqual([],self.fs.close_calls);self.pending()
    def test_fstat_mismatch_closes_raw_once_and_all_prior_handles(self):
        ids=[r['id'] for r in self.rows()]
        original=self.fs.fstat
        def observed(fd):
            value=original(fd)
            if fd==12:value.st_ino+=1
            return value
        with patch.object(os,'fstat',side_effect=observed):
            with self.assertRaises(ValueError):self.registry.open_selection(ids)
        self.assertEqual({11,12},set(self.fs.close_calls));self.assertEqual({},self.fs.opened)
        self.assertEqual(1,self.fs.handles[0].calls);self.assertTrue(self.registry.lifecycle_status()['closure_verified'])
    def test_negative_open_errno_known_absence_not_sticky_unknown(self):
        self.fs.open_error=OSError(errno.EACCES,'synthetic')
        with self.assertRaises(OSError):self.select()
        self.assertEqual([],self.fs.close_calls);self.assertEqual([],self.registry._resources)
        self.assertFalse(self.registry.lifecycle_status()['resource_pending'])
    def test_interrupted_open_registered_before_callback_blocks_new(self):
        self.fs.open_error=KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):self.select()
        self.assertEqual([],self.fs.close_calls);self.pending()
        ticket=self.registry._resources[0];self.assertIs(ticket._open,os.open);self.assertIs(ticket._open.side_effect.__self__,self.fs)
    def test_malformed_fd_return_never_closes_foreign_integer(self):
        for returned in (True,-1,'PRIVATE',object()):
            self.fs.open_result=returned
            registry=f.FileRegistry(self.fs.root);rows=registry.list_files()
            with self.assertRaises(ValueError):registry.open_selection([rows[0]['id']])
            self.assertTrue(registry.lifecycle_status()['resource_pending']);self.assertIs(registry._resources[0].fd,returned)
        self.assertEqual([],self.fs.close_calls)
    def test_fdopen_raise_holds_raw_and_prior_closure_is_independent(self):
        original=self.fs.fdopen
        def claim(fd,mode):
            if fd==12:raise OSError(errno.ENOMEM,'SYNTHETIC_PRIVATE')
            return original(fd,mode)
        with patch.object(os,'fdopen',side_effect=claim):
            with self.assertRaises(OSError):self.select(2)
        self.assertEqual([11],self.fs.close_calls);self.assertEqual({12},set(self.fs.opened));self.pending()
    def test_fdopen_unknown_reuse_never_raw_closes_foreign_fd(self):
        self.fs.fdopen_behavior='reused_raise'
        with self.assertRaises(ValueError):self.select()
        self.assertEqual([11],self.fs.close_calls);self.assertEqual(b'FOREIGN',self.fs.opened[11]['data']);self.pending()
    def test_malformed_none_wrapper_preserves_exact_unknown(self):
        self.fs.fdopen_behavior='malformed_none'
        with self.assertRaises(ValueError):self.select()
        self.assertEqual([],self.fs.close_calls);self.assertIsNone(self.registry._resources[0].handle);self.pending()
    def test_malformed_foreign_wrapper_is_retained_but_never_closed(self):
        foreign=Handle(self.fs,99);self.fs.foreign=foreign;self.fs.fdopen_behavior='malformed_foreign'
        with self.assertRaises(ValueError):self.select()
        self.assertIs(foreign,self.registry._resources[0].handle);self.assertEqual(0,foreign.calls)
        self.assertEqual([],self.fs.close_calls);self.pending()
    def test_first_close_error_attempts_every_original_and_stays_unknown(self):
        selection=self.select(2);self.fs.handles[0].behavior='raise_open'
        with self.assertRaises(ValueError):selection.close()
        self.assertEqual([1,1],[h.calls for h in self.fs.handles]);self.assertTrue(selection.closed)
        status=selection.lifecycle_status();self.assertEqual(2,status['close_attempted_count']);self.assertEqual(1,status['fd_closed_count'])
        self.assertFalse(status['closure_verified']);self.pending();self.assert_repeat_no_io(selection)
    def test_closed_bool_and_ebadf_do_not_erase_close_exception(self):
        selection=self.select(2);self.fs.handles[0].behavior='raise_closed'
        with self.assertRaises(ValueError):selection.close()
        status=selection.lifecycle_status();self.assertEqual(2,status['wrapper_closed_count']);self.assertEqual(2,status['fd_closed_count'])
        self.assertTrue(status['resource_pending']);self.assertFalse(status['closure_verified'])
        self.pending();self.assert_repeat_no_io(selection)
    def test_keyboard_interrupt_close_still_attempts_later_handle(self):
        selection=self.select(2);self.fs.handles[0].behavior='interrupt_closed'
        with self.assertRaises(ValueError):selection.close()
        self.assertEqual([1,1],[h.calls for h in self.fs.handles]);self.pending();self.assert_repeat_no_io(selection)
    def test_closed_bool_with_live_fd_is_not_proof(self):
        selection=self.select();self.fs.handles[0].behavior='bool_only'
        with self.assertRaises(ValueError):selection.close()
        status=selection.lifecycle_status();self.assertEqual(1,status['wrapper_closed_count']);self.assertEqual(0,status['fd_closed_count'])
        self.pending();self.assert_repeat_no_io(selection)
    def test_bad_close_return_is_sticky_despite_actual_closed_observations(self):
        selection=self.select();self.fs.handles[0].behavior='bad_return'
        with self.assertRaises(ValueError):selection.close()
        self.assertFalse(selection.lifecycle_status()['closure_verified']);self.pending()
    def test_post_close_fstat_error_sticky_and_status_is_cached(self):
        selection=self.select();self.fs.fstat_errors=[OSError(errno.EIO,'SYNTHETIC_PRIVATE')]
        with self.assertRaises(ValueError):selection.close()
        before=list(self.fs.fstat_calls);selection.lifecycle_status();self.registry.lifecycle_status()
        self.assertEqual(before,self.fs.fstat_calls);self.pending();self.assert_repeat_no_io(selection)
    def test_mutated_public_entries_cannot_drop_original_resource_owner(self):
        selection=self.select(2);selection.entries.clear();selection.close()
        self.assertEqual({},self.fs.opened);self.assertEqual([1,1],[h.calls for h in self.fs.handles])
        self.assertTrue(selection.lifecycle_status()['closure_verified'])
    def test_total_limit_failure_rolls_back_all_known_handles_once(self):
        with patch.object(f,'MAX_TOTAL',1):
            with self.assertRaises(ValueError):self.select(2)
        self.assertEqual({},self.fs.opened);self.assertEqual([1,1],[h.calls for h in self.fs.handles])
        self.assertTrue(self.registry.lifecycle_status()['closure_verified'])
    def test_readonly_wrapper_validation_does_not_close_unknown_transfer(self):
        original=self.fs.fdopen
        def bad(fd,mode):
            handle=original(fd,mode);handle.mode='wb';return handle
        with patch.object(os,'fdopen',side_effect=bad):
            with self.assertRaises(ValueError):self.select()
        self.assertEqual([],self.fs.close_calls);self.assertEqual(0,self.fs.handles[0].calls);self.pending()
    def test_legacy_named_opaque_select_with_fake_io(self):
        # Original method, but no legacy setUp/tempfile is run.
        self.fs.nodes.pop(os.path.join(self.fs.category,'b.txt'))
        case=legacy.FileTests('test_opaque_select');case.registry=self.registry
        legacy.FileTests.test_opaque_select(case)
    def test_legacy_named_no_paths_or_duplicates_with_fake_io(self):
        case=legacy.FileTests('test_no_paths_or_duplicates');case.registry=self.registry
        legacy.FileTests.test_no_paths_or_duplicates(case)
        self.assertEqual([],self.fs.open_calls)
    def test_legacy_named_modified_with_fake_io(self):
        self.fs.nodes.pop(os.path.join(self.fs.category,'b.txt'))
        case=legacy.FileTests('test_modified');case.registry=self.registry;case.root=Path(self.fs.root)
        def write(path,data):self.fs.nodes[str(path)]['data']=data;return len(data)
        with patch.object(Path,'write_bytes',write):legacy.FileTests.test_modified(case)
        self.assertEqual([],self.fs.open_calls)


if __name__=='__main__':unittest.main()
