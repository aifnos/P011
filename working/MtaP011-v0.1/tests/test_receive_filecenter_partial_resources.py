"""One new HOST retained partial-resource method, no QML/old tests/device.

Actual FileStore opens, sockets, threads and close observations. OSError/fdopen,
cap allocation, semaphore and audio stop failures are explicit fault models.
One numeric regular-file FD models the target rootfd cleanup branch; it is not
P011 directory FD/authentication or original Owner/restore acceptance.
"""
import errno
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest import mock
import urllib.request
import json
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'integration/ToolboxMta-v0.1/runtime'))
sys.path.insert(0,str(ROOT/'candidate/receive-filecenter-v1/runtime'))
import mta_filecenter_storage as S
import mta_filecenter_companion as C
import mta_toolbox_minhttp as HTTP

class PartialResourceTests(unittest.TestCase):
 def test_new_partial_known_resources(self):
  cases=[]
  with tempfile.TemporaryDirectory(prefix='p011-filecenter-partial-host-') as temporary:
   root=Path(temporary)
   def start(name):
    folder=root/name;folder.mkdir()
    value=C._Companion(str(folder),float(time.monotonic()+25),lambda:True)
    (folder/'Received'/'a.png').write_bytes(b'HOST image bytes')
    return value
   value=start('normal')
   try:
    opened=value.open_file('Received/a.png')
    with urllib.request.urlopen(opened['url'],timeout=3) as reply:
     self.assertEqual(b'HOST image bytes',reply.read())
    self.assertGreater(len(value.state.store.open_rows),0)
   finally:self.assertTrue(value.close());self.assertTrue(value.state.store.opens_closed())
   cases.append('new_retained_store_normal_media_http')

   value=start('fstat');original_fstat=os.fstat;count=[]
   def fail_first(fd):
    count.append(fd)
    if len(count)==1:raise OSError(errno.EIO,'HOST injected fstat')
    return original_fstat(fd)
   try:
    with mock.patch.object(S.os,'fstat',side_effect=fail_first):
     self.assertRaises(OSError,value.state.store.open_file,'Received/a.png')
    row=value.state.store.open_rows[-1]
    self.assertTrue(row['returned']);self.assertTrue(row['close_called']);self.assertTrue(row['closed'])
    self.assertTrue(S.fd_closed(row['fd']))
   finally:self.assertTrue(value.close())
   cases.append('fstat_failure_keeps_and_closes_known_numeric_fd')

   value=start('fdopen')
   def consumed_failure(fd,mode):
    os.close(fd);raise RuntimeError('HOST wrapping outcome unknown')
   try:
    with mock.patch.object(S.os,'fdopen',side_effect=consumed_failure):
     self.assertRaises(RuntimeError,value.state.store.open_file,'Received/a.png')
    row=value.state.store.open_rows[-1]
    self.assertTrue(row['wrap_unknown']);self.assertTrue(row['closed'])
    self.assertFalse(value.state.store.opens_closed())
   finally:self.assertFalse(value.close());self.assertFalse(value.closed())
   cases.append('unknown_fdopen_outcome_never_claims_full_close')

   value=C._Companion.__new__(C._Companion);marker=RuntimeError('HOST semaphore ctor')
   folder=root/'server';folder.mkdir()
   with mock.patch.object(HTTP.threading,'BoundedSemaphore',side_effect=marker):
    with self.assertRaises(RuntimeError):C._Companion.__init__(value,str(folder),float(time.monotonic()+25),lambda:True)
   self.assertIs(marker,value.failure);self.assertIsNotNone(value.server.socket)
   self.assertNotEqual(-1,value.server.socket.fileno())
   self.assertFalse(value.close());self.assertEqual(-1,value.server.socket.fileno())
   self.assertIs(marker,value.failure)
   cases.append('partial_server_listener_closed_original_failure_retained')

   value=start('audio');fd=os.open(str(root/'audio'/'Received'/'a.png'),os.O_RDONLY)
   # Explicit HOST rootfd slot model; actual numeric FD closes, not root auth.
   value.state.store.rootfd=value.original_rootfd=fd
   first=RuntimeError('HOST original first failure');stop=RuntimeError('HOST audio stop')
   value.failure=first
   with mock.patch.object(value.audio,'stop_audio',side_effect=stop):
    self.assertFalse(value.close())
   self.assertIs(first,value.failure);self.assertIn(stop,value.cleanup_failures)
   self.assertIsNone(value.state.store.rootfd);self.assertTrue(S.fd_closed(fd))
   self.assertFalse(value.thread.is_alive());self.assertEqual(-1,value.socket_original.fileno())
   cases.append('audio_stop_failure_does_not_skip_known_rootfd_or_listener')

   value=start('media');marker=RuntimeError('HOST cap allocation')
   try:
    with mock.patch.object(C.os,'urandom',side_effect=marker):
     self.assertRaises(RuntimeError,value.open_file,'Received/a.png')
    row=value.media[-1];self.assertIsNotNone(row['handle']);self.assertFalse(row['handle'].closed)
    self.assertIs(marker,row['error']);self.assertFalse(row['valid'])
   finally:
    self.assertTrue(value.close());self.assertTrue(row['closed']);self.assertTrue(row['handle'].closed)
    self.assertTrue(value.state.store.opens_closed())
   cases.append('post_open_cap_failure_keeps_and_closes_original_handle')
  self.assertEqual(6,len(cases));print('RECEIVE_FILECENTER_PARTIAL_RESOURCE_CONTRACTS=6')
if __name__=='__main__':unittest.main(verbosity=0)
