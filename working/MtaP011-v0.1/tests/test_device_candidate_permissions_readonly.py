"""HOST-only permission evidence contracts; no device/permission changes."""
import ast
import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
import stat
import sys
import tempfile
import types
import unittest
from unittest import mock
import zipfile

PROJECT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(PROJECT / "host"))
sys.path.insert(0,str(PROJECT / "runtime"))
import device_candidate_permissions_readonly as checker
from tests import test_device_prior_journal_readonly as old_tests
from tests import test_device_p2p_v6diag as fixtures


def body_fixture(action="good"):
    known=copy.deepcopy(checker.CANDIDATES);memory={};closed=[];opened=[];positions={};fd_paths={};lstats={};walks=[]
    for alias,value in known.items():
        for relative in value["pins"]:
            raw=("HOST_PRIVATE_"+alias+relative).encode("ascii")
            path="/mnt/data/p011-toolbox/candidates/mta-01-"+value["identity"]+"/"+relative
            memory[path]=raw;value["sizes"][relative]=len(raw);value["pins"][relative]=hashlib.sha256(raw).hexdigest()
        base="/mnt/data/p011-toolbox/candidates/mta-01-"+value["identity"]
        walks.extend([(base,["runtime","native"],["SOURCE.sha256"]),(base+"/runtime",[],sorted(name.split("/")[1] for name in value["pins"] if name.startswith("runtime/"))),
                      (base+"/native",[],sorted(name.split("/")[1] for name in value["pins"] if name.startswith("native/")))])
    first="/mnt/data/p011-toolbox/candidates/mta-01-"+known["v5"]["identity"]+"/SOURCE.sha256"
    if action == "digest":memory[first]=b"X"+memory[first][1:]
    elif action == "short":memory[first]=memory[first][:-1]
    elif action == "growth":memory[first]+=b"X"
    def metadata(path,final=False):
        mode=0o100666 if action == "writable" else 0o100600
        if path == first and action == "link":mode=0o120600
        if path == first and action == "fifo":mode=0o010600
        return types.SimpleNamespace(st_dev=1,st_ino=1 if not final else 2,st_mode=mode,
            st_uid=1 if action == "owner" else 0,st_gid=0,st_size=len(memory[path]),st_mtime_ns=1,st_ctime_ns=1)
    def lstat(path):
        lstats[path]=lstats.get(path,0)+1
        return metadata(path,final=action == "replaced" and path == first and lstats[path]>1)
    def open_file(path,flags):
        if flags != 0x20000:raise AssertionError("Expected O_RDONLY|O_NOFOLLOW")
        fd=len(opened)+10;opened.append(path);fd_paths[fd]=path;positions[fd]=0;return fd
    def fstat(fd):
        value=metadata(fd_paths[fd])
        if action == "descriptor_changed":value.st_ino+=1
        return value
    def read(fd,count):
        if not 1 <= count <= 65536:raise AssertionError("Unbounded read")
        path=fd_paths[fd];start=positions[fd];chunk=memory[path][start:start+count];positions[fd]+=len(chunk);return chunk
    def walk(base,followlinks=False):
        if followlinks:raise AssertionError("Followed links")
        rows=[copy.deepcopy(row) for row in walks if row[0]==base or row[0].startswith(base+"/")]
        if action == "unlisted" and base.endswith(known["v5"]["identity"]):rows[0][2].append("HOST_PRIVATE_EXTRA")
        return rows
    calls=[]
    clock=[]
    def monotonic():
        clock.append(True);return 60 if action == "deadline" and len(clock)>1 else 1
    os_mock=types.SimpleNamespace(lstat=lstat,fstat=fstat,open=open_file,read=read,close=lambda fd:closed.append(fd),
        set_inheritable=lambda fd,value:None,geteuid=lambda:0,O_RDONLY=0,O_NOFOLLOW=0x20000,walk=walk,sep="/",
        path=types.SimpleNamespace(islink=lambda unused:False,relpath=lambda path,base:path[len(base)+1:]))
    namespace={"CANDIDATES":known,"AREA":"/mnt/data/p011-toolbox","hashlib":hashlib,"stat":stat,"os":os_mock,
        "time":types.SimpleNamespace(monotonic=monotonic),"private_folder":lambda path:calls.append(path),"owned_directory":lambda path:calls.append(path)}
    buffer=io.StringIO()
    with contextlib.redirect_stdout(buffer):exec(checker.BODY,namespace)
    value=ast.literal_eval(buffer.getvalue().split("RESULT=",1)[1].strip())
    checker.validate_result(value)
    return value,opened,closed


class ProgramTests(unittest.TestCase):
    def test_fixed_host_manifest_payload_sizes_and_ast_no_device(self):
        with mock.patch.object(checker,"Adb",side_effect=AssertionError("No ADB")):
            safety=checker.verify_reference();program=checker.source(safety)
        tree=ast.parse(program,feature_version=(3,5));self.assertFalse(any(isinstance(node,ast.Assert) for node in ast.walk(tree)))
        self.assertEqual(len(checker.CANDIDATES),2)
        for value in checker.CANDIDATES.values():self.assertEqual(len(value["pins"]),8);self.assertEqual(set(value["pins"]),set(value["sizes"]))
        body=ast.parse(checker.BODY,feature_version=(3,5))
        forbidden={"chmod","chown","unlink","remove","mkdir","start","stop","recover","restore","sendto","bind","connect","listen"}
        for node in ast.walk(body):
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute):self.assertNotIn(node.func.attr,forbidden)
        self.assertIn("os.O_RDONLY|os.O_NOFOLLOW",checker.BODY)

    def test_exact_sixteen_files_hash_size_metadata_and_descriptor_close(self):
        value,opened,closed=body_fixture()
        self.assertTrue(value["diagnostic_complete"]);self.assertTrue(value["pins_verified"]);self.assertTrue(value["permissions_gate_satisfied"])
        self.assertEqual(len(value["files"]),16);self.assertEqual(len(opened),16);self.assertEqual(len(closed),16)
        self.assertNotIn("HOST_PRIVATE",json.dumps(value));self.assertNotIn("/mnt/",json.dumps(value))
        for row in value["files"]:
            self.assertEqual(set(row),checker.ROW_FIELDS);self.assertEqual(row["mode"],0o600)

    def test_writable_or_different_owner_is_fact_not_permission_repair(self):
        for action,flag in (("writable","not_other_writable"),("owner","owner_matches_euid")):
            value,opened,closed=body_fixture(action)
            self.assertTrue(value["diagnostic_complete"]);self.assertTrue(value["pins_verified"])
            self.assertFalse(value["permissions_gate_satisfied"]);self.assertTrue(all(not row[flag] for row in value["files"]))
            self.assertEqual(len(closed),16)

    def test_link_or_fifo_rejected_before_open(self):
        for action in ("link","fifo"):
            value,opened,closed=body_fixture(action)
            self.assertFalse(value["diagnostic_complete"]);self.assertEqual(value["reason"],"file_not_regular")
            self.assertEqual(opened,[]);self.assertEqual(closed,[])

    def test_fd_or_final_lstat_changed_identity_fails_closed(self):
        for action in ("descriptor_changed","replaced"):
            value,opened,closed=body_fixture(action)
            self.assertFalse(value["diagnostic_complete"]);self.assertEqual(value["reason"],"file_identity_changed")
            self.assertEqual(len(opened),1);self.assertEqual(len(closed),1)

    def test_short_growth_digest_and_unlisted_fail_not_pinned(self):
        for action in ("short","growth","digest","unlisted"):
            value,opened,closed=body_fixture(action)
            self.assertFalse(value["diagnostic_complete"]);self.assertFalse(value["pins_verified"])
            self.assertEqual(value["reason"],"candidate_contents_invalid" if action == "unlisted" else "file_pin_mismatch")
            self.assertEqual(len(opened),len(closed))

    def test_deadline_no_open_and_no_permissions_claim(self):
        value,opened,closed=body_fixture("deadline")
        self.assertEqual(value["reason"],"readonly_permission_deadline");self.assertFalse(value["diagnostic_complete"])
        self.assertEqual(opened,[]);self.assertEqual(closed,[])

    def test_public_schema_modes_types_aliases_relative_order_and_no_extra(self):
        valid,opened,closed=body_fixture();variants=[]
        for field,value in (("file_count",True),("outer_relative","HOST_SECRET"),("outer_candidate",[]),("errno",True),("reason","HOST_SECRET")):
            row=copy.deepcopy(valid);row[field]=value;variants.append(row)
        for field,value in (("mode",True),("mode",512),("candidate","unknown"),("relative","/HOST_SECRET"),("not_other_writable",1),("mode",0o666)):
            row=copy.deepcopy(valid);row["files"][0][field]=value;variants.append(row)
        row=copy.deepcopy(valid);row["files"][0]["uid"]=1;variants.append(row)
        row=copy.deepcopy(valid);row["files"][0]["full_sha_match"]=False;variants.append(row)
        row=copy.deepcopy(valid);row["files"]=row["files"][:-1];row["file_count"]-=1;variants.append(row)
        for value in variants:
            with self.assertRaises(ValueError):checker.validate_result(value)


class FakeAdb(old_tests.FakeAdb):
    def run(self,label,arguments,timeout=None,input_data=None):
        self.index+=1;self.calls.append((label,arguments,timeout,input_data));ast.parse(input_data.decode("utf-8"),feature_version=(3,5))
        if label == "fixed-permission-files-readonly":value=body_fixture("writable")[0]
        else:
            value=fixtures.private_probe()
            if label == "after-permissions-readonly" and self.action == "changed":value["ipv4"]["rules"][0][1]=200
        return old_tests.wire(value)


class HarnessTests(unittest.TestCase):
    def test_three_readonly_calls_writable_evidence_does_not_become_repair(self):
        with tempfile.TemporaryDirectory() as directory:
            values=[]
            def factory(path):
                value=FakeAdb(path,"good");values.append(value);return value
            with mock.patch.object(checker,"Adb",side_effect=factory):report,out,archive=checker.run_check(Path(directory)/"HOST_ONLY")
            self.assertTrue(report["check_complete"]);self.assertFalse(report["diagnostic"]["permissions_gate_satisfied"])
            self.assertEqual([row[0] for row in values[0].calls],["before-permissions-readonly","fixed-permission-files-readonly","after-permissions-readonly"])
            for field in ("permissions_modified","device_writes","candidate_staged","radio_operations","network_configuration","recovery_invoked","retry_invoked","send_available"):
                self.assertFalse(report[field])
            with zipfile.ZipFile(archive) as bundle:
                self.assertEqual(set(bundle.namelist()),{"result.json","README.txt"})
                content=b"".join(bundle.read(name) for name in bundle.namelist())
                for token in (b"HOST_PRIVATE",b"HOST_SECRET",b"/mnt/",b'"uid"',b'"gid"',b'"inode"'):self.assertNotIn(token,content)

    def test_full_policy_change_blocks_check_without_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            values=[]
            def factory(path):
                value=FakeAdb(path,"changed");values.append(value);return value
            with mock.patch.object(checker,"Adb",side_effect=factory):report,out,archive=checker.run_check(Path(directory)/"HOST_ONLY")
            self.assertFalse(report["check_complete"]);self.assertFalse(report["full_ipv4_rules_unchanged"])
            self.assertEqual(len(values[0].calls),3);self.assertFalse(report["retry_invoked"])

    def test_only_explicit_fixed_readonly_cli_and_prior_reference_changes_block(self):
        for argv in (["program"],["program","--check-readonly","--chmod"],["program","--check-readonly","--candidate","HOST_SECRET"],["program","--freeze-only"]):
            with mock.patch.object(sys,"argv",argv),mock.patch.object(checker,"Adb",side_effect=AssertionError("No ADB")), \
                    contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):checker.main()
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory)/"UNCREATED"
            with mock.patch.object(checker,"PREVIOUS_CHECKER_SHA256","0" * 64),mock.patch.object(checker,"Adb",side_effect=AssertionError("No ADB")),self.assertRaises(ValueError):checker.run_check(output)
            self.assertFalse(output.exists())


if __name__ == "__main__":unittest.main()
