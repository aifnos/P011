"""Pure HOST V9 exact multicast exception; no sockets/kernel/device/RF tests."""
import ast
import copy
import hashlib
import importlib.util
import inspect
import io
import json
import os
from pathlib import Path
import sys
import unittest
from unittest import mock

BASE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BASE / "runtime"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_owned_ip_lease import FakeBackend, FakeLock
import mta_ip_lease as ip

FROZEN = BASE.parents[1] / "logs/MtaP011-P2pV8RouteDiagFreeze-20261001-075316-238ce1ff/private-candidate"
V8 = FROZEN / "runtime/mta_send_wifi.py"
V9 = BASE / "native/private-p2p-runtime-candidate-20261001-v9mroute/runtime/mta_send_wifi.py"
V8_MANIFEST = "7e98dbf4a03abcfaf2cbd38e5f4d95d51e2de2969166b2a3dc5557d606d03c29"
V8_SOURCE = "83770b7e9264dbcb8887d323e9b49771e3db46e8144a7325fccbaa8be8ba7e89"


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, str(path)); result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result); return result


v8 = module(V8, "v8_mroute_fixed_comparison")
v9 = module(V9, "v9_mroute_host_only")
OWNED = {"name":"mta1234abcd","ifindex":9,"wdev":20,"phy":0,"iftype":8}
LL = bytes.fromhex("fe800000000000000000000000000001")


def parts(**changes):
    row = ["ff" + "0" * 30, "08", "0" * 32, "00", "0" * 32,
           "00000100", "00000001", "00000000", "00000001", OWNED["name"]]
    indexes = {"destination":0,"prefix":1,"source":2,"source_prefix":3,"gateway":4,
               "metric":5,"refcount":6,"usecount":7,"flags":8,"name":9}
    for key, value in changes.items():row[indexes[key]] = value
    return row


def route(**changes):return " ".join(parts(**changes)) + "\n"


def linklocal(**changes):
    values = {"destination":"fe80" + "0" * 28,"prefix":"40"}; values.update(changes)
    return route(**values)


def decide(source, text, allow_ipv4=True, ipv4=""):
    opens = []; report = source.ip_creation_l3_diagnostic()
    def opened(path, *unused):
        opens.append(path); return io.StringIO(ipv4 if path == "/proc/net/route" else text)
    with mock.patch("builtins.open", side_effect=opened):
        created = source._creation_owned_routes_safe(OWNED["name"], report)
    created_opens = list(opens); opens.clear()
    with mock.patch("builtins.open", side_effect=opened):
        restored = source._owned_routes_safe(OWNED["name"], allow_ipv4)
    source._l3_copy(report)
    return created, restored, report, created_opens, opens


class ExactProfileTests(unittest.TestCase):
    def test_exact_ff00_8_up_profile_accepted_not_class_only(self):
        self.assertTrue(v9._kernel_multicast_route(parts()))
        for destination in ("ff02" + "0" * 28, "ff" + "0" * 29 + "1", "0" * 32,
                            "fe80" + "0" * 28, "fd00" + "0" * 28):
            with self.subTest(destination=destination):self.assertFalse(v9._kernel_multicast_route(parts(destination=destination)))
    def test_all_prefix_bytes_only_exact08_not_generic_multicast(self):
        for value in range(256):
            with self.subTest(value=value):self.assertEqual(v9._kernel_multicast_route(parts(prefix="%02x" % value)), value == 8)
    def test_destination_source_sourceprefix_gateway_are_canonical_exact(self):
        cases = {"destination":("FF" + "0" * 30,"ff" + "0" * 29,"0xff" + "0" * 30),
            "source":("0" * 31,"0" * 33,LL.hex(),"+" + "0" * 31),
            "source_prefix":("0","000","01","0x00"),
            "gateway":("0" * 31,"0" * 33,LL.hex(),"-" + "0" * 31),
            "prefix":("8","008","0x08","+8","-8")}
        for field, values in cases.items():
            for value in values:
                with self.subTest(field=field,value=value):self.assertFalse(v9._kernel_multicast_route(parts(**{field:value})))
    def test_metric_refcount_usecount_width_hex_only_not_fixed_value(self):
        for field in ("metric","refcount","usecount"):
            for value in ("00000000","00000100","01234567","89abcdef","ffffffff"):
                with self.subTest(field=field,value=value):self.assertTrue(v9._kernel_multicast_route(parts(**{field:value})))
            for value in ("0000000","000000000","FFFFFFFF","0x000100","-0000001","PRIVATE",8,True):
                with self.subTest(field=field,value=value):self.assertFalse(v9._kernel_multicast_route(parts(**{field:value})))
    def test_flags_every_extra_bit_zero_noncanonical_all_rejected(self):
        for bit in range(32):
            value = 1 | (1 << bit)
            with self.subTest(bit=bit):self.assertEqual(v9._kernel_multicast_route(parts(flags="%08x" % value)), bit == 0)
        for value in ("00000000","1","000000001","0x000001","0000000A","80000001","00000201"):
            with self.subTest(value=value):self.assertFalse(v9._kernel_multicast_route(parts(flags=value)))
    def test_type_shape_bad_fields_no_implicit_conversion_or_io(self):
        for value in (None,(),tuple(parts()),"HOST_PRIVATE",parts()[:-1],parts() + ["extra"],parts(metric=b"00000100")):
            with self.subTest(value=value):self.assertFalse(v9._kernel_multicast_route(value))
        with mock.patch("builtins.open", side_effect=AssertionError("unvisited")), \
                mock.patch.object(v9.socket, "socket", side_effect=AssertionError("unvisited")):
            self.assertTrue(v9._kernel_multicast_route(parts()))


class PredicateTests(unittest.TestCase):
    def test_single_profile_new_acceptance_creation_and_restore_old_rejection(self):
        previous = decide(v8, route()); current = decide(v9, route())
        self.assertEqual(previous[:2], (False,False)); self.assertEqual(current[:2], (True,True))
        self.assertEqual(current[3:], previous[3:])
        report = current[2]; self.assertEqual(report["reason"],"accepted"); self.assertEqual(report["stage"],"done")
        self.assertEqual(report["counts"]["ipv6_route_rows_examined"],1)
        self.assertFalse(report["observations"]["route_prefix_is_128"])
        self.assertTrue(report["observations"]["routes_accepted"]); self.assertEqual(report["route_details"],{})
    def test_mixed_linklocal_mroute_order_one_exception_per_interface(self):
        for text in (linklocal() + route(),route() + linklocal(),linklocal() + route() + linklocal()):
            with self.subTest(text=text):self.assertEqual(decide(v9,text)[:2],(True,True))
    def test_duplicate_profile_rejects_in_creation_restore_and_station_cleanup(self):
        for text in (route() * 2,route() + linklocal() + route()):
            for allow_ipv4 in (True,False):
                created, restored, report, unused, opened = decide(v9,text,allow_ipv4)
                self.assertFalse(created); self.assertFalse(restored)
                self.assertEqual(report["reason"],"route_prefix"); self.assertEqual(report["stage"],"route_prefix")
                self.assertEqual(report["route_details"]["values"],{"prefix":8,"destination_class":"multicast"})
                self.assertFalse(report["observations"]["route_prefix_is_128"])
                if not allow_ipv4:self.assertEqual(opened,["/proc/net/route","/proc/net/ipv6_route"])
    def test_other_interface_duplicates_never_count_or_authorize_owned_bad_row(self):
        text = route(name="other") * 2 + route() + route(name="wlan0")
        current = decide(v9,text); self.assertEqual(current[:2],(True,True))
        self.assertEqual(current[2]["counts"]["ipv6_route_rows_examined"],1)
        self.assertEqual(decide(v9,route(name="other") + route(flags="00000003"))[:2],(False,False))
    def test_noncanonical_or_nonprofile_rejected_by_both_predicates(self):
        cases = [{"destination":"ff02" + "0" * 28},{"destination":"FF" + "0" * 30},{"prefix":"0x08"},
            {"source":LL.hex()},{"source_prefix":"01"},{"gateway":LL.hex()}, {"metric":"PRIVATE"},
            {"refcount":"0000000"},{"usecount":"FFFFFFFF"},{"flags":"00000003"},{"flags":"00000000"}]
        for values in cases:
            with self.subTest(values=values):self.assertEqual(decide(v9,route(**values))[:2],(False,False))
    def test_first_rejection_remains_first_and_later_rows_unvisited(self):
        current = decide(v9,route(flags="00000003") + route())
        self.assertEqual(current[:2],(False,False)); self.assertEqual(current[2]["counts"]["ipv6_route_rows_examined"],1)
        self.assertEqual(current[2]["route_details"]["values"]["prefix"],8)
        self.assertTrue(current[2]["route_details"]["observations"]["flags_gateway"])
    def test_old_linklocal_prefix_default_global_local128_gateway_decisions_unchanged(self):
        cases = ["",linklocal(),linklocal(prefix="80"),linklocal(prefix="00"),linklocal(destination="0" * 32),
            linklocal(destination="fd00" + "0" * 28),linklocal(gateway=LL.hex()),linklocal(source=LL.hex()),
            linklocal(source_prefix="01"),linklocal(destination="INVALID"),linklocal(prefix="INVALID"),
            linklocal(metric="PRIVATE",flags="PRIVATE"),"1 2 " + OWNED["name"] + "\n"]
        for text in cases:
            previous = decide(v8,text); current = decide(v9,text)
            with self.subTest(text=text):self.assertEqual(current,previous)
    def test_all_linklocal_prefix_bytes_keep_old_limits(self):
        for prefix in range(256):
            text = linklocal(prefix="%02x" % prefix)
            with self.subTest(prefix=prefix):self.assertEqual(decide(v9,text),decide(v8,text))
    def test_restore_ipv4_guard_remains_and_allowipv4_explicit(self):
        raw = OWNED["name"] + " HOST_PRIVATE_ROUTE\n"
        current = decide(v9,route(),False,raw); previous = decide(v8,route(),False,raw)
        self.assertFalse(current[1]); self.assertFalse(previous[1]); self.assertEqual(current[4],["/proc/net/route"])
        self.assertTrue(decide(v9,route(),True,raw)[1])
    def test_count_resets_each_independent_read_and_empty_has_no_prefix_fact(self):
        for unused in range(3):self.assertEqual(decide(v9,route())[:2],(True,True))
        current = decide(v9,""); self.assertEqual(current[:2],(True,True))
        self.assertNotIn("route_prefix_is_128",current[2]["observations"])
    def test_current_shape_invalid_is_symbolic_not_raw_text(self):
        created, restored, report, unused, unused2 = decide(v9,"PRIVATE_DEST 08 " + OWNED["name"] + "\n")
        self.assertFalse(created); self.assertFalse(restored)
        self.assertEqual(report["route_details"],{"values":{},"observations":{},"invalid_fields":["shape"]})
        for secret in ("PRIVATE_DEST",OWNED["name"]):self.assertNotIn(secret,json.dumps(report))


class BackendGateTests(unittest.TestCase):
    def check(self,text,creating=True,carrier="1",origin=True,addresses=None):
        backend = object.__new__(v9.LinuxBackend); backend.allow_rf = True; backend.guard = mock.Mock(fd=5)
        backend.nl = mock.Mock(); backend.nl.interfaces.return_value = [dict(OWNED,iftype=9,wdev=OWNED["wdev"] if origin else 999)]
        reads = []
        def opened(path,*unused):
            reads.append(path)
            if path == "/proc/net/ipv6_route":return io.StringIO(text)
            if path == "/proc/net/route":return io.StringIO("")
            return io.StringIO({"flags":"0x1003","carrier":carrier,"ifindex":"9"}[path.rsplit("/",1)[1]])
        rows = [{"family":6,"prefix":64,"scope":253,"address":LL}] if addresses is None else addresses
        with mock.patch("builtins.open",side_effect=opened), mock.patch.object(v9,"_digest",side_effect=lambda path:v9.STOCK_PINS[path]), \
                mock.patch.object(v9,"_address_dump",return_value=rows) as dump:
            result = backend.ip_identity_gate(OWNED,creating)
        return result,backend,reads,dump.call_count
    def test_creation_and_restore_full_owned_gate_accept_profile_once(self):
        for creating in (True,False):
            result,backend,reads,dumps = self.check(route(),creating)
            self.assertTrue(result); self.assertEqual(dumps,1); self.assertEqual(reads.count("/proc/net/ipv6_route"),1)
            if creating:self.assertEqual(backend.ip_creation_l3_info["reason"],"accepted")
            else:self.assertFalse(hasattr(backend,"ip_creation_l3_info"))
    def test_carrier_origin_and_address_gates_not_bypassed_by_matching_profile(self):
        for values in ({"carrier":"0"},{"origin":False},{"addresses":[{"family":6,"prefix":128,"scope":253,"address":LL}]}):
            result,backend,reads,dumps = self.check(route(),**values)
            self.assertFalse(result); self.assertNotIn("/proc/net/ipv6_route",reads)
    def test_restore_duplicate_or_gateway_retains_gate_failure(self):
        for text in (route() * 2,route(gateway=LL.hex())):
            self.assertFalse(self.check(text,False)[0])


class MemoryFixture:
    def __init__(self):
        self.backend = FakeBackend(); self.saved = None
        self.lease = v9.GoLease(self.backend,os.path.join(str(BASE),"HOST_ONLY_NO_JOURNAL"),lambda:100.0)
        def save(locked=False):self.saved = copy.deepcopy(self.lease.state)
        self.lease._save = save
        self.lock = mock.patch.object(v9,"JournalLock",FakeLock)
        self.reader = mock.patch.object(v9,"_read_private_json",side_effect=lambda path:copy.deepcopy(self.saved))
    def enter(self):self.lock.start();self.reader.start();return self
    def close(self):self.reader.stop();self.lock.stop()
    def observed(self,text):
        report = v9.ip_creation_l3_diagnostic()
        with mock.patch("builtins.open",return_value=io.StringIO(text)):
            accepted = v9._creation_owned_routes_safe(OWNED["name"],report)
        self.backend.ip_creation_l3_info = report
        self.backend.ip_creation_gate_info = v9.ip_creation_diagnostic("not_recorded" if accepted else "interface_l3","not_recorded" if accepted else "interface_l3")
        self.backend.ip_identity_gate = mock.Mock(return_value=accepted)
        return report


class LeaseTests(unittest.TestCase):
    def setUp(self):self.f = MemoryFixture().enter()
    def tearDown(self):self.f.close()
    def test_fake_accepted_profile_uses_same_receipt_and_precise_rollback_send_false(self):
        self.f.observed(route()); ready = self.f.lease.start(20,lambda path,end:None)
        self.assertEqual(ready["ip_creation_l3"]["reason"],"accepted"); self.assertEqual(ready["ip_creation_l3"]["route_details"],{})
        self.assertTrue(self.f.lease.state["ip"]["receipt_fsynced"]); self.assertFalse(ready["send_available"])
        self.assertNotIn("route_details",json.dumps(self.f.saved)); self.assertTrue(self.f.lease.stop()["complete"])
        self.assertEqual(self.f.backend.calls.count("newaddr"),1); self.assertEqual(self.f.backend.calls.count("deladdr"),1)
    def test_duplicate_failure_preserved_before_cleanup_and_no_address_write(self):
        first = self.f.observed(route() * 2)
        with self.assertRaises(ip.IpLeaseError):self.f.lease.start(20,lambda path,end:None)
        self.assertEqual(self.f.lease.failure_info["ip_creation_l3"],first)
        self.assertNotIn("newaddr",self.f.backend.calls); self.assertNotIn("deladdr",self.f.backend.calls)
        self.assertIn("stop_process",self.f.backend.calls); self.assertIn("remove",self.f.backend.calls)
    def test_other_rejection_still_no_address_or_late_diagnostic_override(self):
        first = self.f.observed(route(flags="00000003"))
        with self.assertRaises(ip.IpLeaseError):self.f.lease.start(20,lambda path,end:None)
        self.f.backend.ip_creation_l3_info = v9.ip_creation_l3_diagnostic("accepted","done")
        self.f.lease._capture_ip_l3(); self.assertEqual(self.f.lease.ip_creation_l3_info,first)
        self.assertNotIn("newaddr",self.f.backend.calls)
    def test_old_v8_identity_not_migrated_for_recovery(self):
        self.f.observed(route()); self.f.lease.start(20,lambda path,end:None)
        row = copy.deepcopy(self.f.saved); v9._journal_envelope(row); row["identity"] = dict(v8.LEASE_IDENTITY)
        with self.assertRaises(v9.LeaseError):v9._journal_envelope(row)
        self.assertTrue(self.f.lease.stop()["complete"])


class SourceTests(unittest.TestCase):
    def test_mechanical_frozen_origin_identity_shared_pins_unchanged(self):
        self.assertEqual(hashlib.sha256((FROZEN / "SOURCE.sha256").read_bytes()).hexdigest(),V8_MANIFEST)
        self.assertEqual(hashlib.sha256(V8.read_bytes()).hexdigest(),V8_SOURCE)
        self.assertEqual(v9.DIAGNOSTIC_RUNTIME_MARKER,"p011-go-ip-only-v9mroute-1")
        self.assertEqual(dict(v8.LEASE_IDENTITY,runtime_marker=v9.DIAGNOSTIC_RUNTIME_MARKER),v9.LEASE_IDENTITY)
        for name,pin in (("mta_ip.py",v8.IP_CODEC_SHA256),("mta_ip_lease.py",v8.IP_HELPER_SHA256)):
            self.assertEqual(hashlib.sha256((BASE / "runtime" / name).read_bytes()).hexdigest(),pin)
        for name in ("mta-wpa-supplicant","mta-wifi-caps"):
            self.assertEqual((FROZEN / "native" / name).read_bytes(),(BASE / "native/private-p2p-candidate-20261001-v2" / name).read_bytes())
    def test_only_two_route_functions_changed_and_one_pure_helper_added(self):
        def functions(text):
            result = {}
            def walk(body,prefix=""):
                for node in body:
                    if isinstance(node,ast.FunctionDef):
                        result[prefix + node.name] = ast.get_source_segment(text,node); walk(node.body,prefix + node.name + ".")
                    elif isinstance(node,ast.ClassDef):walk(node.body,prefix + node.name + ".")
            walk(ast.parse(text).body);return result
        previous = functions(V8.read_text()); current = functions(V9.read_text())
        self.assertEqual(set(current) - set(previous),{"_kernel_multicast_route"})
        for name in set(previous) - {"_owned_routes_safe","_creation_owned_routes_safe"}:
            with self.subTest(function=name):self.assertEqual(previous[name],current[name])
    def test_python35_no_assert_new_imports_socket_calls_or_extra_kernel_reads(self):
        previous = ast.parse(V8.read_text(),feature_version=(3,5)); current = ast.parse(V9.read_text(),feature_version=(3,5))
        self.assertFalse(any(isinstance(node,ast.Assert) for node in ast.walk(current)))
        self.assertEqual([ast.dump(node) for node in previous.body if isinstance(node,(ast.Import,ast.ImportFrom))],
                         [ast.dump(node) for node in current.body if isinstance(node,(ast.Import,ast.ImportFrom))])
        helper = ast.parse(inspect.getsource(v9._kernel_multicast_route))
        calls = [node.func.id for node in ast.walk(helper) if isinstance(node,ast.Call) and isinstance(node.func,ast.Name)]
        self.assertFalse(set(calls) & {"open","socket","_address_dump","_digest","ReadWriteNetlink"})
        source = inspect.getsource(v9._kernel_multicast_route)
        for token in ("sysctl","wlan0","subprocess","send_available"):self.assertNotIn(token,source)
    def test_no_production_or_old_entry_source_replaced(self):
        self.assertEqual(hashlib.sha256((BASE / "native/private-p2p-runtime-candidate-20261001-v8routediag/runtime/mta_send_wifi.py").read_bytes()).hexdigest(),V8_SOURCE)
        expected = {"host/device_p2p_v8routediag.py":"1000b427c8df75891048b92f584ccf39f49f5f2bd679c2638d8d6f24ce3ac713",
                    "tests/test_device_p2p_v8routediag.py":"e7608005f0b58f7e9a32058f743af95185e2c8ab2cc3ba7f95b6b62a35690472"}
        for name,pin in expected.items():self.assertEqual(hashlib.sha256((BASE / name).read_bytes()).hexdigest(),pin)


if __name__ == "__main__":unittest.main()
