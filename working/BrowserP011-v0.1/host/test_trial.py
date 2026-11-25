"""HOST_ONLY checks. No Adb object is constructed and no device is contacted."""
import ast
import base64
import copy
import contextlib
import hashlib
import json
import io
from pathlib import Path
import shlex
import struct
import tempfile
import unittest
import zlib

import trial


def baseline():
    parent = {"pid": 1, "name": "init", "parent": 0, "starttime": "10", "exe": "/sbin/init"}
    rows = []
    for index, name in enumerate(("Z03", "control_engine", "weston"), 20):
        row = {"pid": index, "name": name, "parent": 1, "starttime": str(index * 100), "exe": "/usr/bin/" + name}
        if name != "weston":
            row["parent_identity"] = dict(parent)
        rows.append(row)
    return {"schema": "p011.browser.baseline.v1", "boot_id": "12345678-1234-1234-1234-123456789abc",
            "hashes": {path: hashlib.sha256(path.encode()).hexdigest() for path in trial.STOCK_PATHS},
            "processes": rows}


def png_bytes(width=800, height=480):
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xffffffff)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress((b"\x00" + b"\x00" * width * 4) * height)) + chunk(b"IEND", b""))


class TrialHostTests(unittest.TestCase):
    def payload(self, folder):
        payload = Path(folder) / "payload"
        libraries = {"lib/libQt6" + module + ".so.6" for module in trial.REQUIRED_QT_LIBRARIES}
        for name in trial.REQUIRED_FILES | libraries:
            path = payload.joinpath(*name.split("/"))
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(("HOST_FIXTURE_ONLY:" + name).encode("ascii"))
        modules = {
            "QML": "module QML\nstatic\nsystem\n",
            "QtQml": "module QtQml\noptional plugin qmlplugin\nimport QML 1.0\nimport QtQml.Models auto\nimport QtQml.WorkerScript auto\n",
            "QtQml.Models": "module QtQml.Models\noptional plugin modelsplugin\ndepends QML 1.0\n",
            "QtQml.WorkerScript": "module QtQml.WorkerScript\noptional plugin workerscriptplugin\ndepends QML 1.0\n",
            "QtQuick": "module QtQuick\noptional plugin qtquick2plugin\nimport QtQml auto\n",
            "QtQuick.Window": "module QtQuick.Window\nplugin quickwindowplugin\nimport QtQuick auto\n",
            "QtWebEngine": "module QtWebEngine\nplugin qtwebenginequickplugin\ndepends QtQuick auto\ndepends QtWebChannel auto\n",
            "QtWebChannel": "module QtWebChannel\noptional plugin webchannelquickplugin\n",
        }
        for module, descriptor in modules.items():
            directory = payload / "qml" / Path(*module.split("."))
            directory.mkdir(parents=True, exist_ok=True)
            (directory / "qmldir").write_text(descriptor, encoding="utf-8")
            for line in descriptor.splitlines():
                fields = line.split()
                if "plugin" in fields:
                    (directory / ("lib" + fields[fields.index("plugin") + 1] + ".so")).write_bytes(b"HOST_FIXTURE_PLUGIN")
        return payload

    def test_manifest_is_deterministic_and_content_bound(self):
        with tempfile.TemporaryDirectory() as folder:
            payload = self.payload(folder)
            first = trial.source_manifest(payload)
            name, checksum = trial.manifest_identity(first)
            self.assertEqual(first, trial.source_manifest(payload))
            self.assertEqual(name, "browser-685-" + checksum[:16])
            target = payload / "bin" / "p011-browser-probe"
            target.write_bytes(target.read_bytes() + b" changed")
            changed = trial.source_manifest(payload)
            self.assertNotEqual(checksum, trial.manifest_identity(changed)[1])
            self.assertEqual(changed["total_bytes"] - first["total_bytes"], 8)
            modes = {row["path"]: row["mode"] for row in first["files"]}
            self.assertEqual(modes["bin/p011-browser-probe"], 0o755)
            self.assertEqual(modes["lib/libQt6Core.so.6"], 0o644)

    def test_relative_paths_reject_traversal_and_reserved_control_files(self):
        for path in ("../x", "/etc/passwd", "lib/../x", "C:/x", "lib\\x", "lib//x", "lib/x.",
                     "lib/x;echo", ".candidate-manifest.py", ".manifest-upload.py", "lib/./x"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                trial.safe_relative(path)
        self.assertEqual(trial.safe_relative("translations/en-US.pak"), "translations/en-US.pak")

    def test_host_preparation_retains_reviewable_manifest_and_layout(self):
        with tempfile.TemporaryDirectory() as folder:
            payload = self.payload(folder)
            output = Path(folder) / "review"
            output.mkdir()
            manifest, name, checksum, literal = trial.prepare_payload(payload, output)
            self.assertEqual(name, "browser-685-" + checksum[:16])
            self.assertEqual(json.loads((output / "payload-manifest.json").read_text()), manifest)
            self.assertEqual(ast.literal_eval(literal.read_text())["sha256"], checksum)
            layout = json.loads((output / "runtime-layout.json").read_text())
            self.assertEqual(layout["scope"], "HOST_ONLY_LAYOUT_NO_ELF_OR_QML_EXECUTION")
            self.assertIn("QtQml.WorkerScript", layout["qml_modules"])

    def test_candidate_and_session_paths_are_fixed(self):
        candidate, session = trial.remote_names("browser-685-" + "a" * 16, "20261020-123456-a1b2c3d4")
        self.assertTrue(candidate.startswith(trial.AREA + "/candidates/"))
        self.assertTrue(session.startswith(trial.AREA + "/sessions/"))
        for candidate_name, session_name in (("../x", "20261020-123456-a1b2c3d4"),
                                             ("browser-685-" + "a" * 16, "20261020-123456-a1b2c3d4/../x")):
            with self.assertRaises(ValueError):
                trial.remote_names(candidate_name, session_name)

    def test_manifest_rejects_missing_runtime_and_link(self):
        with tempfile.TemporaryDirectory() as folder:
            payload = self.payload(folder)
            (payload / "runtime" / "guardian.py").unlink()
            with self.assertRaises(ValueError):
                trial.source_manifest(payload)
        with tempfile.TemporaryDirectory() as folder:
            payload = self.payload(folder)
            link = payload / "linked"
            try:
                link.symlink_to(payload / "runtime", target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("Host cannot create symlink; reparse rejection remains statically enforced")
            with self.assertRaises(ValueError):
                trial.source_manifest(payload)

    def test_layout_rejects_missing_actual_loader_paths_before_adb(self):
        for relative in ("plugins/platforms/libqwayland-generic.so",
                         "plugins/wayland-shell-integration/libwl-shell-plugin.so",
                         "plugins/wayland-graphics-integration-client/libqt-plugin-wayland-egl.so",
                         "resources/qtwebengine_resources_100p.pak",
                         "translations/qtwebengine_locales/en-US.pak",
                         "lib/libQt6WebEngineCore.so.6", "qml/QtWebEngine/qmldir",
                         "qml/QtQml/WorkerScript/libworkerscriptplugin.so"):
            with self.subTest(path=relative), tempfile.TemporaryDirectory() as folder:
                payload = self.payload(folder)
                payload.joinpath(*relative.split("/")).unlink()
                with self.assertRaises(ValueError):
                    trial.source_manifest(payload)

    def test_layout_follows_qml_dependencies_and_declared_plugin_identity(self):
        with tempfile.TemporaryDirectory() as folder:
            payload = self.payload(folder)
            manifest = trial.source_manifest(payload)
            layout = trial.validate_runtime_layout(payload, manifest["files"])
            self.assertEqual(layout["qml_modules"], ["QML", "QtQml", "QtQml.Models", "QtQml.WorkerScript",
                                                     "QtQuick", "QtQuick.Window", "QtWebChannel", "QtWebEngine"])
            descriptor = payload / "qml" / "QtQml" / "WorkerScript" / "qmldir"
            descriptor.write_text("module Different\noptional plugin workerscriptplugin\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "QML module identity"):
                trial.source_manifest(payload)
            descriptor.write_text("module QtQml.WorkerScript\nplugin ../../outside\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "QML plugin declaration"):
                trial.source_manifest(payload)
    def test_space_gate_has_exact_128mib_reserve(self):
        bundle = 200 * 1024 * 1024
        needed = bundle + 128 * 1024 * 1024
        self.assertTrue(trial.space_budget(bundle, needed)["passed"])
        self.assertFalse(trial.space_budget(bundle, needed - 1)["passed"])
        for first, second in ((-1, needed), (bundle, -1), (True, needed)):
            with self.assertRaises(ValueError):
                trial.space_budget(first, second)

    def test_payload_transfer_budget_is_size_based_and_bounded(self):
        self.assertEqual(trial.transfer_timeout(0), 30)
        self.assertEqual(trial.transfer_timeout(100 * 1024 * 1024), 130)
        self.assertEqual(trial.transfer_timeout(300 * 1024 * 1024), 180)
        for value in (-1, True, 1.5):
            with self.assertRaises(ValueError):
                trial.transfer_timeout(value)

    def test_current_baseline_accepts_new_hashes_without_archived_pin(self):
        value = baseline()
        self.assertIs(trial.validate_baseline(value), value)
        updated = copy.deepcopy(value)
        updated["hashes"]["/usr/bin/Z03"] = "f" * 64
        self.assertIs(trial.validate_baseline(updated), updated)
        damaged = copy.deepcopy(value)
        damaged["processes"][0].pop("starttime")
        with self.assertRaises(ValueError):
            trial.validate_baseline(damaged)
        self.assertEqual(trial.normalize_preflight(value), value)

    def test_saved_state_is_bound_to_manifest_boot_and_process_baseline(self):
        checksum = "a" * 64
        name = "browser-685-" + checksum[:16]
        session_name = "20261020-123456-a1b2c3d4"
        candidate, session = trial.remote_names(name, session_name)
        before = baseline()
        state = {"schema": "p011.browser.host-run.v1", "candidate_name": name,
                 "session_name": session_name, "baseline": before,
                 "metadata": {"candidate": candidate, "session": session, "boot_id": before["boot_id"],
                              "hashes": before["hashes"], "manifest_sha256": checksum}}
        self.assertEqual(trial.state_config(state)["baseline"], before)
        changed = copy.deepcopy(state)
        changed["metadata"]["boot_id"] = "87654321-1234-1234-1234-123456789abc"
        with self.assertRaises(ValueError):
            trial.state_config(changed)

    def test_public_cli_requires_explicit_pair_and_keeps_offline_separate(self):
        base = ["--transport", "17", "--payload", "HOST_FIXTURE_ONLY"]
        default = trial.arguments(base)
        self.assertIsNone(default.public_site)
        self.assertFalse(default.public_no_sandbox)
        self.assertFalse(default.offline_no_sandbox)
        offline = trial.arguments(base + ["--offline-no-sandbox"])
        self.assertTrue(offline.offline_no_sandbox)
        for site in ("baidu", "bilibili"):
            args = trial.arguments(base + ["--public-site", site, "--public-no-sandbox"])
            self.assertEqual(args.public_site, site)
            self.assertTrue(args.public_no_sandbox)
        invalid = (["--public-site", "baidu"], ["--public-no-sandbox"],
                   ["--public-site", "baidu", "--public-no-sandbox", "--offline-no-sandbox"],
                   ["--public-site", "https://example.com/", "--public-no-sandbox"],
                   ["--public-site", "baidu", "--public-no-sandbox", "--uid", "0"])
        for extra in invalid:
            with self.subTest(arguments=extra), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                trial.arguments(base + extra)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            trial.arguments(["--transport", "17", "--collect", "saved", "--public-site", "baidu", "--public-no-sandbox"])

    def test_public_metrics_require_reasonable_numeric_boolean_contract(self):
        good = {"ready_complete": True, "body_present": True, "viewport_width": 800, "viewport_height": 228,
                "scroll_width": 1000, "scroll_height": 1000, "image_count": 3,
                "loaded_image_count": 1, "text_length": 50}
        self.assertEqual(trial.public_metrics_evidence(good), good)
        for key, value in (("ready_complete", False), ("body_present", 1), ("text_length", 0),
                           ("viewport_width", True), ("image_count", -1), ("loaded_image_count", 0),
                           ("scroll_height", 227), ("text_length", "private page text")):
            bad = dict(good, **{key: value})
            with self.subTest(key=key, value=value):
                self.assertIsNone(trial.public_metrics_evidence(bad))
        self.assertIsNone(trial.public_metrics_evidence(dict(good, page_text="never retain")))

    def test_public_page_requires_bound_site_metrics_capture_and_runtime_mode(self):
        with tempfile.TemporaryDirectory() as folder:
            local = Path(folder)
            capture = local / "app" / "captures" / "public-baidu-window.png"
            capture.parent.mkdir(parents=True)
            capture.write_bytes(png_bytes())
            rows = [{"event": "runtime_identity", "qt": "6.8.5", "webengine": "6.8.5", "chromium": "122.0.6261.171",
                     "local_probe": False, "public_site": "baidu"},
                    {"event": "load_succeeded"},
                    {"event": "public_page_metrics", "public_site": "baidu", "metrics": {
                        "ready_complete": True, "body_present": True, "viewport_width": 800, "viewport_height": 228,
                        "scroll_width": 800, "scroll_height": 228, "image_count": 1,
                        "loaded_image_count": 1, "text_length": 50}},
                    {"event": "public_capture_saved", "public_site": "baidu", "width": 800, "height": 480,
                     "evidence_kind": "application-window", "physical_scanout_verified": False}]
            def stdout():
                (local / "browser.stdout.raw").write_bytes(b"".join((json.dumps(dict(row, schema=1, component="p011-browser-probe")) + "\r\r\n").encode() for row in rows))
            status = {"complete": True, "result": {"passed": True, "public_site": "baidu", "public_no_sandbox": True,
                                                   "offline_local_fixture_only": False, "sandbox_enabled": False}}
            evidence = {"files": [{"path": "app/captures/public-baidu-window.png", "sha256": trial.digest(capture)}]}
            stdout()
            result = trial.page_evidence(local, status, evidence, "baidu")
            self.assertTrue(result["public_site_passed"])
            self.assertTrue(result["selected_page_passed"])
            self.assertFalse(result["page_passed"])
            self.assertFalse(result["video_playback_verified"])
            self.assertFalse(result["physical_input_verified"])
            self.assertFalse(result["physical_display_verified"])
            self.assertFalse(trial.page_evidence(local, status, evidence, "bilibili")["public_site_passed"])
            status["result"]["public_no_sandbox"] = False
            self.assertFalse(trial.page_evidence(local, status, evidence, "baidu")["public_site_passed"])
            status["result"]["public_no_sandbox"] = True
            rows[0]["local_probe"] = True
            rows.append({"event": "dom_probe_result", "detail": 31})
            stdout()
            self.assertFalse(trial.page_evidence(local, status, evidence, "baidu")["public_site_passed"])
            rows.pop()
            rows[0]["local_probe"] = False
            rows[2]["metrics"]["page_text"] = "PRIVATE_NEVER_COPY_TO_SUMMARY"
            stdout()
            result = trial.page_evidence(local, status, evidence, "baidu")
            self.assertFalse(result["public_site_passed"])
            self.assertNotIn("PRIVATE_NEVER_COPY_TO_SUMMARY", json.dumps(result))
            rows[2]["metrics"].pop("page_text")
            rows.append({"event": "certificate_denied"})
            stdout()
            self.assertFalse(trial.page_evidence(local, status, evidence, "baidu")["public_site_passed"])

    def test_remote_python35_sources_compile_and_fit_legacy_shell(self):
        state = baseline()
        candidate, session = trial.remote_names("browser-685-" + "a" * 16, "20261020-123456-a1b2c3d4")
        config = {"candidate": candidate, "session": session, "baseline": state, "prewrite_baseline": state,
                  "metadata": {"candidate": candidate, "session": session, "boot_id": state["boot_id"],
                               "hashes": state["hashes"], "manifest_sha256": "a" * 64,
                               "seconds": 120, "uid": 65534, "gid": 65534, "offline_no_sandbox": False},
                  "shell_integration": "wl-shell", "supervisor_finished": False,
                  "manifest_sha256": "a" * 64, "required_bytes": 500000000, "existing": False,
                  "literal_sha256": "b" * 64, "public_site": None, "public_no_sandbox": False}
        class FakeAdb(trial.Adb):
            def __init__(self):
                self.lengths = []
            def run(self, label, args, timeout=30, require=True):
                # Exercise the real Adb.python -> Adb.shell compressor, quoting
                # and 4096-byte guard. This fake never constructs an adb command.
                self.assert_shell = args[0] == "shell"
                self.lengths.append(len(args[1].encode("utf-8")))
                return "RESULT={}\n__REMOTE_EXIT__=0\n", {"host_exit": 0, "remote_exit": 0}
        fake = FakeAdb()
        for site in (None, "baidu", "bilibili"):
            config.update(public_site=site, public_no_sandbox=site is not None)
            config["metadata"].update(public_site=site, public_no_sandbox=site is not None)
            for name in ("REMOTE_PREPARE", "REMOTE_UPLOAD_DIRS", "REMOTE_VERIFY", "REMOTE_FREEZE", "REMOTE_LAUNCH", "REMOTE_STATUS", "REMOTE_STOP", "REMOTE_EVIDENCE"):
                with self.subTest(source=name, public_site=site):
                    guard = trial.REMOTE_SESSION if name in ("REMOTE_LAUNCH", "REMOTE_STATUS", "REMOTE_STOP", "REMOTE_EVIDENCE") else ""
                    source = trial.REMOTE_COMMON + "\nCONFIG=" + repr(config) + "\n" + guard + getattr(trial, name)
                    ast.parse(source, feature_version=(3, 5))
                    packed = base64.b64encode(zlib.compress(source.encode("utf-8"), 9)).decode("ascii")
                    loader = "import base64,zlib;exec(zlib.decompress(base64.b64decode(%r)))" % packed
                    wrapped = "(python3 -B -c " + shlex.quote(loader) + "); rc=$?; printf '\n__REMOTE_EXIT__=%s\n' \"$rc\""
                    self.assertLess(len(wrapped.encode("utf-8")), 4096)
                    trial.device_call(fake, name, getattr(trial, name), config, bool(guard))
                    self.assertTrue(fake.assert_shell)
                    self.assertLess(fake.lengths[-1], 4096)

    def test_lifecycle_exit_zero_alone_cannot_pass_page(self):
        with tempfile.TemporaryDirectory() as folder:
            local = Path(folder)
            (local / "browser.stdout.raw").write_bytes(b'{}\n')
            result = trial.page_evidence(local, {"complete": True, "result": {"passed": True}}, {"files": []})
            self.assertTrue(result["lifecycle_passed"])
            self.assertFalse(result["page_passed"])

    def test_page_acceptance_requires_identity_dom_and_real_png_bytes(self):
        with tempfile.TemporaryDirectory() as folder:
            local = Path(folder)
            capture = local / "app" / "captures" / "local-fixture-window.png"
            capture.parent.mkdir(parents=True)
            capture.write_bytes(png_bytes())
            rows = [{"event": "runtime_identity", "qt": "6.8.5", "webengine": "6.8.5", "chromium": "122.0.6261.171", "local_probe": True},
                    {"event": "load_succeeded"}, {"event": "dom_probe_result", "detail": 31},
                    {"event": "local_capture_saved", "width": 800, "height": 480,
                     "evidence_kind": "application-window", "physical_scanout_verified": False}]
            def stdout():
                (local / "browser.stdout.raw").write_bytes(b"".join((json.dumps(dict(row, schema=1, component="p011-browser-probe")) + "\r\r\n").encode() for row in rows))
            stdout()
            status = {"complete": True, "result": {"passed": True}}
            evidence = {"files": [{"path": "app/captures/local-fixture-window.png", "sha256": trial.digest(capture)}]}
            result = trial.page_evidence(local, status, evidence)
            self.assertTrue(result["page_passed"])
            self.assertFalse(result["capture_visual_reviewed"])
            rows.append({"event": "render_process_terminated"})
            stdout()
            self.assertFalse(trial.page_evidence(local, status, evidence)["page_passed"])
            rows.pop()
            stdout()
            capture.write_bytes(capture.read_bytes()[:-1])
            self.assertFalse(trial.page_evidence(local, status, evidence)["page_passed"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
