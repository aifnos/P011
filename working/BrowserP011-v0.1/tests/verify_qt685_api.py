#!/usr/bin/env python3
"""Read the actual Qt 6.8.5 source declarations; no build or ADB operations."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--container", required=True)
    args = parser.parse_args()
    requirements = {
        "src/webenginequick/api/qquickwebengineprofile.h": (
            r"Q_PROPERTY\(PersistentPermissionsPolicy persistentPermissionsPolicy",
            r"\bStoreInMemory\b", r"\bMemoryHttpCache\b", r"\bNoPersistentCookies\b"),
        "src/webenginequick/api/qquickwebengineview_p.h": (
            r"void permissionRequested\(QWebEnginePermission", r"void navigationRequested\(",
            r"void renderProcessPidChanged\(qint64 pid\)", r"void registerProtocolHandlerRequested\(",
            *(r"void " + value + r"\(" for value in ("certificateError", "newWindowRequested",
                "fileDialogRequested", "javaScriptDialogRequested", "authenticationDialogRequested", "contextMenuRequested"))),
        "src/webenginequick/api/qquickwebenginesettings_p.h": tuple(
            r"Q_PROPERTY\([^\n]*\b" + value + r"\b" for value in (
                "javascriptCanOpenWindows", "javascriptCanAccessClipboard", "javascriptCanPaste",
                "localContentCanAccessRemoteUrls", "localContentCanAccessFileUrls", "pluginsEnabled",
                "fullScreenSupportEnabled", "screenCaptureEnabled", "allowRunningInsecureContent",
                "allowGeolocationOnInsecureOrigins", "allowWindowActivationFromJavaScript",
                "hyperlinkAuditingEnabled", "dnsPrefetchEnabled", "navigateOnDropEnabled",
                "unknownUrlSchemePolicy")),
        "src/webenginequick/api/qquickwebenginedialogrequests_p.h": (
            r"Q_PROPERTY\(bool accepted READ isAccepted WRITE setAccepted", r"void dialogReject\(\)"),
        "src/core/api/qwebenginenavigationrequest.h": (r"Q_INVOKABLE void reject\(\)",),
        "src/core/api/qwebenginepermission.h": (r"Q_INVOKABLE void deny\(\) const",),
        "src/core/api/qwebenginecertificateerror.h": (r"Q_INVOKABLE void rejectCertificate\(\)",),
        "src/core/api/qwebengineregisterprotocolhandlerrequest.h": (r"Q_INVOKABLE void reject\(\)",),
        "src/core/api/qtwebenginecoreglobal.h": tuple(r"\b" + value + r"\(" for value in (
            "qWebEngineVersion", "qWebEngineChromiumVersion", "qWebEngineChromiumSecurityPatchVersion")),
        "src/webenginequick/api/qtwebenginequickglobal.h": (r"void initialize\(\)",),
    }
    source = """import hashlib,json,pathlib
root=pathlib.Path('/browser-work/sources/qtwebengine-6.8.5')
files=%r
rows=[]
for name in files:
 raw=(root/name).read_bytes()
 rows.append(dict(path=name,sha256=hashlib.sha256(raw).hexdigest(),text=raw.decode('utf-8')))
print(json.dumps(dict(files=rows,chromium_version=(root/'CHROMIUM_VERSION').read_text())))
""" % sorted(requirements)
    output = Path(__file__).resolve().parent / "results" / ("HOST_QT685_API-" + uuid.uuid4().hex[:12])
    output.mkdir(parents=True, exist_ok=False)
    result = subprocess.run(["docker", "exec", args.container, "python3", "-c", source],
                            capture_output=True, timeout=30)
    (output / "source-read.stdout.raw").write_bytes(result.stdout)
    (output / "source-read.stderr.raw").write_bytes(result.stderr)
    record = {"scope": "HOST_SOURCE_API_ONLY", "passed": False, "host_exit": result.returncode,
              "device_accessed": False, "qt_compiled": False, "qml_compiled": False,
              "qt_executed": False, "chromium_executed": False, "checks": [],
              "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    if result.returncode == 0:
        snapshot = json.loads(result.stdout)
        for row in snapshot["files"]:
            for pattern in requirements[row["path"]]:
                record["checks"].append({"file": row["path"], "pattern": pattern,
                                         "passed": re.search(pattern, row["text"]) is not None})
        record["source_files"] = [{"path": row["path"], "sha256": row["sha256"]} for row in snapshot["files"]]
        record["chromium_version"] = snapshot["chromium_version"]
        record["passed"] = all(row["passed"] for row in record["checks"])
    (output / "host-results.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"scope": record["scope"], "passed": record["passed"],
                      "checks": len(record["checks"]), "result_dir": str(output)}))
    return 0 if record["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
