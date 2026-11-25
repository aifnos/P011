#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Narrow host static guardrails; no Qt build or hardware acceptance implied."""
import json
from pathlib import Path
import re

app = Path(__file__).resolve().parents[1] / "app"
cpp = (app / "main.cpp").read_text(encoding="utf-8")
qml = (app / "Main.qml").read_text(encoding="utf-8")
html = (app / "home.html").read_text(encoding="utf-8")
cmake = (app / "CMakeLists.txt").read_text(encoding="utf-8")
public_metrics = (app / "public_metrics.js").read_text(encoding="utf-8")
checks = []

def require(name, condition):
    checks.append({"name": name, "passed": bool(condition)})
    if not condition:
        raise AssertionError(name)

require("outer_geometry_once", len(re.findall(r"\by:\s*106\b", qml)) == 1
        and "height: 268" in qml and "height: 480" in qml and "width: 800" in qml)
require("no_rotation", not re.search(r"\brotation\s*:", qml))
require("qt_6_8_candidate", "find_package(Qt6 6.8.5 REQUIRED" in cmake
        and 'VERSION_LESS "6.9.0"' in cmake)
require("runtime_identity", all(name in cpp for name in (
    "qVersion()", "qWebEngineVersion()", "qWebEngineChromiumVersion()",
    "qWebEngineChromiumSecurityPatchVersion()")))
require("bounded_seconds", "(!interactiveMode && seconds > 120)" in cpp
        and "seconds > 1800" in cpp
        and 'QStringLiteral("30")' in cpp and "deadline.start(seconds * 1000)" in cpp)
require("default_local_resource", 'qrc:/p011-browser/home.html' in cpp
        and "site.isEmpty() ? kLocalPage" in cpp)
require("owned_capture_path", '/app' in cpp and "directory.canonicalFilePath() == path" in cpp
        and "directoryInfo.canonicalFilePath() != directory" in cpp
        and '"/local-fixture-window.png"' in cpp and "QFileInfo::exists(output)" in cpp)
require("application_capture_boundary", '"application-window"' in cpp
        and '"physical_scanout_verified"), false' in cpp and "m_window->grabWindow()" in cpp)
require("https_no_credentials", 'url.scheme() == QStringLiteral("https")' in cpp
        and "url.userInfo().isEmpty()" in cpp)
require("private_profile", "offTheRecord: true" in qml
        and "WebEngineProfile.NoPersistentCookies" in qml)
require("permissions_certificate_download_denied", all(code in qml for code in (
    "permission.deny()", "error.rejectCertificate()", "download.cancel()", "request.reject()")))
require("no_arbitrary_native_bridge", not any(token in cpp + qml for token in (
    "QProcess", "system(", "popen(", "import QtWebChannel", "registerObject(",
    "webChannel:", "killall", "remount", "no-sandbox", "QTWEBENGINE_DISABLE_SANDBOX")))
require("no_fonts_bundled", not any(p.suffix.lower() in (".ttf", ".otf", ".woff", ".woff2")
                                  for p in app.rglob("*")))
require("local_fixture_network_free", "connect-src data:" in html
        and not re.search(r"https?://", html))
require("no_page_text_logging", "onJavaScriptConsoleMessage: function(level, message, lineNumber, sourceID) {}" in qml
        and "console.log" not in html + qml
        and "parser.errorText()" not in cpp)
require("no_item_data_redeclaration", not re.search(r"property\s+\w+\s+data\s*:", qml))
require("fixed_public_sites_without_custom_url_argument", all(value in cpp for value in (
    '"https://www.baidu.com/"', '"https://www.bilibili.com/"', 'QStringLiteral("public-site")'))
    and 'QStringLiteral("url")' not in cpp and "url.host() == m_url.host()" in cpp)
require("public_capture_names_are_fixed", all(value in cpp for value in (
    '"/public-baidu-window.png"', '"/public-bilibili-window.png"', "filename.isEmpty()")))
require("public_metrics_are_delayed_and_packaged", "interval: 2000" in qml
    and "PublicMetrics.script()" in qml and 'public_metrics.js' in cmake)
require("public_metrics_fixed_numeric_boolean_output", 'values.size() != booleanKeys.size() + numericKeys.size()' in cpp
    and "value.isBool()" in cpp and "value.isDouble()" in cpp and "std::isfinite(number)" in cpp
    and '"public_page_metrics"' in cpp and not re.search(r"console\.|location\.|\.href\b", public_metrics))
print(json.dumps({"scope": "host-static-source-guardrails", "passed": True, "checks": checks,
                  "qt_compiled": False, "qt_executed": False, "device_executed": False},
                 ensure_ascii=False))

