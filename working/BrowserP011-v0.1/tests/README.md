# Host validation boundaries

Run from this directory using the development PC:

```powershell
python .\run_host.py
```

This creates a fresh `results/HOST_ONLY-<random>` directory, retaining separate
stdout/stderr bytes, host exit codes and application-source hashes. Equivalent
individual checks:

```powershell
python .\verify_source.py
node --experimental-vm-modules .\fixture.test.mjs
```

`verify_source.py` checks only selected static guardrails. `fixture.test.mjs`
executes the packaged JavaScript in a Node VM with a minimal synthetic DOM,
including successful Fetch, failed Fetch, scrollability and synthetic versus
trusted input separation. Neither command compiles Qt, launches Chromium or
operates P011. Passing these checks does not establish QML API validity,
WebEngine sandboxing, actual device rendering, touch/IME, network compatibility,
physical display scanout, exit restoration or long-term stability.

The packaged HTML emits five capability bits: 1 = module evaluation,
2 = optional chaining/nullish coalescing, 4 = data-URL Fetch/JSON,
8 = programmatic DOM input/event, 16 = document is taller than its viewport.
The complete mask 31 establishes only the local DOM checks after real WebEngine
execution. It does not establish real touch scrolling or system IME input.

The application accepts `--seconds 1..120` (default 30), optional fixed
`--public-site baidu|bilibili` (default packaged qrc fixture), and optional
`--session /mnt/data/p011-browser/sessions/YYYYMMDD-HHMMSS-hex8/app`.
The host creates the session root and grants the low-privilege browser write
access only to its `app` child. The application validates the canonical directory
and writes at most one application-window screenshot to the selected fixed path:
`app/captures/local-fixture-window.png`, `public-baidu-window.png`, or
`public-bilibili-window.png` in the same captures directory. The two public sites
are fixed HTTPS mappings inside the program; there is no custom URL argument.
After a public page load succeeds, a two-second timer collects only fixed
boolean/numeric DOM metrics and captures this application's own 800×480 window.
The image is not proof of physical display scanout. The application sets no
sandbox-disable or root-launch flags. A separate host supervisor must handle
startup/driver hangs that occur before the Qt event-loop timer can fire.

The host/runtime public mode requires both `--public-site baidu|bilibili` and
`--public-no-sandbox`. It is mutually exclusive with the existing explicit
offline qrc-only `--offline-no-sandbox`; there is no automatic fallback. Its
result is `public_site_passed`, separate from the local fixture's mask-31
`page_passed`. Passing the finite public-page evidence does not establish video
playback, physical input, account flows or compatibility across most websites.

Qt API references checked for the candidate:

- https://doc.qt.io/qt-6.8/qml-qtwebengine-webengineview.html
- https://doc.qt.io/qt-6.8/qml-qtwebengine-webengineprofile.html
- https://raw.githubusercontent.com/qt/qtwebengine/v6.8.5-lts-lgpl/src/core/api/qtwebenginecoreglobal.h
- https://raw.githubusercontent.com/qt/qtwebengine/v6.8.5-lts-lgpl/src/core/api/qwebenginenavigationrequest.h
- https://raw.githubusercontent.com/qt/qtwebengine/v6.8.5-lts-lgpl/src/webenginequick/api/qquickwebenginesettings_p.h
- https://raw.githubusercontent.com/qt/qtwebengine/v6.8.5-lts-lgpl/src/webenginequick/api/qquickwebenginedialogrequests_p.h

Private headers above were read to confirm QML properties/signals only; the
application includes only public Qt headers and does not link private Qt APIs.

The source declarations can also be checked against the actual extracted
6.8.5 archive in a running build container without writing inside the container:

```powershell
python -B .\verify_qt685_api.py --container browser685-qt-target
```

This retains the raw source read, source SHA-256 values and declaration checks in
a fresh `results/HOST_QT685_API-*` directory. A match confirms that the selected
QML properties, signals and public methods are declared by that source. It does
not compile the application or establish successful QML creation.

The separate `host/test_trial.py` suite covers the controller without constructing
an ADB connection. Its payload fixtures are synthetic bytes. Before any upload,
the controller requires its fixed Qt library, Wayland plugin, resource and locale
paths and follows the installed `qmldir` import/dependency closure, checking each
declared dynamic plugin. ELF ABI/dependency acceptance belongs to the real build
audit. A large payload file gets a size-based USB transfer budget of 30 to 180
seconds; device Python snippets and status calls remain bounded by 30 seconds.
No failed candidate or previous session is automatically removed.
