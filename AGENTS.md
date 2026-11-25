# P011 project handoff

Use Chinese by default. The owner works under `D:\project\P011` and expects one-click tests plus logs/results ZIPs.

## Read before touching the device

Read `01_Environment/00-项目交接与当前状态.md`, the version-status table and the latest radio analysis. This archive is not a new tested release. Do not automatically execute archived START scripts.

## Known environment

P011 firmware `z031_v2.1.2-20221124_143128-user`; unisoc-wayland Linux 4.14.174/armv7l; Qt 5.10.1/QML/Wayland. Root ADB was verified. The device Python 3.5.5 lacks stdlib json; target code uses bundled p011_json.py. Do not assume Android, APK, Magisk, scrcpy, qmlscene, apt, or a complete vendor SDK.

Pinned original Z03 SHA-256: `e6760ad70cc17b089fd3dded68e58feb545a6b77f3f653b90d7427104b626997`. Restore/backup sets are partial, not a complete recovery image.

## Current blocking issue

During ToolsTest v0.4.3: net.connman unavailable, wlan0 down; BlueZ reported Powered/Discovering true; stock restoration not confirmed in latest Stop. Do not declare the radios flashed/damaged or repaired. Collect current read-only state before making repair proposals. No current SSH login success is established.

## Development constraints

- Never replace `/usr/bin/Z03`, vendor startup, WCN/NV or system partitions as part of an automatic test.
- No unconditional killall, remount-rw, rm-rf of managed menu path, reset, firmware upgrade or disabling ADB.
- UI uses parent's 800x268 content region; do not duplicate y=106 or apply extra rotation in embedded QML.
- Do not redeclare Item.data for telemetry. Do not expose arbitrary shell commands to browser/WebChannel.
- Preserve original and candidate identity; inspect parent loop, PID/start time, exact paths. Requesting Stop is not proof of restoration.
- Separate raw stdout, stderr, remote exit, host exit, observed page events and physical output. Normalize CRCRLF/ANSI only in derived summaries, retain raw logs.
- SSH requires explicit start, key authentication and narrow listen address; never archive private keys. ADB off must have a verified recovery route.
- Distinguish host/static tests from actual P011 hardware tests. Update evidence/status without rewriting historical logs.
- No bundled font files. Respect source notices. Keep credentials/user data out of public repositories.

## Archive utilities

OPEN_INDEX only opens the catalog. VERIFY and REBUILD_SYSTEM are PC-only, no ADB/SSH. Python helpers use the development PC, not the pen. User-owned logs may contain private identifiers; inspect before sharing.
