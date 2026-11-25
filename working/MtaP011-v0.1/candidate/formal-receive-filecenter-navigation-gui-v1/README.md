# SOURCE-only Receiver to Received navigation candidate

## ROOT execution checkpoint, 2026-10-05 11:18

The original author record below is historical. The fixed GUI20 PC build and
unique P011 file-only stage now passed: 4191494/4194304 bytes, 20 files,
3 directories, 40 readbacks, original77 and validator28 FDs closed. The new
Runner/Worker/validator and exact argument were connected in a distinct HOST;
the single receipt-parser fixture and default SOURCE passed.

The one navigation runtime test failed **before any candidate page** at the
original Startup check_active combined startup_expired guard. READY was zero;
no QtTest import, click, Received listing or new screenshot occurred. This is
not a demonstrated QtTest failure. Original UI was never exited; Owner,
Startup resources, guardian, worker FDs and limited stock/carrier checks
closed, pending=false. Raw failure and its exclusive CONTROL remain retained.

The system QtTest directory, qmldir and plugin file exist, but runtime import,
actual navigation, physical touch and phone transfer remain unverified.
No RF or user-file operation was issued. See
[current layered evidence](../../CURRENT_STATUS.md) and
[builder evidence](BUILD_NOTES.md); do not replay the failed window.

## Historical source-author record

This directory is isolated. No builder, Qt/QML test, graph, device or radio action
has been run for it. The frozen 19-file GUI and all runtime sources are untouched.

## Three-source delta

- `device/FormalEntry.qml`: derived from the frozen Receiver/FileCenter entry;
  adds only an optional candidate Loader, finite report fields and an 18-second
  test watchdog. It loads `NavigationTest.qml` only when the candidate process
  arguments contain the exact flag `--p011-mta-navigation-qt-test-v1`.
  Without this flag the Loader source is empty and QtTest is not imported/run.
- `device/NavigationTest.qml`: new in-process observer and one real button click.
- `device/toolbox/FilesPage.qml`: adds `navigationListedGeneration` and
  `navigationListingOK`. They record the actual current-generation successful
  `/api/files` callback; an ended but failed request does not become page proof.
  The listing, opening, audio, video, request and disposal routes are unchanged.

The remaining GUI sources are reused byte for byte, especially
`ReceiveComposition.qml`, `mta/MtaHost.qml`, `mta/MtaPage.qml`,
`toolbox/ExtensionPage.qml` and `toolbox/MtaEmbedded.qml`.

## Actual path and evidence

The Tester first observes the actual FormalEntry READY state and visible window.
It locates existing `mtaFiles`, `mtaPage` and `mtaEmbedded` object names and requires
a visible/enabled control plus the real backend idle/no-request/no-discovery
status. It clicks `mtaFiles` once through QtTest input. It never calls `clicked()`,
`open()`, `openReceivedDirectory()`, `requestExit()` or an API action itself.

The original MtaEmbedded route issues cancel and obtains a new status. The Tester
reads its real `cancelConfirmed` and `exitApproved` property-change events; the
original source sets exitApproved only after the cancel-confirmed fresh status
is valid, generation-matched and quiescent. It then requires the actual Files
Loader item, directory `Received`, successful same-generation listing, no
selection/audio/transfer view and 750 ms of unchanged visible Files state.

There is one click, no retry, no media/file opening or writing, and no receive,
discovery, scan, pairing or transmission command. Waiting uses a 100 ms Timer,
18-second total guard, 6-second READY, 3-second control and 8-second switch bounds.
The Worker must still use the independently defined navigation_test profile:
original 600+60 service/cleanup, launched+20 display and original finalizer.
This QML never renews or closes that service and never grants a revoked Trial.

Only `P011_MTA NAVIGATION_QTTEST_V1` finite JSON facts are logged: fixed outcome/code,
READY/control/cancel/fresh-status/Files/listing/stability booleans and click count.
No token, endpoint, filename, user directory contents or response payload is logged.
A missing/failed QtTest import or timeout records failure, not a page success.
This receipt is UI evidence only, not no-RF, native restoration or phone proof.

## Qt 5.10.1 seam and pending prerequisites

The Qt 5.10.1 TestCase also imports Qt.test.qtestroot, whose singleton is registered
by quick_test_main, not the ordinary QtTest plugin. This candidate therefore does
not instantiate TestCase or run its automatic lifecycle. It uses the plugin's
registered TestEvent and a local visual-tree lookup bounded to 256 items/24 levels.
References: [TestCase](https://raw.githubusercontent.com/qt/qtdeclarative/v5.10.1/src/imports/testlib/TestCase.qml),
[quick_test_main](https://raw.githubusercontent.com/qt/qtdeclarative/v5.10.1/src/qmltest/quicktest.cpp),
[plugin registration](https://raw.githubusercontent.com/qt/qtdeclarative/v5.10.1/src/imports/testlib/main.cpp).

TestEvent is a version-specific implementation detail, not a stable public API.
Its original mouseClick takes the actual Item and returns false without its
window. True is only native event dispatch availability, never page proof; the
cancel/fresh-status/listing/stability events above remain required. References:
[signature](https://raw.githubusercontent.com/qt/qtdeclarative/v5.10.1/src/qmltest/quicktestevent_p.h),
[implementation](https://raw.githubusercontent.com/qt/qtdeclarative/v5.10.1/src/qmltest/quicktestevent.cpp).

The target's QtTest 1.2 import/native TestEvent availability and the original Z03
candidate's handling of the explicit argv flag have not been verified here.
If either is absent, do not substitute evdev coordinates, synthetic callbacks,
HTTP200 or a HOST preview for a P011 page PASS.

## Next builder inputs, not an implemented builder

`host/build_formal_receive_filecenter_ui_v1.py` provides the original immutable
seam. A new builder must pin the three sources above, replace only the original
FormalEntry/FilesPage rows and add `NavigationTest.qml` at the stage root.
Its existing pure helpers, original ELF/NAV slot/399 untouched QRC resources,
VK Bridge and the other fourteen GUI rows remain pinned/reused.

The GUI source list grows from 16 to 17, payload count from 18 to 19 and staged
count from 19 to 20 including SOURCE.sha256; the same three stage directories
remain. A new validator/stage manifest and Worker GUI session/pins will therefore
be needed. No existing builder, validator or Worker is modified by this source
task. Any later HOST must opt in to both navigation_test and the exact candidate
argv flag, preserve all original close gates and require this separate UI receipt.
