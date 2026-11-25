# Isolated CLIENT connection A+B — SOURCE / HOST only

This is a callable association-only implementation, not a production Provider,
phone compatibility result or tested release. No F/Parent CONNECT frame, State
entry, RF capability, DHCP, address installation, data socket or endpoint is
enabled. Xiaomi 15 Ultra remains PHONE_NOT_TESTED. No device action was taken.

## Scope and entry

- `candidate/client-connection/runtime/mta_client_linux_provider.py` is the
  isolated copy of original Provider SHA `8996ae6aa82e48170514f61fc301a83532cf28a20f385153ff41c1e68b236544`.
- Its existing `assemble()` returns the same five exact owner components.
  A trusted internal caller may call `lease.connect_p2p(exact P2pInfo)` once,
  `lease.read_connection(exact last observation)` for a new observation, and
  `lease.disconnect_p2p()` once. Only these new methods use the new module
  `mta_client_connection.py`. No arbitrary command/path parameter is supplied.
- `P2pInfo.key is None` is revalidated and copied, not BLE authentication.
  Future C must bind its actual decrypted input to operation/native epoch/task.
  This real import graph is 21 modules: the existing 19 plus connection and
  `mta_protocol` (which reuses existing `p011_json`). No dependency is omitted
  merely to preserve a source-count label.

## Ownership, commands and facts

- Init already durably owns the private daemon, type8 interface and empty
  private config. Connect reclaims journal exactly once through the existing
  released-journal channel, saves returned actual locks/current, verifies them,
  then marks `_restore_held`. Restore uses that same current journal; it must
  not reacquire a second time. No new journal stage or persistent profile.
- All operations hold the actual Store outer RLock. Context checks same F,
  current locks, journal, original TTL, exact live controller, exact CREATE
  Origin, endpoints and anchors. The durable Origin is checked by full key,
  not mistaken for the actual CREATE object's identity after codec readback.
- Existing non-ATTACH command socket is retained. A second owned socket is
  registered before creation, no-inherit, abstract bound, PASSCRED and exact
  root-owned private endpoint checked. It must authenticate an actual ATTACH
  OK before profile commands. Every datagram verifies controller PID/UID/GID,
  endpoint/anchor/actor again, flags, size and ancillary; rights stay in the
  existing ledger and are rejected, not silently discarded.
- Fixed ADD_NETWORK, eight codec-generated SET_NETWORK fields and
  P2P_GROUP_ADD persistent=N only; no SAVE_CONFIG, SCAN, extra interface,
  process or L3 mutation. An unknown ADD reply is never guessed or removed.
  Command failure requires normal exact-daemon/interface restore later.
- Pre-group stale events, duplicate group/removed events, wrong CLIENT/name/
  SSID/security and optional IP profile are rejected. Informational events are
  bounded and retained privately, never taken as successful association.
- Actual group event plus two fresh completed STATUS packets, exact owned
  interface and full original baseline form a private connection observation.
  STATUS p2p_device_address is local, not remote GO. go_dev_addr/advertised MAC
  equality is only a hint, including zero/mismatch cases: no DHCP proof or
  trusted GO endpoint is ever issued. Readback expires with original RF TTL.
- DISCONNECT OK plus a fresh disconnected STATUS is only an observation,
  never restoration/transfer completion. All sockets remain in the original
  Provider ledger until its original once-close/EBADF cleanup. Unknown factory,
  truncation or FD close state stays pending; no retry/automatic old recovery.

## Budgets and exact evidence

The original MAX_ROWS, MAX_OBSERVERS, MAX_PROC_CALLS and FILES resource limits
are unchanged. New limits: 128 retained datagrams, 64 events, 8 per drain,
0.2-second bounded receives, original deadline <=20 seconds; callback/OS calls
are not forcibly preempted. HOST fixed clocks do not validate ARM performance.
Restore still has its separate <=20-second I/O budget and unchanged body.

- First tool `e9540c`: 24 methods / 6.648s / exit1, 14 PASS, 3 FAIL, 7 ERROR.
  Earliest shared failure was using decoded journal Origin as CREATE owner,
  so later negative examples had not yet reached their intended fault. Kept.
- Narrow correction only chooses the original Provider Origin, with full
  durable-key match. Tools `60b91c` + `fe75ee` + `35829e`: exactly 20 affected
  methods / 22.538s / OK / exit0. Four already verified earlier preconditions
  were not repeated; 24 distinct methods total, not 44 or a project suite.
- Fixtures exercise real B Store/coordination/FILES/marker handoff and original
  ledger over FakeIO. Saved launch actors, kernel, STATUS/event responses and
  clock are synthetic. No real init, fork, socket, WSL, OS lock, ADB or RF.
  Python 3.5 AST and unchanged original restore AST were checked in the focused
  test. Original Provider SHA remained unchanged.

## Required next admission

The original restore currently passes `record.owned` to an exact-object origin
gate; codec value-object identity may require a separately reviewed narrow
argument adaptation. This is a SOURCE finding, not observed P011 failure,
and no old restore/body was changed here. C must also select ROOT-reviewed
route-multiplicity core/collector candidates in its actual fixed graph, not
automatically deploy the old 8996 graph. Full F pipe binding, actual init plus
connection/restore and phone acceptance remain untested. Production gates false.

Primary: fixed official 2.12 archive `source/wpa_supplicant-2.12.tar.gz`
(SHA `08e23937e16d0155e55cab2b51f51fbe10d80a1aa91c4e15442645059b737ef6`),
ctrl_iface_unix.c ATTACH L160/228; p2p_supplicant.c GROUP event L1430, private
client/reused-interface L6200/8115/8430. The [official control-interface guide](https://w1.fi/wpa_supplicant/devel/ctrl_iface_page.html)
also explains separate command and attached-event channels; its displayed API
version is older, so exact codec fields are grounded in the fixed 2.12 source.
