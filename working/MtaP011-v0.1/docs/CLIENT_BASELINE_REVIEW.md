# CLIENT baseline collector — HOST implementation, not platform admission

## Scope and API

Only `runtime/mta_client_baseline.py`, its new test module and this review were added.
`BaselineCollector(manifest, timeout=5.0)` is pure; `collect(deadline)` is one synchronous explicit operation returning the existing `core.Snapshot` only after its own resources close strictly.
`manifest` must be the exact three current `core.STOCK_PINS` plus the actual SHA-256 for `/usr/sbin/wpa_cli`; there is no default/placeholder/migration.
`_io`, `_reader`, `_clock` are trusted internal HOST seams, not QML/HTTP parameters. Construction/import performs no device I/O.
The future fixed single-thread F must serialize the collector and retain it when pending. No State/Provider/capability/Store code was changed.

## Actual default read path

The Linux default uses bounded ordinary FD reads, the existing actual `ProcReader`, raw route/generic netlink sockets and a fixed read-only CLI child, not GO backend or old netlink ownership/close labels.
Ordinary files use Linux UAPI `O_RDONLY|O_NOFOLLOW|O_CLOEXEC`, root-owned non-writable binary ancestors, full entry/FD metadata before/after, full content SHA and final rehash; the default validates those UAPI values on Linux.
F identity/boot/all tasks are observed before/between/after rounds; exactly one task is required. Every tracked stock process has actual ProcReader double observations including all tasks, not only comm/PID.
The tracked census is `Z03/control_engine/weston/connmand/wpa_supplicant/bluetoothd`; unreadable numeric proc entries fail closed. Z03/control_engine/weston must each occur exactly once; other observed tracked actors are retained, not invented.
For Z03/control_engine, only after a fresh exact ProcReader actor is obtained, `/proc/<that pid>/exe` is opened with a separately registered CLOEXEC ticket and intentional magiclink following. Its actual image FD metadata must match the pinned disk inode/metadata and its full digest must match that binary pin.
A second actual ProcReader(expected actor) read after hashing must preserve PID/start/exe/cmdline and complete tasks. `argv_sha` is never compared to an executable digest.
Two complete stock task tuples, including state, must agree between rounds in addition to `Snapshot.key()`; R/S transitions currently fail closed rather than being silently normalized.
The only generic commands are CTRL_GETFAMILY and unfiltered nl80211 GET_INTERFACE dump; actual peer `(0,0)` is separate from header-local port. Sequence/port/version/flags/padding/DONE-zero and bounds are checked; ACK/error/truncation/interruption/filtered/duplicate data cannot imply completion.
IPv4 uses the existing pure `mta_ip` complete address/all-table route/policy-rule parsers, including cacheinfo. `structural_key` is not used. Unsupported rows/default-policy mismatches fail closed.
Both complete `/proc/net/if_inet6` six-field and `/proc/net/ipv6_route` ten-field rows are retained, not a digest/excluded subset. These proc formats do not expose IPv6 rule or per-row table identity; this is not an IPv6 mutation-ownership proof.
The exact command is `('/usr/sbin/wpa_cli','-i','wlan0','status')`, no shell/preexec/arbitrary args. Its opened verified executable FD is inherited using `pass_fds` and `executable='/proc/self/fd/<fd>'`; this does not claim tested target fexecve ABI.
CLI stdout/stderr are read incrementally through select/read, at most 16KiB/4KiB (+one overflow byte), not buffered by unlimited communicate. Exit/wait and original pipes are checked. Only COMPLETED with supported 2.4GHz frequency yields a private full STATUS fingerprint.
CLI STATUS does not authenticate which daemon/control namespace answered. Presence of a similarly named WPA process is not a claimed binding. The future Provider still needs original-control-domain authentication.

## Ownership, bounds and privacy

Resource tickets precede open/socket/Popen creation; actual returns, malformed objects and unknown creation tickets are strongly retained. No retry/second collect is permitted.
Each known original is closed at most once; a failed close does not skip remaining originals. Original FD strict EBADF plus wrapper invalidation is used where applicable, but single-thread/external no-FD-reuse ownership remains a caller prerequisite, not proof of the same OFD/executor.
Only a registered exact known read-only CLI child may be killed/waited on timeout; stock processes are never signaled. Unknown spawn/process/partial pipes are retained, not guessed/killed.
Foreign pipe replacement is not closed. Original refs and invalidation/close exceptions remain pending even if a wrapper later says closed. There is no cleanup/retry/restore fallback.
Time budget is .1–10s (default5), shared with supplied deadline; at most 4096 proc entries/rows, 32 interfaces/actors, 8320 resource tickets, 8MiB/1024 netlink datagrams, 64MiB per binary, 1MiB per IPv6 file. Synchronous OS callbacks may block: checks/timeout admission are not hard preemption.
All raw packets/WPA output, actual ProcObservation raw and tickets/partial data stay private; binary checks preserve digest/metadata rather than publishing binaries. `status()` is passive fixed enum/bool/count only, no SSID/MAC/IP/PID/boot/argv/path/raw/error text.
Two rounds are not an atomic kernel snapshot, Executor/OFD proof, restored network, concurrency caps or RF permission. Public `mutation_admission` and `restoration_verified` remain false.

## Evidence and unresolved actual layer

Unique first batch `8cf0c0`: 32 methods / 0.056s / exit1 = 9 PASS, 17 FAIL, 6 ERROR. The principal shared failure was Windows missing os.O_NOFOLLOW/CLOEXEC before FakeIO, plus valid multi-task refusal incorrectly conflated with unknown resource. That historical failure remains unchanged.
Named affected batch `7797eb`: 28 methods / 0.060s / OK / exit0 after explicit Linux UAPI flags and separate actual-close/actor-admission checks; four unaffected pure constructor/budget/AST methods were not repeated.
After ROOT review, the process-image/full-task checks were added. Batch `0b4597`: 3 new + 3 directly affected named methods / 0.031s / OK / exit0, including Python3.5 AST. The current module has 35 methods; this is not a claim that all 35 ran together on the final source.
HOST uses FakeIO/FakeProc/FakeSocket/FakePopen; all default OS/socket/Popen/select/libc/actual ProcReader paths are tripwired. Synthetic binary hashing is an explicitly patched HOST seam, not verification of real stock bytes/pins.
No actual Linux/P011 collector, socket, child, wpa_cli, proc image, firmware equivalence, phone or RF operation was run in this task. The actual wpa_cli SHA is still missing; the real manifest must therefore not be constructed with an invented pin.
Current old global pending/stock baseline/actual device blockers are not cleared or reclassified by this component. Original task F/current firmware/control-domain authentication and later mutation admission remain external work.

## Primary format references

[Linux v4.14 nl80211 send/dump interface](https://github.com/torvalds/linux/blob/v4.14/net/wireless/nl80211.c#L2404-L2533) emits NEW_INTERFACE and optional netdev identity; a non-netdev record lacking required ifindex/name is rejected rather than omitted.
[Linux v4.14 IPv6 address proc formatter](https://github.com/torvalds/linux/blob/v4.14/net/ipv6/addrconf.c#L3935-L3944) casts flags to u8; index minimum width may expand, flags remain two hex digits.
[Linux v4.14 IPv6 route proc formatter/iterator](https://github.com/torvalds/linux/blob/v4.14/net/ipv6/ip6_fib.c#L1995-L2129) is preserved in full; volatile route counters can conservatively prevent dual-round equality.
[Linux v4.14 fixed open flag UAPI](https://github.com/torvalds/linux/blob/v4.14/include/uapi/asm-generic/fcntl.h) defines the explicit Linux-only no-follow/CLOEXEC constants; missing/other target semantics are not silently emulated.
