# CLIENT v10 bounded preparation — SOURCE / HOST only

This isolated candidate changes only `TwoPhaseClientInitLease.start` from original
`402cf2decd35aa31b47c07828e5ee14b7dd06bb5429740736fd11a54dfd11005`.
The original runtime, frozen Provider, Store, Owner, core and RF gates are unchanged.

## Actual delta

- After the original single-start/provider checks, preparation gets one `now + 20`
  deadline before acquiring the existing shared Store mutex. Waiting counts against
  admission, but this synchronous mutex/OS code does not forcibly preempt blocking.
- Keep original device/journal acquisition, current-empty and pending-absent checks,
  first full baseline, actual Store prior producer, caps and original-actor checks.
  The existing v8 Store still limits its prior producer to five seconds within
  preparation; v10 does not expand that individual read budget.
- Before the first durable prepared record, re-read actual executor proof; require
  its stable Actor key to match the earlier exact proof, then recheck original
  locks, empty current journal and pending absence within the preparation deadline.
  There is no external return or UI wait in this gap.
- Set the active `now + ttl` deadline exactly once immediately before first prepared
  persistence. All later Journal generations and four remaining full snapshots
  retain that same deadline; TTL/default 20 and all remaining start order/refs stay
  unchanged. No create/restore predicate or close/unknown rule is relaxed.

Preparation is not zero-file activity: it acquires locks and reads real components.
Expired/cancelled preparation may retain unresolved resources/finish-incomplete;
it is not reported as restored. Remaining active work can still exceed TTL20;
synthetic timings do not guarantee actual P011 readiness. v8's separate recovery
budget is not copied into this candidate's unchanged restore method.

## Focused evidence (original verdicts retained)

The six new methods clone the unchanged existing fixture into separate globals and
bind the actual isolated v10 class plus v8 Store/Pending graph. Real Store, launch
registry and owner methods execute over FakeIO/FakeKernel; no copied start algorithm
or positive authentication mock replaces them. Existing fixture tripwires prohibit
actual process, file, socket and radio actions.

- First `b96e8c`: six methods, 3 PASS / 1 FAIL / 2 ERROR, unittest 0.885s,
  host exit 1 (wall 1.3787534s). Two tests used a nonexistent public `pending`
  key; positive expectation overlooked the existing prior producer's five-second
  slice. These were test expectations, not production implementation changes.
- Exact affected rerun `22ac4d`: only those three methods, 3 PASS, unittest
  1.583s, host exit 0 (wall 2.0531865s). The other three passed methods were not rerun.
- Six different methods now have passing evidence, not a final six-method batch:
  six full snapshots/deadline separation, preparation expiry/cancel, fresh F/current/
  pending changes, late active phases and retained child/owned refs, invalid TTL and
  default disabled provider, original SHA plus exact start-only diff/Python 3.5 AST.

Command scope: `python -B -m unittest tests.test_client_prepare_v10 -v` initially;
the second invocation names only the three affected `PrepareTests` methods.
No old suite, real Linux/WSL, ADB, P011 RF, phone, SOURCE freeze or host-driver
integration ran. This is not production availability or a tested release.
