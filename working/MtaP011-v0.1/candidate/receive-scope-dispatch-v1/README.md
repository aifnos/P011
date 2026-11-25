# Scope dispatch v1: one exact source delta and one affected-method fixture

Only `_StartupReadScope._originals` changes. Its existing four-row and six-row
`any(generator)` scans become same-order explicit `for` scans. The prefix,
eager tuple inputs, zip argument reads, row predicates, failure code and bound
clock tail are unchanged. All other method bytes and real IO/deadlines remain.
The unique replacement adds 114 bytes and five lines; seed roots/pins are not
changed. A later deployment graph must compute its own actual payload budget.

`generate.py` is PC-only: default prepares/checks a plan; explicit `--write`
exclusively creates `runtime/mta_client_receive_factory.py` and
`exactsource-delta.json`. It never imports or runs Factory/Scope/Owner/device.
Root owns execution and existing outputs must not be overwritten or retried.

The actual generation attempt produced two files, then returned a readback
identity-check failure. That historical failure is not changed into PASS.
The affected HOST may independently reconcile retained actual bytes using
pure `prepare` plus complete byte/AST inverse and a new source snapshot.

The fixture compiles the entire original/new `_originals` AST without edits.
Explicit normal-type models and attribute/zip seams exercise 67 cases (134
actual method calls). After the first guard and `files=None` branch, the
stubbed `_startup_owner_type` raises a fixed continuation boundary sentinel.
No remaining real Owner/Scope construction, OS IO, clock/deadline, lifecycle,
device or RF code is executed. This is not full-method execution evidence.

Selector: `ReceiveScopeDispatchV1Test.test_originals_dispatch_equivalence`.
Optional `P011_SCOPE_DISPATCH_SNAPSHOT_ROOT` selects the four fixed snapshots.
Optional `P011_SCOPE_DISPATCH_RECEIPT` EXCL-writes the exact literal receipt
only after all cases and source readbacks pass; any failure writes no PASS.
The generator and fixture were not executed by their author. Root is sole
executor of SOURCE, the one affected HOST method, generation and device tests.
