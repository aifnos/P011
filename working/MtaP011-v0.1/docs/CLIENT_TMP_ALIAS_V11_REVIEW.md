# CLIENT fixed tmp alias v11 — SOURCE / HOST FakeIO only

## Scope and immutable origins

The isolated sources are under `candidate/client-tmp-alias-v11/runtime/`.
Coordination starts from `ea2f27c6920b4dd2cf47e5f71015382bd08dba65ed7eba9927c16f9a219b408d`;
FILES starts from `d95afa25d82c02592d3e4d5a904a397d0f3c366124f793433131bd3d62342ed3`.
Neither original file is edited. This is not a tested P011 release, an Executor,
Store finish, inherited-OFD proof, restoration or a radio admission.

## Exact profile and API

`FixedTmpAnchor(owner, io, root_ticket, fd_of, open_dir, check)` is pure.
The exact owner stores the object in its private `_tmp_alias` slot before use;
`owner._io` must remain the exact IO. Original callbacks and root reference are
retained in one context. `fd_of` verifies the caller's exact known/live original
ticket; `open_dir` registers before opening and retains unknown returns;
`check` uses the caller's existing finite monotonic operation deadline.

`prepare()` opens only physical `var` and `volatile` through that callback.
`tmp_parent` returns the original volatile ticket. The caller opens its original
tmp-target ticket and calls `bind_tmp(ticket)`. `authenticate(owner, root)` does
fresh FD/entry/link checks and returns the same object, not a Boolean permit.
`prefix_tickets` retains partial known returns; the helper never closes a ticket.
Any observation error is sticky; no rebind, rebase or retry is supplied.

IO is only `stat_root()`, `stat_at(parent_fd, name)`, `fstat(fd)`, and
`readlink_at(parent_fd, 'tmp')`; caller opens use NOFOLLOW/DIRECTORY/CLOEXEC.
The only alias shape is `/tmp -> /var/tmp -> /var/volatile/tmp`.
Both links are root:root symlink0777/nlink1, exact targets and stable full
lstat metadata. Physical `/var` is root:root0755; `/var/volatile` and its `tmp`
are root:root01777. No arbitrary symlinks or writable directories are allowed.
Directory identities compare dev/ino/type/mode/uid/gid; changing normal entry
timestamps, size or positive directory link count is not an identity change.
Historical device observations define this policy, not a fresh FD admission.

## Composition and inventory

Logical root/tmp/base/run remain four anchors; index1 remains the actual global
device-lock/pending parent and index3 the run. The physical tmp parent is the
original volatile ticket. Two extra original prefix tickets are not logical
anchors but are in the caller's actual inventory and all close/readback paths.
Coordination permits 8 initial / one 9th handoff ticket only in this profile;
ordinary `/tmp` directory behavior remains original 6 / one 7th. FILES keeps
its 256 limit. The two logical core locks are not an eight-item CloseProof.
All normal anchor validations additionally authenticate the fixed aliases.
Private base/run0700, file0600/nlink1, full canonical CAS and marker rules remain.
Any old/global pending entry blocks; there is no clear or migration operation.
Malformed opens returning an already-live numeric FD retain an unknown ticket
and do not close the borrowed original. Known originals close once, independently;
device-last includes both new prefix tickets. Sticky close unknown is not erased.

## Actual HOST evidence and limitations

First command: `python -B -m unittest discover -s tests -p test_client_tmp_alias_v11.py -v`.
Tool `123357`: 24 methods, 0.099s, 23 PASS / 1 ERROR, exit1 (wall0.582442s).
The sole ERROR was a fixture expecting MemoryError; unchanged Coord `_report`
maps Exception, including MemoryError, to fixed CoordinationError `io_error`.
Only that expected exception was corrected; production sources were not changed.
Tool `801c24`: that exact one affected method, 0.002s, PASS / exit0
(wall0.3617827s). The original first result is retained; no whole-batch rerun.
The first batch includes Python3.5 AST checks for all three candidate sources,
pure constructor/tripwire checks, actual candidate composition over FakeIO,
ordinary and alias real marker binding/journal handoff, changed aliases/prefixes,
unknown/borrowed/late opens, close errors/device-last and pending preservation.

These are 24 distinct HOST methods, not Linux/P011 syscalls, locks, mount/namei,
device staging, init/restore, phone association or file transfer acceptance.
No OS lock/tmp experiment, ADB, RF, permission/link change or legacy cleanup ran.
F bootstrap, Provider and host staging belong to other authors and require a
separately reviewed fixed source graph; this document does not certify their code.
