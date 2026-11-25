# Owner dispatch model microbenchmark v1

PC-only maker: `host/receive_owner_dispatch_bench_v1_target.py`.
Importing it only defines constants and pure functions; no file/transport is used.

`make_source(inputraws)` accepts exactly the two fixed path-to-bytes inputs:

- Original Owner: 107026 B, SHA-256 `a33b1a4c015bda42fc8ab8ba447fd5f331181df1a5b4240fc82f455dc2b74da7`.
- Dispatch seed: 107104 B, SHA-256 `22aa94d8d5ae2a1dd75c5c98635d80020b318f7071ea84c5c3cb3d85e2805adf`.

Original/new `_context` AST nodes are preserved, including original source positions.
The unchanged original `__init__`/nine methods/error definitions are compiled only.
Definition text is compressed/base64 in at-most-128-character chunks, decoded
outside timing. Generated target source is at most 48000 B, with lines <=256 B;
each uncompressed fixed AST source is bounded by 2 MiB. Raw output cap stays 65536 B.
Each side has its own normal type, namespace and nine real FunctionType bindings.
Only `_context` is called on `object.__new__` field models with `pid=None`.
No real Owner constructor/start/other method/IO/pid/radio/UI operation is called.

Four fixed ABBA groups, 8192 calls per block, 131072 measured calls in total.
Each side warms up for 128 calls before timing; setup/compile are outside timing.
Each block retains monotonic elapsed and process CPU start/end and differences.
Missing, non-finite or backwards target CPU clock explicitly rejects the run.
No adaptive loops, clock checks inside the measured loop, or failed-run retry.

The parent must install a 30-second target alarm before reading fixed-length stdin.
The target does not set/cancel that alarm. Parent HOST deadline remains 45 seconds.
Parent owns source snapshots, raw streams, remote/HOST exits and stock before/after.
`parse(raw)` accepts strict finite MODEL_RESULT data; it does not certify exits.

This is a hot model dispatch benchmark, not full preparation IO, cold startup,
real permission/close proof or a phone/RF acceptance test. ABBA does not remove
frequency/temperature/scheduler variation. Results cannot sign the 10-second gate.
No benchmark, SOURCE, Python, build, ADB or device operation was executed by this
file author. All execution is deferred to Root's source review and fixed driver.
