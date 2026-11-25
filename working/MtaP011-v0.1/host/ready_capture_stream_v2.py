"""Host-only raw-preserving process stream, exact READY callback, no ADB itself.

The caller supplies a fixed executable argv and original process timeout.
Only a complete original stdout line can trigger one callback. Raw bytes,
stderr and exit stay separate; partial/timeouts are retained. This module
does not know a device, read a target, run a shell, or grant UI acceptance.
"""
import os
from pathlib import Path
import subprocess
import threading
import time


READY = b'MTA_FORMAL_UI_READY'
MAX_CAPTURED_BYTES = 8388608


class StreamError(RuntimeError):
    pass


def run_stream(argv, directory, stem, timeout, input_data=None, on_ready=None):
    if (type(argv) is not list or not argv or any(type(row) is not str for row in argv) or
            type(stem) is not str or not stem or '/' in stem or '\\' in stem or
            type(timeout) not in (int, float) or not 0 < timeout <= 810 or
            input_data is not None and type(input_data) is not bytes or
            on_ready is not None and not callable(on_ready)):
        raise StreamError('invalid_stream_input')
    directory = Path(directory)
    deadline = time.monotonic() + float(timeout)
    chunks = [[], []]
    sizes = [0, 0]
    errors = []
    callbacks = []
    ready_count = [0]
    process = None
    timed_out = False
    completed = False
    readers = []
    writer = None
    callback_failures = []

    def callback():
        try:
            on_ready()
        except BaseException as error:
            callback_failures.append(error)

    def consume(pipe, index, suffix):
        pending = b''
        long_fragment = False
        try:
            with (directory / (stem + suffix)).open('xb') as raw_file:
                while True:
                    raw = os.read(pipe.fileno(), 65536)
                    if not raw:
                        break
                    if raw_file.write(raw) != len(raw):
                        raise StreamError('stream_short_write')
                    raw_file.flush()
                    sizes[index] += len(raw)
                    if sizes[index] <= MAX_CAPTURED_BYTES:
                        chunks[index].append(raw)
                    # Keep draining/storing raw after an exceeded return
                    # budget, so the child cannot block on a full pipe.
                    if index != 0 or sizes[index] > MAX_CAPTURED_BYTES:
                        continue
                    pending += raw
                    while b'\n' in pending:
                        line, pending = pending.split(b'\n', 1)
                        if not long_fragment and line.rstrip(b'\r') == READY:
                            ready_count[0] += 1
                            if ready_count[0] == 1 and on_ready is not None:
                                thread = threading.Thread(target=callback, name='host-after-ready-capture')
                                try:
                                    thread.start()
                                except BaseException as error:
                                    errors.append(error)
                                else:
                                    callbacks.append(thread)
                        long_fragment = False
                    if len(pending) > 65536:
                        # Long fragments never become an exact short READY.
                        pending = pending[-65536:]
                        long_fragment = True
        except BaseException as error:
            errors.append(error)
        finally:
            try:
                pipe.close()
            except BaseException as error:
                errors.append(error)

    def send():
        try:
            with process.stdin:
                at = 0
                while at < len(input_data):
                    written = process.stdin.write(input_data[at:])
                    if type(written) is not int or written <= 0:
                        raise StreamError('stream_stdin_short_write')
                    at += written
                process.stdin.flush()
        except BaseException as error:
            errors.append(error)

    try:
        process = subprocess.Popen(argv, stdin=subprocess.PIPE if input_data is not None else None,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
        for index, pipe, suffix in ((0, process.stdout, '.stdout.raw'),
                                    (1, process.stderr, '.stderr.raw')):
            thread = threading.Thread(target=consume, args=(pipe, index, suffix),
                                      name='host-carrier-raw-' + str(index))
            thread.start()
            readers.append(thread)
        if input_data is not None:
            thread = threading.Thread(target=send, name='host-carrier-stdin')
            thread.start()
            writer = thread
        try:
            process.wait(timeout=max(.001, deadline - time.monotonic()))
            completed = True
        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()  # Exact host child only; never a target kill command.
            process.wait(timeout=5)
        except BaseException:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            raise
    finally:
        # Startup can fail before the wait block (e.g. second reader start).
        # Reap only this retained HOST child before joining started workers.
        if process is not None:
            try:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)
            except BaseException as error:
                errors.append(error)
        for thread in readers + ([writer] if writer is not None else []):
            try:
                thread.join(timeout=5)
            except BaseException as error:
                errors.append(error)
        for thread in callbacks:
            try:
                # Separate bounded PC observation cleanup, not a renewed
                # subprocess timeout or remote UI/RF display lease.
                thread.join(timeout=145)
            except BaseException as error:
                errors.append(error)
        if process is not None:
            # An unstarted reader has no raw file or ownership of its pipe.
            # Close retained pipe objects, never manufacture absent stderr.
            for pipe in (process.stdout, process.stderr, process.stdin):
                if pipe is not None:
                    try:
                        pipe.close()
                    except BaseException as error:
                        errors.append(error)
        # Equivalent original exit receipt; no combined stdout/stderr stream.
        value = 'TIMEOUT' if timed_out or not completed else str(process.returncode)
        try:
            with (directory / (stem + '.host-exit')).open('x', encoding='ascii') as handle:
                handle.write(value)
        except BaseException as error:
            errors.append(error)
    facts = dict(host_stream_complete=completed and not timed_out,
                 raw_readers_closed=all(not row.is_alive() for row in readers),
                 stdin_writer_closed=writer is None or not writer.is_alive(),
                 callback_closed=all(not row.is_alive() for row in callbacks),
                 ready_stream_count=ready_count[0],
                 callback_failed=bool(callback_failures),
                 stdout_bytes=sizes[0], stderr_bytes=sizes[1])
    if timed_out or not completed:
        raise StreamError('host_stream_timeout')
    if errors or not facts['raw_readers_closed'] or not facts['stdin_writer_closed'] or not facts['callback_closed']:
        raise StreamError('host_stream_io')
    if any(value > MAX_CAPTURED_BYTES for value in sizes):
        raise StreamError('host_stream_output_budget')
    if process.returncode:
        raise StreamError('host_stream_exit')
    return b''.join(chunks[0]), facts
