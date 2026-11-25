"""HOST-only partial input evidence and private-before-public result sealing.

This module starts no child, device, network, runtime role or historical test.
Every output directory is supplied by a checker and must be a fresh run directory.
"""
import hashlib
import json
import os
from pathlib import Path
import traceback
import zipfile


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def need(value, code):
    if value is not True:
        raise ValueError(code)


def fresh(path, raw):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        need(stream.write(raw) == len(raw), 'short_write')
    need(path.read_bytes() == raw, 'artifact_readback')


class InputEvidence:
    def __init__(self, inputs):
        self.inputs = inputs
        self.partial = set()
        self.changed_attempts = []

    def _retain(self, key, raw):
        if key in self.inputs and self.inputs[key] != raw:
            self.changed_attempts.append((key, raw))
            raise ValueError('input_changed')
        self.inputs[key] = raw

    def read(self, path, key=None, pin=None):
        path = Path(path)
        key = path if key is None else key
        collected = bytearray()
        opened = False
        try:
            with path.open('rb') as stream:
                opened = True
                while True:
                    chunk = stream.read(65536)
                    if not chunk:
                        break
                    collected.extend(chunk)
        except BaseException:
            if opened:
                # Preserve bytes returned before an IO failure, not a full-file claim.
                self.partial.add(key)
                self._retain(key, bytes(collected))
            raise
        raw = bytes(collected)
        # A pin rejection still retains the exact rejected, fully read input.
        self._retain(key, raw)
        if pin is not None:
            need((len(raw), digest(raw)) == tuple(pin), 'input_pin')
        return raw

    def snapshot(self, out, label):
        out = Path(out)
        for key, raw in self.inputs.items():
            relative = Path(label(key))
            need(not relative.is_absolute() and '..' not in relative.parts, 'snapshot_path')
            path = out / 'private-inputs' / relative
            if path.exists():
                need(path.read_bytes() == raw, 'snapshot_changed')
            else:
                fresh(path, raw)
        for index, (key, raw) in enumerate(self.changed_attempts):
            fresh(out / 'private-input-attempts' / ('%04d.raw' % index), raw)
        metadata = dict(partial=[label(key) for key in self.partial],
            changed_attempts=[dict(index=index, path=label(key), bytes=len(raw), sha256=digest(raw))
                for index, (key, raw) in enumerate(self.changed_attempts)])
        target = out / 'private-raw/input-read-status.json'
        raw = (json.dumps(metadata, sort_keys=True, indent=2) + '\n').encode('ascii')
        if target.exists():
            need(target.read_bytes() == raw, 'snapshot_status_changed')
        else:
            fresh(target, raw)


def _verify_zip(path, members):
    with zipfile.ZipFile(path) as stream:
        need(stream.namelist() == list(members) and stream.testzip() is None and
             all(stream.read(name) == raw for name, raw in members.items()), 'zip_readback')
    return digest(Path(path).read_bytes())


def _publish(source, destination):
    # Same-run, same-volume hard link; exclusive and does not replace old results.
    os.link(str(source), str(destination))


def seal_result(out, report, readme):
    """Return a False/nonzero report on any sealing failure; never retry a bad ZIP.

    The verified private ZIP is retained. result.json is the final public commit:
    no public PASS JSON is written before ZIP write, CRC and member readback pass.
    A publication failure quarantines only this fresh run's published files.
    """
    out = Path(out)
    sealed = dict(report)
    private = out / 'private-seal'
    published = []
    archive = None
    archive_sha = None
    try:
        private.mkdir(parents=True, exist_ok=False)
        members = {'result.json': (json.dumps(sealed, sort_keys=True, indent=2) + '\n').encode('ascii'),
                   'README.txt': readme}
        for name, raw in members.items():
            fresh(private / name, raw)
        candidate = private / 'candidate-result.zip'
        with zipfile.ZipFile(candidate, 'x', zipfile.ZIP_DEFLATED) as stream:
            for name, raw in members.items():
                stream.writestr(name, raw)
        archive_sha = _verify_zip(candidate, members)
        for source, name in ((private / 'README.txt', 'README.txt'),
                             (candidate, 'public-result.zip'),
                             (private / 'result.json', 'result.json')):
            _publish(source, out / name)
            published.append(name)
        archive = out / 'public-result.zip'
    except BaseException as failure:
        final_trace = traceback.format_exc().encode('utf-8')
        final_error = type(failure).__name__ + ':' + str(failure)
        sealed['seal_error'] = final_error
        sealed['check_error'] = report.get('error')
        sealed['error'] = 'artifact_seal_failed:' + final_error
        sealed['passed'] = False
        sealed['host_exit'] = 1
        # Preserve failures too if writing diagnostics itself fails.
        evidence_errors = []
        try:
            fresh(out / 'private-raw/seal-exception.txt', final_trace)
        except BaseException as diagnostic_failure:
            evidence_errors.append(type(diagnostic_failure).__name__ + ':' + str(diagnostic_failure))
        for name in reversed(published):
            try:
                os.rename(str(out / name), str(private / ('published-' + name)))
            except BaseException as quarantine_failure:
                evidence_errors.append(type(quarantine_failure).__name__ + ':' + str(quarantine_failure))
        sealed['seal_evidence_errors'] = evidence_errors
        failure_members = {'result.json': (json.dumps(sealed, sort_keys=True, indent=2) + '\n').encode('ascii'),
                           'README.txt': readme + b'\nArtifact sealing failed; see private diagnostics. No PASS ZIP is accepted.\n'}
        for name, raw in failure_members.items():
            try:
                fresh(out / name, raw)
            except BaseException as report_failure:
                evidence_errors.append(type(report_failure).__name__ + ':' + str(report_failure))
        archive_sha = None
    return dict(report=sealed, archive=archive, archive_sha256=archive_sha,
                host_exit=0 if sealed.get('passed') is True else 1)
