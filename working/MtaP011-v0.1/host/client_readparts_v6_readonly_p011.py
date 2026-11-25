"""Fixed readparts-v6 readonly baseline; reuse the reviewed timing transport.

Default source-only. No init/staging/Store lock/child/interface/RF entry is
exposed. The shared v3 timing profile is retained, with one explicit source
replacement and two matching diagnostic site fragments, never a source fallback.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import types

BASE = Path(__file__).absolute().parents[1]
ROOT = BASE.parents[1]
REFERENCE = BASE / 'host/client_init_baseline_v3_p011.py'
REFERENCE_SHA = '518617174571a7f9b8b295083054a44212d67cac0e173340fa4bb4e47b647122'
PROFILE = BASE / 'host/client_baseline_v3_performance_p011.py'
PROFILE_SHA = 'c2077c53c20ef3b6eb1dfc6d2d7a0658807f95569bfb6bd76b8df25155a19a3c'
BASELINE = BASE / 'candidate/client-readparts-v6/runtime/mta_client_baseline.py'
BASELINE_SHA = '1df29147a9cface972c9a2f486fee45c0f33d7979c6ad49dd02cdc330fe9dcc1'
_PROFILE = None


def configured_profile():
    global _PROFILE
    if _PROFILE is not None: return _PROFILE
    if any(p.is_symlink() for p in (REFERENCE,) + tuple(REFERENCE.parents)):
        raise ValueError('reference_shape')
    raw = REFERENCE.read_bytes()
    if hashlib.sha256(raw).hexdigest() != REFERENCE_SHA: raise ValueError('reference_pin')
    ref = types.ModuleType('actor_v5_fixed_reference'); ref.__file__ = str(REFERENCE)
    exec(raw, ref.__dict__); ref._read(REFERENCE, REFERENCE_SHA)
    profile = ref._module(PROFILE, PROFILE_SHA, 'actor_v5_fixed_profile')
    old_legacy = profile._legacy

    original_baseline_sha = profile.BASELINE_SHA
    # Check the frozen reference against its original pin, not the v5 override.
    def legacy_v5():
        value = old_legacy()
        if dict(value.PINS)['mta_client_baseline'] != original_baseline_sha:
            raise ValueError('reference_baseline')
        value.PINS = tuple((name, BASELINE_SHA if name == 'mta_client_baseline' else pin)
            for name, pin in value.PINS)
        value.SOURCE_LOCATIONS = dict(value.SOURCE_LOCATIONS, mta_client_baseline=BASELINE)
        return value

    image_before = "            if fresh.actor.key() != actor.key() or not fresh.actor.live() or not actor.live(): _fail('actor_changed')"
    image_after = ("            if fresh.actor.key() != actor.key() or not fresh.actor.live() or not actor.live():\n"
        "                self._diagnostic_actor_change = ('actor_image', actor, fresh)\n"
        "                _fail('actor_changed')")
    round_before = ("            if tuple(sorted(a.key() for a in self._rounds[0].stock_actors)) != \\\n"
        "                    tuple(sorted(a.key() for a in result.stock_actors)) or any(\n"
        "                        not a.live() for a in self._rounds[0].stock_actors + result.stock_actors): _fail('snapshot_changed')")
    round_after = round_before.replace(": _fail('snapshot_changed')",
        ":\n                self._diagnostic_actor_change = ('snapshot_tasks', self._rounds[0], result)\n"
        "                _fail('snapshot_changed')")
    profile.REPLACEMENTS = ((image_before, image_after),) + profile.REPLACEMENTS[1:5] + ((round_before, round_after),)
    profile._legacy = legacy_v5; profile.BASELINE_SHA = BASELINE_SHA
    # Report/execute pins the actual wrapper that fixes the profile parameters.
    profile.__file__ = str(Path(__file__).absolute())
    _PROFILE = profile
    return profile


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute-readonly', action='store_true')
    parser.add_argument('--expected-driver-sha256')
    args = parser.parse_args(argv)
    if args.execute_readonly != (args.expected_driver_sha256 is not None):
        parser.error('Explicit readonly and reviewed SHA required together')
    try:
        profile = configured_profile()
        if args.execute_readonly:
            output = ROOT / 'logs' / ('MtaP011-ClientReadpartsV6Readonly-' +
                datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S') + '-' + os.urandom(4).hex())
            report = profile.execute(args.expected_driver_sha256, _output=output)
        else: report = profile.source_check()[0]
        print(json.dumps(report, indent=2))
        return 0 if report.get('diagnostic_complete', report.get('source_check_pass', False)) else 1
    except Exception:
        print(json.dumps({'diagnostic_complete': False, 'stage': 'transport_unknown',
            'send_available': False, 'receive_available': False, 'phone_tested': False}))
        return 1


if __name__ == '__main__': raise SystemExit(main())
