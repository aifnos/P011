"""Reattach raw log and exit collectors to the exact already-running container."""
import argparse
import datetime
import json
import os
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument('--container', required=True)
parser.add_argument('--out', type=Path, required=True)
parser.add_argument('--reason', default='Previous host writer ended during interrupted turn; Docker build continued')
args = parser.parse_args()
if args.container != 'browser685-webengine':
    raise SystemExit('Only the owned WebEngine build may be observed')
info = json.loads(subprocess.check_output(['docker', 'inspect', args.container], text=True))[0]
if not info['State']['Running'] or not info['Config']['Image'].startswith('browser685-builder:'):
    raise SystemExit('Expected owned running browser builder')
identity = info['Id']
args.out.mkdir(parents=True, exist_ok=False)
record = {'schema': 1, 'container_id': identity, 'container_name': args.container,
          'image': info['Config']['Image'], 'started_at': info['State']['StartedAt'],
          'collector_pid': os.getpid(), 'compiler_restarted': False,
          'collected_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
          'reason': args.reason,
          'device_tested': False}
(args.out / 'start.json').write_text(json.dumps(record, indent=2))
with (args.out / 'stdout.raw').open('xb') as stdout, (args.out / 'stderr.raw').open('xb') as stderr, \
     (args.out / 'build-wait.stdout.raw').open('xb') as wait_out, \
     (args.out / 'build-wait.stderr.raw').open('xb') as wait_err:
    # Subscribe to exit before an --rm container can disappear.
    waiter = subprocess.Popen(['docker', 'wait', identity], stdout=wait_out, stderr=wait_err)
    logger = subprocess.Popen(['docker', 'logs', '--follow', identity], stdout=stdout, stderr=stderr)
    wait_exit = waiter.wait()
    log_exit = logger.wait()
raw_exit = (args.out / 'build-wait.stdout.raw').read_text().strip()
build_exit = int(raw_exit) if raw_exit.isdigit() else None
record.update({'wait_host_exit': wait_exit, 'logs_host_exit': log_exit, 'build_exit': build_exit,
               'completed_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'complete': build_exit is not None})
(args.out / 'result.json').write_text(json.dumps(record, indent=2))
