"""Request a clean interrupt of this container's exact owned Chromium Ninja."""
import json
import os
from pathlib import Path
import signal

directory = '/browser-work/build-target-qtwebengine/src/core/Release/arm'
matches = []
for entry in Path('/proc').iterdir():
    if not entry.name.isdigit():
        continue
    try:
        raw = (entry / 'cmdline').read_bytes().rstrip(b'\0').split(b'\0')
        args = [value.decode() for value in raw]
        stat = (entry / 'stat').read_text()
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        continue
    if (len(args) == 6 and args[0] == '/usr/bin/ninja'
            and args[1] in ['-j4', '-j8', '-j12']
            and args[2] in ['-l4', '-l8', '-l12']
            and args[3:] == ['-C', directory, 'QtWebEngineCore']):
        start = int(stat[stat.rfind(')') + 2:].split()[19])
        matches.append((int(entry.name), start, args))
if len(matches) != 1:
    raise SystemExit('Expected exactly one owned nested Ninja: ' + repr(matches))
pid, start, args = matches[0]
stat = Path('/proc/{}/stat'.format(pid)).read_text()
if int(stat[stat.rfind(')') + 2:].split()[19]) != start:
    raise SystemExit('Ninja identity changed before interrupt')
print(json.dumps({'event': 'owned_ninja_interrupt', 'pid': pid,
                  'start_ticks': start, 'argv': args, 'signal': 'SIGINT'}), flush=True)
os.kill(pid, signal.SIGINT)
