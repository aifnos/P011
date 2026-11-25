"""Loopback-only browser QA fixture with a PUBLIC synthetic access code.

Never use this fixture to share real user files. No ADB, no real LAN binding.
"""
import pathlib
import sys
import tempfile
import time
BASE=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(BASE/'runtime'))
from server import State
state=State(tempfile.mkdtemp(prefix='p011-web-qa-'),True)
result=state.start_lan('127.0.0.1')
state.lan_code='24681357'  # Public fixture data, not a production credential.
print('WEB_QA_URL='+result['url'],flush=True)
try:
    while state.lan:time.sleep(.5)
except KeyboardInterrupt:pass
finally:state.close()
