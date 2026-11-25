#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Import checks only. No SDL initialization, sockets, recording or camera I/O.
Use -B -S: do not write bytecode or run firmware sitecustomize/history handlers.
A missing optional stdlib json module is reported, never required.
"""
import sys
from p011_json import dumps

required = ('argparse', 'ctypes', 'glob', 'math', 'os', 'random', 'signal',
            'stat', 'struct', 'subprocess', 'time', 'threading')
checks = []
for name in required + ('json',):
    result = {'name': name, 'required': name in required, 'ok': False}
    try:
        mod = __import__(name)
        result['ok'] = True
        result['origin'] = getattr(mod, '__file__', '<built-in>')
    except Exception as error:
        result['exception'] = type(error).__name__
        result['message'] = str(error)
    checks.append(result)
missing = [c['name'] for c in checks if c['required'] and not c['ok']]
result = {'schema': 'p011.preflight.v1.1', 'python': sys.version,
          'executable': sys.executable, 'python_path': sys.path,
          'python_version_supported': sys.version_info >= (3, 5),
          'json_backend': 'project-local p011_json (output only)',
          'modules': checks, 'missing_required': missing,
          'ok': not missing and sys.version_info >= (3, 5),
          'note': 'Import success is not proof that target display/input hardware works.'}
print(dumps(result, ensure_ascii=True, indent=2))
# A complete negative diagnostic is still a successfully generated report.
# The Windows launcher separately checks the report's ok field before proceeding.
