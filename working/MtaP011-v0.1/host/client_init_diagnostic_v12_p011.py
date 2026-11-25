"""Isolated diagnostic v12 CLIENT entry; defaults to PC source inspection.

The frozen v11 infrastructure and staging policy are reused verbatim. This
entry replaces only three diagnostic sources, labels, and the private IPv4
projection. It does not clean the retained v11 stage or bypass its admission.
Unfrozen pins make both the default and explicit execution fail closed.
"""
import hashlib
from pathlib import Path

_V11_SHA = '89a982b0fba22e9720e00a98d95a84547287d38945567f2a53c639e8c5f09248'
_V11_PATH = Path(__file__).absolute().parent / 'client_init_tmp_alias_v11_p011.py'
_V11_RAW = _V11_PATH.read_bytes()
if hashlib.sha256(_V11_RAW).hexdigest() != _V11_SHA:
    raise ValueError('v11_pin')


def _change_once(value, before, after):
    if value.count(before) != 1:
        raise ValueError('v12_delta')
    return value.replace(before, after, 1)


_V11_CODE = _change_once(_V11_RAW,
    b"\nif __name__ == '__main__': sys.exit(main())", b'\n')
_V11_CODE = _change_once(_V11_CODE,
    b"'client-init-tmp-alias-v11'", b"'client-init-diagnostic-v12'")
_V11_CODE = _change_once(_V11_CODE,
    b"'MtaP011-ClientInitTmpAliasV11-'", b"'MtaP011-ClientInitDiagnosticV12-'")
exec(compile(_V11_CODE, '<sha-protected-tmp-alias-v11-host>', 'exec'), globals())
__doc__ = 'Diagnostic v12: source-only by default; no retained-stage cleanup.'

# Three isolated copies frozen by their owners; this alone is not RF admission.
_DIAGNOSTIC_PINS = {
    'mta_client_executor': '549cd0652434d934134e465ddfc08c9baf7df9293acb7e567ce9c1a1285bd78f',
    'mta_client_two_phase_lease': '03210b8c83df82993a0322398169f1ac42836d52ab8e3add92617c34b9191bad',
    'mta_client_linux_provider': '17e09c40d4c04c048b46e50de1151a97726086c0b43cace8a0c7e5fd3d7eb288',
}
_FROZEN = _FROZEN and all(type(pin) is str and re.fullmatch('[0-9a-f]{64}', pin)
    for pin in _DIAGNOSTIC_PINS.values())
if _FROZEN:
    EXECUTOR_SHA = _DIAGNOSTIC_PINS['mta_client_executor']
    PROVIDER_SHA = _DIAGNOSTIC_PINS['mta_client_linux_provider']
    PINS = tuple((name, _DIAGNOSTIC_PINS.get(name, pin)) for name, pin in PINS)
    SOURCE_LOCATIONS.update({name: BASE / ('candidate/client-diagnostic-v12/runtime/' + name + '.py')
        for name in _DIAGNOSTIC_PINS})

# Exact pinned types only: never execute generic _asdict or infer a shape from
# arbitrary namedtuples. This is private logging, not baseline/restore authority.
_PROJECTION_OLD = """def projection(value):
 if value is None or type(value) in (str,bytes,int,float,bool):return value
 if type(value) in (tuple,list):return tuple(projection(x) for x in value)
 if type(value) is dict:return {key:projection(x) for key,x in value.items()}
 if hasattr(value,'__slots__'):return {key:projection(getattr(value,key)) for key in value.__slots__ if not key.startswith('_')}
 return '<private retained owner>'
"""
_PROJECTION_NEW = """def projection(value):
 if value is None or type(value) in (str,bytes,int,float,bool):return value
 ip=modules['mta_ip']
 if type(value) in (ip.IpSnapshot,ip.AddressRecord,ip.RouteRecord,ip.RuleRecord):
  return {key:projection(getattr(value,key)) for key in type(value)._fields}
 if type(value) in (tuple,list):return tuple(projection(x) for x in value)
 if type(value) is dict:return {key:projection(x) for key,x in value.items()}
 if hasattr(value,'__slots__'):return {key:projection(getattr(value,key)) for key in value.__slots__ if not key.startswith('_')}
 return '<private retained owner>'
"""
TARGET = _change_once(TARGET, _PROJECTION_OLD, _PROJECTION_NEW)


if __name__ == '__main__': sys.exit(main())
