"""Default SOURCE; explicit readonly QtTest inventory, no import or UI start."""
import argparse
import ast
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import secrets
import zipfile

BASE = Path(__file__).resolve().parents[1]
PROBE = BASE / 'host/device_probe.py'
PROBE_PIN = (8759, 'e7a841ec250adb083c643250bae3a6ac07412e775c4bef98f935f6d1c9fa9348')
TARGET = '''import os,stat
roots=('/usr/lib/qt/qml/QtTest','/usr/lib/qt5/qml/QtTest','/usr/lib/qml/QtTest','/usr/share/qt5/qml/QtTest')
rows=[]
for index,root in enumerate(roots):
 values=[]
 for path,kind in ((root,'directory'),(root+'/qmldir','file'),(root+'/libqmltestplugin.so','file')):
  try:
   value=os.stat(path)
   values.append(stat.S_ISDIR(value.st_mode) if kind=='directory' else stat.S_ISREG(value.st_mode))
  except OSError as error:
   if error.errno not in (2,20):raise
   values.append(False)
 rows.append((index,tuple(values)))
print('RESULT='+repr(tuple(rows)))
'''


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def fresh(path, raw):
    with path.open('xb') as stream:
        if stream.write(raw) != len(raw):
            raise ValueError('inventory_write')
    if path.read_bytes() != raw:
        raise ValueError('inventory_readback')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-device', action='store_true')
    args = parser.parse_args()
    ast.parse(TARGET, feature_version=(3, 5))
    pinned = PROBE.read_bytes()
    if (len(pinned), sha(pinned)) != PROBE_PIN:
        raise ValueError('inventory_transport_pin')
    out = BASE / 'results' / ('navigation-qttest-inventory-v1-' +
        ('device-' if args.check_device else 'source-') +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4))
    out.mkdir(parents=True, exist_ok=False)
    fresh(out / 'private-target.py', TARGET.encode('ascii'))
    fresh(out / 'private-host.py', Path(__file__).read_bytes())
    fresh(out / 'private-transport.py', pinned)
    result = dict(schema='p011-navigation-qttest-inventory-v1',
        passed=False, source_checked=True, device_invoked=False,
        readonly=True, component_imported=False, ui_started=False,
        input_injected=False, rf_requested=False, phone_tested=False,
        original_files_changed=False, native_TestEvent_verified=False,
        QML_import_verified=False, inventory=None, remote_exit=None,
        host_exit=None, error=None)
    try:
        if args.check_device:
            spec = importlib.util.spec_from_file_location('fixed_navigation_inventory_transport', str(PROBE))
            helper = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(helper)
            adb = helper.Adb(out / 'private-raw')
            result['device_invoked'] = True
            # Original transport retains separate raw streams/exits, validates
            # its original remote frame and returns its single literal RESULT.
            rows = adb.python('readonly-qttest-inventory', TARGET, timeout=25)
            if (type(rows) is not tuple or len(rows) != 4 or
                    any(type(row) is not tuple or len(row) != 2 or type(row[0]) is not int or
                        row[0] != index or type(row[1]) is not tuple or len(row[1]) != 3 or
                        any(type(value) is not bool for value in row[1])
                        for index, row in enumerate(rows))):
                raise ValueError('inventory_result_shape')
            result.update(inventory=rows, remote_exit=0, host_exit=0)
        result['passed'] = PROBE.read_bytes() == pinned
    except Exception as error:
        result['error'] = type(error).__name__
    public = (json.dumps(result, indent=2, sort_keys=True) + '\n').encode('ascii')
    readme = (b'Readonly fixed system-directory inventory only. No QtTest import, '
              b'native TestEvent call, candidate UI, input, RF, phone, user file or restoration proof. '
              b'Rows 0..3: /usr/lib/qt/qml/QtTest, /usr/lib/qt5/qml/QtTest, /usr/lib/qml/QtTest, '
              b'/usr/share/qt5/qml/QtTest. Three flags: directory, qmldir, libqmltestplugin.so. '
              b'PASS means the observation completed, not that a component exists or can load.\n')
    fresh(out / 'result.json', public)
    fresh(out / 'README.txt', readme)
    bundle = out / 'public-result.zip'
    with zipfile.ZipFile(bundle, 'x', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('result.json', public)
        archive.writestr('README.txt', readme)
    with zipfile.ZipFile(bundle) as archive:
        if archive.namelist() != ['result.json', 'README.txt'] or archive.read('result.json') != public or archive.read('README.txt') != readme:
            raise ValueError('inventory_zip_readback')
    print(json.dumps(dict(passed=result['passed'], inventory=result['inventory'],
        result_dir=str(out), zip_sha256=sha(bundle.read_bytes())), sort_keys=True))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
