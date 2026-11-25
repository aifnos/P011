"""HOST source/pin verification. No ADB, radio or service startup."""
import argparse
import ast
import hashlib
import json
from pathlib import Path

BASE = Path(__file__).resolve().parent
MTA = BASE.parent
WORKING = MTA.parent


def verify(output=None):
    pins = json.loads((BASE / 'TOOLBOX_SOURCE_PINS.json').read_text(encoding='utf-8'))
    for row in pins['files']:
        path = WORKING / row['source']
        if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != row['source_sha256']:
            raise AssertionError('Original toolbox source identity changed')
        if not (BASE / row['target']).is_file():
            raise AssertionError('Copied dependency missing')
    candidates = sorted(p for p in (BASE / 'ToolboxMta-v0.1').rglob('*') if p.is_file() and '__pycache__' not in p.parts)
    for path in candidates:
        if path.suffix.lower() in ('.ttf', '.ttc', '.otf', '.woff', '.woff2'):
            raise AssertionError('Fonts must not be bundled')
        if path.suffix == '.py':
            ast.parse(path.read_text(encoding='utf-8'), feature_version=(3, 5))
    source = (BASE / 'ToolboxMta-v0.1/device/ExtensionPage.qml').read_text(encoding='utf-8')
    assert 'immersiveGame||pageName==="Mta"' in source
    assert 'root.immersiveFeature?0:64' in source
    assert 'toolboxHomeScroller' in source and 'Flickable.HorizontalFlick' in source
    assert 'objectName:"toolboxHeaderTitle"' in source and 'text:(root.pageName===""?"工具箱":' in source
    storage = (BASE / 'ToolboxMta-v0.1/runtime/mta_toolbox_storage.py').read_text(encoding='utf-8')
    assert "'Received')" in storage
    wrapper = (BASE / 'ToolboxMta-v0.1/device/MtaEmbedded.qml').read_text(encoding='utf-8')
    assert 'X-P011-MTA-Token' in wrapper and 'action:"cancel"' in wrapper
    assert 'rotation:' not in wrapper and 'y:106' not in wrapper
    deps = sorted((MTA / 'device').glob('Mta*.qml')) + [MTA / 'device/MtaTheme.js']
    rows = [{'path': str(p.relative_to(MTA)).replace('\\', '/'),
             'sha256': hashlib.sha256(p.read_bytes()).hexdigest()} for p in candidates + deps]
    result = {'evidence_level': 'HOST_STATIC', 'pass': True, 'original_pins': len(pins['files']),
              'candidate_files': len(candidates), 'mta_qml_dependencies': len(deps),
              'no_fonts': True, 'python35_ast': True, 'device_tested': False,
              'phone_interop': 'NOT_TESTED', 'files': rows}
    if output:
        output = Path(output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    print('HOST_TOOLBOX_INTEGRATION_STATIC_PASS original_pins=' + str(len(pins['files'])))
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    verify(parser.parse_args().output)
