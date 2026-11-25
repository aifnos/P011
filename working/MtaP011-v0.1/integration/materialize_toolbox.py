"""HOST-only immutable dependency copy for the MTA toolbox candidate.

Copies source files only, never archives, START scripts, user files or fonts.
Does not invoke ADB, Docker or a device. Existing generated files are preserved.
"""
import hashlib
import json
from pathlib import Path
import shutil

BASE = Path(__file__).resolve().parent
PROJECT = BASE.parents[1]
SOURCE = PROJECT / 'ToolboxNext-v0.5.1-native'
DEST = BASE / 'ToolboxMta-v0.1'
SECTIONS = {
    'device': ('ExtensionPage.qml', 'FilesPage.qml', 'GamesPage.qml', 'DashboardPage.qml',
               'VideoPane.qml', 'Theme.js', 'NativeIcon.qml', 'Label.qml', 'Button.qml', 'Games.js'),
    'runtime': ('server.py', 'storage.py', 'metrics.py', 'audio.py', 'minhttp.py', 'p011_json.py'),
    'web': ('index.html', 'transfer.js', 'transfer.css', 'favicon.svg'),
}


def materialize():
    rows = []
    for section, names in SECTIONS.items():
        for name in names:
            source = SOURCE / section / name
            target_name = ('mta_toolbox_json.py' if name == 'p011_json.py' else 'mta_toolbox_' + name) if section == 'runtime' else name
            target = DEST / section / target_name
            if not source.is_file() or source.is_symlink():
                raise RuntimeError('Expected regular pinned source file')
            target.parent.mkdir(parents=True, exist_ok=True)
            if not target.exists():
                shutil.copyfile(str(source), str(target))
            rows.append({'source': str(source.relative_to(PROJECT)).replace('\\', '/'),
                         'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
                         'target': str(target.relative_to(BASE)).replace('\\', '/')})
    pin = BASE / 'TOOLBOX_SOURCE_PINS.json'
    if not pin.exists():
        pin.write_text(json.dumps({'schema': 1, 'evidence': 'SOURCE_COPY_NOT_DEVICE_PASS',
                                   'files': rows}, ensure_ascii=False, indent=2), encoding='utf-8')
    print('HOST_TOOLBOX_SOURCE_COPY_READY files=' + str(len(rows)))


if __name__ == '__main__':
    materialize()
