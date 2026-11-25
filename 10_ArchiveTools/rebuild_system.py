#!/usr/bin/env python3
"""Reassemble the owner's eight system-image slices on the PC only; never flash."""
import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import sys
import zipfile

EXPECTED = 'e22201045d0bbbd11ffc947316ddeb4fc97fcfab51508d3ce29795be47e61c84'
TOTAL = 1073741824
SLICE = 134217728

def sha_file(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            h.update(block)
    return h.hexdigest()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--verify-only', action='store_true')
    parser.add_argument('--output', type=Path, help='New output file; existing files are never overwritten')
    args = parser.parse_args()
    target = None
    partial = None
    output = None
    try:
        root = args.root.resolve()
        metadata = json.loads((root / '06_Firmware/metadata/system-parts.json').read_text(encoding='utf-8-sig'))
        if len(metadata) != 8:
            raise ValueError('Expected exactly eight slices')
        for index, item in enumerate(metadata, 1):
            if (item['part'] != index or item['total_parts'] != 8 or
                    item['offset_bytes'] != (index-1)*SLICE or
                    item['length_bytes'] != SLICE or item['full_image_bytes'] != TOTAL or
                    item['full_image_sha256'].lower() != EXPECTED or
                    item['uncompressed_entry'] != 'system.img.part{:02d}.bin'.format(index)):
                raise ValueError('Slice metadata inconsistent: {}'.format(index))
            archive = root / '06_Firmware/system-parts' / item['archive_filename']
            if archive.parent.resolve() != (root / '06_Firmware/system-parts').resolve():
                raise ValueError('Unsafe archive name')
            if not archive.is_file():
                raise FileNotFoundError('Missing firmware archive: {} (tools edition does not include it)'.format(archive))
            if sha_file(archive) != item['archive_sha256']:
                raise ValueError('Archive SHA mismatch: ' + archive.name)
        if not args.verify_only:
            output = args.output or root / 'working' / ('system-' + datetime.now().strftime('%Y%m%d-%H%M%S-%f')) / 'system.img'
            partial = Path(str(output) + '.partial')
            if output.exists() or partial.exists():
                raise FileExistsError('Refusing to overwrite output or partial file: ' + str(output))
            output.parent.mkdir(parents=True, exist_ok=True)
            target = partial.open('xb')
        full = hashlib.sha256()
        total = 0
        verified = []
        for index, item in enumerate(metadata, 1):
            part = hashlib.sha256()
            length = 0
            archive = root / '06_Firmware/system-parts' / item['archive_filename']
            with zipfile.ZipFile(archive) as z:
                original = json.loads(z.read('slice-manifest.json').decode('utf-8-sig'))
                for key in ('part','total_parts','offset_bytes','length_bytes','uncompressed_entry','full_image_sha256','part_sha256'):
                    if original[key] != item[key]:
                        raise ValueError('Inner manifest differs: ' + key)
                info = z.getinfo(item['uncompressed_entry'])
                if info.file_size != SLICE:
                    raise ValueError('Unexpected ZIP entry size')
                with z.open(info) as stream:
                    for block in iter(lambda: stream.read(1048576), b''):
                        full.update(block)
                        part.update(block)
                        length += len(block)
                        if target is not None:
                            target.write(block)
            if length != SLICE or part.hexdigest() != item['part_sha256'].lower():
                raise ValueError('Slice content verification failed: {}'.format(index))
            total += length
            verified.append(index)
            print('PART {}/8 OK; bytes={}'.format(index, length), flush=True)
        if total != TOTAL or full.hexdigest() != EXPECTED:
            raise ValueError('Full image length/SHA mismatch')
        if target is not None:
            target.close(); target = None
            if output.exists():
                raise FileExistsError('Output appeared during reconstruction; preserved partial file')
            # A newly-created timestamp directory avoids collisions; no existing output is replaced.
            partial.rename(output)
            (output.parent / 'rebuild-result.json').write_text(json.dumps({
                'bytes': total, 'sha256': full.hexdigest(), 'verified_parts': verified,
                'scope': 'PC-only reconstructed image; no device writes or device reread'
            }, indent=2), encoding='utf-8')
            print('SAVED: ' + str(output))
        print('FULL_IMAGE_OK: {} / {} bytes'.format(full.hexdigest(), total))
        return 0
    except (OSError, ValueError, KeyError, zipfile.BadZipFile) as exc:
        print('STOP: {}'.format(exc), file=sys.stderr)
        if partial is not None and partial.exists():
            print('Incomplete file retained: ' + str(partial), file=sys.stderr)
        return 1
    finally:
        if target is not None:
            target.close()

if __name__ == '__main__':
    sys.exit(main())
