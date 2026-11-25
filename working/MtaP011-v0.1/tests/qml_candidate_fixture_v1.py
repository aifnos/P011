"""Private HOST-only actual-QML fixture for the two narrow source candidates.

No old TestCase, native/runtime module, server, device, phone, XHR or RF is run.
Only the request() entry seam is an in-memory delayed callback fixture. All
candidate QML functions, properties, bindings and button signal handlers are
real. This does not test the original XHR epoch/timeout transport or rendering.
The QML engine has no visible window and no screenshot/physical-output claim.
"""
import hashlib
import json
import os
from pathlib import Path
import tempfile


ROOT = Path(__file__).resolve().parents[1]


def read_verified(test, pin):
    test.assertEqual(3, len(pin))
    name, size, digest = pin
    test.assertIs(type(name), str)
    test.assertIs(type(size), int)
    test.assertIs(type(digest), str)
    raw = (ROOT / name).read_bytes()
    test.assertEqual(size, len(raw), name)
    test.assertEqual(digest, hashlib.sha256(raw).hexdigest(), name)
    return raw


def verify_delta(test, pin, schema, source, candidate):
    spec = json.loads(read_verified(test, pin))
    test.assertEqual({'schema', 'evidence', 'source', 'candidate', 'bindings',
                      'replacements', 'runtime_source_only', 'deployed',
                      'actions_changed', 'native_changed'}, set(spec))
    test.assertEqual(schema, spec['schema'])
    test.assertEqual('SOURCE_ONLY_NOT_EXECUTED', spec['evidence'])
    test.assertEqual(list(source), spec['source'])
    test.assertEqual(list(candidate), spec['candidate'])
    test.assertIs(spec['runtime_source_only'], True)
    for field in ('deployed', 'actions_changed', 'native_changed'):
        test.assertIs(spec[field], False)
    before = read_verified(test, source)
    after = read_verified(test, candidate)
    test.assertGreater(len(spec['bindings']), 0)
    binding_raw = [read_verified(test, row) for row in spec['bindings']]
    test.assertEqual(before, binding_raw[0], 'actual frozen UI binding')
    forward = before
    for row in spec['replacements']:
        test.assertEqual({'name', 'before', 'after', 'count'}, set(row))
        test.assertIs(type(row['count']), int)
        test.assertEqual(1, row['count'])
        old, new = row['before'].encode('utf-8'), row['after'].encode('utf-8')
        test.assertTrue(old and new)
        test.assertEqual(row['count'], forward.count(old), row['name'])
        forward = forward.replace(old, new, row['count'])
    test.assertEqual(after, forward, 'actual full-source forward delta')
    reverse = after
    for row in reversed(spec['replacements']):
        old, new = row['before'].encode('utf-8'), row['after'].encode('utf-8')
        test.assertEqual(row['count'], reverse.count(new), row['name'])
        reverse = reverse.replace(new, old, row['count'])
    test.assertEqual(before, reverse, 'actual full-source inverse delta')
    return spec, binding_raw


COMMON_DEPS = (
    ('MtaButton.qml', 758, '7e1d4e378b8e3293e617f4dc432cce3c70ae7fe377f2ea26950aa9bb11393bff'),
    ('MtaLabel.qml', 352, '77caf248c2f83ed50f5221082084e5af360d08fc917df98eb84449e24903bd75'),
    ('MtaTheme.js', 262, '5848aa8bf1dab57cfe590dd80da1122eb819c75c1f208f69ad4184bf669a99ff'),
)
SEND_ROOT = 'candidate/formal-send-filecenter-ui-v5/device/mta/'
RECEIVE_ROOT = ('out/mta-ui-receive-filecenter-navigation-gui-v1-'
                'a87de5c1d0e0b90b35bb2a91/mta/')


def dependencies(receive=False):
    base = RECEIVE_ROOT if receive else SEND_ROOT
    rows = [(name, (base + name, size, digest)) for name, size, digest in COMMON_DEPS]
    if not receive:
        rows.extend((
            ('MtaPage.qml', (SEND_ROOT + 'MtaPage.qml', 26769,
                            '1084ea1a5a906bbf0f56ea20df031ea9b4a1fd0931879e80cd6dfb475f7eabc2')),
            ('MtaKeyboard.qml', (SEND_ROOT + 'MtaKeyboard.qml', 5345,
                                '2de31e8cde68ab6ff76f4da85c386d5cddb466cccefb809987dddfce2f8c40cc')),
        ))
    return rows


class QtFixture:
    def __init__(self, test, sources, harness):
        self.test, self.root, self.engine, self.component = test, None, None, None
        self.warnings = []
        self.directory = tempfile.TemporaryDirectory(prefix='p011-qml-candidate-host-')
        self.application = None
        try:
            # This is a future HOST test, not a target UI or native composition.
            os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
            os.environ.setdefault('QT_QUICK_BACKEND', 'software')
            from PyQt5.QtCore import QUrl
            from PyQt5.QtGui import QGuiApplication
            from PyQt5.QtQml import QQmlComponent, QQmlEngine
            self.application = QGuiApplication.instance() or QGuiApplication([])
            folder = Path(self.directory.name)
            for name, pin in sources:
                raw = read_verified(test, pin)
                target = folder / name
                target.write_bytes(raw)
                test.assertEqual(raw, target.read_bytes())
            harness_path = folder / 'Harness.qml'
            harness_path.write_bytes(harness.encode('utf-8'))
            self.engine = QQmlEngine()
            self.engine.rootContext().setContextProperty('nativeFontFamily', 'sans-serif')
            self.engine.warnings.connect(
                lambda values: self.warnings.extend(value.toString() for value in values))
            self.component = QQmlComponent(self.engine, QUrl.fromLocalFile(str(harness_path)))
            test.assertEqual(QQmlComponent.Ready, self.component.status(),
                             [value.toString() for value in self.component.errors()])
            self.root = self.component.create()
            test.assertIsNotNone(self.root, [value.toString() for value in self.component.errors()])
            self.engine.globalObject().setProperty('_qmlCandidateRoot', self.engine.newQObject(self.root))
            self.settle()
        except BaseException:
            self.close()
            raise

    def settle(self):
        if self.application is not None:
            self.application.processEvents()
        self.test.assertEqual([], self.warnings, 'actual QML warnings')

    def call(self, name, *args):
        arguments = ','.join(json.dumps(value, ensure_ascii=True, allow_nan=False) for value in args)
        value = self.engine.evaluate('_qmlCandidateRoot.' + name + '(' + arguments + ')')
        self.test.assertFalse(value.isError(), value.toString())
        self.settle()
        return value.toVariant()

    def snapshot(self):
        value = self.engine.evaluate('JSON.stringify(_qmlCandidateRoot.snapshot())')
        self.test.assertFalse(value.isError(), value.toString())
        self.settle()
        return json.loads(value.toString())

    def close(self):
        try:
            for value in (self.root, self.component, self.engine):
                if value is not None:
                    value.deleteLater()
            if self.application is not None:
                from PyQt5.QtCore import QCoreApplication, QEvent
                QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
                self.application.processEvents()
        finally:
            self.root = self.component = self.engine = None
            self.directory.cleanup()
