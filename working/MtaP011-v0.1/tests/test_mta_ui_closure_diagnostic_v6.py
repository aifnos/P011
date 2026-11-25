"""One affected HOST contract; no Qt/P011/RF/source-loader/old suite invocation.

Executes only extracted, actual v5/v6 close/projection function bodies against
owned HOST fixtures. This is not a device close or restoration receipt.
"""
import ast
import hashlib
import math
from pathlib import Path
import re
import types
import unittest


BASE = Path(__file__).resolve().parents[1]
PINS = (
    ('candidate/formal-send-filecenter-ui-v5/runtime/ui_session.py',34436,
     '817e3452d7da89974190a615f00f93580439071d01ec01a50a6646a46e42438d'),
    ('candidate/formal-send-filecenter-ui-v6/runtime/ui_session.py',45146,
     'b4c96512767b7839245e2247d3dc1e637fe9fe694cb79c3f29f228c89d916598'),
    ('candidate/formal-send-filecenter-ui-v6/runtime/ui_guardian.py',43993,
     'da3b4d6cf3c50a3e539afb239ed01fa2e443f77066366aa727b13146aabd0a7d'),
    ('candidate/formal-send-filecenter-deploy-v4/runtime/formal_send_session.py',24059,
     'c64d91da4b3bfc8a6cf74255dc5c367e86a8b99ed6d37b826e9ba0d3c9a80803'),
    ('candidate/formal-send-filecenter-ui-v5/runtime/ui_assets.py',12526,
     'ac6bffe961034558da8be607d74bc4edb62209b23ce80b8a930138a8fc7eb890'))


def extracted(raw, names, constants=()):
    tree = ast.parse(raw, feature_version=(3,5))
    chosen = []
    for row in tree.body:
        if isinstance(row,(ast.FunctionDef,ast.ClassDef)) and row.name in names:
            chosen.append(row)
        elif isinstance(row,ast.Assign) and any(
                isinstance(target,ast.Name) and target.id in constants for target in row.targets):
            chosen.append(row)
    namespace = dict(__name__='host_closure_contract_v6', re=re, math=math)
    exec(compile(ast.Module(body=chosen,type_ignores=[]),'<actual-ui-close-bodies>','exec'),namespace)
    return namespace


def fixture(options):
    calls = []
    defaults = dict(close=True, closed=True, filecenter=True, settled=True,
                    channel=True, bound=True, fc=True, constructed=True, ticket=True,
                    throw=None, prevent_error=False, cleanup_changed=False)
    defaults.update(options)
    def call(name):
        calls.append(name)
        if defaults['throw'] == name: raise RuntimeError('private payload not a control code')
        return defaults[name]
    class Owner(object):
        def __init__(self):
            self.cleanup_until = self._cleanup_until_original = 5.0
            if defaults['cleanup_changed']: self.cleanup_until = 6.0
        def _filecenter_closed(self): return call('filecenter')
    class Sender(object):
        def __init__(self):
            self.owner = Owner()
            self.owner_ticket = dict(constructed=True, partial=self.owner, creator=Owner)
        def close(self): return call('close')
        def _closed(self): return call('closed')
    class Channel(object):
        def __init__(self): self.bound = defaults['bound']
        def prevent_new(self):
            calls.append('prevent')
            if defaults['prevent_error']: raise RuntimeError('private prevent failure')
        def settled(self): return call('settled')
    class Scope(object):
        def __init__(self):
            self.sender = Sender()
            self.sender_ticket = dict(constructed=defaults['constructed'], original=self.sender,
                                      creator=Sender, close_return=None) if defaults['ticket'] else None
            self.filecenter_ticket = object() if defaults['fc'] else None
            self.channel = Channel() if defaults['channel'] else None
            self.cleanup_until = 10.0
            self.failures = []
            self.close_observation = None
        def mark_closing(self): calls.append('mark')
    return Scope(), calls


class ClosureObservationV6(unittest.TestCase):
    def test_original_short_circuit_retained_snapshot_and_privacy(self):
        raws = []
        for path,size,sha in PINS:
            raw = (BASE/path).read_bytes()
            self.assertEqual((len(raw),hashlib.sha256(raw).hexdigest()),(size,sha))
            raws.append(raw)
        old = extracted(raws[0], {'SenderUiError','_need','_close_sender'})
        names = {'SenderUiError','_need','_close_sender','_observed_bool','_error_records',
                 '_retained_error_observation','_row_observation','_close_snapshot',
                 '_exception_projection'}
        new = extracted(raws[1], names,
                        ('CLOSE_ERROR_CODES','DIAGNOSTIC_STAGES','DIAGNOSTIC_LIMIT'))
        real_snapshot = new['_close_snapshot']
        snapshots = []
        new['_close_snapshot'] = lambda scope, observation: snapshots.append(observation)
        cases = [dict(), dict(close=False), dict(close=None), dict(closed=False),
                 dict(closed=None), dict(filecenter=False), dict(filecenter=None),
                 dict(settled=False), dict(settled=None), dict(fc=False), dict(channel=False),
                 dict(bound=False), dict(throw='close'), dict(throw='closed'),
                 dict(throw='filecenter'), dict(throw='settled'), dict(prevent_error=True),
                 dict(cleanup_changed=True), dict(ticket=False), dict(constructed=False)]
        predicate_names = ('sender_close','sender_closed','filecenter_closed','channel_settled')
        method_names = ('close','closed','filecenter','settled')
        for options in cases:
            left, left_calls = fixture(options)
            right, right_calls = fixture(options)
            a = old['_close_sender'](left)
            b = new['_close_sender'](right)
            self.assertIs(a,b,options)
            self.assertEqual(left_calls,right_calls,options)
            self.assertEqual([type(error).__name__ for error in left.failures],
                             [type(error).__name__ for error in right.failures],options)
            observed = right.close_observation
            self.assertEqual(observed['kind'],'sender-ui-close-observation-v6')
            for predicate,method in zip(predicate_names,method_names):
                self.assertIs(observed[predicate]['called'],method in right_calls,options)
                if method not in right_calls or options.get('throw') == method:
                    self.assertIsNone(observed[predicate]['returned'],options)
            self.assertLessEqual(right_calls.count('close'),1)
            self.assertLessEqual(right_calls.count('closed'),1)
            self.assertLessEqual(right_calls.count('filecenter'),1)
            self.assertLessEqual(right_calls.count('settled'),1)
        # Restore and execute the actual passive snapshot function body. No
        # recomputation of _closed, filecenter/audio predicates or FD methods.
        new['_close_snapshot'] = real_snapshot
        scope, calls = fixture({})
        sender, owner = scope.sender, scope.sender.owner
        sender.close_called = True; sender.close_complete = False; sender.pending = True
        sender.owner_close_return = False
        sender.failure = sender.close_failure = None
        sender.failures = []; sender.rows = []; sender.loader_ticket = sender.loader = None
        for name in ('close_called','stop_called','state_close_called'):
            setattr(owner,name,True)
        for name in ('close_complete','state_close_return','directory_close_called',
                     'directory_close_complete','cleanup_deadline_expired'):
            setattr(owner,name,False)
        owner.cleanup_clock_failure = owner.failure = owner.loop_failure = None
        owner.assets = owner.requests = owner.threads = []
        secret = 'do-not-publish account@example.test 198.51.100.23 /private/name token'
        try: raise OSError(9,secret)
        except OSError as error: retained_error = error
        owner.failures = [retained_error]
        class Audio(object): pass
        class FileCenter(object): pass
        fc = FileCenter(); fc.audio = Audio(); fc.audio.cleanup_pending = False; fc.audio.tickets = []
        fc.failure = None; fc.cleanup_failures = []; fc.media = []
        fc.close_called = True; fc.close_complete = False
        fc.state_complete = fc.server_complete = fc.start_returned = True
        fc_ticket = dict(original=fc, cls=FileCenter, create_returned=True,
                         close_called=True, close_return=False, failure=None, close_failure=None)
        scope.filecenter = fc; scope.filecenter_ticket = fc_ticket
        owner.filecenter_ticket = owner._filecenter_ticket_original = fc_ticket
        scope.channel.closing = True; scope.channel.terminal = False
        scope.channel.failure = None; scope.channel.rows = []
        observed = dict(kind='sender-ui-close-observation-v6')
        real_snapshot(scope,observed)
        self.assertEqual(calls,[])
        self.assertIs(observed['snapshot_available'],True)
        self.assertIs(observed['owner']['close_complete'],False)
        self.assertEqual(observed['owner_failures']['failure_count'],1)
        self.assertEqual(observed['owner_failures']['original_failure_list_count'],1)
        self.assertEqual(observed['owner_failures']['errors'][0][0]['errno'],9)
        self.assertEqual(observed['owner_failures']['errors'][0][0]['kind'],'OSError')
        self.assertTrue(observed['owner_failures']['errors'][0][0]['frames'])
        raw = new['_exception_projection']([],['scope_created','sender_close'],observed)
        self.assertNotIn(secret.encode('ascii'),raw)
        self.assertNotIn(b'account@example.test',raw)
        self.assertNotIn(b'198.51.100.23',raw)
        self.assertNotIn(b'/private/name',raw)
        self.assertNotIn(str(BASE).encode('ascii'),raw)
        projected = ast.literal_eval(raw.decode('ascii'))
        self.assertEqual(projected['kind'],'sender-ui-diagnostic-v6')
        self.assertEqual(projected['failure_count'],0)
        self.assertIs(projected['close_observation']['owner']['close_complete'],False)
        known = new['SenderUiError']('deadline')
        unknown = new['SenderUiError'](secret)
        errors = new['_error_records']([known,unknown])
        self.assertEqual(errors['errors'][0][0]['code'],'deadline')
        self.assertIsNone(errors['errors'][1][0]['code'])
        # Large original inventories are counted but bounded before projection.
        sender.failures = [OSError(9,secret) for index in range(80)]
        observed = dict(kind='sender-ui-close-observation-v6')
        real_snapshot(scope,observed)
        self.assertEqual(observed['sender_failures']['original_failure_list_count'],80)
        self.assertIs(observed['sender_failures']['inventory_truncated'],True)
        self.assertLessEqual(len(observed['sender_failures']['errors']),4)
        self.assertLessEqual(len(new['_exception_projection']([],['sender_close'],observed)),32768)


if __name__ == '__main__':
    unittest.main()
