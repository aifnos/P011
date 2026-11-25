"""One affected HOST method: actual fixed sender picker, delayed HTTP seam.

No test is run by importing this module. The old/current and versioned new
MtaHost plus actual pinned dependencies run under HOST Qt, not a copied picker
algorithm. Only request() is overridden; original XHR epochs are not tested.
Back/Done use the actual button signal handlers, not physical touch. Direct
received-mode fixture covers a guard, not an enabled sender receive route.
"""
import hashlib
import importlib.util
from pathlib import Path
import unittest


_HELPER_PATH = Path(__file__).resolve().parent / 'qml_candidate_fixture_v1.py'
_HELPER_RAW = _HELPER_PATH.read_bytes()
if (len(_HELPER_RAW) != 7249 or hashlib.sha256(_HELPER_RAW).hexdigest() !=
        '346c11f2a432101d0bc0cc40c8bcccb5b50c2f39eba4a396a291f5f5949fecd3'):
    raise RuntimeError('picker_fixture_helper_pin')
_HELPER_SPEC = importlib.util.spec_from_file_location('p011_picker_qml_fixture_v1', _HELPER_PATH)
_HELPER = importlib.util.module_from_spec(_HELPER_SPEC)
# Execute only the exact checked bytes, without a second loader read or sys.path.
exec(compile(_HELPER_RAW, str(_HELPER_PATH), 'exec'), _HELPER.__dict__)
QtFixture, dependencies, verify_delta = _HELPER.QtFixture, _HELPER.dependencies, _HELPER.verify_delta


SOURCE = ('candidate/formal-send-filecenter-ui-v5/device/mta/MtaHost.qml', 6342,
          'c151b0bd7a9b686f5110eef968c50506d9a814c14b5d9db9ccebfe8f05d7b322')
CANDIDATE = ('candidate/formal-send-picker-generation-v1/device/mta/MtaHost.qml', 6602,
             'dcb6178f6d3179b7bab61e6818ae21a02443c902446f6b203c82bd16b8b479c3')
DELTA = ('candidate/formal-send-picker-generation-v1/exactsource-delta.json', 1840,
         'cf3e8d6146b95cb6c27e941230d8eaa80fe0fd96a4cb8baf32f724f1bafa2b7e')

HARNESS = '''import QtQuick 2.10
Item {
    id:fixture;objectName:"pickerHostFixture";width:800;height:268
    property var requests:[]
    function record(path,bootstrap,done){
        if(path!=="/v1/files"||bootstrap!==false)throw new Error("HOST unexpected picker IO");
        requests.push({path:path,done:done,replied:false});
    }
    function reply(index,ok,rows){
        if(index<0||index>=requests.length||requests[index].replied)throw new Error("HOST response order");
        requests[index].replied=true;requests[index].done(ok,{files:rows});
    }
    function fetch(mode){subject.fetchFiles(mode);}
    function setPicked(rows){subject.picked=rows;}
    function setMode(mode){subject.fileMode=mode;}
    function setStage(stage){subject.stage=stage;}
    function reset(){subject.resetHost();}
    function find(item,name){
        if(item.objectName===name)return item;
        for(var i=0;i<item.children.length;i++){var value=find(item.children[i],name);if(value)return value;}
        return null;
    }
    function clickButton(item,prefix){
        if(typeof item.clicked==="function"&&typeof item.text==="string"&&item.text.indexOf(prefix)===0){
            if(!item.enabled)throw new Error("HOST disabled button");item.clicked();return true;
        }
        for(var i=0;i<item.children.length;i++)if(clickButton(item.children[i],prefix))return true;
        return false;
    }
    function back(){if(!clickButton(subject,"‹ 互传"))throw new Error("HOST missing back handler");}
    function done(){if(!clickButton(subject,"完成 · "))throw new Error("HOST missing Done handler");}
    function snapshot(){
        var page=find(subject,"mtaPage");
        return {stage:subject.stage,mode:subject.fileMode,rows:subject.fileRows,picked:subject.picked,
            selected:page.selectedFiles,message:subject.message,requests:requests.length,
            generation:typeof subject.listingGeneration==="number"?subject.listingGeneration:null,
            width:subject.width,height:subject.height,endpoint:subject.endpoint,token:subject.accessToken};
    }
    MtaHost {
        id:subject;anchors.fill:parent;hostPreview:true
        function request(path,bootstrap,done){fixture.record(path,bootstrap,done);}
    }
}
'''

FRESH = [dict(id='HOST-FRESH', name='Text/HOST-fresh.txt', size=4)]
OLD = [dict(id='HOST-OLD', name='Text/HOST-old.txt', size=3)]


class PickerGenerationTests(unittest.TestCase):
    def test_actual_picker_generation_stage_mode_and_leave(self):
        spec, _ = verify_delta(self, DELTA,
                              'p011-formal-send-picker-generation-source-delta-v1',
                              SOURCE, CANDIDATE)
        self.assertEqual(4, len(spec['replacements']))
        outcomes = {}
        for label, pin in (('original', SOURCE), ('candidate', CANDIDATE)):
            fixture = QtFixture(self, [('MtaHost.qml', pin)] + dependencies(), HARNESS)
            try:
                start = fixture.snapshot()
                self.assertEqual((800, 268, '', '', 0),
                                 (start['width'], start['height'], start['endpoint'],
                                  start['token'], start['requests']))
                # The original lifecycle epoch is unchanged by picker Back.
                # A belongs to the old listing, B to the current real listing.
                fixture.call('setPicked', FRESH)
                fixture.call('fetch', 'select')  # A=0
                fixture.call('back')
                fixture.call('fetch', 'select')  # B=1
                fixture.call('reply', 1, True, FRESH)
                current = fixture.snapshot()
                self.assertEqual(FRESH, current['rows'])
                self.assertEqual(FRESH, current['picked'])
                fixture.call('reply', 0, True, OLD)
                late = fixture.snapshot()
                outcomes[label] = late
                if label == 'original':
                    self.assertEqual(OLD, late['rows'])
                    self.assertEqual([], late['picked'])
                    continue
                self.assertEqual(current, late, 'old success cannot write rows/message/picked')

                fixture.call('fetch', 'select')  # C=2
                fixture.call('back')
                fixture.call('fetch', 'select')  # D=3
                fixture.call('reply', 3, True, FRESH)
                current = fixture.snapshot()
                fixture.call('reply', 2, False, [])
                self.assertEqual(current, fixture.snapshot(), 'old failure cannot erase current rows')

                fixture.call('fetch', 'select')  # E=4
                before = fixture.snapshot()
                fixture.call('setMode', 'received')
                mode_changed = fixture.snapshot()
                self.assertEqual(before['generation'], mode_changed['generation'])
                fixture.call('reply', 4, True, OLD)
                self.assertEqual(mode_changed, fixture.snapshot(), 'mode mismatch without a generation change')

                fixture.call('fetch', 'select')  # F=5
                fixture.call('setStage', 'keyboard')
                before = fixture.snapshot()
                fixture.call('reply', 5, False, [])
                self.assertEqual(before, fixture.snapshot(), 'non-picker stage rejects callback')

                fixture.call('fetch', 'select')  # G=6
                fixture.call('reset')
                before = fixture.snapshot()
                fixture.call('reply', 6, True, OLD)
                self.assertEqual(before, fixture.snapshot(), 'reset invalidates picker generation at the seam')

                fixture.call('fetch', 'select')  # H=7
                fixture.call('setPicked', FRESH)
                fixture.call('done')
                committed = fixture.snapshot()
                self.assertEqual('mta', committed['stage'])
                self.assertEqual(FRESH, committed['selected'])
                fixture.call('reply', 7, True, OLD)
                self.assertEqual(committed, fixture.snapshot(), 'Done cannot be followed by a stale picker write')

                fixture.call('fetch', 'received')  # direct guard fixture, not a sender direction switch
                received = [dict(id='HOST-RECEIVED', name='Received/HOST.txt', size=5)]
                fixture.call('reply', 8, True, FRESH + received)
                self.assertEqual(received, fixture.snapshot()['rows'])
                fixture.call('fetch', 'select')
                fixture.call('reply', 9, False, [])
                self.assertEqual([], fixture.snapshot()['rows'])
                self.assertEqual('文件目录暂不可用', fixture.snapshot()['message'])
                self.assertEqual(10, fixture.snapshot()['requests'])
            finally:
                fixture.close()
        self.assertNotEqual(outcomes['original']['rows'], outcomes['candidate']['rows'])
        # No automatic source checker, device command, native import or old suite is invoked.
        self.host_only_case_count = 9
        print('PICKER_GENERATION_FIXTURE_CONTRACT=1')


if __name__ == '__main__':
    unittest.main()
