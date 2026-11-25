import pathlib
import sys
import unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'runtime'))
import p011_json as json

class JsonTests(unittest.TestCase):
    def test_roundtrip(self):
        value={'name':'学习笔😀','array':[True,False,None,12,-34,2.5],'escaped':'a\n"\\'}
        self.assertEqual(value,json.loads(json.dumps(value)))

    def test_strict(self):
        for text in ['{"x":1,"x":2}','[1,]','{"a":1,}','01','NaN','1e999','"\\ud800"','[0] garbage','"\x00"']:
            with self.assertRaises(ValueError,msg=repr(text)):json.loads(text)

    def test_bounds(self):
        for text in ['['*30+'0'+']'*30,' '*131073,'['+','.join(['0']*8200)+']']:
            with self.assertRaises(ValueError):json.loads(text)

if __name__=='__main__':unittest.main()
