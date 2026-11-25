"""Offline acceptance cases: missing/ambiguous binding must not mean unbound."""
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'MtaP011-v0.1/runtime'))
import device_account as D


class Acceptance(unittest.TestCase):
    def info(self, payload, http=200):
        return D.classify(json.dumps(payload).encode(),http)[0]

    def test_explicit_unbound(self):
        row=self.info({'code':200,'data':{'binded':0}})
        self.assertTrue(D.info_valid(row)); self.assertIs(row['bound'],False)

    def test_explicit_bound(self):
        row=self.info({'code':200,'data':{'binded':1}})
        self.assertTrue(D.info_valid(row)); self.assertIs(row['bound'],True)

    def test_missing_binding_cannot_succeed(self):
        self.assertFalse(D.info_valid(self.info({'code':200,'data':{}})))

    def test_boolean_or_string_cannot_succeed(self):
        for value in (False,True,'0','1',None,-1,2):
            with self.subTest(value=value):
                self.assertFalse(D.info_valid(self.info({'code':200,'data':{'binded':value}})))

    def test_error_code_or_http_cannot_succeed(self):
        self.assertFalse(D.info_valid(self.info({'code':401,'data':{'binded':0}})))
        self.assertFalse(D.info_valid(self.info({'code':200,'data':{'binded':0}},500)))

    def test_invalid_json_cannot_succeed(self):
        row,_=D.classify(b'<html>gateway</html>',200)
        self.assertFalse(D.info_valid(row))

    def test_response_summary_omits_account_records(self):
        row=self.info({'code':200,'data':{'binded':1,'profiles':[{'name':'PRIVATE_NAME','token':'PRIVATE_TOKEN'}]}})
        self.assertEqual(row['profiles_count'],1)
        self.assertNotIn('PRIVATE_',repr(row))


if __name__=='__main__':
    unittest.main()
