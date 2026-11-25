import io
import pathlib
import socket
import sys
import time
import unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'runtime'))
from mta_transport import Stream, WebSocket, TransportError, Cancelled, download_body, read_headers, private_ipv4
from mta_protocol import WsMessage


class FakeSocket:
    def __init__(self,data=b''):self.data=data;self.sent=b''
    def settimeout(self,value):pass
    def recv(self,size):part,self.data=self.data[:size],self.data[size:];return part
    def send(self,data):self.sent+=data;return len(data)


class TransportTests(unittest.TestCase):
    def test_frame_roundtrip(self):
        sender=FakeSocket();ws=WebSocket(Stream(sender),True)
        ws.send(WsMessage('action',1,'versionNegotiation',{'version':1}))
        result=WebSocket(Stream(FakeSocket(sender.sent)),False).receive()
        self.assertEqual(result.name,'versionNegotiation')
        self.assertEqual(result.payload,{'version':1})

    def test_wrong_mask(self):
        with self.assertRaises(TransportError):WebSocket(Stream(FakeSocket(b'\x81\x02{}')),False).receive()

    def test_fragment_ping(self):
        data=b'\x01\x04acti'+b'\x89\x01!'+b'\x80\x1bon:2:versionNegotiation'
        # Test exact split payload rather than rely on a hand-counted length.
        tail=b'on:2:versionNegotiation'
        data=b'\x01\x04acti'+b'\x89\x01!'+bytes([0x80,len(tail)])+tail
        sock=FakeSocket(data)
        self.assertEqual(WebSocket(Stream(sock),True).receive().id,2)
        self.assertTrue(sock.sent)

    def test_body_bounds(self):
        output=io.BytesIO()
        self.assertEqual(download_body(Stream(FakeSocket(b'3\r\nabc\r\n0\r\n\r\n')),{'transfer-encoding':'chunked'},output),3)
        self.assertEqual(output.getvalue(),b'abc')
        for headers in [{'content-length':'4','transfer-encoding':'chunked'},{'content-length':'9999'},{'content-length':'-1'},{}]:
            with self.assertRaises(TransportError):download_body(Stream(FakeSocket()),headers,io.BytesIO(),10)

    def test_header_duplicate(self):
        with self.assertRaises(TransportError):read_headers(Stream(FakeSocket(b'HTTP/1.1 200 OK\r\nContent-Length: 1\r\ncontent-length: 2\r\n\r\n')))

    def test_cancel_deadline(self):
        with self.assertRaises(Cancelled):Stream(FakeSocket(),lambda:True).read(1)
        with self.assertRaises(TransportError):Stream(FakeSocket(),deadline=time.monotonic()-1).read(1)

    def test_private_endpoint(self):
        self.assertEqual(private_ipv4('192.168.49.1'),'192.168.49.1')
        for host in ['127.0.0.1','8.8.8.8','localhost','192.168.1.01','192.168.1.255','10.999.1.1']:
            with self.assertRaises(TransportError):private_ipv4(host)

if __name__=='__main__':unittest.main()
