"""One scoped account request using the verified v2.4.0 stock protocol.

Credentials stay in this process; all stock memory access is read-only.
Never modifies stock files, account configuration, process memory, or SN.
"""
import argparse
import hashlib
import http.client
import os
import re
import signal
import ssl
import stat
import struct
import time
from urllib.parse import quote
import p011_json as J

PINS = {
 '/usr/bin/Z03':'cb8d6a78617d50f64c6adc8056427dd963bc83979cbb04e349275dd8e8ffb62a',
 '/usr/bin/control_engine':'364b0bf820799070e89d9362000de4a3796a0e6a2d5f4d657464c6385b8dbd6d',
 '/usr/bin/zyb_z03_launch.sh':'7bce5379e3cc78e5bd8c04ceb603c88814f24c3a7efd28105ecc3c5849d6a42b'}
OBJECT = 0x40a538
VTABLE = 0x405af8
HOST = 'iot-api.zybang.com'
INFO = '/iot-server/api/pen/device/info'
UNBIND = '/iot-server/api/pen/device/unbind'


def sign(params, secret):
    plain = ''.join(item + '&' for item in sorted(k + '=' + str(v) for k,v in params.items()))
    return hashlib.md5((plain + 'secret=' + secret).encode('utf8')).hexdigest()


def encoded(params):
    return '&'.join(quote(str(k), safe='') + '=' + quote(str(v), safe='') for k,v in sorted(params.items()))


def classify(body, status):
    result = dict(http_status=status, body_bytes=len(body), body_sha256=hashlib.sha256(body).hexdigest())
    try:
        value = J.loads(body.decode('utf8'))
    except (ValueError, UnicodeError):
        result['json_valid'] = False
        return result, None
    result['json_valid'] = isinstance(value, dict)
    if not isinstance(value, dict):
        return result, value
    code = value.get('code')
    result['business_code'] = code if type(code) is int else None
    data = value.get('data')
    result['data_is_object'] = isinstance(data, dict)
    if isinstance(data, dict):
        bound = data.get('binded')
        result['binding_field_valid'] = type(bound) is int and bound in (0,1)
        if result['binding_field_valid']:
            result['bound'] = bound == 1
        for key in ('app_status',):
            if type(data.get(key)) is int:
                result[key] = data[key]
        for key in ('profiles','parentProfiles'):
            if isinstance(data.get(key), list):
                result[key + '_count'] = len(data[key])
    return result, value


def identity(pid):
    raw = open('/proc/%d/stat' % pid).read(4096)
    end = raw.rindex(')'); fields = raw[end+2:].split()
    return dict(pid=pid, starttime=fields[19], name=raw[raw.index('(')+1:end],
                parent=int(fields[1]), exe=os.readlink('/proc/%d/exe' % pid))


def write_private(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(data); handle.flush(); os.fsync(handle.fileno())


class Stock:
    def __init__(self, pid, starttime):
        self.pid = pid
        self.expected = identity(pid)
        if self.expected['name'] != 'Z03' or self.expected['exe'] != '/usr/bin/Z03' or self.expected['starttime'] != str(starttime):
            raise ValueError('Stock process identity mismatch')
        for path, value in PINS.items():
            if hashlib.sha256(open(path,'rb').read()).hexdigest() != value:
                raise ValueError('Stock file identity mismatch')
        if os.getuid() != 0 or 'z031_v2.4.0-20251128_174826-user' not in open('/etc/os-release').read(4096):
            raise ValueError('Unexpected device identity')
        self.fd = os.open('/proc/%d/mem' % pid, os.O_RDONLY)
        self.refresh_maps()
        if self.u32(OBJECT) != VTABLE or self.read(0x10000, 6) != b'\x7fELF\x01\x01':
            raise ValueError('Stock object layout mismatch')

    def refresh_maps(self):
        self.maps = []
        with open('/proc/%d/maps' % self.pid) as handle:
            for line in handle:
                parts = line.split()
                if parts[1].startswith('r'):
                    first, last = parts[0].split('-')
                    self.maps.append((int(first,16),int(last,16)))

    def read(self, address, size):
        if size < 0 or size > 16384 or not any(a <= address and address+size <= b for a,b in self.maps):
            raise ValueError('Stock memory read outside bounded mapping')
        data = os.pread(self.fd, size, address)
        if len(data) != size:
            raise ValueError('Short stock memory read')
        return data

    def u32(self, address):
        return struct.unpack('<I',self.read(address,4))[0]

    def i32(self, address):
        return struct.unpack('<i',self.read(address,4))[0]

    def string(self, offset, limit=4096):
        field = OBJECT + offset
        pointer = self.u32(field)
        header = self.read(pointer,16)
        ref, size, alloc, relative = struct.unpack('<iiIi',header)
        if size < 0 or size > limit:
            raise ValueError('Stock string length invalid')
        data = self.read(pointer+relative, size*2) if size else b''
        if self.u32(field) != pointer or self.read(pointer,16) != header:
            raise ValueError('Stock string changed during read')
        return data.decode('utf-16-le')

    def account(self):
        if identity(self.pid) != self.expected:
            raise ValueError('Stock process changed')
        self.refresh_maps()
        if self.u32(OBJECT) != VTABLE:
            raise ValueError('Stock object changed')
        values = dict(sn=self.string(8,64), secret=self.string(12,256), token=self.string(0x60,4096),
                      version=self.string(0x18,256), child_id=self.i32(OBJECT+0x104),
                      parent_id=self.i32(OBJECT+0x120), user_name=self.string(0x110,256),
                      parent_name=self.string(0x12c,256), bound=bool(self.read(OBJECT+0x5c,1)[0]),
                      production=bool(self.read(OBJECT+0x1c0,1)[0]), locale=self.i32(OBJECT+0x40))
        values['local'] = {1:'zh-TW',2:'en'}.get(values['locale'],'zh-CN')
        return values

    def close(self):
        os.close(self.fd)


def safe_account(account):
    return dict(login=account['child_id'] > 0, child_positive=account['child_id'] > 0,
                parent_positive=account['parent_id'] > 0, bound=account['bound'],
                has_user_name=bool(account['user_name']), has_parent_name=bool(account['parent_name']),
                has_token=bool(account['token']), has_sn=len(account['sn']) >= 18,
                has_secret=len(account['secret']) >= 32, production=account['production'],
                local=account['local'], version=account['version'])


def safe_message(value, account):
    text = ''
    if isinstance(value, dict):
        for name in ('msg','message'):
            if isinstance(value.get(name),str):
                text = value[name][:400]; break
    for name in ('sn','secret','token','user_name','parent_name'):
        if account.get(name):
            text = text.replace(account[name], '[redacted]')
    text = re.sub(r'[0-9]{7,}', '[redacted-number]', text)
    text = re.sub(r'[A-Za-z0-9+/=_-]{24,}', '[redacted-value]', text)
    return text[:240]


class Protocol:
    def __init__(self, folder):
        self.folder = folder
        self.post_count = 0
        self.requests = []

    def request(self, kind, account, label):
        if kind not in ('info','unbind') or not account['production']:
            raise ValueError('Only verified production endpoints are allowed')
        params = dict(local=account['local'], sn=account['sn'], token=account['token'],
                      stamp=str(int(time.time()*1000)))
        if kind == 'info':
            params['version'] = account['version']
        else:
            if self.post_count:
                raise ValueError('A second unlink request is prohibited')
            params['child_id'] = str(account['child_id'])
        params['sig'] = sign(params, account['secret'])
        body = encoded(params)
        context = ssl.create_default_context()
        connection = http.client.HTTPSConnection(HOST, timeout=15, context=context)
        result = dict(kind=kind, method='GET' if kind == 'info' else 'POST',
                      host=HOST, path=INFO if kind == 'info' else UNBIND,
                      tls_certificate_verified=True, retries=0)
        try:
            if kind == 'info':
                connection.request('GET', INFO+'?'+body, headers={'Accept':'application/json','Connection':'close'})
            else:
                marker = self.folder+'/UNBIND_ATTEMPTED'
                write_private(marker, b'one authorized request; do not automatically repeat\n')
                self.post_count += 1
                connection.request('POST', UNBIND, body.encode('ascii'),
                    {'Content-Type':'application/x-www-form-urlencoded','Accept':'application/json','Connection':'close'})
            reply = connection.getresponse()
            raw = reply.read(65537)
            if len(raw) > 65536:
                raise ValueError('Server response exceeded limit')
            write_private(self.folder+'/'+label+'.response.private',raw)
            summary, value = classify(raw,reply.status)
            result.update(summary)
            result['message'] = safe_message(value,account)
        except Exception as exc:
            result['transport_error_type'] = type(exc).__name__
        finally:
            connection.close()
        self.requests.append(result)
        return result


def info_valid(result):
    return (result.get('http_status') == 200 and result.get('json_valid') is True
            and result.get('business_code') == 200 and result.get('binding_field_valid') is True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('state','verify'))
    parser.add_argument('--pid',type=int,required=True)
    parser.add_argument('--starttime',required=True)
    parser.add_argument('--execute-logout',action='store_true')
    args = parser.parse_args()
    folder = os.path.dirname(os.path.realpath(__file__))
    if not folder.startswith('/mnt/data/p011-toolbox/account-check/') or os.path.islink(__file__):
        raise ValueError('Unexpected helper location')
    signal.signal(signal.SIGALRM, lambda a,b: (_ for _ in ()).throw(RuntimeError('Absolute deadline')))
    signal.alarm(125)
    protocol = Protocol(folder)
    stock = None
    result = dict(action=args.action, logout_authorized=args.execute_logout,
                  stock_memory_writes=False, factory_writes=False, account_config_writes=False)
    try:
        stock = Stock(args.pid,args.starttime)
        account = stock.account()
        result['before'] = safe_account(account)
        if args.action == 'state':
            result['status'] = 'STATE_ONLY'
        else:
            if not (account['production'] and len(account['sn'])>=18 and len(account['secret'])>=32 and account['token']):
                raise ValueError('Account authentication prerequisites missing')
            before = protocol.request('info',account,'01-before')
            result['cloud_before'] = before
            if not info_valid(before):
                result['status'] = 'READ_INTERFACE_NOT_VERIFIED_NO_UNBIND'
            elif not before['bound']:
                result['status'] = 'ALREADY_UNBOUND_NO_UNBIND'
            elif not args.execute_logout:
                result['status'] = 'PREFLIGHT_OK_NO_UNBIND'
            elif account['child_id'] <= 0:
                result['status'] = 'NO_CURRENT_ACCOUNT_NO_UNBIND'
            else:
                if stock.account() != account:
                    raise ValueError('Account changed before request')
                answer = protocol.request('unbind',account,'02-unbind')
                result['unbind'] = answer
                reply_ok = answer.get('http_status') == 200 and answer.get('business_code') == 200
                for i in range(3):
                    time.sleep(2 if i == 0 else 5)
                    after = protocol.request('info',account,'%02d-after' % (i+3))
                    result.setdefault('cloud_after',[]).append(after)
                    if info_valid(after) and after['bound'] is False:
                        result['status'] = ('CLOUD_UNBIND_CONFIRMED' if reply_ok else
                                            'CLOUD_UNBOUND_REPLY_NOT_CONFIRMED')
                        break
                else:
                    result['status'] = ('UNBIND_REPLY_OK_CLOUD_STATE_UNCONFIRMED' if reply_ok
                                        else 'UNBIND_NOT_CONFIRMED')
            result['after'] = safe_account(stock.account())
    except Exception as exc:
        result['error_type'] = type(exc).__name__
        result['status'] = 'STOPPED_NO_AUTOMATIC_RETRY'
    finally:
        if stock is not None:
            stock.close()
        result['post_count'] = protocol.post_count
        result['requests'] = protocol.requests
        write_private(folder+'/result-'+args.action+'.json',J.dumps(result,ensure_ascii=False,indent=2).encode('utf8'))
        print('RESULT='+repr(result),flush=True)
        signal.alarm(0)


if __name__ == '__main__':
    main()
