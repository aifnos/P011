"""Pure, bounded WPA 2.12 CLIENT control bytes; never opens a control socket.

Private objects deliberately redact repr/str. Explicit private accessors still
return secrets and must not be logged. Immutable Python bytes cannot promise
secure erasure. No result proves kernel ownership, association or an endpoint.
"""
import binascii
import hashlib
import hmac

MAX_STATUS = 4096
MAX_EVENT = 1024
MAX_NETWORK_ID = 2147483647
ERROR_CODES = (
    'invalid_bytes', 'invalid_length', 'invalid_credentials', 'unsupported_kdf',
    'invalid_network_id', 'invalid_reply', 'invalid_owned_name', 'invalid_frame',
    'duplicate_field', 'unsupported_status_field', 'unsupported_event_field',
    'invalid_field', 'invalid_ssid_encoding', 'ssid_mismatch', 'key_mismatch',
    'security_mismatch', 'role_mismatch', 'interface_mismatch', 'missing_field',
    'invalid_ip_profile', 'invalid_codec_code',
)
STATES = (
    b'DISCONNECTED', b'INTERFACE_DISABLED', b'INACTIVE', b'SCANNING',
    b'AUTHENTICATING', b'ASSOCIATING', b'ASSOCIATED', b'4WAY_HANDSHAKE',
    b'GROUP_HANDSHAKE', b'COMPLETED',
)
_HEX = b'0123456789abcdef'
_SSID_ESCAPES = {34: b'\\"', 92: b'\\\\', 27: b'\\e', 10: b'\\n',
                 13: b'\\r', 9: b'\\t'}
_ESCAPED_OCTETS = {34: 34, 92: 92, 101: 27, 110: 10, 114: 13, 116: 9}


class CtrlCodecError(ValueError):
    """Only a fixed code, never the rejected input or a native error string."""
    def __init__(self, code):
        if type(code) is not str or code not in ERROR_CODES:
            code = 'invalid_codec_code'
        self.code = code
        ValueError.__init__(self, code)


def _fail(code):
    raise CtrlCodecError(code)


class _PrivateImmutable(object):
    __slots__ = ()

    def __setattr__(self, name, value):
        raise AttributeError('private immutable object')

    def __repr__(self):
        return '<P2pClientPrivate redacted>'

    __str__ = __repr__


class ClientCredentials(_PrivateImmutable):
    __slots__ = ('_ssid', '_psk')

    def __init__(self, ssid, passphrase=None, raw_psk=None):
        _bytes(ssid, 1, 32, 'invalid_credentials')
        if (passphrase is None) == (raw_psk is None):
            _fail('invalid_credentials')
        if raw_psk is not None:
            _bytes(raw_psk, 32, 32, 'invalid_credentials')
            key = raw_psk
        else:
            _bytes(passphrase, 8, 63, 'invalid_credentials')
            if any(o < 32 or o > 126 for o in passphrase):
                _fail('invalid_credentials')
            key = _derive(passphrase, ssid)
        object.__setattr__(self, '_ssid', ssid)
        object.__setattr__(self, '_psk', key)

    def public_summary(self):
        return {'credential_profile': 'wpa2_psk_ccmp', 'credentials_valid': True}


class _WireCommand(_PrivateImmutable):
    __slots__ = ('_kind', '_wire')

    def __init__(self, kind, wire):
        object.__setattr__(self, '_kind', kind)
        object.__setattr__(self, '_wire', wire)

    def private_bytes(self):
        """Trusted private transport only; no argv, stdout, debug or journal."""
        return self._wire

    def public_summary(self):
        return {'command_kind': self._kind}


class _ControlReport(_PrivateImmutable):
    __slots__ = ('_fields', '_summary')

    def __init__(self, fields, summary):
        object.__setattr__(self, '_fields', tuple(sorted(fields.items())))
        object.__setattr__(self, '_summary', tuple(sorted(summary.items())))

    def private_fields(self):
        """A fresh private copy, not a public status or ownership receipt."""
        return dict(self._fields)

    def public_summary(self):
        return dict(self._summary)


def _bytes(value, minimum, maximum, code='invalid_bytes'):
    if type(value) is not bytes:
        _fail(code)
    if not minimum <= len(value) <= maximum:
        _fail('invalid_length' if code == 'invalid_bytes' else code)
    return value


def _credentials(value):
    if type(value) is not ClientCredentials:
        _fail('invalid_credentials')
    return value


def _derive(passphrase, ssid):
    function = getattr(hashlib, 'pbkdf2_hmac', None)
    if function is None:
        _fail('unsupported_kdf')
    try:
        result = function('sha1', passphrase, ssid, 4096, 32)
    except (ValueError, TypeError, OverflowError, NotImplementedError):
        raise CtrlCodecError('unsupported_kdf') from None
    if type(result) is not bytes or len(result) != 32:
        _fail('unsupported_kdf')
    return result


def _decimal(value, minimum, maximum):
    if (not value or len(value) > 10 or any(o < 48 or o > 57 for o in value)
            or (len(value) > 1 and value[0] == 48)):
        _fail('invalid_field')
    number = int(value)
    if not minimum <= number <= maximum:
        _fail('invalid_field')
    return number


def _network_id(value):
    if type(value) is not int or not 0 <= value <= MAX_NETWORK_ID:
        _fail('invalid_network_id')
    return str(value).encode('ascii')


def _owned_name(value):
    _bytes(value, 11, 11, 'invalid_owned_name')
    if not value.startswith(b'mta') or any(o not in _HEX for o in value[3:]):
        _fail('invalid_owned_name')
    return value


def client_config():
    """Only the two source-backed global items; no path or network profile."""
    return _WireCommand('client_config', b'ap_scan=1\np2p_no_group_iface=1\n')


def add_network_command():
    return _WireCommand('add_network', b'ADD_NETWORK')


def status_command():
    return _WireCommand('status', b'STATUS')


def parse_add_network_reply(reply):
    _bytes(reply, 2, 11)
    if not reply.endswith(b'\n'):
        _fail('invalid_reply')
    value = reply[:-1]
    try:
        return _decimal(value, 0, MAX_NETWORK_ID)
    except CtrlCodecError:
        raise CtrlCodecError('invalid_network_id') from None


def parse_ok_reply(reply):
    _bytes(reply, 3, 5)
    if reply == b'OK\n':
        return True
    if reply == b'FAIL\n':
        return False
    _fail('invalid_reply')


def network_commands(network_id, credentials):
    """Fixed fields only. The caller must obtain id from its real ADD reply."""
    number = _network_id(network_id)
    credentials = _credentials(credentials)
    fields = (
        ('ssid', binascii.hexlify(credentials._ssid)),
        ('psk', binascii.hexlify(credentials._psk)),
        ('proto', b'RSN'), ('key_mgmt', b'WPA-PSK'),
        ('pairwise', b'CCMP'), ('group', b'CCMP'),
        ('mode', b'0'), ('disabled', b'2'),
    )
    return tuple(_WireCommand('set_' + key,
                             b'SET_NETWORK ' + number + b' ' +
                             key.encode('ascii') + b' ' + value)
                 for key, value in fields)


def group_add_command(network_id):
    return _WireCommand('group_add_persistent',
                        b'P2P_GROUP_ADD persistent=' + _network_id(network_id))


def _ssid_text(ssid):
    # Exact printf_encode output, used by BOTH source STATUS and group events.
    result = []
    for octet in ssid:
        if octet in _SSID_ESCAPES:
            result.append(_SSID_ESCAPES[octet])
        elif 32 <= octet <= 126:
            result.append(bytes((octet,)))
        else:
            result.append(b'\\x' + binascii.hexlify(bytes((octet,))))
    return b''.join(result)


def _ssid_decode(text):
    if not 1 <= len(text) <= 128:
        _fail('invalid_ssid_encoding')
    result, pos = [], 0
    while pos < len(text):
        octet = text[pos]
        if octet == 92:
            if pos + 1 >= len(text):
                _fail('invalid_ssid_encoding')
            escape = text[pos + 1]
            if escape in _ESCAPED_OCTETS:
                result.append(_ESCAPED_OCTETS[escape])
                pos += 2
            elif escape == 120 and pos + 3 < len(text):
                pair = text[pos + 2:pos + 4]
                if any(o not in _HEX for o in pair):
                    _fail('invalid_ssid_encoding')
                result.append(int(pair, 16))
                pos += 4
            else:
                _fail('invalid_ssid_encoding')
        elif 32 <= octet <= 126 and octet != 34:
            result.append(octet)
            pos += 1
        else:
            _fail('invalid_ssid_encoding')
        if len(result) > 32:
            _fail('invalid_ssid_encoding')
    value = bytes(result)
    if _ssid_text(value) != text:
        _fail('invalid_ssid_encoding')
    return value


def _mac(text, allow_zero=False):
    if len(text) != 17 or any(text[pos] != 58 for pos in (2, 5, 8, 11, 14)):
        _fail('invalid_field')
    pairs = text.split(b':')
    if any(len(pair) != 2 or any(o not in _HEX for o in pair) for pair in pairs):
        _fail('invalid_field')
    value = bytes(int(pair, 16) for pair in pairs)
    if value[0] & 1 or (not allow_zero and not any(value)):
        _fail('invalid_field')
    return value


def _ipv4(text, mask=False):
    parts = text.split(b'.')
    if len(parts) != 4:
        _fail('invalid_ip_profile')
    try:
        numbers = tuple(_decimal(part, 0, 255) for part in parts)
    except CtrlCodecError:
        raise CtrlCodecError('invalid_ip_profile') from None
    number = sum(o << (24 - pos * 8) for pos, o in enumerate(numbers))
    if mask:
        inverse = number ^ 0xffffffff
        if (not number or not inverse or inverse & (inverse + 1)
                or inverse < 3):
            _fail('invalid_ip_profile')
    elif not number or numbers[0] in (0, 127) or numbers[0] >= 224:
        _fail('invalid_ip_profile')
    return number


def _summary(kind, state=b'not_reported'):
    return {'report_kind': kind, 'evidence': 'control_fields_only',
            'ctrl_state': state.decode('ascii'), 'ctrl_completed': False,
            'ctrl_client_role': False, 'ctrl_ssid_matches': False,
            'ctrl_wpa2_ccmp': False, 'ctrl_key_reported': False,
            'ctrl_key_matches': False, 'optional_ip_reported': False}


_STATUS_FIELDS = frozenset((
    b'bssid', b'freq', b'ssid', b'id', b'mode', b'wifi_generation',
    b'max_nss_rx', b'max_nss_tx', b'channel_width', b'pairwise_cipher',
    b'group_cipher', b'key_mgmt', b'pmf', b'mgmt_group_cipher', b'wpa_state',
    b'ip_address', b'p2p_device_address', b'address', b'uuid', b'ieee80211ac',
    b'bss_max_idle_period', b'ssid_verified', b'bigtk_set',
))


def parse_status(reply, credentials):
    """STATUS reports no ifname/type8. Provider must bind origin separately."""
    credentials = _credentials(credentials)
    _bytes(reply, 1, MAX_STATUS)
    if b'\x00' in reply or b'\r' in reply or not reply.endswith(b'\n'):
        _fail('invalid_frame')
    lines = reply[:-1].split(b'\n')
    if len(lines) > 32:
        _fail('invalid_length')
    fields = {}
    for line in lines:
        if not line or len(line) > 256 or b'=' not in line:
            _fail('invalid_frame')
        key, value = line.split(b'=', 1)
        if key in fields:
            _fail('duplicate_field')
        if key not in _STATUS_FIELDS:
            _fail('unsupported_status_field')
        if not value or any(o < 32 or o > 126 for o in value):
            _fail('invalid_field')
        fields[key] = value
    state = fields.get(b'wpa_state')
    if state not in STATES:
        _fail('missing_field' if state is None else 'invalid_field')
    private, summary = {}, _summary('status', state)
    for key, value in fields.items():
        if key == b'ssid':
            # STATUS has no surrounding quotes; embedded quotes are escaped.
            ssid = _ssid_decode(value)
            if ssid != credentials._ssid:
                _fail('ssid_mismatch')
            private['ssid'] = ssid
            summary['ctrl_ssid_matches'] = True
        elif key in (b'bssid', b'p2p_device_address', b'address'):
            private[key.decode('ascii')] = _mac(value)
        elif key in (b'freq', b'id', b'bss_max_idle_period'):
            minimum, maximum = (1, 65535) if key == b'freq' else (0, MAX_NETWORK_ID)
            private[key.decode('ascii')] = _decimal(value, minimum, maximum)
        elif key == b'ip_address':
            private['ip_address'] = _ipv4(value)
            summary['optional_ip_reported'] = True
        elif key in (b'pairwise_cipher', b'group_cipher'):
            if value != b'CCMP':
                _fail('security_mismatch')
        elif key == b'key_mgmt':
            if value != b'WPA2-PSK':
                _fail('security_mismatch')
        elif key == b'mode':
            if value != b'station':
                _fail('role_mismatch')
        elif key == b'pmf':
            _decimal(value, 0, 2)
        elif key == b'mgmt_group_cipher':
            if value != b'AES-128-CMAC':
                _fail('security_mismatch')
        elif key == b'wifi_generation':
            _decimal(value, 4, 7)
        elif key in (b'max_nss_rx', b'max_nss_tx'):
            _decimal(value, 0, 16)
        elif key == b'channel_width':
            if _decimal(value, 0, 320) not in (0, 20, 40, 80, 160, 320):
                _fail('invalid_field')
        elif key in (b'ieee80211ac', b'ssid_verified', b'bigtk_set'):
            if value != b'1':
                _fail('invalid_field')
        elif key == b'uuid':
            if (len(value) != 36 or any(value[pos] != 45 for pos in (8, 13, 18, 23))
                    or len(value.replace(b'-', b'')) != 32
                    or any(o not in _HEX for o in value.replace(b'-', b''))):
                _fail('invalid_field')
    security = (b'pairwise_cipher', b'group_cipher', b'key_mgmt')
    summary['ctrl_wpa2_ccmp'] = all(key in fields for key in security)
    if state == b'COMPLETED':
        required = (b'ssid', b'id', b'mode', b'bssid', b'freq', b'address') + security
        if any(key not in fields for key in required):
            _fail('missing_field')
        summary['ctrl_completed'] = True
    private['state'] = state
    return _ControlReport(private, summary)


def _group_tokens(line):
    """Specific source grammar, not a generic quoted-string/ctrl parser."""
    fields, persistent, pos = {}, False, 0
    while pos < len(line):
        if line[pos:pos + 12] == b'[PERSISTENT]':
            if persistent:
                _fail('duplicate_field')
            persistent = True
            pos += 12
        else:
            end = line.find(b'=', pos)
            if end < 0 or b' ' in line[pos:end]:
                _fail('invalid_frame')
            key = line[pos:end]
            if key in fields:
                _fail('duplicate_field')
            if key not in (b'ssid', b'freq', b'psk', b'passphrase', b'go_dev_addr',
                           b'ip_addr', b'ip_mask', b'go_ip_addr'):
                _fail('unsupported_event_field')
            pos = end + 1
            if key in (b'ssid', b'passphrase'):
                if line[pos:pos + 1] != b'"':
                    _fail('invalid_frame')
                begin, pos = pos + 1, pos + 1
                while pos < len(line):
                    if line[pos] == 34:
                        break
                    # SSID uses printf_encode; passphrase source prints raw.
                    if key == b'ssid' and line[pos] == 92:
                        pos += 1
                    pos += 1
                if pos >= len(line):
                    _fail('invalid_frame')
                value, pos = line[begin:pos], pos + 1
            else:
                end = line.find(b' ', pos)
                if end < 0:
                    end = len(line)
                value, pos = line[pos:end], end
            if not value:
                _fail('invalid_field')
            fields[key] = value
        if pos < len(line):
            if line[pos:pos + 1] != b' ' or pos + 1 == len(line):
                _fail('invalid_frame')
            pos += 1
    return fields, persistent


def parse_group_started(event, owned_name, credentials):
    credentials = _credentials(credentials)
    owned_name = _owned_name(owned_name)
    _bytes(event, 1, MAX_EVENT)
    if event.endswith(b'\n'):
        event = event[:-1]
    if not event or any(o < 32 or o > 126 for o in event):
        _fail('invalid_frame')
    if event.startswith(b'IFNAME='):
        marker, separator, event = event.partition(b' ')
        if not separator or marker[7:] != owned_name:
            _fail('interface_mismatch')
    if event.startswith(b'<'):
        if len(event) < 3 or event[2:3] != b'>' or event[1] not in b'012345':
            _fail('invalid_frame')
        event = event[3:]
    parts = event.split(b' ', 3)
    if len(parts) != 4 or parts[0] != b'P2P-GROUP-STARTED':
        _fail('invalid_frame')
    if parts[1] != owned_name:
        _fail('interface_mismatch')
    if parts[2] != b'client':
        _fail('role_mismatch')
    fields, persistent = _group_tokens(parts[3])
    if any(key not in fields for key in (b'ssid', b'freq', b'go_dev_addr')):
        _fail('missing_field')
    # GROUP surrounds the same source printf_encode bytes in double quotes.
    ssid = _ssid_decode(fields[b'ssid'])
    if ssid != credentials._ssid:
        _fail('ssid_mismatch')
    private = {'ssid': ssid, 'frequency': _decimal(fields[b'freq'], 1, 65535),
               'go_dev_addr': _mac(fields[b'go_dev_addr'], allow_zero=True),
               'persistent': persistent, 'interface': owned_name}
    summary = _summary('group_started')
    summary['ctrl_client_role'] = summary['ctrl_ssid_matches'] = True
    for key in (b'psk', b'passphrase'):
        if key not in fields:
            continue
        value = fields[key]
        if key == b'psk':
            if len(value) != 64 or any(o not in _HEX for o in value):
                _fail('invalid_field')
            key_bytes = binascii.unhexlify(value)
        else:
            if not 8 <= len(value) <= 63 or any(o < 32 or o > 126 for o in value):
                _fail('invalid_field')
            key_bytes = _derive(value, ssid)
        if not hmac.compare_digest(key_bytes, credentials._psk):
            _fail('key_mismatch')
        summary['ctrl_key_reported'] = summary['ctrl_key_matches'] = True
    ip_keys = (b'ip_addr', b'ip_mask', b'go_ip_addr')
    count = sum(key in fields for key in ip_keys)
    if count and count != 3:
        _fail('missing_field')
    if count:
        local, mask, go = (_ipv4(fields[b'ip_addr']), _ipv4(fields[b'ip_mask'], True),
                           _ipv4(fields[b'go_ip_addr']))
        inverse = mask ^ 0xffffffff
        if (local == go or local & mask != go & mask or
                (local & inverse) in (0, inverse) or (go & inverse) in (0, inverse)):
            _fail('invalid_ip_profile')
        private.update({'ip_address': local, 'ip_mask': mask, 'go_ip_address': go})
        summary['optional_ip_reported'] = True
    return _ControlReport(private, summary)
