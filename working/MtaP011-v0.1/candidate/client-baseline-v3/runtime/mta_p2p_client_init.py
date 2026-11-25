"""HOST CLIENT RF-init ownership core, not a Linux provider or receive backend.

Import/construction does no I/O. Only an internal, separately reviewed provider
and Store can implement the contracts below; this file supplies neither. Tests
use explicitly synthetic providers. No GROUP/SCAN/IP/DHCP/data operations exist.
Initialization may cause RF in the driver/firmware even with an empty profile.
Public capabilities remain false. Python 3.5, no json dependency.
"""
import mta_ip as ip


VERSION = 4
KIND = 'p2p_client_rf_init_only'
MARKER = 'p011-client-rf-init-v1-1'
WPA_SHA = 'e069aef76a089215367f502015266e9ce59cf4ebb7d7246974815ff60d67f301'
CTRL_SHA = '793b784f1b39eca18001aa65a1f0d6cdbd6de466dc58b3cf2ada167f71d902b5'
CLIENT_CONFIG = b'ap_scan=1\np2p_no_group_iface=1\n'
STOCK_PINS = (
    ('/usr/bin/Z03','cb8d6a78617d50f64c6adc8056427dd963bc83979cbb04e349275dd8e8ffb62a'),
    ('/usr/bin/control_engine','364b0bf820799070e89d9362000de4a3796a0e6a2d5f4d657464c6385b8dbd6d'),
    ('/usr/bin/zyb_z03_launch.sh','7bce5379e3cc78e5bd8c04ceb603c88814f24c3a7efd28105ecc3c5849d6a42b'))
_HEX = frozenset('0123456789abcdef')
_STAGES = frozenset(('new', 'prepared', 'watchdog_intent', 'watchdog_saved',
    'interface_intent', 'interface_owned', 'controller_intent',
    'controller_saved', 'client_init_ready', 'cleanup_intent',
    'cleanup_verified', 'reconciled'))
_CODES = frozenset(('provider_unavailable', 'store_unavailable',
    'invalid_provider', 'invalid_store', 'invalid_identity', 'invalid_clock',
    'expired', 'cancelled', 'invalid_budget', 'invalid_caps', 'unsupported_combo',
    'invalid_snapshot', 'baseline_changed', 'invalid_origin', 'origin_changed',
    'unexpected_owned_l3', 'invalid_status', 'unsupported_status_field',
    'unexpected_ctrl_state', 'invalid_ticket', 'invalid_actor', 'actor_unknown',
    'actor_reap_unknown', 'invalid_locks', 'pending_blocked', 'current_blocked',
    'invalid_journal', 'stale_current', 'durability_unknown', 'exec_gate_failed',
    'invalid_close_proof', 'resource_close_unknown', 'store_finish_unknown',
    'unexpected_provider_error','executor_role_forbidden','self_actor_recovery',
    'external_finalizer_lock_unverified','locks_close_unverified',
    'finish_sealed','store_finish_incomplete'))


class ClientInitError(ValueError):
    def __init__(self, code):
        self.code = code if type(code) is str and code in _CODES else 'unexpected_provider_error'
        ValueError.__init__(self, self.code)


def _fail(code):
    raise ClientInitError(code)


def _uint(value, maximum=0xffffffff, minimum=0):
    if type(value) is not int or not minimum <= value <= maximum:
        _fail('invalid_snapshot')
    return value


def _hash(value, code='invalid_snapshot'):
    if type(value) is not str or len(value) != 64 or any(c not in _HEX for c in value):
        _fail(code)
    return value


def _finite(value, code):
    if type(value) not in (int, float) or not 0 <= value < 1e12:
        _fail(code)
    return float(value)


def _boot(value):
    if type(value) is not str or len(value) != 36 or any(value[i] != '-' for i in (8, 13, 18, 23)) or \
            len(value.replace('-', '')) != 32 or any(c not in _HEX for c in value.replace('-', '')):
        _fail('invalid_snapshot')
    return value


def _name(value, owned=False):
    if type(value) is not str or not 1 <= len(value) <= 15 or \
            any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789_.-' for c in value):
        _fail('invalid_origin')
    if owned and (len(value) != 11 or not value.startswith('mta') or any(c not in _HEX for c in value[3:])):
        _fail('invalid_origin')
    return value


class _Private(object):
    __slots__ = ()

    def __setattr__(self, name, value):
        raise AttributeError('private immutable record')

    def __repr__(self):
        return '<CLIENT RF-init private record>'

    __str__ = __repr__


class Identity(_Private):
    """Outer manifest pin supplied by the future fixed harness, not a UI field."""
    __slots__ = ('candidate_sha',)

    def __init__(self, candidate_sha):
        object.__setattr__(self, 'candidate_sha', _hash(candidate_sha, 'invalid_identity'))

    def key(self):
        return (VERSION, KIND, MARKER, self.candidate_sha, WPA_SHA, CTRL_SHA)


class Origin(_Private):
    __slots__ = ('phy', 'wdev', 'ifindex', 'name', 'iftype')

    def __init__(self, phy, wdev, ifindex, name, iftype):
        for key, value in (('phy', _uint(phy)), ('wdev', _uint(wdev, (1 << 64) - 1, 1)),
                           ('ifindex', _uint(ifindex, 0x7fffffff, 1)),
                           ('name', _name(name)), ('iftype', _uint(iftype, 12, 1))):
            object.__setattr__(self, key, value)

    def key(self):
        return (self.phy, self.wdev, self.ifindex, self.name, self.iftype)


class Actor(_Private):
    """Private PID/start/exe/argv and complete task identity, not cmdline gone."""
    __slots__ = ('pid', 'start', 'exe', 'argv_sha', 'tasks')

    def __init__(self, pid, start, exe, argv_sha, tasks):
        _uint(pid, 0x7fffffff, 1); _uint(start, (1 << 64) - 1, 1)
        if type(exe) is not str or not 1 <= len(exe) <= 256 or not exe.startswith('/') or \
                any(p in ('', '.', '..') for p in exe[1:].split('/')) or any(ord(c)<32 for c in exe):
            _fail('invalid_actor')
        if type(tasks) is not tuple or not 1 <= len(tasks) <= 128:
            _fail('invalid_actor')
        for row in tasks:
            if type(row) is not tuple or len(row) != 3 or type(row[2]) is not str or \
                    row[2] not in ('R', 'S', 'D', 'T', 't', 'Z', 'X', 'I'):
                _fail('invalid_actor')
            _uint(row[0], 0x7fffffff, 1); _uint(row[1], (1 << 64) - 1, 1)
        if len(set(r[0] for r in tasks)) != len(tasks) or not any(r[:2] == (pid, start) for r in tasks):
            _fail('invalid_actor')
        for key, value in (('pid', pid), ('start', start), ('exe', exe),
                           ('argv_sha', _hash(argv_sha, 'invalid_actor')), ('tasks', tasks)):
            object.__setattr__(self, key, value)

    def key(self):
        return (self.pid, self.start, self.exe, self.argv_sha, tuple((t[0],t[1]) for t in self.tasks))

    def live(self):
        return all(t[2] not in ('Z','X') for t in self.tasks)


class InterfaceTicket(_Private):
    """Private CREATE intent fixed before provider mutation; no inferred WDEV."""
    __slots__=('boot','phy','name','sequence','port_id')

    def __init__(self,boot,phy,name,sequence,port_id):
        for key,value in (('boot',_boot(boot)),('phy',_uint(phy)),('name',_name(name,True)),
                ('sequence',_uint(sequence,0xffffffff,1)),('port_id',_uint(port_id,0xffffffff,1))):
            object.__setattr__(self,key,value)

    def key(self):
        return (self.boot,self.phy,self.name,self.sequence,self.port_id)


class Ticket(_Private):
    """Provider registers a strong private resource ticket BEFORE any fork."""
    __slots__ = ('token', 'role', 'boot', 'exe', 'argv_sha')

    def __init__(self, token, role, boot, exe, argv_sha):
        if type(token) is not str or len(token) != 32 or any(c not in _HEX for c in token) or \
                role not in ('controller', 'watchdog') or type(role) is not str:
            _fail('invalid_ticket')
        # Validate the path without inventing a PID or process identity.
        if type(exe) is not str or not 1 <= len(exe) <= 256 or not exe.startswith('/') or \
                any(p in ('', '.', '..') for p in exe[1:].split('/')) or any(ord(c)<32 for c in exe):
            _fail('invalid_ticket')
        for key, value in (('token', token), ('role', role), ('boot', _boot(boot)),
                           ('exe', exe), ('argv_sha', _hash(argv_sha, 'invalid_ticket'))):
            object.__setattr__(self, key, value)

    def key(self):
        return (self.token, self.role, self.boot, self.exe, self.argv_sha)


class Handle(_Private):
    """Strong actual provider resource, retained even after a late spawn."""
    __slots__ = ('ticket', 'actor', 'resource')

    def __init__(self, ticket, actor, resource):
        if type(ticket) is not Ticket or type(actor) is not Actor or resource is None or \
                (actor.exe, actor.argv_sha) != (ticket.exe, ticket.argv_sha):
            _fail('invalid_actor')
        for key, value in (('ticket', ticket), ('actor', actor), ('resource', resource)):
            object.__setattr__(self, key, value)


class ExitProof(_Private):
    """Entire fixed PID/task tree absent + actual child wait/reap, not a flag."""
    __slots__ = ('actor', 'pid_path_absent', 'remaining_tasks', 'waited', 'exit_code')

    def __init__(self, actor, pid_path_absent, remaining_tasks, waited, exit_code):
        if type(actor) is not Actor or type(pid_path_absent) is not bool or type(waited) is not bool or \
                type(remaining_tasks) is not tuple or len(remaining_tasks) > 128 or \
                any(type(v) is not int or not 0 < v <= 0x7fffffff for v in remaining_tasks) or \
                (exit_code is not None and (type(exit_code) is not int or not -255 <= exit_code <= 255)):
            _fail('actor_reap_unknown')
        for key, value in (('actor', actor), ('pid_path_absent', pid_path_absent),
                           ('remaining_tasks', remaining_tasks), ('waited', waited), ('exit_code', exit_code)):
            object.__setattr__(self, key, value)

    def gone(self, actor):
        return (type(actor) is Actor and self.actor.key() == actor.key() and self.pid_path_absent and
                not self.remaining_tasks and self.waited and self.exit_code is not None)


class UnlaunchedProof(_Private):
    """Positive provider registry proof, NEVER inferred from a journal stage."""
    __slots__=('ticket','never_forked','resources_closed')

    def __init__(self,ticket,never_forked,resources_closed):
        if type(ticket) is not Ticket or type(never_forked) is not bool or type(resources_closed) is not bool:
            _fail('actor_unknown')
        for key,value in (('ticket',ticket),('never_forked',never_forked),('resources_closed',resources_closed)):
            object.__setattr__(self,key,value)


class ExecutorProof(_Private):
    """Current trusted executor identity. No actual proc reader exists here."""
    __slots__=('role','actor','same_ofd_verified')

    def __init__(self,role,actor,same_ofd_verified):
        if type(role) is not str or role not in ('owner','external_finalizer','watchdog') or \
                type(actor) is not Actor or not actor.live() or type(same_ofd_verified) is not bool:
            _fail('executor_role_forbidden')
        for key,value in (('role',role),('actor',actor),('same_ofd_verified',same_ofd_verified)):
            object.__setattr__(self,key,value)


class CloseProof(_Private):
    """One bool per recorded FD/handle; all independently attempted/read back."""
    __slots__ = ('expected', 'attempted', 'closed')

    def __init__(self, expected, attempted, closed):
        _uint(expected, 128)
        if type(attempted) is not tuple or type(closed) is not tuple or \
                len(attempted) != expected or len(closed) != expected or \
                any(type(v) is not bool for v in attempted + closed):
            _fail('invalid_close_proof')
        for key, value in (('expected', expected), ('attempted', attempted), ('closed', closed)):
            object.__setattr__(self, key, value)

    def complete(self):
        return all(self.attempted) and all(self.closed)


def _ipv4(value):
    if type(value) is not ip.IpSnapshot or any(type(rows) is not tuple or len(rows) > 4096
            for rows in (value.addresses, value.routes, value.rules)):
        _fail('invalid_snapshot')
    for rows, cls in ((value.addresses, ip.AddressRecord), (value.routes, ip.RouteRecord), (value.rules, ip.RuleRecord)):
        if any(type(row) is not cls for row in rows): _fail('invalid_snapshot')
    for row in value.addresses:
        if any(type(v) is not int for v in row[:6]) or type(row.cacheinfo) is not tuple or len(row.cacheinfo) != 4:
            _fail('invalid_snapshot')
        _uint(row.ifindex, 0x7fffffff, 1); _uint(row.local); _uint(row.address); _uint(row.prefixlen, 32)
        if row.scope not in (0, 253, 254) or row.flags != 0x80 or \
                any(type(v) is not int or not 0 <= v <= 0xffffffff for v in row.cacheinfo) or \
                row.cacheinfo[:2] != (0xffffffff, 0xffffffff):
            _fail('invalid_snapshot')
        if row.label is not None and (type(row.label) is not bytes or not 2 <= len(row.label) <= 16 or
                row.label[-1:] != b'\x00' or b'\x00' in row.label[:-1]): _fail('invalid_snapshot')
        if row.broadcast is not None: _uint(row.broadcast)
    for row in value.routes:
        if any(type(v) is not int for v in row[:7]) or type(row.metrics) is not tuple or len(row.metrics) > 15:
            _fail('invalid_snapshot')
        _uint(row.network); _uint(row.prefixlen, 32); _uint(row.table, 0xffffffff, 1); _uint(row.protocol, 255)
        if row.scope not in (0, 253, 254) or row.kind not in (1, 2, 3) or row.flags & ~0x19 or \
                row.network & ((0xffffffff << (32 - row.prefixlen)) & 0xffffffff if row.prefixlen else 0) != row.network:
            _fail('invalid_snapshot')
        for v in row[7:11]:
            if v is not None: _uint(v)
        if row.oif is not None: _uint(row.oif, 0x7fffffff, 1)
        for pair in row.metrics:
            if type(pair) is not tuple or len(pair) != 2: _fail('invalid_snapshot')
            _uint(pair[0], 15, 1); _uint(pair[1])
        if len(set(p[0] for p in row.metrics)) != len(row.metrics): _fail('invalid_snapshot')
    for row in value.rules:
        _uint(row.priority); _uint(row.table, 0xffffffff, 1)
    if any(len(set(rows)) != len(rows) for rows in (value.addresses, value.routes, value.rules)):
        _fail('invalid_snapshot')
    try: ip.require_default_rules(value)
    except ip.IpCoreError: _fail('invalid_snapshot')
    return value


def _rows(rows, width, limit=4096, _unique=True):
    if type(_unique) is not bool or type(rows) is not tuple or len(rows) > limit or any(type(row) is not tuple or len(row) != width
            or any(type(v) is not str or not 1 <= len(v) <= 256 or '\x00' in v or '\n' in v or '\r' in v for v in row)
            for row in rows) or (_unique and len(set(rows)) != len(rows)):
        _fail('invalid_snapshot')
    return rows


class Snapshot(_Private):
    """Complete supplied records. The absent Linux reader must authenticate dumps."""
    __slots__ = ('boot', 'stock_hashes', 'stock_actors', 'station', 'station_state_sha',
                 'station_frequency', 'interfaces', 'ipv4', 'ipv6_addresses', 'ipv6_routes','station_completed')

    def __init__(self, boot, stock_hashes, stock_actors, station, station_state_sha,
                 station_frequency, interfaces, ipv4, ipv6_addresses, ipv6_routes,station_completed):
        if type(stock_hashes) is not tuple or not 1 <= len(stock_hashes) <= 16 or \
                any(type(row) is not tuple or len(row) != 2 or type(row[0]) is not str or
                    not row[0].startswith('/') for row in stock_hashes): _fail('invalid_snapshot')
        for row in stock_hashes: _hash(row[1])
        if tuple(sorted(stock_hashes)) != tuple(sorted(STOCK_PINS)) or station_completed is not True:
            _fail('invalid_snapshot')
        if type(stock_actors) is not tuple or not 1 <= len(stock_actors) <= 32 or \
                any(type(row) is not Actor for row in stock_actors) or \
                len(set(a.pid for a in stock_actors)) != len(stock_actors): _fail('invalid_snapshot')
        if not {'/usr/bin/Z03','/usr/bin/control_engine'} <= set(a.exe for a in stock_actors) or \
                not any(a.exe.rsplit('/',1)[-1]=='weston' for a in stock_actors) or \
                any(not a.live() for a in stock_actors): _fail('invalid_snapshot')
        if type(station) is not Origin or station.name != 'wlan0' or station.iftype != 2 or \
                type(interfaces) is not tuple or not 1 <= len(interfaces) <= 32 or \
                any(type(row) is not Origin for row in interfaces) or \
                len(set(row.ifindex for row in interfaces)) != len(interfaces) or \
                len(set(row.name for row in interfaces)) != len(interfaces) or \
                sum(row.key() == station.key() for row in interfaces) != 1:
            _fail('invalid_snapshot')
        _uint(station_frequency, 2484, 2412)
        for key, value in (('boot', _boot(boot)), ('stock_hashes', tuple(sorted(stock_hashes))),
                ('stock_actors', stock_actors), ('station', station), ('station_state_sha', _hash(station_state_sha)),
                ('station_frequency', station_frequency), ('interfaces', interfaces), ('ipv4', _ipv4(ipv4)),
                ('ipv6_addresses', _rows(ipv6_addresses, 6)), ('ipv6_routes', _rows(ipv6_routes, 10, _unique=False)),
                ('station_completed',True)):
            object.__setattr__(self, key, value)

    def key(self, owned=None):
        # No IPv4 subtraction: RF-init must not own any IPv4 address/route.
        if owned is not None:
            if type(owned) is not Origin or owned.iftype != 8: _fail('invalid_origin')
            if any(r.ifindex == owned.ifindex for r in self.ipv4.addresses) or \
                    any(r.oif == owned.ifindex for r in self.ipv4.routes): _fail('unexpected_owned_l3')
            owned_interfaces = tuple(r for r in self.interfaces if r.name == owned.name or r.ifindex == owned.ifindex or r.wdev == owned.wdev)
            if len(owned_interfaces) != 1 or owned_interfaces[0].key() != owned.key(): _fail('origin_changed')
            _owned_ipv6(self.ipv6_addresses, self.ipv6_routes, owned)
        return (self.boot, self.stock_hashes, tuple(sorted(a.key() for a in self.stock_actors)),
                self.station.key(), self.station_state_sha, self.station_frequency,
                tuple(sorted(r.key() for r in self.interfaces if owned is None or r.key() != owned.key())),
                tuple(sorted(self.ipv4.addresses,key=lambda r:repr(tuple(r)))), tuple(sorted(self.ipv4.routes, key=lambda r: repr(tuple(r)))),
                tuple(sorted(self.ipv4.rules)),
                tuple(sorted(r for r in self.ipv6_addresses if owned is None or r[-1] != owned.name)),
                tuple(sorted(r for r in self.ipv6_routes if owned is None or r[-1] != owned.name)))


def _hex(text, width):
    return type(text) is str and len(text) == width and all(c in _HEX for c in text)


def _owned_ipv6(addresses, routes, owned):
    for row in addresses:
        if row[-1] != owned.name: continue
        # /proc/net/if_inet6: address, index, prefix, scope, flags, name.
        if not _hex(row[0], 32) or not 2 <= len(row[1]) <= 8 or not _hex(row[1],len(row[1])) or \
                int(row[1], 16) != owned.ifindex or \
                row[2] != '40' or row[3] != '20' or not _hex(row[4], 2) or int(row[4],16)&~0xc0 or \
                int(row[0], 16) >> 118 != 0x3fa:
            _fail('unexpected_owned_l3')
    mroute = 0
    for row in routes:
        if row[-1] != owned.name: continue
        if not all(_hex(row[i], width) for i, width in ((0,32),(1,2),(2,32),(3,2),(4,32),(5,8),(6,8),(7,8),(8,8))):
            _fail('unexpected_owned_l3')
        if row[2] != '0'*32 or row[3] != '00' or row[4] != '0'*32: _fail('unexpected_owned_l3')
        if row[0] == 'ff'+'0'*30 and row[1] == '08' and row[8] == '00000001':
            mroute += 1
            if mroute > 1: _fail('unexpected_owned_l3')
        elif not 10 <= int(row[1],16) <= 64 or int(row[0],16) >> 118 != 0x3fa:
            _fail('unexpected_owned_l3')
        elif int(row[8],16)&~0x00040001 or not int(row[8],16)&1:
            _fail('unexpected_owned_l3')


def client_combo(caps, snapshot):
    """Full counts/coverage, not the native GO boolean. Unknown constraints reject."""
    if type(snapshot) is not Snapshot or type(caps) is not dict or set(caps) != {'phys', 'complete'} or caps['complete'] is not True or \
            type(caps['phys']) is not tuple or not 1 <= len(caps['phys']) <= 8:
        _fail('invalid_caps')
    phys = []
    for phy in caps['phys']:
        if type(phy) is not dict or set(phy) != {'index','iftypes','software_iftypes','combinations','unknown_constraints'}:
            _fail('invalid_caps')
        _uint(phy['index']); phys.append(phy['index'])
        if type(phy['iftypes']) is not tuple or type(phy['software_iftypes']) is not tuple or \
                any(type(t) is not int or not 1 <= t <= 12 for t in phy['iftypes']+phy['software_iftypes']) or \
                len(set(phy['iftypes'])) != len(phy['iftypes']) or len(set(phy['software_iftypes'])) != len(phy['software_iftypes']) or \
                type(phy['unknown_constraints']) is not tuple or phy['unknown_constraints'] or \
                type(phy['combinations']) is not tuple or not 1 <= len(phy['combinations']) <= 16:
            _fail('invalid_caps')
        for combo in phy['combinations']:
            if type(combo) is not dict or set(combo) != {'max_interfaces','num_channels','limits','radar_widths','radar_regions','beacon_match'} or \
                    type(combo['limits']) is not tuple or not 1 <= len(combo['limits']) <= 16 or \
                    type(combo['beacon_match']) is not bool:
                _fail('invalid_caps')
            _uint(combo['max_interfaces'],32,1); _uint(combo['num_channels'],32,1)
            _uint(combo['radar_widths']); _uint(combo['radar_regions'])
            covered = set()
            for limit in combo['limits']:
                if type(limit) is not dict or set(limit) != {'max','types'} or type(limit['types']) is not tuple or not limit['types']:
                    _fail('invalid_caps')
                _uint(limit['max'],32,1)
                if any(type(t) is not int or not 1 <= t <= 12 for t in limit['types']) or \
                        len(set(limit['types'])) != len(limit['types']) or covered.intersection(limit['types']): _fail('invalid_caps')
                covered.update(limit['types'])
    if len(set(phys)) != len(phys): _fail('invalid_caps')
    matches = [p for p in caps['phys'] if p['index'] == snapshot.station.phy]
    if len(matches) != 1: _fail('unsupported_combo')
    phy = matches[0]
    if 2 not in phy['iftypes'] or 8 not in phy['iftypes'] or phy['software_iftypes']: _fail('unsupported_combo')
    counts = {}
    for row in snapshot.interfaces:
        if row.phy == phy['index']: counts[row.iftype] = counts.get(row.iftype,0)+1
    counts[8] = counts.get(8,0)+1
    for combo in phy['combinations']:
        # Empty CLIENT has no known operating channel: no claim of two channels.
        if combo['radar_widths'] or combo['radar_regions'] or combo['beacon_match']: continue
        covered = set(t for lim in combo['limits'] for t in lim['types'])
        if set(counts) <= covered and sum(counts.values()) <= combo['max_interfaces'] and all(
                sum(counts.get(t,0) for t in lim['types']) <= lim['max'] for lim in combo['limits']): return True
    _fail('unsupported_combo')


def parse_init_status(reply):
    """Fixed 2.12 nonverbose INACTIVE output; no fabricated Credentials."""
    if type(reply) is not bytes or not 1 <= len(reply) <= 2048 or not reply.endswith(b'\n') or b'\x00' in reply or b'\r' in reply:
        _fail('invalid_status')
    fields = {}
    allowed = (b'wpa_state',b'p2p_device_address',b'address',b'uuid',b'ieee80211ac',b'bss_max_idle_period')
    lines = reply[:-1].split(b'\n')
    if not 1 <= len(lines) <= 8: _fail('invalid_status')
    for line in lines:
        if b'=' not in line or len(line) > 128: _fail('invalid_status')
        key,value = line.split(b'=',1)
        if key in fields or not value: _fail('invalid_status')
        if key not in allowed: _fail('unsupported_status_field')
        fields[key] = value
    if fields.get(b'wpa_state') != b'INACTIVE': _fail('unexpected_ctrl_state')
    for key in (b'address',b'p2p_device_address'):
        value = fields.get(key)
        if value is None or len(value) != 17 or any(value[i] != 58 for i in (2,5,8,11,14)) or \
                any(c not in b'0123456789abcdef' for i,c in enumerate(value) if i not in (2,5,8,11,14)) or \
                int(value.replace(b':',b''),16) == 0 or int(value[:2],16)&1: _fail('invalid_status')
    uuid = fields.get(b'uuid')
    if uuid is None or len(uuid) != 36 or any(uuid[i] != 45 for i in (8,13,18,23)) or \
            len(uuid.replace(b'-',b'')) != 32 or any(c not in b'0123456789abcdef' for c in uuid.replace(b'-',b'')):
        _fail('invalid_status')
    if b'ieee80211ac' in fields and fields[b'ieee80211ac'] != b'1': _fail('invalid_status')
    if b'bss_max_idle_period' in fields:
        value = fields[b'bss_max_idle_period']
        if len(value)>5 or any(c not in b'0123456789' for c in value) or \
                len(value)>1 and value.startswith(b'0') or not 1 <= int(value) <= 65535: _fail('invalid_status')
    # No parsed address/UUID escapes this function, even on errors.
    return {'ctrl_inactive':True,'control_fields_only':True,'association_verified':False}


class Journal(_Private):
    """Strict immutable version4 logical schema; on-disk codec is not supplied."""
    __slots__ = ('identity','stage','baseline','deadline','owned','interface_ticket','controller_ticket','controller',
                 'watchdog_ticket','watchdog','ready')

    def __init__(self, identity, stage, baseline, deadline, owned=None, controller_ticket=None,
                 controller=None, watchdog_ticket=None, watchdog=None, ready=False,interface_ticket=None):
        if type(identity) is not Identity or type(stage) is not str or stage not in _STAGES or \
                type(baseline) is not Snapshot or type(ready) is not bool:
            _fail('invalid_journal')
        _finite(deadline,'invalid_journal')
        if owned is not None and (type(owned) is not Origin or owned.iftype != 8): _fail('invalid_journal')
        if owned is not None: _name(owned.name,True)
        if interface_ticket is not None and (type(interface_ticket) is not InterfaceTicket or
                interface_ticket.boot!=baseline.boot or interface_ticket.phy!=baseline.station.phy): _fail('invalid_journal')
        if owned is not None and (interface_ticket is None or (owned.name,owned.phy)!=
                (interface_ticket.name,interface_ticket.phy)): _fail('invalid_journal')
        for ticket,actor,role in ((controller_ticket,controller,'controller'),(watchdog_ticket,watchdog,'watchdog')):
            if ticket is not None and (type(ticket) is not Ticket or ticket.role != role or ticket.boot != baseline.boot): _fail('invalid_journal')
            if actor is not None and (type(actor) is not Actor or ticket is None or
                    (actor.exe,actor.argv_sha) != (ticket.exe,ticket.argv_sha)): _fail('invalid_journal')
        if (controller_ticket is not None and owned is None) or ready and (owned is None or controller is None or watchdog is None):
            _fail('invalid_journal')
        if ready and stage!='client_init_ready' or stage=='client_init_ready' and not ready or \
                stage in ('controller_saved','client_init_ready') and controller is None or \
                stage in ('interface_owned','controller_intent','controller_saved','client_init_ready') and owned is None or \
                stage in ('watchdog_saved','interface_intent','interface_owned','controller_intent','controller_saved','client_init_ready') and watchdog is None:
            _fail('invalid_journal')
        if stage in ('new','prepared') and any(v is not None for v in
                (owned,interface_ticket,controller_ticket,controller,watchdog_ticket,watchdog)) or \
                stage=='watchdog_intent' and watchdog_ticket is None or \
                stage=='interface_intent' and interface_ticket is None or \
                stage=='controller_intent' and controller_ticket is None:
            _fail('invalid_journal')
        for key,value in (('identity',identity),('stage',stage),('baseline',baseline),('deadline',float(deadline)),
                ('owned',owned),('controller_ticket',controller_ticket),('controller',controller),
                ('watchdog_ticket',watchdog_ticket),('watchdog',watchdog),('ready',ready),('interface_ticket',interface_ticket)):
            object.__setattr__(self,key,value)

    def key(self):
        return (self.identity.key(),self.stage,self.baseline.key(),self.deadline,
                None if self.owned is None else self.owned.key(),
                None if self.interface_ticket is None else self.interface_ticket.key(),
                None if self.controller_ticket is None else self.controller_ticket.key(),
                None if self.controller is None else self.controller.key(),
                None if self.watchdog_ticket is None else self.watchdog_ticket.key(),
                None if self.watchdog is None else self.watchdog.key(),self.ready)

    def replace(self, **changes):
        if set(changes)-set(self.__slots__): _fail('invalid_journal')
        return Journal(**dict((key,changes.get(key,getattr(self,key))) for key in self.__slots__))


class ClientInitProvider(object):
    """Internal contract ONLY. No concrete Linux provider/default action exists.

    Implementations must authenticate kernel replies, fixed binaries and private
    actors; resolve every registered ticket, including fork/spawn exceptions.
    Live proof reads all task identities. Closed/exit proof cannot come from a
    cached Event. Callback deadlines are admission limits, not preemptive I/O.
    """
    # Watchdog is a passive recovery-request source, never its own finalizer.
    # Only an external executor can reap the recorded watchdog/controller.
    # Real orphan recovery is NOT implemented: wait/reap must not be invented.
    def executor(self, deadline): _fail('provider_unavailable')
    def snapshot(self, deadline): _fail('provider_unavailable')
    def caps(self, deadline): _fail('provider_unavailable')
    def original_actors(self, baseline, deadline): _fail('provider_unavailable')
    def register(self, role, identity, boot, deadline): _fail('provider_unavailable')
    def launch_watchdog(self, ticket, record, inherited_locks, deadline): _fail('provider_unavailable')
    def register_interface(self, identity, baseline, deadline): _fail('provider_unavailable')
    def create_client(self, ticket, deadline): _fail('provider_unavailable')
    def origin_up(self, owned, deadline): _fail('provider_unavailable')
    def launch_controller(self, ticket, owned, config, deadline): _fail('provider_unavailable')
    def release_exec(self, handle, deadline): _fail('provider_unavailable')
    def live_actor(self, handle, deadline): _fail('provider_unavailable')
    def status(self, handle, owned, deadline): _fail('provider_unavailable')
    def resolve(self, ticket, deadline): _fail('provider_unavailable')
    def stop_and_reap(self, handle, deadline): _fail('provider_unavailable')
    def exit_proof(self, handle, deadline): _fail('provider_unavailable')
    def delete_client(self, owned, deadline): _fail('provider_unavailable')
    def origin_absent(self, owned, deadline): _fail('provider_unavailable')
    def close_resources(self, handles, deadline): _fail('provider_unavailable')
    def closed_resources(self, handles, deadline): _fail('provider_unavailable')


class ClientInitStore(object):
    """Unimplemented durable Store/lock contract. Never just an in-memory event.

    acquire holds device flock and journal RLock; a watchdog inherits the SAME
    open-file description, not a second flock. finish always releases each
    owned reference independently and reports actual closed resources. On any
    uncertain close/durability it reports physical marker and logical resource
    facts separately. After terminal publication/own marker clear, an unknown
    last close must NOT pretend that the marker is still present. The fixed
    producer authenticates its issued receipt and actual resource inventory;
    merely constructing a correctly shaped FinishReceipt gives no authority.
    A ready return releases the journal lock but retains the parent device lock.
    Recover reacquires only the journal lock when an inherited device ticket is
    supplied; it must not reread a stale pre-lock record or adopt a GO identity.
    closed_locks is readback ONLY of the original two lock references. Unknown
    close cannot be retried or repaired by closing a possibly reused FD.
    Implementing these OS/disk guarantees is a later reviewed task.
    """
    def acquire(self, identity, deadline, inherited=None): _fail('store_unavailable')
    def lock_valid(self, locks): _fail('store_unavailable')
    def current(self, locks): _fail('store_unavailable')
    def pending_clear(self, locks): _fail('store_unavailable')
    def prior_clear(self, locks, baseline, deadline): _fail('store_unavailable')
    def pending_matches(self, locks, record): _fail('store_unavailable')
    def commit(self, locks, record): _fail('store_unavailable')
    def active_return(self, locks, record): _fail('store_unavailable')
    def finish(self, locks, record, normal_restored, deadline): _fail('store_unavailable')
    def authenticate_finish(self, locks, record, receipt, deadline): _fail('store_unavailable')
    def closed_locks(self, locks, deadline): _fail('store_unavailable')


class FinishReceipt(_Private):
    """Typed PRIVATE producer report, not an OS proof or mutation capability.

    The trusted Store must authenticate this exact issued object/epoch and its
    actual observations. store/locks/request_record/identity bind the request;
    construction and booleans alone cannot sign producer provenance.
    """
    __slots__ = ('store','locks','identity','request_record','record',
        'normal_restored','terminal_durable','marker_state','clear_durability',
        'resources_closed','resource_pending','complete')

    def __init__(self, store, locks, identity, request_record, record,
                 normal_restored, terminal_durable, marker_state,
                 clear_durability, resources_closed, resource_pending, complete):
        if not isinstance(store,ClientInitStore) or locks is None or type(identity) is not Identity or \
                any(value is not None and type(value) is not Journal for value in (request_record,record)) or \
                any(type(value) is not bool for value in (normal_restored,terminal_durable,
                    resources_closed,resource_pending,complete)) or \
                type(marker_state) is not str or marker_state not in ('retained_observed','absent_observed','unknown') or \
                type(clear_durability) is not str or clear_durability not in ('not_attempted','verified','unknown'):
            _fail('store_finish_unknown')
        for key,value in (('store',store),('locks',locks),('identity',identity),
                ('request_record',request_record),('record',record),
                ('normal_restored',normal_restored),('terminal_durable',terminal_durable),
                ('marker_state',marker_state),('clear_durability',clear_durability),
                ('resources_closed',resources_closed),('resource_pending',resource_pending),('complete',complete)):
            object.__setattr__(self,key,value)


def _same_journal(left,right):
    """Full logical equality INCLUDING task states omitted by Journal.key()."""
    if left is None or right is None: return left is right
    if type(left) is not Journal or type(right) is not Journal or left.key()!=right.key(): return False
    if tuple(a.tasks for a in left.baseline.stock_actors)!=tuple(a.tasks for a in right.baseline.stock_actors): return False
    return all((a is None and b is None) or (a is not None and b is not None and a.tasks==b.tasks)
        for a,b in ((left.controller,right.controller),(left.watchdog,right.watchdog)))


class ClientInitLease(object):
    """HOST ownership ordering. No actual provider or production admission."""
    def __init__(self, provider, store, identity, clock):
        if not isinstance(provider,ClientInitProvider): _fail('invalid_provider')
        if not isinstance(store,ClientInitStore): _fail('invalid_store')
        if type(identity) is not Identity or not callable(clock): _fail('invalid_identity')
        self.provider=provider; self.store=store; self.identity=identity; self.clock=clock
        self.record=None; self.locks=None; self.handles={}; self.last_time=None
        self.reason='not_recorded'; self.cleanup_complete=False; self.pending=True
        self.locks_uncertain=False
        self.sealed=False; self.finish_attempted=False; self.finish_receipt=None
        self.normal_restored=False; self.terminal_durable=False
        self.marker_state='unknown'; self.clear_durability='not_attempted'
        self.resource_pending=False

    def _now(self):
        try: value=_finite(self.clock(),'invalid_clock')
        except Exception: _fail('invalid_clock')
        if self.last_time is not None and value<self.last_time: _fail('invalid_clock')
        self.last_time=value
        return value

    def _budget(self,deadline,cancelled=None):
        if cancelled is not None:
            if not callable(cancelled): _fail('invalid_budget')
            value=cancelled()
            if type(value) is not bool: _fail('invalid_budget')
            if value: _fail('cancelled')
        if self._now()>=deadline: _fail('expired')

    def _locked(self):
        if self.locks is None or self.store.lock_valid(self.locks) is not True: _fail('invalid_locks')

    def _executor(self,deadline,starting=False,inherited=None):
        proof=self.provider.executor(deadline)
        if type(proof) is not ExecutorProof or proof.role=='watchdog' or \
                starting and proof.role!='owner': _fail('executor_role_forbidden')
        if proof.role=='external_finalizer' and (inherited is None or not proof.same_ofd_verified):
            _fail('external_finalizer_lock_unverified')
        if self.record is not None and any(actor is not None and
                (proof.actor.pid,proof.actor.start)==(actor.pid,actor.start)
                for actor in (self.record.controller,self.record.watchdog)):
            _fail('self_actor_recovery')
        return proof

    def _known_locks_before_acquire(self,deadline):
        if self.sealed:
            self._sealed_status(deadline)
            _fail(self.reason)
        if not self.locks_uncertain: return
        # READBACK ONLY: do not call acquire/finish/close on an unknown FD.
        proof=self.store.closed_locks(self.locks,deadline)
        if type(proof) is not CloseProof or proof.expected!=2 or not proof.complete():
            _fail('locks_close_unverified')
        self.locks=None; self.locks_uncertain=False

    def _active_return_lock(self):
        accepted=False
        try:
            proof=self.store.active_return(self.locks,self.record)
            if type(proof) is not CloseProof or proof.expected!=1 or not proof.complete():
                _fail('resource_close_unknown')
            accepted=True
        finally:
            # This runs for BaseException too. Interrupted close may have
            # consumed the FD: retain its exact reference and forbid retry.
            if not accepted:
                self.locks_uncertain=self.locks is not None
                self.cleanup_complete=False; self.pending=True
                self.reason='resource_close_unknown'
                self.resource_pending=True

    def _finish_receipt(self,record,normal_restored,deadline):
        accepted=False
        if self.finish_attempted or self.sealed: _fail('finish_sealed')
        if type(normal_restored) is not bool or record is not self.record or \
                record is not None and (type(record) is not Journal or record.identity.key()!=self.identity.key()) or \
                normal_restored and (record is None or record.ready or record.stage not in ('cleanup_verified','reconciled')):
            _fail('store_finish_unknown')
        # The caller's trusted owner/RLock serializes this once transition.
        # Retain the exact returned producer object BEFORE validation/callbacks.
        self.sealed=True; self.finish_attempted=True; self.normal_restored=normal_restored
        self.cleanup_complete=False; self.pending=True; self.resource_pending=True
        self.marker_state='unknown'; self.clear_durability='unknown'
        try:
            terminal=record.replace(stage='reconciled',ready=False) if normal_restored else record
            final=self.store.finish(self.locks,record,normal_restored,deadline)
            self.finish_receipt=final
            if type(final) is not FinishReceipt or final.store is not self.store or final.locks is not self.locks or \
                    final.request_record is not record or type(final.identity) is not Identity or \
                    final.identity.key()!=self.identity.key() or \
                    any(type(getattr(final,k)) is not bool for k in ('normal_restored','terminal_durable',
                        'resources_closed','resource_pending','complete')) or \
                    final.normal_restored!=normal_restored or \
                    type(final.marker_state) is not str or final.marker_state not in ('retained_observed','absent_observed','unknown') or \
                    type(final.clear_durability) is not str or final.clear_durability not in ('not_attempted','verified','unknown'):
                _fail('store_finish_unknown')
            if final.terminal_durable:
                if not normal_restored or not _same_journal(final.record,terminal): _fail('store_finish_unknown')
            elif not (_same_journal(final.record,record) or normal_restored and _same_journal(final.record,terminal)):
                _fail('store_finish_unknown')
            if final.clear_durability=='verified' and (not normal_restored or not final.terminal_durable or
                    final.marker_state!='absent_observed'): _fail('store_finish_unknown')
            if final.marker_state=='unknown' and final.clear_durability=='verified' or \
                    final.resources_closed==final.resource_pending:
                _fail('store_finish_unknown')
            expected_complete=bool(normal_restored and final.terminal_durable and
                final.marker_state=='absent_observed' and final.clear_durability=='verified' and
                final.resources_closed and not final.resource_pending)
            if final.complete!=expected_complete or \
                    self.store.authenticate_finish(self.locks,record,final,deadline) is not True:
                _fail('store_finish_unknown')
            accepted=True  # ENTIRE semantics + exact fixed producer/epoch proof.
            self.record=final.record; self.normal_restored=final.normal_restored
            self.terminal_durable=final.terminal_durable; self.marker_state=final.marker_state
            self.clear_durability=final.clear_durability; self.resource_pending=final.resource_pending
            self.cleanup_complete=final.complete; self.pending=not final.complete
            if final.resources_closed:
                self.locks=None; self.locks_uncertain=False
            else:
                self.locks_uncertain=self.locks is not None
            if normal_restored and not final.complete: self.reason='store_finish_incomplete'
            return final
        finally:
            if not accepted:
                self.locks_uncertain=self.locks is not None
                self.cleanup_complete=False; self.pending=True; self.resource_pending=True
                self.reason='store_finish_unknown'

    def _sealed_status(self,deadline):
        """Once finished, ONLY original lock readback; never reopen/reclose/RF.

        Two original lock observations do not erase an unknown whole-Store
        inventory or authenticate a failed finish receipt. Keep exact refs.
        """
        self.reason='finish_sealed'
        if self.locks_uncertain and self.locks is not None:
            try:
                proof=self.store.closed_locks(self.locks,deadline)
                if type(proof) is not CloseProof or proof.expected!=2 or not proof.complete():
                    _fail('locks_close_unverified')
            except Exception as error:
                self.reason=error.code if type(error) is ClientInitError else 'unexpected_provider_error'
        return self.status()

    def _fresh(self):
        self._locked()
        current=self.store.current(self.locks)
        if type(current) is not Journal or current.identity.key()!=self.identity.key() or \
                self.record is None or current.key()!=self.record.key() or \
                not self._pending_admission(current): _fail('stale_current')
        return current

    def _pending_admission(self,current):
        # Only a terminal current-role record may have already cleared pending.
        # This is admission to fresh checks, never a successful cached shortcut.
        return (self.store.pending_matches(self.locks,current) is True or
                current.stage=='reconciled' and self.store.pending_clear(self.locks) is True)

    def _save(self,record):
        if self.sealed: _fail('finish_sealed')
        self._locked()
        if type(record) is not Journal or record.identity.key()!=self.identity.key(): _fail('invalid_journal')
        # Do not overwrite a changed record after a provider callback, even
        # inside the lock scope. The real Store must additionally perform CAS.
        if self.record is not None: self._fresh()
        elif self.store.current(self.locks) is not None: _fail('current_blocked')
        result=self.store.commit(self.locks,record)
        if type(result) is not Journal or result.key()!=record.key(): _fail('durability_unknown')
        self.record=result
        if self.store.pending_matches(self.locks,result) is True: self.marker_state='retained_observed'

    def _baseline(self,deadline,owned=None):
        self._fresh(); self._budget(deadline)
        current=self.provider.snapshot(deadline)
        if type(current) is not Snapshot or current.key(owned)!=self.record.baseline.key(): _fail('baseline_changed')
        if self.provider.original_actors(self.record.baseline,deadline) is not True: _fail('actor_unknown')
        self._budget(deadline)
        return current

    def _handle(self,ticket,handle):
        if type(ticket) is not Ticket or ticket.boot!=self.record.baseline.boot or type(handle) is not Handle or \
                handle.ticket.key()!=ticket.key(): _fail('invalid_actor')
        self.handles[ticket.role]=handle
        return handle

    def _register(self,role,deadline):
        self._budget(deadline); self._fresh()
        ticket=self.provider.register(role,self.identity,self.record.baseline.boot,deadline)
        if type(ticket) is not Ticket or ticket.role!=role or ticket.boot!=self.record.baseline.boot: _fail('invalid_ticket')
        return ticket

    def start(self,ttl=20,cancelled=None):
        _finite(ttl,'invalid_budget')
        if not 0<ttl<=20: _fail('invalid_budget')
        deadline=self._now()+ttl
        if self.sealed: return self._sealed_status(deadline)
        active_return_attempted=False
        acquire_attempted=False
        try:
            self._budget(deadline,cancelled)
            self._known_locks_before_acquire(deadline)
            self._executor(deadline,starting=True)
            self._budget(deadline,cancelled)
            acquire_attempted=True
            self.locks=self.store.acquire(self.identity,deadline)
            self._locked()
            if self.store.current(self.locks) is not None: _fail('current_blocked')
            if self.store.pending_clear(self.locks) is not True: _fail('pending_blocked')
            self.marker_state='absent_observed'
            baseline=self.provider.snapshot(deadline)
            if type(baseline) is not Snapshot: _fail('invalid_snapshot')
            if self.store.prior_clear(self.locks,baseline,deadline) is not True: _fail('pending_blocked')
            client_combo(self.provider.caps(deadline),baseline)
            if self.provider.original_actors(baseline,deadline) is not True: _fail('actor_unknown')
            self._budget(deadline,cancelled)
            self._save(Journal(self.identity,'prepared',baseline,deadline))
            ticket=self._register('watchdog',deadline)
            self._save(self.record.replace(stage='watchdog_intent',watchdog_ticket=ticket))
            self._budget(deadline,cancelled); self._fresh()
            handle=self._handle(ticket,self.provider.launch_watchdog(ticket,self.record,self.locks,deadline))
            self._save(self.record.replace(stage='watchdog_saved',watchdog=handle.actor))
            self._budget(deadline,cancelled)
            if self.provider.release_exec(handle,deadline) is not True: _fail('exec_gate_failed')
            baseline=self._baseline(deadline)
            client_combo(self.provider.caps(deadline),baseline)
            self._budget(deadline,cancelled)
            interface_ticket=self.provider.register_interface(self.identity,self.record.baseline,deadline)
            if type(interface_ticket) is not InterfaceTicket or interface_ticket.boot!=self.record.baseline.boot or \
                    interface_ticket.phy!=self.record.baseline.station.phy: _fail('invalid_origin')
            self._save(self.record.replace(stage='interface_intent',interface_ticket=interface_ticket))
            self._budget(deadline,cancelled); self._fresh()
            owned=self.provider.create_client(interface_ticket,deadline)
            if type(owned) is not Origin or owned.iftype!=8 or owned.phy!=self.record.baseline.station.phy:
                _fail('invalid_origin')
            if owned.name!=interface_ticket.name: _fail('origin_changed')
            _name(owned.name,True)
            if any(r.name==owned.name or r.ifindex==owned.ifindex or r.wdev==owned.wdev
                   for r in self.record.baseline.interfaces): _fail('origin_changed')
            self._save(self.record.replace(stage='interface_owned',owned=owned))
            self._baseline(deadline,owned)
            ticket=self._register('controller',deadline)
            self._save(self.record.replace(stage='controller_intent',controller_ticket=ticket))
            self._budget(deadline,cancelled); self._fresh()
            handle=self._handle(ticket,self.provider.launch_controller(ticket,owned,CLIENT_CONFIG,deadline))
            # Save even a late returned actual child BEFORE checking its deadline.
            self._save(self.record.replace(stage='controller_saved',controller=handle.actor))
            self._budget(deadline,cancelled)
            if self.provider.release_exec(handle,deadline) is not True: _fail('exec_gate_failed')
            self._baseline(deadline,owned)
            if self.provider.origin_up(owned,deadline) is not True: _fail('origin_changed')
            for live in tuple(self.handles.values()):
                proof=self.provider.live_actor(live,deadline)
                if type(proof) is not Actor or proof.key()!=live.actor.key() or not proof.live(): _fail('actor_unknown')
            parse_init_status(self.provider.status(handle,owned,deadline))
            self._baseline(deadline,owned); self._budget(deadline,cancelled)
            self._save(self.record.replace(stage='client_init_ready',ready=True))
            active_return_attempted=True
            self._active_return_lock()
            self.reason='not_recorded'
            return self.status()
        except Exception as error:
            self.reason=error.code if type(error) is ClientInitError else 'unexpected_provider_error'
            # Keep the registered tickets/strong handles. Caller must separately
            # restore via a trusted external finalizer. Watchdog can request
            # recovery only; it cannot reap itself or report completion.
            # Do not keep the journal lock and block the external finalizer.
            try:
                if acquire_attempted and not self.locks_uncertain and self.locks is not None and self.record is not None:
                    if not active_return_attempted:
                        self._active_return_lock()
                elif acquire_attempted and not self.locks_uncertain and self.locks is not None:
                    self._finish_receipt(None,False,deadline)
            except Exception:
                self.pending=True
                if self.locks is not None: self.locks_uncertain=True
            return self.status()

    def restore(self,timeout=20,inherited=None):
        _finite(timeout,'invalid_budget')
        if not 0<timeout<=20: _fail('invalid_budget')
        deadline=self._now()+timeout
        if self.sealed: return self._sealed_status(deadline)
        complete=False
        resources_closed=False
        close_attempted=False
        # Reject self-watchdog recovery before any Store acquire or cleanup.
        # A failed role/unknown-lock admission must not enter the finally writer.
        try:
            self._known_locks_before_acquire(deadline)
            inherited=self.locks if inherited is None else inherited
            executor=self._executor(deadline,inherited=inherited)
        except Exception as error:
            self.reason=error.code if type(error) is ClientInitError else 'unexpected_provider_error'
            self.cleanup_complete=False; self.pending=True
            return self.status()
        self_recovery_rejected=False
        try:
            self.locks=self.store.acquire(self.identity,deadline,inherited)
            self._locked()
            # FIRST read current journal only AFTER both lock domains are held.
            current=self.store.current(self.locks)
            if type(current) is not Journal or current.identity.key()!=self.identity.key() or \
                    not self._pending_admission(current): _fail('current_blocked')
            self.record=current
            for actor in (current.controller,current.watchdog):
                if actor is not None and (executor.actor.pid,executor.actor.start)==(actor.pid,actor.start):
                    self_recovery_rejected=True
                    _fail('self_actor_recovery')
            already_reconciled=current.stage=='reconciled'
            if already_reconciled: close_attempted=True  # readonly closure proof, no repeat close
            if not already_reconciled: self._save(current.replace(stage='cleanup_intent',ready=False))
            # A reconciled record requires fresh absence and full unexcluded
            # baseline; it must not pretend the old netdev still exists.
            if already_reconciled and self.record.owned is not None:
                if self.provider.origin_absent(self.record.owned,deadline) is not True: _fail('origin_changed')
            self._baseline(deadline,None if already_reconciled else self.record.owned)
            for role,ticket,actor in (('controller',self.record.controller_ticket,self.record.controller),
                                      ('watchdog',self.record.watchdog_ticket,self.record.watchdog)):
                if ticket is None: continue
                handle=self.provider.resolve(ticket,deadline)
                if type(handle) is UnlaunchedProof:
                    if actor is not None or handle.ticket.key()!=ticket.key() or \
                            not handle.never_forked or not handle.resources_closed: _fail('actor_unknown')
                    continue
                if type(handle) is not Handle: _fail('actor_unknown')
                self._handle(ticket,handle)
                if actor is not None and handle.actor.key()!=actor.key(): _fail('actor_unknown')
                self._fresh(); self._budget(deadline)
                proof=(self.provider.exit_proof(handle,deadline) if already_reconciled else
                       self.provider.stop_and_reap(handle,deadline))
                if type(proof) is not ExitProof or not proof.gone(handle.actor): _fail('actor_reap_unknown')
                # Stop/reap is never inferred from empty cmdline, Z, or an Event.
            owned=self.record.owned
            self._baseline(deadline,None if already_reconciled else owned)
            if owned is not None and not already_reconciled:
                self._fresh(); self._budget(deadline)
                if self.provider.origin_up(owned,deadline) is not True: _fail('origin_changed')
                if self.provider.delete_client(owned,deadline) is not True: _fail('origin_changed')
                self._budget(deadline)
                if self.provider.origin_absent(owned,deadline) is not True: _fail('origin_changed')
            # Post-delete full baseline has no exclusion and no owned IP delta.
            self._baseline(deadline)
            close_attempted=True
            close=(self.provider.closed_resources(tuple(self.handles.values()),deadline) if already_reconciled else
                   self.provider.close_resources(tuple(self.handles.values()),deadline))
            if type(close) is not CloseProof or close.expected<len(self.handles) or not close.complete(): _fail('resource_close_unknown')
            resources_closed=True
            # A close callback is not proof that the last pre-close snapshot
            # remained equal. The sealed finisher may clear only after this.
            self._baseline(deadline)
            if not already_reconciled: self._save(self.record.replace(stage='cleanup_verified',ready=False))
            complete=True
        except Exception as error:
            self.reason=error.code if type(error) is ClientInitError else 'unexpected_provider_error'
        finally:
            if not close_attempted and not self_recovery_rejected:
                try:
                    close_attempted=True
                    close=self.provider.close_resources(tuple(self.handles.values()),deadline)
                    resources_closed=type(close) is CloseProof and close.complete()
                except Exception:
                    resources_closed=False
                complete=False
            # No repeat close after an uncertain callback: a reused descriptor
            # must never be mistaken for the original resource. The provider
            # must independently attempt EVERY registered resource in one call.
            # The sealed finisher reports marker and original resource closure
            # independently. Partial legal receipts remain truthful, not complete.
            try:
                if self_recovery_rejected: _fail('self_actor_recovery')
                self._finish_receipt(self.record,complete,deadline)
            except Exception:
                self.cleanup_complete=False; self.pending=True
                if not self_recovery_rejected: self.reason='store_finish_unknown'
            finally:
                # No caller may clear references after only seeing a true flag.
                # The complete validator alone commits resource release.
                if self.locks is not None:
                    self.locks_uncertain=True
        return self.status()

    def recover_current(self,timeout=20,inherited=None):
        # No pre-lock load and no old GoLease call. Strong registered resources
        # are resolved by the provider from the fresh private ticket record.
        return self.restore(timeout,inherited)

    def status(self):
        return {'evidence':'HOST_OWNER_CONTRACT_ONLY','stage':'new' if self.record is None else self.record.stage,
                'reason':self.reason,'client_init_ready':bool(self.record is not None and self.record.ready and
                    self.reason=='not_recorded' and not self.cleanup_complete and not self.locks_uncertain and not self.sealed),
                'cleanup_complete':self.cleanup_complete,'pending_retained':True if self.marker_state=='retained_observed' else
                    False if self.marker_state=='absent_observed' else None,
                'marker_state':self.marker_state,'clear_durability':self.clear_durability,
                'normal_restored':self.normal_restored,'terminal_durable':self.terminal_durable,
                'resource_pending':self.resource_pending or self.locks_uncertain,
                'cleanup_unresolved':self.pending,'finish_sealed':self.sealed,
                'locks_close_unverified':self.locks_uncertain,
                'rf_init_possible':True,'association_verified':False,'ip_ready':False,
                'dhcp_ready':False,'data_ready':False,'phone_tested':False,
                'receive_available':False,'send_available':False}
