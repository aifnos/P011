"""Strict P011 little-endian nl80211 WIPHY attribute projection decoder.

Pure Python 3.5: no I/O, sockets, JSON, mutation admission or kernel proof.
The future trusted transport must retain the complete raw split dump and
authenticate sequence/socket/peer/DONE before projecting the five attributes
below. Neither an attribute projection nor a caller boolean proves that.
Linux UAPI definitions are used as an interface specification; this is an
independent parser, not a copy of the native probe or kernel implementation.
"""

import struct
from collections import namedtuple


# Linux v4.14 UAPI; top-level IDs also match the pinned probe's --ids record.
WIPHY, SUPPORTED_IFTYPES, SUPPORTED_COMMANDS = 1, 32, 50
INTERFACE_COMBINATIONS, SOFTWARE_IFTYPES = 120, 121
COMB_LIMITS, COMB_MAXNUM, COMB_BEACON_MATCH, COMB_CHANNELS = 1, 2, 3, 4
COMB_RADAR_WIDTHS, COMB_RADAR_REGIONS, COMB_BI_MIN_GCD = 5, 6, 7
LIMIT_MAX, LIMIT_TYPES = 1, 2
NLA_F_NESTED, NLA_F_NET_BYTEORDER, NLA_TYPE_MASK = 0x8000, 0x4000, 0x3fff
MAX_BYTES, MAX_FRAGMENTS, MAX_PHYS = 262144, 64, 8
MAX_ATTRIBUTES, MAX_COMBINATIONS, MAX_LIMITS, MAX_COMMANDS = 4096, 16, 16, 256
_ATTR = struct.Struct('<HH')
_U32 = struct.Struct('<I')
_TOP = frozenset((WIPHY, SUPPORTED_IFTYPES, SUPPORTED_COMMANDS,
                  INTERFACE_COMBINATIONS, SOFTWARE_IFTYPES))
_COMB = frozenset(range(1, 8))

Limit = namedtuple('Limit', 'maximum types')
Combination = namedtuple('Combination',
    'maximum channels limits beacon_match_present beacon_match '
    'radar_widths_present radar_widths radar_regions_present radar_regions '
    'bi_min_gcd_present bi_min_gcd bi_policy')
Phy = namedtuple('Phy',
    'index iftypes_present iftypes software_iftypes_present software_iftypes '
    'combinations_present combinations commands_present commands')
DecodedCaps = namedtuple('DecodedCaps', 'phys')


class CapsDecodeError(ValueError):
    """Fixed error codes only; never echoes the raw input or identifiers."""
    def __init__(self, code):
        self.code = code
        ValueError.__init__(self, code)


def _fail(code):
    raise CapsDecodeError(code)


class _Budget(object):
    def __init__(self):
        self.attributes = 0

    def visit(self):
        self.attributes += 1
        if self.attributes > MAX_ATTRIBUTES:
            _fail('attribute_budget')


def _attributes(data, budget):
    offset = 0
    while offset < len(data):
        if len(data) - offset < 4:
            _fail('truncated_attribute')
        length, kind = _ATTR.unpack_from(data, offset)
        step = (length + 3) & ~3
        if length < 4 or length > len(data) - offset or step > len(data) - offset:
            _fail('truncated_attribute')
        if any(data[offset + length:offset + step]):
            _fail('nonzero_padding')
        budget.visit()
        yield kind & NLA_TYPE_MASK, kind & ~NLA_TYPE_MASK, data[offset + 4:offset + length]
        offset += step


def _nested(flags):
    # v4.14 nla_nest_start emits unflagged containers; both encodings are valid.
    if flags not in (0, NLA_F_NESTED):
        _fail('invalid_attribute_flags')


def _scalar(flags, payload, positive=False):
    if flags != 0:
        _fail('invalid_attribute_flags')
    if len(payload) != 4:
        _fail('invalid_u32')
    value = _U32.unpack(payload)[0]
    if positive and value == 0:
        _fail('invalid_positive_u32')
    return value


def _flag(flags, payload):
    if flags != 0:
        _fail('invalid_attribute_flags')
    if payload:
        _fail('invalid_flag_payload')
    return True


def _types(flags, payload, budget, nonempty=False):
    _nested(flags)
    values = []
    for kind, child_flags, value in _attributes(payload, budget):
        if not 1 <= kind <= 12:
            _fail('unknown_iftype')
        _flag(child_flags, value)
        if kind in values:
            _fail('duplicate_iftype')
        values.append(kind)
    if nonempty and not values:
        _fail('empty_iftypes')
    return tuple(sorted(values))


def _array(flags, payload, budget, maximum):
    _nested(flags)
    rows, seen = [], set()
    for index, child_flags, value in _attributes(payload, budget):
        if not 1 <= index <= maximum:
            _fail('array_budget_or_index')
        if index in seen:
            _fail('duplicate_array_index')
        seen.add(index)
        rows.append((index, child_flags, value))
        if len(rows) > maximum:
            _fail('array_budget_or_index')
    if seen != set(range(1, len(rows) + 1)):
        _fail('noncanonical_array_index')
    return tuple(sorted(rows))


def _limit(flags, payload, budget):
    _nested(flags)
    fields = {}
    for kind, child_flags, value in _attributes(payload, budget):
        if kind not in (LIMIT_MAX, LIMIT_TYPES):
            _fail('unknown_limit_constraint')
        if kind in fields:
            _fail('duplicate_limit_attribute')
        fields[kind] = (_scalar(child_flags, value, True) if kind == LIMIT_MAX else
                        _types(child_flags, value, budget, True))
    if set(fields) != {LIMIT_MAX, LIMIT_TYPES}:
        _fail('missing_limit_attribute')
    return Limit(fields[LIMIT_MAX], fields[LIMIT_TYPES])


def _combination(flags, payload, budget):
    _nested(flags)
    fields = {}
    for kind, child_flags, value in _attributes(payload, budget):
        if kind not in _COMB:
            _fail('unknown_combination_constraint')
        if kind in fields:
            _fail('duplicate_combination_attribute')
        if kind == COMB_LIMITS:
            limits = tuple(_limit(f, p, budget) for _, f, p in
                           _array(child_flags, value, budget, MAX_LIMITS))
            if not limits:
                _fail('empty_limits')
            covered = set()
            for limit in limits:
                if covered.intersection(limit.types):
                    _fail('overlapping_limit_types')
                covered.update(limit.types)
            fields[kind] = limits
        elif kind == COMB_BEACON_MATCH:
            fields[kind] = _flag(child_flags, value)
        else:
            fields[kind] = _scalar(child_flags, value,
                kind in (COMB_MAXNUM, COMB_CHANNELS, COMB_BI_MIN_GCD))
            if kind == COMB_RADAR_WIDTHS and fields[kind] & ~0xff:
                _fail('unknown_radar_width')
            if kind == COMB_RADAR_REGIONS and fields[kind] & ~0x0f:
                _fail('unknown_radar_region')
    if not {COMB_LIMITS, COMB_MAXNUM, COMB_CHANNELS}.issubset(fields):
        _fail('missing_combination_attribute')
    return Combination(fields[COMB_MAXNUM], fields[COMB_CHANNELS], fields[COMB_LIMITS],
        COMB_BEACON_MATCH in fields, fields.get(COMB_BEACON_MATCH, False),
        COMB_RADAR_WIDTHS in fields, fields.get(COMB_RADAR_WIDTHS),
        COMB_RADAR_REGIONS in fields, fields.get(COMB_RADAR_REGIONS),
        COMB_BI_MIN_GCD in fields, fields.get(COMB_BI_MIN_GCD),
        'minimum_gcd' if COMB_BI_MIN_GCD in fields else 'all_beacons_identical')


def _commands(flags, payload, budget):
    values = tuple(_scalar(f, p, True) for _, f, p in
                   _array(flags, payload, budget, MAX_COMMANDS))
    if len(set(values)) != len(values):
        _fail('duplicate_command')
    return tuple(sorted(values))


def decode_wiphy_projection(fragments):
    """Decode an exact tuple of projected attribute streams, not NL messages.

    Every fragment must contain one WIPHY index. Repeated identity is legal;
    other projected singleton fields cannot repeat, even in another fragment.
    No argument can assert complete/split/kernel provenance.
    """
    if type(fragments) is not tuple or not 1 <= len(fragments) <= MAX_FRAGMENTS:
        _fail('invalid_fragments')
    total = 0
    for fragment in fragments:
        if type(fragment) is not bytes or not 4 <= len(fragment) <= MAX_BYTES:
            _fail('invalid_fragment')
        total += len(fragment)
        if total > MAX_BYTES:
            _fail('byte_budget')
    budget, phys = _Budget(), {}
    for fragment in fragments:
        fields = {}
        for kind, flags, value in _attributes(fragment, budget):
            if kind not in _TOP:
                _fail('unknown_projected_attribute')
            if kind in fields:
                _fail('duplicate_phy_attribute')
            if kind == WIPHY:
                fields[kind] = _scalar(flags, value)
            elif kind in (SUPPORTED_IFTYPES, SOFTWARE_IFTYPES):
                fields[kind] = _types(flags, value, budget, kind == SUPPORTED_IFTYPES)
            elif kind == SUPPORTED_COMMANDS:
                fields[kind] = _commands(flags, value, budget)
            else:
                combinations = tuple(_combination(f, p, budget) for _, f, p in
                    _array(flags, value, budget, MAX_COMBINATIONS))
                if len(set(combinations)) != len(combinations):
                    _fail('duplicate_combination')
                fields[kind] = combinations
        if WIPHY not in fields:
            _fail('missing_wiphy')
        index = fields.pop(WIPHY)
        if index not in phys:
            if len(phys) >= MAX_PHYS:
                _fail('phy_budget')
            phys[index] = {}
        if set(phys[index]).intersection(fields):
            _fail('duplicate_phy_attribute')
        phys[index].update(fields)
    result = []
    for index in sorted(phys):
        fields = phys[index]
        iftypes = fields.get(SUPPORTED_IFTYPES, ())
        software = fields.get(SOFTWARE_IFTYPES, ())
        combinations = fields.get(INTERFACE_COMBINATIONS, ())
        if SUPPORTED_IFTYPES in fields:
            if not set(software).issubset(iftypes) or any(
                    not set(limit.types).issubset(iftypes)
                    for combo in combinations for limit in combo.limits):
                _fail('unadvertised_iftype')
        result.append(Phy(index, SUPPORTED_IFTYPES in fields, iftypes,
            SOFTWARE_IFTYPES in fields, software, INTERFACE_COMBINATIONS in fields,
            combinations, SUPPORTED_COMMANDS in fields, fields.get(SUPPORTED_COMMANDS, ())))
    return DecodedCaps(tuple(result))


def decoded_client_schema(fragments):
    """Return {'phys': tuple} only when current CLIENT schema loses no limit.

    Deliberately has no 'complete' field and no mutation/transport proof. Missing
    radar attributes remain unknown. The old core lacks BI_MIN_GCD: only an
    explicit value 1 is representable (every positive BI GCD is at least 1).
    Default identical-BI or a larger threshold must not be silently discarded.
    Software/radar/beacon values are preserved; the core may reject them later.
    """
    decoded = decode_wiphy_projection(fragments)
    phys = []
    for phy in decoded.phys:
        if not phy.iftypes_present or not phy.software_iftypes_present or \
                not phy.combinations_present or not phy.combinations:
            _fail('incomplete_decoded_schema')
        combinations = []
        for combo in phy.combinations:
            if not combo.radar_widths_present or not combo.radar_regions_present:
                _fail('unrepresented_radar_absence')
            if not combo.bi_min_gcd_present or combo.bi_min_gcd != 1:
                _fail('unrepresented_bi_constraint')
            combinations.append({'max_interfaces': combo.maximum,
                'num_channels': combo.channels,
                'limits': tuple({'max': row.maximum, 'types': row.types} for row in combo.limits),
                'radar_widths': combo.radar_widths, 'radar_regions': combo.radar_regions,
                'beacon_match': combo.beacon_match})
        phys.append({'index': phy.index, 'iftypes': phy.iftypes,
            'software_iftypes': phy.software_iftypes, 'combinations': tuple(combinations),
            'unknown_constraints': ()})
    return {'phys': tuple(phys)}
