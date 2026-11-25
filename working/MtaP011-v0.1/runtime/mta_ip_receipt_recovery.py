"""Pure private IPv4 receipt-delta inspection, NOT recovery authorization.

No socket, address write, journal change or actor/boot/interface proof lives
here. Only a caller-supplied full snapshot and already durable receipt are
compared. This narrowly separate inspector does not relax the fixed create or
ordinary restore helper's four-route requirement. Python 3.5.
"""
from collections import namedtuple
import mta_ip as core
import mta_ip_lease as helper


_ERROR_CODES = frozenset((
    'invalid_receipt', 'invalid_snapshot', 'baseline_contains_owned_interface',
    'receipt_address_missing', 'receipt_address_changed', 'owned_address_count',
    'unexpected_owned_route', 'original_baseline_changed'))


class ReceiptInspectionError(ValueError):
    """Fixed nonsecret code only; never format a private record or exception."""
    def __init__(self, code):
        if type(code) is not str or code not in _ERROR_CODES:
            code = 'invalid_snapshot'
        self.code = code
        ValueError.__init__(self, code)


def _reject(code):
    raise ReceiptInspectionError(code)


class ReceiptDeltaFacts(namedtuple('_ReceiptDeltaFacts',
                                  'state receipt_stage receipt_address '
                                  'remaining_owned_routes baseline_view')):
    """Immutable private facts. No field grants authority to perform a write."""
    __slots__ = ()

    def __repr__(self):
        return '<ReceiptDeltaFacts private inspection only>'

    __str__ = __repr__

    def status(self):
        """New fixed public summary; no address/interface/packet identifiers."""
        return {'evidence': 'supplied_ipv4_records_only',
                'state': self.state, 'receipt_stage': self.receipt_stage,
                'owned_address_present': self.receipt_address is not None,
                'owned_expected_routes_present': len(self.remaining_owned_routes),
                'owned_expected_routes_missing': 4 - len(self.remaining_owned_routes),
                'full_ipv4_baseline_equal_after_subtraction': True,
                'write_authorized': False, 'recovery_performed': False}


def _full_snapshot(value):
    """Reject mutable/unknown shapes, retain all cacheinfo and route fields."""
    if type(value) is not core.IpSnapshot or \
            any(type(rows) is not tuple for rows in (value.addresses, value.routes, value.rules)):
        _reject('invalid_snapshot')
    if any(len(rows) > core.MAX_DUMP_RECORDS for rows in (value.addresses, value.routes, value.rules)) or \
            any(type(row) is not core.AddressRecord for row in value.addresses) or \
            any(type(row) is not core.RouteRecord for row in value.routes) or \
            any(type(row) is not core.RuleRecord for row in value.rules):
        _reject('invalid_snapshot')
    for row in value.addresses:
        if any(type(v) is not int for v in row[:6]) or \
                (row.label is not None and (type(row.label) is not bytes or not 2 <= len(row.label) <= 16)) or \
                (row.broadcast is not None and type(row.broadcast) is not int) or \
                type(row.cacheinfo) is not tuple or len(row.cacheinfo) != 4 or \
                any(type(v) is not int for v in row.cacheinfo):
            _reject('invalid_snapshot')
    for row in value.routes:
        if any(type(v) is not int for v in row[:7]) or \
                any(v is not None and type(v) is not int for v in row[7:11]) or \
                type(row.metrics) is not tuple or len(row.metrics) > 15 or any(type(pair) is not tuple or
                    len(pair) != 2 or any(type(v) is not int for v in pair)
                    for pair in row.metrics):
            _reject('invalid_snapshot')
    if any(any(type(v) is not int for v in row) for row in value.rules):
        _reject('invalid_snapshot')
    try:
        # The old decoder checks bounds, duplicate rows, permanent/infinite
        # lifetimes, full route shape and exactly the supported default rules.
        return helper.snapshot_from_data(helper.snapshot_data(value))
    except (helper.IpLeaseError, core.IpCoreError, ValueError, TypeError,
            IndexError, AttributeError, OverflowError):
        _reject('invalid_snapshot')


def inspect_receipt_delta(current, original_baseline, record, owned):
    """Compare supplied full IPv4 records; perform no ownership/RF recovery.

    Only confirmed/delete_intent + receipt_fsynced=True is admissible.
    Actual same-boot current candidate/journal/pending, shared guard/lock,
    controller/actors gone, full interface origin/type/sysfs, safe IPv6 and
    non-IP original baseline are ALL outside this component. The executing
    caller must independently prove them and reread before each send/ACK.
    """
    if type(record) is not dict:
        _reject('invalid_receipt')
    receipt_stage = record.get('stage')
    if type(receipt_stage) is not str or receipt_stage not in ('confirmed', 'delete_intent'):
        _reject('invalid_receipt')
    try:
        spec, address = helper._validate_receipt(record, owned)
        expected = helper._expected_routes(spec)
    except (helper.IpLeaseError, core.IpCoreError, ValueError, TypeError,
            IndexError, AttributeError, OverflowError):
        _reject('invalid_receipt')
    before = _full_snapshot(original_baseline)
    now = _full_snapshot(current)
    if any(row.ifindex == spec.ifindex for row in before.addresses) or \
            any(row.oif == spec.ifindex for row in before.routes):
        _reject('baseline_contains_owned_interface')
    if helper.snapshot_data(now) == helper.snapshot_data(before):
        return ReceiptDeltaFacts('baseline_already_equal', receipt_stage, None, (), now)
    addresses = tuple(row for row in now.addresses if row.ifindex == spec.ifindex)
    routes = tuple(row for row in now.routes if row.oif == spec.ifindex)
    if not addresses:
        _reject('receipt_address_missing')
    if len(addresses) != 1:
        _reject('owned_address_count')
    if addresses[0] != address:
        _reject('receipt_address_changed')
    if len(routes) > 4 or len(set(routes)) != len(routes) or any(row not in expected for row in routes):
        _reject('unexpected_owned_route')
    remainder = core.IpSnapshot(
        tuple(row for row in now.addresses if row != address),
        tuple(row for row in now.routes if row not in routes), now.rules)
    if helper.snapshot_data(remainder) != helper.snapshot_data(before):
        _reject('original_baseline_changed')
    return ReceiptDeltaFacts('exact_receipt_delta', receipt_stage, address,
                            tuple(sorted(routes, key=lambda row: repr(tuple(row)))), remainder)
