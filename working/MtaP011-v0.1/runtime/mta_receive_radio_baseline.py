"""Strict comparison of native read-only Bluetooth observations.

This module performs no IO and grants no receive, mutation or restoration
authority. State must obtain both observations from its actual helper, close
the original probe actors and separately prove its operation/Parent closure.
Object paths and the unique bus name are private: never export raw observations
in public result archives. Python 3.5 compatible, no stdlib json dependency.
"""
import re


SCHEMA = 'p011-bluez-radio-baseline-v1'
_OWNER = re.compile(r'^:[0-9]+\.[0-9]+$')
_PEER = re.compile(r'^/org/bluez/hci0/dev_[0-9A-Fa-f]{2}(?:_[0-9A-Fa-f]{2}){5}$')
_BOOL_FIELDS = ('powered', 'bredr_enabled', 'le_enabled', 'global_advertising',
                'bluez_advertising_active', 'connectable_advert',
                'discovering', 'discoverable', 'pairable')
_KNOWN_FIELDS = ('mgmt_info', 'features', 'bluez_advertising_known',
                 'adapter_properties_known', 'connected_devices_known')
_BYTE_FIELDS = ('max_adv', 'max_scan', 'max_instances', 'active_instances')


class RadioObservationError(ValueError):
    def __init__(self, code):
        self.code = code
        ValueError.__init__(self, code)


def _fail(code):
    raise RadioObservationError(code)


def _integer(value, minimum, maximum):
    return type(value) is int and minimum <= value <= maximum


def normalize(observation):
    """Validate actual DATA, returning a private immutable comparison tuple.

    In particular, two missing fields cannot match, unknown != empty, boolean
    values are not numbers, and a count is not an advertisement identity set.
    This tuple is DATA only, not a hardware or ownership certificate.
    """
    if (type(observation) is not dict or observation.get('event') != 'capabilities' or
            observation.get('radio_schema') != SCHEMA):
        _fail('radio_schema')
    if any(observation.get(name) is not True for name in _KNOWN_FIELDS):
        _fail('radio_unknown')
    if any(type(observation.get(name)) is not bool for name in _BOOL_FIELDS):
        _fail('radio_fields')
    if any(not _integer(observation.get(name), 0, 255) for name in _BYTE_FIELDS):
        _fail('radio_fields')
    settings = observation.get('current_settings')
    owner = observation.get('bluez_owner')
    if (not _integer(settings, 0, 0xffffffff) or type(owner) is not str or
            len(owner) > 64 or _OWNER.fullmatch(owner) is None):
        _fail('radio_fields')
    for name, bit in (('powered', 0), ('bredr_enabled', 7),
                      ('le_enabled', 9), ('global_advertising', 10)):
        if observation[name] is not bool(settings & (1 << bit)):
            _fail('radio_inconsistent')
    instances = observation.get('active_instance_ids')
    if (type(instances) is not list or len(instances) > 255 or
            any(not _integer(value, 1, 255) for value in instances) or
            len(set(instances)) != len(instances) or
            len(instances) != observation['active_instances'] or
            observation['max_instances'] > 254 or
            len(instances) > observation['max_instances'] or
            any(value > observation['max_instances'] for value in instances)):
        _fail('radio_instances')
    peers = observation.get('connected_devices')
    if (type(peers) is not list or len(peers) > 256 or
            any(type(path) is not str or len(path) > 96 or
                _PEER.fullmatch(path) is None for path in peers) or
            len(set(peers)) != len(peers)):
        _fail('radio_peers')
    return (SCHEMA, owner, settings,
            tuple(observation[name] for name in _BOOL_FIELDS),
            tuple(observation[name] for name in _BYTE_FIELDS),
            tuple(sorted(instances)), tuple(sorted(peers)))


def matches(before, after):
    """Strict comparison; malformed/unknown DATA never passes restoration."""
    try:
        return normalize(before) == normalize(after)
    except RadioObservationError:
        return False
