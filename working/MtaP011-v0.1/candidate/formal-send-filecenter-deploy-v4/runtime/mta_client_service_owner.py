"""Independent sender/FileCenter SOURCE composition; derived from formal-send-v1 once-owned fixed service SOURCE.

Default main does no IO. Explicit trusted send_trial_requested performs actual
source/helper/asset readback and one readonly Parent collection before binding
the once-owned preparation trial. This is NOT Native/RF success; unchanged F93
must perform its actual fresh baseline/reservation/native startup. The actual
State GO worker, not this outer Owner, produces the original terminal composite
restoration proof. Close only consumes actual retained original closure and
never resets caps, claims, pending records, sources, keys or Client history.
This SOURCE candidate has not been staged or run. One send per service process.
"""
import builtins
import errno
import hashlib
import math
import os
import socket
import stat
import sys
import threading
import time
import types

ROOT = '/tmp/p011-mta-formal-send-filecenter-deploy-v4'
USER_ROOT = '/mnt/data/p011-toolbox/user'
BLUEZ = ROOT + '/native/mta-bluez-helper'
NETWORK = ROOT + '/native/mta-network-helper'
BOOT_PATH = ROOT + '/runtime/mta_client_receive_boot.py'
BOOT_PIN = (19583, '4aeffe569138a8f364b377f746a9e80f29cb246e514dd103f3753eca65120a6e')
BOOT_SCHEMA = 'p011-formal-send-v1-source'
BOOT_MODULES = (
    'mta_client_executor', 'p011_json', 'mta_protocol', 'mta_storage',
    'mta_files', 'mta_crypto', 'mta_transfer_session', 'mta_dhcp',
    'mta_dhcp_server', 'mta_scoped_sockets', 'mta_transport', 'mta_sender',
    'mta_send_worker', 'mta_scan_handoff', 'mta_wifi', 'minhttp',
    'mta_client_control_frame', 'mta_client_connect_handoff', 'mta_client_tmp_alias',
    'mta_client_receive_factory', 'mta_client_state_bridge', 'mta_go_deployment',
    'mta_send_preparation', 'mta_go_readonly_parent', 'mta_go_send_publication',
    'mta_go_send_bridge', 'mta_go_readonly_terminal_parent',
    'mta_receive_radio_baseline', 'mta_receive_network', 'mta_send_trial',
    'mta_send_terminal_consumer', 'mta_service')
GO_ASSET_RUNTIME = '/var/volatile/tmp/p011-mta-go-send-filecenter-v3-assets/runtime'
HELPER_PINS = ((74920, 'c06398ddae281cf4a6f8a41953baf84795992f8f3e3769baebaf11f6d9964181'),
               (47464, 'ef3b904ef1017b6f0011b1e2cfcadbc98f9e8026933153ff0291699f32c525e6'))
CONNMAN = ROOT + '/mta-connman-observer'
CONNMAN_PIN = (46008, '5f2612224a3db35d8f0850adf10d1fece7094bff6387521c185570c4be8068e2')
FIXED_ASSET_PINS = (
    ("/var/volatile/tmp/p011-mta-go-send-filecenter-v3-assets/runtime/p011_json.py", 8061, 'fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88', 0o400),
    ("/var/volatile/tmp/p011-mta-go-send-filecenter-v3-assets/runtime/mta_ip.py", 22049, '1fa5e72817772285fd966f52c57af105950ff0d3b6ea49b202983aebfbab40c5', 0o400),
    ("/var/volatile/tmp/p011-mta-go-send-filecenter-v3-assets/runtime/mta_client_tmp_alias.py", 8827, '1a4a52bd0bae7add6ae42f66bd9827c43865a0170c666eaab00797d1f45f7f2f', 0o400),
    ("/var/volatile/tmp/p011-mta-go-send-filecenter-v3-assets/runtime/mta_p2p_client_init.py", 69966, '178bd8a491e9e5ec03e8da3bce780f8e8e8c1c8781bfeaca7d8c3bac59fa364b', 0o400),
    ("/var/volatile/tmp/p011-mta-go-send-filecenter-v3-assets/runtime/mta_snapshot_data.py", 17217, 'cb5e8f16c78cc4c879a8986dd9c2ab8ed5e6c055f105baad3ce60eb9a10d2a26', 0o400),
    ("/var/volatile/tmp/p011-mta-go-send-filecenter-v3-assets/runtime/mta_client_resource_budget.py", 16215, '56d6dbe2370279b1572a563e67fd3313bf942c0baa78fbd8e36cd973ba09839e', 0o400),
    ("/var/volatile/tmp/p011-mta-go-send-filecenter-v3-assets/runtime/mta_client_proc.py", 39384, 'ede5953c33ba4c17d3aecb1fffe8a9358589497b37e3109034d5e1de3eadb3d6', 0o400),
    ("/var/volatile/tmp/p011-mta-go-send-filecenter-v3-assets/runtime/mta_client_journal_codec.py", 17450, '2ffeca6b59498c9e2dfa4b9906bbe55db909d5d5e1d448fa0c795490996fe14a', 0o400),
    ("/var/volatile/tmp/p011-mta-go-send-filecenter-v3-assets/runtime/mta_client_coordination.py", 35591, '930e56d35ebf08d0b1c83fe7ccab843cbe6520ecd68c0799e9a07b2bbe40823f', 0o400),
    ("/var/volatile/tmp/p011-mta-go-send-filecenter-v3-assets/runtime/mta_client_files.py", 28938, '30c07bb4a5a28ce02aa76f35650ee1c87af63617f445e554c3fd7f73a2705864', 0o400),
    ("/var/volatile/tmp/p011-mta-go-send-filecenter-v3-assets/runtime/mta_client_pending.py", 42432, 'cfba740700268d5998eb3a91bf7cdc34d893fa8f0083377d716ea98950c3f5af', 0o400),
    ("/var/volatile/tmp/p011-mta-go-send-filecenter-v3-assets/runtime/mta_client_store.py", 71524, 'f328dcaa95ecfc5288c85a3715ecfdbdbdb8e83c83797b91cde3e334d188f4a2', 0o400),
    ("/var/volatile/tmp/p011-mta-go-send-filecenter-v3-assets/runtime/mta_go_process_owner.py", 42612, '78a480728a348e98e578acf4e7c778be50bfae3411ba5d34bb563493e1ba6583', 0o400),
    ("/var/volatile/tmp/p011-mta-go-send-filecenter-v3-assets/runtime/mta_go_deployment.py", 26543, 'e8dc91c0a44a48d6cecf066257e79185fe590385f98300d01835edddb8114efe', 0o400),
    ("/var/volatile/tmp/p011-mta-go-send-filecenter-v3-assets/runtime/mta_go_executor.py", 62728, 'f33ad96651e8aed38adab1ca931da6de7455130b8dbcedd774e1038ee39c8ed0', 0o400),
    ("/var/volatile/tmp/p011-mta-go-send-filecenter-v3-assets/runtime/mta_ip_lease.py", 18704, '39373dba355557ee73cfac354bdbaa95eaf0ddde4e27313450edf0e74742f12c', 0o400),
    ("/var/volatile/tmp/p011-mta-go-send-filecenter-v3-assets/runtime/mta_dhcp.py", 15719, '631987bd7307580af069f1978e440d21fbd449ecc62c83e0e06195c330f50176', 0o400),
    ("/var/volatile/tmp/p011-mta-go-send-filecenter-v3-assets/runtime/mta_go_bootstrap_store.py", 78430, '24620844c7d24f4777114ba9bfb4ea292ded2020a281681dd8e71fe07c7a4eae', 0o400),
    ("/var/volatile/tmp/p011-mta-go-send-filecenter-v3-assets/runtime/mta_go_dhcp.py", 21997, '3f7dbab30c8925cf0ea288a1e011787d436c07d3a8178a8a45934db3597f9312', 0o400),
    ("/var/volatile/tmp/p011-mta-go-send-filecenter-v3-assets/runtime/mta_go_native.py", 200317, 'ee46d8313fe31cbc5a0d16d0d14aff7ce2b3fb507f3cdac572e59bc5f16dfa9f', 0o400),
    ("/var/volatile/tmp/p011-mta-go-send-filecenter-v3-assets/runtime/mta_go_bootstrap.py", 31964, '93bc97ccb9d83d5727c2f528f0a2934f09d8cae093591821a9bf5ad60f425697', 0o400),
    ("/var/volatile/tmp/p011-mta-go-send-filecenter-v3-assets/runtime/mta_protocol.py", 17958, '4f7c2bd46cde114f0a2a0c33b31631aa463f09e71b156d26e34daf2251dd8a57', 0o400),
    ("/var/volatile/tmp/p011-mta-go-send-filecenter-v3-assets/runtime/mta_transport.py", 31883, '29e5ea6bf8f5de9ddae33824c158f4e401bab391d51b18dc0b8a1ab2cbc2dc72', 0o400),
    ("/var/volatile/tmp/p011-mta-go-send-filecenter-v3-assets/runtime/mta_sender_pump.py", 33455, '81c3d7ff98ab71cde2ac2858daaffd267f129033b28ebde1dbd2f13f19ff447c', 0o400),
    ("/var/volatile/tmp/p011-mta-go-send-filecenter-v3-assets/runtime/mta_go_send_bridge.py", 87625, '027be64bf7b1b4f6ae57d09921b821e4cc77db44c602b9a5d99d901ed5736f02', 0o400),
    ("/var/volatile/tmp/p011-mta-go-observer-libc-v1/runtime/p011_json.py", 8061, 'fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88', 0o400),
    ("/var/volatile/tmp/p011-mta-go-observer-libc-v1/runtime/mta_ip.py", 22049, '1fa5e72817772285fd966f52c57af105950ff0d3b6ea49b202983aebfbab40c5', 0o400),
    ("/var/volatile/tmp/p011-mta-go-observer-libc-v1/runtime/mta_client_tmp_alias.py", 8827, '1a4a52bd0bae7add6ae42f66bd9827c43865a0170c666eaab00797d1f45f7f2f', 0o400),
    ("/var/volatile/tmp/p011-mta-go-observer-libc-v1/runtime/mta_p2p_client_init.py", 71315, 'd3b51493d3ae778aeb72c1304dc50e5a6221428f7775bc7a28d15a3f19abeaaa', 0o400),
    ("/var/volatile/tmp/p011-mta-go-observer-libc-v1/runtime/mta_client_resource_budget.py", 16215, '56d6dbe2370279b1572a563e67fd3313bf942c0baa78fbd8e36cd973ba09839e', 0o400),
    ("/var/volatile/tmp/p011-mta-go-observer-libc-v1/runtime/mta_client_proc.py", 39384, 'ede5953c33ba4c17d3aecb1fffe8a9358589497b37e3109034d5e1de3eadb3d6', 0o400),
    ("/var/volatile/tmp/p011-mta-go-observer-libc-v1/runtime/mta_client_caps.py", 11821, 'c1792c2294fed5da16ec4a676423fbcbe53d44e9bc4ddadc1bc26fd45afe046c', 0o400),
    ("/var/volatile/tmp/p011-mta-go-observer-libc-v1/runtime/mta_client_caps_transport.py", 19614, 'df6b4cf3ede6039c684c6b689a8b61ffe1ba5b87259bb4a5581aa5c3ece84420', 0o400),
    ("/var/volatile/tmp/p011-mta-go-observer-libc-v1/runtime/mta_client_baseline.py", 31338, 'e950877bd99ee7907c66ee237e3140960ac8e4d64f979310b82bfdab2fa271ea', 0o400),
    ("/var/volatile/tmp/p011-mta-go-observer-libc-v1/runtime/mta_client_journal_codec.py", 17450, '2ffeca6b59498c9e2dfa4b9906bbe55db909d5d5e1d448fa0c795490996fe14a', 0o400),
    ("/var/volatile/tmp/p011-mta-go-observer-libc-v1/runtime/mta_client_coordination.py", 36295, '5b8a4295a5479cb5693182085fc8d35c6041bb0f14d9efb660ec11f024a5eeb3', 0o400),
    ("/var/volatile/tmp/p011-mta-go-observer-libc-v1/runtime/mta_client_files.py", 28938, '30c07bb4a5a28ce02aa76f35650ee1c87af63617f445e554c3fd7f73a2705864', 0o400),
    ("/var/volatile/tmp/p011-mta-go-observer-libc-v1/runtime/mta_client_pending.py", 53132, 'deaf62f9830b951584b36100de0f88548bcd6356b7327c3be0fa8578b65aba8a', 0o400),
    ("/var/volatile/tmp/p011-mta-go-observer-libc-v1/runtime/mta_client_store.py", 74676, 'bc51d3c64d3c92a87da331c740d93cea7466c535c5a81969422a45b8c5b68f63', 0o400),
    ("/var/volatile/tmp/p011-mta-go-observer-libc-v1/runtime/mta_client_process_owner.py", 34361, 'c144bc197a8fd1d4fbbfc358ba0172a84f5c9070058732189e4709c8c801ffeb', 0o400),
    ("/var/volatile/tmp/p011-mta-go-observer-libc-v1/runtime/mta_client_launch_registration.py", 21679, '833d46f5717e0b7e9db0c5392a0eb93d812d039b4b946a57d49d5903534a1aa0', 0o400),
    ("/var/volatile/tmp/p011-mta-go-observer-libc-v1/runtime/mta_client_two_phase_lease.py", 27606, 'c227989ec5188c272ad0a212974d569572704d3bb07c4c61c72670abcd0981a5', 0o400),
    ("/var/volatile/tmp/p011-mta-go-observer-libc-v1/runtime/mta_p2p_client_ctrl.py", 18712, '793b784f1b39eca18001aa65a1f0d6cdbd6de466dc58b3cf2ada167f71d902b5', 0o400),
    ("/var/volatile/tmp/p011-mta-go-observer-libc-v1/runtime/mta_client_wpa_status.py", 39133, '47074a5af8d9f75746fa7cd72e1e42b50c8402fcbb612963f6523c875fe1c269', 0o400),
    ("/var/volatile/tmp/p011-mta-go-observer-libc-v1/runtime/mta_protocol.py", 17958, '4f7c2bd46cde114f0a2a0c33b31631aa463f09e71b156d26e34daf2251dd8a57', 0o400),
    ("/var/volatile/tmp/p011-mta-go-observer-libc-v1/runtime/mta_client_control_frame.py", 20942, 'd1a8fce91ab705524f14edac8d81e8d391c0cddbf8f4ac96ee7a6446c0512278', 0o400),
    ("/var/volatile/tmp/p011-mta-go-observer-libc-v1/runtime/mta_client_kernel_proof.py", 23702, '4ebfedf198673e3bad2f64a4bd72c581e5d6af24cef83e589b4456d2a38f8ede', 0o400),
    ("/var/volatile/tmp/p011-mta-go-observer-libc-v1/runtime/mta_client_connection.py", 22494, 'ae2932252bbef16b89e6bf4614c2ebdb1721d507274dbd9b9fe4d9db1d0ff159', 0o400),
    ("/var/volatile/tmp/p011-mta-go-observer-libc-v1/runtime/mta_client_linux_provider.py", 174220, '5f080f8a0d53d7232ec95c303e0e84036d22d4e0927ac98dd3195291cf6d56ba', 0o400),
    ("/var/volatile/tmp/p011-mta-go-observer-libc-v1/runtime/mta_client_executor.py", 105182, 'f3f7c9fb54e46f82b4321152dfac6f4ab9b037943c403d76716f8254700bb17e', 0o400),
    ("/var/volatile/tmp/p011-mta-go-observer-libc-v1/runtime/mta_dhcp.py", 15719, '631987bd7307580af069f1978e440d21fbd449ecc62c83e0e06195c330f50176', 0o400),
    ("/var/volatile/tmp/p011-mta-go-observer-libc-v1/runtime/mta_dhcp_client_core.py", 12362, '13c03d181139fd9ead7ff3bf2bcbb4930669f1e795b17360da85834dc345e9fa', 0o400),
    ("/var/volatile/tmp/p011-mta-go-observer-libc-v1/runtime/mta_dhcp_client.py", 24670, '794421678866d04a10ca46fa9eb7e17174f24c4d9e705cf59016b457702003a0', 0o400),
    ("/var/volatile/tmp/p011-mta-go-observer-libc-v1/runtime/mta_client_dora.py", 48149, 'f17f8405b28799fda8ee8f3ea9d280f871cceb1e0c6b999fc855bcb652ab2f7e', 0o400),
    ("/var/volatile/tmp/p011-mta-go-observer-libc-v1/runtime/mta_client_dynamic_ip.py", 32427, '01476613eb965a05cd5441dfbfea53f15ce763da12213b76791ecdb23152199a', 0o400),
    ("/var/volatile/tmp/p011-mta-go-observer-libc-v1/runtime/mta_client_peer.py", 31242, 'f8a15d046b505a8c5117a5be19d2ee59f38096759be1b29a0310535ceea08ec9', 0o400),
    ("/var/volatile/tmp/p011-mta-go-observer-libc-v1/runtime/mta_scoped_sockets.py", 26339, 'b95cfbe724b43baf90511c9d2a4a39d869a40a57e78e2a87d398ea134f9f84b8', 0o400),
    ("/var/volatile/tmp/p011-mta-go-observer-libc-v1/runtime/mta_storage.py", 14335, '3c5c5f65ef0c8eb9a0256a99f931faff40558484bb908e89acee1c1c0aa3b4d6', 0o400),
    ("/var/volatile/tmp/p011-mta-go-observer-libc-v1/runtime/mta_transport.py", 35209, '77d9cd45936318315cf3343ab1bd2594c6a3381e33a7d0fdcfd853916063eefa', 0o400),
    ("/var/volatile/tmp/p011-mta-go-observer-libc-v1/runtime/mta_client_transfer.py", 30747, '8633b2a1156c3012ec613e776eaee7e9339c14c76cffff9c8e5ff75646f35184', 0o400),
    ("/var/volatile/tmp/p011-mta-go-observer-libc-v1/runtime/mta_client_readonly_baseline.py", 13934, 'c2052c39fdad148d25f83743476b95a51a88e7f9e16ec2235c91d4de6adc9aad', 0o400),
    ("/var/volatile/tmp/p011-mta-go-observer-libc-v1/runtime/mta_snapshot_data.py", 17217, 'cb5e8f16c78cc4c879a8986dd9c2ab8ed5e6c055f105baad3ce60eb9a10d2a26', 0o400),
    ("/var/volatile/tmp/p011-mta-go-observer-libc-v1/runtime/mta_go_readonly_preflight.py", 64948, '802ad7c3b80ea6e9ea4678a4112bd2ec95be08cff5fe6684e1162f127ae55f44', 0o400),
    ("/var/volatile/tmp/p011-mta-go-observer-libc-v1/runtime/mta_go_readonly_loader.py", 36543, '8e60e8f86a0cd4a261ca65f657739e9189137cf37dc04f4af1495263ce1b8e56', 0o400),
    ("/var/volatile/tmp/p011-mta-go-observer-libc-v1/runtime/mta_observer_packet.py", 48253, '004ff5616924a4529ce3a3f710ac83a8d2dedbd55ae2edb790998a68f68fe40f', 0o400),
    ("/var/volatile/tmp/p011-mta-go-observer-libc-v1/runtime/mta_go_readonly_entry.py", 45310, 'b97328b01617ce1944d3576bb4c0e22160414120c737b336e2509004d0031ffa', 0o400),
    ("/var/volatile/tmp/p011-mta-go-send-filecenter-v3-assets/source-manifest.json", 3677, 'be67d8cec589b4e54235d8205660a67f02a188f23e99251bf2219b35b147f3d5', 0o400),
    ("/var/volatile/tmp/p011-mta-go-send-filecenter-v3-assets/native/mta-wpa-supplicant", 1351192, 'e069aef76a089215367f502015266e9ce59cf4ebb7d7246974815ff60d67f301', 0o500),
)
MAX_REQUESTS = 4096
CLEANUP_SECONDS = 60.0
_MAIN = None


class ServiceOwnerError(ValueError):
    def __init__(self, code):
        self.code = code
        ValueError.__init__(self, code)


def _fail(code): raise ServiceOwnerError(code) from None


def _finite(value):
    return type(value) in (int, float) and 0 <= value < 1e12 and math.isfinite(float(value))


def _meta(value):
    result = tuple(getattr(value, key, None) for key in
                   ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size'))
    if any(type(v) is not int or not 0 <= v < (1 << 64) for v in result): _fail('metadata_unknown')
    return result


# Independent fixed deployment inventory. No old ordinary root is overwritten;
# its files-only stage rejects partial or different existing inventories.
# No FileCenter credentials or guardian ACK producer is provided here.
FILECENTER_MAX_SOURCE = 131072
FILECENTER_PINS = (
    ('mta_toolbox_json', 3069, 'e32cf4433b966714a16e725e405052fa905715ce108b80199f8d50904abe5c7c'),
    ('mta_toolbox_minhttp', 9303, '6f8ec322fe8bb9522b9cc5ab1b52d844c17d366eaf7e176634b5760089bc3f93'),
    ('mta_toolbox_storage', 9114, 'd9fa92a795729d88f6fac27705a2883adba8aac72423b4ebcd9220ffb78ddb51'),
    ('mta_toolbox_metrics', 4080, 'e56808ec3bc7c751e5dff43a053294595bb719cad658a44eb378932142b7a679'),
    ('mta_toolbox_audio', 9045, 'c4ea432c8c6e972a28134f352fa75ff773827fd4a41e205865c9309f96a63432'),
    ('mta_toolbox_server', 19732, 'fab0c1afa6fc85a30de711b4f4d94467e03911e836ce292b73e8796ead8a9bc6'),
    ('mta_filecenter_audio', 15082, '898e5373f6ec4789eaf756ffd01731646bcafb7b0f35019731403a2e881147af'),
    ('mta_filecenter_storage', 4581, '19013d117ffc041d7be0f6f1101a65ef9acfba45ffe7bb815264f596556cf169'),
    ('mta_filecenter_companion', 25966, '51f212ef07e0e323cc3803cfd2583ec29867ce0bbf7daff9129ad51d4f6eeeb3'),
)


def _held_directory_policy(binding, root):
    """Original receive fixed-node policy, through the real no-follow FD chain."""
    expected = ('/', 'mnt', 'data', 'p011-toolbox', 'user')
    if root == USER_ROOT + '/Received': expected += ('Received',)
    elif root != USER_ROOT: _fail('unsafe_user_root')
    if binding.root != root or binding.check() is not binding: _fail('unsafe_user_root')
    rows = binding.identity_rows()
    if type(rows) is not tuple or len(rows) != len(expected): _fail('unsafe_user_root')
    for row, name in zip(rows, expected):
        if (type(row) is not tuple or len(row) != 6 or row[0] != name or
                any(type(v) is not int for v in row[1:]) or
                not stat.S_ISDIR(row[3]) or row[3] & 0o022): _fail('unsafe_user_root')
        if name == 'data':
            if row[1:] != (66328, 21, stat.S_IFDIR | 0o755, 1000, 1000): _fail('unsafe_user_root')
        elif row[4:6] != (0, 0): _fail('unsafe_user_root')
        if name in ('p011-toolbox', 'user', 'Received') and stat.S_IMODE(row[3]) != 0o700:
            _fail('unsafe_user_root')
    if binding.check() is not binding or binding.identity_rows() != rows: _fail('anchor_changed')
    return rows


class _LinuxIo(object):
    def _anchors(self):
        rows = []
        physical = '/var/volatile/tmp/p011-mta-formal-send-filecenter-deploy-v4'
        for path, mode, target in (('/', None, None), ('/tmp', stat.S_IFLNK | 0o777, '/var/tmp'),
                ('/var', stat.S_IFDIR | 0o755, None),
                ('/var/tmp', stat.S_IFLNK | 0o777, '/var/volatile/tmp'),
                ('/var/volatile', stat.S_IFDIR | 0o1777, None),
                ('/var/volatile/tmp', stat.S_IFDIR | 0o1777, None),
                (physical, stat.S_IFDIR | 0o700, None),
                (physical + '/runtime', stat.S_IFDIR | 0o700, None),
                (physical + '/native', stat.S_IFDIR | 0o700, None)):
            meta = _meta(os.lstat(path))
            if (meta[3:5] != (0, 0) or meta[5] < 1 or
                    mode is None and (not stat.S_ISDIR(meta[2]) or meta[2] & 0o022) or
                    mode is not None and meta[2] != mode): _fail('unsafe_anchor')
            if target is not None and (meta[5] != 1 or os.readlink(path) != target or meta[6] != len(target)):
                _fail('unsafe_anchor')
            rows.append((path, meta if target is not None else meta[:5], target))
        # Received is owned by the actual DirectoryBinding initializer below;
        # including it in pre-construction anchors would reject the original
        # permitted ENOENT -> mkdirat(EXCL) initialization before it can run.
        for path in ('/mnt', '/mnt/data', '/mnt/data/p011-toolbox', USER_ROOT):
            meta = _meta(os.lstat(path))
            if not stat.S_ISDIR(meta[2]) or meta[2] & 0o022 or meta[5] < 1:
                _fail('unsafe_user_root')
            # Only this already observed fixed mount has uid/gid 1000:1000.
            # Do not allow that ownership on its ancestors or user subtrees.
            if path == '/mnt/data':
                if meta[:5] != (66328, 21, stat.S_IFDIR | 0o755, 1000, 1000):
                    _fail('unsafe_user_root')
            elif meta[3:5] != (0, 0):
                _fail('unsafe_user_root')
            if path in (USER_ROOT, USER_ROOT + '/Received') and stat.S_IMODE(meta[2]) != 0o700:
                _fail('unsafe_user_root')
            rows.append((path, meta[:5], None))
        # These are immutable reused asset roots, not the new ordinary role
        # root. Validate every fixed physical chain; never repair or overwrite.
        for path in ('/var/volatile/tmp/p011-mta-go-send-filecenter-v3-assets',
                '/var/volatile/tmp/p011-mta-go-send-filecenter-v3-assets/runtime',
                '/var/volatile/tmp/p011-mta-go-send-filecenter-v3-assets/native',
                '/var/volatile/tmp/p011-mta-go-observer-libc-v1',
                '/var/volatile/tmp/p011-mta-go-observer-libc-v1/runtime',
                '/var/volatile/tmp/p011-mta-go-send-v78-prepared'):
            meta=_meta(os.lstat(path))
            if (meta[2]!=stat.S_IFDIR|0o700 or meta[3:5]!=(0,0) or meta[5]<1 or
                    os.path.realpath(path)!=path):_fail('unsafe_send_asset_anchor')
            rows.append((path,meta[:5],None))
        for suffix in ('', '/runtime', '/native'):
            if _meta(os.stat(ROOT + suffix))[:5] != _meta(os.lstat(physical + suffix))[:5]:
                _fail('anchor_changed')
        result = tuple(rows)
        if hasattr(self, 'original_anchors') and self.original_anchors != result: _fail('anchor_changed')
        return result
    def validate(self):
        if (sys.platform != 'linux' or sys.byteorder != 'little' or os.geteuid() != 0 or
                os.uname()[4] != 'armv7l' or os.O_NOFOLLOW != 0x8000 or os.O_CLOEXEC != 0x80000):
            _fail('unsupported_platform')
        self.original_anchors = self._anchors()
    def state_paths(self): return USER_ROOT, BLUEZ, NETWORK
    def pid(self): return os.getpid()
    def stat(self, path):
        self._anchors()
        return os.stat(path, follow_symlinks=False)
    def open(self, path):
        if path not in ((BOOT_PATH, BLUEZ, NETWORK, CONNMAN)+tuple(row[0] for row in FIXED_ASSET_PINS)):
            _fail('fixed_paths_unknown')
        self._anchors()
        return os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    def fstat(self, fd): return os.fstat(fd)
    def read(self, fd, count): return os.read(fd, count)
    def close(self, fd): return os.close(fd)


def _read_asset(io, path, size, pin, mode, rows, check):
    row = {'path': path, 'fd': None, 'metadata': None, 'raw': None, 'attempted': False,
           'closed': False, 'unknown': True, 'failure': None}
    rows.append(row)
    try:
        check(); row['fd'] = io.open(path)  # Retain before any late-cap check.
        if type(row['fd']) is not int or row['fd'] < 0: _fail('descriptor_unknown')
        row['metadata'] = _meta(io.fstat(row['fd'])); row['unknown'] = False
        check(); meta = row['metadata']
        if not stat.S_ISREG(meta[2]) or stat.S_IMODE(meta[2]) != mode or meta[3:6] != (0, 0, 1) or meta[6] != size:
            _fail('asset_shape')
        parts, count = [], 0
        while count <= size:
            check(); raw = io.read(row['fd'], min(65536, size + 1 - count)); check()
            if type(raw) is not bytes: _fail('asset_shape')
            parts.append(raw); count += len(raw)
            if not raw: break
        row['raw'] = b''.join(parts)
        if (len(row['raw']) != size or hashlib.sha256(row['raw']).hexdigest() != pin or
                _meta(io.fstat(row['fd'])) != meta or _meta(io.stat(path)) != meta): _fail('asset_changed')
        return row['raw']
    except BaseException as error:
        row['failure'] = error
        raise
    finally:
        if row['unknown'] is False:
            row['attempted'] = True
            try:
                if _meta(io.fstat(row['fd'])) != row['metadata']: _fail('close_unknown')
                returned = io.close(row['fd'])
                try: io.fstat(row['fd'])
                except OSError as error:
                    row['closed'] = returned is None and type(error.errno) is int and error.errno == errno.EBADF
            except BaseException as error:
                row['close_failure'] = error
                row['unknown'] = True


class _SocketRef(object):
    """Original socket byte operations; intercept only its once close proof."""
    def __init__(self, owner, row): self.owner, self.row = owner, row
    def accept(self): return self.row['socket'].accept()
    def _remaining(self):
        now = self.owner.clock()  # Per-request sample; never shared owner.last.
        if not _finite(now) or now >= self.owner.until or self.owner.stop_called: _fail('deadline')
        return self.owner.until - now
    def _clip(self):
        remaining = self._remaining(); current = self.row['socket'].gettimeout()
        self.row['socket'].settimeout(remaining if current is None else min(current, remaining))
    def recv(self, count):
        self._clip(); value = self.row['socket'].recv(count); self._remaining(); return value
    def sendall(self, data):
        self._clip(); value = self.row['socket'].sendall(data); self._remaining(); return value
    def settimeout(self, value):
        if value is None or not _finite(value): _fail('timeout_unknown')
        return self.row['socket'].settimeout(min(value, self._remaining()))
    def shutdown(self, how): return self.row['socket'].shutdown(how)
    def fileno(self): return self.row['socket'].fileno()
    def close(self):
        if not self.owner._close_socket(self.row): _fail('socket_close_unknown')
        return None


class FixedStateServiceOwner(object):
    def __init__(self, loader, original_until, _io=None, send_trial_requested=False):
        boot = sys.modules.get('mta_client_receive_boot')
        if (type(boot) is not types.ModuleType or type(loader) is not boot.BootSourceLoader or
                not _finite(original_until) or float(original_until) != loader._original_until or
                loader.clock is not time.monotonic): _fail('invalid_owner')
        if type(send_trial_requested) is not bool: _fail('send_trial_profile')
        self.send_trial_requested = self._send_trial_requested_original = send_trial_requested
        self.send_trial = self._send_trial_original = self.send_trial_ticket = None
        self.send_preflight_parent = self.send_preflight_report = self.send_preflight_ticket = None
        self.network_observer_spec = self._network_observer_spec_original = None
        self._network_observer_asset_original = None
        self.boot, self.loader = boot, loader
        self.until = self.original_until = loader._original_until
        self.clock = time.monotonic
        self.io = self.original_io = _LinuxIo() if _io is None else _io
        self.worker = threading.current_thread()
        self.pid = None
        self.lock = threading.RLock()
        self.factory = self.state = self.server = self.thread = None
        self.probe_rows = None
        self.service = self.http = None
        self.server_constructor_failure = None
        self.assets, self.requests, self.threads = [], [], []
        self.listener = None
        self.paths = None
        self.started = self.start_complete = self.state_complete = self.server_complete = False
        self.factory_called = self.state_called = self.server_called = False
        self.stop_called = self.close_called = self.close_complete = False
        self.state_close_called = False
        self.state_close_return = None
        self.cleanup_until = self._cleanup_until_original = None
        self.cleanup_deadline_expired = False
        self.cleanup_clock_failure = None
        self.failure, self.loop_failure, self.failures = None, None, []
        self.last = None
        self._startup_owner_type_original = type(self)
        self._startup_namespace_original = globals()
        self._state_original = self._server_original = None
        self._assets_original, self._requests_original, self._threads_original = self.assets, self.requests, self.threads
        self.directory_module = self.directory_type = None
        self.directory_methods = self._directory_methods_original = None
        self.user_directory = self._user_directory_original = None
        self.received_directory = self._received_directory_original = None
        self.directory_tickets = self._directory_tickets_original = []
        self.directory_close_called = self.directory_close_complete = False
        self.service_methods = self._service_methods_original = None
        self.service_type = self._service_type_original = None
        self.filecenter_ticket = self._filecenter_ticket_original = None

    def _context(self):
        own = sys.modules.get('mta_client_service_owner')
        if (type(own) is not types.ModuleType or own.__dict__ is not self._startup_namespace_original or
                own.FixedStateServiceOwner is not self._startup_owner_type_original or
                type(self) is not self._startup_owner_type_original or
                type(self).__init__.__globals__ is not self._startup_namespace_original or
                self.state is not self._state_original or self.server is not self._server_original or
                self.assets is not self._assets_original or self.requests is not self._requests_original or
                self.threads is not self._threads_original or
                self.io is not self.original_io or self.until is not self.original_until or
                self.loader._original_until is not self.original_until or self.loader.clock is not self.clock or
                sys.modules.get('mta_client_receive_boot') is not self.boot or
                self.pid is not None and self.io.pid() != self.pid): _fail('owner_changed')
        if self.service is not None and (self.service.State is not self._service_type_original or
                self.service_type is not self._service_type_original or
                self.service_methods is not self._service_methods_original or
                any(getattr(self.service_type, name) is not original
                    for name, original in self.service_methods.items())):
            _fail('state_source_changed')

    def _boot_roles(self):
        # Original authenticate has already checked all fixed bytes, original
        # namespaces and source closes. This pure role contract grants no RF.
        if (self.boot.SOURCE_SCHEMA != BOOT_SCHEMA or self.boot.MODULES != BOOT_MODULES or
                type(self.loader.modules) is not dict or len(self.loader.modules) != len(BOOT_MODULES)):
            _fail('boot_roles_changed')
        for name in BOOT_MODULES:
            module = self.loader.modules.get(name)
            root = GO_ASSET_RUNTIME if name == 'mta_go_deployment' else ROOT + '/runtime'
            if (type(module) is not types.ModuleType or sys.modules.get(name) is not module or
                    module.__file__ != root + '/' + name + '.py'):
                _fail('boot_roles_changed')

    def _now(self, cleanup=False):
        with self.lock:
            self._context(); now = self.clock()
            if not _finite(now) or self.last is not None and now < self.last: _fail('clock_unknown')
            self.last = now
            cap = self.cleanup_until if cleanup else self.until
            if cap is None or now >= cap: _fail('deadline')
            return now

    def _start_directories(self):
        """Real original DirectoryBinding objects, retained before construction."""
        self._now()
        if self.paths[0] != USER_ROOT or self.directory_tickets:
            _fail('directory_original_required')
        module = self.loader.modules['mta_storage']
        cls = getattr(module, 'DirectoryBinding', None)
        if (type(module) is not types.ModuleType or sys.modules.get('mta_storage') is not module or
                type(cls) is not type or cls.__init__.__globals__ is not module.__dict__):
            _fail('directory_source_required')
        self.directory_module, self.directory_type = module, cls
        methods = {name: getattr(cls, name) for name in
            ('__init__', '_current', '_now', 'check', 'identity_rows', 'ensure_private_child',
             'close', 'closed', 'root', 'absolute_until')}
        self.directory_methods = self._directory_methods_original = methods
        ticket = dict(name='user', value=None, called=False, complete=False, rows=None,
                      row_originals=None, identities=None, failure=None)
        self.directory_tickets.append(ticket)
        try:
            value = cls.__new__(cls)
            ticket['value'] = self.user_directory = self._user_directory_original = value
            ticket['called'] = True
            methods['__init__'](value, USER_ROOT, self.original_until, clock=self.clock)
            ticket.update(complete=True, rows=value.rows, row_originals=value._row_originals,
                          identities=_held_directory_policy(value, USER_ROOT))
        except BaseException as error:
            ticket['failure'] = error
            raise
        child = dict(name='received', value=None, called=False, complete=False, rows=None,
                     row_originals=None, identities=None, failure=None, initialization=None)
        self.directory_tickets.append(child)
        try:
            self._now()
            previous = len(value.initializations)
            child['called'] = True
            received = methods['ensure_private_child'](value, 'Received')
            child['value'] = self.received_directory = self._received_directory_original = received
            if len(value.initializations) != previous+1:
                _fail('directory_original_required')
            child['initialization'] = value.initializations[-1]
            child.update(complete=True, rows=received.rows, row_originals=received._row_originals,
                         identities=_held_directory_policy(received, USER_ROOT+'/Received'))
            if (child['initialization']['child'] is not received or
                    child['identities'][:-1] != ticket['identities'] or
                    received.clock is not self.clock or received.absolute_until is not self.original_until):
                _fail('directory_original_required')
        except BaseException as error:
            child['failure'] = error
            raise
        finally:
            # ensure_private_child itself retains before __init__. Even a failed
            # RHS is adopted, never discarded or represented as no child.
            if child['called'] and len(value.initializations) > previous:
                original = value.initializations[previous]
                child['initialization'] = original
                retained = original['child']
                if child['value'] is None and retained is not None:
                    child['value'] = self.received_directory = self._received_directory_original = retained

    def _directory_definitions_current(self):
        module, cls, methods = self.directory_module, self.directory_type, self.directory_methods
        return (type(module) is types.ModuleType and sys.modules.get('mta_storage') is module and
                self.loader.modules.get('mta_storage') is module and module.DirectoryBinding is cls and
                methods is self._directory_methods_original and type(methods) is dict and
                cls.__init__.__globals__ is module.__dict__ and
                all(getattr(cls, name) is original for name, original in methods.items()) and
                self.directory_tickets is self._directory_tickets_original and
                self.user_directory is self._user_directory_original and
                self.received_directory is self._received_directory_original)

    def _directory_inventory_closed(self):
        if not self.directory_tickets:
            return self.user_directory is None and self.received_directory is None
        if not self._directory_definitions_current(): return False
        if len(self.directory_tickets) != 2: return False
        for ticket, binding in zip(self.directory_tickets, (self.user_directory, self.received_directory)):
            if (ticket['complete'] is not True or ticket['failure'] is not None or
                    ticket['value'] is not binding or type(binding) is not self.directory_type or
                    binding.rows is not ticket['rows'] or binding._row_originals is not ticket['row_originals'] or
                    len(binding.rows) != len(ticket['row_originals']) or
                    any(a is not b for a, b in zip(binding.rows, ticket['row_originals'])) or
                    binding.failure is not None or binding.cleanup_errors or
                    binding.clock is not self.clock or binding.absolute_until is not self.original_until or
                    self.directory_methods['closed'](binding) is not True):
                return False
            for row in ticket['row_originals']:
                if (row['closed'] is not True or row['unknown'] is not False or
                        row['fd'] != row['fd_original'] or row['close_error'] is not None or
                        type(row['fd_original']) is not int):
                    return False
                try: os.fstat(row['fd_original'])
                except OSError as error:
                    if type(error.errno) is not int or error.errno != errno.EBADF: return False
                else: return False
            if binding.downloads or binding.archives: return False
        child = self.directory_tickets[1]['initialization']
        return (len(self.user_directory.initializations) == 1 and
                self.user_directory.initializations[0] is child and child['child'] is self.received_directory and
                child['error'] is None and child['child_returned'] is True)

    def create_filecenter(self, source_rows):
        """Single fixed nine-source producer; returns no public credentials.

        A future fixed UI must bind its REAL audio guardian before issuing
        FileCenter credentials. This function does not supply a substitute ACK
        or success callback, invoke audio, or grant Native/RF/restoration.
        """
        self._now()
        if (self.filecenter_ticket is not None or not self.start_complete or
                self.stop_called or self.close_called or not self._directory_definitions_current()):
            _fail('filecenter_original_required')
        if type(source_rows) is not tuple or len(source_rows) != len(FILECENTER_PINS):
            _fail('filecenter_source_required')
        for row, pin in zip(source_rows, FILECENTER_PINS):
            if (type(row) is not tuple or len(row) != 2 or row[0] != pin[0] or
                    type(row[1]) is not bytes or len(row[1]) != pin[1] or
                    hashlib.sha256(row[1]).hexdigest() != pin[2]):
                _fail('filecenter_source_required')
        if sum(len(raw) for name, raw in source_rows) > FILECENTER_MAX_SOURCE:
            _fail('filecenter_source_required')
        if any(name in sys.modules for name, raw in source_rows):
            _fail('filecenter_namespace_busy')
        own = sys.modules['mta_client_service_owner']
        ticket = dict(sources=source_rows, modules=[], module=None, namespace=None, cls=None,
                      creator=None, methods=None, original=None, create_called=False, create_returned=False,
                      close_called=False, close_return=None, failure=None, close_failure=None,
                      state=None, server=None, thread=None, media=None, audio=None, audio_tickets=None,
                      owner_module=own, owner_namespace=own.__dict__)
        self.filecenter_ticket = self._filecenter_ticket_original = ticket
        try:
            for name, raw in source_rows:
                self._now()
                module = types.ModuleType(name)
                module.__file__ = '<fixed-sender-filecenter-memory/'+name+'.py>'
                row = dict(name=name, raw=raw, module=module, namespace=module.__dict__,
                           entered=False, complete=False, definitions=None)
                ticket['modules'].append(row)
                sys.modules[name] = module
                row['entered'] = True
                exec(raw, module.__dict__)
                # Hold actual source definitions, not a user-provided creator.
                row['definitions'] = tuple((key, value, tuple(vars(value).items()) if type(value) is type else None)
                    for key, value in module.__dict__.items()
                    if type(value) in (types.FunctionType, type) and
                    getattr(value, '__module__', None) == name)
                row['complete'] = True
                self._now()
            module = ticket['modules'][-1]['module']
            cls, creator = module._Companion, module.create
            if (type(creator) is not types.FunctionType or creator.__globals__ is not module.__dict__ or
                    type(cls) is not type or cls.__init__.__globals__ is not module.__dict__):
                _fail('filecenter_source_required')
            ticket.update(module=module, namespace=module.__dict__, cls=cls, creator=creator,
                          methods={name: getattr(cls, name) for name in
                                   ('__init__', 'close', 'closed', '_workers_closed', 'check', 'credentials')})
            def retain(original):
                if (ticket is not self._filecenter_ticket_original or not ticket['create_called'] or
                        ticket['original'] is not None or type(original) is not cls):
                    _fail('filecenter_original_required')
                ticket['original'] = original  # Before any Companion child constructor.
            ticket['create_called'] = True
            result = creator(self, own, retain)
            ticket['create_returned'] = True
            if result is not ticket['original']: _fail('filecenter_original_required')
            ticket.update(state=result.state, server=result.server, thread=result.thread, media=result.media,
                          audio=result.audio, audio_tickets=result.audio.tickets)
            # Retain the actual atomic resources before fstat can fail. Current
            # child-object identity alone cannot authorize close of a swapped
            # FileStore or listener hidden inside those original children.
            store, sock = result.state.store, result.server.socket
            ticket.update(store=store, store_fd=store.rootfd, store_metadata=None,
                          socket=sock, socket_fd=None, socket_metadata=None)
            if (type(store) is not ticket['modules'][7]['module'].RetainedFileStore or
                    type(sock) is not socket.socket or type(ticket['store_fd']) is not int or
                    ticket['store_fd'] < 0):
                _fail('filecenter_original_changed')
            ticket['store_metadata'] = _meta(os.fstat(ticket['store_fd']))
            ticket['socket_fd'] = sock.fileno()
            if type(ticket['socket_fd']) is not int or ticket['socket_fd'] < 0:
                _fail('filecenter_original_changed')
            ticket['socket_metadata'] = _meta(os.fstat(ticket['socket_fd']))
            if (ticket['store_metadata'][:5] != self.directory_tickets[0]['identities'][-1][1:] or
                    not stat.S_ISSOCK(ticket['socket_metadata'][2])):
                _fail('filecenter_original_changed')
            if not self._filecenter_current(): _fail('filecenter_original_changed')
            self._now()
            return result  # Intentionally NOT Companion.credentials(result).
        except BaseException as error:
            ticket['failure'] = error
            if ticket['original'] is not None:
                self._capture_filecenter_partial(ticket)
            raise

    def _filecenter_definitions_current(self):
        ticket = self.filecenter_ticket
        if (type(ticket) is not dict or ticket is not self._filecenter_ticket_original or
                ticket['owner_module'] is not sys.modules.get('mta_client_service_owner') or
                ticket['owner_namespace'] is not self._startup_namespace_original or
                len(ticket['modules']) != len(FILECENTER_PINS)):
            return False
        for row, pin in zip(ticket['modules'], FILECENTER_PINS):
            if (row['name'] != pin[0] or row['complete'] is not True or
                    sys.modules.get(row['name']) is not row['module'] or
                    row['module'].__dict__ is not row['namespace']):
                return False
            for name, value, attributes in row['definitions']:
                if row['namespace'].get(name) is not value: return False
                if attributes is not None and any(vars(value).get(key) is not original for key, original in attributes):
                    return False
        module, cls = ticket['module'], ticket['cls']
        return (module is ticket['modules'][-1]['module'] and module.__dict__ is ticket['namespace'] and
                module.create is ticket['creator'] and module._Companion is cls and
                all(getattr(cls, name) is value for name, value in ticket['methods'].items()))

    def _filecenter_current(self):
        if not self._filecenter_definitions_current(): return False
        ticket, value = self.filecenter_ticket, self.filecenter_ticket['original']
        same = (ticket['create_returned'] is True and type(value) is ticket['cls'] and
                value.owner is self and value.worker is self.worker and value.until is self.original_until and
                value.root == USER_ROOT and value.state is ticket['state'] and
                value.server is ticket['server'] and value.thread is ticket['thread'] and
                value.media is ticket['media'] and value.audio is ticket['audio'] and
                value.audio is value.original_audio and value.state.audio is value.audio and
                value.audio.tickets is ticket['audio_tickets'] and
                value.state.store is ticket['store'] and value.server.socket is ticket['socket'] and
                value.socket_original is ticket['socket'] and
                value.rootfd is ticket['store_fd'] and value.original_rootfd is ticket['store_fd'])
        if not same: return False
        if value.close_called is True:
            # Only the same originally retained objects may transition to a
            # closed handle. Closed child fields do not imply original EBADF.
            if ticket['store'].rootfd is not None or ticket['socket'].fileno() != -1:
                return False
            for fd in (ticket['store_fd'], ticket['socket_fd']):
                try: os.fstat(fd)
                except OSError as error:
                    if type(error.errno) is not int or error.errno != errno.EBADF: return False
                else: return False
            return True
        return (value.close_called is False and ticket['store'].rootfd is ticket['store_fd'] and
                ticket['socket'].fileno() == ticket['socket_fd'] and
                _meta(os.fstat(ticket['store_fd']))[:5] == ticket['store_metadata'][:5] and
                _meta(os.fstat(ticket['socket_fd'])) == ticket['socket_metadata'])

    def _capture_filecenter_partial(self, ticket):
        """Retain actual partial children before any cleanup; never a receipt."""
        value = ticket['original']
        partial = dict(value=value, attributes=(), children=(), socket=None, socket_fd=None,
                       socket_metadata=None, store_fd=None, store_metadata=None,
                       captured=False, failure=None)
        ticket['partial_inventory'] = partial
        try:
            if (not self._filecenter_definitions_current() or type(value) is not ticket['cls'] or
                    ticket['create_called'] is not True or ticket['create_returned'] is not False):
                _fail('filecenter_partial_unknown')
            names = ('root', 'until', 'worker', 'owner', 'state', 'server', 'thread', 'audio',
                     'media', 'rootfd', 'original_rootfd', 'socket_original',
                     'state_complete', 'server_complete', 'thread_initialized',
                     'start_called', 'start_returned', 'close_called')
            partial['attributes'] = tuple((name, hasattr(value, name), getattr(value, name, None)) for name in names)
            # Header validation can fail before its resource inventory exists.
            # No missing field is projected to a successful empty constructor.
            if not all(hasattr(value, name) for name in names) or value.owner is not self or value.worker is not self.worker:
                _fail('filecenter_partial_unknown')
            module = ticket['module']
            children = []
            for original, cls, names in (
                    (value.state, module._FileCenterState, ('store', 'audio', 'stop_event')),
                    (value.server, module._FileCenterServer, ('state', 'socket', 'stopping')),
                    (value.thread, threading.Thread, ('_initialized',)),
                    (value.audio, ticket['modules'][6]['module'].FileCenterAudio, ('audio', 'tickets'))):
                children.append((original, cls, tuple((name, hasattr(original, name), getattr(original, name, None))
                                                     for name in names) if original is not None else ()))
                partial['children'] = tuple(children)  # Before subsequent fstat/type checks.
                if original is not None and type(original) is not cls: _fail('filecenter_partial_unknown')
            state, server, audio = value.state, value.server, value.audio
            store = getattr(state, 'store', None)
            children.append((store, ticket['modules'][7]['module'].RetainedFileStore,
                             tuple((name, hasattr(store, name), getattr(store, name, None))
                                   for name in ('root', 'rootfd')) if store is not None else ()))
            partial['children'] = tuple(children)
            if store is not None:
                if type(store) is not children[-1][1]: _fail('filecenter_partial_unknown')
                fd = getattr(store, 'rootfd', None)
                partial['store_fd'] = fd
                if fd is not None:
                    if type(fd) is not int or fd < 0: _fail('filecenter_partial_unknown')
                    partial['store_metadata'] = _meta(os.fstat(fd))[:5]
                    if (getattr(store, 'root', None) != USER_ROOT or
                            partial['store_metadata'] != self.directory_tickets[0]['identities'][-1][1:]):
                        _fail('filecenter_partial_unknown')
            sock = getattr(server, 'socket', None)
            partial['socket'] = sock
            if sock is not None:
                if type(sock) is not socket.socket: _fail('filecenter_partial_unknown')
                partial['socket_fd'] = sock.fileno()
                if partial['socket_fd'] >= 0:
                    partial['socket_metadata'] = _meta(os.fstat(partial['socket_fd']))
                    if not stat.S_ISSOCK(partial['socket_metadata'][2]): _fail('filecenter_partial_unknown')
                elif partial['socket_fd'] != -1: _fail('filecenter_partial_unknown')
            # A partial creator never issued credentials or invoked audio.play.
            # An unexpected actor cannot be cleaned by guessing its ownership.
            if audio is not None and (getattr(audio, 'audio', None) is not None or getattr(audio, 'tickets', None)):
                _fail('filecenter_partial_unknown')
            partial['captured'] = True
        except BaseException as error:
            partial['failure'] = error  # Strong original failure; no retry/clearing.

    def _filecenter_partial_current(self):
        ticket = self.filecenter_ticket
        partial = ticket.get('partial_inventory')
        if (type(partial) is not dict or not partial['captured'] or partial['failure'] is not None or
                not self._filecenter_definitions_current() or partial['value'] is not ticket['original'] or
                type(ticket['original']) is not ticket['cls'] or ticket['create_returned'] is not False):
            return False
        for original, attributes in [(partial['value'], partial['attributes'])] + [
                (value, attributes) for value, cls, attributes in partial['children']]:
            if any(hasattr(original, name) is not present or present and getattr(original, name) is not retained
                   for name, present, retained in attributes):
                return False
        if any(value is not None and type(value) is not cls for value, cls, attributes in partial['children']):
            return False
        fd = partial['store_fd']
        if fd is not None and _meta(os.fstat(fd))[:5] != partial['store_metadata']: return False
        sock = partial['socket']
        if sock is not None and (sock.fileno() != partial['socket_fd'] or
                partial['socket_fd'] >= 0 and _meta(os.fstat(partial['socket_fd'])) != partial['socket_metadata']):
            return False
        return True


    def _close_filecenter(self):
        ticket = self.filecenter_ticket
        if ticket is None:
            return ticket is self._filecenter_ticket_original
        if ticket is not self._filecenter_ticket_original: _fail('filecenter_original_changed')
        if ticket['close_called']: return self._filecenter_closed()
        if (not self._filecenter_definitions_current() or
                type(ticket['original']) is not ticket['cls']):
            return False  # Partial definitions/unknown creator: preserve originals.
        if ticket['create_returned']:
            if not self._filecenter_current(): return False
        elif not self._filecenter_partial_current():
            return False  # Unknown/changed child: no foreign close or fake absence.
        ticket['close_called'] = True
        try:
            # Original FileCenter close clips all child waits to this Owner's
            # same original absolute cleanup cap; no child renews that cap.
            ticket['close_return'] = ticket['methods']['close'](ticket['original'],
                cleanup_until=self._cleanup_until_original)
        except BaseException as error:
            ticket['close_failure'] = error
            raise
        return self._filecenter_closed()

    def _filecenter_closed(self):
        if self.filecenter_ticket is None:
            return self._filecenter_ticket_original is None
        ticket = self.filecenter_ticket
        try:
            return (ticket is self._filecenter_ticket_original and ticket['create_returned'] is True and
                    ticket['failure'] is None and ticket['close_failure'] is None and
                    ticket['close_called'] is True and ticket['close_return'] is True and
                    self._filecenter_current() and
                    ticket['methods']['closed'](ticket['original']) is True and
                    ticket['audio'].actors_closed() is True)
        except BaseException:
            return False  # A passive failure is never a closure/grant.

    def _http_passively_closed(self):
        if (self.requests is not self._requests_original or self.threads is not self._threads_original or
                self.server is not self._server_original):
            return False
        for ticket in self.threads:
            if (ticket['unknown'] or ticket['thread'] is not ticket['thread_original'] or
                    not ticket['initialized'] or type(ticket['thread']) is not threading.Thread or
                    ticket['thread'].is_alive() or
                    ticket['called'] and (not ticket['returned'] or not ticket['ended']) or
                    not ticket['called'] and ticket['thread'].ident is not None):
                return False
        for row in ([self.listener] if self.listener is not None else []) + self.requests:
            if (row['unknown'] or not row['closed'] or row['socket'] is not row['socket_original'] or
                    row['proxy'] is not row['proxy_original'] or row['fd'] != row['fd_original'] or
                    row['metadata'] is not row['metadata_original'] or row['socket_original'].fileno() != -1):
                return False
            try: self.io.fstat(row['fd_original'])
            except OSError as error:
                if type(error.errno) is not int or error.errno != errno.EBADF: return False
            else: return False
            ticket = row.get('ticket')
            if ticket is not None and (ticket is not row.get('ticket_original') or
                    not any(ticket is original for original in self.threads)):
                return False
        if self.server_called:
            return (self.server_complete and type(self.server) is self.service.Server and
                    self.server.state is self.state and self.stop_called and self.server.stopping.is_set() and
                    self.listener is not None and self.server.socket is self.listener['proxy_original'] and
                    not self.server.workers)
        return self.server is None and not self.requests and not self.threads and self.listener is None

    def _close_directories(self):
        self._context()
        if self.directory_close_called: return self.directory_close_complete
        if not self._filecenter_closed() or not self._service_closed(): return False
        if not self.directory_tickets:
            self.directory_close_called = self.directory_close_complete = (
                self.user_directory is None and self.received_directory is None)
            return self.directory_close_complete
        if not self._directory_definitions_current() or not 1 <= len(self.directory_tickets) <= 2:
            return False
        self.directory_close_called = True
        for index in reversed(range(len(self.directory_tickets))):
            ticket = self.directory_tickets[index]
            binding, original = ((self.user_directory, self._user_directory_original) if index == 0 else
                                 (self.received_directory, self._received_directory_original))
            # A later partial child cannot suppress close-only work on the
            # earlier complete user chain. Its error/unknown inventory stays
            # retained; the final all-ticket gate still refuses success.
            if (ticket['complete'] is not True or ticket['failure'] is not None or
                    binding is not original or ticket['value'] is not binding or
                    type(binding) is not self.directory_type or binding.rows is not ticket['rows'] or
                    binding._row_originals is not ticket['row_originals'] or
                    len(binding.rows) != len(ticket['row_originals']) or
                    any(a is not b for a, b in zip(binding.rows, ticket['row_originals']))):
                continue
            try: self.directory_methods['close'](binding)
            except BaseException as error: self.failures.append(error)
        self.directory_close_complete = self._directory_inventory_closed()
        return self.directory_close_complete

    def _closed(self):
        try:
            return (self._service_closed() and self._filecenter_closed() and
                    self.directory_close_complete and self._directory_inventory_closed())
        except BaseException:
            return False

    def _socket_row(self, raw, row):
        # The caller registers this exact row before fileno/fstat can fail.
        if type(raw) is not socket.socket: _fail('socket_unknown')
        row['fd'] = raw.fileno()
        if type(row['fd']) is not int or row['fd'] < 0: _fail('socket_unknown')
        row['metadata'] = _meta(self.io.fstat(row['fd']))
        if not stat.S_ISSOCK(row['metadata'][2]): _fail('socket_unknown')
        row['unknown'] = False; row['proxy'] = _SocketRef(self, row)
        row['socket_original'], row['fd_original'] = raw, row['fd']
        row['metadata_original'], row['proxy_original'] = row['metadata'], row['proxy']
        return row

    def _close_socket(self, row):
        with self.lock:
            self._context()
            if row['attempted']: return row['closed'] is True and row['unknown'] is False
            if row['unknown']: return False
            row['attempted'] = True
            try:
                if row['socket'].fileno() != row['fd'] or _meta(self.io.fstat(row['fd'])) != row['metadata']:
                    _fail('socket_close_unknown')
                returned = row['socket'].close()
                try: self.io.fstat(row['fd'])
                except OSError as error:
                    row['closed'] = returned is None and type(error.errno) is int and error.errno == errno.EBADF
            except BaseException as error:
                row['failure'] = error; row['unknown'] = True
            return row['closed'] is True and row['unknown'] is False

    def _new_thread(self, target):
        ticket = {'thread': None, 'initialized': False, 'called': False, 'returned': False,
                  'unknown': False, 'ended': False, 'failure': None}
        self.threads.append(ticket)
        value = threading.Thread.__new__(threading.Thread); ticket['thread'] = ticket['thread_original'] = value
        try:
            threading.Thread.__init__(value, target=target); value.daemon = True
            ticket['initialized'] = True
        except BaseException as error:
            ticket['failure'] = error; ticket['unknown'] = True; raise
        return ticket

    def _start_thread(self, ticket):
        self._now()
        if self.stop_called or self.server.stopping.is_set(): _fail('deadline')
        ticket['called'] = True
        try: ticket['thread'].start(); ticket['returned'] = True
        except BaseException as error:
            ticket['failure'] = error; ticket['unknown'] = True; raise

    def _prepare_send_trial(self):
        if (threading.current_thread() is not self.worker or self.server_called or
                self.send_trial is not None or self.send_trial_ticket is not None or
                self.state_complete is not True or len(self.assets)!=71 or
                self.state._network_observer_spec_original is not self._network_observer_spec_original):
            _fail('send_trial_original_owner')
        self._now();self._boot_roles()
        if self.send_trial_requested:
            if (self.service._probe_result(self.state.bluetooth_probe_actor,self.state.bluetooth_caps,
                    self.paths[1],['--capabilities','hci0']) is not True or
                    self.state.bluetooth_caps.get('powered') is not True):
                _fail('send_trial_radio_baseline_missing')
            self.loader.modules['mta_receive_radio_baseline'].normalize(self.state.bluetooth_caps)
            module=self.loader.modules['mta_go_readonly_parent'];cls=module.ReadonlyDataParent
            args=(os.urandom(16).hex(),1,1,self.original_until,self.original_until)
            ticket={'creator':cls,'arguments':args,'partial':None,'returned':None,
                'constructor_called':True,'constructed':False,'collect_called':False,
                'collect_return':None,'ended':False,'unknown':True,'failure':None}
            self.send_preflight_ticket=ticket
            try:
                parent=object.__new__(cls)
                ticket['partial']=self.send_preflight_parent=parent
                cls.__init__(parent,*args);ticket['constructed']=True;ticket['returned']=parent
                self._now();ticket['collect_called']=True
                report=cls.collect(parent)
                ticket['collect_return']=self.send_preflight_report=report
                ticket['unknown']=False
                self._now()
            except BaseException as error:
                ticket['failure']=error;raise
            finally:
                if ticket['constructed'] and self.send_preflight_parent.close_attempted is False:
                    try:cls.close(self.send_preflight_parent)
                    except BaseException as error:
                        if ticket['failure'] is None:ticket['failure']=error
                        ticket['unknown']=True
                ticket['ended']=True
        module=self.loader.modules['mta_send_trial'];cls=module.FixedSendTrial
        ticket={'creator':cls,'partial':None,'constructor_called':True,
                'constructed':False,'ended':False,'failure':None}
        self.send_trial_ticket=ticket
        try:
            trial=object.__new__(cls)
            ticket['partial']=self.send_trial=self._send_trial_original=trial
            cls.__init__(trial,self,self.send_trial_requested)
            ticket['constructed']=True
            self.state._send_trial=self.state._send_trial_original=trial
            # Public availability is derived from the exact gate every time;
            # State.send_available remains the historical false sentinel.
            if (self.send_trial_requested and cls.available(trial,self.state) is not True or
                    not self.send_trial_requested and cls.available(trial,self.state) is not False):
                _fail('send_trial_initial_gate')
        except BaseException as error:
            ticket['failure']=error;raise
        finally:ticket['ended']=True

    def _close_send_trial(self):
        if self.send_trial is None:return self.send_trial_ticket is None
        if self.send_trial_ticket['constructed'] is not True:return False
        module=self.loader.modules['mta_send_trial']
        module.FixedSendTrial.revoke(self.send_trial,self.state,'owner_closed')
        return module.FixedSendTrial.closed(self.send_trial,self.state)

    def start(self):
        if self.started or self.close_called: _fail('already_started')
        if threading.current_thread() is not self.worker: _fail('wrong_worker')
        self.started = True
        try:
            self._now(); self.io.validate(); self.pid = self.io.pid()
            if type(self.pid) is not int or not 1 <= self.pid <= 0x7fffffff: _fail('owner_changed')
            self._now()
            self.boot.BootSourceLoader.authenticate(self.loader)
            self._boot_roles()
            if self.send_trial_requested and self.until-self._now()>600.0: _fail('send_trial_window')
            self.factory_called = True
            self.factory = self.boot.BootSourceLoader.create_fixed_factory(self.loader)
            self.service, self.http = self.loader.modules['mta_service'], self.loader.modules['minhttp']
            self.service_type = self._service_type_original = self.service.State
            self.service_methods = self._service_methods_original = {
                name: getattr(self.service.State, name) for name in
                ('__init__', 'close', 'closed', '_probes_closed', '_close_probes',
                 '_go_local_closed', '_go_restoration_current')}
            paths = self.io.state_paths()
            if type(paths) is not tuple or len(paths) != 3 or any(type(p) is not str or not os.path.isabs(p) for p in paths):
                _fail('fixed_paths_unknown')
            if type(self.io) is _LinuxIo and paths != (USER_ROOT, BLUEZ, NETWORK): _fail('fixed_paths_unknown')
            self.paths = paths
            self._start_directories()
            for path, pin in zip(paths[1:], HELPER_PINS):
                _read_asset(self.io, path, pin[0], pin[1], 0o500, self.assets, self._now)
            _read_asset(self.io,CONNMAN,CONNMAN_PIN[0],CONNMAN_PIN[1],0o700,self.assets,self._now)
            self._network_observer_asset_original=self.assets[-1]
            self.network_observer_spec=self._network_observer_spec_original=(CONNMAN,CONNMAN_PIN[0],CONNMAN_PIN[1])
            for path,size,pin,mode in FIXED_ASSET_PINS:
                _read_asset(self.io,path,size,pin,mode,self.assets,self._now)
            wpa=self.assets[-1]['raw']
            if (wpa[:6]!=b'\x7fELF\x01\x01' or wpa[18:20]!=b'\x28\x00' or
                    len(self.assets)!=71 or any(row['unknown'] or row['closed'] is not True for row in self.assets)):
                _fail('asset_close_unknown')
            self._now(); self.state_called = True
            self.state = self._state_original = self.service.State.__new__(self.service.State)
            try:
                self.service.State.__init__(self.state, paths[0], paths[1], paths[2],
                                           trusted_receive_deployment_factory=self.factory,
                                           original_service_until=self.original_until,
                                           network_observer_spec=self._network_observer_spec_original)
            finally:
                self.probe_rows = getattr(self.state, 'probe_actors', None)
            self.state_complete = True
            if (self.state.registry.root != USER_ROOT or self.state.received_root != USER_ROOT+'/Received' or
                    self.user_directory.check() is not self.user_directory or
                    self.received_directory.check() is not self.received_directory):
                _fail('state_directory_changed')
            self.state.scan_available = False
            if (self.state.receive_available is not False or self.state.send_available is not False or
                    self.state.wifi_restore_pending is not False or self.state.radio_restore_pending is not False or
                    self.state._trusted_receive_deployment_factory is not self.factory or
                    self.state._original_service_until is not self.original_until or
                    self.state._service_until_original is not self.original_until or
                    not self.service.State._probes_closed(self.state)):
                _fail('state_start_pending')
            self._prepare_send_trial()
            self._now(); self.server_called = True
            self.server = self._server_original = self.service.Server.__new__(self.service.Server)
            try:
                self.service.Server.__init__(self.server, self.state, 0, True)
                self.server_complete = True
            except BaseException as error:
                self.server_constructor_failure = error
                raise
            finally:
                raw = getattr(self.server, 'socket', None)
                if raw is not None:
                    self.listener = {'socket': raw, 'fd': None, 'metadata': None, 'proxy': None,
                        'attempted': False, 'closed': False, 'unknown': True, 'failure': None}
                    try: self._socket_row(raw, self.listener)
                    except BaseException as error:
                        self.listener['failure'] = error; self.failures.append(error)
            if self.listener is None or self.listener['unknown']: _fail('server_socket_unknown')
            self.server.socket = self.listener['proxy']
            self.server.bootstrap_deadline = min(self.server.bootstrap_deadline, self.until)
            owner, base, http = self, self.service.Handler, self.http
            class FiniteHandler(base):
                def setup(self):
                    self.deadline = min(self.deadline, owner.until)
                    http.BaseHTTPRequestHandler.setup(self)
                def _dispatch(self, method):
                    if owner.clock() >= owner.until or self.server.stopping.is_set(): return
                    return method(self)
                def do_GET(self): return self._dispatch(base.do_GET)
                def do_POST(self): return self._dispatch(base.do_POST)
            self.server.handler = FiniteHandler
            self._now(); ticket = self._new_thread(self._serve)
            self.thread = ticket['thread']; self._start_thread(ticket)
            self._now(); self.start_complete = True
            return self
        except BaseException as error:
            self.failure = error; self.failures.append(error)
            raise

    def _request(self, row, address):
        try: self.http.HTTPServer.process(self.server, row['proxy'], address)
        except BaseException as error: row['failure'] = error; self.failures.append(error)
        finally: row['ended'] = True

    def _serve(self):
        try:
            while not self.server.stopping.is_set():
                self._now()
                if len(self.requests) >= MAX_REQUESTS: _fail('request_budget')
                # Serialize accept+inventory against proxy close/EBADF so our
                # own accept cannot reuse a descriptor before its close proof.
                with self.lock:
                    try: raw, address = self.server.socket.accept()
                    except socket.timeout: continue
                    row = {'socket': raw, 'fd': None, 'metadata': None, 'proxy': None,
                           'attempted': False, 'closed': False, 'unknown': True, 'ended': False, 'failure': None}
                    self.requests.append(row)
                    self._socket_row(raw, row)
                self._now()  # Adopt first; late accept cannot create new work.
                if self.stop_called or self.server.stopping.is_set(): _fail('deadline')
                if not self.server.slots.acquire(False): row['proxy'].close(); row['ended'] = True; continue
                ticket = self._new_thread(lambda r=row, a=address: self._request(r, a))
                row['ticket'] = row['ticket_original'] = ticket
                with self.server.worker_lock: self.server.workers[row['proxy']] = ticket['thread']
                self._start_thread(ticket)
        except BaseException as error:
            if not self.stop_called and not (type(error) is ServiceOwnerError and error.code == 'deadline'):
                self.loop_failure = error
                self.failures.append(error)
        finally:
            self._stop_server()

    def _stop_server(self):
        with self.lock:
            if self.stop_called: return
            self.stop_called = True
            if self.server_complete:
                try: self.http.HTTPServer.shutdown(self.server)
                except BaseException as error: self.failures.append(error)
            elif self.listener is not None: self._close_socket(self.listener)
            for row in self.requests:
                try:
                    if row.get('closed') is not True: row['socket'].shutdown(socket.SHUT_RDWR)
                except OSError: pass
                except BaseException as error: self.failures.append(error)

    def endpoint(self):
        self._now()
        if not self.start_complete or self.stop_called: _fail('service_unavailable')
        return {'endpoint': 'http://' + self.server.expected_host, 'token': self.state.token}

    def close(self):
        if threading.current_thread() is not self.worker: _fail('wrong_worker')
        if self.close_called: return self._closed()
        self._context()
        self.close_called = True
        try:
            now = self.clock()
            if not _finite(now) or self.last is not None and now < self.last: _fail('clock_unknown')
            self.cleanup_until = self._cleanup_until_original = min(now + CLEANUP_SECONDS, self.until + CLEANUP_SECONDS)
        except BaseException as error:
            self.cleanup_clock_failure = error; self.failures.append(error)
            self.cleanup_deadline_expired = True
            self.cleanup_until = self._cleanup_until_original = self.until + CLEANUP_SECONDS
        # The actual FileCenter/media/audio originals close before State/HTTP.
        # A partial/unknown companion never grants directory release. Known
        # original State/HTTP cancellation below still occurs on refusal.
        try: self._close_filecenter()
        except BaseException as error: self.failures.append(error)
        # Expiry clips waits to zero; it must not bypass known originals.
        try: self._stop_server()
        except BaseException as error: self.failures.append(error)
        try: self._close_send_trial()
        except BaseException as error: self.failures.append(error)
        try:
            if (self.state is not None and type(self.probe_rows) is list and
                    self.state.probe_actors is self.probe_rows and self.state.operation is None):
                self.service_methods['_close_probes'](self.state,timeout=min(3.0,self._cleanup_remaining()),
                    cleanup_until=self._cleanup_until_original)
        except BaseException as error: self.failures.append(error)
        if self.state_complete:
            try:
                if self.state.operation is not None and (self.state.operation.kind!='go_send' or
                        self.state.operation is not self.send_trial.claimed_original):
                    _fail('state_operation_pending')
                self.state_close_called = True
                self.state_close_return = self.service_methods['close'](self.state,timeout=min(30.0,self._cleanup_remaining()))
            except BaseException as error: self.failures.append(error)
        for ticket in self.threads:
            value = ticket['thread']
            try:
                if ticket['initialized'] and ticket['called']:
                    value.join(self._cleanup_remaining())
                    ticket['ended'] = value.is_alive() is False
            except BaseException as error: ticket['failure'] = error; self.failures.append(error)
        for row in self.requests:
            try:
                if row.get('ticket') is None or row['ticket']['called'] is False or row['ticket']['ended']:
                    self._close_socket(row)
            except BaseException as error: self.failures.append(error)
        try: self._close_send_trial()
        except BaseException as error: self.failures.append(error)
        self._cleanup_remaining()
        try: self._close_directories()
        except BaseException as error: self.failures.append(error)
        self.close_complete = self._closed()
        return self.close_complete

    def _cleanup_remaining(self):
        with self.lock:
            self._context()
            if self.cleanup_until is not self._cleanup_until_original: _fail('cleanup_cap_changed')
            if self.cleanup_clock_failure is not None:return 0.0
            try:
                now=self.clock()
                if not _finite(now) or self.last is not None and now<self.last:_fail('clock_unknown')
                self.last=now
            except BaseException as error:
                self.cleanup_clock_failure=error;self.failures.append(error)
                self.cleanup_deadline_expired=True
                return 0.0
            remaining=max(0.0,self._cleanup_until_original-now)
            if remaining==0.0:self.cleanup_deadline_expired=True
            return remaining

    def _service_closed(self):
        if not self._http_passively_closed(): return False
        if self.service is not None:
            if (self.service_methods is not self._service_methods_original or
                    any(getattr(self.service.State, name) is not original
                        for name, original in self.service_methods.items())):
                return False
        if self.state_complete and (self.state is not self._state_original or
                type(self.state) is not self.service.State or self.state.closing is not True or
                self.service_methods['closed'](self.state) is not True or
                self.state.registry.lifecycle_status()['closure_verified'] is not True):
            return False
        if self.cleanup_deadline_expired or self.cleanup_clock_failure is not None:return False
        if self.state_called and not self.state_complete or self.server_called and not self.server_complete: return False
        if any(row['unknown'] or row['closed'] is not True for row in self.assets): return False
        if self.listener is not None and (self.listener['unknown'] or self.listener['closed'] is not True): return False
        if any(row.get('unknown', True) or row.get('closed') is not True for row in self.requests): return False
        if any(t['unknown'] or t['called'] and (not t['returned'] or not t['ended']) for t in self.threads): return False
        if self.state is not None and (type(self.probe_rows) is not list or self.state.probe_actors is not self.probe_rows or
                not self.service.State._probes_closed(self.state)): return False
        if self.state_complete and (not self.state_close_called or self.state_close_return is not True): return False
        if self.send_trial is not None:
            trial=self.loader.modules['mta_send_trial']
            if (self.send_trial_ticket['constructed'] is not True or
                    trial.FixedSendTrial.closed(self.send_trial,self.state) is not True):return False
        if self.send_preflight_ticket is not None and (self.send_preflight_ticket['unknown'] is not False or
                self.send_preflight_ticket['ended'] is not True or self.send_preflight_parent.closed is not True):return False
        if self.state is not None and self.state.operation is not None:
            op=self.state.operation
            if (op.kind!='go_send' or self.service.State._go_local_closed(self.state,op) is not True or
                    op.go_child_called and self.service.State._go_restoration_current(self.state,op) is not True):return False
        return True

    def status(self):
        actual_closed = self._closed() if self.close_called else False
        return {'kind': 'formal-send-filecenter-v1-fixed-service-owner', 'started': self.started,
                'directory_resources_closed': self.directory_close_complete and self._directory_inventory_closed(),
                'filecenter_created': bool(self.filecenter_ticket is not None and
                    self.filecenter_ticket['create_returned']),
                'filecenter_resources_closed': self._filecenter_closed(),
                'filecenter_credentials_issued': False,
                'guardian_producer_available': False,
                'startup_complete': self.start_complete, 'close_called': self.close_called,
                'service_resources_closed': actual_closed, 'resource_pending': not actual_closed,
                'state_constructor_complete': self.state_complete, 'server_constructor_complete': self.server_complete,
                'loop_failed': self.loop_failure is not None, 'startup_failed': self.failure is not None,
                'state_close_called': self.state_close_called, 'state_close_verified': self.state_close_return is True,
                'cleanup_deadline_expired':self.cleanup_deadline_expired,
                'assets': len(self.assets), 'requests': len(self.requests), 'threads': len(self.threads),
                'receive_available': False, 'send_available': bool(self.state is not None and
                    self.service.State._go_send_admitted(self.state)), 'scan_available': False,
                'send_trial_requested':self.send_trial_requested,
                'preparation_claimed':bool(self.send_trial is not None and self.send_trial.claim_count==1),
                'native_restored': False, 'phone_tested': False}


def main(argv=None):
    # Only a separately pinned outer envelope may load Boot first, then this
    # canonical Owner source, and call the fixed constructor. Loading Owner
    # before Boot would violate Boot's original namespace-busy guard.
    args = sys.argv[1:] if argv is None else argv
    if args:
        _fail('authenticated_fixed_sender_envelope_required')
    print('SOURCE_FORMAL_SEND service=false preparation=false native=false rf=false')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
