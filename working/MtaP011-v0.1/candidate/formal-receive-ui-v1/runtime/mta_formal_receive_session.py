"""Fixed formal receive integration: strict idle startup, passive receive closure.

SOURCE-authored independent copy. Fixed ordinary33/private35/native3, WPA and
one monitor extra are staged only into an absent formal-receive-v3 root; present
roots must be complete/exact. The focused non-UI entry does not repeat HTTP smoke.
There is no private-extension repair or install mode. The actual original Owner
observes Baseline/STATUS before its HTTP threads; no acquire or RF is granted.
The host supplies only the exact fixed bytes listed below.
Run in a fresh private, non-canonical module. Boot loads the real canonical
ordinary graph from its real fixed paths. Existing conflicts are preserved.
Individual mkdir/open creations are exclusive; no whole-tree atomicity claim.
Partial new project trees remain available for diagnosis, never removed here.
"""
import errno
import hashlib
import os
import re
import socket
import stat
import sys
import threading
import time
import types

STATE_ROOT = '/var/volatile/tmp/p011-mta-formal-receive-ui-v1'
STATE_ALIAS = '/tmp/p011-mta-formal-receive-ui-v1'
GO_ROOT = '/var/volatile/tmp/p011-mta-go-send-v76-assets'
USER_ROOT = '/mnt/data/p011-toolbox/user'
PENDING = '/var/volatile/tmp/p011-mta-p2p-device.pending'
PF_KTHREAD = 0x00200000  # Linux v4.14 include/linux/sched.h.
ROLE_PINS = (
    ('mta_client_executor', 117746, 'a195089707f5988ef7587283f0ec816fc4e2d57d0715047d7e51330ff03a506c'),
    ('p011_json', 8061, 'fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88'),
    ('mta_protocol', 17958, '4f7c2bd46cde114f0a2a0c33b31631aa463f09e71b156d26e34daf2251dd8a57'),
    ('mta_storage', 55562, 'ea3d3df1177019125c9b3124b8ebaf33196dd1013db95ac24580e1fe1a96c8d1'),
    ('mta_files', 10987, 'c6316be40cf34f017d1d2160f48989a55edfa0a60a2abe6a2ff6b656773f752b'),
    ('mta_crypto', 15274, '6fde6a60ec327895938a59990c4734a923dd5ff68bd5ee6979791df9a607e516'),
    ('mta_transfer_session', 20633, 'e7321ad446318f96bf84b1a94f0e5e3c76b1e973e28826f1c2514527b6967859'),
    ('mta_dhcp', 15719, '631987bd7307580af069f1978e440d21fbd449ecc62c83e0e06195c330f50176'),
    ('mta_dhcp_server', 20515, 'a34fdbc07a96f2ed3337872612510aa2a8b72b970a193f58b8045c0653b8d8bc'),
    ('mta_scoped_sockets', 26339, 'b95cfbe724b43baf90511c9d2a4a39d869a40a57e78e2a87d398ea134f9f84b8'),
    ('mta_transport', 40223, '171efb7cdfabbe4ea826afc03df6b401d1ee2b55cf23810e1fc7fb7b11f89826'),
    ('mta_sender', 33949, 'da25d3359d0759f71d8a4483680e3a3d5376c9e745e85224dbaee2a672f0670a'),
    ('mta_send_worker', 43252, 'de0dd8c2c0fb3b45923199ccc987ae057046fa0244c6a405c3a254850f7e68e7'),
    ('mta_scan_handoff', 11515, '51af67e80cf64038160cf420ad08f4f255a15dd9577e14fdcdb44fc26711046a'),
    ('mta_wifi', 28459, '62322b09fe4fd96bf6d49d8a2f7ac416e9a9d4dadcb3df23a6330e3205bcd017'),
    ('minhttp', 9690, 'bf5648457b19b60ad0f17320f8bd0431064f9cb4edf0d238d82136000eb57235'),
    ('mta_client_control_frame', 20942, 'd1a8fce91ab705524f14edac8d81e8d391c0cddbf8f4ac96ee7a6446c0512278'),
    ('mta_client_connect_handoff', 12229, 'c86ccf734d9370ce86c3532cdc58a488382a056dd6b1e2d45ab24d06f27a683d'),
    ('mta_client_tmp_alias', 8827, '1a4a52bd0bae7add6ae42f66bd9827c43865a0170c666eaab00797d1f45f7f2f'),
    ('mta_client_startup_readonly', 20426, '2e49f367ae1eb27e82c03ef675861639415ecbad9471a8c3a62b4999fd48ee73'),
    ('mta_client_receive_factory', 82666, 'd3944828b28428ac4b715c658374bc26eedc060ca2addc5631751928da0af3c5'),
    ('mta_client_state_bridge', 21284, '1eb369f21ea26583ca255e992f2d88590dc8ef7235b58326d85de589c33483e2'),
    ('mta_go_deployment', 26543, 'e8dc91c0a44a48d6cecf066257e79185fe590385f98300d01835edddb8114efe'),
    ('mta_send_preparation', 28532, '0e92fc68947601d0517cfe64a22d90d50b9952529c4594a6a189970420f69814'),
    ('mta_go_readonly_parent', 52873, '96873084af32bc8c7fe0c0a236ddb49f4b91b85677b1b9b966fe6c714c03724b'),
    ('mta_go_send_publication', 45133, '1f9d4f771d998d24677a6bc276526acaa96362a2ed508595690ad6ba19173f96'),
    ('mta_go_send_bridge', 87625, '027be64bf7b1b4f6ae57d09921b821e4cc77db44c602b9a5d99d901ed5736f02'),
    ('mta_go_readonly_terminal_parent', 66973, '42ef91c27805d080f80706097834c6a73e4d5fe7b7683533a60fb33e59025a7a'),
    ('mta_receive_radio_baseline', 3971, '27a1cf60be3f964862904233c600af11b8d3e9468febba61d8c622fceb29824c'),
    ('mta_receive_network', 15860, '1d2b2e250d63376f070816262fde601af5cd6005fb4f5877812f3d20ab8675a6'),
    ('mta_receive_barrier', 24113, 'd2721874aa6971b0742c4ae4b1dea9ba9bee277046ddb7253c3975b3dd6bf397'),
    ('mta_receive_trial', 64493, 'b3ffef7c593d254c375f8f4f0f97aa97cb7027db03e88861db639294dd1de13a'),
    ('mta_service', 155732, '76f48871bb4c2a3b72bb308e9bef56b3d509f01ef45c7ac2808d210acedd6960'),
    ('mta_client_receive_boot', 19709, '5a08582ccb0ca7c490b9c4d05a08045eb4da8c2cdff9cf6bbb671d24b06325c7'),
    ('mta_client_service_owner', 78661, '4eb75d7ee5c8f800b4ea8f31dbdac38edd36bc56a36bb11e7f7ef4519dbc60fb'),
)
HELPER_PINS = (
    ('mta-bluez-helper', 74920, 'c06398ddae281cf4a6f8a41953baf84795992f8f3e3769baebaf11f6d9964181'),
    ('mta-network-helper', 47464, 'ef3b904ef1017b6f0011b1e2cfcadbc98f9e8026933153ff0291699f32c525e6'),
    ('mta-connman-observer', 46008, '5f2612224a3db35d8f0850adf10d1fece7094bff6387521c185570c4be8068e2'),
)
PRIVATE_PINS = (
    ('p011_json', 8061, 'fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88'),
    ('mta_ip', 22049, '1fa5e72817772285fd966f52c57af105950ff0d3b6ea49b202983aebfbab40c5'),
    ('mta_client_tmp_alias', 8827, '1a4a52bd0bae7add6ae42f66bd9827c43865a0170c666eaab00797d1f45f7f2f'),
    ('mta_p2p_client_init', 71315, 'd3b51493d3ae778aeb72c1304dc50e5a6221428f7775bc7a28d15a3f19abeaaa'),
    ('mta_client_resource_budget', 16215, '56d6dbe2370279b1572a563e67fd3313bf942c0baa78fbd8e36cd973ba09839e'),
    ('mta_client_proc', 39384, 'ede5953c33ba4c17d3aecb1fffe8a9358589497b37e3109034d5e1de3eadb3d6'),
    ('mta_client_caps', 11821, 'c1792c2294fed5da16ec4a676423fbcbe53d44e9bc4ddadc1bc26fd45afe046c'),
    ('mta_client_caps_transport', 19614, 'df6b4cf3ede6039c684c6b689a8b61ffe1ba5b87259bb4a5581aa5c3ece84420'),
    ('mta_client_baseline', 29510, 'b74696eb4fa0586b254633f667eb588634700234cc30d8b49d5453e4592782bf'),
    ('mta_client_journal_codec', 17450, '2ffeca6b59498c9e2dfa4b9906bbe55db909d5d5e1d448fa0c795490996fe14a'),
    ('mta_client_coordination', 36295, '5b8a4295a5479cb5693182085fc8d35c6041bb0f14d9efb660ec11f024a5eeb3'),
    ('mta_client_files', 28938, '30c07bb4a5a28ce02aa76f35650ee1c87af63617f445e554c3fd7f73a2705864'),
    ('mta_client_pending', 57246, '14e85b8297868a7a07d964a598bc3cbc665e1e6cf19d615466e165386a27f524'),
    ('mta_client_store', 74676, 'bc51d3c64d3c92a87da331c740d93cea7466c535c5a81969422a45b8c5b68f63'),
    ('mta_client_process_owner', 34361, 'c144bc197a8fd1d4fbbfc358ba0172a84f5c9070058732189e4709c8c801ffeb'),
    ('mta_client_launch_registration', 21679, '833d46f5717e0b7e9db0c5392a0eb93d812d039b4b946a57d49d5903534a1aa0'),
    ('mta_client_two_phase_lease', 27606, 'c227989ec5188c272ad0a212974d569572704d3bb07c4c61c72670abcd0981a5'),
    ('mta_p2p_client_ctrl', 18712, '793b784f1b39eca18001aa65a1f0d6cdbd6de466dc58b3cf2ada167f71d902b5'),
    ('mta_client_wpa_status', 44902, 'b1d9ce5ed37c7249952804f3bb2979fbb15492a57ac1514396bfa5d0e0103128'),
    ('mta_protocol', 17958, '4f7c2bd46cde114f0a2a0c33b31631aa463f09e71b156d26e34daf2251dd8a57'),
    ('mta_client_control_frame', 20942, 'd1a8fce91ab705524f14edac8d81e8d391c0cddbf8f4ac96ee7a6446c0512278'),
    ('mta_client_kernel_proof', 23702, '4ebfedf198673e3bad2f64a4bd72c581e5d6af24cef83e589b4456d2a38f8ede'),
    ('mta_client_connection', 22494, 'ae2932252bbef16b89e6bf4614c2ebdb1721d507274dbd9b9fe4d9db1d0ff159'),
    ('mta_client_linux_provider', 174220, '5f080f8a0d53d7232ec95c303e0e84036d22d4e0927ac98dd3195291cf6d56ba'),
    ('mta_client_executor', 117746, 'a195089707f5988ef7587283f0ec816fc4e2d57d0715047d7e51330ff03a506c'),
    ('mta_dhcp', 15719, '631987bd7307580af069f1978e440d21fbd449ecc62c83e0e06195c330f50176'),
    ('mta_dhcp_client_core', 12362, '13c03d181139fd9ead7ff3bf2bcbb4930669f1e795b17360da85834dc345e9fa'),
    ('mta_dhcp_client', 24670, '794421678866d04a10ca46fa9eb7e17174f24c4d9e705cf59016b457702003a0'),
    ('mta_client_dora', 48149, 'f17f8405b28799fda8ee8f3ea9d280f871cceb1e0c6b999fc855bcb652ab2f7e'),
    ('mta_client_dynamic_ip', 32427, '01476613eb965a05cd5441dfbfea53f15ce763da12213b76791ecdb23152199a'),
    ('mta_client_peer', 31242, 'f8a15d046b505a8c5117a5be19d2ee59f38096759be1b29a0310535ceea08ec9'),
    ('mta_scoped_sockets', 26339, 'b95cfbe724b43baf90511c9d2a4a39d869a40a57e78e2a87d398ea134f9f84b8'),
    ('mta_storage', 55562, 'ea3d3df1177019125c9b3124b8ebaf33196dd1013db95ac24580e1fe1a96c8d1'),
    ('mta_transport', 40223, '171efb7cdfabbe4ea826afc03df6b401d1ee2b55cf23810e1fc7fb7b11f89826'),
    ('mta_client_transfer', 30747, '8633b2a1156c3012ec613e776eaee7e9339c14c76cffff9c8e5ff75646f35184'),
)
PRIVATE_PAYLOAD_PINS = tuple(('runtime35/' + name, size, sha) for name, size, sha in PRIVATE_PINS)
WPA_PIN = ('mta-wpa-supplicant', 1351192, 'e069aef76a089215367f502015266e9ce59cf4ebb7d7246974815ff60d67f301')
OBSERVER_NAME = 'mta-connman-observer'
MONITOR_PIN = ('receive_monitor', 13963, 'fe2a8bab0db21c45c6fe3d0a4733029492c8617d57ddbc9f296888c8c6837e36')
STOCK_PINS = (
    ('/usr/bin/Z03', 'cb8d6a78617d50f64c6adc8056427dd963bc83979cbb04e349275dd8e8ffb62a'),
    ('/usr/bin/control_engine', '364b0bf820799070e89d9362000de4a3796a0e6a2d5f4d657464c6385b8dbd6d'),
    ('/usr/bin/zyb_z03_launch.sh', '7bce5379e3cc78e5bd8c04ceb603c88814f24c3a7efd28105ecc3c5849d6a42b'),
)
BOOL_FIELDS = (
    'platform_validated', 'payload_validated', 'before_baseline_observed',
    'after_baseline_observed', 'stock_hashes_match', 'stock_processes_match',
    'baseline_unchanged', 'preflight_complete', 'stage_verified',
    'boot_loaded', 'owner_started', 'http_verified', 'gates_remained_closed',
    'operation_inventory_idle', 'capability_actors_closed', 'owner_close_called',
    'owner_resources_closed', 'runner_fds_closed', 'client_sockets_closed',
    'complete', 'resource_pending', 'staging_pending', 'private_assets_verified',
    'startup_readonly_called', 'startup_readonly_verified', 'startup_baseline_collected',
    'startup_status_verified', 'startup_resources_closed', 'interactive_window_requested',
)
COUNT_FIELDS = ('created_directory_count', 'created_file_count', 'runner_opened_fd_count',
                'runner_closed_fd_count', 'client_socket_count', 'http_request_count',
                'capability_actor_count', 'state_conflict_count', 'go_conflict_count',
                'startup_status_count', 'startup_proc_reader_count')
REASONS = ('not_started', 'complete', 'preflight_complete', 'startup_readonly', 'unsupported_platform',
           'payload', 'deadline', 'unsafe_anchor', 'source_changed', 'state_conflict',
           'go_conflict', 'foreign_worker', 'user_directory', 'stock_baseline',
           'baseline_changed', 'stage_io', 'stage_changed', 'namespace_busy',
           'boot', 'owner', 'http', 'gates_changed', 'close', 'unexpected')
_RETAINED = None


class ClosedServiceError(ValueError):
    def __init__(self, code):
        self.code = code
        ValueError.__init__(self, code)


def fail(code):
    raise ClosedServiceError(code) from None


def metadata(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid,
            value.st_gid, value.st_nlink, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)


class FixedSession(object):
    def __init__(self, artifacts, preflight_only, receive_trial_requested=False,
                 profile='diagnostic'):
        if (type(preflight_only) is not bool or type(receive_trial_requested) is not bool or
                preflight_only and receive_trial_requested or type(profile) is not str or
                profile not in ('diagnostic', 'receive-interactive-v1') or
                profile == 'receive-interactive-v1' and
                (preflight_only or not receive_trial_requested)): fail('payload')
        self.preflight_only = preflight_only
        self.receive_trial_requested = self._receive_trial_requested_original = receive_trial_requested
        self.trial_start_facts = self.trial_end_facts = None
        # Select one sealed, finite profile at construction, never renew a live
        # Owner/Gate/Session cap. Startup and all user actions spend this cap.
        self.profile = profile
        self.window_started_at = time.monotonic()
        self.until = self.window_started_at + (
            600.0 if profile == 'receive-interactive-v1' else 60.0)
        self.cleanup_until = self.until + 60.0
        self._window_original = self._window_retained = (
            profile, self.window_started_at, self.until, self.cleanup_until)
        self.worker = threading.current_thread()
        self.pid = os.getpid()
        self.rows, self.creations, self.clients, self.http = [], [], [], []
        self.process_scans = []
        self.process_no_exe_failures = []
        self.process_zombie_observations = []
        self.failures = []
        self.first_error = None
        self.boot = self.loader = self.owner_module = self.owner = None
        self.codec = None
        self.before = self.after = None
        self.startup_scope = self.startup_collection = self.startup_snapshot = None
        self.original_artifacts = artifacts
        self.artifacts = {}
        self.roots = {}
        self.anchor_fd = None
        self.anchor_edges, self.directory_edges, self.alias_rows = [], [], []
        self.result = dict((key, False) for key in BOOL_FIELDS)
        self.result.update(dict((key, 0) for key in COUNT_FIELDS))
        self.result['interactive_window_requested'] = profile == 'receive-interactive-v1'
        self.result['reason'] = 'not_started'

    def window_current(self):
        retained = self._window_retained
        return (type(retained) is tuple and len(retained) == 4 and
                self._window_original is retained and
                type(self.profile) is str and self.profile is retained[0] and
                type(self.window_started_at) is float and self.window_started_at is retained[1] and
                type(self.until) is float and self.until is retained[2] and
                type(self.cleanup_until) is float and self.cleanup_until is retained[3] and
                self.until - self.window_started_at == (
                    600.0 if self.profile == 'receive-interactive-v1' else 60.0) and
                self.cleanup_until - self.until == 60.0)

    def check(self, cleanup=False):
        if not self.window_current(): fail('payload')
        if os.getpid() != self.pid or threading.current_thread() is not self.worker:
            fail('foreign_worker')
        if time.monotonic() >= (self.cleanup_until if cleanup else self.until): fail('deadline')

    def platform(self):
        if (sys.platform != 'linux' or sys.byteorder != 'little' or os.geteuid() != 0 or
                os.uname()[4] != 'armv7l' or sys.version_info[:3] != (3, 5, 5) or
                os.O_NOFOLLOW != 0x8000 or os.O_CLOEXEC != 0x80000):
            fail('unsupported_platform')
        self.result['platform_validated'] = True

    def validate_payload(self):
        rows = self.original_artifacts
        expected = ROLE_PINS + HELPER_PINS + PRIVATE_PAYLOAD_PINS + (WPA_PIN, MONITOR_PIN)
        if type(rows) is not tuple or len(rows) != len(expected): fail('payload')
        total = 0
        for row, pin in zip(rows, expected):
            if (type(row) is not tuple or len(row) != 4 or row[:3] != pin or
                    type(row[3]) is not bytes or len(row[3]) != pin[1] or
                    hashlib.sha256(row[3]).hexdigest() != pin[2]): fail('payload')
            if pin[0] in self.artifacts: fail('payload')
            total += len(row[3]); self.artifacts[pin[0]] = row[3]
        if total > 4 * 1024 * 1024: fail('payload')
        self.result['payload_validated'] = True

    def open_fd(self, path, flags, mode=0o400, parent=None):
        row = {'fd': None, 'metadata': None, 'unknown': True, 'closed': False,
               'attempted': False, 'no_fd': False, 'error': None}
        self.rows.append(row)
        try:
            row['fd'] = os.open(path, flags | os.O_NOFOLLOW | os.O_CLOEXEC, mode,
                                **({} if parent is None else {'dir_fd': parent}))
            if type(row['fd']) is not int or not 0 <= row['fd'] <= 0x7fffffff: fail('stage_io')
            row['metadata'] = metadata(os.fstat(row['fd']))
            row['unknown'] = False
            return row
        except OSError as error:
            row['error'] = error
            if row['fd'] is None and type(error.errno) is int and 1 <= error.errno <= 4095:
                row['unknown'] = False; row['no_fd'] = True; row['closed'] = True
            raise
        except BaseException as error:
            row['error'] = error
            raise

    def close_fd(self, row):
        if row['attempted'] or row['no_fd']: return row['closed'] and not row['unknown']
        row['attempted'] = True
        try:
            count = 5 if row['metadata'] is not None and stat.S_ISDIR(row['metadata'][2]) else 6
            if row['unknown'] or row['metadata'] is None or metadata(os.fstat(row['fd']))[:count] != row['metadata'][:count]:
                fail('close')
            returned = os.close(row['fd'])
            try: os.fstat(row['fd'])
            except OSError as error:
                row['closed'] = returned is None and type(error.errno) is int and error.errno == errno.EBADF
            if not row['closed']: fail('close')
        except BaseException as error:
            row['error'] = error; row['unknown'] = True
            self.failures.append(error)
        return row['closed'] and not row['unknown']

    def read(self, path, limit, parent=None):
        self.check(True)
        row = self.open_fd(path, os.O_RDONLY, parent=parent)
        try:
            pieces, count = [], 0
            while count <= limit:
                self.check(True)
                raw = os.read(row['fd'], min(65536, limit + 1 - count))
                if type(raw) is not bytes: fail('stage_io')
                if not raw: break
                pieces.append(raw); count += len(raw)
            if count > limit: fail('stage_io')
            return b''.join(pieces)
        finally:
            if not self.close_fd(row): fail('close')

    def fingerprint(self, path, limit):
        initial = metadata(os.lstat(path))
        if not stat.S_ISREG(initial[2]) or initial[3] != 0 or initial[5] != 1: fail('unsafe_anchor')
        row = self.open_fd(path, os.O_RDONLY)
        try:
            if row['metadata'] != initial: fail('source_changed')
            digest, count = hashlib.sha256(), 0
            while True:
                self.check(True); block = os.read(row['fd'], 65536)
                if not block: break
                count += len(block)
                if count > limit: fail('source_changed')
                digest.update(block)
            if (count != initial[6] or metadata(os.fstat(row['fd'])) != initial or
                    metadata(os.lstat(path)) != initial): fail('source_changed')
            return (count, digest.hexdigest(), initial)
        finally:
            if not self.close_fd(row): fail('close')

    def process_stat(self, pid, parent=None):
        raw = self.read('/proc/' + str(pid) + '/stat' if parent is None else 'stat',
                        4096, parent=parent)
        begin, at = raw.index(b'('), raw.rindex(b')')
        fields = raw[at + 2:].split()
        # proc/array.c v4.14: fields after comm start at state (field 3),
        # flags is offset 6 (field 9), num_threads offset 17 (field 20),
        # start_time offset 19 (field 22).
        if (raw[:begin] != str(pid).encode('ascii') + b' ' or at <= begin or
                len(fields) < 20 or any(not fields[index].isdigit() for index in (1, 6, 17, 19))):
            fail('stock_baseline')
        parent_pid, flags, threads, started = (int(fields[1]), int(fields[6]),
                                              int(fields[17]), int(fields[19]))
        if (not 0 <= parent_pid <= 0x7fffffff or not 0 <= flags <= 0xffffffff or
                not 1 <= threads <= 0x7fffffff or not 0 <= started < (1 << 64)):
            fail('stock_baseline')
        state = (fields[0].decode('ascii') if fields[0] in
                 (b'R', b'S', b'D', b'T', b't', b'X', b'Z', b'P', b'I') else 'unknown')
        # State/thread count are private scanner observations, not part of
        # retained actor identity; process_identity's no-exe gate stays strict.
        return (pid, parent_pid, started, raw[begin + 1:at], flags, state, threads)

    def process_comm_class(self, comm):
        stock = (b'Z03', b'control_engine', b'weston', b'connmand',
                 b'bluetoothd', b'wpa_supplicant')
        python = (b'python', b'python3', b'python3.5')
        helpers = (b'mta-bluez-helper', b'mta-network-helper',
                   b'mta-wpa-supplicant', b'mta-wpa-cli', b'mta-wifi-caps')
        return ('stock6' if comm in stock else 'python' if comm in python else
                'mtahelper' if any(comm == name or comm == name[:15]
                                   for name in helpers) else 'other')

    def closed_other_zombie(self, pid, facts):
        # Scanner-only, bounded observation; never actor/parent identity or
        # proof of prior actor ownership, journal cleanup or receive admission.
        observed = {'first': facts, 'rows': [], 'rounds': [], 'edges': (),
                    'complete': False, 'fds_closed': False, 'error': None}
        self.process_zombie_observations.append(observed)
        try:
            if (facts[4] & PF_KTHREAD or facts[5] != 'Z' or facts[6] != 1 or
                    self.process_comm_class(facts[3]) != 'other'):
                fail('stock_baseline')
            proc_path = '/proc/' + str(pid)
            original = self.open_fd(proc_path, os.O_RDONLY | os.O_DIRECTORY)
            observed['rows'].append(original)
            task = self.open_fd('task', os.O_RDONLY | os.O_DIRECTORY, parent=original['fd'])
            observed['rows'].append(task)
            descriptors = self.open_fd('fd', os.O_RDONLY | os.O_DIRECTORY, parent=original['fd'])
            observed['rows'].append(descriptors)
            edges = ((None, proc_path, original), (original['fd'], 'task', task),
                     (original['fd'], 'fd', descriptors))
            observed['edges'] = edges

            def edges_current():
                self.check(True)
                for parent_fd, name, row in edges:
                    if (row['unknown'] or row['closed'] or row['metadata'] is None or
                            not stat.S_ISDIR(row['metadata'][2]) or
                            metadata(os.fstat(row['fd']))[:5] != row['metadata'][:5] or
                            metadata(os.lstat(name, **({} if parent_fd is None else
                                     {'dir_fd': parent_fd})))[:5] != row['metadata'][:5]):
                        fail('stock_baseline')

            def same_zombie(current):
                return (current[:4] == facts[:4] and not current[4] & PF_KTHREAD and
                        current[5] == 'Z' and current[6] == 1 and
                        self.process_comm_class(current[3]) == 'other')

            for unused in range(2):
                edges_current()
                row = {'head': None, 'tail': None, 'task': None, 'fd': None,
                       'cmdline': None, 'exe_errno': None}
                observed['rounds'].append(row)
                row['head'] = self.process_stat(pid, parent=original['fd'])
                if not same_zombie(row['head']): fail('stock_baseline')
                # Reset the held directories before each actual inventory;
                # never treat an already-consumed directory offset as empty.
                if (os.lseek(task['fd'], 0, os.SEEK_SET) != 0 or
                        os.lseek(descriptors['fd'], 0, os.SEEK_SET) != 0):
                    fail('stock_baseline')
                row['task'] = tuple(os.listdir(task['fd']))
                row['fd'] = tuple(os.listdir(descriptors['fd']))
                row['cmdline'] = self.read('cmdline', 16384, parent=original['fd'])
                if row['task'] != (str(pid),) or row['fd'] or row['cmdline']:
                    fail('stock_baseline')
                try: os.readlink('exe', dir_fd=original['fd'])
                except OSError as error:
                    row['exe_errno'] = error.errno
                    if type(error.errno) is not int or error.errno != errno.ENOENT: raise
                else: fail('stock_baseline')
                row['tail'] = self.process_stat(pid, parent=original['fd'])
                if not same_zombie(row['tail']): fail('stock_baseline')
                edges_current()
            observed['complete'] = True
        except OSError as error:
            # Candidate disappearance or any unknown observation is not a
            # race exemption; the scanner's original 32-race budget is intact.
            observed['error'] = error
            fail('stock_baseline')
        except BaseException as error:
            observed['error'] = error
            raise
        finally:
            closed = True
            for row in reversed(observed['rows']):
                if not self.close_fd(row): closed = False
            observed['fds_closed'] = closed
            if not closed and observed['error'] is None: fail('close')

    def process_identity(self, pid):
        facts = self.process_stat(pid)
        # A tracked stock actor or its retained parent must have an actual
        # userspace executable. Only the scanner's separate bounded classes
        # can classify an expected absent exe; never this identity API.
        if facts[4] & PF_KTHREAD: fail('stock_baseline')
        try: executable = os.readlink('/proc/' + str(pid) + '/exe')
        except OSError as error:
            if type(error.errno) is int and error.errno in (errno.ENOENT, errno.ESRCH):
                # exe -ENOENT alone does not prove that a PID disappeared.
                # Stable userspace/zombie/unknown no-exe remains a failure.
                current = self.process_stat(pid)
                diagnostic = {'state': current[5], 'comm_class': self.process_comm_class(current[3]),
                              'pf_kthread': bool(current[4] & PF_KTHREAD),
                              'identity_stable': (current[:4] == facts[:4] and
                                  bool(current[4] & PF_KTHREAD) == bool(facts[4] & PF_KTHREAD)),
                              'errno': error.errno}
                # Keep both original observations in private memory; emit
                # only bounded classifications, never PID/comm/exe/raw stat.
                self.process_no_exe_failures.append({'first': facts, 'current': current,
                                                     'diagnostic': diagnostic})
                print('PROCESS_NO_EXE_DIAGNOSTIC=' + repr(diagnostic))
                fail('stock_baseline')
            raise
        current = self.process_stat(pid)
        if current[:4] != facts[:4] or current[4] & PF_KTHREAD: fail('stock_baseline')
        return facts[:4] + (executable,)

    def processes(self, foreign=False):
        tracked = (b'Z03', b'control_engine', b'weston', b'connmand', b'bluetoothd', b'wpa_supplicant')
        scan = {'stable_kernel_no_exe_count': 0, 'stable_other_zombie_no_active_threads_count': 0,
                'races': 0, 'complete': False}
        self.process_scans.append(scan)
        output = []
        try:
            names = os.listdir('/proc')
            pids = sorted(int(name) for name in names if name.isdigit())
            if len(names) > 4096 or len(pids) > 512: fail('stock_baseline')
            for pid in pids:
                if pid == self.pid: continue
                facts = None
                try:
                    facts = self.process_stat(pid)
                    if facts[4] & PF_KTHREAD:
                        if facts[3] in tracked: fail('stock_baseline')
                        try: os.readlink('/proc/' + str(pid) + '/exe')
                        except OSError as error:
                            if type(error.errno) is not int or error.errno != errno.ENOENT: raise
                            current = self.process_stat(pid)
                            if current[:4] != facts[:4] or not current[4] & PF_KTHREAD:
                                fail('stock_baseline')
                            # Do not compare scheduling state/CPU counters or
                            # unrelated changing task flags; this bit is actual.
                            scan['stable_kernel_no_exe_count'] += 1
                            continue
                        fail('stock_baseline')  # Unexpected kthread executable.
                    if facts[5] == 'Z' and self.process_comm_class(facts[3]) == 'other':
                        self.closed_other_zombie(pid, facts)
                        scan['stable_other_zombie_no_active_threads_count'] += 1
                        continue
                    row = self.process_identity(pid)
                    if row[:4] != facts[:4]: fail('stock_baseline')
                    if foreign:
                        command = self.read('/proc/' + str(pid) + '/cmdline', 16384)
                        if (row[4] == '/usr/bin/python3.5' or
                                any(root.encode('ascii') in command for root in (STATE_ROOT, STATE_ALIAS, GO_ROOT))):
                            fail('foreign_worker')
                    if row[3] not in tracked: continue
                    parent = self.process_identity(row[1])
                    if self.process_identity(pid) != row or self.process_identity(row[1]) != parent:
                        fail('stock_baseline')
                    output.append((row, parent))
                except OSError as error:
                    if facts is not None and facts[3] in tracked: fail('stock_baseline')
                    if type(error.errno) is int and error.errno in (errno.ENOENT, errno.ESRCH):
                        try: self.process_stat(pid)
                        except OSError as missing:
                            if type(missing.errno) is not int or missing.errno not in (errno.ENOENT, errno.ESRCH):
                                raise
                        else: fail('stock_baseline')
                        scan['races'] += 1
                        if scan['races'] > 32: fail('stock_baseline')
                    else: raise
            scan['complete'] = True
            return tuple(output)
        finally:
            # Private scalar observation only, no PID/name/raw stat or gate.
            print('PROCESS_SCAN_COUNTS=' + repr((scan['stable_kernel_no_exe_count'], scan['races'])))
            print('PROCESS_ZOMBIE_COUNTS=' + repr(scan['stable_other_zombie_no_active_threads_count']))

    def snapshot(self):
        self.check(True)
        try: pending = self.fingerprint(PENDING, 65536)
        except OSError as error:
            if type(error.errno) is int and error.errno == errno.ENOENT: pending = None
            else: raise
        devices = []
        for name in sorted(os.listdir('/sys/class/net')):
            if not re.match(r'^[A-Za-z0-9_.:-]{1,15}$', name): fail('stock_baseline')
            raw = self.read('/sys/class/net/' + name + '/ifindex', 32).strip()
            if not raw.isdigit() or not 0 < int(raw) <= 0x7fffffff: fail('stock_baseline')
            devices.append((name, int(raw)))
        if len(devices) > 64: fail('stock_baseline')
        return {'stock': tuple((path, self.fingerprint(path, 134217728)) for path, pin in STOCK_PINS),
                'boot': self.read('/proc/sys/kernel/random/boot_id', 128),
                'pending': pending, 'routes': self.read('/proc/net/route', 1048576),
                'netdev': tuple(devices), 'processes': self.processes()}

    def anchors(self):
        self.check()
        prior = None
        expected = (('/', 0o755), ('var', 0o755), ('volatile', 0o1777), ('tmp', 0o1777))
        for name, mode in expected:
            row = self.open_fd(name, os.O_RDONLY | os.O_DIRECTORY, parent=prior)
            if (not stat.S_ISDIR(row['metadata'][2]) or stat.S_IMODE(row['metadata'][2]) != mode or
                    row['metadata'][3:5] != (0, 0)): fail('unsafe_anchor')
            self.anchor_edges.append((prior, name, row))
            prior = row['fd']
        self.anchor_fd = prior
        for path, target in (('/tmp', '/var/tmp'), ('/var/tmp', '/var/volatile/tmp')):
            value = metadata(os.lstat(path))
            if (value[2] != stat.S_IFLNK | 0o777 or value[3:6] != (0, 0, 1) or
                    value[6] != len(target) or os.readlink(path) != target): fail('unsafe_anchor')
            self.alias_rows.append((path, value, target))

    def anchors_current(self):
        # Own child creation changes directory nlink/mtime, not identity,
        # type/permissions/uid/gid or its original parent/name relationship.
        self.check()
        if len(self.anchor_edges) != 4 or len(self.alias_rows) != 2: fail('stage_changed')
        for parent, name, row in self.anchor_edges + self.directory_edges:
            if row['unknown'] or row['closed'] or row['metadata'] is None: fail('stage_changed')
            current = metadata(os.fstat(row['fd']))
            named = metadata(os.stat(name, follow_symlinks=False,
                                     **({} if parent is None else {'dir_fd': parent})))
            if current[:5] != row['metadata'][:5] or named[:5] != row['metadata'][:5]:
                fail('stage_changed')
        for path, original, target in self.alias_rows:
            if metadata(os.lstat(path)) != original or os.readlink(path) != target:
                fail('stage_changed')

    def directory(self, parent, name, conflict):
        row = self.open_fd(name, os.O_RDONLY | os.O_DIRECTORY, parent=parent)
        if (not stat.S_ISDIR(row['metadata'][2]) or stat.S_IMODE(row['metadata'][2]) != 0o700 or
                row['metadata'][3:5] != (0, 0)): fail(conflict)
        if metadata(os.stat(name, dir_fd=parent, follow_symlinks=False))[:5] != row['metadata'][:5]:
            fail(conflict)
        self.directory_edges.append((parent, name, row))
        return row

    def file(self, parent, name, pin, mode, conflict):
        initial = metadata(os.stat(name, dir_fd=parent, follow_symlinks=False))
        if (not stat.S_ISREG(initial[2]) or stat.S_IMODE(initial[2]) != mode or
                initial[3:6] != (0, 0, 1) or initial[6] != pin[1]): fail(conflict)
        row = self.open_fd(name, os.O_RDONLY, parent=parent)
        try:
            if row['metadata'] != initial: fail(conflict)
            data, count = [], 0
            while count <= pin[1]:
                self.check(); raw = os.read(row['fd'], min(65536, pin[1] + 1 - count))
                if not raw: break
                data.append(raw); count += len(raw)
            observed = b''.join(data)
            if (observed != self.artifacts[pin[0]] or count != pin[1] or
                    hashlib.sha256(observed).hexdigest() != pin[2] or
                    metadata(os.fstat(row['fd'])) != initial or
                    metadata(os.stat(name, dir_fd=parent, follow_symlinks=False)) != initial): fail(conflict)
            return initial
        finally:
            if not self.close_fd(row): fail('close')

    def inspect_root(self, kind):
        name = os.path.basename(STATE_ROOT if kind == 'state' else GO_ROOT)
        conflict = 'state_conflict' if kind == 'state' else 'go_conflict'
        try: meta = metadata(os.stat(name, dir_fd=self.anchor_fd, follow_symlinks=False))
        except OSError as error:
            if type(error.errno) is int and error.errno == errno.ENOENT:
                return {'present': False, 'name': name, 'row': None, 'runtime': None,
                        'native': None, 'runtime35': None, 'wpa_present': False, 'files': ()}
            raise
        root = self.directory(self.anchor_fd, name, conflict)
        if root['metadata'] != meta: fail(conflict)
        root_names = set(os.listdir(root['fd']))
        if kind == 'state' and root_names != {'runtime', 'native', 'runtime35', OBSERVER_NAME}:
            fail(conflict)
        runtime = self.directory(root['fd'], 'runtime', conflict)
        private, wpa_present = None, False
        if kind == 'state':
            roles = tuple(pin for pin in ROLE_PINS if pin[0] != 'mta_go_deployment')
            if set(os.listdir(runtime['fd'])) != {pin[0] + '.py' for pin in roles} | {MONITOR_PIN[0] + '.py'}: fail(conflict)
            native = self.directory(root['fd'], 'native', conflict)
            native_names = set(os.listdir(native['fd']))
            helpers = {pin[0] for pin in HELPER_PINS if pin[0] != OBSERVER_NAME}
            if native_names != helpers | {WPA_PIN[0]}: fail(conflict)
            wpa_present = WPA_PIN[0] in native_names
            if 'runtime35' in root_names:
                private = self.directory(root['fd'], 'runtime35', conflict)
                if set(os.listdir(private['fd'])) != {pin[0] + '.py' for pin in PRIVATE_PINS}:
                    fail(conflict)  # Preserve partial/conflicting existing trees; no fill/repair.
        else:
            roles = tuple(pin for pin in ROLE_PINS if pin[0] == 'mta_go_deployment')
            native = None
        files = tuple((pin[0], self.file(runtime['fd'], pin[0] + '.py', pin, 0o400, conflict)) for pin in roles)
        if native is not None:
            files += tuple((pin[0], self.file(native['fd'], pin[0], pin, 0o500, conflict))
                           for pin in HELPER_PINS if pin[0] != OBSERVER_NAME)
            observer = tuple(pin for pin in HELPER_PINS if pin[0] == OBSERVER_NAME)
            if len(observer) != 1: fail(conflict)
            files += ((OBSERVER_NAME, self.file(root['fd'], OBSERVER_NAME, observer[0], 0o700, conflict)),)
            files += ((MONITOR_PIN[0], self.file(runtime['fd'], MONITOR_PIN[0] + '.py', MONITOR_PIN, 0o400, conflict)),)
            if wpa_present:
                files += ((WPA_PIN[0], self.file(native['fd'], WPA_PIN[0], WPA_PIN, 0o500, conflict)),)
        if private is not None:
            files += tuple((pin[0], self.file(private['fd'], source[0] + '.py', pin, 0o400, conflict))
                           for source, pin in zip(PRIVATE_PINS, PRIVATE_PAYLOAD_PINS))
        if set(os.listdir(root['fd'])) != root_names: fail(conflict)
        if kind == 'state' and (set(os.listdir(runtime['fd'])) != {pin[0] + '.py' for pin in roles} | {MONITOR_PIN[0] + '.py'} or
                set(os.listdir(native['fd'])) != native_names or private is not None and
                set(os.listdir(private['fd'])) != {pin[0] + '.py' for pin in PRIVATE_PINS}):
            fail(conflict)
        return {'present': True, 'name': name, 'row': root, 'runtime': runtime,
                'native': native, 'runtime35': private, 'wpa_present': wpa_present, 'files': files}

    def user_directory(self):
        # Existing Received is mandatory: the actual Owner must not need mkdir.
        parent = None
        for name in ('/', 'mnt', 'data', 'p011-toolbox', 'user', 'Received'):
            row = self.open_fd(name, os.O_RDONLY | os.O_DIRECTORY, parent=parent)
            meta = row['metadata']
            if not stat.S_ISDIR(meta[2]) or meta[2] & 0o022: fail('user_directory')
            if name == 'data':
                if meta[:5] != (66328, 21, stat.S_IFDIR | 0o755, 1000, 1000): fail('user_directory')
            elif meta[3:5] != (0, 0): fail('user_directory')
            if name in ('p011-toolbox', 'user', 'Received') and stat.S_IMODE(meta[2]) != 0o700:
                fail('user_directory')
            parent = row['fd']

    def preflight(self):
        self.anchors(); self.user_directory(); self.processes(foreign=True)
        errors = []
        for kind in ('state', 'go'):
            try: self.roots[kind] = self.inspect_root(kind)
            except BaseException as error:
                self.result[kind + '_conflict_count'] += 1
                errors.append(error)
        if errors:
            self.failures.extend(errors[1:]); raise errors[0]
        state = self.roots['state']
        self.result['private_assets_verified'] = state['runtime35'] is not None and state['wpa_present']
        self.result['preflight_complete'] = True

    def new_directory(self, parent, name):
        self.anchors_current()
        creation = {'kind': 'directory', 'name': name, 'parent': parent,
                    'attempted': True, 'returned': False, 'error': None}
        self.creations.append(creation)
        try:
            os.mkdir(name, 0o700, dir_fd=parent)
            creation['returned'] = True
            self.result['created_directory_count'] += 1
            row = self.directory(parent, name, 'stage_changed')
            self.anchors_current()
            return row
        except BaseException as error:
            creation['error'] = error; raise

    def new_file(self, parent, name, pin, mode):
        self.anchors_current()
        creation = {'kind': 'file', 'name': name, 'parent': parent,
                    'attempted': True, 'returned': False, 'error': None}
        self.creations.append(creation)
        row = None
        try:
            row = self.open_fd(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode, parent)
            creation['returned'] = True
            self.result['created_file_count'] += 1
            self.anchors_current()
            original = row['metadata']
            if (not stat.S_ISREG(original[2]) or stat.S_IMODE(original[2]) != mode or
                    original[3:6] != (0, 0, 1) or original[6] != 0): fail('stage_io')
            data, offset = self.artifacts[pin[0]], 0
            while offset < len(data):
                self.anchors_current(); written = os.write(row['fd'], data[offset:offset + 65536])
                if type(written) is not int or not 1 <= written <= min(65536, len(data) - offset): fail('stage_io')
                offset += written
                self.anchors_current()
            os.fsync(row['fd'])
            row['metadata'] = metadata(os.fstat(row['fd']))
            if (row['metadata'][:6] != original[:6] or row['metadata'][6] != len(data) or
                    metadata(os.stat(name, dir_fd=parent, follow_symlinks=False)) != row['metadata']): fail('stage_io')
        except BaseException as error:
            creation['error'] = error; raise
        finally:
            if row is not None and not self.close_fd(row): fail('close')
        # A WRONLY creation FD cannot read; reopen and check original inode.
        observed = self.file(parent, name, pin, mode, 'stage_changed')
        if observed != row['metadata']: fail('stage_changed')
        self.anchors_current()

    def stage_precheck(self):
        if not self.result['preflight_complete'] or self.preflight_only: fail('stage_io')
        self.anchors_current(); self.processes(foreign=True)
        for kind in ('state', 'go'):
            initial = self.roots[kind]
            current = self.inspect_root(kind)
            if current['present'] != initial['present']: fail('stage_changed')
            if current['present']:
                if (current['row']['metadata'] != initial['row']['metadata'] or
                        current['runtime']['metadata'] != initial['runtime']['metadata'] or
                        current['files'] != initial['files']): fail('stage_changed')

    def stage(self):
        self.stage_precheck()
        # All existing roots were inspected before the first mkdir/write.
        for kind in ('state', 'go'):
            original = self.roots[kind]
            if original['present']: continue
            root = self.new_directory(self.anchor_fd, original['name'])
            runtime = self.new_directory(root['fd'], 'runtime')
            if kind == 'state':
                native = self.new_directory(root['fd'], 'native')
                private = self.new_directory(root['fd'], 'runtime35')
                for pin in ROLE_PINS:
                    if pin[0] != 'mta_go_deployment': self.new_file(runtime['fd'], pin[0] + '.py', pin, 0o400)
                for pin in HELPER_PINS:
                    if pin[0] == OBSERVER_NAME: self.new_file(root['fd'], pin[0], pin, 0o700)
                    else: self.new_file(native['fd'], pin[0], pin, 0o500)
                self.new_file(runtime['fd'], MONITOR_PIN[0] + '.py', MONITOR_PIN, 0o400)
                self.new_file(native['fd'], WPA_PIN[0], WPA_PIN, 0o500)
                for source_pin, pin in zip(PRIVATE_PINS, PRIVATE_PAYLOAD_PINS):
                    self.new_file(private['fd'], source_pin[0] + '.py', pin, 0o400)
                os.fsync(private['fd']); os.fsync(native['fd'])
            else:
                pin = next(pin for pin in ROLE_PINS if pin[0] == 'mta_go_deployment')
                self.new_file(runtime['fd'], pin[0] + '.py', pin, 0o400)
            os.fsync(runtime['fd']); os.fsync(root['fd']); os.fsync(self.anchor_fd)
        for kind in ('state', 'go'): self.roots[kind] = self.inspect_root(kind)
        self.anchors_current()
        state = self.roots['state']
        if state['runtime35'] is None or not state['wpa_present']: fail('stage_changed')
        self.result['private_assets_verified'] = True
        self.result['stage_verified'] = True

    def idle(self):
        state = self.owner.state
        return (state.receive_available is False and state.send_available is False and
                self.owner.service.State._receive_trial_available(state) is False and
                state.scan_available is False and state.operation is None and state.session is None and
                all(getattr(state, name) is None for name in ('helper', 'key', 'crypto', 'lease', 'transport', 'worker')) and
                state.discoverable is False and state.scanning is False)

    def original_receive_ui_idle(self):
        """Original empty inventory, not a closed admission or RF receipt.

        The fixed receive-only UI may show an unclaimed ready gate or a real
        refusal. It cannot clear a pending record, accept a foreign gate, reuse
        a claim, hide a partial Session or reset the original service deadline.
        binds() is a passive original-source check; no startup IO is repeated.
        The existing idle() deliberately retains its closed-policy meaning.
        """
        try:
            owner, loader = self.owner, self.loader
            if (owner is None or loader is None or
                    self.receive_trial_requested is not True or
                    self._receive_trial_requested_original is not True or
                    owner.receive_trial_requested is not True or
                    owner._receive_trial_requested_original is not True or
                    owner.start_complete is not True or owner.stop_called is not False or
                    owner.close_called is not False):
                return False
            service = loader.modules.get('mta_service')
            gate_module = loader.modules.get('mta_receive_trial')
            state, trial = owner.state, owner.receive_trial
            if (type(service) is not types.ModuleType or owner.service is not service or
                    sys.modules.get('mta_service') is not service or type(state) is not service.State or
                    state is not owner._state_original or type(gate_module) is not types.ModuleType or
                    sys.modules.get('mta_receive_trial') is not gate_module or
                    type(trial) is not gate_module.FixedReceiveTrial or trial is not owner._receive_trial_original):
                return False
            with state.lock:
                return (service.State._receive_trial_exact(state) is True and
                    trial is state._receive_trial_original and trial.requested is True and
                    trial.revoked is False and trial.expired is False and trial.failure is None and
                    type(trial.claim_count) is int and trial.claim_count == 0 and
                    trial.claimed_operation is None and trial._claimed_operation_original is None and
                    trial.session is None and trial._session_original is None and
                    state.state == 'idle' and state.closing is False and
                    state.receive_available is False and state.send_available is False and
                    state.scan_available is False and state.operation is None and state.session is None and
                    all(getattr(state, name) is None for name in
                        ('helper', 'key', 'crypto', 'lease', 'transport', 'worker')) and
                    state.discoverable is False and state.scanning is False and
                    state.wifi_restore_pending is False and state.radio_restore_pending is False)
        except (AttributeError, KeyError, TypeError, ValueError, RuntimeError):
            return False

    def load_owner(self):
        if any(type(name) is str and name.startswith(('mta_', 'p011_')) for name in sys.modules):
            fail('namespace_busy')
        self.boot = types.ModuleType('mta_client_receive_boot')
        self.boot.__file__ = STATE_ALIAS + '/runtime/mta_client_receive_boot.py'
        sys.modules[self.boot.__name__] = self.boot
        exec(self.artifacts['mta_client_receive_boot'], self.boot.__dict__)
        self.loader = self.boot.BootSourceLoader.__new__(self.boot.BootSourceLoader)
        self.boot.BootSourceLoader.__init__(self.loader, self.until)
        self.loader.load(); self.result['boot_loaded'] = True
        if (self.loader.pending or self.loader.failure is not None or len(self.loader.modules) != 33 or
                any(row['closed'] is not True or row['unknown'] for row in self.loader.rows)): fail('boot')
        self.owner_module = types.ModuleType('startup_readonly_private_owner')
        self.owner_module.__file__ = STATE_ALIAS + '/runtime/mta_client_service_owner.py'
        exec(self.artifacts['mta_client_service_owner'], self.owner_module.__dict__)
        self.codec = self.loader.modules['p011_json']
        creator = self.owner_module.FixedStateServiceOwner
        self.owner = creator.__new__(creator)
        creator.__init__(self.owner, self.loader, self.loader._original_until,
                         receive_trial_requested=self._receive_trial_requested_original)
        self.owner.start(); self.result['owner_started'] = True
        self.trial_start_facts = self.owner.receive_trial.public_facts()
        self.verify_startup()
        if self._receive_trial_requested_original:
            if not self.original_receive_ui_idle(): fail('gates_changed')
        elif not self.idle(): fail('gates_changed')
        # An empty inventory with a ready receive gate is not closed-policy
        # evidence. The service refusal check still requires actual False.
        self.result['gates_remained_closed'] = self.idle()
        self.result['operation_inventory_idle'] = True

    def retain_startup(self):
        # Preserve original producer objects, even after a failed Owner.start().
        # This passive adoption is not permission to re-run an observation.
        owner = self.owner
        if owner is None:
            return None
        scope = getattr(owner, 'startup_scope', None)
        if scope is None:
            return None
        if self.startup_scope is None:
            self.startup_scope = scope
        if (scope is not self.startup_scope or scope is not owner._startup_scope_original or
                owner.factory is None or scope is not owner.factory._startup_scope or
                scope.owner is not owner or scope.factory is not owner.factory):
            fail('startup_readonly')
        ticket = getattr(scope, 'collector_ticket', None)
        collection = ticket.get('returned') if type(ticket) is dict else None
        if collection is not None:
            if self.startup_collection is None:
                self.startup_collection = collection
            if collection is not self.startup_collection:
                fail('startup_readonly')
            snapshot = getattr(collection, 'snapshot', None)
            if snapshot is not None:
                if self.startup_snapshot is None:
                    self.startup_snapshot = snapshot
                if snapshot is not self.startup_snapshot:
                    fail('startup_readonly')
        return scope

    def startup_closed(self):
        # Known original resource inventories only; no new clock/IO/read grant.
        try:
            scope = self.retain_startup()
            if scope is None or scope.closed() is not True:
                return False
            ticket = scope.collector_ticket
            if type(ticket) is not dict:
                return scope.collector_called is False and ticket is None
            module = self.loader.modules.get('mta_client_startup_readonly')
            collection = self.startup_collection
            return (type(module) is types.ModuleType and
                sys.modules.get('mta_client_startup_readonly') is module and
                ticket.get('creator') is module.StartupCollection and
                collection is ticket.get('returned') and type(collection) is module.StartupCollection and
                collection.scope is scope and scope._collection() is collection and
                collection.resources_closed() is True)
        except BaseException:
            return False

    def verify_startup(self):
        # Owner completed this producer synchronously before its Server/threads.
        # A displayed boolean is insufficient: require the retained originals.
        self.check()
        owner = self.owner
        self.result['startup_readonly_called'] = owner.startup_called is True
        scope = self.retain_startup()
        module = self.loader.modules.get('mta_client_startup_readonly')
        if (type(module) is not types.ModuleType or
                sys.modules.get('mta_client_startup_readonly') is not module or
                owner._startup_module_original is not module or
                owner._startup_collect_original is not module.collect or
                owner._startup_collection_type_original is not module.StartupCollection or
                owner.startup_called is not True or owner.startup_complete is not True or
                owner.startup_failure is not None or scope is None or scope.success is not True or
                scope.failure is not None or scope.collector_called is not True):
            fail('startup_readonly')
        ticket, collection = scope.collector_ticket, self.startup_collection
        if (type(ticket) is not dict or ticket.get('creator') is not module.StartupCollection or
                ticket.get('returned') is not collection or owner.startup_result is not collection or
                ticket.get('started') is not True or ticket.get('ended') is not True or
                ticket.get('failure') is not None or type(collection) is not module.StartupCollection or
                collection.scope is not scope or scope._collection() is not collection or
                collection.attempted is not True or collection.ended is not True or
                collection.success is not True or collection.failure is not None or
                collection.io_started is not True):
            fail('startup_readonly')
        private = scope.private_modules
        baseline, proc, status, store, core = (private[name] for name in
            ('mta_client_baseline', 'mta_client_proc', 'mta_client_wpa_status',
             'mta_client_store', 'mta_p2p_client_init'))
        if (collection.modules is not private or baseline.proc is not proc or baseline.core is not core or
                status.proc is not proc or status.core is not core or status.baseline is not baseline or
                store.proc is not proc or store.core is not core):
            fail('startup_readonly')
        collector, snapshot = collection.collector, self.startup_snapshot
        if (collector is not collection._collector_original or
                type(collector) is not collection._native_class or type(snapshot) is not core.Snapshot or
                snapshot is not collection.snapshot or collector._snapshot is not snapshot or
                type(collector._rounds) is not list or len(collector._rounds) != 2 or
                collector._rounds[1] is not snapshot or
                type(collection.status_rows) is not list or len(collection.status_rows) != 2 or
                type(collection.reader_rows) is not list or len(collection.reader_rows) != 3):
            fail('startup_readonly')
        self.result['startup_baseline_collected'] = True
        for row in collection.status_rows:
            source, reader, value = row['source'], row['reader'], row['value']
            if (type(source) is not status.LinuxStatusSource or
                    type(reader) is not status.AuthenticatedStatusReader or
                    reader._source is not source or type(value) is not dict or reader._result is not value or
                    value.get('completed') is not True or value.get('source_authenticated') is not True or
                    row['failure'] is not None):
                fail('startup_readonly')
            facts = reader.status()
            if (facts.get('read_success') is not True or facts.get('socket_closed') is not True or
                    facts.get('resource_pending') is not False):
                fail('startup_readonly')
        self.result['startup_status_count'] = len(collection.status_rows)
        self.result['startup_proc_reader_count'] = len(collection.reader_rows)
        self.result['startup_status_verified'] = True
        self.result['startup_resources_closed'] = self.startup_closed()
        if self.result['startup_resources_closed'] is not True:
            fail('startup_readonly')
        self.result['startup_readonly_verified'] = True

    def close_client(self, row):
        if row['attempted']: return row['closed'] and not row['unknown']
        row['attempted'] = True
        try:
            with self.owner.lock:
                sock = row['socket']
                if (row['unknown'] or sock is not row['original'] or sock.fileno() != row['fd'] or
                        metadata(os.fstat(row['fd'])) != row['metadata']): fail('close')
                returned = sock.close()
                try: os.fstat(row['fd'])
                except OSError as error:
                    row['closed'] = returned is None and type(error.errno) is int and error.errno == errno.EBADF
                if not row['closed']: fail('close')
        except BaseException as error:
            row['error'] = error; row['unknown'] = True; self.failures.append(error)
        return row['closed'] and not row['unknown']

    def client_timeout(self, sock):
        self.check()
        remaining = min(5.0, self.until - time.monotonic())
        if remaining <= 0: fail('deadline')
        sock.settimeout(remaining)

    def request(self, method, path, token=None, value=None):
        self.check()
        server = self.owner.server
        if not self.idle(): fail('gates_changed')
        row = {'socket': None, 'original': None, 'fd': None, 'metadata': None,
               'attempted': False, 'closed': False, 'unknown': True, 'error': None}
        self.clients.append(row)
        headers = [method + ' ' + path + ' HTTP/1.1', 'Host: ' + server.expected_host,
                   'Connection: close']
        body = b'' if value is None else self.codec.dumps(value).encode('utf-8')
        if token is not None: headers.append('X-P011-MTA-Token: ' + token)
        if value is not None:
            headers.extend(('Content-Type: application/json', 'Content-Length: ' + str(len(body))))
        payload = ('\r\n'.join(headers) + '\r\n\r\n').encode('ascii') + body
        try:
            with self.owner.lock:
                previous_count = len(self.owner.requests)
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                row['socket'] = row['original'] = sock
                row['fd'] = sock.fileno(); row['metadata'] = metadata(os.fstat(row['fd']))
                if type(row['fd']) is not int or row['fd'] < 0 or not stat.S_ISSOCK(row['metadata'][2]): fail('http')
                row['unknown'] = False
            self.client_timeout(sock); sock.connect(server.server_address)
            client_address = sock.getsockname()
            server_row = None
            # Correlate the exact accepted peer before sending HTTP bytes.
            # No next client is allocated while this retained server row runs.
            barrier_until = min(self.until, time.monotonic() + 3.0)
            while server_row is None:
                self.check()
                if time.monotonic() >= barrier_until: fail('http')
                with self.owner.lock:
                    if len(self.owner.requests) > previous_count + 1: fail('http')
                    if len(self.owner.requests) == previous_count + 1:
                        candidate = self.owner.requests[previous_count]
                        ticket = candidate.get('ticket')
                        if (ticket is not None and ticket.get('returned') is True and
                                candidate.get('unknown') is False and candidate.get('closed') is False):
                            if (candidate['socket'] is not candidate['socket_original'] or
                                    candidate['socket'].getpeername() != client_address or
                                    ticket is not candidate.get('ticket_original') or
                                    ticket['thread'] is not ticket['thread_original']): fail('http')
                            server_row = candidate
                if server_row is None: time.sleep(.01)
            row['server_row'] = server_row
            self.client_timeout(sock); sock.sendall(payload)
            raw = b''
            while b'\r\n\r\n' not in raw:
                self.client_timeout(sock); part = sock.recv(4096)
                if not part: fail('http')
                raw += part
                if len(raw) > 1048576: fail('http')
            head, body = raw.split(b'\r\n\r\n', 1)
            lines = head.decode('ascii').split('\r\n')
            match = re.match(r'^HTTP/1\.[01] ([0-9]{3})(?: |$)', lines[0])
            lengths = [line.split(':', 1)[1].strip() for line in lines[1:] if line.lower().startswith('content-length:')]
            if not match or len(lengths) != 1 or not lengths[0].isdigit(): fail('http')
            length = int(lengths[0])
            if not 0 < length <= 1048576: fail('http')
            while len(body) < length:
                self.client_timeout(sock); part = sock.recv(min(65536, length - len(body)))
                if not part: fail('http')
                body += part
            if len(body) != length: fail('http')
            decoded = self.codec.loads(body.decode('utf-8'))
            if type(decoded) is not dict: fail('http')
            # Bodies, including bootstrap token/filenames, remain memory-only.
            self.http.append({'method': method, 'path': path, 'code': int(match.group(1)), 'body': decoded})
            self.result['http_request_count'] += 1
            # Receiving a response is not proof of server-side closure.
            # The Owner will perform its own original joins during close().
            barrier_until = min(self.until, time.monotonic() + 3.0)
            while True:
                self.check()
                if time.monotonic() >= barrier_until: fail('http')
                with self.owner.lock:
                    ticket = server_row.get('ticket')
                    ended = (server_row.get('ended') is True and server_row.get('closed') is True and
                        server_row.get('unknown') is False and server_row.get('failure') is None and
                        ticket is server_row.get('ticket_original') and type(ticket) is dict and
                        ticket['thread'] is ticket['thread_original'] and ticket.get('returned') is True and
                        ticket.get('unknown') is False and ticket.get('failure') is None and
                        ticket['thread'].is_alive() is False)
                if ended: break
                time.sleep(.01)
            return int(match.group(1)), decoded
        except BaseException as error:
            row['error'] = error; raise
        finally:
            if not self.close_client(row): fail('close')

    def smoke(self):
        endpoint = self.owner.endpoint()
        if (endpoint['endpoint'] != 'http://' + self.owner.server.expected_host or
                type(endpoint['token']) is not str or endpoint['token'] != self.owner.state.token): fail('http')
        if self.request('GET', '/v1/status')[0] != 403: fail('http')
        code, bootstrap = self.request('GET', '/v1/bootstrap')
        if code != 200 or bootstrap.get('token') != endpoint['token']: fail('http')
        token = bootstrap['token']
        if self.request('GET', '/v1/bootstrap')[0] != 403: fail('http')
        if self.request('GET', '/v1/status', 'incorrect-fixed-token')[0] != 403: fail('http')
        code, status = self.request('GET', '/v1/status', token)
        if (code != 200 or status.get('capabilities', {}).get('receive', {}).get('available') is not False or
                status.get('capabilities', {}).get('send', {}).get('available') is not False or
                status.get('capabilities', {}).get('scan') is not False or status.get('restorePending') is not False): fail('http')
        code, files = self.request('GET', '/v1/files', token)
        if code != 200 or type(files.get('files')) is not list or len(files['files']) > 256: fail('http')
        for action in ({'action': 'discover_start'}, {'action': 'scan'}, {'action': 'send_prepare', 'fileIds': []}):
            if self.request('POST', '/v1/action', token, action)[0] != 409: fail('http')
            if not self.idle(): fail('gates_changed')
        self.result['http_verified'] = True
        self.result['gates_remained_closed'] = self.idle()
        self.result['operation_inventory_idle'] = self.idle()

    def terminal_inventory_closed(self):
        # Empty startup inventory stays strictly idle. A retained receive is
        # accepted only through the actual Owner and State passive close gates.
        # No reference clearing, restoration callback, clock or new IO here.
        owner = self.owner
        if owner is None or self.loader is None: return False
        state, service = owner.state, owner.service
        if (service is not self.loader.modules.get('mta_service') or
                type(state) is not service.State or state is not owner._state_original):
            return False
        try:
            with state.lock:
                op, session = state.operation, state.session
            if op is None or session is None:
                return (op is None and session is None and self.idle() is True and
                        owner._state_closed() is True)
            if (type(op) is not service.Operation or op.kind != 'receive' or
                    op.backend is not None or session is not op.session or
                    type(session) is not service.TransferSession):
                return False
            if (owner._state_closed() is not True or
                    service.State._receive_terminal_closed(state, op) is not True):
                return False
            with state.lock:
                return state.operation is op and state.session is session
        except BaseException: return False

    def finish_owner(self):
        if self.owner is None: return
        self.result['owner_close_called'] = True
        try:
            returned = self.owner.close()
            actual = self.owner.status()
            if self.owner.receive_trial is not None:
                self.trial_end_facts = self.owner.receive_trial.public_facts()
            # Operation failure and physical closure are separate layers.
            # Preserve every original error for complete/PASS, not as a fake
            # live-resource flag after the original close inventory is known.
            for error in (self.owner.failure, self.owner.loop_failure) + tuple(self.owner.failures):
                if (isinstance(error, BaseException) and
                        not any(error is original for original in self.failures)):
                    self.failures.append(error)
            self.result['startup_readonly_called'] = self.owner.startup_called is True
            self.result['startup_resources_closed'] = self.startup_closed()
            self.result['capability_actor_count'] = len(self.owner.state.probe_actors) if self.owner.state is not None else 0
            self.result['capability_actors_closed'] = (
                self.owner.state is not None and type(self.owner.probe_rows) is list and
                self.owner.state.probe_actors is self.owner.probe_rows and
                self.owner.service.State._probes_closed(self.owner.state) is True)
            self.result['owner_resources_closed'] = (
                returned is True and actual['service_resources_closed'] is True and
                actual['resource_pending'] is False and actual['receive_directory_closed'] is True and
                actual['state_close_verified'] is True and self.result['capability_actors_closed'] and
                self.result['startup_resources_closed'] is True and
                self.owner._closed() is True and self.owner._http_closed() is True and
                self.terminal_inventory_closed() is True)
            if not self.result['owner_resources_closed']: fail('close')
        except BaseException as error:
            self.failures.append(error)

    def run(self):
        try:
            self.platform(); self.validate_payload()
            self.before = self.snapshot(); self.result['before_baseline_observed'] = True
            self.result['stock_hashes_match'] = dict((p, row[1]) for p, row in self.before['stock']) == dict(STOCK_PINS)
            rows = self.before['processes']
            self.result['stock_processes_match'] = all(sum(row[0][3] == name for row in rows) == 1
                                                       for name in (b'Z03', b'control_engine', b'weston')) and all(
                row[0][4] == '/usr/bin/' + row[0][3].decode('ascii') for row in rows
                if row[0][3] in (b'Z03', b'control_engine', b'weston'))
            if not self.result['stock_hashes_match'] or not self.result['stock_processes_match']: fail('stock_baseline')
            self.preflight()
            if not self.preflight_only:
                self.stage(); self.load_owner()
        except BaseException as error:
            self.first_error = error; self.failures.append(error)
            code = getattr(error, 'code', None)
            self.result['reason'] = code if code in REASONS else 'unexpected'
        finally:
            self.finish_owner()
            try:
                self.after = self.snapshot(); self.result['after_baseline_observed'] = True
                self.result['baseline_unchanged'] = self.before is not None and self.before == self.after
                if not self.result['baseline_unchanged']: fail('baseline_changed')
            except BaseException as error: self.failures.append(error)
            for row in reversed(self.rows): self.close_fd(row)
            self.result['runner_opened_fd_count'] = sum(type(row['fd']) is int for row in self.rows)
            self.result['runner_closed_fd_count'] = sum(type(row['fd']) is int and row['closed'] and not row['unknown'] for row in self.rows)
            self.result['runner_fds_closed'] = all(row['closed'] and not row['unknown'] for row in self.rows)
            self.result['client_socket_count'] = len(self.clients)
            self.result['client_sockets_closed'] = all(row['closed'] and not row['unknown'] for row in self.clients)
            self.result['resource_pending'] = (
                not self.result['runner_fds_closed'] or not self.result['client_sockets_closed'] or
                self.owner is not None and not self.result['owner_resources_closed'] or
                self.loader is not None and (getattr(self.loader, 'pending', True) or
                    type(getattr(self.loader, 'rows', None)) is not list or
                    any(row['unknown'] or not row['closed'] for row in getattr(self.loader, 'rows', ()))))
            self.result['staging_pending'] = bool(self.creations and not self.result['stage_verified'])
        if self.first_error is None and self.failures:
            self.first_error = self.failures[0]
            code = getattr(self.first_error, 'code', None)
            self.result['reason'] = code if code in REASONS else 'unexpected'
        common = ('platform_validated', 'payload_validated', 'before_baseline_observed',
                  'after_baseline_observed', 'stock_hashes_match', 'stock_processes_match',
                  'baseline_unchanged', 'preflight_complete', 'runner_fds_closed', 'client_sockets_closed')
        service = ('stage_verified', 'boot_loaded', 'owner_started',
                   'gates_remained_closed', 'operation_inventory_idle', 'capability_actors_closed',
                   'owner_close_called', 'owner_resources_closed', 'private_assets_verified',
                   'startup_readonly_called', 'startup_readonly_verified', 'startup_baseline_collected',
                   'startup_status_verified', 'startup_resources_closed')
        self.result['complete'] = (not self.failures and not self.result['resource_pending'] and
            not self.result['staging_pending'] and all(self.result[key] for key in common) and
            (self.preflight_only and self.boot is None and self.loader is None and self.owner is None and
             not self.clients and not self.http or not self.preflight_only and
             not self.http and not self.clients and self.result['http_verified'] is False and
             all(self.result[key] for key in service)))
        if self.result['complete']:
            self.result['reason'] = 'preflight_complete' if self.preflight_only else 'complete'
        return self.result

    def _error_projection(self, error):
        if not isinstance(error, BaseException): return None
        kind = type(error).__name__
        if re.match(r'^[A-Za-z_][A-Za-z0-9_]{0,63}$', kind) is None: kind = 'unclassified'
        code = getattr(error, 'code', None)
        if type(code) is not str or re.match(r'^[A-Za-z_][A-Za-z0-9_]{0,63}$', code) is None: code = None
        native_errno = getattr(error, 'errno', None)
        if type(native_errno) is not int or not 1 <= native_errno <= 4095: native_errno = None
        trusted = tuple(pin[0] for pin in ROLE_PINS) + tuple(pin[0] for pin in PRIVATE_PINS) + (
            'fixed_startup_readonly_diagnostic', 'startup_readonly_private_owner')
        trace, cursor = [], error.__traceback__
        for unused in range(32):
            if cursor is None: break
            frame = cursor.tb_frame
            module, function = frame.f_globals.get('__name__'), frame.f_code.co_name
            if (module in trusted and type(function) is str and
                    re.match(r'^[A-Za-z_<>][A-Za-z0-9_<>]{0,95}$', function) is not None and
                    type(cursor.tb_lineno) is int and 0 < cursor.tb_lineno < 1000000):
                trace.append((module, function, cursor.tb_lineno))
            cursor = cursor.tb_next
        # No error str/args/locals/path, user data, credentials or HTTP body.
        return {'kind': kind, 'code': code, 'errno': native_errno, 'trace': tuple(trace)}

    def private_error_detail(self):
        # Preserve the primary projection independently of producer details.
        return self._error_projection(self.first_error)

    def private_startup_error_details(self):
        # Passive actual producer inventory only. Do not start another read,
        # inspect an endpoint, close a resource or substitute another scope.
        output, seen = [], []
        def retain(error):
            if (len(output) >= 16 or not isinstance(error, BaseException) or
                    any(error is original for original in seen)):
                return
            seen.append(error)
            value = self._error_projection(error)
            if value is not None: output.append(value)
        try:
            scope = self.retain_startup()
            if scope is None: return ()
            ticket = getattr(scope, 'collector_ticket', None)
            module = self.loader.modules.get('mta_client_startup_readonly')
            if (type(ticket) is not dict or type(module) is not types.ModuleType or
                    sys.modules.get('mta_client_startup_readonly') is not module or
                    ticket.get('creator') is not module.StartupCollection):
                return ()
            collection = ticket.get('returned')
            if (collection is not self.startup_collection or
                    type(collection) is not module.StartupCollection or collection.scope is not scope):
                return ()
            private = scope.private_modules
            proc, status = private.get('mta_client_proc'), private.get('mta_client_wpa_status')
            if type(proc) is not types.ModuleType or type(status) is not types.ModuleType:
                return ()
            for row in getattr(collection, 'reader_rows', ()):
                reader = row.get('value') if type(row) is dict else None
                if type(reader) is not proc.ProcReader: continue
                for generation in reader.operation_history:
                    retain(getattr(generation, 'error', None))
                    if len(output) >= 16: return tuple(output)
            for row in getattr(collection, 'status_rows', ()):
                if type(row) is not dict: continue
                retain(row.get('failure'))
                reader, source = row.get('reader'), row.get('source')
                if type(reader) is status.AuthenticatedStatusReader:
                    retain(getattr(reader, '_failure', None))
                if type(source) is status.LinuxStatusSource:
                    for call in source._actor_calls:
                        if type(call) is dict: retain(call.get('error'))
                if len(output) >= 16: return tuple(output)
        except BaseException:
            # Unknown diagnostic inventory cannot replace the primary error.
            return tuple(output)
        return tuple(output)


def run_fixed(artifacts, preflight_only, receive_trial_requested=False):
    global _RETAINED
    if _RETAINED is not None: fail('foreign_worker')
    os.umask(0o077)
    _RETAINED = FixedSession(artifacts, preflight_only, receive_trial_requested)
    return _RETAINED.run()
