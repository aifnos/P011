"""Fixed v5 ordinary-only publication; sender/observer are readonly prerequisites.

Three independent bounded batches preserve the original decoded 4 MiB limit.
Imports/default main do not stage. Explicit stage() accepts only fixed immutable
byte payloads. Existing complete inventories are re-read, not adopted by receipt.
Conflicts and partial publications remain untouched. No CLIENT/pending reads,
RF, scan, helper spawn, restoration grant, overwrite, deletion or permission repair.
"""
import errno
import hashlib
import math
import os
import stat
import sys
import threading
import time

RAW_LIMIT = 4 * 1024 * 1024
MAX_SECONDS = 120.0
PROFILE_TOTALS = (('sender', 27, 2402458), ('observer', 41, 1442508),
                  ('ordinary', 37, 1353776))
SERVICE_PARENTS = ('p011-mta-go-send-v78-prepared', 'p011-mta-go-session')
PROFILE_FILES = (
    ('sender', '/var/volatile/tmp/p011-mta-go-send-filecenter-v3-assets', (
        ('runtime/p011_json.py', 8061, 'fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88', 256),
        ('runtime/mta_ip.py', 22049, '1fa5e72817772285fd966f52c57af105950ff0d3b6ea49b202983aebfbab40c5', 256),
        ('runtime/mta_client_tmp_alias.py', 8827, '1a4a52bd0bae7add6ae42f66bd9827c43865a0170c666eaab00797d1f45f7f2f', 256),
        ('runtime/mta_p2p_client_init.py', 69966, '178bd8a491e9e5ec03e8da3bce780f8e8e8c1c8781bfeaca7d8c3bac59fa364b', 256),
        ('runtime/mta_snapshot_data.py', 17217, 'cb5e8f16c78cc4c879a8986dd9c2ab8ed5e6c055f105baad3ce60eb9a10d2a26', 256),
        ('runtime/mta_client_resource_budget.py', 16215, '56d6dbe2370279b1572a563e67fd3313bf942c0baa78fbd8e36cd973ba09839e', 256),
        ('runtime/mta_client_proc.py', 39384, 'ede5953c33ba4c17d3aecb1fffe8a9358589497b37e3109034d5e1de3eadb3d6', 256),
        ('runtime/mta_client_journal_codec.py', 17450, '2ffeca6b59498c9e2dfa4b9906bbe55db909d5d5e1d448fa0c795490996fe14a', 256),
        ('runtime/mta_client_coordination.py', 35591, '930e56d35ebf08d0b1c83fe7ccab843cbe6520ecd68c0799e9a07b2bbe40823f', 256),
        ('runtime/mta_client_files.py', 28938, '30c07bb4a5a28ce02aa76f35650ee1c87af63617f445e554c3fd7f73a2705864', 256),
        ('runtime/mta_client_pending.py', 42432, 'cfba740700268d5998eb3a91bf7cdc34d893fa8f0083377d716ea98950c3f5af', 256),
        ('runtime/mta_client_store.py', 71524, 'f328dcaa95ecfc5288c85a3715ecfdbdbdb8e83c83797b91cde3e334d188f4a2', 256),
        ('runtime/mta_go_process_owner.py', 42612, '78a480728a348e98e578acf4e7c778be50bfae3411ba5d34bb563493e1ba6583', 256),
        ('runtime/mta_go_deployment.py', 26543, 'e8dc91c0a44a48d6cecf066257e79185fe590385f98300d01835edddb8114efe', 256),
        ('runtime/mta_go_executor.py', 62728, 'f33ad96651e8aed38adab1ca931da6de7455130b8dbcedd774e1038ee39c8ed0', 256),
        ('runtime/mta_ip_lease.py', 18704, '39373dba355557ee73cfac354bdbaa95eaf0ddde4e27313450edf0e74742f12c', 256),
        ('runtime/mta_dhcp.py', 15719, '631987bd7307580af069f1978e440d21fbd449ecc62c83e0e06195c330f50176', 256),
        ('runtime/mta_go_bootstrap_store.py', 78430, '24620844c7d24f4777114ba9bfb4ea292ded2020a281681dd8e71fe07c7a4eae', 256),
        ('runtime/mta_go_dhcp.py', 21997, '3f7dbab30c8925cf0ea288a1e011787d436c07d3a8178a8a45934db3597f9312', 256),
        ('runtime/mta_go_native.py', 200317, 'ee46d8313fe31cbc5a0d16d0d14aff7ce2b3fb507f3cdac572e59bc5f16dfa9f', 256),
        ('runtime/mta_go_bootstrap.py', 31964, '93bc97ccb9d83d5727c2f528f0a2934f09d8cae093591821a9bf5ad60f425697', 256),
        ('runtime/mta_protocol.py', 17958, '4f7c2bd46cde114f0a2a0c33b31631aa463f09e71b156d26e34daf2251dd8a57', 256),
        ('runtime/mta_transport.py', 31883, '29e5ea6bf8f5de9ddae33824c158f4e401bab391d51b18dc0b8a1ab2cbc2dc72', 256),
        ('runtime/mta_sender_pump.py', 33455, '81c3d7ff98ab71cde2ac2858daaffd267f129033b28ebde1dbd2f13f19ff447c', 256),
        ('runtime/mta_go_send_bridge.py', 87625, '027be64bf7b1b4f6ae57d09921b821e4cc77db44c602b9a5d99d901ed5736f02', 256),
        ('source-manifest.json', 3677, 'be67d8cec589b4e54235d8205660a67f02a188f23e99251bf2219b35b147f3d5', 256),
        ('native/mta-wpa-supplicant', 1351192, 'e069aef76a089215367f502015266e9ce59cf4ebb7d7246974815ff60d67f301', 320),
    )),
    ("observer", "/var/volatile/tmp/p011-mta-go-observer-libc-v1", (
        ("runtime/p011_json.py", 8061, "fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88", 256),
        ("runtime/mta_ip.py", 22049, "1fa5e72817772285fd966f52c57af105950ff0d3b6ea49b202983aebfbab40c5", 256),
        ("runtime/mta_client_tmp_alias.py", 8827, "1a4a52bd0bae7add6ae42f66bd9827c43865a0170c666eaab00797d1f45f7f2f", 256),
        ("runtime/mta_p2p_client_init.py", 71315, "d3b51493d3ae778aeb72c1304dc50e5a6221428f7775bc7a28d15a3f19abeaaa", 256),
        ("runtime/mta_client_resource_budget.py", 16215, "56d6dbe2370279b1572a563e67fd3313bf942c0baa78fbd8e36cd973ba09839e", 256),
        ("runtime/mta_client_proc.py", 39384, "ede5953c33ba4c17d3aecb1fffe8a9358589497b37e3109034d5e1de3eadb3d6", 256),
        ("runtime/mta_client_caps.py", 11821, "c1792c2294fed5da16ec4a676423fbcbe53d44e9bc4ddadc1bc26fd45afe046c", 256),
        ("runtime/mta_client_caps_transport.py", 19614, "df6b4cf3ede6039c684c6b689a8b61ffe1ba5b87259bb4a5581aa5c3ece84420", 256),
        ("runtime/mta_client_baseline.py", 31338, "e950877bd99ee7907c66ee237e3140960ac8e4d64f979310b82bfdab2fa271ea", 256),
        ("runtime/mta_client_journal_codec.py", 17450, "2ffeca6b59498c9e2dfa4b9906bbe55db909d5d5e1d448fa0c795490996fe14a", 256),
        ("runtime/mta_client_coordination.py", 36295, "5b8a4295a5479cb5693182085fc8d35c6041bb0f14d9efb660ec11f024a5eeb3", 256),
        ("runtime/mta_client_files.py", 28938, "30c07bb4a5a28ce02aa76f35650ee1c87af63617f445e554c3fd7f73a2705864", 256),
        ("runtime/mta_client_pending.py", 53132, "deaf62f9830b951584b36100de0f88548bcd6356b7327c3be0fa8578b65aba8a", 256),
        ("runtime/mta_client_store.py", 74676, "bc51d3c64d3c92a87da331c740d93cea7466c535c5a81969422a45b8c5b68f63", 256),
        ("runtime/mta_client_process_owner.py", 34361, "c144bc197a8fd1d4fbbfc358ba0172a84f5c9070058732189e4709c8c801ffeb", 256),
        ("runtime/mta_client_launch_registration.py", 21679, "833d46f5717e0b7e9db0c5392a0eb93d812d039b4b946a57d49d5903534a1aa0", 256),
        ("runtime/mta_client_two_phase_lease.py", 27606, "c227989ec5188c272ad0a212974d569572704d3bb07c4c61c72670abcd0981a5", 256),
        ("runtime/mta_p2p_client_ctrl.py", 18712, "793b784f1b39eca18001aa65a1f0d6cdbd6de466dc58b3cf2ada167f71d902b5", 256),
        ("runtime/mta_client_wpa_status.py", 39133, "47074a5af8d9f75746fa7cd72e1e42b50c8402fcbb612963f6523c875fe1c269", 256),
        ("runtime/mta_protocol.py", 17958, "4f7c2bd46cde114f0a2a0c33b31631aa463f09e71b156d26e34daf2251dd8a57", 256),
        ("runtime/mta_client_control_frame.py", 20942, "d1a8fce91ab705524f14edac8d81e8d391c0cddbf8f4ac96ee7a6446c0512278", 256),
        ("runtime/mta_client_kernel_proof.py", 23702, "4ebfedf198673e3bad2f64a4bd72c581e5d6af24cef83e589b4456d2a38f8ede", 256),
        ("runtime/mta_client_connection.py", 22494, "ae2932252bbef16b89e6bf4614c2ebdb1721d507274dbd9b9fe4d9db1d0ff159", 256),
        ("runtime/mta_client_linux_provider.py", 174220, "5f080f8a0d53d7232ec95c303e0e84036d22d4e0927ac98dd3195291cf6d56ba", 256),
        ("runtime/mta_client_executor.py", 105182, "f3f7c9fb54e46f82b4321152dfac6f4ab9b037943c403d76716f8254700bb17e", 256),
        ("runtime/mta_dhcp.py", 15719, "631987bd7307580af069f1978e440d21fbd449ecc62c83e0e06195c330f50176", 256),
        ("runtime/mta_dhcp_client_core.py", 12362, "13c03d181139fd9ead7ff3bf2bcbb4930669f1e795b17360da85834dc345e9fa", 256),
        ("runtime/mta_dhcp_client.py", 24670, "794421678866d04a10ca46fa9eb7e17174f24c4d9e705cf59016b457702003a0", 256),
        ("runtime/mta_client_dora.py", 48149, "f17f8405b28799fda8ee8f3ea9d280f871cceb1e0c6b999fc855bcb652ab2f7e", 256),
        ("runtime/mta_client_dynamic_ip.py", 32427, "01476613eb965a05cd5441dfbfea53f15ce763da12213b76791ecdb23152199a", 256),
        ("runtime/mta_client_peer.py", 31242, "f8a15d046b505a8c5117a5be19d2ee59f38096759be1b29a0310535ceea08ec9", 256),
        ("runtime/mta_scoped_sockets.py", 26339, "b95cfbe724b43baf90511c9d2a4a39d869a40a57e78e2a87d398ea134f9f84b8", 256),
        ("runtime/mta_storage.py", 14335, "3c5c5f65ef0c8eb9a0256a99f931faff40558484bb908e89acee1c1c0aa3b4d6", 256),
        ("runtime/mta_transport.py", 35209, "77d9cd45936318315cf3343ab1bd2594c6a3381e33a7d0fdcfd853916063eefa", 256),
        ("runtime/mta_client_transfer.py", 30747, "8633b2a1156c3012ec613e776eaee7e9339c14c76cffff9c8e5ff75646f35184", 256),
        ("runtime/mta_client_readonly_baseline.py", 13934, "c2052c39fdad148d25f83743476b95a51a88e7f9e16ec2235c91d4de6adc9aad", 256),
        ("runtime/mta_snapshot_data.py", 17217, "cb5e8f16c78cc4c879a8986dd9c2ab8ed5e6c055f105baad3ce60eb9a10d2a26", 256),
        ("runtime/mta_go_readonly_preflight.py", 64948, "802ad7c3b80ea6e9ea4678a4112bd2ec95be08cff5fe6684e1162f127ae55f44", 256),
        ("runtime/mta_go_readonly_loader.py", 36543, "8e60e8f86a0cd4a261ca65f657739e9189137cf37dc04f4af1495263ce1b8e56", 256),
        ("runtime/mta_observer_packet.py", 48253, "004ff5616924a4529ce3a3f710ac83a8d2dedbd55ae2edb790998a68f68fe40f", 256),
        ("runtime/mta_go_readonly_entry.py", 45310, "b97328b01617ce1944d3576bb4c0e22160414120c737b336e2509004d0031ffa", 256),
    )),
    ("ordinary", "/var/volatile/tmp/p011-mta-formal-send-filecenter-deploy-v6", (
        ("runtime/mta_client_executor.py", 105182, "f3f7c9fb54e46f82b4321152dfac6f4ab9b037943c403d76716f8254700bb17e", 256),
        ("runtime/p011_json.py", 8061, "fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88", 256),
        ("runtime/mta_protocol.py", 17958, "4f7c2bd46cde114f0a2a0c33b31631aa463f09e71b156d26e34daf2251dd8a57", 256),
        ("runtime/mta_storage.py", 55562, "ea3d3df1177019125c9b3124b8ebaf33196dd1013db95ac24580e1fe1a96c8d1", 256),
        ("runtime/mta_files.py", 10267, "c37a00be58487abee32abf7ded7ed857e059883aee680e049e6372d3d06681ae", 256),
        ("runtime/mta_crypto.py", 15274, "6fde6a60ec327895938a59990c4734a923dd5ff68bd5ee6979791df9a607e516", 256),
        ("runtime/mta_transfer_session.py", 20633, "e7321ad446318f96bf84b1a94f0e5e3c76b1e973e28826f1c2514527b6967859", 256),
        ("runtime/mta_dhcp.py", 15719, "631987bd7307580af069f1978e440d21fbd449ecc62c83e0e06195c330f50176", 256),
        ("runtime/mta_dhcp_server.py", 20515, "a34fdbc07a96f2ed3337872612510aa2a8b72b970a193f58b8045c0653b8d8bc", 256),
        ("runtime/mta_scoped_sockets.py", 26339, "b95cfbe724b43baf90511c9d2a4a39d869a40a57e78e2a87d398ea134f9f84b8", 256),
        ("runtime/mta_transport.py", 31883, "29e5ea6bf8f5de9ddae33824c158f4e401bab391d51b18dc0b8a1ab2cbc2dc72", 256),
        ("runtime/mta_sender.py", 33949, "da25d3359d0759f71d8a4483680e3a3d5376c9e745e85224dbaee2a672f0670a", 256),
        ("runtime/mta_send_worker.py", 43252, "de0dd8c2c0fb3b45923199ccc987ae057046fa0244c6a405c3a254850f7e68e7", 256),
        ("runtime/mta_scan_handoff.py", 11515, "51af67e80cf64038160cf420ad08f4f255a15dd9577e14fdcdb44fc26711046a", 256),
        ("runtime/mta_wifi.py", 28459, "62322b09fe4fd96bf6d49d8a2f7ac416e9a9d4dadcb3df23a6330e3205bcd017", 256),
        ("runtime/minhttp.py", 9690, "bf5648457b19b60ad0f17320f8bd0431064f9cb4edf0d238d82136000eb57235", 256),
        ("runtime/mta_client_control_frame.py", 20942, "d1a8fce91ab705524f14edac8d81e8d391c0cddbf8f4ac96ee7a6446c0512278", 256),
        ("runtime/mta_client_connect_handoff.py", 10533, "aeade54eac7ed055936d7004087aa2a30a731ee7742365080cbd037264a58cc4", 256),
        ("runtime/mta_client_tmp_alias.py", 8827, "1a4a52bd0bae7add6ae42f66bd9827c43865a0170c666eaab00797d1f45f7f2f", 256),
        ("runtime/mta_client_receive_factory.py", 54158, "29265227937c2191e8af7a90a25ee518c87e6cb2a28162a99f883196bd9d7329", 256),
        ("runtime/mta_client_state_bridge.py", 21283, "17d3c5339c1e68bf5eb68308858144d687b1b17616cbeaa0817bad91bd33b8fd", 256),
        ("runtime/mta_send_preparation.py", 28532, "0e92fc68947601d0517cfe64a22d90d50b9952529c4594a6a189970420f69814", 256),
        ("runtime/mta_go_readonly_parent.py", 52881, "a950577490c576698b3186efe87c6a8da773b21128f836d51b5b26a7bb5d45d6", 256),
        ("runtime/mta_go_send_publication.py", 45722, "7afbdc2b675b1d4fc61ded61ae6ff9d4dfbe529525c616ad96f7881b378d948d", 256),
        ("runtime/mta_go_send_bridge.py", 87625, "027be64bf7b1b4f6ae57d09921b821e4cc77db44c602b9a5d99d901ed5736f02", 256),
        ("runtime/mta_go_readonly_terminal_parent.py", 66981, "ba34d2442ded555d7f7ab1166b9ffd703a1e59f2aa484c20a6226a428e49e823", 256),
        ("runtime/mta_receive_radio_baseline.py", 3971, "27a1cf60be3f964862904233c600af11b8d3e9468febba61d8c622fceb29824c", 256),
        ("runtime/mta_receive_network.py", 15860, "1d2b2e250d63376f070816262fde601af5cd6005fb4f5877812f3d20ab8675a6", 256),
        ("runtime/mta_send_trial.py", 22052, "dfb4c95aba33612a7cf94c46c04af234af0d6f01bb73b69b39713c7eea683011", 256),
        ("runtime/mta_send_terminal_consumer.py", 12785, "5cc4c7fac05719c17f568c14c9fe3e13e7203c679305c73887a7e7597f414153", 256),
        ("runtime/mta_service.py", 145733, "38039da81606508f4633662b3802b2882d851df223f32bcf7bd237ee1a53fa76", 256),
        ("runtime/mta_client_receive_boot.py", 19583, "ccf7db818c159c1637676ea6860c48ce4ffa9298b3fd44c76a2565635583c405", 256),
        ("runtime/mta_client_service_owner.py", 89599, "f8f2bca88915d372ba685024bf995e9d746491559d5c981e83ff1a1e3d6ddea0", 256),
        ("runtime/formal_send_session.py", 24059, "9c7f87dc4eb7cca9cc09e65a75063365429c363ea1e68da27e9597f228bbf036", 256),
        ("native/mta-bluez-helper", 74920, "c06398ddae281cf4a6f8a41953baf84795992f8f3e3769baebaf11f6d9964181", 320),
        ("native/mta-network-helper", 47464, "ef3b904ef1017b6f0011b1e2cfcadbc98f9e8026933153ff0291699f32c525e6", 320),
        ("mta-connman-observer", 46008, "5f2612224a3db35d8f0850adf10d1fece7094bff6387521c185570c4be8068e2", 448),
    )),
)

_PROFILE_FILES_ORIGINAL = PROFILE_FILES
_RETAINED = None


class StageError(ValueError):
    def __init__(self, code):
        self.code = code
        ValueError.__init__(self, code)


def fail(code):
    raise StageError(code) from None


def meta(value):
    return tuple(getattr(value, name) for name in
                 ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
                  'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def identity(value):
    return value[:5]


class FixedStage(object):
    def __init__(self, profile, original_until):
        self.rows = self._rows_original = []
        self.edges = self._edges_original = []
        self.creations = self._creations_original = []
        self.failures = []
        self.first_error = None
        self.close_failure = None
        self.profile = self._profile_original = profile
        choices = [row for row in PROFILE_FILES if type(profile) is str and row[0] == profile]
        if len(choices) != 1:
            fail('profile')
        if type(original_until) is not float or not math.isfinite(original_until) or not 0 < original_until < 1e12:
            fail('deadline')
        self.spec = self._spec_original = choices[0]
        self.until = self._until_original = original_until
        self.worker = self._worker_original = threading.current_thread()
        self.pid = self._pid_original = os.getpid()
        self.clock = self._clock_original = time.monotonic
        self.last = self.issued = None
        self.alias_original = None
        self.called = self.ended = self.complete = self.close_called = self.closed = False
        self.raws = None
        self.base = self.var = self.volatile = self.tmp = None
        self.snapshots = []
        self.service_parent_facts = []
        self.created_files = self.created_directories = 0
        self.existing_complete = False

    def context(self):
        if (self.rows is not self._rows_original or self.edges is not self._edges_original or
                self.creations is not self._creations_original or self.spec is not self._spec_original or
                PROFILE_FILES is not _PROFILE_FILES_ORIGINAL or self.until is not self._until_original or
                self.profile is not self._profile_original or self.profile != self.spec[0] or
                self.clock is not self._clock_original or self.clock is not time.monotonic or
                self.worker is not self._worker_original or threading.current_thread() is not self.worker or
                self.pid != self._pid_original or os.getpid() != self.pid):
            fail('original_changed')

    def now(self):
        self.context()
        value = self.clock()
        if (type(value) not in (int, float) or not math.isfinite(value) or
                not 0 <= value < 1e12 or self.last is not None and value < self.last or value >= self.until):
            fail('deadline')
        self.last = float(value)
        return self.last

    def platform(self):
        if (sys.platform != 'linux' or sys.byteorder != 'little' or os.geteuid() != 0 or
                os.uname()[4] != 'armv7l' or tuple(sys.version_info[:3]) != (3, 5, 5) or
                sys.flags.optimize or os.O_NOFOLLOW != 0x8000 or os.O_CLOEXEC != 0x80000):
            fail('platform')

    def payload(self, value):
        expected = self.spec[2]
        total = next(row for row in PROFILE_TOTALS if row[0] == self.profile)
        if (type(value) is not tuple or len(value) != total[1] or len(expected) != total[1] or
                sum(row[1] for row in expected) != total[2] or not 0 < total[2] <= RAW_LIMIT):
            fail('payload')
        retained = []
        for item, pin in zip(value, expected):
            self.now()
            if (type(item) is not tuple or len(item) != 2 or item[0] != pin[0] or
                    type(item[1]) is not bytes or len(item[1]) != pin[1] or
                    hashlib.sha256(item[1]).hexdigest() != pin[2]):
                fail('payload')
            retained.append(item)
        self.raws = tuple(retained)

    def aliases(self):
        self.now()
        result = []
        for path, target in (('/tmp', '/var/tmp'), ('/var/tmp', '/var/volatile/tmp')):
            observed = meta(os.lstat(path))
            if (observed[2] != stat.S_IFLNK | 0o777 or observed[3:6] != (0, 0, 1) or
                    observed[6] != len(target) or os.readlink(path) != target):
                fail('alias')
            result.append((path, observed, target))
        value = tuple(result)
        if self.alias_original is None:
            self.alias_original = value
        elif value != self.alias_original:
            fail('alias_changed')
        self.now()

    def open_row(self, parent, name, flags, mode, kind):
        self.now()
        self.edges_current()
        if kind == 'file':
            flags |= os.O_NONBLOCK
        row = dict(parent=parent, name=name, flags=flags, mode=mode, kind=kind,
                   fd=None, original_fd=None, metadata=None, original_identity=None,
                   open_called=False, returned=False, no_fd=False, unknown=True,
                   close_called=False, close_return=None, close_error=None, closed=False,
                   ebadf=False, failure=None, raw_sha=None)
        self.rows.append(row)
        row['open_called'] = True
        try:
            fd = os.open(name, flags | os.O_NOFOLLOW | os.O_CLOEXEC, mode,
                         dir_fd=None if parent is None else parent['fd'])
            row['fd'] = row['original_fd'] = fd
            row['returned'] = True
            if type(fd) is not int or fd < 0:
                fail('descriptor_unknown')
            observed = meta(os.fstat(fd))
            row['metadata'] = observed
            row['original_identity'] = identity(observed)
            collisions = [old for old in self._rows_original if old is not row and
                          old['returned'] and not old['closed'] and old['fd'] == fd]
            if collisions:
                error = StageError('descriptor_unknown')
                for original in collisions + [row]:
                    original['unknown'] = True
                    if original['failure'] is None:
                        original['failure'] = error
                raise error
            row['unknown'] = False
            self.now()
            return row
        except OSError as error:
            row['failure'] = error
            if (row['returned'] is False and row['fd'] is None and
                    type(error.errno) is int and 1 <= error.errno <= 4095):
                row['no_fd'] = row['closed'] = True
                row['unknown'] = False
            raise
        except BaseException as error:
            row['failure'] = error
            raise

    def close_row(self, row):
        try:
            self.context()
            if not any(row is original for original in self._rows_original):
                return False
            if row['close_called']:
                return row['closed'] is True and row['unknown'] is False
            if row['no_fd']:
                return row['returned'] is False and row['fd'] is None and row['unknown'] is False and row['closed'] is True
            if (row['unknown'] or not row['returned'] or row['fd'] is not row['original_fd'] or
                    row['original_identity'] is None):
                return False
            row['close_called'] = True
            current = meta(os.fstat(row['fd']))
            if identity(current) != row['original_identity']:
                fail('close_identity')
            row['close_return'] = os.close(row['fd'])
            try:
                os.fstat(row['fd'])
            except OSError as error:
                row['close_error'] = error
                row['ebadf'] = type(error.errno) is int and error.errno == errno.EBADF
                row['closed'] = row['close_return'] is None and row['ebadf']
            if row['closed'] is not True:
                row['unknown'] = True
        except BaseException as error:
            row['unknown'] = True
            row['failure'] = error
            self.failures.append(error)
            if self.close_failure is None:
                self.close_failure = error
        return row['closed'] is True and row['unknown'] is False

    def directory(self, parent, name, mode):
        self.now()
        before = meta(os.stat(name, dir_fd=None if parent is None else parent['fd'], follow_symlinks=False))
        if (before[2] != stat.S_IFDIR | mode or before[3:5] != (0, 0) or before[5] < 1):
            fail('directory_policy')
        row = self.open_row(parent, name, os.O_RDONLY | os.O_DIRECTORY, mode, 'directory')
        if identity(row['metadata']) != identity(before):
            fail('directory_changed')
        self.edges.append((parent, name, row))
        self.edges_current()
        return row

    def edges_current(self):
        self.context()
        self.aliases_current()
        for parent, name, row in self._edges_original:
            if (row['unknown'] or row['closed'] or row['close_called'] or row['fd'] is not row['original_fd'] or
                    parent is not row['parent'] or name != row['name']):
                fail('directory_changed')
            current = meta(os.fstat(row['fd']))
            path = meta(os.stat(name, dir_fd=None if parent is None else parent['fd'], follow_symlinks=False))
            if (identity(current) != row['original_identity'] or identity(path) != row['original_identity'] or
                    current[2] != stat.S_IFDIR | row['mode'] or current[3:5] != (0, 0)):
                fail('directory_changed')

    def aliases_current(self):
        if self.alias_original is None:
            return
        for path, original, target in self.alias_original:
            if meta(os.lstat(path)) != original or os.readlink(path) != target:
                fail('alias_changed')

    def names(self, row):
        self.now()
        self.edges_current()
        os.lseek(row['fd'], 0, os.SEEK_SET)
        names = os.listdir(row['fd'])
        if type(names) is not list or any(type(name) is not str for name in names):
            fail('inventory_unknown')
        self.now()
        self.edges_current()
        return tuple(sorted(names))

    def present(self, parent, name):
        self.now()
        self.edges_current()
        try:
            value = meta(os.stat(name, dir_fd=parent['fd'], follow_symlinks=False))
        except OSError as error:
            if type(error.errno) is int and error.errno == errno.ENOENT:
                self.now()
                return None
            raise
        self.now()
        return value

    def tree_names(self, pins):
        children = {}
        for path, size, sha, mode in pins:
            parts = path.split('/')
            if len(parts) > 2 or any(not part or part in ('.', '..') for part in parts):
                fail('fixed_path')
            children.setdefault('', set()).add(parts[0])
            if len(parts) == 2:
                children.setdefault(parts[0], set()).add(parts[1])
        return dict((key, tuple(sorted(value))) for key, value in children.items())

    def read_file(self, parent, name, pin):
        self.now()
        self.edges_current()
        before = meta(os.stat(name, dir_fd=parent['fd'], follow_symlinks=False))
        if (before[2] != stat.S_IFREG | pin[3] or before[3:6] != (0, 0, 1) or before[6] != pin[1]):
            fail('file_policy')
        row = self.open_row(parent, name, os.O_RDONLY, pin[3], 'file')
        primary = None
        try:
            if row['metadata'] != before:
                fail('file_changed')
            count = 0
            digest = hashlib.sha256()
            while count <= pin[1]:
                self.now()
                data = os.read(row['fd'], min(65536, pin[1] + 1 - count))
                if type(data) is not bytes:
                    fail('read_unknown')
                self.now()
                digest.update(data)
                count += len(data)
                if not data:
                    break
            row['raw_sha'] = digest.hexdigest()
            if (count != pin[1] or row['raw_sha'] != pin[2] or meta(os.fstat(row['fd'])) != before or
                    meta(os.stat(name, dir_fd=parent['fd'], follow_symlinks=False)) != before):
                fail('file_changed')
            self.edges_current()
        except BaseException as error:
            primary = row['failure'] = error
        finally:
            if self.close_row(row) is not True and primary is None:
                primary = StageError('file_close')
        if primary is not None:
            raise primary
        return before

    def inspect(self, spec):
        name = spec[1].rsplit('/', 1)[1]
        observed = self.present(self.tmp, name)
        if observed is None:
            return None
        root = self.directory(self.tmp, name, 0o700)
        expected = self.tree_names(spec[2])
        if self.names(root) != expected['']:
            fail('existing_conflict')
        directories = {'': root}
        for child in ('runtime', 'native'):
            if child in expected:
                directories[child] = self.directory(root, child, 0o700)
                if self.names(directories[child]) != expected[child]:
                    fail('existing_conflict')
        files = []
        for pin in spec[2]:
            parent_name, _, basename = pin[0].rpartition('/')
            files.append((pin[0], self.read_file(directories[parent_name], basename, pin)))
        self.edges_current()
        for key, row in directories.items():
            if self.names(row) != expected[key]:
                fail('existing_changed')
        for path, original in files:
            self.now()
            parent_name, _, basename = path.rpartition('/')
            current = meta(os.stat(basename, dir_fd=directories[parent_name]['fd'], follow_symlinks=False))
            if current != original:
                fail('file_changed')
        self.edges_current()
        return (root['original_identity'], tuple((key, row['original_identity']) for key, row in sorted(directories.items())),
                tuple(files))

    def create_directory(self, parent, name):
        self.now()
        self.edges_current()
        if self.present(parent, name) is not None:
            fail('existing_changed')
        ticket = dict(parent=parent, name=name, kind='directory', called=True,
                      returned=False, unknown=True, error=None, row=None)
        self.creations.append(ticket)
        try:
            returned = os.mkdir(name, 0o700, dir_fd=parent['fd'])
            ticket['returned'] = returned is None
            ticket['unknown'] = returned is not None
            if returned is not None:
                fail('mkdir_return')
            self.created_directories += 1
            self.now()
            ticket['row'] = self.directory(parent, name, 0o700)
            self.edges_current()
            if os.fsync(parent['fd']) is not None:
                fail('sync_return')
            return ticket['row']
        except BaseException as error:
            ticket['error'] = error
            raise

    def write_file(self, parent, name, pin, raw):
        self.now()
        self.edges_current()
        ticket = dict(parent=parent, name=name, kind='file', called=True,
                      returned=False, unknown=True, error=None, row=None)
        self.creations.append(ticket)
        row = None
        primary = None
        try:
            row = self.open_row(parent, name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, pin[3], 'file')
            ticket['row'] = row
            ticket['returned'] = True
            ticket['unknown'] = False
            self.created_files += 1
            before = row['metadata']
            if before[2:7] != (stat.S_IFREG | pin[3], 0, 0, 1, 0):
                fail('new_file_policy')
            count = 0
            while count < len(raw):
                self.now()
                self.edges_current()
                if (meta(os.fstat(row['fd'])) != row['metadata'] or
                        meta(os.stat(name, dir_fd=parent['fd'], follow_symlinks=False)) != row['metadata']):
                    fail('file_changed')
                returned = os.write(row['fd'], raw[count:count + 65536])
                if type(returned) is not int or not 1 <= returned <= min(65536, len(raw) - count):
                    fail('write_return')
                count += returned
                row['metadata'] = meta(os.fstat(row['fd']))
                if row['metadata'][:6] != before[:6] or row['metadata'][6] != count:
                    fail('file_changed')
                self.now()
                self.edges_current()
            if os.fsync(row['fd']) is not None:
                fail('sync_return')
            row['metadata'] = meta(os.fstat(row['fd']))
            if self.read_file(parent, name, pin) != row['metadata']:
                fail('readback_changed')
            self.edges_current()
        except BaseException as error:
            primary = ticket['error'] = error
            if row is not None:
                row['failure'] = error
        finally:
            if row is not None and self.close_row(row) is not True and primary is None:
                primary = StageError('file_close')
        if primary is not None:
            raise primary

    def parents(self):
        self.aliases()
        self.base = self.directory(None, '/', 0o755)
        self.var = self.directory(self.base, 'var', 0o755)
        self.volatile = self.directory(self.var, 'volatile', 0o1777)
        self.tmp = self.directory(self.volatile, 'tmp', 0o1777)

    def service_parents(self):
        prepared = []
        for name in SERVICE_PARENTS:
            observed = self.present(self.tmp, name)
            existing = observed is not None
            row = self.directory(self.tmp, name, 0o700) if existing else None
            names = self.names(row) if existing else ()
            # These are future work parents, not owned historical job contents.
            # Retain and compare inventory names; never open/remove their children.
            prepared.append((name, row, existing, names))
        # Both fixed existing nodes are authenticated before either is created.
        for name, row, existing, names in prepared:
            if existing:
                if self.names(row) != names:
                    fail('service_parent_changed')
            elif self.present(self.tmp, name) is not None:
                fail('service_parent_changed')
        for name, row, existing, names in prepared:
            if not existing:
                row = self.create_directory(self.tmp, name)
                if self.names(row) != ():
                    fail('service_parent_changed')
            self.service_parent_facts.append((name, row, existing, names))
        self.edges_current()

    def service_parents_current(self):
        for name, row, existing, names in self.service_parent_facts:
            if self.names(row) != names:
                fail('service_parent_changed')

    def close(self):
        if self.close_called:
            return self.closed
        self.close_called = True
        good = True
        for row in reversed(self._rows_original):
            good = self.close_row(row) and good
        self.closed = good and all(ticket['unknown'] is False for ticket in self._creations_original)
        return self.closed

    def stage(self, fixed_raws):
        if self.called or self.close_called:
            fail('once')
        self.called = True
        try:
            self.platform()
            issued = self.now()
            self.issued = issued
            if not 0 < self.until - issued <= MAX_SECONDS:
                fail('deadline')
            self.payload(fixed_raws)
            self.parents()
            prior = []
            if self.profile == 'ordinary':
                for spec in PROFILE_FILES[:2]:
                    value = self.inspect(spec)
                    if value is None:
                        fail('prerequisite_missing')
                    prior.append((spec, value))
                    self.snapshots.append((spec, value))
            before = self.inspect(self.spec)
            self.snapshots.append((self.spec, before))
            self.existing_complete = before is not None
            # Repeat every prior/current actual inventory before any write.
            for spec, value in prior:
                if self.inspect(spec) != value:
                    fail('prerequisite_changed')
            if self.inspect(self.spec) != before:
                fail('existing_changed')
            if self.profile == 'ordinary':
                self.service_parents()
            if before is None:
                root = self.create_directory(self.tmp, self.spec[1].rsplit('/', 1)[1])
                directories = {'': root}
                expected = self.tree_names(self.spec[2])
                for child in ('runtime', 'native'):
                    if child in expected:
                        directories[child] = self.create_directory(root, child)
                for pin, item in zip(self.spec[2], self.raws):
                    parent_name, _, basename = pin[0].rpartition('/')
                    self.write_file(directories[parent_name], basename, pin, item[1])
                for row in directories.values():
                    self.now()
                    self.edges_current()
                    if os.fsync(row['fd']) is not None:
                        fail('sync_return')
            after = self.inspect(self.spec)
            if after is None or before is not None and after != before:
                fail('existing_changed')
            for spec, value in prior:
                if self.inspect(spec) != value:
                    fail('prerequisite_changed')
            self.service_parents_current()
            self.edges_current()
            self.now()
            self.complete = True
        except BaseException as error:
            if self.first_error is None:
                self.first_error = error
            self.failures.append(error)
            raise
        finally:
            self.ended = True
            self.close()
        if self.closed is not True:
            fail('close_pending')
        return self

    def result(self):
        return dict(kind='formal-send-stage-v1-files-only', profile=self.profile,
                    stage_complete=self.complete and self.closed and self.first_error is None,
                    resource_pending=not self.closed, staging_pending=bool(self.creations) and not self.complete,
                    original_fds=len(self.rows), original_fds_closed=sum(row['closed'] is True for row in self.rows),
                    created_files=self.created_files, created_directories=self.created_directories,
                    existing_complete=self.existing_complete, prerequisites=max(0, len(self.snapshots) - 1),
                    service_parent_count=len(self.service_parent_facts), receive=False, send=False,
                    boot=False, owner=False, helper=False, rf=False, restoration=False, phone=False)


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    return 0 if not args else 2


if __name__ == '__main__':
    raise SystemExit(main())
