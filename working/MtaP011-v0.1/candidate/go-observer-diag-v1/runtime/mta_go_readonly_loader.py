"""Fixed v94 isolated read-only definitions Loader; SOURCE only.

One fresh private process loads the exact RO35 v51 definitions, readonly leaf,
pure snapshot-data codec and preflight definitions. Loading constructs no
State, Server, F, Collector, helper or radio owner and executes no collection.
The future stager must already have installed this fixed root; no mkdir,
namespace adoption, source fallback or sys.modules rollback is performed.

Every source is read from its actual immutable runtime file. Failed source
bytes/modules and original FD/once-close inventories remain retained. The
embedded manifest is the original 8096-byte data, SHA-authenticated before its
35 rows are compared with the fixed source table. Source provenance is not
admission, observation, baseline closure, restoration or sending permission.
Private IO/clock seams are explicit HOST models, not target certification.
Python objects do not protect against arbitrary in-process code alteration.
"""
import base64
import builtins
import errno
import hashlib
import math
import os
import re
import stat
import sys
import threading
import time
import types

ROOT = '/var/volatile/tmp/p011-mta-go-observer-diag-v1'
RUNTIME = ROOT + '/runtime'
ALIAS_ROOT = '/tmp/p011-mta-go-observer-diag-v1'
ALIAS_RUNTIME = ALIAS_ROOT + '/runtime'
MAX_SOURCE = 2 * 1024 * 1024
LOAD_SECONDS = 10.0
LOAD_COUNT = 38
ARM_READ = 0x88000
READONLY_MANIFEST_SHA = '8e7882aed5237eb4a2a704bee36bd8a8bdf930c079efae20a90d7dfc26a89b60'
READONLY_PREVIOUS_SHA = '4b9ea54997194ca895a3459cf88cd715b2ccc05e46c55b533920f8182314d07a'
READONLY_SCHEMA = 'client-readonly-diagnostic-v47-source'
LEAF_SHA = 'c2052c39fdad148d25f83743476b95a51a88e7f9e16ec2235c91d4de6adc9aad'

SOURCE_PINS = (
    ("p011_json", 8061, "fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88"),
    ("mta_ip", 22049, "1fa5e72817772285fd966f52c57af105950ff0d3b6ea49b202983aebfbab40c5"),
    ("mta_client_tmp_alias", 8827, "1a4a52bd0bae7add6ae42f66bd9827c43865a0170c666eaab00797d1f45f7f2f"),
    ("mta_p2p_client_init", 71315, "d3b51493d3ae778aeb72c1304dc50e5a6221428f7775bc7a28d15a3f19abeaaa"),
    ("mta_client_resource_budget", 16215, "56d6dbe2370279b1572a563e67fd3313bf942c0baa78fbd8e36cd973ba09839e"),
    ("mta_client_proc", 39384, "ede5953c33ba4c17d3aecb1fffe8a9358589497b37e3109034d5e1de3eadb3d6"),
    ("mta_client_caps", 11821, "c1792c2294fed5da16ec4a676423fbcbe53d44e9bc4ddadc1bc26fd45afe046c"),
    ("mta_client_caps_transport", 19614, "df6b4cf3ede6039c684c6b689a8b61ffe1ba5b87259bb4a5581aa5c3ece84420"),
    ("mta_client_baseline", 31338, "e950877bd99ee7907c66ee237e3140960ac8e4d64f979310b82bfdab2fa271ea"),
    ("mta_client_journal_codec", 17450, "2ffeca6b59498c9e2dfa4b9906bbe55db909d5d5e1d448fa0c795490996fe14a"),
    ("mta_client_coordination", 36295, "5b8a4295a5479cb5693182085fc8d35c6041bb0f14d9efb660ec11f024a5eeb3"),
    ("mta_client_files", 28938, "30c07bb4a5a28ce02aa76f35650ee1c87af63617f445e554c3fd7f73a2705864"),
    ("mta_client_pending", 53132, "deaf62f9830b951584b36100de0f88548bcd6356b7327c3be0fa8578b65aba8a"),
    ("mta_client_store", 74676, "bc51d3c64d3c92a87da331c740d93cea7466c535c5a81969422a45b8c5b68f63"),
    ("mta_client_process_owner", 34361, "c144bc197a8fd1d4fbbfc358ba0172a84f5c9070058732189e4709c8c801ffeb"),
    ("mta_client_launch_registration", 21679, "833d46f5717e0b7e9db0c5392a0eb93d812d039b4b946a57d49d5903534a1aa0"),
    ("mta_client_two_phase_lease", 27606, "c227989ec5188c272ad0a212974d569572704d3bb07c4c61c72670abcd0981a5"),
    ("mta_p2p_client_ctrl", 18712, "793b784f1b39eca18001aa65a1f0d6cdbd6de466dc58b3cf2ada167f71d902b5"),
    ("mta_client_wpa_status", 39133, "47074a5af8d9f75746fa7cd72e1e42b50c8402fcbb612963f6523c875fe1c269"),
    ("mta_protocol", 17958, "4f7c2bd46cde114f0a2a0c33b31631aa463f09e71b156d26e34daf2251dd8a57"),
    ("mta_client_control_frame", 20942, "d1a8fce91ab705524f14edac8d81e8d391c0cddbf8f4ac96ee7a6446c0512278"),
    ("mta_client_kernel_proof", 23702, "4ebfedf198673e3bad2f64a4bd72c581e5d6af24cef83e589b4456d2a38f8ede"),
    ("mta_client_connection", 22494, "ae2932252bbef16b89e6bf4614c2ebdb1721d507274dbd9b9fe4d9db1d0ff159"),
    ("mta_client_linux_provider", 174220, "5f080f8a0d53d7232ec95c303e0e84036d22d4e0927ac98dd3195291cf6d56ba"),
    ("mta_client_executor", 105182, "f3f7c9fb54e46f82b4321152dfac6f4ab9b037943c403d76716f8254700bb17e"),
    ("mta_dhcp", 15719, "631987bd7307580af069f1978e440d21fbd449ecc62c83e0e06195c330f50176"),
    ("mta_dhcp_client_core", 12362, "13c03d181139fd9ead7ff3bf2bcbb4930669f1e795b17360da85834dc345e9fa"),
    ("mta_dhcp_client", 24670, "794421678866d04a10ca46fa9eb7e17174f24c4d9e705cf59016b457702003a0"),
    ("mta_client_dora", 48149, "f17f8405b28799fda8ee8f3ea9d280f871cceb1e0c6b999fc855bcb652ab2f7e"),
    ("mta_client_dynamic_ip", 32427, "01476613eb965a05cd5441dfbfea53f15ce763da12213b76791ecdb23152199a"),
    ("mta_client_peer", 31242, "f8a15d046b505a8c5117a5be19d2ee59f38096759be1b29a0310535ceea08ec9"),
    ("mta_scoped_sockets", 26339, "b95cfbe724b43baf90511c9d2a4a39d869a40a57e78e2a87d398ea134f9f84b8"),
    ("mta_storage", 14335, "3c5c5f65ef0c8eb9a0256a99f931faff40558484bb908e89acee1c1c0aa3b4d6"),
    ("mta_transport", 35209, "77d9cd45936318315cf3343ab1bd2594c6a3381e33a7d0fdcfd853916063eefa"),
    ("mta_client_transfer", 30747, "8633b2a1156c3012ec613e776eaee7e9339c14c76cffff9c8e5ff75646f35184"),
    ('mta_client_readonly_baseline', 13934, LEAF_SHA),
    ('mta_snapshot_data', 17217, 'cb5e8f16c78cc4c879a8986dd9c2ab8ed5e6c055f105baad3ce60eb9a10d2a26'),
    ('mta_go_readonly_preflight', 64948, 'a10d6c9ff9ec4bf4b2d542120b19af3e36a111caf1153eaa8bc7d842aaa245eb'),
)
MODULES = tuple(row[0] for row in SOURCE_PINS)
_READONLY_MANIFEST_B64 = (
    'ewogICJwcmV2aW91c19tYW5pZmVzdF9zaGEyNTYiOiAiNGI5ZWE1NDk5NzE5NGNhODk1YTM0NTljZjg4Y2Q3MTViMmNjYzA1ZTQ2YzU1YjUzMzkyMGY4MTgyMzE0ZDA3'
    'YSIsCiAgInNjaGVtYSI6ICJjbGllbnQtcmVhZG9ubHktZGlhZ25vc3RpYy12NDctc291cmNlIiwKICAic291cmNlcyI6IFsKICAgIHsKICAgICAgImJ5dGVzIjogODA2'
    'MSwKICAgICAgIm1vZHVsZSI6ICJwMDExX2pzb24iLAogICAgICAicGF0aCI6ICJydW50aW1lL3AwMTFfanNvbi5weSIsCiAgICAgICJzaGEyNTYiOiAiZmI2YzgwM2Ix'
    'ODUyODMyNThjMjMxMmU2MzBkZjhiYjgwZDYyOTkwMDdlOTVhMWYzY2YzMTI1MGFhMGU4Y2E4OCIKICAgIH0sCiAgICB7CiAgICAgICJieXRlcyI6IDIyMDQ5LAogICAg'
    'ICAibW9kdWxlIjogIm10YV9pcCIsCiAgICAgICJwYXRoIjogInJ1bnRpbWUvbXRhX2lwLnB5IiwKICAgICAgInNoYTI1NiI6ICIxZmE1ZTcyODE3NzcyMjg1ZmQ5NjZm'
    'NTJjNTdhZjEwNTk1MGZmMGQzYjZlYTQ5YjIwMjk4M2FlYmZiYWI0MGM1IgogICAgfSwKICAgIHsKICAgICAgImJ5dGVzIjogODgyNywKICAgICAgIm1vZHVsZSI6ICJt'
    'dGFfY2xpZW50X3RtcF9hbGlhcyIsCiAgICAgICJwYXRoIjogImNhbmRpZGF0ZS9jbGllbnQtdG1wLWFsaWFzLXYxMS9ydW50aW1lL210YV9jbGllbnRfdG1wX2FsaWFz'
    'LnB5IiwKICAgICAgInNoYTI1NiI6ICIxYTRhNTJiZDBiYWU3YWRkNmFlNDJmNjZiZDk4MjdjNDM4NjVhMDE3MGM2NjZlYWFiMDA3OTdkMWY0NWY3ZjJmIgogICAgfSwK'
    'ICAgIHsKICAgICAgImJ5dGVzIjogNzEzMTUsCiAgICAgICJtb2R1bGUiOiAibXRhX3AycF9jbGllbnRfaW5pdCIsCiAgICAgICJwYXRoIjogImNhbmRpZGF0ZS9jbGll'
    'bnQtcGFyZW50LWNhcC12MzMvcnVudGltZS9tdGFfcDJwX2NsaWVudF9pbml0LnB5IiwKICAgICAgInNoYTI1NiI6ICJkM2I1MTQ5M2QzYWU3NzhhZWI3MmMxMzA0ZGM1'
    'MGU1YTYyMjE0MjhmNzc3NWJjN2EyOGQxNWEzZjE5YWJlYWFhIgogICAgfSwKICAgIHsKICAgICAgImJ5dGVzIjogMTYyMTUsCiAgICAgICJtb2R1bGUiOiAibXRhX2Ns'
    'aWVudF9yZXNvdXJjZV9idWRnZXQiLAogICAgICAicGF0aCI6ICJjYW5kaWRhdGUvY2xpZW50LXNlc3Npb24tdjI4L3J1bnRpbWUvbXRhX2NsaWVudF9yZXNvdXJjZV9i'
    'dWRnZXQucHkiLAogICAgICAic2hhMjU2IjogIjU2ZDZkYmUyMzcwMjc5YjE1NzJhNTYzZTY3ZmQzMzEzYmY5NDJjMGJhYTc4ZmJkOGUzNmNkOTczYmEwOTgzOWUiCiAg'
    'ICB9LAogICAgewogICAgICAiYnl0ZXMiOiAzOTM4NCwKICAgICAgIm1vZHVsZSI6ICJtdGFfY2xpZW50X3Byb2MiLAogICAgICAicGF0aCI6ICJjYW5kaWRhdGUvY2xp'
    'ZW50LXByb2MtZGVhZGxpbmUtdjI1L3J1bnRpbWUvbXRhX2NsaWVudF9wcm9jLnB5IiwKICAgICAgInNoYTI1NiI6ICJlZGU1OTUzYzMzYmE0YzE3ZDNhZWNiMWZmZmU4'
    'YTkzNTg1ODk0OTdiMzdlMzEwOTAzNGQ1ZTFkZTNlYWRiM2Q2IgogICAgfSwKICAgIHsKICAgICAgImJ5dGVzIjogMTE4MjEsCiAgICAgICJtb2R1bGUiOiAibXRhX2Ns'
    'aWVudF9jYXBzIiwKICAgICAgInBhdGgiOiAicnVudGltZS9tdGFfY2xpZW50X2NhcHMucHkiLAogICAgICAic2hhMjU2IjogImMxNzkyYzIyOTRmZWQ1ZGExNmVjNGE2'
    'NzY0MjNmYmNiZTUzZDQ0ZTliYzRkZGFkYzFiYzI2ZmQ0NWFmZTA0NmMiCiAgICB9LAogICAgewogICAgICAiYnl0ZXMiOiAxOTYxNCwKICAgICAgIm1vZHVsZSI6ICJt'
    'dGFfY2xpZW50X2NhcHNfdHJhbnNwb3J0IiwKICAgICAgInBhdGgiOiAicnVudGltZS9tdGFfY2xpZW50X2NhcHNfdHJhbnNwb3J0LnB5IiwKICAgICAgInNoYTI1NiI6'
    'ICJkZjZiNGNmM2VkZTYwMzljNjg0YzZiNjg5YThiNjFmZmUxYmE1Yjg3MjU5YmI0YTU1ODFhYTVjM2VjZTg0NDIwIgogICAgfSwKICAgIHsKICAgICAgImJ5dGVzIjog'
    'MzEzMzgsCiAgICAgICJtb2R1bGUiOiAibXRhX2NsaWVudF9iYXNlbGluZSIsCiAgICAgICJwYXRoIjogImNhbmRpZGF0ZS9jbGllbnQtcmVhZG9ubHktcHJvYy12YW5p'
    'c2gtdjUxL3J1bnRpbWUvbXRhX2NsaWVudF9iYXNlbGluZS5weSIsCiAgICAgICJzaGEyNTYiOiAiZTk1MDg3N2JkOTllZTc5MDdjNjZlZTIzN2UzMTQwOTYwYWM4ZTRk'
    'NjRmOTc5MzEwYjgyYmZkYWIyZmEyNzFlYSIKICAgIH0sCiAgICB7CiAgICAgICJieXRlcyI6IDE3NDUwLAogICAgICAibW9kdWxlIjogIm10YV9jbGllbnRfam91cm5h'
    'bF9jb2RlYyIsCiAgICAgICJwYXRoIjogImNhbmRpZGF0ZS9jbGllbnQtc2Vzc2lvbi12MjgvcnVudGltZS9tdGFfY2xpZW50X2pvdXJuYWxfY29kZWMucHkiLAogICAg'
    'ICAic2hhMjU2IjogIjJmZmVjYTZiNTk0OThjOWUyZGZhNGI5OTA2YmJlNTVkYjkwOWQ1ZDVlMWQ0NDhmYTBjNzk1NDkwOTk2ZmUxNGEiCiAgICB9LAogICAgewogICAg'
    'ICAiYnl0ZXMiOiAzNjI5NSwKICAgICAgIm1vZHVsZSI6ICJtdGFfY2xpZW50X2Nvb3JkaW5hdGlvbiIsCiAgICAgICJwYXRoIjogImNhbmRpZGF0ZS9jbGllbnQtYnVk'
    'Z2V0LXJlZnVzYWwtdjM2L3J1bnRpbWUvbXRhX2NsaWVudF9jb29yZGluYXRpb24ucHkiLAogICAgICAic2hhMjU2IjogIjViOGE0Mjk1YTU0NzljYjU2OTMxODIwODVm'
    'YzhkMzVjNjA0MWJiMGYxNGQ5ZWZiNjYwZWMxMWYwMjRhNWVlYjMiCiAgICB9LAogICAgewogICAgICAiYnl0ZXMiOiAyODkzOCwKICAgICAgIm1vZHVsZSI6ICJtdGFf'
    'Y2xpZW50X2ZpbGVzIiwKICAgICAgInBhdGgiOiAiY2FuZGlkYXRlL2NsaWVudC1yZXNvdXJjZS12MjMvcnVudGltZS9tdGFfY2xpZW50X2ZpbGVzLnB5IiwKICAgICAg'
    'InNoYTI1NiI6ICIzMGMwN2JiNGE1YTI4Y2UwMmFhNzZmMzU2NTBlZTFjODdhZjYzNjE3ZjQ0NWU1NTRjM2ZkN2Y3M2EyNzA1ODY0IgogICAgfSwKICAgIHsKICAgICAg'
    'ImJ5dGVzIjogNTMxMzIsCiAgICAgICJtb2R1bGUiOiAibXRhX2NsaWVudF9wZW5kaW5nIiwKICAgICAgInBhdGgiOiAiY2FuZGlkYXRlL2NsaWVudC1idWRnZXQtcmVm'
    'dXNhbC12MzYvcnVudGltZS9tdGFfY2xpZW50X3BlbmRpbmcucHkiLAogICAgICAic2hhMjU2IjogImRlYWY2MmY5ODMwYjk1MTU4NGIzNjEwMGRlMGY4ODU0OGJjZDYz'
    'NTZiNzMyN2MzYmUwZmE4NTc4YjY1YWJhOGEiCiAgICB9LAogICAgewogICAgICAiYnl0ZXMiOiA3NDY3NiwKICAgICAgIm1vZHVsZSI6ICJtdGFfY2xpZW50X3N0b3Jl'
    'IiwKICAgICAgInBhdGgiOiAiY2FuZGlkYXRlL2NsaWVudC1pbnRlZ3JhdGVkLXYzNy9ydW50aW1lL210YV9jbGllbnRfc3RvcmUucHkiLAogICAgICAic2hhMjU2Ijog'
    'ImJjNTFkM2M2NGQzYzkyYTg3ZGEzMzFjNzQwZDkzY2VhNzQ2NmM1MzVjNWE4MTk2OTQyMmE0NWI4YzViNjhmNjMiCiAgICB9LAogICAgewogICAgICAiYnl0ZXMiOiAz'
    'NDM2MSwKICAgICAgIm1vZHVsZSI6ICJtdGFfY2xpZW50X3Byb2Nlc3Nfb3duZXIiLAogICAgICAicGF0aCI6ICJjYW5kaWRhdGUvY2xpZW50LXRyYW5zZmVyLXYzMC1y'
    'Mi9ydW50aW1lL210YV9jbGllbnRfcHJvY2Vzc19vd25lci5weSIsCiAgICAgICJzaGEyNTYiOiAiYzE0NGJjMTk3YThmZDFkNGZiYmZjMzU4YmEwMTcyYTg0ZjVjOTA3'
    'MDA1ODczMjE4OWU0NzA5YzhjODAxZmZlYiIKICAgIH0sCiAgICB7CiAgICAgICJieXRlcyI6IDIxNjc5LAogICAgICAibW9kdWxlIjogIm10YV9jbGllbnRfbGF1bmNo'
    'X3JlZ2lzdHJhdGlvbiIsCiAgICAgICJwYXRoIjogInJ1bnRpbWUvbXRhX2NsaWVudF9sYXVuY2hfcmVnaXN0cmF0aW9uLnB5IiwKICAgICAgInNoYTI1NiI6ICI4MzNk'
    'NDZmNTcxN2UwYjdlOWRiMGM1MzkyYTBlYjkzZDgxMmQwMzliNGI5NDZhNTdkNDlkNTkwMzUzNGExYWEwIgogICAgfSwKICAgIHsKICAgICAgImJ5dGVzIjogMjc2MDYs'
    'CiAgICAgICJtb2R1bGUiOiAibXRhX2NsaWVudF90d29fcGhhc2VfbGVhc2UiLAogICAgICAicGF0aCI6ICJjYW5kaWRhdGUvY2xpZW50LXBhcmVudC1jYXAtdjMzL3J1'
    'bnRpbWUvbXRhX2NsaWVudF90d29fcGhhc2VfbGVhc2UucHkiLAogICAgICAic2hhMjU2IjogImMyMjc5ODllYzUxODhjMjcyYWQwYTIxMjk3NGQ1Njk1NzI3MDRkM2Ji'
    'MDdjNGM2MWM3MjY3MGFiY2QwOTgxYTUiCiAgICB9LAogICAgewogICAgICAiYnl0ZXMiOiAxODcxMiwKICAgICAgIm1vZHVsZSI6ICJtdGFfcDJwX2NsaWVudF9jdHJs'
    'IiwKICAgICAgInBhdGgiOiAicnVudGltZS9tdGFfcDJwX2NsaWVudF9jdHJsLnB5IiwKICAgICAgInNoYTI1NiI6ICI3OTNiNzg0ZjFiMzllY2ExODAwMWFhNjVhMWYw'
    'ZDZjZGJkNmRlNDY2ZGM1OGIzY2YyYWRhMTY3ZjcxZDkwMmI1IgogICAgfSwKICAgIHsKICAgICAgImJ5dGVzIjogMzkxMzMsCiAgICAgICJtb2R1bGUiOiAibXRhX2Ns'
    'aWVudF93cGFfc3RhdHVzIiwKICAgICAgInBhdGgiOiAiY2FuZGlkYXRlL2NsaWVudC1wcm9jLWRlYWRsaW5lLXYyNS9ydW50aW1lL210YV9jbGllbnRfd3BhX3N0YXR1'
    'cy5weSIsCiAgICAgICJzaGEyNTYiOiAiNDcwNzRhNWFmOGQ5Zjc1NzQ2ZmE3Y2Q3MmUxZTQyYjUwYzg0MDJmY2JiNjEyOTYzZjY1MjNjODc1ZmUxYzI2OSIKICAgIH0s'
    'CiAgICB7CiAgICAgICJieXRlcyI6IDE3OTU4LAogICAgICAibW9kdWxlIjogIm10YV9wcm90b2NvbCIsCiAgICAgICJwYXRoIjogInJ1bnRpbWUvbXRhX3Byb3RvY29s'
    'LnB5IiwKICAgICAgInNoYTI1NiI6ICI0ZjdjMmJkNDZjZGUxMTRmMGEyYTBjMzNiMzE2MzFhYTQ2M2YwOWU3MWIxNTZkMjZlMzRkYWYyMjUxZGQ4YTU3IgogICAgfSwK'
    'ICAgIHsKICAgICAgImJ5dGVzIjogMjA5NDIsCiAgICAgICJtb2R1bGUiOiAibXRhX2NsaWVudF9jb250cm9sX2ZyYW1lIiwKICAgICAgInBhdGgiOiAiY2FuZGlkYXRl'
    'L2NsaWVudC1pbnRlZ3JhdGVkLXYzNy9ydW50aW1lL210YV9jbGllbnRfY29udHJvbF9mcmFtZS5weSIsCiAgICAgICJzaGEyNTYiOiAiZDFhOGZjZTkxYWI3MDU1MjRm'
    'MTRlZGFjOGQ4MWU4ZDM5MWMwY2RkYmY4ZjRhYzk2ZWU3YTY0NDZjMDUxMjI3OCIKICAgIH0sCiAgICB7CiAgICAgICJieXRlcyI6IDIzNzAyLAogICAgICAibW9kdWxl'
    'IjogIm10YV9jbGllbnRfa2VybmVsX3Byb29mIiwKICAgICAgInBhdGgiOiAiY2FuZGlkYXRlL2NsaWVudC1hc3NvY2lhdGlvbi12MTYvcnVudGltZS9tdGFfY2xpZW50'
    'X2tlcm5lbF9wcm9vZi5weSIsCiAgICAgICJzaGEyNTYiOiAiNGViZmVkZjE5ODY3M2UzYmFkMmY2NGE0YmQ3MmM1ODFlNWQ2YWYyNGNlZjgzZTU4OWI0NDU2ZDJhMzhm'
    'OGVkZSIKICAgIH0sCiAgICB7CiAgICAgICJieXRlcyI6IDIyNDk0LAogICAgICAibW9kdWxlIjogIm10YV9jbGllbnRfY29ubmVjdGlvbiIsCiAgICAgICJwYXRoIjog'
    'ImNhbmRpZGF0ZS9jbGllbnQtZHVyYWJsZS1jb25uZWN0LXYxOS9ydW50aW1lL210YV9jbGllbnRfY29ubmVjdGlvbi5weSIsCiAgICAgICJzaGEyNTYiOiAiYWUyOTMy'
    'MjUyYmJlZjE2Yjg5ZTZiZjQ2MTRjMmViZGIxNzIxZDUwNzI3NGRiZDliOWZlNGQ5ZGIxZDBmZjE1OSIKICAgIH0sCiAgICB7CiAgICAgICJieXRlcyI6IDE3NDIyMCwK'
    'ICAgICAgIm1vZHVsZSI6ICJtdGFfY2xpZW50X2xpbnV4X3Byb3ZpZGVyIiwKICAgICAgInBhdGgiOiAiY2FuZGlkYXRlL2NsaWVudC1pbnRlZ3JhdGVkLXYzNy9ydW50'
    'aW1lL210YV9jbGllbnRfbGludXhfcHJvdmlkZXIucHkiLAogICAgICAic2hhMjU2IjogIjVmMDgwZjhhMGQ1M2Q3MjMyZWM5NWMzMDNlMGU4NDAzNmQyMmQ0ZTA5Mjdh'
    'Yzk4ZGQzMTk1MjkxY2Y2ZDU2YmEiCiAgICB9LAogICAgewogICAgICAiYnl0ZXMiOiAxMDUxODIsCiAgICAgICJtb2R1bGUiOiAibXRhX2NsaWVudF9leGVjdXRvciIs'
    'CiAgICAgICJwYXRoIjogImNhbmRpZGF0ZS9jbGllbnQtaW50ZWdyYXRlZC12MzcvcnVudGltZS9tdGFfY2xpZW50X2V4ZWN1dG9yLnB5IiwKICAgICAgInNoYTI1NiI6'
    'ICJmM2Y3YzlmYjU0ZTQ2ZjgyYjQzMjExNTJkZmFjNmY0YWI5YjAzNzk0M2M0MDNkNzY3MTZmODI1NDcwMGJiMTdlIgogICAgfSwKICAgIHsKICAgICAgImJ5dGVzIjog'
    'MTU3MTksCiAgICAgICJtb2R1bGUiOiAibXRhX2RoY3AiLAogICAgICAicGF0aCI6ICJydW50aW1lL210YV9kaGNwLnB5IiwKICAgICAgInNoYTI1NiI6ICI2MzE5ODdi'
    'ZDczMDc1ODBhZjA2OWYxOTc4ZTQ0MGQyMWZiZDQ0OWVjYzYyYzgzZTBlMDYxOTVjMzMwZjUwMTc2IgogICAgfSwKICAgIHsKICAgICAgImJ5dGVzIjogMTIzNjIsCiAg'
    'ICAgICJtb2R1bGUiOiAibXRhX2RoY3BfY2xpZW50X2NvcmUiLAogICAgICAicGF0aCI6ICJydW50aW1lL210YV9kaGNwX2NsaWVudF9jb3JlLnB5IiwKICAgICAgInNo'
    'YTI1NiI6ICIxM2MwM2QxODExMzlmZDllYWQ3ZmYzYmYyYmNiYjQ5MzA2NjlmMWU3OTViMTczNjBkYTg1ODM0ZGMzNDVlOWZhIgogICAgfSwKICAgIHsKICAgICAgImJ5'
    'dGVzIjogMjQ2NzAsCiAgICAgICJtb2R1bGUiOiAibXRhX2RoY3BfY2xpZW50IiwKICAgICAgInBhdGgiOiAiY2FuZGlkYXRlL2NsaWVudC1kaGNwLXYyMS9ydW50aW1l'
    'L210YV9kaGNwX2NsaWVudC5weSIsCiAgICAgICJzaGEyNTYiOiAiNzk0NDIxNjc4ODY2ZDA0YTEwY2E0NmZhOWViN2UxNzE3NGYyNGM0ZDllNzA1Y2Y1OTAxNmI0NTc3'
    'MDIwMDNhMCIKICAgIH0sCiAgICB7CiAgICAgICJieXRlcyI6IDQ4MTQ5LAogICAgICAibW9kdWxlIjogIm10YV9jbGllbnRfZG9yYSIsCiAgICAgICJwYXRoIjogImNh'
    'bmRpZGF0ZS9jbGllbnQtc2Vzc2lvbi12MjgvcnVudGltZS9tdGFfY2xpZW50X2RvcmEucHkiLAogICAgICAic2hhMjU2IjogImYxN2Y4NDA1YjI4Nzk5ZmRhOGVlOGYz'
    'ZWE5ZDI4MGY4NzFjY2ViMWUwYzZiOTk5ZmM4NTViY2I2NTJhYjJmN2UiCiAgICB9LAogICAgewogICAgICAiYnl0ZXMiOiAzMjQyNywKICAgICAgIm1vZHVsZSI6ICJt'
    'dGFfY2xpZW50X2R5bmFtaWNfaXAiLAogICAgICAicGF0aCI6ICJjYW5kaWRhdGUvY2xpZW50LXNlc3Npb24tdjI4LXIyL3J1bnRpbWUvbXRhX2NsaWVudF9keW5hbWlj'
    'X2lwLnB5IiwKICAgICAgInNoYTI1NiI6ICIwMTQ3NjYxM2ViOTY1YTA1Y2Q1NDQxZGZiZmVhNTNmMTVjZTc2M2RhMTIyMTNiNzY3OTFlY2RiMjMxNTIxOTlhIgogICAg'
    'fSwKICAgIHsKICAgICAgImJ5dGVzIjogMzEyNDIsCiAgICAgICJtb2R1bGUiOiAibXRhX2NsaWVudF9wZWVyIiwKICAgICAgInBhdGgiOiAiY2FuZGlkYXRlL2NsaWVu'
    'dC1wZWVyLXYyOS1yMy9ydW50aW1lL210YV9jbGllbnRfcGVlci5weSIsCiAgICAgICJzaGEyNTYiOiAiZjhhMTVkMDQ2YjUwNWE4YzUxMTdhNWJlMTlkMmVlNTlmMzgw'
    'OTY3NTliZTFiMjlhMDMxMDUzNWNlZWEwOGVjOSIKICAgIH0sCiAgICB7CiAgICAgICJieXRlcyI6IDI2MzM5LAogICAgICAibW9kdWxlIjogIm10YV9zY29wZWRfc29j'
    'a2V0cyIsCiAgICAgICJwYXRoIjogInJ1bnRpbWUvbXRhX3Njb3BlZF9zb2NrZXRzLnB5IiwKICAgICAgInNoYTI1NiI6ICJiOTVjZmJlNzI0YjQzYmFmOTA1MTFjOWQy'
    'YTRhMzlkODY5YTQwYTU3ZTc4ZTJhODdkMzk4ZWExMzRmOWY4NGI4IgogICAgfSwKICAgIHsKICAgICAgImJ5dGVzIjogMTQzMzUsCiAgICAgICJtb2R1bGUiOiAibXRh'
    'X3N0b3JhZ2UiLAogICAgICAicGF0aCI6ICJydW50aW1lL210YV9zdG9yYWdlLnB5IiwKICAgICAgInNoYTI1NiI6ICIzYzVjNWY2NWVmMGM4ZWI5YTAyNTZhOTlmOTMx'
    'ZmFmZjQwNTU4NDg0YmI5MDhlODlhY2VlMWMxYzBhYTNiNGQ2IgogICAgfSwKICAgIHsKICAgICAgImJ5dGVzIjogMzUyMDksCiAgICAgICJtb2R1bGUiOiAibXRhX3Ry'
    'YW5zcG9ydCIsCiAgICAgICJwYXRoIjogImNhbmRpZGF0ZS9jbGllbnQtdHJhbnNmZXItdjMwL3J1bnRpbWUvbXRhX3RyYW5zcG9ydC5weSIsCiAgICAgICJzaGEyNTYi'
    'OiAiNzdkOWNkNDU5MzYzMTgzMTVjZjMzNDNhYjFiZDI1OTRjNmEzMzgxZTMzYTdkMGZkY2ZkODUzOTE2MDYzZWVmYSIKICAgIH0sCiAgICB7CiAgICAgICJieXRlcyI6'
    'IDMwNzQ3LAogICAgICAibW9kdWxlIjogIm10YV9jbGllbnRfdHJhbnNmZXIiLAogICAgICAicGF0aCI6ICJjYW5kaWRhdGUvY2xpZW50LXRyYW5zZmVyLXYzMC1yMy9y'
    'dW50aW1lL210YV9jbGllbnRfdHJhbnNmZXIucHkiLAogICAgICAic2hhMjU2IjogIjg2MzNiMmExMTU2YzMwMTJlYzYxM2U3NzZlYWVlN2U5MzM5YzE0Yzc2Y2ZmZmY5'
    'YzhlNWZmNzU2NDZmMzUxODQiCiAgICB9CiAgXQp9Cgo='
)
_SOURCE_PINS_ORIGINAL = SOURCE_PINS
_MODULES_ORIGINAL = MODULES
_MANIFEST_B64_ORIGINAL = _READONLY_MANIFEST_B64


class ReadonlyLoaderError(ValueError):
    def __init__(self, code):
        self.code = code
        ValueError.__init__(self, code)


def _fail(code):
    raise ReadonlyLoaderError(code) from None


def _finite(value):
    return type(value) in (int, float) and 0 <= value < 1e12 and math.isfinite(float(value))


def _meta(value):
    result = tuple(getattr(value, name, None) for name in
        ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size'))
    if any(type(item) is not int or not 0 <= item < (1 << 64) for item in result):
        _fail('metadata_unknown')
    return result


def _source_path(name):
    if name not in MODULES:
        _fail('source_role_unknown')
    return RUNTIME + '/' + name + '.py'


class _LinuxIo(object):
    def validate(self):
        if (sys.platform != 'linux' or sys.byteorder != 'little' or os.geteuid() != 0 or
                os.uname()[4] != 'armv7l' or tuple(sys.version_info[:3]) != (3, 5, 5) or
                sys.flags.optimize or os.O_NOFOLLOW != 0x8000 or os.O_CLOEXEC != 0x80000):
            _fail('unsupported_platform')
    def pid(self):
        return os.getpid()
    def stat(self, path):
        return os.stat(path, follow_symlinks=False)
    def readlink(self, path):
        return os.readlink(path)
    def open(self, path):
        return os.open(path, ARM_READ)
    def fstat(self, fd):
        return os.fstat(fd)
    def read(self, fd, count):
        return os.read(fd, count)
    def close(self, fd):
        return os.close(fd)


class ReadonlySourceLoader(object):
    """One fixed definitions lifetime on the original worker and absolute cap.

    load() alone consumes one min(original_until, first_load_now + 10) slice.
    authenticate() is passive same-owner/source/closure verification; it does
    not renew that slice or call any collector/preflight function.
    """
    def __init__(self, original_until, _io=None, _clock=None):
        if not _finite(original_until):
            _fail('invalid_budget')
        self.until = self._original_until = float(original_until)
        self.io = self._io_original = _LinuxIo() if _io is None else _io
        self.clock = self._clock_original = time.monotonic if _clock is None else _clock
        if not callable(self.clock):
            _fail('invalid_clock')
        self.worker = threading.current_thread()
        self.pid = None
        self.deadline = self._original_deadline = None
        self.last = None
        self.rows = self._rows_original = []
        self.raw = self._raw_original = []
        self.modules = self._modules_original = {}
        self.module_originals = self._module_originals_original = []
        self.attempted = self.ended = self.pending = False
        self.failure = None
        self._root_original = None
        self._manifest_raw = self._manifest_raw_original = None
        self._manifest_value = None
        self._source_rows_original = None
        self._definition_rows_original = None
        self._seal_original = None

    def _context(self):
        if (self.io is not self._io_original or self.clock is not self._clock_original or
                self.until is not self._original_until or threading.current_thread() is not self.worker or
                self.deadline is not self._original_deadline or self.rows is not self._rows_original or
                self.raw is not self._raw_original or self.modules is not self._modules_original or
                self.module_originals is not self._module_originals_original):
            _fail('owner_changed')
        if self.pid is not None and self.io.pid() != self.pid:
            _fail('owner_changed')

    def check(self):
        self._context()
        now = self.clock()
        if not _finite(now) or self.last is not None and now < self.last:
            _fail('invalid_clock')
        self.last = float(now)
        cap = self.until if self.deadline is None else self.deadline
        if now >= cap:
            _fail('deadline')
        return float(now)

    def _anchors(self):
        self.check()
        paths = ('/', '/tmp', '/var', '/var/tmp', '/var/volatile',
                 '/var/volatile/tmp', ROOT, RUNTIME)
        modes = (None, stat.S_IFLNK | 0o777, stat.S_IFDIR | 0o755,
                 stat.S_IFLNK | 0o777, stat.S_IFDIR | 0o1777,
                 stat.S_IFDIR | 0o1777, stat.S_IFDIR | 0o700, stat.S_IFDIR | 0o700)
        result = []
        for path, mode in zip(paths, modes):
            self.check()
            actual_stat = self.io.stat(path)
            row = _meta(actual_stat)
            if (row[3:5] != (0, 0) or
                    mode is None and (not stat.S_ISDIR(row[2]) or row[2] & 0o022) or
                    mode is not None and row[2] != mode or row[5] < 1):
                _fail('unsafe_root')
            if stat.S_ISLNK(row[2]):
                times = tuple(getattr(actual_stat, key, None) for key in ('st_mtime_ns', 'st_ctime_ns'))
                if row[5] != 1 or any(type(item) is not int or not 0 <= item < (1 << 64) for item in times):
                    _fail('unsafe_root')
                target = '/var/tmp' if path == '/tmp' else '/var/volatile/tmp'
                self.check()
                observed = self.io.readlink(path)
                if type(observed) is not str or observed != target or row[6] != len(target):
                    _fail('unsafe_root')
                result.append((path, row + times, target))
            else:
                result.append((path, row[:5], None))
        for virtual, physical in ((ALIAS_ROOT, ROOT), (ALIAS_RUNTIME, RUNTIME)):
            self.check()
            virtual_meta = _meta(self.io.stat(virtual))
            self.check()
            physical_meta = _meta(self.io.stat(physical))
            if virtual_meta[:5] != physical_meta[:5]:
                _fail('root_changed')
        self.check()
        value = tuple(result)
        if self._root_original is None:
            self._root_original = value
        elif value != self._root_original:
            _fail('root_changed')
        return value

    def _close_row(self, row):
        self._context()  # Expiry never suppresses the original known-FD close.
        if not any(row is original for original in self.rows):
            return False
        if row['attempted']:
            return row['closed'] is True and row['unknown'] is False
        if row['unknown'] or type(row['fd']) is not int:
            self.pending = True
            return False
        row['attempted'] = True
        try:
            if _meta(self.io.fstat(row['fd'])) != row['metadata']:
                _fail('close_unknown')
            returned = self.io.close(row['fd'])
            row['close_return'] = returned
            try:
                self.io.fstat(row['fd'])
            except OSError as error:
                row['close_error'] = error
                row['closed'] = returned is None and type(error.errno) is int and error.errno == errno.EBADF
        except BaseException as error:
            row['close_failure'] = error
            row['unknown'] = True
        if row['closed'] is not True:
            self.pending = True
        return row['closed'] is True and row['unknown'] is False

    def _read_source(self, name, size, pin):
        self.check()
        if len(self.rows) >= LOAD_COUNT:
            _fail('file_budget')
        before = self._anchors()
        path = _source_path(name)
        row = {'path': path, 'name': name, 'size': size, 'pin': pin,
               'fd': None, 'metadata': None, 'raw': None, 'read_values': [], 'unknown': True,
               'attempted': False, 'closed': False, 'open_called': False, 'open_error': None,
               'read_error': None, 'close_return': None, 'close_error': None, 'close_failure': None}
        self.rows.append(row)  # Original ticket before open; no missing-file retry.
        try:
            self.check()
            row['open_called'] = True
            try:
                row['fd'] = self.io.open(path)
            except BaseException as error:
                row['open_error'] = error
                raise
            if (type(row['fd']) is not int or row['fd'] < 0 or any(other is not row and
                    other['fd'] == row['fd'] and not other['closed'] for other in self.rows)):
                _fail('descriptor_unknown')
            # Retain the returned FD and its close identity BEFORE active expiry
            # checks; only exact fstat metadata can authorize once close.
            meta = _meta(self.io.fstat(row['fd']))
            row['metadata'], row['unknown'] = meta, False
            self.check()
            if (not stat.S_ISREG(meta[2]) or stat.S_IMODE(meta[2]) != 0o400 or
                    meta[3:6] != (0, 0, 1) or meta[6] != size):
                _fail('source_shape')
            chunks, total = [], 0
            while total <= size:
                self.check()
                count = min(65536, size + 1 - total)
                raw = self.io.read(row['fd'], count)
                row['read_values'].append(raw)  # Retain a returned read before rejecting lateness.
                self.check()
                if type(raw) is not bytes or len(raw) > count:
                    _fail('source_shape')
                chunks.append(raw)
                total += len(raw)
                if not raw:
                    break
            raw = b''.join(chunks)
            row['raw'] = raw
            self.raw.append((name, raw))
            if (len(raw) != size or hashlib.sha256(raw).hexdigest() != pin or
                    _meta(self.io.fstat(row['fd'])) != meta or _meta(self.io.stat(path)) != meta or
                    _meta(self.io.stat(ALIAS_RUNTIME + '/' + name + '.py')) != meta or
                    self._anchors() != before):
                _fail('source_changed')
            self.check()
            return raw
        except BaseException as error:
            row['read_error'] = error
            raise
        finally:
            try:
                if not self._close_row(row):
                    self.pending = True
            except BaseException as error:
                row['close_failure'] = error
                self.pending = True

    def _source_shape(self):
        if (SOURCE_PINS is not _SOURCE_PINS_ORIGINAL or MODULES is not _MODULES_ORIGINAL or
                _READONLY_MANIFEST_B64 is not _MANIFEST_B64_ORIGINAL or
                type(SOURCE_PINS) is not tuple or len(SOURCE_PINS) != LOAD_COUNT or
                SOURCE_PINS[0] != ('p011_json', 8061,
                    'fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88') or
                SOURCE_PINS[35] != ('mta_client_readonly_baseline', 13934, LEAF_SHA) or
                MODULES[-2:] != ('mta_snapshot_data', 'mta_go_readonly_preflight')):
            _fail('source_shape')
        names = []
        for row in SOURCE_PINS:
            if (type(row) is not tuple or len(row) != 3 or type(row[0]) is not str or
                    re.fullmatch('[a-z][a-z0-9_]{0,63}', row[0]) is None or
                    type(row[1]) is not int or not 0 < row[1] <= MAX_SOURCE or
                    type(row[2]) is not str or re.fullmatch('[0-9a-f]{64}', row[2]) is None):
                _fail('source_shape')
            names.append(row[0])
        if tuple(names) != MODULES or len(set(names)) != LOAD_COUNT:
            _fail('source_shape')
        raw = base64.b64decode(_READONLY_MANIFEST_B64, validate=True)
        if len(raw) != 8096 or hashlib.sha256(raw).hexdigest() != READONLY_MANIFEST_SHA:
            _fail('source_seal')
        self._manifest_raw = self._manifest_raw_original = raw

    def _seal_readonly_manifest(self):
        codec = self.modules['p011_json']
        value = codec.loads(self._manifest_raw.decode('utf-8', 'strict'))
        if (type(value) is not dict or set(value) != {'previous_manifest_sha256', 'schema', 'sources'} or
                value['previous_manifest_sha256'] != READONLY_PREVIOUS_SHA or
                value['schema'] != READONLY_SCHEMA or type(value['sources']) is not list or
                len(value['sources']) != 35):
            _fail('source_seal')
        for expected, row in zip(SOURCE_PINS[:35], value['sources']):
            if (type(row) is not dict or set(row) != {'module', 'path', 'bytes', 'sha256'} or
                    type(row['path']) is not str or type(row['bytes']) is not int or
                    (row['module'], row['bytes'], row['sha256']) != expected):
                _fail('source_seal')
        self._manifest_value = value
        self._seal_original = (self._manifest_raw, codec, codec.loads, SOURCE_PINS,
                               self.modules['mta_client_readonly_baseline'],
                               self.modules['mta_snapshot_data'],
                               self.modules['mta_go_readonly_preflight'])

    def load(self):
        if self.attempted:
            _fail('already_attempted')
        self.attempted = True
        try:
            now = self.check()
            self.deadline = self._original_deadline = min(self.until, now + LOAD_SECONDS)
            self._source_shape()
            if self.rows or self.raw or self.modules or self.module_originals:
                _fail('owner_changed')
            for name, existing in tuple(sys.modules.items()):
                if type(name) is not str or not (name in MODULES or name.startswith(('mta_', 'p011_'))):
                    continue
                if name == __name__ and type(existing) is types.ModuleType and existing.__dict__ is globals():
                    continue
                _fail('canonical_namespace_busy')
            self.check()
            self.io.validate()
            self.check()
            self.pid = self.io.pid()
            if type(self.pid) is not int or not 1 <= self.pid <= 0x7fffffff:
                _fail('owner_changed')
            self.check()
            original_import = builtins.__import__

            def pinned_import(name, globals=None, locals=None, fromlist=(), level=0):
                if type(name) is not str or level:
                    _fail('source_import')
                if name in MODULES:
                    if name not in self.modules or sys.modules.get(name) is not self.modules[name]:
                        _fail('source_import')
                    return self.modules[name]
                if name.startswith(('mta_', 'p011_')):
                    _fail('source_import')
                return original_import(name, globals, locals, fromlist, level)

            for name, size, pin in SOURCE_PINS:
                raw = self._read_source(name, size, pin)
                if self.pending:
                    _fail('close_unknown')
                self.check()
                if name in sys.modules:
                    _fail('canonical_namespace_busy')
                module = types.ModuleType(name)
                module.__file__ = _source_path(name)
                module.__dict__['__builtins__'] = dict(vars(builtins), __import__=pinned_import)
                self.modules[name] = module
                self.module_originals.append((name, module, module.__dict__))
                sys.modules[name] = module  # Failed definitions remain owned, never rolled back.
                exec(raw, module.__dict__)
                self.check()
            self._seal_readonly_manifest()
            self.check()
            self._anchors()
            self._source_rows_original = tuple(self.rows)
            self._definition_rows_original = tuple(self.module_originals)
        except BaseException as error:
            self.failure = error
            raise
        finally:
            for row in reversed(self.rows):
                try:
                    if not self._close_row(row):
                        self.pending = True
                except BaseException as error:
                    self.pending = True
                    if self.failure is None:
                        self.failure = error
            self.ended = True
        self.authenticate()
        return self

    def authenticate(self):
        self._context()
        if (self.attempted is not True or self.ended is not True or self.failure is not None or
                self.pending is not False or type(self._source_rows_original) is not tuple or
                type(self._definition_rows_original) is not tuple or
                len(self.rows) != LOAD_COUNT or len(self.raw) != LOAD_COUNT or
                len(self.module_originals) != LOAD_COUNT or len(self.modules) != LOAD_COUNT or
                len(self._source_rows_original) != LOAD_COUNT or
                len(self._definition_rows_original) != LOAD_COUNT or
                any(row is not original for row, original in zip(self.rows, self._source_rows_original)) or
                any(row is not original for row, original in
                    zip(self.module_originals, self._definition_rows_original))):
            _fail('source_unavailable')
        for expected, row, retained, definition in zip(SOURCE_PINS, self.rows, self.raw, self.module_originals):
            name, size, pin = expected
            actual_name, module, original_dict = definition
            if (type(row) is not dict or row['unknown'] is not False or row['closed'] is not True or
                    row['attempted'] is not True or row['close_return'] is not None or
                    row['close_failure'] is not None or not isinstance(row['close_error'], OSError) or
                    type(row['close_error'].errno) is not int or
                    row['close_error'].errno != errno.EBADF or row['path'] != _source_path(name) or
                    (row['name'], row['size'], row['pin']) != expected or type(row['raw']) is not bytes or
                    len(row['raw']) != size or type(retained) is not tuple or len(retained) != 2 or
                    retained[0] != name or retained[1] is not row['raw'] or actual_name != name or
                    type(module) is not types.ModuleType or self.modules.get(name) is not module or
                    sys.modules.get(name) is not module or module.__dict__ is not original_dict or
                    module.__file__ != _source_path(name)):
                _fail('source_changed')
        seal = self._seal_original
        if (type(seal) is not tuple or len(seal) != 7 or
                self._manifest_raw is not self._manifest_raw_original or seal[0] is not self._manifest_raw or
                seal[1] is not self.modules['p011_json'] or seal[2] is not seal[1].loads or
                seal[3] is not SOURCE_PINS or SOURCE_PINS is not _SOURCE_PINS_ORIGINAL or
                MODULES is not _MODULES_ORIGINAL or
                seal[4] is not self.modules['mta_client_readonly_baseline'] or
                seal[5] is not self.modules['mta_snapshot_data'] or
                seal[6] is not self.modules['mta_go_readonly_preflight'] or
                seal[4].SOURCE_MANIFEST_SHA != READONLY_MANIFEST_SHA):
            _fail('source_seal')
        return self


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if args:
        _fail('source_only')
    return 0  # Default has no loader, target IO, collector, service or RF action.


if __name__ == '__main__':
    raise SystemExit(main())
