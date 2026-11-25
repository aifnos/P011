"""Deterministic project source transform for the private WPA V2 build only.

Input must already contain the archived V1 patch; each anchor is exact/unique.
The generated patch is packaged with corresponding source/relink objects.
This script does not contact a device or execute the resulting WPA binary.
"""
import difflib
from pathlib import Path
import sys


def replace_once(text, before, after):
    if text.count(before) != 1:
        raise ValueError('Private V2 source anchor changed')
    return text.replace(before, after)


def main():
    root = Path(sys.argv[1]).resolve()
    if not str(root).startswith('/work/mta-p2p-build-'):
        raise ValueError('Private V2 build path refused')
    changes = {}
    source = root / 'wpa_supplicant-2.12/src/drivers/driver_nl80211.c'
    old = source.read_text(); text = old
    text = replace_once(text, '\n\n#ifndef NETLINK_CAP_ACK\n', '''

/* Project diagnostics: fixed numeric stages, no format/string/key inputs.
 * FD 3 is a private inherited pipe, never a log or public control socket. */
void mta_p2p_diag(unsigned int stage, int code)
{
\tconst char *enabled = getenv("MTA_PRIVATE_P2P");
\tchar line[64];
\tint length;

\tif (!enabled || strcmp(enabled, "1") != 0 || stage > 32)
\t\treturn;
\tif (code < -4095 || code > 4095)
\t\tcode = -4095;
\tlength = snprintf(line, sizeof(line),
\t\t\t  "MTA_P2P_DIAG stage=%u code=%d\\n", stage, code);
\tif (length > 0 && (size_t) length < sizeof(line)) {
\t\tssize_t result = write(3, line, length);
\t\tif (result < 0)
\t\t\treturn;
\t}
}


#ifndef NETLINK_CAP_ACK
''')
    text = replace_once(text, '''\treturn wpa_driver_nl80211_drv_init(ctx, ifname, global_priv, 0, NULL,
\t\t\t\t\t   NULL, p2p_mode);
''', '''\tconst char *enabled = getenv("MTA_PRIVATE_P2P");
\tconst char *initial_params = NULL;

\t/* Explicit project opt-in is applied BEFORE finish_drv_init. The normal
\t * init2 ABI supplies NULL; a late conf driver_param cannot preserve mode. */
\tif (enabled && strcmp(enabled, "1") == 0) {
\t\tif (!ifname || strlen(ifname) != 11 ||
\t\t    strncmp(ifname, "mta", 3) != 0 ||
\t\t    strspn(ifname + 3, "0123456789abcdef") != 8) {
\t\t\tmta_p2p_diag(1, -EINVAL);
\t\t\treturn NULL;
\t\t}
\t\tinitial_params = "mta_p2p_initial=1 control_port=0";
\t\tmta_p2p_diag(1, 0);
\t}
\treturn wpa_driver_nl80211_drv_init(ctx, ifname, global_priv, 0, NULL,
\t\t\t\t\t   initial_params, p2p_mode);
''')
    text = replace_once(text, '''\tif (first && wpa_driver_nl80211_capa(drv))
\t\treturn -1;

\tif (driver_params && nl80211_set_param(bss, driver_params) < 0)
\t\treturn -1;
''', '''\tif (first) {
\t\tint result = wpa_driver_nl80211_capa(drv);
\t\tmta_p2p_diag(2, result);
\t\tif (result)
\t\t\treturn -1;
\t}

\tif (driver_params) {
\t\tint result = nl80211_set_param(bss, driver_params);
\t\tmta_p2p_diag(3, result);
\t\tif (result < 0)
\t\t\treturn -1;
\t}
''')
    text = replace_once(text, '''\t\t    !is_p2p_net_interface(nl80211_get_ifmode(bss)))
\t\t\treturn -1;
\t\tmta_private_initial = true;
''', '''\t\t    !is_p2p_net_interface(nl80211_get_ifmode(bss))) {
\t\t\tmta_p2p_diag(4, -EINVAL);
\t\t\treturn -1;
\t\t}
\t\tmta_private_initial = true;
\t\tbss->mta_private_lease = 1;
\t\tmta_p2p_diag(4, 0);
''')
    text = replace_once(text, '''\tif (first && wpa_driver_nl80211_set_mode(bss, nlmode) < 0) {
\t\twpa_printf(MSG_ERROR, "nl80211: Could not configure driver mode");
\t\treturn -1;
\t}
''', '''\tif (first) {
\t\tint result = wpa_driver_nl80211_set_mode(bss, nlmode);
\t\tmta_p2p_diag(5, result);
\t\tif (result < 0)
\t\t\treturn -1;
\t}
''')
    text = replace_once(text, '''\t\tint ret = i802_set_iface_flags(bss, 1);
\t\tif (ret) {
''', '''\t\tint ret = i802_set_iface_flags(bss, 1);
\t\tmta_p2p_diag(6, ret);
\t\tif (ret) {
''')
    text = replace_once(text, '''\tif (send_rfkill_event)
\t\teloop_register_timeout(0, 0, wpa_driver_nl80211_send_rfkill,
''', '''\tmta_p2p_diag(7, 0);
\tif (send_rfkill_event)
\t\teloop_register_timeout(0, 0, wpa_driver_nl80211_send_rfkill,
''')
    text = replace_once(text, '''failed:
\twpa_driver_nl80211_deinit(bss);
\treturn NULL;
}


/**
 * wpa_driver_nl80211_init''', '''failed:
\tmta_p2p_diag(8, -1);
\twpa_driver_nl80211_deinit(bss);
\treturn NULL;
}


/**
 * wpa_driver_nl80211_init''')
    text = replace_once(text, '''\tbss->in_deinit = 1;
\tif (drv->data_tx_status)
''', '''\tbss->in_deinit = 1;
\tmta_p2p_diag(9, 0);
\tif (drv->data_tx_status)
''')
    text = replace_once(text, '''\tif (drv->nlmode == NL80211_IFTYPE_P2P_GO && bss->if_dynamic)
\t\treturn 0;
''', '''\tif (drv->nlmode == NL80211_IFTYPE_P2P_GO &&
\t    (bss->if_dynamic || bss->mta_private_lease)) {
\t\tmta_p2p_diag(10, 0);
\t\treturn 0;
\t}
''')
    text = replace_once(text, '''\tif (bss->if_dynamic)
\t\treturn 0;

\treturn wpa_driver_nl80211_set_mode(priv, NL80211_IFTYPE_STATION);
''', '''\tif (bss->if_dynamic || bss->mta_private_lease) {
\t\tmta_p2p_diag(11, 0);
\t\treturn 0;
\t}

\treturn wpa_driver_nl80211_set_mode(priv, NL80211_IFTYPE_STATION);
''')
    changes[source] = (old, text)
    header = root / 'wpa_supplicant-2.12/src/drivers/driver_nl80211.h'
    old = header.read_text()
    text = replace_once(old, '\tunsigned int static_ap:1;\n',
                        '\tunsigned int static_ap:1;\n\tunsigned int mta_private_lease:1;\n')
    changes[header] = (old, text)
    supplicant = root / 'wpa_supplicant-2.12/wpa_supplicant/wpa_supplicant.c'
    old = supplicant.read_text(); text = old
    text = replace_once(text, '''static int wpas_init_driver(struct wpa_supplicant *wpa_s,
''', '''/* Project-only fixed numeric diagnostic function in private nl80211. */
extern void mta_p2p_diag(unsigned int stage, int code);

static int wpas_init_driver(struct wpa_supplicant *wpa_s,
''')
    text = replace_once(text, '''\twpa_s->drv_priv = wpa_drv_init(wpa_s, wpa_s->ifname);
\tif (wpa_s->drv_priv == NULL) {
''', '''\twpa_s->drv_priv = wpa_drv_init(wpa_s, wpa_s->ifname);
\tmta_p2p_diag(12, wpa_s->drv_priv ? 0 : -1);
\tif (wpa_s->drv_priv == NULL) {
''')
    text = replace_once(text, '''\tif (wpas_wps_init(wpa_s))
\t\treturn -1;
''', '''\t{
\t\tint result = wpas_wps_init(wpa_s);
\t\tmta_p2p_diag(13, result);
\t\tif (result)
\t\t\treturn -1;
\t}
''')
    text = replace_once(text, '''\tif (wpa_supplicant_init_eapol(wpa_s) < 0)
\t\treturn -1;
''', '''\t{
\t\tint result = wpa_supplicant_init_eapol(wpa_s);
\t\tmta_p2p_diag(14, result);
\t\tif (result < 0)
\t\t\treturn -1;
\t}
''')
    text = replace_once(text, '''\twpa_s->ctrl_iface = wpa_supplicant_ctrl_iface_init(wpa_s);
\tif (wpa_s->ctrl_iface == NULL) {
''', '''\twpa_s->ctrl_iface = wpa_supplicant_ctrl_iface_init(wpa_s);
\tmta_p2p_diag(15, wpa_s->ctrl_iface ? 0 : -1);
\tif (wpa_s->ctrl_iface == NULL) {
''')
    text = replace_once(text, '''\tif ((!(wpa_s->drv_flags & WPA_DRIVER_FLAGS_DEDICATED_P2P_DEVICE) ||
\t     wpa_s->p2p_mgmt) &&
\t    wpas_p2p_init(wpa_s->global, wpa_s) < 0) {
\t\twpa_msg(wpa_s, MSG_ERROR, "Failed to init P2P");
\t\treturn -1;
\t}
''', '''\tif (!(wpa_s->drv_flags & WPA_DRIVER_FLAGS_DEDICATED_P2P_DEVICE) ||
\t    wpa_s->p2p_mgmt) {
\t\tint result = wpas_p2p_init(wpa_s->global, wpa_s);
\t\tmta_p2p_diag(16, result);
\t\tif (result < 0)
\t\t\treturn -1;
\t}
''')
    changes[supplicant] = (old, text)
    patch = []
    for path, (before, after) in changes.items():
        relative = path.relative_to(root / 'wpa_supplicant-2.12').as_posix()
        patch.extend(difflib.unified_diff(before.splitlines(True), after.splitlines(True),
                                         fromfile='a/' + relative, tofile='b/' + relative))
        path.write_text(after)
    (root / 'project-v2-supplicant.patch').write_text(''.join(patch))
    print('Private WPA V2 source transform PASS; no device/RF')


if __name__ == '__main__':
    main()
