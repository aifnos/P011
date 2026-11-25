/* Independently written read-only Linux nl80211 capability probe.
 * Linux UAPI definitions come from system headers, not copied implementations.
 * This program never sends a scan, create/delete-interface, or P2P command.
 */
#define _POSIX_C_SOURCE 200809L
#include "mta_wifi_caps.h"
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <linux/nl80211.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct attr { const unsigned char *value; size_t size; unsigned int type; };
struct cursor { const unsigned char *p; size_t left; };
static size_t aligned(size_t n) { return (n + 3u) & ~(size_t)3u; }
static int next_attr(struct cursor *c, struct attr *a)
{
    uint16_t n, t;
    size_t step;
    if (!c->left) return 0;
    if (c->left < 4) return -1;
    memcpy(&n, c->p, 2); memcpy(&t, c->p + 2, 2);
    if (n < 4 || n > c->left) return -1;
    step = aligned(n);
    /* Every netlink nested attribute must include its alignment padding. */
    if (step > c->left) return -1;
    a->value = c->p + 4; a->size = n - 4;
    a->type = t & NLA_TYPE_MASK;
    c->p += step; c->left -= step;
    return 1;
}
static int u32(const struct attr *a, uint32_t *v)
{
    if (a->size != 4) return 0;
    memcpy(v, a->value, 4); return 1;
}
static int type_set(const struct attr *a, uint64_t *out)
{
    struct cursor c = {a->value, a->size}; struct attr child; int r;
    uint64_t v = 0;
    while ((r = next_attr(&c, &child)) > 0) {
        if (child.type >= 64 || child.size) return 0;
        v |= UINT64_C(1) << child.type;
    }
    if (r < 0) return 0;
    *out = v; return 1;
}
static int parse_limit(const struct attr *a, struct mta_wifi_limit *out)
{
    struct cursor c = {a->value, a->size}; struct attr ch; int r, seen = 0;
    memset(out, 0, sizeof(*out));
    while ((r = next_attr(&c, &ch)) > 0) {
        if (ch.type == NL80211_IFACE_LIMIT_MAX) {
            if ((seen & 1) || !u32(&ch, &out->max) || !out->max) return 0;
            seen |= 1;
        } else if (ch.type == NL80211_IFACE_LIMIT_TYPES) {
            if ((seen & 2) || !type_set(&ch, &out->types) || !out->types) return 0;
            seen |= 2;
        }
    }
    return r == 0 && seen == 3;
}
static int parse_combination(const struct attr *a, struct mta_wifi_combination *out)
{
    struct cursor c = {a->value, a->size}; struct attr ch; int r, seen = 0;
    uint64_t covered = 0;
    memset(out, 0, sizeof(*out));
    while ((r = next_attr(&c, &ch)) > 0) {
        if (ch.type == NL80211_IFACE_COMB_MAXNUM) {
            if ((seen & 1) || !u32(&ch, &out->max_interfaces) || !out->max_interfaces) return 0;
            seen |= 1;
        } else if (ch.type == NL80211_IFACE_COMB_NUM_CHANNELS) {
            if ((seen & 2) || !u32(&ch, &out->num_channels) || !out->num_channels) return 0;
            seen |= 2;
        } else if (ch.type == NL80211_IFACE_COMB_LIMITS) {
            struct cursor lc = {ch.value, ch.size}; struct attr l; int lr;
            if (seen & 4) return 0;
            while ((lr = next_attr(&lc, &l)) > 0) {
                struct mta_wifi_limit *lim;
                if (out->nlimits >= MTA_WIFI_MAX_LIMITS) return 0;
                lim = &out->limits[out->nlimits++];
                if (!parse_limit(&l, lim) || (covered & lim->types)) return 0;
                covered |= lim->types;
            }
            if (lr < 0 || !out->nlimits) return 0;
            seen |= 4;
        } else if (ch.type == NL80211_IFACE_COMB_STA_AP_BI_MATCH) {
            if (ch.size) return 0;
            out->beacon_interval_match = 1;
        } else if (ch.type == NL80211_IFACE_COMB_RADAR_DETECT_WIDTHS) {
            uint32_t v;
            if (!u32(&ch, &v)) return 0;
            out->radar_widths_present = 1;
        }
    }
    return r == 0 && seen == 7;
}
int mta_wifi_parse_phy(struct mta_wifi_caps *caps, const unsigned char *p, size_t n)
{
    struct cursor c = {p, n}; struct attr a; int r, have_index = 0;
    uint32_t index = 0; unsigned int i;
    struct mta_wifi_phy temp, *out = NULL;
    if (!caps || (!p && n) || n > 262144) return 0;
    memset(&temp, 0, sizeof(temp));
    while ((r = next_attr(&c, &a)) > 0) {
        if (a.type == NL80211_ATTR_WIPHY) {
            if (have_index || !u32(&a, &index)) return 0;
            have_index = 1;
        } else if (a.type == NL80211_ATTR_SUPPORTED_IFTYPES || a.type == NL80211_ATTR_SOFTWARE_IFTYPES) {
            uint64_t types;
            if (!type_set(&a, &types)) return 0;
            if (a.type == NL80211_ATTR_SUPPORTED_IFTYPES) {
                temp.types |= types; temp.types_present = 1;
            } else temp.software_types |= types;
        } else if (a.type == NL80211_ATTR_INTERFACE_COMBINATIONS) {
            struct cursor cc = {a.value, a.size}; struct attr comb; int cr;
            temp.combinations_present = 1;
            while ((cr = next_attr(&cc, &comb)) > 0) {
                if (temp.ncombinations >= MTA_WIFI_MAX_COMBINATIONS ||
                    !parse_combination(&comb, &temp.combinations[temp.ncombinations++])) return 0;
            }
            if (cr < 0) return 0;
        } else if (a.type == NL80211_ATTR_SUPPORTED_COMMANDS) {
            struct cursor cc = {a.value, a.size}; struct attr cmd; int cr;
            while ((cr = next_attr(&cc, &cmd)) > 0) {
                uint32_t id;
                if (!u32(&cmd, &id)) return 0;
                if (id == NL80211_CMD_START_P2P_DEVICE) temp.cmd_start_p2p_device = 1;
                if (id == NL80211_CMD_NEW_INTERFACE) temp.cmd_new_interface = 1;
                if (id == NL80211_CMD_START_AP) temp.cmd_start_ap = 1;
            }
            if (cr < 0) return 0;
        }
    }
    if (r < 0 || !have_index) return 0;
    for (i = 0; i < caps->nphys; ++i) if (caps->phys[i].index == index) out = &caps->phys[i];
    if (!out) {
        if (caps->nphys >= MTA_WIFI_MAX_PHYS) return 0;
        out = &caps->phys[caps->nphys++]; memset(out, 0, sizeof(*out)); out->index = index;
    }
    if (out->ncombinations + temp.ncombinations > MTA_WIFI_MAX_COMBINATIONS) return 0;
    out->types |= temp.types; out->software_types |= temp.software_types;
    out->types_present |= temp.types_present; out->combinations_present |= temp.combinations_present;
    out->cmd_start_p2p_device |= temp.cmd_start_p2p_device;
    out->cmd_new_interface |= temp.cmd_new_interface; out->cmd_start_ap |= temp.cmd_start_ap;
    memcpy(out->combinations + out->ncombinations, temp.combinations,
           temp.ncombinations * sizeof(temp.combinations[0]));
    out->ncombinations += temp.ncombinations;
    return 1;
}
int mta_wifi_combination_allows(const struct mta_wifi_combination *comb,
                              const uint32_t counts[64], uint32_t channels)
{
    uint64_t total = 0, covered = 0; unsigned int i, j;
    if (!comb || !counts || !channels || channels > comb->num_channels ||
        !comb->nlimits || comb->nlimits > MTA_WIFI_MAX_LIMITS) return 0;
    for (i = 0; i < 64; ++i) total += counts[i];
    if (!total || total > comb->max_interfaces) return 0;
    for (i = 0; i < comb->nlimits; ++i) {
        uint64_t used = 0;
        if (covered & comb->limits[i].types) return 0;
        covered |= comb->limits[i].types;
        for (j = 0; j < 64; ++j) if (comb->limits[i].types & (UINT64_C(1) << j)) used += counts[j];
        if (used > comb->limits[i].max) return 0;
    }
    for (i = 0; i < 64; ++i) if (counts[i] && !(covered & (UINT64_C(1) << i))) return 0;
    return 1;
}

#ifndef MTA_WIFI_CAPS_NO_MAIN
#include <poll.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
static int64_t now_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts)) return -1;
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}
static int send_request(int fd, uint16_t family, uint8_t cmd, uint16_t flags,
                        uint32_t sequence, const unsigned char *attrs, size_t n)
{
    unsigned char packet[256]; struct nlmsghdr nh; struct genlmsghdr gh;
    struct sockaddr_nl dest;
    if (n > sizeof(packet) - sizeof(nh) - sizeof(gh)) return 0;
    memset(&nh, 0, sizeof(nh)); memset(&gh, 0, sizeof(gh)); memset(&dest, 0, sizeof(dest));
    nh.nlmsg_len = (uint32_t)(sizeof(nh) + sizeof(gh) + n);
    nh.nlmsg_type = family; nh.nlmsg_flags = NLM_F_REQUEST | flags; nh.nlmsg_seq = sequence;
    gh.cmd = cmd; gh.version = 1; dest.nl_family = AF_NETLINK;
    memcpy(packet, &nh, sizeof(nh)); memcpy(packet + sizeof(nh), &gh, sizeof(gh));
    if (n) memcpy(packet + sizeof(nh) + sizeof(gh), attrs, n);
    return sendto(fd, packet, nh.nlmsg_len, 0, (struct sockaddr *)&dest, sizeof(dest)) == (ssize_t)nh.nlmsg_len;
}
static int receive_reply(int fd, uint32_t sequence, int family_query,
                         uint16_t *family, struct mta_wifi_caps *caps, int *err)
{
    unsigned char buffer[262144]; int64_t deadline = now_ms() + 5000;
    unsigned int rounds = 0, bytes = 0;
    for (;;) {
        struct pollfd pollfd = {fd, POLLIN, 0}; struct sockaddr_nl sender;
        struct iovec io = {buffer, sizeof(buffer)}; struct msghdr msg;
        int64_t remain = deadline - now_ms(); ssize_t got; size_t at = 0;
        if (remain <= 0 || ++rounds > 256) { *err = ETIMEDOUT; return 0; }
        if (poll(&pollfd, 1, (int)remain) < 0) { if (errno == EINTR) continue; *err = errno; return 0; }
        if (!(pollfd.revents & POLLIN)) { *err = ETIMEDOUT; return 0; }
        memset(&sender, 0, sizeof(sender)); memset(&msg, 0, sizeof(msg));
        msg.msg_name = &sender; msg.msg_namelen = sizeof(sender); msg.msg_iov = &io; msg.msg_iovlen = 1;
        got = recvmsg(fd, &msg, MSG_DONTWAIT);
        if (got < 0) { if (errno == EINTR || errno == EAGAIN) continue; *err = errno; return 0; }
        if ((msg.msg_flags & MSG_TRUNC) || sender.nl_pid || got == 0) { *err = EPROTO; return 0; }
        bytes += (unsigned int)got;
        if (bytes > 1048576) { *err = EOVERFLOW; return 0; }
        while (at < (size_t)got) {
            struct nlmsghdr nh; size_t bodylen, step; const unsigned char *body;
            if ((size_t)got - at < sizeof(nh)) { *err = EPROTO; return 0; }
            memcpy(&nh, buffer + at, sizeof(nh)); step = aligned(nh.nlmsg_len);
            if (nh.nlmsg_len < sizeof(nh) || step > (size_t)got - at || nh.nlmsg_seq != sequence) { *err = EPROTO; return 0; }
            if (nh.nlmsg_flags & NLM_F_DUMP_INTR) { *err = EINTR; return 0; }
            body = buffer + at + sizeof(nh); bodylen = nh.nlmsg_len - sizeof(nh);
            if (nh.nlmsg_type == NLMSG_ERROR) {
                int e;
                if (bodylen < sizeof(e)) { *err = EPROTO; return 0; }
                memcpy(&e, body, sizeof(e));
                if (e) { *err = -e; return 0; }
            } else if (nh.nlmsg_type == NLMSG_DONE) {
                int e = 0;
                if (bodylen >= sizeof(e)) memcpy(&e, body, sizeof(e));
                if (e) { *err = e < 0 ? -e : e; return 0; }
                return caps->nphys > 0;
            } else if (nh.nlmsg_type == (family_query ? GENL_ID_CTRL : *family)) {
                struct genlmsghdr gh;
                if (bodylen < sizeof(gh)) { *err = EPROTO; return 0; }
                memcpy(&gh, body, sizeof(gh)); body += sizeof(gh); bodylen -= sizeof(gh);
                if (family_query) {
                    struct cursor c = {body, bodylen}; struct attr a; int r;
                    while ((r = next_attr(&c, &a)) > 0) if (a.type == CTRL_ATTR_FAMILY_ID) {
                        if (a.size != 2) { *err = EPROTO; return 0; }
                        memcpy(family, a.value, 2);
                    }
                    if (r < 0 || !*family) { *err = EPROTO; return 0; }
                    return 1;
                }
                if (gh.cmd != NL80211_CMD_NEW_WIPHY || !mta_wifi_parse_phy(caps, body, bodylen)) { *err = EPROTO; return 0; }
            }
            at += step;
        }
    }
}
static const char *type_name(unsigned int type)
{
    switch (type) {
    case NL80211_IFTYPE_STATION: return "station";
    case NL80211_IFTYPE_AP: return "ap";
    case NL80211_IFTYPE_P2P_CLIENT: return "p2p_client";
    case NL80211_IFTYPE_P2P_GO: return "p2p_go";
    case NL80211_IFTYPE_P2P_DEVICE: return "p2p_device";
    case NL80211_IFTYPE_ADHOC: return "adhoc";
    case NL80211_IFTYPE_MONITOR: return "monitor";
    case NL80211_IFTYPE_AP_VLAN: return "ap_vlan";
    case NL80211_IFTYPE_MESH_POINT: return "mesh";
    default: return NULL;
    }
}
static void print_types(uint64_t types)
{
    unsigned int i; int comma = 0;
    putchar('[');
    for (i = 0; i < 64; ++i) if (types & (UINT64_C(1) << i)) {
        const char *name = type_name(i);
        if (comma++) putchar(',');
        if (name) printf("\"%s\"", name); else printf("\"iftype_%u\"", i);
    }
    putchar(']');
}
static void print_caps(const struct mta_wifi_caps *caps)
{
    unsigned int i, j, k;
    printf("{\"event\":\"wifi_caps\",\"read_only\":true,\"phys\":[");
    for (i = 0; i < caps->nphys; ++i) {
        const struct mta_wifi_phy *p = &caps->phys[i];
        if (i) putchar(',');
        printf("{\"index\":%u,\"iftypes_present\":%s,\"iftypes\":", p->index, p->types_present ? "true" : "false");
        print_types(p->types); printf(",\"software_iftypes\":"); print_types(p->software_types);
        printf(",\"commands\":{\"new_interface\":%s,\"start_ap\":%s,\"start_p2p_device\":%s},\"combinations_present\":%s,\"combinations\":[",
               p->cmd_new_interface ? "true" : "false", p->cmd_start_ap ? "true" : "false", p->cmd_start_p2p_device ? "true" : "false", p->combinations_present ? "true" : "false");
        for (j = 0; j < p->ncombinations; ++j) {
            const struct mta_wifi_combination *c = &p->combinations[j]; uint32_t counts[64] = {0};
            int sta_go, sta_ap;
            counts[NL80211_IFTYPE_STATION] = 1; counts[NL80211_IFTYPE_P2P_GO] = 1;
            sta_go = mta_wifi_combination_allows(c, counts, 1);
            counts[NL80211_IFTYPE_P2P_GO] = 0; counts[NL80211_IFTYPE_AP] = 1;
            sta_ap = mta_wifi_combination_allows(c, counts, 1);
            if (j) putchar(',');
            printf("{\"max_interfaces\":%u,\"num_channels\":%u,\"station_plus_go_same_channel\":%s,\"station_plus_ap_same_channel\":%s,\"beacon_interval_match\":%s,\"radar_restriction_present\":%s,\"limits\":[",
                   c->max_interfaces, c->num_channels, sta_go ? "true" : "false", sta_ap ? "true" : "false", c->beacon_interval_match ? "true" : "false", c->radar_widths_present ? "true" : "false");
            for (k = 0; k < c->nlimits; ++k) {
                if (k) putchar(',');
                printf("{\"max\":%u,\"types\":", c->limits[k].max); print_types(c->limits[k].types); putchar('}');
            }
            printf("]}");
        }
        printf("]}");
    }
    printf("]}\n");
}
int main(int argc, char **argv)
{
    int fd, err = 0; uint16_t family = 0; unsigned char attrs[16] = {0};
    struct sockaddr_nl local; struct mta_wifi_caps caps; uint16_t len = 12, type = CTRL_ATTR_FAMILY_NAME;
    if (argc == 2 && !strcmp(argv[1], "--ids")) {
        printf("{\"get_wiphy\":%d,\"new_wiphy\":%d,\"wiphy\":%d,\"supported_iftypes\":%d,\"software_iftypes\":%d,\"interface_combinations\":%d,\"supported_commands\":%d,\"comb_limits\":%d,\"comb_maxnum\":%d,\"comb_channels\":%d,\"limit_max\":%d,\"limit_types\":%d,\"start_p2p_device\":%d,\"new_interface\":%d,\"start_ap\":%d,\"get_interface\":%d,\"delete_interface\":%d,\"ifindex\":%d,\"ifname\":%d,\"iftype\":%d,\"wdev\":%d,\"frequency\":%d}\n",
               NL80211_CMD_GET_WIPHY, NL80211_CMD_NEW_WIPHY, NL80211_ATTR_WIPHY, NL80211_ATTR_SUPPORTED_IFTYPES,
               NL80211_ATTR_SOFTWARE_IFTYPES, NL80211_ATTR_INTERFACE_COMBINATIONS, NL80211_ATTR_SUPPORTED_COMMANDS,
               NL80211_IFACE_COMB_LIMITS, NL80211_IFACE_COMB_MAXNUM, NL80211_IFACE_COMB_NUM_CHANNELS,
               NL80211_IFACE_LIMIT_MAX, NL80211_IFACE_LIMIT_TYPES, NL80211_CMD_START_P2P_DEVICE,
               NL80211_CMD_NEW_INTERFACE, NL80211_CMD_START_AP, NL80211_CMD_GET_INTERFACE,
               NL80211_CMD_DEL_INTERFACE, NL80211_ATTR_IFINDEX, NL80211_ATTR_IFNAME,
               NL80211_ATTR_IFTYPE, NL80211_ATTR_WDEV, NL80211_ATTR_WIPHY_FREQ);
        return 0;
    }
    if (argc != 2 || strcmp(argv[1], "--capabilities")) {
        fprintf(stderr, "Usage: mta-wifi-caps --capabilities | --ids\n"); return 2;
    }
    memset(&caps, 0, sizeof(caps)); memset(&local, 0, sizeof(local)); local.nl_family = AF_NETLINK;
    fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC);
    if (fd < 0) err = errno;
    else if (bind(fd, (struct sockaddr *)&local, sizeof(local))) err = errno;
    if (!err) {
        memcpy(attrs, &len, 2); memcpy(attrs + 2, &type, 2); memcpy(attrs + 4, "nl80211", 8);
        if (!send_request(fd, GENL_ID_CTRL, CTRL_CMD_GETFAMILY, 0, 1, attrs, len)) err = errno ? errno : EIO;
        else if (!receive_reply(fd, 1, 1, &family, &caps, &err) && !err) err = EPROTO;
    }
    if (!err) {
        if (!send_request(fd, family, NL80211_CMD_GET_WIPHY, NLM_F_DUMP, 2, NULL, 0)) err = errno ? errno : EIO;
        else if (!receive_reply(fd, 2, 0, &family, &caps, &err) && !err) err = ENODATA;
    }
    if (fd >= 0) close(fd);
    if (err) { printf("{\"event\":\"wifi_caps_error\",\"read_only\":true,\"errno\":%d}\n", err); return 1; }
    print_caps(&caps); return 0;
}
#endif
