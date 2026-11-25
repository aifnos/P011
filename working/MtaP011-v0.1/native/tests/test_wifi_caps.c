#include "../mta_wifi_caps.h"
#include <linux/nl80211.h>
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct builder { unsigned char data[8192]; size_t n; };
static void add(struct builder *b, unsigned int type, const void *p, size_t n)
{
    uint16_t len = (uint16_t)(n + 4), t = (uint16_t)type; size_t step = (len + 3u) & ~(size_t)3u;
    assert(b->n + step <= sizeof(b->data));
    memset(b->data + b->n, 0, step); memcpy(b->data + b->n, &len, 2); memcpy(b->data + b->n + 2, &t, 2);
    if (n) memcpy(b->data + b->n + 4, p, n);
    b->n += step;
}
static void number(struct builder *b, unsigned int t, uint32_t v) { add(b, t, &v, 4); }
static void limit(struct builder *b, uint32_t index, unsigned int first, unsigned int second)
{
    struct builder types = {{0},0}, l = {{0},0};
    add(&types, first, NULL, 0); if (second) add(&types, second, NULL, 0);
    number(&l, NL80211_IFACE_LIMIT_MAX, 1); add(&l, NL80211_IFACE_LIMIT_TYPES, types.data, types.n);
    add(b, index, l.data, l.n);
}
static void valid_phy(struct builder *p)
{
    struct builder types = {{0},0}, limits = {{0},0}, comb = {{0},0}, combs = {{0},0}, commands = {{0},0};
    number(p, NL80211_ATTR_WIPHY, 0);
    add(&types, NL80211_IFTYPE_STATION, NULL, 0); add(&types, NL80211_IFTYPE_AP, NULL, 0);
    add(&types, NL80211_IFTYPE_P2P_GO, NULL, 0); add(&types, NL80211_IFTYPE_P2P_CLIENT, NULL, 0);
    add(&types, NL80211_IFTYPE_P2P_DEVICE, NULL, 0);
    add(p, NL80211_ATTR_SUPPORTED_IFTYPES, types.data, types.n);
    limit(&limits, 1, NL80211_IFTYPE_STATION, NL80211_IFTYPE_AP);
    limit(&limits, 2, NL80211_IFTYPE_P2P_GO, NL80211_IFTYPE_P2P_CLIENT);
    limit(&limits, 3, NL80211_IFTYPE_P2P_DEVICE, 0);
    add(&comb, NL80211_IFACE_COMB_LIMITS, limits.data, limits.n);
    number(&comb, NL80211_IFACE_COMB_MAXNUM, 3); number(&comb, NL80211_IFACE_COMB_NUM_CHANNELS, 2);
    add(&combs, 1, comb.data, comb.n); add(p, NL80211_ATTR_INTERFACE_COMBINATIONS, combs.data, combs.n);
    number(&commands, 1, NL80211_CMD_START_P2P_DEVICE); number(&commands, 2, NL80211_CMD_START_AP);
    number(&commands, 3, NL80211_CMD_NEW_INTERFACE); add(p, NL80211_ATTR_SUPPORTED_COMMANDS, commands.data, commands.n);
}
int main(void)
{
    struct builder p = {{0},0}; struct mta_wifi_caps caps; uint32_t counts[64] = {0};
    uint32_t seed = 0x20301414; unsigned int i, j;
    valid_phy(&p); memset(&caps, 0, sizeof(caps));
    assert(mta_wifi_parse_phy(&caps, p.data, p.n)); assert(caps.nphys == 1);
    assert(caps.phys[0].ncombinations == 1 && caps.phys[0].types_present);
    assert(caps.phys[0].cmd_start_p2p_device && caps.phys[0].cmd_new_interface && caps.phys[0].cmd_start_ap);
    counts[NL80211_IFTYPE_STATION] = 1; counts[NL80211_IFTYPE_P2P_GO] = 1;
    assert(mta_wifi_combination_allows(&caps.phys[0].combinations[0], counts, 1));
    assert(mta_wifi_combination_allows(&caps.phys[0].combinations[0], counts, 2));
    assert(!mta_wifi_combination_allows(&caps.phys[0].combinations[0], counts, 3));
    counts[NL80211_IFTYPE_P2P_DEVICE] = 1;
    assert(mta_wifi_combination_allows(&caps.phys[0].combinations[0], counts, 1));
    counts[NL80211_IFTYPE_P2P_CLIENT] = 1;
    assert(!mta_wifi_combination_allows(&caps.phys[0].combinations[0], counts, 1));
    counts[NL80211_IFTYPE_P2P_CLIENT] = 0; counts[NL80211_IFTYPE_P2P_DEVICE] = 0;
    counts[NL80211_IFTYPE_P2P_GO] = 0; counts[NL80211_IFTYPE_AP] = 1;
    assert(!mta_wifi_combination_allows(&caps.phys[0].combinations[0], counts, 1));
    memset(counts, 0, sizeof(counts)); counts[NL80211_IFTYPE_STATION] = UINT32_MAX;
    assert(!mta_wifi_combination_allows(&caps.phys[0].combinations[0], counts, 1));
    memset(&caps, 0, sizeof(caps));
    assert(!mta_wifi_parse_phy(&caps, p.data, p.n - 1));
    assert(!mta_wifi_parse_phy(&caps, NULL, 1));
    { struct builder duplicate = p; number(&duplicate, NL80211_ATTR_WIPHY, 1);
      assert(!mta_wifi_parse_phy(&caps, duplicate.data, duplicate.n)); }
    { struct builder missing = {{0},0}; unsigned char bytes[5] = {0};
      add(&missing, NL80211_ATTR_SUPPORTED_IFTYPES, bytes, sizeof(bytes));
      assert(!mta_wifi_parse_phy(&caps, missing.data, missing.n)); }
    /* Fixed-seed, bounded malformed attribute streams exercise sanitizer edges. */
    for (i = 0; i < 100000; ++i) {
        unsigned char fuzz[512]; size_t n;
        seed = seed * 1664525u + 1013904223u; n = seed % sizeof(fuzz);
        for (j = 0; j < n; ++j) { seed = seed * 1664525u + 1013904223u; fuzz[j] = (unsigned char)(seed >> 24); }
        memset(&caps, 0, sizeof(caps)); (void)mta_wifi_parse_phy(&caps, fuzz, n);
    }
    puts("wifi capability parser/combination/fuzz PASS (host only)"); return 0;
}
