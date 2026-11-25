#ifndef MTA_WIFI_CAPS_H
#define MTA_WIFI_CAPS_H
#include <stddef.h>
#include <stdint.h>

#define MTA_WIFI_MAX_PHYS 8
#define MTA_WIFI_MAX_COMBINATIONS 16
#define MTA_WIFI_MAX_LIMITS 16

struct mta_wifi_limit { uint32_t max; uint64_t types; };
struct mta_wifi_combination {
    uint32_t max_interfaces, num_channels;
    unsigned int nlimits;
    struct mta_wifi_limit limits[MTA_WIFI_MAX_LIMITS];
    int radar_widths_present, beacon_interval_match;
};
struct mta_wifi_phy {
    uint32_t index;
    uint64_t types, software_types;
    int types_present, combinations_present;
    int cmd_start_p2p_device, cmd_new_interface, cmd_start_ap;
    unsigned int ncombinations;
    struct mta_wifi_combination combinations[MTA_WIFI_MAX_COMBINATIONS];
};
struct mta_wifi_caps {
    unsigned int nphys;
    struct mta_wifi_phy phys[MTA_WIFI_MAX_PHYS];
};

/* Parse one GET_WIPHY generic-netlink attribute stream; fail closed on limits. */
int mta_wifi_parse_phy(struct mta_wifi_caps *, const unsigned char *, size_t);
/* Counts are requirements, not a claim that firmware can actually create them. */
int mta_wifi_combination_allows(const struct mta_wifi_combination *,
                              const uint32_t counts[64], uint32_t channels);
#endif
