#ifndef P011_MTA_CORE_H
#define P011_MTA_CORE_H

#include <stddef.h>
#include <stdint.h>

#define MTA_STATUS_MAX 512u
#define MTA_P2P_MAX 2048u
#define MTA_LINE_MAX 8192u
#define MTA_ADV_MAX 31u

enum mta_command_type { MTA_LISTEN, MTA_ADVERT, MTA_SET_STATUS, MTA_STOP,
                        MTA_SCAN, MTA_CLIENT_READ, MTA_CLIENT_WRITE };
struct mta_command {
    enum mta_command_type type;
    char adapter[16];
    uint8_t status[MTA_STATUS_MAX], adv[MTA_ADV_MAX], scan[MTA_ADV_MAX], payload[MTA_P2P_MAX];
    size_t status_len, adv_len, scan_len, payload_len;
    unsigned ttl, peer;
};
struct mta_advertising_features {
    uint32_t flags;
    uint8_t adv_max, scan_max, max_instances, count, instances[254];
};
struct mta_payload { uint8_t bytes[MTA_P2P_MAX]; size_t length; };

void mta_wipe(void *buffer, size_t size);
int mta_parse_command(const char *line, size_t length, struct mta_command *out);
int mta_base64_decode(const char *text, size_t length, uint8_t *out,
                      size_t capacity, size_t *written);
int mta_ad_valid(const uint8_t *bytes, size_t length);
int mta_features_decode(const uint8_t *bytes, size_t length,
                        struct mta_advertising_features *out);
int mta_free_instance(const struct mta_advertising_features *features);
size_t mta_add_advertising(uint8_t *out, size_t capacity, uint8_t instance,
                           unsigned ttl, const uint8_t *adv, size_t adv_len,
                           const uint8_t *scan, size_t scan_len);
/* 1: complete JSON object envelope; 0: incomplete; -1: malformed envelope.
 * This is NOT a JSON semantic validator. The protocol process must validate it. */
int mta_json_envelope(const uint8_t *bytes, size_t length);
/* Strict sequential offsets. offset=0 starts a NEW ATT value. */
int mta_payload_push(struct mta_payload *buffer, size_t offset,
                      const uint8_t *bytes, size_t length);

#endif
