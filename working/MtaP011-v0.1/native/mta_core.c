/* Original P011 implementation, using the documented BlueZ 5.48 wire formats.
 * No BlueZ or third-party implementation source is incorporated. */
#include "mta_core.h"
#include <string.h>
#include <ctype.h>

void mta_wipe(void *buffer, size_t size) {
    volatile unsigned char *p = buffer;
    while (size--) *p++ = 0;
}
static int base64_value(unsigned char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}
int mta_base64_decode(const char *text, size_t length, uint8_t *out,
                      size_t capacity, size_t *written) {
    size_t i, n = 0;
    if (length % 4 || length / 4 > (capacity + 2) / 3) return 0;
    for (i = 0; i < length; i += 4) {
        int a = base64_value((unsigned char)text[i]);
        int b = base64_value((unsigned char)text[i+1]);
        int c = text[i+2] == '=' ? 0 : base64_value((unsigned char)text[i+2]);
        int d = text[i+3] == '=' ? 0 : base64_value((unsigned char)text[i+3]);
        unsigned pad = (text[i+3] == '=') + (text[i+2] == '=');
        if (a < 0 || b < 0 || c < 0 || d < 0 ||
            (pad && i + 4 != length) || (text[i+2] == '=' && text[i+3] != '=') ||
            (pad == 2 && (b & 15)) || (pad == 1 && (c & 3)) ||
            n + 3 - pad > capacity) return 0;
        out[n++] = (uint8_t)((a << 2) | (b >> 4));
        if (pad < 2) out[n++] = (uint8_t)((b << 4) | (c >> 2));
        if (pad < 1) out[n++] = (uint8_t)((c << 6) | d);
    }
    *written = n;
    return 1;
}
static void skip_ws(const char **p, const char *end) {
    while (*p < end && (**p == ' ' || **p == '\t' || **p == '\r' || **p == '\n')) ++*p;
}
/* IPC fields are ASCII tokens and canonical base64. JSON escapes are refused. */
static int token_string(const char **p, const char *end, const char **start, size_t *length) {
    const char *q;
    if (*p == end || *(*p)++ != '"') return 0;
    *start = *p;
    for (q = *p; q < end && *q != '"'; q++)
        if ((unsigned char)*q < 0x20 || (unsigned char)*q > 0x7e || *q == '\\') return 0;
    if (q == end) return 0;
    *length = (size_t)(q - *start); *p = q + 1;
    return 1;
}
static int equal(const char *p, size_t n, const char *literal) {
    return strlen(literal) == n && !memcmp(p, literal, n);
}
int mta_parse_command(const char *line, size_t length, struct mta_command *out) {
    const char *p = line, *end = line + length, *key, *value;
    size_t key_len, value_len;
    unsigned seen = 0, kind = 99;
    memset(out, 0, sizeof(*out)); strcpy(out->adapter, "hci0"); out->ttl = 20;
    if (!length || length > MTA_LINE_MAX || memchr(line, 0, length)) return 0;
    skip_ws(&p, end); if (p == end || *p++ != '{') return 0;
    skip_ws(&p, end);
    while (p < end && *p != '}') {
        unsigned field;
        if (!token_string(&p, end, &key, &key_len)) return 0;
        if (equal(key,key_len,"cmd")) field = 1;
        else if (equal(key,key_len,"adapter")) field = 2;
        else if (equal(key,key_len,"status_b64")) field = 4;
        else if (equal(key,key_len,"adv_b64")) field = 8;
        else if (equal(key,key_len,"scan_b64")) field = 16;
        else if (equal(key,key_len,"ttl")) field = 32;
        else if (equal(key,key_len,"peer")) field = 64;
        else if (equal(key,key_len,"payload_b64")) field = 128;
        else return 0;
        if (seen & field) return 0;
        seen |= field; skip_ws(&p,end); if (p == end || *p++ != ':') return 0;
        skip_ws(&p,end);
        if (field == 32 || field == 64) {
            unsigned number = 0; const char *first = p;
            while (p < end && *p >= '0' && *p <= '9') {
                number = number * 10 + (unsigned)(*p++ - '0');
                if (number > (field==32 ? 600u : 65535u)) return 0;
            }
            if (p == first || (p - first > 1 && *first == '0') || number < 1) return 0;
            if (field==32) out->ttl=number; else out->peer=number;
        } else {
            if (!token_string(&p,end,&value,&value_len)) return 0;
            if (field == 1) {
                if (equal(value,value_len,"listen")) kind = MTA_LISTEN;
                else if (equal(value,value_len,"advert")) kind = MTA_ADVERT;
                else if (equal(value,value_len,"set_status")) kind = MTA_SET_STATUS;
                else if (equal(value,value_len,"stop")) kind = MTA_STOP;
                else if (equal(value,value_len,"scan")) kind = MTA_SCAN;
                else if (equal(value,value_len,"client_read")) kind = MTA_CLIENT_READ;
                else if (equal(value,value_len,"client_write")) kind = MTA_CLIENT_WRITE;
                else return 0;
            } else if (field == 2) {
                size_t i;
                if (value_len < 4 || value_len >= sizeof(out->adapter) || memcmp(value,"hci",3)) return 0;
                for (i = 3; i < value_len; i++) if (value[i] < '0' || value[i] > '9') return 0;
                memcpy(out->adapter,value,value_len); out->adapter[value_len] = 0;
            } else {
                uint8_t *bytes; size_t *n, maximum;
                if (field == 4) { bytes=out->status; n=&out->status_len; maximum=MTA_STATUS_MAX; }
                else if (field == 8) { bytes=out->adv; n=&out->adv_len; maximum=MTA_ADV_MAX; }
                else if (field == 16) { bytes=out->scan; n=&out->scan_len; maximum=MTA_ADV_MAX; }
                else { bytes=out->payload; n=&out->payload_len; maximum=MTA_P2P_MAX; }
                if (!mta_base64_decode(value,value_len,bytes,maximum,n)) return 0;
            }
        }
        skip_ws(&p,end);
        if (p < end && *p == ',') { p++; skip_ws(&p,end); if (p == end || *p == '}') return 0; }
        else break;
    }
    if (p == end || *p++ != '}') return 0;
    skip_ws(&p,end); if (p != end || kind == 99) return 0;
    out->type = (enum mta_command_type)kind;
    if (kind == MTA_LISTEN) return (seen & 4) && !(seen & (8|16|32|64|128)) && out->status_len && mta_json_envelope(out->status,out->status_len) == 1;
    if (kind == MTA_SET_STATUS) return seen == (1|4) && out->status_len && mta_json_envelope(out->status,out->status_len) == 1;
    if (kind == MTA_ADVERT) return !(seen & (4|64|128)) && (seen & (8|16)) == (8|16) && out->adv_len && out->scan_len && mta_ad_valid(out->adv,out->adv_len) && mta_ad_valid(out->scan,out->scan_len);
    if (kind == MTA_SCAN) return !(seen & (4|8|16|64|128)) && out->ttl<=60;
    if (kind == MTA_CLIENT_READ) return seen==(1|64);
    if (kind == MTA_CLIENT_WRITE) return seen==(1|64|128) && out->payload_len && mta_json_envelope(out->payload,out->payload_len)==1;
    return seen == 1;
}
int mta_ad_valid(const uint8_t *bytes, size_t length) {
    size_t p = 0;
    if (length > MTA_ADV_MAX) return 0;
    while (p < length) {
        unsigned size = bytes[p];
        if (!size || size < 1 || p + size + 1 > length) return 0;
        p += size + 1;
    }
    return 1;
}
static uint16_t le16(const uint8_t *p) { return (uint16_t)(p[0] | ((uint16_t)p[1]<<8)); }
static uint32_t le32(const uint8_t *p) { return (uint32_t)le16(p) | ((uint32_t)le16(p+2)<<16); }
static void put16(uint8_t *p, unsigned n) { p[0]=(uint8_t)n; p[1]=(uint8_t)(n>>8); }
int mta_features_decode(const uint8_t *bytes, size_t length, struct mta_advertising_features *out) {
    unsigned i, j;
    if (length < 8 || length != (size_t)8 + bytes[7] || bytes[6] > 254 || bytes[7] > bytes[6]) return 0;
    memset(out,0,sizeof(*out)); out->flags=le32(bytes); out->adv_max=bytes[4]; out->scan_max=bytes[5];
    out->max_instances=bytes[6]; out->count=bytes[7];
    for (i=0; i<out->count; i++) {
        if (!bytes[8+i] || bytes[8+i] > out->max_instances) return 0;
        for (j=0; j<i; j++) if (bytes[8+i]==bytes[8+j]) return 0;
        out->instances[i]=bytes[8+i];
    }
    return 1;
}
int mta_free_instance(const struct mta_advertising_features *features) {
    int candidate;
    for (candidate=features->max_instances; candidate>=1; candidate--) {
        unsigned i;
        for (i=0; i<features->count && features->instances[i] != candidate; i++) {}
        if (i==features->count) return candidate;
    }
    return 0;
}
size_t mta_add_advertising(uint8_t *out, size_t capacity, uint8_t instance,
                           unsigned ttl, const uint8_t *adv, size_t adv_len,
                           const uint8_t *scan, size_t scan_len) {
    size_t size=11+adv_len+scan_len;
    if (!instance || instance==255 || !ttl || ttl>600 || capacity<size || !mta_ad_valid(adv,adv_len) || !mta_ad_valid(scan,scan_len)) return 0;
    memset(out,0,11); out[0]=instance; out[1]=1; /* connectable only, exact AD bytes */
    put16(out+5,2); put16(out+7,ttl); out[9]=(uint8_t)adv_len; out[10]=(uint8_t)scan_len;
    memcpy(out+11,adv,adv_len); memcpy(out+11+adv_len,scan,scan_len); return size;
}
int mta_json_envelope(const uint8_t *bytes, size_t length) {
    size_t i=0; char stack[32]; unsigned depth=0; int quoted=0, escaped=0, ended=0;
    while (i<length && isspace(bytes[i])) i++;
    if (i==length) return 0;
    if (bytes[i]!='{') return -1;
    for (;i<length;i++) {
        unsigned char c=bytes[i];
        if (quoted) {
            if (c<0x20) return -1;
            if (escaped) escaped=0;
            else if (c=='\\') escaped=1;
            else if (c=='"') quoted=0;
        } else if (ended) { if (!isspace(c)) return -1; }
        else if (c=='"') quoted=1;
        else if (c=='{' || c=='[') { if (depth==sizeof(stack)) return -1; stack[depth++]=(char)c; }
        else if (c=='}' || c==']') {
            if (!depth || stack[depth-1]!=(c=='}' ? '{' : '[')) return -1;
            if (!--depth) ended=1;
        } else if (c<0x20 && !isspace(c)) return -1;
    }
    return ended && !quoted ? 1 : 0;
}
int mta_payload_push(struct mta_payload *buffer, size_t offset, const uint8_t *bytes, size_t length) {
    if (!offset) { mta_wipe(buffer->bytes,sizeof(buffer->bytes)); buffer->length=0; }
    if (offset!=buffer->length || !length || length>sizeof(buffer->bytes)-offset) return -1;
    memcpy(buffer->bytes+offset,bytes,length); buffer->length+=length;
    return mta_json_envelope(buffer->bytes,buffer->length);
}
