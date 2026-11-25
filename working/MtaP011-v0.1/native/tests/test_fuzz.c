#include "../mta_core.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>

static uint32_t random_state=0x0119955u;
static uint32_t next_random(void) {
    random_state^=random_state<<13; random_state^=random_state>>17; random_state^=random_state<<5;
    return random_state;
}
int main(void) {
    char input[MTA_LINE_MAX]; uint8_t output[MTA_P2P_MAX];
    struct mta_command command; struct mta_advertising_features features;
    for (unsigned round=0;round<100000;round++) {
        size_t length=next_random()%sizeof(input),written=0;
        for (size_t i=0;i<length;i++) input[i]=(char)next_random();
        (void)mta_parse_command(input,length,&command);
        (void)mta_base64_decode(input,length,output,sizeof(output),&written);
        (void)mta_json_envelope((const uint8_t *)input,length);
        (void)mta_ad_valid((const uint8_t *)input,length);
        (void)mta_features_decode((const uint8_t *)input,length,&features);
        mta_wipe(&command,sizeof(command));
    }
    puts("PASS deterministic malformed-input fuzz: 100000 rounds (run with ASan/UBSan on host)");
    return 0;
}
