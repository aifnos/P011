#include "../mta_core.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void command_tests(void) {
    struct mta_command c;
    const char *good="{\"cmd\":\"listen\",\"adapter\":\"hci0\",\"status_b64\":\"e30=\"}";
    const char *bad[]={"{\"cmd\":\"shell\"}","{\"cmd\":\"stop\",\"cmd\":\"stop\"}","{\"cmd\":\"stop\",}","{\"cmd\":\"stop\",\"x\":1}","{\"cmd\":\"stop\"}x","{\"cmd\":\"stop\",\"adapter\":\"hci0\"}","{\"cmd\":\"advert\",\"adv_b64\":\"AgEG\",\"scan_b64\":\"AgEG\",\"ttl\":0}","{\"cmd\":\"listen\",\"status_b64\":\"e31=\"}","{\"cmd\":\"listen\",\"adapter\":\"../../x\",\"status_b64\":\"e30=\"}"};
    size_t i;
    assert(mta_parse_command(good,strlen(good),&c)); assert(c.type==MTA_LISTEN && c.status_len==2);
    good="{\"cmd\":\"advert\",\"adv_b64\":\"AgEG\",\"scan_b64\":\"AgEG\",\"ttl\":600}";
    assert(mta_parse_command(good,strlen(good),&c)); assert(c.ttl==600);
    good="{\"cmd\":\"scan\",\"ttl\":30}"; assert(mta_parse_command(good,strlen(good),&c) && c.type==MTA_SCAN);
    good="{\"cmd\":\"scan\",\"ttl\":61}"; assert(!mta_parse_command(good,strlen(good),&c));
    good="{\"cmd\":\"client_read\",\"peer\":1}"; assert(mta_parse_command(good,strlen(good),&c) && c.peer==1);
    good="{\"cmd\":\"client_write\",\"peer\":1,\"payload_b64\":\"e30=\"}"; assert(mta_parse_command(good,strlen(good),&c) && c.payload_len==2);
    for(i=0;i<sizeof(bad)/sizeof(bad[0]);i++) assert(!mta_parse_command(bad[i],strlen(bad[i]),&c));
}
static void base64_tests(void) {
    uint8_t b[4]; size_t n;
    assert(mta_base64_decode("YWJj",4,b,3,&n) && n==3 && !memcmp(b,"abc",3));
    assert(mta_base64_decode("YQ==",4,b,1,&n) && n==1 && b[0]=='a');
    assert(!mta_base64_decode("YR==",4,b,1,&n));
    assert(!mta_base64_decode("YQ=A",4,b,4,&n));
    assert(!mta_base64_decode("YQ==YQ==",8,b,4,&n));
    assert(!mta_base64_decode("YWJj",4,b,2,&n));
}
static void mgmt_tests(void) {
    struct mta_advertising_features f;
    uint8_t features[]={1,0,0,0,31,31,5,2,1,5};
    uint8_t packet[73],ad[]={2,1,6},scan[]={3,0x16,0xff,0xff};
    assert(mta_features_decode(features,sizeof(features),&f)); assert(mta_free_instance(&f)==4);
    features[9]=1; assert(!mta_features_decode(features,sizeof(features),&f));
    assert(!mta_features_decode(features,7,&f));
    assert(mta_add_advertising(packet,sizeof(packet),4,20,ad,sizeof(ad),scan,sizeof(scan))==18);
    assert(packet[0]==4 && packet[1]==1 && packet[5]==2 && packet[7]==20 && packet[9]==3 && packet[10]==4);
    assert(!memcmp(packet+11,ad,sizeof(ad))); assert(!memcmp(packet+14,scan,sizeof(scan)));
    assert(!mta_add_advertising(packet,sizeof(packet),0,20,ad,sizeof(ad),scan,sizeof(scan)));
    assert(!mta_ad_valid((const uint8_t *)"\x04\x16\xff",3));
}
static void payload_tests(void) {
    struct mta_payload p={{0},0};
    assert(mta_payload_push(&p,0,(const uint8_t *)"{\"x\":",5)==0);
    assert(mta_payload_push(&p,5,(const uint8_t *)"1}",2)==1);
    assert(mta_payload_push(&p,9,(const uint8_t *)"x",1)==-1);
    assert(mta_payload_push(&p,0,(const uint8_t *)"{}x",3)==-1);
    assert(mta_json_envelope((const uint8_t *)"{\"x\":\"}\\\"{\"}",12)==1);
    assert(mta_json_envelope((const uint8_t *)"{]",2)==-1);
    assert(mta_payload_push(&p,0,(const uint8_t *)"{}",2)==1);
    mta_wipe(&p,sizeof(p)); assert(p.length==0 && p.bytes[0]==0);
}
int main(void) {
    command_tests(); base64_tests(); mgmt_tests(); payload_tests();
    puts("PASS portable native core: IPC whitelist, strict base64, MGMT wire framing, bounded sequential GATT payload");
    return 0;
}
