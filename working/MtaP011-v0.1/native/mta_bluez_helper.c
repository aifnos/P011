#define _GNU_SOURCE
/* Linux-only transport bridge. It never changes adapter Powered/Discoverable,
 * never invokes a shell, and never stops the vendor bluetoothd service.
 * Private stdout is IPC (P2P payloads may contain credentials); do not log it. */
#include "mta_core.h"
#include <gio/gio.h>
#include <glib-unix.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <poll.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MGMT_READ_INFO 0x0004
#define MGMT_READ_ADV_FEATURES 0x003d
#define MGMT_ADD_ADV 0x003e
#define MGMT_REMOVE_ADV 0x003f
#define MGMT_EV_COMPLETE 0x0001
#define MGMT_EV_STATUS 0x0002
#define MGMT_EV_ADV_ADDED 0x0023
#define MGMT_EV_ADV_REMOVED 0x0024
/* Linux HCI socket UAPI layout; protocol constants, no third-party headers. */
#define MTA_BTPROTO_HCI 1
#define MTA_HCI_DEV_NONE 0xffff
#define MTA_HCI_CHANNEL_CONTROL 3
struct p011_sockaddr_hci { sa_family_t family; uint16_t device; uint16_t channel; };
#define APP_PATH "/org/p011/mta"
#define SERVICE_PATH APP_PATH "/service0"
#define STATUS_PATH SERVICE_PATH "/char0"
#define P2P_PATH SERVICE_PATH "/char1"
#define SERVICE_UUID "00009955-0000-1000-8000-00805f9b34fb"
#define STATUS_UUID "00009954-0000-1000-8000-00805f9b34fb"
#define P2P_UUID "00009953-0000-1000-8000-00805f9b34fb"
#define MTA_ADV_UUID "00003331-0000-1000-8000-008123456789"
#define MTA_ADV_UUID_STANDARD "00003331-0000-1000-8000-00805f9b34fb"

struct discovered_peer { char *path; GVariant *properties; unsigned id; gint64 last_emit; };

struct helper {
    GDBusConnection *bus;
    GMainLoop *loop;
    GDBusNodeInfo *introspection;
    GIOChannel *stdin_channel;
    char *bluez_owner, *peer_path;
    char adapter[16], adapter_path[64];
    uint16_t index;
    int mgmt_fd, lock_fd;
    guint registrations[4], owner_subscription, properties_subscription, added_subscription;
    gboolean registered, registering, stop_requested, shutting_down;
    gboolean adding, candidate_conflict;
    uint8_t own_instance, candidate_instance;
    gint64 lease_deadline, peer_deadline, rate_window;
    unsigned rate_count, session;
    uint8_t status[MTA_STATUS_MAX]; size_t status_len;
    struct mta_payload p2p;
    GString *input;
    gboolean scanning, scan_pending, client_pending, client_connect_owned, client_connecting, client_cancel_requested;
    gint64 scan_deadline, client_deadline;
    struct discovered_peer peers[32]; unsigned peer_count,next_peer_id;
    unsigned client_id;
    char *client_status_path,*client_p2p_path,*client_peer_path;
};
static struct helper *active_helper;
static gboolean output_failed;

static void stop_discovery(struct helper *h);
static void stop_client(struct helper *h);
static void clear_discovered(struct helper *h);
static void observe_device(struct helper *h,const char *path,GVariant *properties,gboolean cached);
static void client_tick(struct helper *h);

static const char introspection_xml[] =
    "<node>"
    "<interface name='org.freedesktop.DBus.ObjectManager'>"
    "<method name='GetManagedObjects'><arg type='a{oa{sa{sv}}}' direction='out'/></method>"
    "</interface>"
    "<interface name='org.bluez.GattService1'>"
    "<property name='UUID' type='s' access='read'/><property name='Primary' type='b' access='read'/>"
    "<property name='Includes' type='ao' access='read'/>"
    "</interface>"
    "<interface name='org.bluez.GattCharacteristic1'>"
    "<method name='ReadValue'><arg type='a{sv}' direction='in'/><arg type='ay' direction='out'/></method>"
    "<method name='WriteValue'><arg type='ay' direction='in'/><arg type='a{sv}' direction='in'/></method>"
    "<property name='UUID' type='s' access='read'/><property name='Service' type='o' access='read'/>"
    "<property name='Flags' type='as' access='read'/>"
    "</interface>"
    "</node>";

static uint16_t read16(const uint8_t *p) { return (uint16_t)(p[0] | ((uint16_t)p[1]<<8)); }
static uint32_t read32(const uint8_t *p) { return (uint32_t)read16(p) | ((uint32_t)read16(p+2)<<16); }
static void write16(uint8_t *p,unsigned n) { p[0]=(uint8_t)n; p[1]=(uint8_t)(n>>8); }
static gboolean emit_line(const char *line) {
    size_t size=strlen(line);
    if (output_failed || size>4096) return FALSE;
    ssize_t written;
    do { written=write(STDOUT_FILENO,line,size); } while (written<0 && errno==EINTR);
    if (written!=(ssize_t)size) {
        /* <= PIPE_BUF events + nonblocking pipe: never block the radio loop if
         * the protocol process stops draining. Fail closed instead of dropping
         * a partial/credential-bearing event and continuing invisibly. */
        output_failed=TRUE;
        if (active_helper && active_helper->loop) g_main_loop_quit(active_helper->loop);
        return FALSE;
    }
    return TRUE;
}
static void result(const char *event, const char *code) {
    char line[512]; snprintf(line,sizeof(line),"{\"event\":\"%s\",\"code\":\"%s\"}\n",event,code); (void)emit_line(line);
}
static gboolean sender_is_bluez(struct helper *h,const char *sender) {
    return h->bluez_owner && sender && !strcmp(h->bluez_owner,sender);
}
static GVariant *call(struct helper *h,const char *path,const char *interface,
                      const char *method,GVariant *parameters,const GVariantType *type) {
    GError *error=NULL;
    GVariant *reply=g_dbus_connection_call_sync(h->bus,h->bluez_owner,path,interface,
                           method,parameters,type,G_DBUS_CALL_FLAGS_NONE,1500,NULL,&error);
    if (error) g_error_free(error); /* DBus messages can contain peer identifiers. */
    return reply;
}
static gboolean bool_property(struct helper *h,const char *path,const char *interface,
                               const char *name,gboolean *value) {
    GVariant *reply=call(h,path,"org.freedesktop.DBus.Properties","Get",
                         g_variant_new("(ss)",interface,name),G_VARIANT_TYPE("(v)"));
    GVariant *wrapped,*actual;
    if (!reply) return FALSE;
    wrapped=g_variant_get_child_value(reply,0); actual=g_variant_get_variant(wrapped);
    gboolean ok=g_variant_is_of_type(actual,G_VARIANT_TYPE_BOOLEAN);
    if (ok) *value=g_variant_get_boolean(actual);
    g_variant_unref(actual); g_variant_unref(wrapped); g_variant_unref(reply); return ok;
}
static gboolean adapter_powered(struct helper *h) {
    gboolean value=FALSE;
    return bool_property(h,h->adapter_path,"org.bluez.Adapter1","Powered",&value) && value;
}
static int open_mgmt(void) {
    struct p011_sockaddr_hci address;
    int fd=socket(AF_BLUETOOTH,SOCK_RAW|SOCK_CLOEXEC|SOCK_NONBLOCK,MTA_BTPROTO_HCI);
    if (fd<0) return -1;
    memset(&address,0,sizeof(address)); address.family=AF_BLUETOOTH;
    address.device=MTA_HCI_DEV_NONE; address.channel=MTA_HCI_CHANNEL_CONTROL;
    if (bind(fd,(struct sockaddr *)&address,sizeof(address))<0) { close(fd); return -1; }
    return fd;
}
static void mgmt_event(struct helper *h,uint16_t event,const uint8_t *data,size_t length) {
    if (length!=1) return;
    if (h->adding && data[0]==h->candidate_instance &&
        (event==MGMT_EV_ADV_ADDED || event==MGMT_EV_ADV_REMOVED)) h->candidate_conflict=TRUE;
    if (event==MGMT_EV_ADV_REMOVED && data[0]==h->own_instance) {
        h->own_instance=0; result("advertisement","expired_or_removed");
    } else if (event==MGMT_EV_ADV_ADDED && data[0]==h->own_instance && !h->adding) {
        /* Somebody replaced this ID. MGMT has no per-socket ownership. */
        h->own_instance=0; result("advertisement","ownership_lost");
    }
}
/* Only four explicit MGMT opcodes exist in this implementation. A response
 * timeout does NOT mean the command did not run. Add has a kernel TTL lease. */
static int mgmt_command(struct helper *h,uint16_t opcode,const uint8_t *parameters,
                         size_t size,uint8_t *reply,size_t capacity,size_t *written) {
    uint8_t command[6+73],packet[4096];
    gint64 deadline=g_get_monotonic_time()+3000000;
    if (size>sizeof(command)-6) return -1;
    write16(command,opcode); write16(command+2,h->index); write16(command+4,(unsigned)size);
    if (size) memcpy(command+6,parameters,size);
    if (send(h->mgmt_fd,command,size+6,0)!=(ssize_t)(size+6)) return -1;
    for (;;) {
        gint64 left=deadline-g_get_monotonic_time();
        struct pollfd pollfd={h->mgmt_fd,POLLIN,0};
        ssize_t received; uint16_t event,index,length;
        if (left<=0) return -2;
        int ready=poll(&pollfd,1,(int)((left+999)/1000));
        if (ready<0 && errno==EINTR) continue;
        if (ready<=0 || !(pollfd.revents&POLLIN)) return -2;
        received=recv(h->mgmt_fd,packet,sizeof(packet),0);
        if (received<6) continue;
        event=read16(packet); index=read16(packet+2); length=read16(packet+4);
        if (index!=h->index || (size_t)received!=(size_t)length+6) continue;
        mgmt_event(h,event,packet+6,length);
        if ((event==MGMT_EV_COMPLETE || event==MGMT_EV_STATUS) && length>=3 && read16(packet+6)==opcode) {
            unsigned status=packet[8];
            if (status) return -(int)(100+status);
            if (event==MGMT_EV_STATUS) continue;
            if ((size_t)length-3>capacity) return -3;
            *written=(size_t)length-3; if (*written) memcpy(reply,packet+9,*written);
            return 0;
        }
    }
}
static gboolean features(struct helper *h,struct mta_advertising_features *f) {
    uint8_t bytes[262]; size_t length=0;
    return mgmt_command(h,MGMT_READ_ADV_FEATURES,NULL,0,bytes,sizeof(bytes),&length)==0 && mta_features_decode(bytes,length,f);
}
static gboolean bluez_has_advertisements(struct helper *h,gboolean *known) {
    GVariant *reply=call(h,h->adapter_path,"org.freedesktop.DBus.Properties","Get",
                         g_variant_new("(ss)","org.bluez.LEAdvertisingManager1","ActiveInstances"),G_VARIANT_TYPE("(v)"));
    *known=FALSE;
    if (!reply) return TRUE;
    GVariant *wrapped=g_variant_get_child_value(reply,0),*value=g_variant_get_variant(wrapped);
    gboolean active=TRUE;
    if (g_variant_is_of_type(value,G_VARIANT_TYPE_BYTE)) { *known=TRUE; active=g_variant_get_byte(value)!=0; }
    g_variant_unref(value); g_variant_unref(wrapped); g_variant_unref(reply); return active;
}
static void clear_peer(struct helper *h) {
    g_clear_pointer(&h->peer_path,g_free); mta_wipe(&h->p2p,sizeof(h->p2p)); h->peer_deadline=0;
}
static void remove_own_advertisement(struct helper *h) {
    uint8_t instance=h->own_instance,reply[1]; size_t size=0;
    struct mta_advertising_features f;
    unsigned i;
    if (!instance) return;
    /* Drain observable ownership changes BEFORE deciding to remove. */
    uint8_t packet[4096]; ssize_t n;
    while ((n=recv(h->mgmt_fd,packet,sizeof(packet),MSG_DONTWAIT))>0)
        if (n>=6 && read16(packet+2)==h->index && (size_t)n==(size_t)read16(packet+4)+6)
            mgmt_event(h,read16(packet),packet+6,(size_t)n-6);
    if (h->own_instance!=instance) return;
    if (!features(h,&f)) { result("cleanup","advertisement_readback_failed_ttl_retained"); return; }
    for (i=0;i<f.count && f.instances[i]!=instance;i++) {}
    if (i==f.count || h->own_instance!=instance) { h->own_instance=0; return; }
    /* Never instance=0: that removes every instance, including vendor ones. */
    if (mgmt_command(h,MGMT_REMOVE_ADV,&instance,1,reply,sizeof(reply),&size)==0 && size==1 && reply[0]==instance) {
        h->own_instance=0; result("cleanup","advertisement_removed");
    } else result("cleanup","advertisement_remove_failed_ttl_retained");
}
static void unregister_application(struct helper *h) {
    if (h->registered && h->bluez_owner) {
        GVariant *reply=call(h,h->adapter_path,"org.bluez.GattManager1","UnregisterApplication",g_variant_new("(o)",APP_PATH),NULL);
        if (reply) { g_variant_unref(reply); result("cleanup","gatt_unregistered"); }
        else result("cleanup","gatt_unregister_failed_connection_exit_will_release");
    }
    h->registered=FALSE;
}
static void stop_resources(struct helper *h) {
    h->stop_requested=TRUE;
    stop_discovery(h); stop_client(h);
    remove_own_advertisement(h); unregister_application(h); clear_peer(h); clear_discovered(h);
    mta_wipe(h->status,sizeof(h->status)); h->status_len=0; h->lease_deadline=0;
    if (h->lock_fd>=0) { flock(h->lock_fd,LOCK_UN); close(h->lock_fd); h->lock_fd=-1; }
}
static GVariant *service_properties(void) {
    GVariantBuilder b; g_variant_builder_init(&b,G_VARIANT_TYPE("a{sv}"));
    g_variant_builder_add(&b,"{sv}","UUID",g_variant_new_string(SERVICE_UUID));
    g_variant_builder_add(&b,"{sv}","Primary",g_variant_new_boolean(TRUE));
    g_variant_builder_add(&b,"{sv}","Includes",g_variant_new_objv(NULL,0));
    return g_variant_builder_end(&b);
}
static GVariant *char_properties(gboolean status) {
    const char *read_flags[]={"read",NULL},*write_flags[]={"write","write-without-response",NULL};
    GVariantBuilder b; g_variant_builder_init(&b,G_VARIANT_TYPE("a{sv}"));
    g_variant_builder_add(&b,"{sv}","UUID",g_variant_new_string(status?STATUS_UUID:P2P_UUID));
    g_variant_builder_add(&b,"{sv}","Service",g_variant_new_object_path(SERVICE_PATH));
    g_variant_builder_add(&b,"{sv}","Flags",g_variant_new_strv(status?read_flags:write_flags,-1));
    return g_variant_builder_end(&b);
}
static void object_add(GVariantBuilder *objects,const char *path,const char *interface,GVariant *properties) {
    GVariantBuilder interfaces; g_variant_builder_init(&interfaces,G_VARIANT_TYPE("a{sa{sv}}"));
    g_variant_builder_add(&interfaces,"{s@a{sv}}",interface,properties);
    g_variant_builder_add(objects,"{o@a{sa{sv}}}",path,g_variant_builder_end(&interfaces));
}
static void dbus_error(GDBusMethodInvocation *invocation,const char *name) {
    g_dbus_method_invocation_return_dbus_error(invocation,name,"P011 MTA request rejected");
}
static gboolean peer_connected(struct helper *h,GVariant *options,const char **peer) {
    gboolean connected=FALSE; size_t prefix=strlen(h->adapter_path);
    if (!g_variant_lookup(options,"device","&o",peer) ||
        strncmp(*peer,h->adapter_path,prefix) || strncmp(*peer+prefix,"/dev_",5)) return FALSE;
    const char *address=*peer+prefix+5;
    if (strlen(address)!=17) return FALSE;
    for (unsigned i=0;i<17;i++) {
        if ((i+1)%3==0) { if (address[i]!='_') return FALSE; }
        else if (!g_ascii_isxdigit(address[i])) return FALSE;
    }
    return bool_property(h,*peer,"org.bluez.Device1","Connected",&connected) && connected;
}
static void method_call(GDBusConnection *connection,const char *sender,const char *path,
                         const char *interface,const char *method,GVariant *parameters,
                         GDBusMethodInvocation *invocation,gpointer data) {
    struct helper *h=data;
    (void)connection; (void)interface;
    if (!sender_is_bluez(h,sender)) { dbus_error(invocation,"org.bluez.Error.NotAuthorized"); return; }
    if (!strcmp(path,APP_PATH) && !strcmp(method,"GetManagedObjects")) {
        GVariantBuilder objects; g_variant_builder_init(&objects,G_VARIANT_TYPE("a{oa{sa{sv}}}"));
        object_add(&objects,SERVICE_PATH,"org.bluez.GattService1",service_properties());
        object_add(&objects,STATUS_PATH,"org.bluez.GattCharacteristic1",char_properties(TRUE));
        object_add(&objects,P2P_PATH,"org.bluez.GattCharacteristic1",char_properties(FALSE));
        g_dbus_method_invocation_return_value(invocation,g_variant_new("(@a{oa{sa{sv}}})",g_variant_builder_end(&objects))); return;
    }
    if (!h->registered || h->stop_requested) { dbus_error(invocation,"org.bluez.Error.NotPermitted"); return; }
    GVariant *options=NULL,*value=NULL;
    const char *peer=NULL; guint16 offset=0; gboolean prepare=FALSE;
    if (!strcmp(method,"ReadValue") && !strcmp(path,STATUS_PATH)) g_variant_get(parameters,"(@a{sv})",&options);
    else if (!strcmp(method,"WriteValue") && !strcmp(path,P2P_PATH)) g_variant_get(parameters,"(@ay@a{sv})",&value,&options);
    else { dbus_error(invocation,"org.bluez.Error.NotSupported"); return; }
    if (!peer_connected(h,options,&peer)) { dbus_error(invocation,"org.bluez.Error.NotAuthorized"); goto done; }
    g_variant_lookup(options,"offset","q",&offset);
    g_variant_lookup(options,"prepare-authorize","b",&prepare);
    if (prepare) { dbus_error(invocation,"org.bluez.Error.NotSupported"); goto done; }
    if (!value) {
        if (offset>h->status_len) { dbus_error(invocation,"org.bluez.Error.InvalidOffset"); goto done; }
        GVariant *bytes=g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE,h->status+offset,h->status_len-offset,1);
        g_dbus_method_invocation_return_value(invocation,g_variant_new("(@ay)",bytes)); goto done;
    }
    gint64 now=g_get_monotonic_time();
    if (h->peer_path && strcmp(h->peer_path,peer)) { dbus_error(invocation,"org.bluez.Error.InProgress"); goto done; }
    if (now-h->rate_window>10000000) { h->rate_window=now; h->rate_count=0; }
    if (++h->rate_count>32) { dbus_error(invocation,"org.bluez.Error.InProgress"); goto done; }
    if (!h->peer_path) { h->peer_path=g_strdup(peer); h->session++; }
    gsize length=0; const uint8_t *bytes=g_variant_get_fixed_array(value,&length,1);
    int complete=mta_payload_push(&h->p2p,offset,bytes,length);
    if (complete<0) { mta_wipe(&h->p2p,sizeof(h->p2p)); dbus_error(invocation,"org.bluez.Error.InvalidValueLength"); goto done; }
    h->peer_deadline=now+10000000;
    if (complete==1) {
        if (!g_utf8_validate((const char *)h->p2p.bytes,(gssize)h->p2p.length,NULL)) { mta_wipe(&h->p2p,sizeof(h->p2p)); dbus_error(invocation,"org.bluez.Error.InvalidValueLength"); goto done; }
        char *encoded=g_base64_encode(h->p2p.bytes,h->p2p.length);
        /* Private inherited pipe only. Never tee stdout to diagnostic logs. */
        char *line=g_strdup_printf("{\"event\":\"p2p\",\"session\":%u,\"payload_b64\":\"%s\"}\n",h->session,encoded);
        gboolean delivered=emit_line(line); mta_wipe(line,strlen(line)); g_free(line);
        mta_wipe(encoded,strlen(encoded)); g_free(encoded); mta_wipe(&h->p2p,sizeof(h->p2p));
        if (!delivered) { dbus_error(invocation,"org.bluez.Error.Failed"); goto done; }
    }
    g_dbus_method_invocation_return_value(invocation,NULL);
done:
    if (value) g_variant_unref(value);
    if (options) g_variant_unref(options);
}
static GVariant *get_property(GDBusConnection *connection,const char *sender,const char *path,
                              const char *interface,const char *property,GError **error,gpointer data) {
    struct helper *h=data; GVariant *properties,*value;
    (void)connection; (void)interface;
    if (!sender_is_bluez(h,sender)) { g_set_error_literal(error,G_IO_ERROR,G_IO_ERROR_PERMISSION_DENIED,"not BlueZ owner"); return NULL; }
    properties=!strcmp(path,SERVICE_PATH)?service_properties():char_properties(!strcmp(path,STATUS_PATH));
    value=g_variant_lookup_value(properties,property,NULL); g_variant_ref_sink(properties); g_variant_unref(properties); return value;
}
static const GDBusInterfaceVTable vtable={method_call,get_property,NULL,{0}};

static void register_done(GObject *object,GAsyncResult *response,gpointer data) {
    struct helper *h=data; GError *error=NULL;
    GVariant *reply=g_dbus_connection_call_finish(G_DBUS_CONNECTION(object),response,&error);
    h->registering=FALSE;
    if (!reply) {
        if (error) g_error_free(error);
        result("listen","register_failed_exit_releases_owner");
        stop_resources(h); g_main_loop_quit(h->loop); return;
    }
    g_variant_unref(reply); h->registered=TRUE;
    if (h->stop_requested) { unregister_application(h); return; }
    result("listen","ready");
}
static int acquire_lock(struct helper *h) {
    char path[128]; struct stat st;
    snprintf(path,sizeof(path),"/run/p011-mta-hci%u.lock",h->index);
    int fd=open(path,O_CREAT|O_RDWR|O_CLOEXEC|O_NOFOLLOW,0600);
    if (fd<0) return -1;
    if (fstat(fd,&st)<0 || !S_ISREG(st.st_mode) || st.st_uid!=geteuid() || (st.st_mode&077)!=0 || flock(fd,LOCK_EX|LOCK_NB)<0) { close(fd); return -1; }
    return fd;
}
static void listen_command(struct helper *h,const struct mta_command *command) {
    if (h->registered || h->registering) { result("listen","already_active"); return; }
    if (strcmp(command->adapter,h->adapter)) { result("listen","adapter_mismatch"); return; }
    if (!adapter_powered(h)) { result("listen","bluetooth_off_or_unavailable"); return; }
    if (!g_utf8_validate((const char *)command->status,(gssize)command->status_len,NULL)) { result("listen","invalid_utf8"); return; }
    h->lock_fd=acquire_lock(h);
    if (h->lock_fd<0) { result("listen","ownership_lock_unavailable"); return; }
    memcpy(h->status,command->status,command->status_len); h->status_len=command->status_len;
    h->stop_requested=FALSE; h->registering=TRUE; h->lease_deadline=g_get_monotonic_time()+600000000;
    g_dbus_connection_call(h->bus,h->bluez_owner,h->adapter_path,"org.bluez.GattManager1","RegisterApplication",
                           g_variant_new("(oa{sv})",APP_PATH,NULL),NULL,G_DBUS_CALL_FLAGS_NONE,5000,NULL,register_done,h);
}
static void advert_command(struct helper *h,const struct mta_command *command) {
    uint8_t parameters[73],reply[1],info[280]; size_t size=0,returned=0;
    struct mta_advertising_features f; gboolean known=FALSE;
    if (!h->registered || h->stop_requested) { result("advert","gatt_not_ready"); return; }
    if (strcmp(command->adapter,h->adapter)) { result("advert","adapter_mismatch"); return; }
    if (h->own_instance) { result("advert","already_active_stop_first"); return; }
    if (!adapter_powered(h)) { result("advert","bluetooth_off_or_unavailable"); return; }
    if (mgmt_command(h,MGMT_READ_INFO,NULL,0,info,sizeof(info),&returned)!=0 || returned<17) { result("advert","controller_read_failed"); return; }
    uint32_t settings=read32(info+13);
    if (!(settings&1) || !(settings&(1u<<9))) { result("advert","powered_or_le_unavailable"); return; }
    /* Linux 4.14 can implicitly prepend an AD Flags field when BR/EDR is
     * disabled, even without MANAGED_FLAGS. Refuse that raw-byte mode rather
     * than duplicating Flags or silently exceeding the 31-byte packet. */
    if (!(settings&(1u<<7))) { result("advert","raw_layout_requires_existing_bredr_enabled"); return; }
    if (settings&(1u<<10)) { result("advert","global_advertising_active_refused"); return; }
    if (bluez_has_advertisements(h,&known) || !known || !features(h,&f)) { result("advert","external_advertisement_or_unknown"); return; }
    /* Initial version refuses ALL pre-existing advertising instances. MGMT
     * AddAdvertising is an update, not an atomic ownership reservation. */
    if (f.count) { result("advert","external_advertisement_refused"); return; }
    if (!(f.flags&1) || command->adv_len>f.adv_max || command->scan_len>f.scan_max || !mta_free_instance(&f)) { result("advert","unsupported_capability"); return; }
    h->candidate_instance=(uint8_t)mta_free_instance(&f);
    size=mta_add_advertising(parameters,sizeof(parameters),h->candidate_instance,command->ttl,
                             command->adv,command->adv_len,command->scan,command->scan_len);
    h->adding=TRUE; h->candidate_conflict=FALSE;
    int status=mgmt_command(h,MGMT_ADD_ADV,parameters,size,reply,sizeof(reply),&returned);
    h->adding=FALSE;
    if (h->candidate_conflict) result("advert","concurrent_mutation_ownership_unknown_ttl_retained");
    else if (status==0 && returned==1 && reply[0]==h->candidate_instance) {
        h->own_instance=reply[0];
        char line[160]; snprintf(line,sizeof(line),"{\"event\":\"advert\",\"code\":\"ready\",\"instance\":%u,\"ttl\":%u}\n",h->own_instance,command->ttl); (void)emit_line(line);
    } else result("advert",status==-2?"outcome_unknown_kernel_ttl_retained":"add_failed");
    h->candidate_instance=0;
}
static struct discovered_peer *peer_by_id(struct helper *h,unsigned id) {
    for (unsigned i=0;i<h->peer_count;i++) if (h->peers[i].id==id) return &h->peers[i];
    return NULL;
}
static void clear_discovered(struct helper *h) {
    for (unsigned i=0;i<h->peer_count;i++) {
        g_free(h->peers[i].path);
        if (h->peers[i].properties) g_variant_unref(h->peers[i].properties);
    }
    memset(h->peers,0,sizeof(h->peers)); h->peer_count=0;
}
static gboolean uuid_safe(const char *text) {
    if (strlen(text)!=36) return FALSE;
    for (unsigned i=0;i<36;i++) {
        if (i==8 || i==13 || i==18 || i==23) { if (text[i]!='-') return FALSE; }
        else if (!g_ascii_isxdigit(text[i])) return FALSE;
    }
    return TRUE;
}
static gboolean device_path_valid(struct helper *h,const char *path) {
    size_t prefix=strlen(h->adapter_path);
    if (strncmp(path,h->adapter_path,prefix) || strncmp(path+prefix,"/dev_",5) || strlen(path+prefix+5)!=17) return FALSE;
    for (unsigned i=0;i<17;i++) {
        char c=path[prefix+5+i];
        if ((i+1)%3==0) { if (c!='_') return FALSE; }
        else if (!g_ascii_isxdigit(c)) return FALSE;
    }
    return TRUE;
}
static gboolean properties_are_mta(GVariant *properties) {
    GVariant *uuids=g_variant_lookup_value(properties,"UUIDs",G_VARIANT_TYPE_STRING_ARRAY);
    if (!uuids) return FALSE;
    GVariantIter it; const char *uuid; gboolean match=FALSE;
    g_variant_iter_init(&it,uuids);
    while (g_variant_iter_next(&it,"&s",&uuid))
        if (!g_ascii_strcasecmp(uuid,MTA_ADV_UUID) || !g_ascii_strcasecmp(uuid,MTA_ADV_UUID_STANDARD)) match=TRUE;
    g_variant_unref(uuids); return match;
}
static void emit_peer(struct discovered_peer *peer,gboolean cached) {
    const char *name="";
    if (!g_variant_lookup(peer->properties,"Name","&s",&name)) name="";
    size_t name_size=strlen(name); if (name_size>128) name_size=128;
    const char *valid_end=NULL;
    if (!g_utf8_validate(name,(gssize)name_size,&valid_end)) name_size=(size_t)(valid_end-name);
    char *name_encoded=g_base64_encode((const guchar *)name,name_size);
    GString *line=g_string_new(NULL);
    g_string_append_printf(line,"{\"event\":\"discovered\",\"peer\":%u,\"cached\":%s,\"name_b64\":\"%s\",\"service_data\":[",peer->id,cached?"true":"false",name_encoded);
    g_free(name_encoded);
    GVariant *service_data=g_variant_lookup_value(peer->properties,"ServiceData",G_VARIANT_TYPE("a{sv}"));
    unsigned count=0;
    if (service_data) {
        GVariantIter it; const char *uuid; GVariant *bytes;
        g_variant_iter_init(&it,service_data);
        while (g_variant_iter_next(&it,"{&sv}",&uuid,&bytes)) {
            if (uuid_safe(uuid) && g_variant_is_of_type(bytes,G_VARIANT_TYPE_BYTESTRING) && count<8) {
                gsize size; const guchar *data=g_variant_get_fixed_array(bytes,&size,1);
                if (size<=31) {
                    char *encoded=g_base64_encode(data,size);
                    g_string_append_printf(line,"%s{\"uuid\":\"%s\",\"payload_b64\":\"%s\"}",count?",":"",uuid,encoded); count++; g_free(encoded);
                }
            }
            g_variant_unref(bytes);
        }
        g_variant_unref(service_data);
    }
    g_string_append(line,"]}\n"); (void)emit_line(line->str); mta_wipe(line->str,line->len); g_string_free(line,TRUE);
}
static void observe_device(struct helper *h,const char *path,GVariant *properties,gboolean cached) {
    if (!h->scanning || !device_path_valid(h,path)) return;
    struct discovered_peer *peer=NULL;
    for (unsigned i=0;i<h->peer_count;i++) if (!strcmp(h->peers[i].path,path)) peer=&h->peers[i];
    GVariant *merged=NULL;
    if (peer) {
        GVariantDict dict; g_variant_dict_init(&dict,peer->properties);
        GVariantIter it; const char *key; GVariant *value;
        g_variant_iter_init(&it,properties);
        while (g_variant_iter_next(&it,"{&sv}",&key,&value)) { g_variant_dict_insert_value(&dict,key,value); g_variant_unref(value); }
        merged=g_variant_ref_sink(g_variant_dict_end(&dict));
    } else merged=g_variant_ref(properties);
    if (!properties_are_mta(merged)) { g_variant_unref(merged); return; }
    if (!peer) {
        if (h->peer_count==G_N_ELEMENTS(h->peers) || h->next_peer_id==65535) { g_variant_unref(merged); return; }
        peer=&h->peers[h->peer_count++]; peer->path=g_strdup(path); peer->id=++h->next_peer_id;
    }
    if (peer->properties) g_variant_unref(peer->properties);
    peer->properties=merged;
    gint64 now=g_get_monotonic_time();
    if (!peer->last_emit || now-peer->last_emit>=500000) { emit_peer(peer,cached); peer->last_emit=now; }
}
static void snapshot_done(GObject *object,GAsyncResult *response,gpointer data) {
    struct helper *h=data; GError *error=NULL;
    GVariant *reply=g_dbus_connection_call_finish(G_DBUS_CONNECTION(object),response,&error);
    if (!reply) { if (error) g_error_free(error); result("scan","snapshot_unavailable"); return; }
    if (h->scanning) {
        GVariant *objects=g_variant_get_child_value(reply,0); GVariantIter it; const char *path; GVariant *interfaces;
        g_variant_iter_init(&it,objects);
        while (g_variant_iter_next(&it,"{&o@a{sa{sv}}}",&path,&interfaces)) {
            GVariant *properties=g_variant_lookup_value(interfaces,"org.bluez.Device1",G_VARIANT_TYPE("a{sv}"));
            if (properties) { observe_device(h,path,properties,TRUE); g_variant_unref(properties); }
            g_variant_unref(interfaces);
        }
        g_variant_unref(objects);
    }
    g_variant_unref(reply);
}
static void scan_started(GObject *object,GAsyncResult *response,gpointer data) {
    struct helper *h=data; GError *error=NULL;
    GVariant *reply=g_dbus_connection_call_finish(G_DBUS_CONNECTION(object),response,&error); h->scan_pending=FALSE;
    if (!reply) {
        if (error) g_error_free(error);
        result("scan","start_failed_or_outcome_unknown");
        h->scanning=TRUE; stop_discovery(h); return;
    }
    g_variant_unref(reply); h->scanning=TRUE;
    if (h->stop_requested || !h->scan_deadline) { stop_discovery(h); return; }
    result("scan","ready");
    g_dbus_connection_call(h->bus,h->bluez_owner,"/","org.freedesktop.DBus.ObjectManager","GetManagedObjects",NULL,
                           G_VARIANT_TYPE("(a{oa{sa{sv}}})"),G_DBUS_CALL_FLAGS_NONE,3000,NULL,snapshot_done,h);
}
static void scan_command(struct helper *h,const struct mta_command *command) {
    if (strcmp(command->adapter,h->adapter)) { result("scan","adapter_mismatch"); return; }
    if (h->scanning || h->scan_pending) { result("scan","already_active"); return; }
    if (h->client_id || h->client_pending) { result("scan","client_active_stop_first"); return; }
    if (!adapter_powered(h)) { result("scan","bluetooth_off_or_unavailable"); return; }
    GVariantBuilder filter; const char *uuids[]={MTA_ADV_UUID,MTA_ADV_UUID_STANDARD,NULL};
    g_variant_builder_init(&filter,G_VARIANT_TYPE("a{sv}"));
    g_variant_builder_add(&filter,"{sv}","Transport",g_variant_new_string("le"));
    g_variant_builder_add(&filter,"{sv}","UUIDs",g_variant_new_strv(uuids,-1));
    g_variant_builder_add(&filter,"{sv}","DuplicateData",g_variant_new_boolean(TRUE));
    GVariant *reply=call(h,h->adapter_path,"org.bluez.Adapter1","SetDiscoveryFilter",g_variant_new("(@a{sv})",g_variant_builder_end(&filter)),NULL);
    if (!reply) { result("scan","filter_failed"); return; }
    g_variant_unref(reply); clear_discovered(h); h->scan_pending=TRUE; h->stop_requested=FALSE;
    h->scan_deadline=g_get_monotonic_time()+(gint64)command->ttl*1000000;
    g_dbus_connection_call(h->bus,h->bluez_owner,h->adapter_path,"org.bluez.Adapter1","StartDiscovery",NULL,
                           NULL,G_DBUS_CALL_FLAGS_NONE,3000,NULL,scan_started,h);
}
static void stop_discovery(struct helper *h) {
    if (h->scanning && h->bluez_owner) {
        GVariant *reply=call(h,h->adapter_path,"org.bluez.Adapter1","StopDiscovery",NULL,NULL);
        if (reply) { g_variant_unref(reply); result("scan","own_session_stopped"); }
        else result("cleanup","scan_stop_failed_owner_exit_will_release");
        reply=call(h,h->adapter_path,"org.bluez.Adapter1","SetDiscoveryFilter",g_variant_new("(a{sv})",NULL),NULL);
        if (reply) g_variant_unref(reply);
    }
    h->scanning=FALSE; h->scan_deadline=0;
}
static void stop_client(struct helper *h) {
    if (h->client_peer_path && h->client_connect_owned && h->bluez_owner) {
        GVariant *reply=call(h,h->client_peer_path,"org.bluez.Device1","Disconnect",NULL,NULL);
        if (reply) { g_variant_unref(reply); result("client","own_connection_disconnect_requested"); }
        else result("cleanup","client_disconnect_failed");
    }
    h->client_deadline=0;
    g_clear_pointer(&h->client_status_path,g_free); g_clear_pointer(&h->client_p2p_path,g_free);
    if (h->client_connecting) {
        /* Keep a private copy after discovery-table cleanup so a late successful
         * Connect can still be disconnected. Do not allow another operation. */
        h->client_cancel_requested=TRUE; return;
    }
    h->client_id=0; h->client_connect_owned=FALSE; h->client_cancel_requested=FALSE;
    g_clear_pointer(&h->client_peer_path,g_free);
}
static void client_read_done(GObject *object,GAsyncResult *response,gpointer data) {
    struct helper *h=data; GError *error=NULL;
    GVariant *reply=g_dbus_connection_call_finish(G_DBUS_CONNECTION(object),response,&error); h->client_pending=FALSE;
    if (!reply) { if (error) g_error_free(error); result("client_read","read_failed"); stop_client(h); return; }
    GVariant *bytes=g_variant_get_child_value(reply,0); gsize size; const guchar *data_bytes=g_variant_get_fixed_array(bytes,&size,1);
    if (!h->client_id || size>MTA_STATUS_MAX || mta_json_envelope(data_bytes,size)!=1 || !g_utf8_validate((const char *)data_bytes,(gssize)size,NULL)) {
        result("client_read","invalid_status"); stop_client(h);
    } else {
        char *encoded=g_base64_encode(data_bytes,size);
        char *line=g_strdup_printf("{\"event\":\"client_status\",\"peer\":%u,\"payload_b64\":\"%s\"}\n",h->client_id,encoded);
        (void)emit_line(line); mta_wipe(line,strlen(line)); g_free(line);
        mta_wipe(encoded,strlen(encoded)); g_free(encoded); h->client_deadline=g_get_monotonic_time()+30000000;
    }
    g_variant_unref(bytes); g_variant_unref(reply);
}
static void client_objects_done(GObject *object,GAsyncResult *response,gpointer data) {
    struct helper *h=data; GError *error=NULL;
    GVariant *reply=g_dbus_connection_call_finish(G_DBUS_CONNECTION(object),response,&error);
    h->client_pending=FALSE; h->client_connecting=FALSE;
    if (!reply) { if (error) g_error_free(error); result("client_read","services_unavailable"); stop_client(h); return; }
    struct discovered_peer *peer=peer_by_id(h,h->client_id);
    if (!peer) { g_variant_unref(reply); return; }
    GVariant *objects=g_variant_get_child_value(reply,0); GVariantIter it; const char *path; GVariant *interfaces;
    char *service_path=NULL;
    g_variant_iter_init(&it,objects);
    while (g_variant_iter_next(&it,"{&o@a{sa{sv}}}",&path,&interfaces)) {
        GVariant *properties=g_variant_lookup_value(interfaces,"org.bluez.GattService1",G_VARIANT_TYPE("a{sv}"));
        const char *uuid=NULL;
        if (properties && g_str_has_prefix(path,peer->path) && path[strlen(peer->path)]=='/' &&
            g_variant_lookup(properties,"UUID","&s",&uuid) && !g_ascii_strcasecmp(uuid,SERVICE_UUID)) {
            if (service_path) { g_free(service_path); service_path=NULL; g_variant_unref(properties); g_variant_unref(interfaces); break; }
            service_path=g_strdup(path);
        }
        if (properties) g_variant_unref(properties);
        g_variant_unref(interfaces);
    }
    if (service_path) {
        g_variant_iter_init(&it,objects);
        while (g_variant_iter_next(&it,"{&o@a{sa{sv}}}",&path,&interfaces)) {
            GVariant *properties=g_variant_lookup_value(interfaces,"org.bluez.GattCharacteristic1",G_VARIANT_TYPE("a{sv}"));
            const char *uuid=NULL,*service=NULL;
            if (properties && g_str_has_prefix(path,service_path) && path[strlen(service_path)]=='/' &&
                g_variant_lookup(properties,"UUID","&s",&uuid) && g_variant_lookup(properties,"Service","&o",&service) && !strcmp(service,service_path)) {
                if (!g_ascii_strcasecmp(uuid,STATUS_UUID) && !h->client_status_path) h->client_status_path=g_strdup(path);
                if (!g_ascii_strcasecmp(uuid,P2P_UUID) && !h->client_p2p_path) h->client_p2p_path=g_strdup(path);
            }
            if (properties) g_variant_unref(properties);
            g_variant_unref(interfaces);
        }
    }
    g_free(service_path); g_variant_unref(objects); g_variant_unref(reply);
    if (!h->client_status_path || !h->client_p2p_path) { result("client_read","mta_characteristics_missing"); stop_client(h); return; }
    h->client_pending=TRUE;
    g_dbus_connection_call(h->bus,h->bluez_owner,h->client_status_path,"org.bluez.GattCharacteristic1","ReadValue",
                           g_variant_new("(a{sv})",NULL),G_VARIANT_TYPE("(ay)"),G_DBUS_CALL_FLAGS_NONE,5000,NULL,client_read_done,h);
}
static void client_connected(GObject *object,GAsyncResult *response,gpointer data) {
    struct helper *h=data; GError *error=NULL;
    GVariant *reply=g_dbus_connection_call_finish(G_DBUS_CONNECTION(object),response,&error);
    h->client_pending=FALSE; h->client_connecting=FALSE;
    if (!reply) { if (error) g_error_free(error); result("client_read","connect_failed"); stop_client(h); return; }
    g_variant_unref(reply);
    if (h->stop_requested || h->client_cancel_requested || !h->client_id) { stop_client(h); return; }
    h->client_deadline=g_get_monotonic_time()+10000000;
}
static void client_tick(struct helper *h) {
    if (!h->client_id || h->client_cancel_requested) return;
    if (g_get_monotonic_time()>=h->client_deadline) { result("client","lease_or_services_timeout"); stop_client(h); return; }
    if (h->client_pending || h->client_status_path) return;
    struct discovered_peer *peer=peer_by_id(h,h->client_id); gboolean resolved=FALSE;
    if (!peer || !bool_property(h,peer->path,"org.bluez.Device1","ServicesResolved",&resolved) || !resolved) return;
    h->client_pending=TRUE;
    g_dbus_connection_call(h->bus,h->bluez_owner,"/","org.freedesktop.DBus.ObjectManager","GetManagedObjects",NULL,
                           G_VARIANT_TYPE("(a{oa{sa{sv}}})"),G_DBUS_CALL_FLAGS_NONE,3000,NULL,client_objects_done,h);
}
static void client_read_command(struct helper *h,const struct mta_command *command) {
    struct discovered_peer *peer=peer_by_id(h,command->peer); gboolean connected=FALSE;
    if (!peer || !properties_are_mta(peer->properties)) { result("client_read","unknown_mta_peer"); return; }
    if (h->client_id || h->client_pending) { result("client_read","already_active_stop_first"); return; }
    if (!adapter_powered(h) || !bool_property(h,peer->path,"org.bluez.Device1","Connected",&connected)) { result("client_read","peer_unavailable"); return; }
    stop_discovery(h); h->client_id=peer->id; h->client_peer_path=g_strdup(peer->path);
    h->stop_requested=FALSE; h->client_connect_owned=!connected; h->client_cancel_requested=FALSE;
    h->client_deadline=g_get_monotonic_time()+10000000;
    if (connected) { client_tick(h); return; }
    h->client_pending=TRUE; h->client_connecting=TRUE;
    g_dbus_connection_call(h->bus,h->bluez_owner,peer->path,"org.bluez.Device1","Connect",NULL,
                           NULL,G_DBUS_CALL_FLAGS_NONE,10000,NULL,client_connected,h);
}
static void client_write_done(GObject *object,GAsyncResult *response,gpointer data) {
    struct helper *h=data; GError *error=NULL;
    GVariant *reply=g_dbus_connection_call_finish(G_DBUS_CONNECTION(object),response,&error); h->client_pending=FALSE;
    if (!reply) { if (error) g_error_free(error); result("client_write","failed"); }
    else { g_variant_unref(reply); result("client_write",h->client_id && !h->stop_requested?"accepted_by_bluez_not_file_transfer_complete":"cancelled_or_late_reply"); }
}
static void client_write_command(struct helper *h,const struct mta_command *command) {
    if (command->peer!=h->client_id || !h->client_p2p_path || h->client_pending || h->stop_requested) { result("client_write","peer_not_ready"); return; }
    if (!g_utf8_validate((const char *)command->payload,(gssize)command->payload_len,NULL)) { result("client_write","invalid_utf8"); return; }
    h->client_pending=TRUE; h->client_deadline=g_get_monotonic_time()+30000000;
    g_dbus_connection_call(h->bus,h->bluez_owner,h->client_p2p_path,"org.bluez.GattCharacteristic1","WriteValue",
                           g_variant_new("(@aya{sv})",g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE,command->payload,command->payload_len,1),NULL),
                           NULL,G_DBUS_CALL_FLAGS_NONE,10000,NULL,client_write_done,h);
}
static void dispatch_line(struct helper *h,const char *line,size_t length) {
    struct mta_command command;
    if (!mta_parse_command(line,length,&command)) { result("error","invalid_command"); mta_wipe(&command,sizeof(command)); return; }
    if (output_failed) { mta_wipe(&command,sizeof(command)); return; }
    if (command.type!=MTA_STOP && h->stop_requested && (h->registering || h->scan_pending || h->client_pending)) {
        result("error","cleanup_pending"); mta_wipe(&command,sizeof(command)); return;
    }
    switch (command.type) {
    case MTA_LISTEN: listen_command(h,&command); break;
    case MTA_ADVERT: advert_command(h,&command); break;
    case MTA_SET_STATUS:
        if (!h->registered || h->stop_requested) result("set_status","not_active");
        else if (!g_utf8_validate((const char *)command.status,(gssize)command.status_len,NULL)) result("set_status","invalid_utf8");
        else { mta_wipe(h->status,sizeof(h->status)); memcpy(h->status,command.status,command.status_len); h->status_len=command.status_len; result("set_status","ready"); }
        break;
    case MTA_STOP:
        stop_resources(h);
        result("stop",h->registering || h->scan_pending || h->client_connecting?"pending_cleanup":"resources_released_or_cleanup_reported");
        break;
    case MTA_SCAN: scan_command(h,&command); break;
    case MTA_CLIENT_READ: client_read_command(h,&command); break;
    case MTA_CLIENT_WRITE: client_write_command(h,&command); break;
    }
    mta_wipe(&command,sizeof(command));
}
static gboolean stdin_ready(GIOChannel *channel,GIOCondition condition,gpointer data) {
    struct helper *h=data; char bytes[1024]; gsize received=0; GError *error=NULL;
    if (condition&(G_IO_ERR|G_IO_NVAL)) { g_main_loop_quit(h->loop); return G_SOURCE_REMOVE; }
    GIOStatus status=g_io_channel_read_chars(channel,bytes,sizeof(bytes),&received,&error);
    if (error) g_error_free(error);
    for (gsize i=0;i<received;i++) {
        if (bytes[i]=='\n') {
            dispatch_line(h,h->input->str,h->input->len);
            mta_wipe(h->input->str,h->input->len); g_string_truncate(h->input,0);
        } else if (h->input->len>=MTA_LINE_MAX) {
            result("error","line_limit_exit"); g_main_loop_quit(h->loop); return G_SOURCE_REMOVE;
        } else g_string_append_c(h->input,bytes[i]);
    }
    mta_wipe(bytes,sizeof(bytes));
    if (status==G_IO_STATUS_EOF || (condition&G_IO_HUP && !received)) { g_main_loop_quit(h->loop); return G_SOURCE_REMOVE; }
    return G_SOURCE_CONTINUE;
}
static gboolean mgmt_ready(gint fd,GIOCondition condition,gpointer data) {
    struct helper *h=data; uint8_t packet[4096]; ssize_t n;
    if (condition&(G_IO_HUP|G_IO_ERR|G_IO_NVAL)) { result("error","mgmt_socket_closed"); g_main_loop_quit(h->loop); return G_SOURCE_REMOVE; }
    while ((n=recv(fd,packet,sizeof(packet),MSG_DONTWAIT))>0)
        if (n>=6 && read16(packet+2)==h->index && (size_t)n==(size_t)read16(packet+4)+6)
            mgmt_event(h,read16(packet),packet+6,(size_t)n-6);
    return G_SOURCE_CONTINUE;
}
static gboolean tick(gpointer data) {
    struct helper *h=data; gint64 now=g_get_monotonic_time();
    if (h->peer_deadline && now>=h->peer_deadline) { clear_peer(h); result("peer","fragment_or_session_timeout"); }
    if (h->lease_deadline && now>=h->lease_deadline) { stop_resources(h); result("listen","lease_expired"); }
    if (h->scan_deadline && now>=h->scan_deadline) { stop_discovery(h); result("scan","lease_expired"); }
    client_tick(h);
    return G_SOURCE_CONTINUE;
}
static gboolean signal_stop(gpointer data) { struct helper *h=data; g_main_loop_quit(h->loop); return G_SOURCE_REMOVE; }
static void owner_changed(GDBusConnection *connection,const char *sender,const char *path,
                           const char *interface,const char *signal,GVariant *parameters,gpointer data) {
    struct helper *h=data; const char *name,*old_owner,*new_owner;
    (void)connection; (void)sender; (void)path; (void)interface; (void)signal;
    g_variant_get(parameters,"(&s&s&s)",&name,&old_owner,&new_owner);
    (void)name; (void)old_owner;
    if (strcmp(new_owner,h->bluez_owner)) { g_clear_pointer(&h->bluez_owner,g_free); h->registered=FALSE; result("error","bluez_owner_changed_exit"); g_main_loop_quit(h->loop); }
}
static void device_changed(GDBusConnection *connection,const char *sender,const char *path,
                            const char *interface,const char *signal,GVariant *parameters,gpointer data) {
    struct helper *h=data; const char *changed_interface; GVariant *changed,*invalidated;
    (void)connection; (void)interface; (void)signal;
    if (!sender_is_bluez(h,sender)) return;
    g_variant_get(parameters,"(&s@a{sv}@as)",&changed_interface,&changed,&invalidated);
    gboolean connected;
    if (!strcmp(changed_interface,"org.bluez.Device1")) {
        observe_device(h,path,changed,FALSE);
        if (h->peer_path && !strcmp(path,h->peer_path) && g_variant_lookup(changed,"Connected","b",&connected) && !connected) { clear_peer(h); result("peer","disconnected"); }
    }
    g_variant_unref(changed); g_variant_unref(invalidated);
}
static void interfaces_added(GDBusConnection *connection,const char *sender,const char *path,
                              const char *interface,const char *signal,GVariant *parameters,gpointer data) {
    struct helper *h=data; const char *device_path; GVariant *interfaces;
    (void)connection; (void)path; (void)interface; (void)signal;
    if (!sender_is_bluez(h,sender)) return;
    g_variant_get(parameters,"(&o@a{sa{sv}})",&device_path,&interfaces);
    GVariant *properties=g_variant_lookup_value(interfaces,"org.bluez.Device1",G_VARIANT_TYPE("a{sv}"));
    if (properties) { observe_device(h,device_path,properties,FALSE); g_variant_unref(properties); }
    g_variant_unref(interfaces);
}
static gboolean initialize(struct helper *h,const char *adapter) {
    char *tail=NULL; unsigned long index;
    if (strncmp(adapter,"hci",3) || strlen(adapter)>=sizeof(h->adapter) || !g_ascii_isdigit(adapter[3])) return FALSE;
    errno=0; index=strtoul(adapter+3,&tail,10);
    if (errno || !tail || *tail || index>65534) return FALSE;
    strcpy(h->adapter,adapter); snprintf(h->adapter_path,sizeof(h->adapter_path),"/org/bluez/%s",adapter); h->index=(uint16_t)index;
    GError *error=NULL;
    char *bus_address=g_dbus_address_get_for_bus_sync(G_BUS_TYPE_SYSTEM,NULL,&error);
    if (bus_address) {
        h->bus=g_dbus_connection_new_for_address_sync(bus_address,
            G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT|G_DBUS_CONNECTION_FLAGS_MESSAGE_BUS_CONNECTION,
            NULL,NULL,&error);
        g_free(bus_address);
    }
    if (!h->bus) { if (error) g_error_free(error); result("error","system_bus_unavailable"); return FALSE; }
    GVariant *reply=g_dbus_connection_call_sync(h->bus,"org.freedesktop.DBus","/org/freedesktop/DBus","org.freedesktop.DBus","GetNameOwner",
                          g_variant_new("(s)","org.bluez"),G_VARIANT_TYPE("(s)"),G_DBUS_CALL_FLAGS_NONE,1500,NULL,&error);
    if (!reply) { if (error) g_error_free(error); result("error","bluez_unavailable"); return FALSE; }
    g_variant_get(reply,"(s)",&h->bluez_owner); g_variant_unref(reply);
    h->mgmt_fd=open_mgmt();
    if (h->mgmt_fd<0) { result("error","mgmt_permission_or_socket_unavailable"); return FALSE; }
    return TRUE;
}
static gboolean export_objects(struct helper *h) {
    GError *error=NULL;
    h->introspection=g_dbus_node_info_new_for_xml(introspection_xml,&error);
    if (!h->introspection) { if (error) g_error_free(error); return FALSE; }
    const char *paths[]={APP_PATH,SERVICE_PATH,STATUS_PATH,P2P_PATH};
    const char *interfaces[]={"org.freedesktop.DBus.ObjectManager","org.bluez.GattService1","org.bluez.GattCharacteristic1","org.bluez.GattCharacteristic1"};
    for (unsigned i=0;i<4;i++) {
        h->registrations[i]=g_dbus_connection_register_object(h->bus,paths[i],g_dbus_node_info_lookup_interface(h->introspection,interfaces[i]),&vtable,h,NULL,&error);
        if (!h->registrations[i]) { if (error) g_error_free(error); return FALSE; }
    }
    return TRUE;
}
static int capabilities(struct helper *h) {
    struct mta_advertising_features f; uint8_t info[280]; size_t length=0;
    gboolean powered=adapter_powered(h),known=FALSE;
    gboolean active=bluez_has_advertisements(h,&known);
    gboolean info_ok=mgmt_command(h,MGMT_READ_INFO,NULL,0,info,sizeof(info),&length)==0 && length>=17;
    gboolean feature_ok=features(h,&f);
    GString *line=g_string_new(NULL);
    g_string_append_printf(line,"{\"event\":\"capabilities\",\"powered\":%s,\"mgmt_info\":%s,\"features\":%s,\"bluez_advertising_known\":%s,\"bluez_advertising_active\":%s",
           powered?"true":"false",info_ok?"true":"false",feature_ok?"true":"false",known?"true":"false",active?"true":"false");
    uint32_t current=info_ok?read32(info+13):0;
    g_string_append_printf(line,",\"bredr_enabled\":%s,\"le_enabled\":%s,\"global_advertising\":%s",
                          info_ok?((current&(1u<<7))?"true":"false"):"null",
                          info_ok?((current&(1u<<9))?"true":"false"):"null",
                          info_ok?((current&(1u<<10))?"true":"false"):"null");
    if (feature_ok) g_string_append_printf(line,",\"connectable_advert\":%s,\"max_adv\":%u,\"max_scan\":%u,\"max_instances\":%u,\"active_instances\":%u",(f.flags&1)?"true":"false",f.adv_max,f.scan_max,f.max_instances,f.count);
    g_string_append(line,"}\n"); (void)emit_line(line->str); g_string_free(line,TRUE);
    return info_ok && feature_ok && !output_failed?0:2;
}
int main(int argc,char **argv) {
    struct helper h; memset(&h,0,sizeof(h)); h.mgmt_fd=-1; h.lock_fd=-1;
    if (argc!=3 || (strcmp(argv[1],"--serve") && strcmp(argv[1],"--capabilities"))) {
        fputs("usage: mta-bluez-helper --capabilities hci0 | --serve hci0\n",stderr); return 64;
    }
    /* Serve is a PRIVATE PIPE, not an interactive shell or logging stream. */
    struct stat input_stat,output_stat;
    if (!strcmp(argv[1],"--serve") &&
        (fstat(STDIN_FILENO,&input_stat)<0 || fstat(STDOUT_FILENO,&output_stat)<0 ||
         !S_ISFIFO(input_stat.st_mode) || !S_ISFIFO(output_stat.st_mode))) {
        result("error","private_pipe_required"); return 64;
    }
    signal(SIGPIPE,SIG_IGN); umask(0077);
    struct rlimit core_limit={0,0};
    if (setrlimit(RLIMIT_CORE,&core_limit)<0 || prctl(PR_SET_DUMPABLE,0,0,0,0)<0) {
        result("error","private_memory_protection_failed"); return 64;
    }
    active_helper=&h;
    if (!strcmp(argv[1],"--serve")) {
        int flags=fcntl(STDOUT_FILENO,F_GETFL,0);
        if (flags<0 || fcntl(STDOUT_FILENO,F_SETFL,flags|O_NONBLOCK)<0) { result("error","nonblocking_private_pipe_required"); return 64; }
    }
    int exit_code=1;
    if (!initialize(&h,argv[2])) goto cleanup;
    if (!strcmp(argv[1],"--capabilities")) { exit_code=capabilities(&h); goto cleanup; }
    if (!export_objects(&h)) { result("error","gatt_export_failed"); goto cleanup; }
    h.loop=g_main_loop_new(NULL,FALSE); h.input=g_string_sized_new(1024);
    h.stdin_channel=g_io_channel_unix_new(STDIN_FILENO);
    g_io_channel_set_encoding(h.stdin_channel,NULL,NULL); g_io_channel_set_buffered(h.stdin_channel,FALSE);
    g_io_channel_set_flags(h.stdin_channel,g_io_channel_get_flags(h.stdin_channel)|G_IO_FLAG_NONBLOCK,NULL);
    g_io_add_watch(h.stdin_channel,G_IO_IN|G_IO_HUP|G_IO_ERR|G_IO_NVAL,stdin_ready,&h);
    g_unix_fd_add(h.mgmt_fd,G_IO_IN|G_IO_HUP|G_IO_ERR|G_IO_NVAL,mgmt_ready,&h);
    g_unix_signal_add(SIGTERM,signal_stop,&h); g_unix_signal_add(SIGINT,signal_stop,&h);
    g_timeout_add_seconds(1,tick,&h);
    h.owner_subscription=g_dbus_connection_signal_subscribe(h.bus,"org.freedesktop.DBus","org.freedesktop.DBus","NameOwnerChanged","/org/freedesktop/DBus","org.bluez",G_DBUS_SIGNAL_FLAGS_NONE,owner_changed,&h,NULL);
    h.properties_subscription=g_dbus_connection_signal_subscribe(h.bus,h.bluez_owner,"org.freedesktop.DBus.Properties","PropertiesChanged",NULL,NULL,G_DBUS_SIGNAL_FLAGS_NONE,device_changed,&h,NULL);
    h.added_subscription=g_dbus_connection_signal_subscribe(h.bus,h.bluez_owner,"org.freedesktop.DBus.ObjectManager","InterfacesAdded",NULL,NULL,G_DBUS_SIGNAL_FLAGS_NONE,interfaces_added,&h,NULL);
    result("helper","ready_no_radio_change");
    if (!output_failed) g_main_loop_run(h.loop);
    exit_code=output_failed?2:0;
cleanup:
    if (h.bus) stop_resources(&h);
    /* Service/scan/Connect requests can succeed after stdin closes. Give their
     * bounded callbacks time to unregister/disconnect before dropping the
     * dedicated unique bus owner. A pending Device1 Connect is also cancelled
     * by the scoped Disconnect request above; no global radio reset is used. */
    if (h.loop) {
        gint64 cleanup_deadline=g_get_monotonic_time()+12000000;
        while ((h.registering || h.scan_pending || h.client_pending) && g_get_monotonic_time()<cleanup_deadline) {
            while (g_main_context_iteration(NULL,FALSE)) {}
            g_usleep(10000);
        }
        if (h.registering || h.scan_pending || h.client_pending) result("cleanup","async_completion_timeout_owner_exit");
        stop_resources(&h);
    }
    if (h.bus) {
        for (unsigned i=0;i<4;i++) if (h.registrations[i]) g_dbus_connection_unregister_object(h.bus,h.registrations[i]);
        if (h.owner_subscription) g_dbus_connection_signal_unsubscribe(h.bus,h.owner_subscription);
        if (h.properties_subscription) g_dbus_connection_signal_unsubscribe(h.bus,h.properties_subscription);
        if (h.added_subscription) g_dbus_connection_signal_unsubscribe(h.bus,h.added_subscription);
        /* Dedicated unique owner; closing releases even an unacknowledged
         * RegisterApplication, rather than leaving a shared cached bus live. */
        g_dbus_connection_close_sync(h.bus,NULL,NULL);
        g_object_unref(h.bus);
    }
    if (h.mgmt_fd>=0) close(h.mgmt_fd);
    if (h.stdin_channel) g_io_channel_unref(h.stdin_channel);
    if (h.loop) g_main_loop_unref(h.loop);
    if (h.introspection) g_dbus_node_info_unref(h.introspection);
    if (h.input) { mta_wipe(h.input->str,h.input->len); g_string_free(h.input,TRUE); }
    g_free(h.bluez_owner); clear_peer(&h); mta_wipe(&h,sizeof(h)); return exit_code;
}
