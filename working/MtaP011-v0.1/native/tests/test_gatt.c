/* Private mock bus tests. No system bus, Bluetooth controller or MGMT socket. */
#define main mta_helper_program_main
#include "../mta_bluez_helper.c"
#undef main

struct mock_bluez {
    const char *address;
    GMutex mutex;
    GCond condition;
    GDBusConnection *connection;
    GMainLoop *loop;
    GMainContext *context;
    gboolean ready,connected;
    gint starts,stops,connects,disconnects,writes;
};
static const char *peer_path="/org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF";
#define MOCK_SERVICE "/org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF/service1"
#define MOCK_STATUS MOCK_SERVICE "/char1"
#define MOCK_P2P MOCK_SERVICE "/char2"
static GVariant *mock_device_properties(void) {
    const char *uuids[]={MTA_ADV_UUID,NULL};
    GVariantBuilder properties,service_data;
    g_variant_builder_init(&properties,G_VARIANT_TYPE("a{sv}"));
    g_variant_builder_add(&properties,"{sv}","UUIDs",g_variant_new_strv(uuids,-1));
    g_variant_builder_add(&properties,"{sv}","Name",g_variant_new_string("mock phone"));
    g_variant_builder_init(&service_data,G_VARIANT_TYPE("a{sv}"));
    const guchar name_data[]={0,0,1,2};
    g_variant_builder_add(&service_data,"{sv}","0000ffff-0000-1000-8000-00805f9b34fb",g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE,name_data,sizeof(name_data),1));
    g_variant_builder_add(&properties,"{sv}","ServiceData",g_variant_builder_end(&service_data));
    return g_variant_builder_end(&properties);
}
static GVariant *mock_property(GDBusConnection *connection,const char *sender,const char *path,
                               const char *interface,const char *property,GError **error,gpointer data) {
    struct mock_bluez *mock=data;
    (void)connection; (void)sender; (void)path; (void)interface; (void)error;
    if (!strcmp(property,"Connected")) return g_variant_new_boolean(g_atomic_int_get(&mock->connected));
    if (!strcmp(property,"ServicesResolved") || !strcmp(property,"Powered")) return g_variant_new_boolean(TRUE);
    return NULL;
}
static void mock_method(GDBusConnection *connection,const char *sender,const char *path,
                        const char *interface,const char *method,GVariant *parameters,
                        GDBusMethodInvocation *invocation,gpointer data) {
    struct mock_bluez *mock=data;
    (void)connection; (void)sender; (void)interface;
    if (!strcmp(method,"GetManagedObjects")) {
        GVariantBuilder objects,p;
        g_variant_builder_init(&objects,G_VARIANT_TYPE("a{oa{sa{sv}}}"));
        object_add(&objects,peer_path,"org.bluez.Device1",mock_device_properties());
        g_variant_builder_init(&p,G_VARIANT_TYPE("a{sv}"));
        g_variant_builder_add(&p,"{sv}","UUID",g_variant_new_string(SERVICE_UUID));
        object_add(&objects,MOCK_SERVICE,"org.bluez.GattService1",g_variant_builder_end(&p));
        g_variant_builder_init(&p,G_VARIANT_TYPE("a{sv}"));
        g_variant_builder_add(&p,"{sv}","UUID",g_variant_new_string(STATUS_UUID));
        g_variant_builder_add(&p,"{sv}","Service",g_variant_new_object_path(MOCK_SERVICE));
        object_add(&objects,MOCK_STATUS,"org.bluez.GattCharacteristic1",g_variant_builder_end(&p));
        g_variant_builder_init(&p,G_VARIANT_TYPE("a{sv}"));
        g_variant_builder_add(&p,"{sv}","UUID",g_variant_new_string(P2P_UUID));
        g_variant_builder_add(&p,"{sv}","Service",g_variant_new_object_path(MOCK_SERVICE));
        object_add(&objects,MOCK_P2P,"org.bluez.GattCharacteristic1",g_variant_builder_end(&p));
        g_dbus_method_invocation_return_value(invocation,g_variant_new("(@a{oa{sa{sv}}})",g_variant_builder_end(&objects))); return;
    }
    if (!strcmp(method,"ReadValue") && !strcmp(path,MOCK_STATUS)) {
        g_dbus_method_invocation_return_value(invocation,g_variant_new("(@ay)",g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE,"{}",2,1))); return;
    }
    if (!strcmp(method,"WriteValue") && !strcmp(path,MOCK_P2P)) {
        GVariant *bytes=g_variant_get_child_value(parameters,0); gsize size; const guchar *value=g_variant_get_fixed_array(bytes,&size,1);
        g_assert_cmpuint(size,==,2); g_assert_cmpmem(value,size,"{}",2); g_variant_unref(bytes); g_atomic_int_inc(&mock->writes);
    } else if (!strcmp(method,"StartDiscovery")) g_atomic_int_inc(&mock->starts);
    else if (!strcmp(method,"StopDiscovery")) g_atomic_int_inc(&mock->stops);
    else if (!strcmp(method,"SetDiscoveryFilter")) {
        GVariant *filter=g_variant_get_child_value(parameters,0); const char *transport;
        if (g_variant_n_children(filter)) { g_assert_true(g_variant_lookup(filter,"Transport","&s",&transport)); g_assert_cmpstr(transport,==,"le"); }
        g_variant_unref(filter);
    } else if (!strcmp(method,"Connect")) { g_atomic_int_inc(&mock->connects); g_usleep(100000); }
    else if (!strcmp(method,"Disconnect")) g_atomic_int_inc(&mock->disconnects);
    else { dbus_error(invocation,"org.bluez.Error.NotSupported"); return; }
    g_dbus_method_invocation_return_value(invocation,NULL);
}
static const GDBusInterfaceVTable mock_vtable={mock_method,mock_property,NULL,{0}};
static gpointer mock_thread(gpointer data) {
    struct mock_bluez *mock=data; GError *error=NULL;
    mock->context=g_main_context_new(); g_main_context_push_thread_default(mock->context);
    mock->loop=g_main_loop_new(mock->context,FALSE);
    mock->connection=g_dbus_connection_new_for_address_sync(mock->address,
        G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT|G_DBUS_CONNECTION_FLAGS_MESSAGE_BUS_CONNECTION,
        NULL,NULL,&error);
    g_assert_no_error(error); g_assert_nonnull(mock->connection);
    GDBusNodeInfo *node=g_dbus_node_info_new_for_xml(
        "<node><interface name='org.bluez.Device1'><method name='Connect'/><method name='Disconnect'/><property name='Connected' type='b' access='read'/><property name='ServicesResolved' type='b' access='read'/></interface>"
        "<interface name='org.bluez.Adapter1'><method name='SetDiscoveryFilter'><arg type='a{sv}' direction='in'/></method><method name='StartDiscovery'/><method name='StopDiscovery'/><property name='Powered' type='b' access='read'/></interface>"
        "<interface name='org.freedesktop.DBus.ObjectManager'><method name='GetManagedObjects'><arg type='a{oa{sa{sv}}}' direction='out'/></method></interface>"
        "<interface name='org.bluez.GattCharacteristic1'><method name='ReadValue'><arg type='a{sv}' direction='in'/><arg type='ay' direction='out'/></method><method name='WriteValue'><arg type='ay' direction='in'/><arg type='a{sv}' direction='in'/></method></interface>"
        "</node>",&error);
    g_assert_no_error(error);
    const char *paths[]={peer_path,"/org/bluez/hci0","/",MOCK_STATUS,MOCK_P2P};
    guint registrations[5];
    for (unsigned i=0;i<5;i++) {
        registrations[i]=g_dbus_connection_register_object(mock->connection,paths[i],node->interfaces[i<3?i:3],&mock_vtable,mock,NULL,&error);
        g_assert_no_error(error); g_assert_cmpuint(registrations[i],>,0);
    }
    g_mutex_lock(&mock->mutex); mock->ready=TRUE; g_cond_signal(&mock->condition); g_mutex_unlock(&mock->mutex);
    g_main_loop_run(mock->loop);
    for (unsigned i=0;i<5;i++) g_dbus_connection_unregister_object(mock->connection,registrations[i]);
    g_dbus_node_info_unref(node);
    g_dbus_connection_close_sync(mock->connection,NULL,NULL); g_object_unref(mock->connection);
    g_main_loop_unref(mock->loop); g_main_context_pop_thread_default(mock->context); g_main_context_unref(mock->context);
    return NULL;
}
struct async_call { gboolean done; GVariant *reply; GError *error; };
static void call_done(GObject *object,GAsyncResult *result,gpointer data) {
    struct async_call *call=data;
    call->reply=g_dbus_connection_call_finish(G_DBUS_CONNECTION(object),result,&call->error); call->done=TRUE;
}
static GVariant *invoke(struct helper *h,GDBusConnection *client,const char *path,const char *interface,
                        const char *method,GVariant *parameters,gboolean success) {
    struct async_call operation={FALSE,NULL,NULL};
    g_dbus_connection_call(client,g_dbus_connection_get_unique_name(h->bus),path,interface,method,parameters,
                          NULL,G_DBUS_CALL_FLAGS_NONE,3000,NULL,call_done,&operation);
    while (!operation.done) g_main_context_iteration(NULL,TRUE);
    if (success) { g_assert_no_error(operation.error); g_assert_nonnull(operation.reply); }
    else { g_assert_nonnull(operation.error); g_assert_null(operation.reply); g_error_free(operation.error); }
    return operation.reply;
}
static GVariant *options(unsigned offset,gboolean prepare,gboolean include_device) {
    GVariantBuilder b; g_variant_builder_init(&b,G_VARIANT_TYPE("a{sv}"));
    g_variant_builder_add(&b,"{sv}","offset",g_variant_new_uint16((guint16)offset));
    if (include_device) g_variant_builder_add(&b,"{sv}","device",g_variant_new_object_path(peer_path));
    if (prepare) g_variant_builder_add(&b,"{sv}","prepare-authorize",g_variant_new_boolean(TRUE));
    return g_variant_builder_end(&b);
}
static GVariant *write_parameters(const char *text,unsigned offset,gboolean prepare,gboolean include_device) {
    return g_variant_new("(@ay@a{sv})",g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE,text,strlen(text),1),options(offset,prepare,include_device));
}
int main(int argc,char **argv) {
    g_test_init(&argc,&argv,NULL);
    GTestDBus *private_bus=g_test_dbus_new(G_TEST_DBUS_NONE); g_test_dbus_up(private_bus);
    struct mock_bluez mock={0}; mock.address=g_test_dbus_get_bus_address(private_bus); mock.connected=TRUE;
    g_mutex_init(&mock.mutex); g_cond_init(&mock.condition);
    GThread *thread=g_thread_new("mock-bluez",mock_thread,&mock);
    g_mutex_lock(&mock.mutex); while (!mock.ready) g_cond_wait(&mock.condition,&mock.mutex); g_mutex_unlock(&mock.mutex);
    struct helper h; memset(&h,0,sizeof(h)); h.mgmt_fd=-1; h.lock_fd=-1;
    GError *error=NULL;
    h.bus=g_dbus_connection_new_for_address_sync(mock.address,
        G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT|G_DBUS_CONNECTION_FLAGS_MESSAGE_BUS_CONNECTION,NULL,NULL,&error);
    g_assert_no_error(error); h.bluez_owner=g_strdup(g_dbus_connection_get_unique_name(mock.connection));
    strcpy(h.adapter,"hci0"); strcpy(h.adapter_path,"/org/bluez/hci0"); h.registered=TRUE;
    memcpy(h.status,"{}",2); h.status_len=2; g_assert_true(export_objects(&h));
    GVariant *reply=invoke(&h,mock.connection,APP_PATH,"org.freedesktop.DBus.ObjectManager","GetManagedObjects",NULL,TRUE);
    GVariant *objects=g_variant_get_child_value(reply,0);
    g_assert_cmpuint(g_variant_n_children(objects),==,3); g_variant_unref(objects); g_variant_unref(reply);
    reply=invoke(&h,mock.connection,STATUS_PATH,"org.bluez.GattCharacteristic1","ReadValue",g_variant_new("(@a{sv})",options(1,FALSE,TRUE)),TRUE);
    GVariant *bytes=g_variant_get_child_value(reply,0); gsize size=0; const char *value=g_variant_get_fixed_array(bytes,&size,1);
    g_assert_cmpuint(size,==,1); g_assert_cmpint(value[0],==,'}'); g_variant_unref(bytes); g_variant_unref(reply);
    invoke(&h,mock.connection,STATUS_PATH,"org.bluez.GattCharacteristic1","ReadValue",g_variant_new("(@a{sv})",options(3,FALSE,TRUE)),FALSE);
    invoke(&h,mock.connection,STATUS_PATH,"org.bluez.GattCharacteristic1","ReadValue",g_variant_new("(@a{sv})",options(0,FALSE,FALSE)),FALSE);
    invoke(&h,mock.connection,P2P_PATH,"org.bluez.GattCharacteristic1","WriteValue",write_parameters("{}",0,TRUE,TRUE),FALSE);
    reply=invoke(&h,mock.connection,P2P_PATH,"org.bluez.GattCharacteristic1","WriteValue",write_parameters("{\"x\":",0,FALSE,TRUE),TRUE); g_variant_unref(reply);
    g_assert_cmpuint(h.p2p.length,==,5);
    reply=invoke(&h,mock.connection,P2P_PATH,"org.bluez.GattCharacteristic1","WriteValue",write_parameters("1}",5,FALSE,TRUE),TRUE); g_variant_unref(reply);
    g_assert_cmpuint(h.p2p.length,==,0);
    invoke(&h,mock.connection,P2P_PATH,"org.bluez.GattCharacteristic1","WriteValue",write_parameters("x",999,FALSE,TRUE),FALSE);
    GDBusConnection *stranger=g_dbus_connection_new_for_address_sync(mock.address,
        G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT|G_DBUS_CONNECTION_FLAGS_MESSAGE_BUS_CONNECTION,NULL,NULL,&error);
    g_assert_no_error(error);
    invoke(&h,stranger,APP_PATH,"org.freedesktop.DBus.ObjectManager","GetManagedObjects",NULL,FALSE);
    g_dbus_connection_close_sync(stranger,NULL,NULL); g_object_unref(stranger);
    clear_peer(&h); h.peer_deadline=g_get_monotonic_time()-1; tick(&h); g_assert_cmpint(h.peer_deadline,==,0);
    struct mta_command command; memset(&command,0,sizeof(command)); strcpy(command.adapter,"hci0"); command.ttl=20;
    scan_command(&h,&command);
    while (h.scan_pending || h.peer_count==0) g_main_context_iteration(NULL,TRUE);
    g_assert_cmpint(g_atomic_int_get(&mock.starts),==,1); g_assert_cmpuint(h.peer_count,==,1);
    g_assert_cmpstr(h.peers[0].path,==,peer_path);
    stop_discovery(&h); g_assert_cmpint(g_atomic_int_get(&mock.stops),==,1);
    /* Pre-existing connection is reused but not owned/disconnected. */
    command.peer=1; client_read_command(&h,&command);
    while (h.client_pending) g_main_context_iteration(NULL,TRUE);
    g_assert_nonnull(h.client_status_path); g_assert_nonnull(h.client_p2p_path);
    g_assert_false(h.client_connect_owned);
    memcpy(command.payload,"{}",2); command.payload_len=2; client_write_command(&h,&command);
    while (h.client_pending) g_main_context_iteration(NULL,TRUE);
    g_assert_cmpint(g_atomic_int_get(&mock.writes),==,1);
    stop_client(&h); g_assert_cmpint(g_atomic_int_get(&mock.disconnects),==,0);
    /* Late Connect response after Stop and discovery-table release must still
     * release only the connection this helper attempted to establish. */
    g_atomic_int_set(&mock.connected,FALSE); client_read_command(&h,&command);
    g_assert_true(h.client_connecting); stop_client(&h); clear_discovered(&h);
    while (h.client_pending) g_main_context_iteration(NULL,TRUE);
    g_assert_cmpuint(h.client_id,==,0); g_assert_null(h.client_peer_path);
    g_assert_false(h.client_connecting); g_assert_cmpint(g_atomic_int_get(&mock.connects),==,1);
    g_assert_cmpint(g_atomic_int_get(&mock.disconnects),>=,1);
    clear_discovered(&h);
    for (unsigned i=0;i<4;i++) g_dbus_connection_unregister_object(h.bus,h.registrations[i]);
    g_dbus_connection_close_sync(h.bus,NULL,NULL); g_object_unref(h.bus); g_free(h.bluez_owner); g_dbus_node_info_unref(h.introspection);
    g_main_loop_quit(mock.loop); g_thread_join(thread); g_mutex_clear(&mock.mutex); g_cond_clear(&mock.condition);
    g_test_dbus_down(private_bus); g_object_unref(private_bus);
    int pipefd[2],saved_stdout=dup(STDOUT_FILENO); g_assert_cmpint(pipe(pipefd),==,0);
    g_assert_cmpint(fcntl(pipefd[1],F_SETFL,O_NONBLOCK),==,0);
    char filler[4096]; memset(filler,'x',sizeof(filler));
    while (write(pipefd[1],filler,sizeof(filler))>0) {}
    g_assert_cmpint(dup2(pipefd[1],STDOUT_FILENO),>=,0);
    gint64 start=g_get_monotonic_time();
    g_assert_false(emit_line("{\"event\":\"synthetic\"}\n"));
    g_assert_true(output_failed); g_assert_cmpint(g_get_monotonic_time()-start,<,1000000);
    g_assert_cmpint(dup2(saved_stdout,STDOUT_FILENO),>=,0);
    close(saved_stdout); close(pipefd[0]); close(pipefd[1]); output_failed=FALSE;
    puts("PASS private DBus mock: GATT objects/read/write/offset/owner/peer gates; bounded BLE scan; MTA client read/write; preserve existing connection; late Connect cancellation");
    return 0;
}
