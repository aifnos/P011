/* HOST ONLY: isolated GTestDBus ConnMan fixture. Never calls the real system
 * bus, opens radio hardware or handles device/user credentials. */
#define _POSIX_C_SOURCE 200809L
#include <gio/gio.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <glib/gstdio.h>
#include <signal.h>

#define OLD "/net/connman/service/wifi_host_old_managed_psk"
#define TARGET "/net/connman/service/wifi_host_new_managed_psk"
#define PROFILE_ROOT "/tmp/p011-mta-mock-profiles"
#define TARGET_DIRECTORY PROFILE_ROOT "/wifi_host_new_managed_psk"
#define TARGET_SETTINGS TARGET_DIRECTORY "/settings"
typedef struct {
    GMainLoop *loop; GDBusConnection *bus; GPid child; int input;
    GIOChannel *output; char *agent_sender; gboolean powered, visible, favorite;
    gboolean old_connected, target_connected, target_baseline, probe;
    gboolean saw_connected, saw_restored, saw_capability, saw_error, timed_out;
    unsigned writes, scans, credential_requests, removes; int exit_status;
    char *journal_dir, *helper; guint watch; int output_fd; unsigned scenario, stage;
    gboolean prepared_readonly, saw_prepared, recovery_started;
} Fixture;
static const char receive_command[] = "{\"cmd\":\"receive\",\"consented\":true,\"ssid_b64\":\"SE9TVA==\",\"psk_b64\":\"MTIzNDU2Nzg=\",\"timeout\":10,\"ttl\":30}\n";
static gboolean spawn_child(Fixture *f, gboolean recovery);
static GVariant *network_props(gboolean target, Fixture *f) {
    GVariantBuilder props, ip;
    const char *security[] = {"psk", NULL};
    g_variant_builder_init(&props, G_VARIANT_TYPE("a{sv}")); g_variant_builder_init(&ip, G_VARIANT_TYPE("a{sv}"));
    g_variant_builder_add(&props, "{sv}", "Type", g_variant_new_string("wifi"));
    g_variant_builder_add(&props, "{sv}", "Name", g_variant_new_string(target ? "HOST" : "HOST-old"));
    g_variant_builder_add(&props, "{sv}", "State", g_variant_new_string((target ? f->target_connected : f->old_connected) ? "ready" : "idle"));
    g_variant_builder_add(&props, "{sv}", "Favorite", g_variant_new_boolean(target ? f->favorite : TRUE));
    g_variant_builder_add(&props, "{sv}", "Immutable", g_variant_new_boolean(FALSE));
    g_variant_builder_add(&props, "{sv}", "Security", g_variant_new_strv(security, -1));
    g_variant_builder_add(&ip, "{sv}", "Address", g_variant_new_string(target ? "192.168.49.2" : "192.168.1.2"));
    g_variant_builder_add(&ip, "{sv}", "Gateway", g_variant_new_string(target ? "192.168.49.1" : "192.168.1.1"));
    g_variant_builder_add(&props, "{sv}", "IPv4", g_variant_builder_end(&ip));
    return g_variant_builder_end(&props);
}
typedef struct { Fixture *fixture; GDBusMethodInvocation *invocation; } InputRequest;
static void credentials_done(GObject *source, GAsyncResult *result, gpointer userdata) {
    InputRequest *request = userdata; Fixture *f = request->fixture; GError *error = NULL;
    GVariant *reply = g_dbus_connection_call_finish(G_DBUS_CONNECTION(source), result, &error), *values = NULL;
    const char *password = NULL;
    if (reply) { values = g_variant_get_child_value(reply, 0); g_variant_lookup(values, "Passphrase", "&s", &password); }
    if (error || !password || strcmp(password, "12345678")) {
        g_dbus_method_invocation_return_dbus_error(request->invocation, "net.connman.Error.Failed", "HOST fixture input validation failed");
    } else {
        f->credential_requests++; f->target_connected = TRUE; f->old_connected = FALSE; f->favorite = TRUE;
        if (g_mkdir(TARGET_DIRECTORY, 0700) || !g_file_set_contents(TARGET_SETTINGS, "HOST-private-fixture-profile\n", -1, NULL) || g_chmod(TARGET_SETTINGS, 0600)) f->timed_out = TRUE;
        g_dbus_method_invocation_return_value(request->invocation, NULL);
    }
    if (values) g_variant_unref(values);
    if (reply) g_variant_unref(reply);
    if (error) g_error_free(error);
    g_object_unref(request->invocation); g_free(request);
}
static void method(GDBusConnection *bus, const char *sender, const char *path, const char *interface, const char *name, GVariant *params, GDBusMethodInvocation *invocation, gpointer userdata) {
    Fixture *f = userdata;
    if (!strcmp(interface, "net.connman.Manager")) {
        if (!strcmp(name, "GetTechnologies")) {
            GVariantBuilder rows, props; g_variant_builder_init(&rows, G_VARIANT_TYPE("a(oa{sv})")); g_variant_builder_init(&props, G_VARIANT_TYPE("a{sv}"));
            g_variant_builder_add(&props, "{sv}", "Type", g_variant_new_string("wifi"));
            g_variant_builder_add(&props, "{sv}", "Powered", g_variant_new_boolean(f->powered));
            g_variant_builder_add(&rows, "(o@a{sv})", "/net/connman/technology/wifi", g_variant_builder_end(&props));
            g_dbus_method_invocation_return_value(invocation, g_variant_new("(a(oa{sv}))", &rows)); return;
        }
        if (!strcmp(name, "GetServices")) {
            GVariantBuilder rows; g_variant_builder_init(&rows, G_VARIANT_TYPE("a(oa{sv})"));
            g_variant_builder_add(&rows, "(o@a{sv})", OLD, network_props(FALSE, f));
            if (f->visible) g_variant_builder_add(&rows, "(o@a{sv})", TARGET, network_props(TRUE, f));
            g_dbus_method_invocation_return_value(invocation, g_variant_new("(a(oa{sv}))", &rows)); return;
        }
        if (!strcmp(name, "RegisterAgent")) { f->writes++; g_free(f->agent_sender); f->agent_sender = g_strdup(sender); }
        else if (!strcmp(name, "UnregisterAgent")) f->writes++;
        else { g_dbus_method_invocation_return_dbus_error(invocation, "net.connman.Error.NotSupported", "HOST fixture method not permitted"); return; }
    } else if (!strcmp(interface, "net.connman.Technology")) {
        if (!strcmp(name, "Scan")) { f->scans++; f->visible = TRUE; }
        else { g_dbus_method_invocation_return_dbus_error(invocation, "net.connman.Error.NotSupported", "HOST fixture forbids technology writes"); return; }
    } else if (!strcmp(interface, "net.connman.Service")) {
        f->writes++;
        if (!strcmp(name, "Connect") && !strcmp(path, TARGET)) {
            GVariantBuilder fields, details; InputRequest *request = g_new0(InputRequest, 1);
            request->fixture = f; request->invocation = g_object_ref(invocation);
            g_variant_builder_init(&fields, G_VARIANT_TYPE("a{sv}")); g_variant_builder_init(&details, G_VARIANT_TYPE("a{sv}"));
            g_variant_builder_add(&details, "{sv}", "Type", g_variant_new_string("psk"));
            g_variant_builder_add(&details, "{sv}", "Requirement", g_variant_new_string("mandatory"));
            g_variant_builder_add(&fields, "{sv}", "Passphrase", g_variant_builder_end(&details));
            g_dbus_connection_call(bus, f->agent_sender, "/org/p011/Mta/NetworkAgent", "net.connman.Agent", "RequestInput", g_variant_new("(oa{sv})", TARGET, &fields), G_VARIANT_TYPE("(a{sv})"), G_DBUS_CALL_FLAGS_NO_AUTO_START, 5000, NULL, credentials_done, request); return;
        }
        if (!strcmp(name, "Connect") && !strcmp(path, OLD)) f->old_connected = TRUE;
        else if (!strcmp(name, "Disconnect") && !strcmp(path, TARGET)) f->target_connected = FALSE;
        else if (!strcmp(name, "Remove") && !strcmp(path, TARGET) && !f->target_baseline) { f->removes++; f->visible = FALSE; f->favorite = FALSE; if (g_unlink(TARGET_SETTINGS) || g_rmdir(TARGET_DIRECTORY)) f->timed_out = TRUE; }
        else if (!strcmp(name, "SetProperty") && !strcmp(path, TARGET)) {
            const char *property; GVariant *value; gboolean valid;
            g_variant_get(params, "(&sv)", &property, &value); valid = !strcmp(property, "AutoConnect") && g_variant_is_of_type(value, G_VARIANT_TYPE_BOOLEAN) && !g_variant_get_boolean(value); g_variant_unref(value);
            if (!valid) { g_dbus_method_invocation_return_dbus_error(invocation, "net.connman.Error.InvalidArguments", "HOST fixture forbids profile writes"); return; }
        } else { g_dbus_method_invocation_return_dbus_error(invocation, "net.connman.Error.NotSupported", "HOST fixture forbids old profile mutation"); return; }
    }
    g_dbus_method_invocation_return_value(invocation, NULL);
}
static const GDBusInterfaceVTable vtable = {method, NULL, NULL, {NULL}};
static const char xml[] = "<node>"
    "<interface name='net.connman.Manager'><method name='GetServices'><arg type='a(oa{sv})' direction='out'/></method><method name='GetTechnologies'><arg type='a(oa{sv})' direction='out'/></method><method name='RegisterAgent'><arg type='o' direction='in'/></method><method name='UnregisterAgent'><arg type='o' direction='in'/></method></interface>"
    "<interface name='net.connman.Technology'><method name='Scan'/></interface>"
    "<interface name='net.connman.Service'><method name='Connect'/><method name='Disconnect'/><method name='Remove'/><method name='SetProperty'><arg type='s' direction='in'/><arg type='v' direction='in'/></method></interface>"
    "</node>";
static gboolean output_ready(GIOChannel *channel, GIOCondition condition, gpointer userdata) {
    Fixture *f = userdata; char *line = NULL; gsize length = 0; GIOStatus status;
    if (condition & G_IO_IN) {
        status = g_io_channel_read_line(channel, &line, &length, NULL, NULL);
        while (status == G_IO_STATUS_NORMAL && line) {
            if (strstr(line, "12345678") || strstr(line, "MTIzNDU2Nzg")) f->timed_out = TRUE;
            if (strstr(line, "\"event\":\"prepared\"")) {
                f->saw_prepared = TRUE; f->prepared_readonly = !f->writes && !f->scans && !f->credential_requests;
                /* A phone AP can enter ConnMan's cache through stock activity
                 * after prepare, without our helper ever scanning early. */
                f->visible = TRUE;
                if (f->scenario == 1) {
                    const char *restore = "{\"cmd\":\"restore\"}\n"; if (write(f->input, restore, strlen(restore)) != (ssize_t)strlen(restore)) f->timed_out = TRUE;
                } else if (f->scenario == 5) kill(f->child, SIGKILL);
                else if (write(f->input, receive_command, strlen(receive_command)) != (ssize_t)strlen(receive_command)) f->timed_out = TRUE;
            }
            if (strstr(line, "\"event\":\"connected\"")) {
                const char *restore = "{\"cmd\":\"restore\"}\n";
                f->saw_connected = TRUE;
                if (f->scenario == 2 || f->scenario == 3 || (f->scenario >= 6 && f->scenario <= 9)) {
                    if (f->scenario == 3 && !g_file_set_contents(TARGET_SETTINGS, "HOST-other-actor-modified-profile\n", -1, NULL)) f->timed_out = TRUE;
                    kill(f->child, SIGKILL); /* HOST crash fixture only. */
                } else if (write(f->input, restore, strlen(restore)) != (ssize_t)strlen(restore)) f->timed_out = TRUE;
            }
            if (strstr(line, "\"event\":\"restored\"")) f->saw_restored = TRUE;
            if (strstr(line, "\"event\":\"capabilities\"")) f->saw_capability = TRUE;
            if (strstr(line, "\"event\":\"error\"")) f->saw_error = TRUE;
            g_free(line); line = NULL;
            status = g_io_channel_read_line(channel, &line, &length, NULL, NULL);
        }
    }
    return !(condition & (G_IO_HUP | G_IO_ERR | G_IO_NVAL));
}
static void exited(GPid pid, gint status, gpointer userdata) {
    Fixture *f = userdata; f->exit_status = status; g_spawn_close_pid(pid);
    if (!f->stage && (f->scenario == 2 || f->scenario == 3 || (f->scenario >= 5 && f->scenario <= 9))) {
        f->stage = 1;
        if (g_main_context_find_source_by_id(NULL, f->watch)) g_source_remove(f->watch);
        close(f->input); close(f->output_fd); g_io_channel_unref(f->output); f->output = NULL;
        if (spawn_child(f, TRUE)) return;
        f->timed_out = TRUE;
    }
    g_main_loop_quit(f->loop);
}
static gboolean expired(gpointer userdata) { Fixture *f = userdata; f->timed_out = TRUE; g_main_loop_quit(f->loop); return FALSE; }
static gboolean spawn_child(Fixture *f, gboolean recovery) {
    char *args[] = {f->helper, recovery ? "--recover" : f->probe ? "--capabilities" : "--prepare", NULL}, *wire = NULL; GError *error = NULL;
    if (!g_spawn_async_with_pipes(NULL, args, NULL, G_SPAWN_DO_NOT_REAP_CHILD | G_SPAWN_STDERR_TO_DEV_NULL, NULL, NULL, &f->child, &f->input, &f->output_fd, NULL, &error)) { if (error) g_error_free(error); return FALSE; }
    if (recovery) {
        GDir *dir = g_dir_open(f->journal_dir, 0, NULL); const char *name; char *path = NULL, *b64;
        while (dir && (name = g_dir_read_name(dir))) if (g_str_has_suffix(name, ".ini") && g_str_has_prefix(name, "lease-")) { if (path) { g_free(path); path = NULL; break; } path = g_build_filename(f->journal_dir, name, NULL); }
        if (dir) g_dir_close(dir);
        if (!path) return FALSE;
        if (f->scenario >= 6) { GKeyFile *key = g_key_file_new(); char *data; gsize size;
            g_key_file_load_from_file(key, path, G_KEY_FILE_NONE, NULL);
            if (f->scenario == 6) g_key_file_set_string(key, "Lease", "Boot", "HOST-different-boot");
            if (f->scenario == 7) { char *stat_text = NULL, *p; unsigned field;
                g_file_get_contents("/proc/self/stat", &stat_text, NULL, NULL); p = strrchr(stat_text, ')') + 2;
                for (field = 3; field < 22; field++) { while (*p && *p != ' ') p++; while (*p == ' ') p++; }
                g_key_file_set_uint64(key, "Lease", "ActorPID", (guint64)getpid()); g_key_file_set_uint64(key, "Lease", "ActorStart", g_ascii_strtoull(p, NULL, 10)); g_free(stat_text);
            }
            if (f->scenario == 8) g_key_file_set_string(key, "Lease", "ConnmanOwner", ":HOST-other-owner");
            if (f->scenario == 9) g_key_file_set_string(key, "Lease", "TargetProfileHash", "");
            data = g_key_file_to_data(key, &size, NULL); if (!g_file_set_contents(path, data, size, NULL) || g_chmod(path, 0600)) f->timed_out = TRUE;
            g_free(data); g_key_file_unref(key);
        }
        b64 = g_base64_encode((guchar *)path, strlen(path)); wire = g_strdup_printf("{\"cmd\":\"recover\",\"journal_file_b64\":\"%s\"}\n", b64); g_free(path); g_free(b64); f->recovery_started = TRUE;
    } else if (!f->probe) {
        char *b64 = g_base64_encode((guchar *)f->journal_dir, strlen(f->journal_dir)); wire = g_strdup_printf("{\"cmd\":\"prepare\",\"journal_dir_b64\":\"%s\",\"ttl\":30}\n", b64); g_free(b64);
    }
    if (wire) { gboolean ok = write(f->input, wire, strlen(wire)) == (ssize_t)strlen(wire); g_free(wire); if (!ok) return FALSE; }
    f->output = g_io_channel_unix_new(f->output_fd); g_io_channel_set_flags(f->output, G_IO_FLAG_NONBLOCK, NULL);
    f->watch = g_io_add_watch(f->output, G_IO_IN | G_IO_HUP | G_IO_ERR, output_ready, f); g_child_watch_add(f->child, exited, f); return TRUE;
}
static gboolean run_case(const char *helper, gboolean probe, gboolean baseline, gboolean powered, unsigned scenario) {
    GTestDBus *test_bus = g_test_dbus_new(G_TEST_DBUS_NONE); Fixture f; GError *error = NULL; GVariant *reply;
    GDBusNodeInfo *info; guint objects[4], timeout, i; gboolean success;
    memset(&f, 0, sizeof(f)); f.probe = probe; f.target_baseline = baseline; f.visible = baseline; f.powered = powered; f.old_connected = TRUE;
    f.scenario = scenario; f.helper = g_strdup(helper); f.journal_dir = g_dir_make_tmp("p011-mta-journal-XXXXXX", NULL); if (!f.journal_dir || g_chmod(f.journal_dir, 0700)) return FALSE;
    g_test_dbus_up(test_bus); g_setenv("DBUS_SYSTEM_BUS_ADDRESS", g_test_dbus_get_bus_address(test_bus), TRUE);
    f.bus = g_dbus_connection_new_for_address_sync(g_test_dbus_get_bus_address(test_bus), G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT | G_DBUS_CONNECTION_FLAGS_MESSAGE_BUS_CONNECTION, NULL, NULL, &error);
    if (!f.bus) { if (error) g_error_free(error); g_test_dbus_down(test_bus); g_object_unref(test_bus); return FALSE; }
    reply = g_dbus_connection_call_sync(f.bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "RequestName", g_variant_new("(su)", "net.connman", 0), G_VARIANT_TYPE("(u)"), G_DBUS_CALL_FLAGS_NO_AUTO_START, 5000, NULL, NULL);
    if (!reply) return FALSE;
    g_variant_unref(reply);
    info = g_dbus_node_info_new_for_xml(xml, NULL);
    objects[0] = g_dbus_connection_register_object(f.bus, "/", info->interfaces[0], &vtable, &f, NULL, NULL);
    objects[1] = g_dbus_connection_register_object(f.bus, "/net/connman/technology/wifi", info->interfaces[1], &vtable, &f, NULL, NULL);
    objects[2] = g_dbus_connection_register_object(f.bus, OLD, info->interfaces[2], &vtable, &f, NULL, NULL);
    objects[3] = g_dbus_connection_register_object(f.bus, TARGET, info->interfaces[2], &vtable, &f, NULL, NULL);
    f.loop = g_main_loop_new(NULL, FALSE);
    if (!spawn_child(&f, FALSE)) return FALSE;
    timeout = g_timeout_add_seconds(20, expired, &f);
    g_main_loop_run(f.loop); if (!f.timed_out) g_source_remove(timeout);
    /* Final stdout lines may be queued when SIGCHLD arrives. */
    while (g_main_context_iteration(NULL, FALSE)) {}
    success = !f.timed_out && WIFEXITED(f.exit_status);
    if (probe) success = success && WEXITSTATUS(f.exit_status) == 0 && f.saw_capability && !f.writes && !f.scans && !f.credential_requests;
    else if (!powered) success = success && WEXITSTATUS(f.exit_status) != 0 && f.saw_error && !f.writes && !f.scans;
    else if (baseline) success = success && f.old_connected && WEXITSTATUS(f.exit_status) != 0 && f.saw_error && f.saw_restored && !f.saw_connected && !f.credential_requests && !f.removes && f.visible;
    else if (scenario == 1 || scenario == 5) success = success && f.old_connected && WEXITSTATUS(f.exit_status) == 0 && f.saw_prepared && f.prepared_readonly && f.saw_restored && !f.saw_connected && !f.writes && !f.scans && !f.removes;
    else if (scenario == 11) success = success && f.old_connected && f.saw_prepared && f.prepared_readonly && WEXITSTATUS(f.exit_status) != 0 && f.saw_error && f.saw_restored && !f.saw_connected && !f.writes && !f.scans && !f.removes;
    else if (scenario == 3 || (scenario >= 6 && scenario <= 9)) success = success && f.recovery_started && WEXITSTATUS(f.exit_status) != 0 && f.saw_error && f.saw_connected && !f.saw_restored && f.target_connected && !f.removes;
    else success = success && f.old_connected && f.prepared_readonly && WEXITSTATUS(f.exit_status) == 0 && f.saw_connected && f.saw_restored && f.credential_requests == 1 && f.removes == 1 && !f.visible;
    if (g_main_context_find_source_by_id(NULL, f.watch)) g_source_remove(f.watch);
    close(f.input); close(f.output_fd); g_io_channel_unref(f.output);
    { GDir *dir = g_dir_open(f.journal_dir, 0, NULL); const char *name; unsigned journals = 0;
      while (dir && (name = g_dir_read_name(dir))) { char *path = g_build_filename(f.journal_dir, name, NULL), *contents = NULL; struct stat st; journals++;
        if (g_lstat(path, &st) || !S_ISREG(st.st_mode) || (st.st_mode & 0777) != 0600 || !g_file_get_contents(path, &contents, NULL, NULL) || strstr(contents, "12345678") || strstr(contents, "Passphrase")) success = FALSE;
        g_free(contents); g_unlink(path); g_free(path); }
      if (dir) g_dir_close(dir);
      if ((scenario == 3 || (scenario >= 6 && scenario <= 9)) ? journals != 1 : journals != 0) success = FALSE;
    }
    if (g_file_test(TARGET_SETTINGS, G_FILE_TEST_EXISTS)) g_unlink(TARGET_SETTINGS);
    if (g_file_test(TARGET_DIRECTORY, G_FILE_TEST_IS_DIR)) g_rmdir(TARGET_DIRECTORY);
    g_rmdir(f.journal_dir); g_free(f.journal_dir); g_free(f.helper);
    for (i = 0; i < 4; i++) g_dbus_connection_unregister_object(f.bus, objects[i]);
    g_dbus_node_info_unref(info); g_dbus_connection_close_sync(f.bus, NULL, NULL); g_object_unref(f.bus); g_main_loop_unref(f.loop); g_free(f.agent_sender);
    g_test_dbus_down(test_bus); g_object_unref(test_bus); return success;
}
int main(int argc, char **argv) {
    if (argc != 2 && (argc != 3 || strcmp(argv[2], "--production-gate"))) return 2;
    g_setenv("PATH", "/usr/bin:/bin", TRUE);
    if (g_mkdir(PROFILE_ROOT, 0700)) { puts("HOST_NETWORK_DBUS_MOCK_FAIL dedicated-profile-root-already-exists"); return 1; }
    if (argc == 3) {
        if (!run_case(argv[1], FALSE, FALSE, TRUE, 11)) { puts("HOST_NETWORK_DBUS_MOCK_FAIL production-gate-no-wireless-write"); return 1; }
        g_rmdir(PROFILE_ROOT); puts("HOST_NETWORK_PRODUCTION_GATE_PASS device_tested=false"); return 0;
    }
    if (!run_case(argv[1], TRUE, FALSE, TRUE, 0)) { puts("HOST_NETWORK_DBUS_MOCK_FAIL readonly-capabilities"); return 1; }
    if (!run_case(argv[1], FALSE, FALSE, TRUE, 0)) { puts("HOST_NETWORK_DBUS_MOCK_FAIL prepared-cache-lease-restore"); return 1; }
    if (!run_case(argv[1], FALSE, TRUE, TRUE, 0)) { puts("HOST_NETWORK_DBUS_MOCK_FAIL existing-profile-preserved"); return 1; }
    if (!run_case(argv[1], FALSE, FALSE, FALSE, 0)) { puts("HOST_NETWORK_DBUS_MOCK_FAIL powered-off-no-change"); return 1; }
    if (!run_case(argv[1], FALSE, FALSE, TRUE, 1)) { puts("HOST_NETWORK_DBUS_MOCK_FAIL readonly-prepare-cancel"); return 1; }
    if (!run_case(argv[1], FALSE, FALSE, TRUE, 2)) { puts("HOST_NETWORK_DBUS_MOCK_FAIL crash-profile-hash-recovery"); return 1; }
    if (!run_case(argv[1], FALSE, FALSE, TRUE, 3)) { puts("HOST_NETWORK_DBUS_MOCK_FAIL modified-profile-lock"); return 1; }
    if (!run_case(argv[1], FALSE, FALSE, TRUE, 5)) { puts("HOST_NETWORK_DBUS_MOCK_FAIL crashed-prepare-untouched"); return 1; }
    if (!run_case(argv[1], FALSE, FALSE, TRUE, 6)) { puts("HOST_NETWORK_DBUS_MOCK_FAIL other-boot-lock"); return 1; }
    if (!run_case(argv[1], FALSE, FALSE, TRUE, 7)) { puts("HOST_NETWORK_DBUS_MOCK_FAIL live-actor-identity-lock"); return 1; }
    if (!run_case(argv[1], FALSE, FALSE, TRUE, 8)) { puts("HOST_NETWORK_DBUS_MOCK_FAIL connman-owner-changed-lock"); return 1; }
    if (!run_case(argv[1], FALSE, FALSE, TRUE, 9)) { puts("HOST_NETWORK_DBUS_MOCK_FAIL profile-hash-missing-lock"); return 1; }
    g_rmdir(PROFILE_ROOT);
    puts("HOST_NETWORK_DBUS_MOCK_PASS cases=12 device_tested=false"); return 0;
}
