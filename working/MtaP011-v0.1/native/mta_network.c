/* Original P011 ConnMan lease helper. Only documented Manager, Technology,
 * Service and Agent APIs are used. Profile bytes are streamed only into hashes,
 * never parsed, copied into journals or logged. No shell or password logs.
 * Credentials arrive as base64 over a private stdin pipe, never argv.
 */
#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700
#include <gio/gio.h>
#include <glib-unix.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <limits.h>
#include <errno.h>
#include "mta_core.h"

#define BUS "net.connman"
#define MANAGER "net.connman.Manager"
#define SERVICE "net.connman.Service"
#define TECHNOLOGY "net.connman.Technology"
#define AGENT_PATH "/org/p011/Mta/NetworkAgent"
#define COMMAND_MAX 8192
#define CALL_MS 5000
#ifndef MTA_SESSION_ROOT
#define MTA_SESSION_ROOT "/mnt/data/p011-toolbox/sessions/"
#endif
#ifndef MTA_PROFILE_ROOT
#define MTA_PROFILE_ROOT "/var/lib/connman"
#endif
/* Production cannot assume ConnMan owns the vendor's active supplicant or
 * uses the upstream per-service profile layout. HOST fixtures opt in only. */
#ifndef MTA_CONNMAN_STA_VERIFIED
#define MTA_CONNMAN_STA_VERIFIED 0
#endif

typedef struct { char ssid[33], psk[65], journal_dir[1024], profile_root[1024], journal_file[1024]; unsigned timeout, ttl; unsigned kind; } Command;
typedef struct {
    char *path, *name, *state, *address, *gateway;
    gboolean favorite, immutable, psk;
} Network;
typedef struct {
    GDBusConnection *bus;
    GMainLoop *loop;
    GPtrArray *before;
    char *wifi_path, *old_path, *target, *owner;
    Command command;
    GCancellable *operation;
    guint agent_id, stdin_watch, tick_id;
    GIOChannel *input;
    gboolean agent_registered, powered, touched, cleaning, clean_done;
    gboolean restoring, restored, failed, disconnected, connected, stopped;
    gint64 deadline, lease_deadline, restore_deadline;
    char reason[64];
    char control[COMMAND_MAX + 1];
    size_t control_length;
    gboolean prepared, recovering, target_absence_verified;
    char *journal_path, *profile_root, *target_name_hash, *target_profile_hash;
    GKeyFile *journal;
} Lease;

static void wipe(void *data, size_t size) { mta_wipe(data, size); }
static void skip(const char **p) { while (**p == ' ' || **p == '\t' || **p == '\r' || **p == '\n') ++*p; }
static gboolean text_token(const char **p, char *out, size_t capacity) {
    size_t n = 0;
    if (*(*p)++ != '"') return FALSE;
    while (**p && **p != '"') {
        unsigned char c = (unsigned char)**p;
        if (c < 32 || c > 126 || c == '\\' || n + 1 >= capacity) return FALSE;
        out[n++] = *(*p)++;
    }
    if (*(*p)++ != '"') return FALSE;
    out[n] = 0;
    return TRUE;
}
static gboolean decode_secret(const char *value, char *out, size_t maximum) {
    size_t written = 0;
    if (!mta_base64_decode(value, strlen(value), (uint8_t *)out, maximum, &written) || !written || memchr(out, 0, written)) return FALSE;
    out[written] = 0;
    return TRUE;
}
static gboolean parse_command(const char *line, Command *command, gboolean control) {
    const char *p = line;
    char key[32], value[1536], kind[16] = "";
    unsigned seen = 0;
    memset(command, 0, sizeof(*command)); command->timeout = 45; command->ttl = 300;
    skip(&p); if (*p++ != '{') return FALSE; skip(&p);
    while (*p && *p != '}') {
        unsigned field;
        if (!text_token(&p, key, sizeof(key))) return FALSE;
        if (!strcmp(key, "cmd")) field = 1;
        else if (!strcmp(key, "consented")) field = 2;
        else if (!strcmp(key, "ssid_b64")) field = 4;
        else if (!strcmp(key, "psk_b64")) field = 8;
        else if (!strcmp(key, "timeout")) field = 16;
        else if (!strcmp(key, "ttl")) field = 32;
        else if (!strcmp(key, "journal_dir_b64")) field = 64;
        else if (!strcmp(key, "profile_root_b64")) field = 128;
        else if (!strcmp(key, "journal_file_b64")) field = 256;
        else return FALSE;
        if (seen & field) return FALSE;
        seen |= field; skip(&p); if (*p++ != ':') return FALSE; skip(&p);
        if (field == 2) { if (strncmp(p, "true", 4)) return FALSE; p += 4; }
        else if (field == 16 || field == 32) {
            unsigned number = 0; const char *first = p;
            while (*p >= '0' && *p <= '9') { number = number * 10 + (unsigned)(*p++ - '0'); if (number > 600) return FALSE; }
            if (first == p || (p - first > 1 && *first == '0')) return FALSE;
            if (field == 16) { if (number < 10 || number > 90) return FALSE; command->timeout = number; }
            else { if (number < 10 || number > 600) return FALSE; command->ttl = number; }
        } else {
            if (!text_token(&p, value, sizeof(value))) return FALSE;
            if (field == 1) { if (strlen(value) >= sizeof(kind)) return FALSE; strcpy(kind, value); }
            else if (field == 4) { if (!decode_secret(value, command->ssid, 32)) return FALSE; }
            else if (field == 8) { if (!decode_secret(value, command->psk, 64)) return FALSE; }
            else if (field == 64) { if (!decode_secret(value, command->journal_dir, sizeof(command->journal_dir)-1)) return FALSE; }
            else if (field == 128) { if (!decode_secret(value, command->profile_root, sizeof(command->profile_root)-1)) return FALSE; }
            else if (field == 256) { if (!decode_secret(value, command->journal_file, sizeof(command->journal_file)-1)) return FALSE; }
            wipe(value, sizeof(value));
        }
        skip(&p); if (*p == '}') break; if (*p++ != ',') return FALSE; skip(&p); if (*p == '}') return FALSE;
    }
    if (*p++ != '}') return FALSE;
    skip(&p); if (*p) return FALSE;
    if (control && seen == 1 && (!strcmp(kind, "restore") || !strcmp(kind, "cancel"))) { command->kind = 1; return TRUE; }
    if (!strcmp(kind, "prepare")) { command->kind = 2; return (seen & 65) == 65 && !(seen & ~(1u|32u|64u)); }
    if (!strcmp(kind, "recover")) { command->kind = 3; return seen == 257; }
    if ((seen & 15) != 15 || (seen & ~(1u|2u|4u|8u|16u|32u|64u)) || strcmp(kind, "receive") || !g_utf8_validate(command->ssid, -1, NULL)) return FALSE;
    command->kind = 4;
    {
        size_t i, n = strlen(command->psk);
        if (n < 8 || n > 64) return FALSE;
        for (i = 0; i < n; i++) if ((unsigned char)command->psk[i] < 32 || (unsigned char)command->psk[i] > 126 || (n == 64 && !g_ascii_isxdigit(command->psk[i]))) return FALSE;
    }
    return TRUE;
}
static void network_free(gpointer data) {
    Network *n = data;
    g_free(n->path); g_free(n->name); g_free(n->state); g_free(n->address); g_free(n->gateway); g_free(n);
}
static GVariant *call(Lease *l, const char *path, const char *interface, const char *method, GVariant *params, const GVariantType *type) {
    GError *error = NULL;
    GVariant *reply = g_dbus_connection_call_sync(l->bus, l->owner ? l->owner : BUS, path, interface, method, params, type, G_DBUS_CALL_FLAGS_NO_AUTO_START, CALL_MS, NULL, &error);
    if (error) g_error_free(error); /* Never print errors containing SSID/path. */
    return reply;
}
static char *property_string(GVariant *props, const char *key) {
    const char *value = "";
    g_variant_lookup(props, key, "&s", &value);
    return g_strdup(value);
}
static GPtrArray *networks(Lease *l) {
    GVariant *reply = call(l, "/", MANAGER, "GetServices", NULL, G_VARIANT_TYPE("(a(oa{sv}))"));
    GVariant *rows, *props; GVariantIter iter; const char *path;
    GPtrArray *result;
    if (!reply) return NULL;
    result = g_ptr_array_new_with_free_func(network_free); rows = g_variant_get_child_value(reply, 0); g_variant_iter_init(&iter, rows);
    while (g_variant_iter_next(&iter, "(&o@a{sv})", &path, &props)) {
        const char *type = ""; GVariant *ipv4, *security;
        g_variant_lookup(props, "Type", "&s", &type);
        if (!strcmp(type, "wifi") && result->len >= 512) {
            /* An incomplete baseline cannot prove profile ownership. */
            g_variant_unref(props); g_variant_unref(rows); g_variant_unref(reply); g_ptr_array_unref(result); return NULL;
        }
        if (!strcmp(type, "wifi")) {
            Network *n = g_new0(Network, 1);
            n->path = g_strdup(path); n->name = property_string(props, "Name"); n->state = property_string(props, "State");
            g_variant_lookup(props, "Favorite", "b", &n->favorite); g_variant_lookup(props, "Immutable", "b", &n->immutable);
            ipv4 = g_variant_lookup_value(props, "IPv4", G_VARIANT_TYPE("a{sv}"));
            n->address = ipv4 ? property_string(ipv4, "Address") : g_strdup(""); n->gateway = ipv4 ? property_string(ipv4, "Gateway") : g_strdup("");
            if (ipv4) g_variant_unref(ipv4);
            security = g_variant_lookup_value(props, "Security", G_VARIANT_TYPE("as"));
            if (security) { GVariantIter s; const char *entry; g_variant_iter_init(&s, security); while (g_variant_iter_next(&s, "&s", &entry)) if (!strcmp(entry, "psk")) n->psk = TRUE; g_variant_unref(security); }
            g_ptr_array_add(result, n);
        }
        g_variant_unref(props);
    }
    g_variant_unref(rows); g_variant_unref(reply); return result;
}
static Network *find(GPtrArray *rows, const char *path) {
    guint i; if (!rows || !path) return NULL;
    for (i = 0; i < rows->len; i++) { Network *n = g_ptr_array_index(rows, i); if (!strcmp(path, n->path)) return n; }
    return NULL;
}
static gboolean connected(Network *n) { return n && (!strcmp(n->state, "ready") || !strcmp(n->state, "online")); }
static gboolean ipv4_address(const char *text) {
    GInetAddress *address = g_inet_address_new_from_string(text);
    gboolean valid = address && g_inet_address_get_family(address) == G_SOCKET_FAMILY_IPV4 && !g_inet_address_get_is_any(address);
    if (address) g_object_unref(address);
    return valid;
}
static gboolean technologies(Lease *l, char **wifi_path, gboolean *powered) {
    GVariant *reply = call(l, "/", MANAGER, "GetTechnologies", NULL, G_VARIANT_TYPE("(a(oa{sv}))"));
    GVariant *rows, *props; GVariantIter iter; const char *path; unsigned found = 0;
    if (!reply) return FALSE;
    rows = g_variant_get_child_value(reply, 0); g_variant_iter_init(&iter, rows);
    while (g_variant_iter_next(&iter, "(&o@a{sv})", &path, &props)) {
        const char *type = ""; gboolean state = FALSE;
        g_variant_lookup(props, "Type", "&s", &type);
        if (!strcmp(type, "wifi")) { found++; g_variant_lookup(props, "Powered", "b", &state); if (found == 1) { *wifi_path = g_strdup(path); *powered = state; } }
        g_variant_unref(props);
    }
    g_variant_unref(rows); g_variant_unref(reply); return found == 1;
}
static gboolean private_bus(Lease *l) {
    GError *error = NULL; char *address = g_dbus_address_get_for_bus_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
    if (address) l->bus = g_dbus_connection_new_for_address_sync(address, G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT | G_DBUS_CONNECTION_FLAGS_MESSAGE_BUS_CONNECTION, NULL, NULL, &error);
    g_free(address); if (error) g_error_free(error);
    if (l->bus) g_dbus_connection_set_exit_on_close(l->bus, FALSE);
    return l->bus != NULL;
}
static void emit_error(const char *reason) { printf("{\"event\":\"error\",\"ok\":false,\"reason\":\"%s\"}\n", reason); fflush(stdout); }
static guint64 process_start(guint64 pid) {
    char *path = g_strdup_printf("/proc/%" G_GUINT64_FORMAT "/stat", pid), *contents = NULL, *p;
    guint64 result = 0; unsigned field;
    if (!g_file_get_contents(path, &contents, NULL, NULL)) { g_free(path); return 0; }
    p = strrchr(contents, ')'); if (p) { p += 2; for (field = 3; field < 22 && *p; field++) { while (*p && *p != ' ') p++; while (*p == ' ') p++; } if (field == 22) result = g_ascii_strtoull(p, NULL, 10); }
    g_free(path); g_free(contents); return result;
}
static char *file_hash(const char *path, size_t maximum) {
    struct stat st; int fd = open(path, O_RDONLY | O_NOFOLLOW); char bytes[4096]; ssize_t count; size_t total = 0; char *result = NULL;
    GChecksum *checksum;
    if (fd < 0) return NULL;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_uid != geteuid() || st.st_nlink != 1 || st.st_size < 0 || (guint64)st.st_size > maximum) { close(fd); return NULL; }
    checksum = g_checksum_new(G_CHECKSUM_SHA256);
    while ((count = read(fd, bytes, sizeof(bytes))) > 0) { total += (size_t)count; if (total > maximum) break; g_checksum_update(checksum, (guchar *)bytes, (gsize)count); wipe(bytes, sizeof(bytes)); }
    if (count == 0 && total <= maximum) result = g_strdup(g_checksum_get_string(checksum));
    wipe(bytes, sizeof(bytes)); g_checksum_free(checksum); close(fd); return result;
}
static gboolean secure_directory(const char *path, gboolean session) {
    char actual[PATH_MAX]; struct stat st;
    if (!path || path[0] != '/' || !realpath(path, actual) || strcmp(path, actual) || lstat(path, &st) || !S_ISDIR(st.st_mode) || st.st_uid != geteuid()) return FALSE;
    if (session) return g_str_has_prefix(path, MTA_SESSION_ROOT) && (st.st_mode & 0777) == 0700;
    return !(st.st_mode & 0022);
}
static gboolean service_path(const char *path) {
    const char *p; if (!path || !g_str_has_prefix(path, "/net/connman/service/wifi_") || strlen(path) > 256) return FALSE;
    for (p = path + strlen("/net/connman/service/"); *p; p++) if (!g_ascii_isalnum(*p) && *p != '_') return FALSE;
    return TRUE;
}
static char *profile_path(Lease *l) {
    const char *base; char *directory, *path;
    if (!l->profile_root || !secure_directory(l->profile_root, FALSE) || !service_path(l->target)) return NULL;
    base = strrchr(l->target, '/') + 1;
    directory = g_build_filename(l->profile_root, base, NULL);
    if (!secure_directory(directory, FALSE)) { g_free(directory); return NULL; }
    path = g_build_filename(directory, "settings", NULL); g_free(directory); return path;
}
static char *profile_hash(Lease *l) { char *path = profile_path(l), *result = path ? file_hash(path, 1024 * 1024) : NULL; g_free(path); return result; }
static gboolean owner_identity(Lease *l, guint64 *pid, guint64 *start) {
    GVariant *reply; const char *owner; guint32 process;
    reply = g_dbus_connection_call_sync(l->bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "GetNameOwner", g_variant_new("(s)", BUS), G_VARIANT_TYPE("(s)"), G_DBUS_CALL_FLAGS_NO_AUTO_START, CALL_MS, NULL, NULL);
    if (!reply) return FALSE;
    g_variant_get(reply, "(&s)", &owner); if (!l->owner) l->owner = g_strdup(owner);
    if (strcmp(l->owner, owner)) { g_variant_unref(reply); return FALSE; } g_variant_unref(reply);
    reply = g_dbus_connection_call_sync(l->bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "GetConnectionUnixProcessID", g_variant_new("(s)", l->owner), G_VARIANT_TYPE("(u)"), G_DBUS_CALL_FLAGS_NO_AUTO_START, CALL_MS, NULL, NULL);
    if (!reply) return FALSE;
    g_variant_get(reply, "(u)", &process); g_variant_unref(reply); *pid = process; *start = process_start(process); return *start != 0;
}
static gboolean write_all(int fd, const char *data, size_t size) { while (size) { ssize_t n = write(fd, data, size); if (n <= 0) return FALSE; data += n; size -= (size_t)n; } return TRUE; }
static gboolean journal_save(Lease *l, const char *phase, gboolean first) {
    char *directory, *base, *temp, *data; gsize size; int dirfd = -1, fd = -1; gboolean ok = FALSE; struct stat st;
    if (!l->journal_path || !l->journal) return FALSE;
    directory = g_path_get_dirname(l->journal_path); base = g_path_get_basename(l->journal_path); temp = g_strdup_printf(".%s.%u.next", base, (unsigned)getpid());
    if (!secure_directory(directory, TRUE) || !g_str_has_prefix(base, "lease-") || !g_str_has_suffix(base, ".ini")) goto out;
    dirfd = open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW); if (dirfd < 0) goto out;
    if (!first && (fstatat(dirfd, base, &st, AT_SYMLINK_NOFOLLOW) || !S_ISREG(st.st_mode) || st.st_uid != geteuid() || (st.st_mode & 0777) != 0600 || st.st_nlink != 1)) goto out;
    g_key_file_set_string(l->journal, "Lease", "Phase", phase);
    g_key_file_set_uint64(l->journal, "Lease", "ActorPID", (guint64)getpid()); g_key_file_set_uint64(l->journal, "Lease", "ActorStart", process_start((guint64)getpid()));
    g_key_file_set_string(l->journal, "Lease", "TargetPath", l->target ? l->target : "");
    g_key_file_set_string(l->journal, "Lease", "TargetNameHash", l->target_name_hash ? l->target_name_hash : "");
    g_key_file_set_string(l->journal, "Lease", "TargetProfileHash", l->target_profile_hash ? l->target_profile_hash : "");
    g_key_file_set_boolean(l->journal, "Lease", "TargetAbsentBeforeConnect", l->target_absence_verified);
    data = g_key_file_to_data(l->journal, &size, NULL);
    fd = openat(dirfd, first ? base : temp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd >= 0 && write_all(fd, data, size) && !fsync(fd)) {
        if (first || !renameat(dirfd, temp, dirfd, base)) ok = fsync(dirfd) == 0;
    }
    g_free(data);
out:
    if (fd >= 0) close(fd);
    if (!ok && dirfd >= 0 && !first) unlinkat(dirfd, temp, 0);
    if (dirfd >= 0) close(dirfd);
    g_free(directory); g_free(base); g_free(temp); return ok;
}
static gboolean journal_begin(Lease *l) {
    char *boot = NULL, *tag, *name; guint64 pid, start; char **paths; guint i;
    if (!secure_directory(l->command.journal_dir, TRUE) || !owner_identity(l, &pid, &start) || !g_file_get_contents("/proc/sys/kernel/random/boot_id", &boot, NULL, NULL)) return FALSE;
    tag = file_hash("/proc/self/exe", 16 * 1024 * 1024); /* /proc symlink is intentionally resolved only for this running image. */
    if (!tag) { char actual[PATH_MAX]; if (realpath("/proc/self/exe", actual)) tag = file_hash(actual, 16 * 1024 * 1024); }
    if (!tag) { g_free(boot); return FALSE; }
    g_strstrip(boot); l->journal = g_key_file_new();
    g_key_file_set_integer(l->journal, "Lease", "Version", 1); g_key_file_set_string(l->journal, "Lease", "Boot", boot); g_key_file_set_string(l->journal, "Lease", "HelperSHA256", tag);
    g_key_file_set_uint64(l->journal, "Lease", "ConnmanPID", pid); g_key_file_set_uint64(l->journal, "Lease", "ConnmanStart", start); g_key_file_set_string(l->journal, "Lease", "ConnmanOwner", l->owner);
    g_key_file_set_string(l->journal, "Lease", "WifiPath", l->wifi_path); g_key_file_set_boolean(l->journal, "Lease", "Powered", l->powered);
    g_key_file_set_string(l->journal, "Lease", "OriginalPath", l->old_path ? l->old_path : "");
    { Network *old = find(l->before, l->old_path); char *hash = old ? g_compute_checksum_for_string(G_CHECKSUM_SHA256, old->name, -1) : g_strdup(""); g_key_file_set_string(l->journal, "Lease", "OriginalNameHash", hash); g_free(hash); }
    g_key_file_set_string(l->journal, "Lease", "ProfileRoot", l->profile_root ? l->profile_root : "");
    paths = g_new0(char *, l->before->len + 1); for (i = 0; i < l->before->len; i++) paths[i] = ((Network *)g_ptr_array_index(l->before, i))->path;
    g_key_file_set_string_list(l->journal, "Lease", "BeforePaths", (const char *const *)paths, l->before->len); g_free(paths);
    name = g_strdup_printf("lease-%u-%" G_GUINT64_FORMAT ".ini", (unsigned)getpid(), process_start((guint64)getpid())); l->journal_path = g_build_filename(l->command.journal_dir, name, NULL);
    g_free(name); g_free(tag); g_free(boot); return journal_save(l, "prepared", TRUE);
}
static gboolean journal_remove(Lease *l) {
    char *directory, *base; struct stat st; int dirfd; gboolean ok;
    if (!l->journal_path) return FALSE;
    directory = g_path_get_dirname(l->journal_path); base = g_path_get_basename(l->journal_path);
    if (!secure_directory(directory, TRUE)) { g_free(directory); g_free(base); return FALSE; }
    dirfd = open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW); g_free(directory);
    ok = dirfd >= 0 && !fstatat(dirfd, base, &st, AT_SYMLINK_NOFOLLOW) && S_ISREG(st.st_mode) && st.st_uid == geteuid() && (st.st_mode & 0777) == 0600 && st.st_nlink == 1 && !unlinkat(dirfd, base, 0) && !fsync(dirfd);
    if (dirfd >= 0) close(dirfd);
    g_free(base); return ok;
}
static gboolean target_identity(Lease *l, Network *n) {
    char *hash; gboolean ok;
    if (!n || !l->target_name_hash || n->immutable || !n->psk) return FALSE;
    hash = g_compute_checksum_for_string(G_CHECKSUM_SHA256, n->name, -1); ok = !strcmp(hash, l->target_name_hash); g_free(hash); return ok;
}
static gboolean same_profile(Lease *l) {
    char *hash = profile_hash(l); gboolean ok = hash && l->target_profile_hash && !strcmp(hash, l->target_profile_hash);
    g_free(hash); return ok;
}
static gboolean target_profile_absent(Lease *l) {
    char *path; struct stat st; gboolean ok;
    if (!l->profile_root || !secure_directory(l->profile_root, FALSE) || !service_path(l->target)) return FALSE;
    path = g_build_filename(l->profile_root, strrchr(l->target, '/') + 1, NULL);
    ok = lstat(path, &st) == -1 && errno == ENOENT; g_free(path); return ok;
}
static void locked(Lease *l, const char *reason) {
    l->failed = TRUE; l->stopped = TRUE; g_strlcpy(l->reason, reason, sizeof(l->reason)); emit_error(reason);
    if (l->loop) g_main_loop_quit(l->loop);
}
static gboolean hex_hash(const char *text) {
    size_t i; if (!text || strlen(text) != 64) return FALSE;
    for (i = 0; i < 64; i++) if (!g_ascii_isxdigit(text[i])) return FALSE;
    return TRUE;
}
static gboolean journal_load(Lease *l) {
    char *directory = g_path_get_dirname(l->command.journal_file), *base = g_path_get_basename(l->command.journal_file);
    char *contents = NULL, *phase = NULL, *boot = NULL, *recorded = NULL, *tag = NULL, actual[PATH_MAX];
    char **paths = NULL; gsize size = 0, count = 0, i; int fd = -1; struct stat st; gboolean ok = FALSE; guint64 pid, start;
    GError *error = NULL;
    if (!secure_directory(directory, TRUE) || !g_str_has_prefix(base, "lease-") || !g_str_has_suffix(base, ".ini")) goto out;
    fd = open(l->command.journal_file, O_RDONLY | O_NOFOLLOW);
    if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_uid != geteuid() || (st.st_mode & 0777) != 0600 || st.st_nlink != 1 || st.st_size <= 0 || st.st_size > 262144) goto out;
    size = (gsize)st.st_size; contents = g_malloc(size + 1);
    { size_t used = 0; while (used < size) { ssize_t n = read(fd, contents + used, size - used); if (n <= 0) goto out; used += (size_t)n; } contents[size] = 0; }
    l->journal = g_key_file_new();
    if (!g_key_file_load_from_data(l->journal, contents, size, G_KEY_FILE_NONE, &error) || g_key_file_get_integer(l->journal, "Lease", "Version", NULL) != 1) goto out;
    if (!g_file_get_contents("/proc/sys/kernel/random/boot_id", &boot, NULL, NULL) || !realpath("/proc/self/exe", actual) || !(tag = file_hash(actual, 16 * 1024 * 1024))) goto out;
    g_strstrip(boot); recorded = g_key_file_get_string(l->journal, "Lease", "Boot", NULL);
    if (!recorded || strcmp(recorded, boot)) goto out;
    g_free(recorded); recorded = g_key_file_get_string(l->journal, "Lease", "HelperSHA256", NULL);
    if (!recorded || strcmp(recorded, tag)) goto out;
    pid = g_key_file_get_uint64(l->journal, "Lease", "ActorPID", NULL); start = g_key_file_get_uint64(l->journal, "Lease", "ActorStart", NULL);
    if (!pid || !start || process_start(pid) == start) goto out; /* Never interrupt a live lease or PID reuse. */
    g_free(recorded); recorded = g_key_file_get_string(l->journal, "Lease", "ConnmanOwner", NULL);
    if (!recorded || !l->owner || strcmp(recorded, l->owner) || !owner_identity(l, &pid, &start) || pid != g_key_file_get_uint64(l->journal, "Lease", "ConnmanPID", NULL) || start != g_key_file_get_uint64(l->journal, "Lease", "ConnmanStart", NULL)) goto out;
    g_free(recorded); recorded = g_key_file_get_string(l->journal, "Lease", "WifiPath", NULL);
    if (!recorded || strcmp(recorded, l->wifi_path) || l->powered != g_key_file_get_boolean(l->journal, "Lease", "Powered", NULL)) goto out;
    g_free(recorded); recorded = g_key_file_get_string(l->journal, "Lease", "ProfileRoot", NULL);
    if (!recorded || strcmp(recorded, MTA_PROFILE_ROOT) || !secure_directory(recorded, FALSE)) goto out;
    l->profile_root = g_strdup(recorded);
    paths = g_key_file_get_string_list(l->journal, "Lease", "BeforePaths", &count, NULL); if (!paths || count > 512) goto out;
    { char *original = g_key_file_get_string(l->journal, "Lease", "OriginalPath", NULL), *name_hash = g_key_file_get_string(l->journal, "Lease", "OriginalNameHash", NULL);
      if (!original || !name_hash) { g_free(original); g_free(name_hash); goto out; }
      if (*original) { Network *old = find(l->before, original); char *hash = old ? g_compute_checksum_for_string(G_CHECKSUM_SHA256, old->name, -1) : NULL; gboolean same = hash && !strcmp(hash, name_hash); g_free(hash); if (!same) { g_free(original); g_free(name_hash); goto out; } }
      g_free(original); g_free(name_hash);
    }
    g_ptr_array_unref(l->before); l->before = g_ptr_array_new_with_free_func(network_free);
    for (i = 0; i < count; i++) { Network *n; if (!service_path(paths[i]) || find(l->before, paths[i])) goto out; n = g_new0(Network, 1); n->path = g_strdup(paths[i]); g_ptr_array_add(l->before, n); }
    g_free(l->old_path); l->old_path = g_key_file_get_string(l->journal, "Lease", "OriginalPath", NULL);
    if (!l->old_path || (*l->old_path && (!service_path(l->old_path) || !find(l->before, l->old_path)))) goto out;
    if (!*l->old_path) { g_free(l->old_path); l->old_path = NULL; }
    phase = g_key_file_get_string(l->journal, "Lease", "Phase", NULL); if (!phase) goto out;
    l->target = g_key_file_get_string(l->journal, "Lease", "TargetPath", NULL);
    if (!l->target) goto out;
    l->journal_path = g_strdup(l->command.journal_file); l->recovering = TRUE;
    if (!strcmp(phase, "prepared") && !*l->target) { l->prepared = TRUE; ok = TRUE; goto out; }
    if ((!strcmp(phase, "connecting") || !strcmp(phase, "connected") || !strcmp(phase, "restoring")) && service_path(l->target) && !find(l->before, l->target)) {
        l->target_name_hash = g_key_file_get_string(l->journal, "Lease", "TargetNameHash", NULL);
        l->target_profile_hash = g_key_file_get_string(l->journal, "Lease", "TargetProfileHash", NULL);
        l->target_absence_verified = g_key_file_get_boolean(l->journal, "Lease", "TargetAbsentBeforeConnect", NULL);
        if (l->target_absence_verified && hex_hash(l->target_name_hash) && hex_hash(l->target_profile_hash)) { l->touched = TRUE; ok = TRUE; }
    }
out:
    if (fd >= 0) close(fd);
    if (error) g_error_free(error);
    g_free(contents); g_free(directory); g_free(base); g_free(phase); g_free(boot); g_free(recorded); g_free(tag); g_strfreev(paths); return ok;
}
static void unregister_agent(Lease *l) {
    if (l->agent_registered) { GVariant *reply = call(l, "/", MANAGER, "UnregisterAgent", g_variant_new("(o)", AGENT_PATH), NULL); if (reply) g_variant_unref(reply); l->agent_registered = FALSE; }
    if (l->agent_id) { g_dbus_connection_unregister_object(l->bus, l->agent_id); l->agent_id = 0; }
}
static void begin_restore(Lease *l, const char *reason) {
    if (l->restoring || l->stopped) return;
    l->restoring = TRUE; l->restore_deadline = g_get_monotonic_time() + 30 * G_TIME_SPAN_SECOND;
    if (reason && *reason) { l->failed = TRUE; g_strlcpy(l->reason, reason, sizeof(l->reason)); }
    if (l->operation) g_cancellable_cancel(l->operation);
    unregister_agent(l); wipe(l->command.psk, sizeof(l->command.psk));
    if (l->touched && !journal_save(l, "restoring", FALSE)) { locked(l, "JOURNAL_WRITE_FAILED_RECOVERY_LOCKED"); return; }
    printf("{\"event\":\"restoring\",\"ok\":true}\n"); fflush(stdout);
}
static void agent_method(GDBusConnection *bus, const char *sender, const char *path, const char *interface, const char *method, GVariant *params, GDBusMethodInvocation *invocation, gpointer userdata) {
    Lease *l = userdata;
    (void)bus; (void)path; (void)interface;
    if (!l->owner || strcmp(sender, l->owner)) { g_dbus_method_invocation_return_dbus_error(invocation, "net.connman.Agent.Error.Canceled", "Unowned agent request"); return; }
    if (!strcmp(method, "RequestInput")) {
        const char *service_path; GVariant *fields; GVariantBuilder out; GVariantIter iter; const char *key; GVariant *details; gboolean valid = TRUE;
        g_variant_get(params, "(&o@a{sv})", &service_path, &fields);
        if (l->restoring || !l->target || strcmp(service_path, l->target)) valid = FALSE;
        g_variant_builder_init(&out, G_VARIANT_TYPE("a{sv}")); g_variant_iter_init(&iter, fields);
        while (g_variant_iter_next(&iter, "{&sv}", &key, &details)) {
            const char *requirement = "";
            if (g_variant_is_of_type(details, G_VARIANT_TYPE("a{sv}"))) g_variant_lookup(details, "Requirement", "&s", &requirement);
            if (!strcmp(key, "Passphrase")) g_variant_builder_add(&out, "{sv}", key, g_variant_new_string(l->command.psk));
            else if (!strcmp(key, "Name")) g_variant_builder_add(&out, "{sv}", key, g_variant_new_string(l->command.ssid));
            else if (!strcmp(key, "SSID")) g_variant_builder_add(&out, "{sv}", key, g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, l->command.ssid, strlen(l->command.ssid), 1));
            else if (!strcmp(requirement, "mandatory")) valid = FALSE;
            g_variant_unref(details);
        }
        g_variant_unref(fields);
        if (valid) g_dbus_method_invocation_return_value(invocation, g_variant_new("(a{sv})", &out));
        else { g_variant_builder_clear(&out); g_dbus_method_invocation_return_dbus_error(invocation, "net.connman.Agent.Error.Canceled", "Unsupported or unowned input"); }
    } else if (!strcmp(method, "RequestBrowser") || !strcmp(method, "RequestPeerAuthorization")) {
        g_dbus_method_invocation_return_dbus_error(invocation, "net.connman.Agent.Error.Canceled", "Only temporary WPA2 STA is permitted");
    } else {
        g_dbus_method_invocation_return_value(invocation, NULL);
        if (!strcmp(method, "Release") || !strcmp(method, "Cancel") || !strcmp(method, "ReportError")) begin_restore(l, "CONNMAN_AGENT_CANCELED");
    }
}
static const GDBusInterfaceVTable agent_vtable = {agent_method, NULL, NULL, {NULL}};
static const char agent_xml[] = "<node><interface name='net.connman.Agent'>"
    "<method name='Release'/><method name='Cancel'/>"
    "<method name='ReportError'><arg type='o' direction='in'/><arg type='s' direction='in'/></method>"
    "<method name='ReportPeerError'><arg type='o' direction='in'/><arg type='s' direction='in'/></method>"
    "<method name='RequestInput'><arg type='o' direction='in'/><arg type='a{sv}' direction='in'/><arg type='a{sv}' direction='out'/></method>"
    "<method name='RequestBrowser'><arg type='o' direction='in'/><arg type='s' direction='in'/></method>"
    "<method name='RequestPeerAuthorization'><arg type='o' direction='in'/><arg type='a{sv}' direction='in'/><arg type='a{sv}' direction='out'/></method>"
    "</interface></node>";
static gboolean register_agent(Lease *l) {
    GError *error = NULL; GVariant *reply;
    GDBusNodeInfo *info = g_dbus_node_info_new_for_xml(agent_xml, &error);
    if (!info) { if (error) g_error_free(error); return FALSE; }
    { guint64 pid, start; if (!owner_identity(l, &pid, &start)) { g_dbus_node_info_unref(info); return FALSE; } }
    l->agent_id = l->owner ? g_dbus_connection_register_object(l->bus, AGENT_PATH, info->interfaces[0], &agent_vtable, l, NULL, &error) : 0;
    g_dbus_node_info_unref(info); if (error) g_error_free(error); if (!l->agent_id) return FALSE;
    reply = call(l, "/", MANAGER, "RegisterAgent", g_variant_new("(o)", AGENT_PATH), NULL);
    if (!reply) return FALSE;
    g_variant_unref(reply); l->agent_registered = TRUE; return TRUE;
}
static void operation_done(GObject *source, GAsyncResult *result, gpointer userdata) {
    Lease *l = userdata; GError *error = NULL;
    GVariant *reply = g_dbus_connection_call_finish(G_DBUS_CONNECTION(source), result, &error);
    if (reply) g_variant_unref(reply);
    if (error) { if (!l->restoring) begin_restore(l, "TEMPORARY_CONNECTION_FAILED"); g_error_free(error); }
}
static void async_connect(Lease *l, const char *path, unsigned seconds) {
    g_dbus_connection_call(l->bus, l->owner ? l->owner : BUS, path, SERVICE, "Connect", NULL, NULL, G_DBUS_CALL_FLAGS_NO_AUTO_START, (gint)seconds * 1000, l->operation, operation_done, l);
}
static gboolean discover_target(Lease *l, GPtrArray *rows) {
    Network *candidate = NULL; guint i;
    for (i = 0; i < rows->len; i++) {
        Network *n = g_ptr_array_index(rows, i);
        if (strcmp(n->name, l->command.ssid)) continue;
        if (candidate) { begin_restore(l, "AMBIGUOUS_TARGET_NETWORK"); return FALSE; }
        candidate = n;
    }
    if (!candidate) return FALSE;
    /* Do not overwrite or remove ANY service that existed in the baseline,
     * even a non-favorite scan-cache entry. Ownership is not proven for it. */
    if (find(l->before, candidate->path) || candidate->favorite || candidate->immutable || !candidate->psk) { begin_restore(l, "TARGET_PROFILE_OWNERSHIP_NOT_PROVEN"); return FALSE; }
    l->target = g_strdup(candidate->path);
    if (!target_profile_absent(l)) { begin_restore(l, "TARGET_PROFILE_OWNERSHIP_NOT_PROVEN"); return FALSE; }
    l->target_absence_verified = TRUE;
    l->target_name_hash = g_compute_checksum_for_string(G_CHECKSUM_SHA256, candidate->name, -1);
    if (!journal_save(l, "connecting", FALSE)) { locked(l, "JOURNAL_WRITE_FAILED_RECOVERY_LOCKED"); return FALSE; }
    l->touched = TRUE;
    async_connect(l, l->target, l->command.timeout); return TRUE;
}
static gboolean verify_power(Lease *l) {
    char *path = NULL; gboolean powered = FALSE;
    gboolean ok = technologies(l, &path, &powered) && powered == l->powered && path && !strcmp(path, l->wifi_path);
    g_free(path); return ok;
}
static gboolean restore_tick(Lease *l, GPtrArray *rows) {
    Network *target = find(rows, l->target), *old = find(rows, l->old_path); guint i;
    if (!l->touched) {
        if (!journal_remove(l)) { locked(l, "JOURNAL_CLEANUP_FAILED_RECOVERY_LOCKED"); return FALSE; }
        l->restored = TRUE; l->stopped = TRUE;
        puts("{\"event\":\"restored\",\"ok\":true,\"networkUntouched\":true,\"temporaryProfileRemoved\":true}"); fflush(stdout);
        if (l->failed) emit_error(l->reason[0] ? l->reason : "TRANSFER_CANCELED");
        g_main_loop_quit(l->loop); return FALSE;
    }
    if (!l->cleaning) {
        l->cleaning = TRUE;
        if (target && l->touched) {
            GVariant *reply;
            if (find(l->before, target->path) || !target_identity(l, target) || !same_profile(l)) { locked(l, "TEMPORARY_PROFILE_HASH_NOT_PROVEN"); return FALSE; }
            else {
                reply = call(l, target->path, SERVICE, "Disconnect", NULL, NULL); if (reply) g_variant_unref(reply);
                reply = call(l, target->path, SERVICE, "Remove", NULL, NULL); l->clean_done = reply != NULL; if (reply) g_variant_unref(reply);
            }
        } else l->clean_done = l->target_profile_hash && target_profile_absent(l);
        if (l->old_path && old && !connected(old)) {
            if (l->operation) g_object_unref(l->operation);
            l->operation = g_cancellable_new(); async_connect(l, l->old_path, 20);
        }
        return TRUE;
    }
    if (l->clean_done && (!l->old_path || connected(old))) {
        gboolean other_active = FALSE;
        for (i = 0; i < rows->len; i++) { Network *n = g_ptr_array_index(rows, i); if (connected(n) && (!l->old_path || strcmp(n->path, l->old_path))) other_active = TRUE; }
        if (!other_active && (!target || !target->favorite) && target_profile_absent(l) && verify_power(l)) {
            if (!journal_remove(l)) { locked(l, "JOURNAL_CLEANUP_FAILED_RECOVERY_LOCKED"); return FALSE; }
            l->restored = TRUE; l->stopped = TRUE;
            printf("{\"event\":\"restored\",\"ok\":true,\"originalNetworkRestored\":true,\"temporaryProfileRemoved\":true}\n"); fflush(stdout);
            if (l->failed) emit_error(l->reason[0] ? l->reason : "TRANSFER_CANCELED");
            g_main_loop_quit(l->loop); return FALSE;
        }
    }
    if (g_get_monotonic_time() >= l->restore_deadline) {
        l->stopped = TRUE; l->failed = TRUE; emit_error("NETWORK_RESTORE_NOT_CONFIRMED"); g_main_loop_quit(l->loop); return FALSE;
    }
    return TRUE;
}
static gboolean tick(gpointer userdata) {
    Lease *l = userdata; GPtrArray *rows; gboolean keep = TRUE;
    if (l->stopped) return FALSE;
    if (l->prepared && !l->restoring) { if (g_get_monotonic_time() >= l->lease_deadline) begin_restore(l, "PREPARED_LEASE_EXPIRED"); return !l->stopped; }
    rows = networks(l);
    if (!rows) {
        if (!l->restoring) begin_restore(l, "CONNMAN_STATE_UNAVAILABLE");
        else if (g_get_monotonic_time() >= l->restore_deadline) { emit_error("NETWORK_RESTORE_NOT_CONFIRMED"); l->failed = TRUE; l->stopped = TRUE; g_main_loop_quit(l->loop); keep = FALSE; }
        return keep;
    }
    if (l->restoring) keep = restore_tick(l, rows);
    else {
        Network *target;
        if (!l->target) discover_target(l, rows);
        target = find(rows, l->target);
        if (!l->restoring && target && connected(target) && !l->connected) {
            if (!ipv4_address(target->address) || !ipv4_address(target->gateway)) begin_restore(l, "TARGET_IPV4_GATEWAY_UNAVAILABLE");
            else {
                GVariant *reply = call(l, target->path, SERVICE, "SetProperty", g_variant_new("(sv)", "AutoConnect", g_variant_new_boolean(FALSE)), NULL);
                if (!reply) begin_restore(l, "TEMPORARY_AUTOCONNECT_DISABLE_FAILED");
                else {
                    g_variant_unref(reply);
                    l->target_profile_hash = profile_hash(l);
                    if (!l->target_profile_hash || !journal_save(l, "connected", FALSE)) { locked(l, "TEMPORARY_PROFILE_HASH_NOT_PROVEN"); g_ptr_array_unref(rows); return FALSE; }
                    l->connected = TRUE; unregister_agent(l); wipe(l->command.psk, sizeof(l->command.psk));
                    l->lease_deadline = g_get_monotonic_time() + l->command.ttl * G_TIME_SPAN_SECOND;
                    /* Only actual IP and gateway are emitted, never credentials. */
                    printf("{\"event\":\"connected\",\"ok\":true,\"address\":\"%s\",\"gateway\":\"%s\",\"leaseSeconds\":%u}\n", target->address, target->gateway, l->command.ttl); fflush(stdout);
                }
            }
        }
        if (!l->restoring && !l->connected && g_get_monotonic_time() >= l->deadline) begin_restore(l, "TARGET_CONNECTION_TIMEOUT");
        if (!l->restoring && l->connected && (g_get_monotonic_time() >= l->lease_deadline || !connected(target))) begin_restore(l, "TEMPORARY_LEASE_ENDED");
    }
    g_ptr_array_unref(rows); return keep;
}
static gboolean start_receive(Lease *l, Command *command) {
    char *old_dir; guint64 pid, start;
    if (!MTA_CONNMAN_STA_VERIFIED) { begin_restore(l, "PRIOR_WIFI_OWNERSHIP_NOT_VERIFIED"); return TRUE; }
    if (command->kind != 4 || !owner_identity(l, &pid, &start) || !verify_power(l)) return FALSE;
    old_dir = g_strdup(l->command.journal_dir); wipe(&l->command, sizeof(l->command)); l->command = *command;
    g_strlcpy(l->command.journal_dir, old_dir, sizeof(l->command.journal_dir)); g_free(old_dir); l->prepared = FALSE;
    if (!register_agent(l)) { begin_restore(l, "CONNMAN_AGENT_REGISTER_FAILED"); return TRUE; }
    l->deadline = g_get_monotonic_time() + l->command.timeout * G_TIME_SPAN_SECOND;
    g_dbus_connection_call(l->bus, l->owner, l->wifi_path, TECHNOLOGY, "Scan", NULL, NULL, G_DBUS_CALL_FLAGS_NO_AUTO_START, (gint)l->command.timeout * 1000, l->operation, operation_done, l);
    puts("{\"event\":\"connecting\",\"ok\":true,\"snapshotCaptured\":true,\"preparedBaselineReused\":true}"); fflush(stdout); return TRUE;
}
static gboolean input_ready(GIOChannel *channel, GIOCondition condition, gpointer userdata) {
    Lease *l = userdata; char bytes[256]; gsize length = 0, i; Command command; GIOStatus result;
    if (condition & G_IO_IN) {
        result = g_io_channel_read_chars(channel, bytes, sizeof(bytes), &length, NULL);
        if (result == G_IO_STATUS_NORMAL) for (i = 0; i < length; i++) {
            if (bytes[i] == '\n') {
                gboolean valid;
                l->control[l->control_length] = 0; valid = parse_command(l->control, &command, TRUE);
                if (valid && command.kind == 1) begin_restore(l, "");
                else if (!valid || !l->prepared || l->restoring || !start_receive(l, &command)) begin_restore(l, "INVALID_LEASE_CONTROL");
                wipe(&command, sizeof(command)); wipe(l->control, sizeof(l->control)); l->control_length = 0;
            } else if (!bytes[i] || l->control_length >= COMMAND_MAX) {
                l->stdin_watch = 0; begin_restore(l, "INVALID_LEASE_CONTROL"); return FALSE;
            } else l->control[l->control_length++] = bytes[i];
        }
        if (result == G_IO_STATUS_EOF) { l->stdin_watch = 0; begin_restore(l, "PARENT_PIPE_CLOSED"); return FALSE; }
    }
    if (condition & (G_IO_HUP | G_IO_ERR | G_IO_NVAL)) { l->stdin_watch = 0; begin_restore(l, "PARENT_PIPE_CLOSED"); return FALSE; }
    return TRUE;
}
static gboolean interrupted(gpointer userdata) { begin_restore(userdata, "LEASE_INTERRUPTED"); return G_SOURCE_CONTINUE; }
static gboolean initial_line(char *line, size_t maximum) {
    fd_set reads; struct timeval timeout = {5, 0}; size_t n = 0;
    while (n + 1 < maximum) {
        char c; FD_ZERO(&reads); FD_SET(STDIN_FILENO, &reads);
        if (select(STDIN_FILENO + 1, &reads, NULL, NULL, &timeout) <= 0 || read(STDIN_FILENO, &c, 1) != 1) return FALSE;
        if (c == '\n') { line[n] = 0; return TRUE; }
        if (!c) return FALSE;
        line[n++] = c;
    }
    return FALSE;
}
static int self_test(void) {
    Command c;
    const char *good = "{\"cmd\":\"receive\",\"consented\":true,\"ssid_b64\":\"SE9TVA==\",\"psk_b64\":\"MTIzNDU2Nzg=\",\"timeout\":10,\"ttl\":10}";
    if (!parse_command(good, &c, FALSE) || strcmp(c.ssid, "HOST") || strcmp(c.psk, "12345678")) return 1;
    if (parse_command("{\"cmd\":\"receive\",\"consented\":false}", &c, FALSE) || parse_command("{\"cmd\":\"cancel\",\"cmd\":\"restore\"}", &c, TRUE) || parse_command("{\"cmd\":\"shell\"}", &c, TRUE) || !parse_command("{\"cmd\":\"restore\"}", &c, TRUE)) return 1;
    wipe(&c, sizeof(c)); puts("HOST_NETWORK_PARSER_SELFTEST_PASS"); return 0;
}
int main(int argc, char **argv) {
    Lease lease; char initial[COMMAND_MAX + 1]; int result = 1; guint i; unsigned active = 0;
    signal(SIGPIPE, SIG_IGN); /* Parent exit must not bypass restoration. */
    memset(&lease, 0, sizeof(lease)); memset(initial, 0, sizeof(initial));
    if (argc != 2 || (strcmp(argv[1], "--capabilities") && strcmp(argv[1], "--prepare") && strcmp(argv[1], "--recover") && strcmp(argv[1], "--receive") && strcmp(argv[1], "--self-test"))) { emit_error("FIXED_MODE_REQUIRED"); return 2; }
    if (!strcmp(argv[1], "--self-test")) return self_test();
    if (strcmp(argv[1], "--capabilities")) {
        unsigned expected = !strcmp(argv[1], "--prepare") ? 2 : !strcmp(argv[1], "--recover") ? 3 : 4;
        if (!initial_line(initial, sizeof(initial)) || !parse_command(initial, &lease.command, FALSE) || lease.command.kind != expected || (expected == 4 && !lease.command.journal_dir[0])) { wipe(initial, sizeof(initial)); wipe(&lease.command, sizeof(lease.command)); emit_error("EXPLICIT_CONSENT_AND_VALID_PRIVATE_COMMAND_REQUIRED"); return 2; }
        wipe(initial, sizeof(initial));
    }
    if (!private_bus(&lease)) { emit_error("CONNMAN_READONLY_PROBE_UNAVAILABLE"); goto out; }
    { guint64 pid, start; if (!owner_identity(&lease, &pid, &start)) { emit_error("CONNMAN_READONLY_PROBE_UNAVAILABLE"); goto out; } }
    if (!technologies(&lease, &lease.wifi_path, &lease.powered) || !(lease.before = networks(&lease))) { emit_error("CONNMAN_READONLY_PROBE_UNAVAILABLE"); goto out; }
    for (i = 0; i < lease.before->len; i++) { Network *n = g_ptr_array_index(lease.before, i); if (connected(n)) { active++; if (!lease.old_path) lease.old_path = g_strdup(n->path); } }
    if (!strcmp(argv[1], "--capabilities")) {
        printf("{\"event\":\"capabilities\",\"ok\":true,\"connman\":true,\"wifiPowered\":%s,\"receive\":%s,\"receiveVerified\":false,\"send\":false,\"p2pVerified\":false,\"concurrencyVerified\":false,\"reason\":\"%s\"}\n", lease.powered ? "true" : "false", MTA_CONNMAN_STA_VERIFIED && lease.powered && active <= 1 ? "true" : "false", !lease.powered ? "WIFI_POWERED_OFF_NO_AUTOMATIC_ENABLE" : active > 1 ? "MULTIPLE_WIFI_CONNECTIONS_UNSUPPORTED" : !MTA_CONNMAN_STA_VERIFIED ? "PRIOR_WIFI_OWNERSHIP_NOT_VERIFIED" : "SEND_P2P_AP_NOT_VERIFIED"); result = 0; goto out;
    }
    if ((!lease.powered || active > 1) && strcmp(argv[1], "--recover")) { emit_error(!lease.powered ? "WIFI_POWERED_OFF_NO_AUTOMATIC_ENABLE" : "MULTIPLE_WIFI_CONNECTIONS_UNSUPPORTED"); goto out; }
    lease.loop = g_main_loop_new(NULL, FALSE); lease.operation = g_cancellable_new();
    { guint64 pid, start; if (!owner_identity(&lease, &pid, &start)) { emit_error("CONNMAN_READONLY_PROBE_UNAVAILABLE"); goto out; } }
    if (!strcmp(argv[1], "--recover")) {
        if (!journal_load(&lease)) { emit_error("JOURNAL_IDENTITY_UNPROVEN_RECOVERY_LOCKED"); goto out; }
        begin_restore(&lease, "");
    } else {
        lease.profile_root = g_strdup(MTA_PROFILE_ROOT);
        if (!secure_directory(lease.profile_root, FALSE) || !journal_begin(&lease)) { emit_error("JOURNAL_PREPARE_FAILED_NETWORK_UNTOUCHED"); goto out; }
        lease.prepared = TRUE; lease.lease_deadline = g_get_monotonic_time() + lease.command.ttl * G_TIME_SPAN_SECOND;
        if (!strcmp(argv[1], "--receive")) { Command command = lease.command; if (!start_receive(&lease, &command)) { wipe(&command, sizeof(command)); begin_restore(&lease, "INVALID_LEASE_CONTROL"); } else wipe(&command, sizeof(command)); }
        else { printf("{\"event\":\"prepared\",\"ok\":true,\"networkUntouched\":true,\"snapshotCaptured\":true,\"leaseSeconds\":%u}\n", lease.command.ttl); fflush(stdout); }
    }
    lease.input = g_io_channel_unix_new(STDIN_FILENO); g_io_channel_set_encoding(lease.input, NULL, NULL); g_io_channel_set_buffered(lease.input, FALSE); g_io_channel_set_flags(lease.input, G_IO_FLAG_NONBLOCK, NULL);
    lease.stdin_watch = g_io_add_watch(lease.input, G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL, input_ready, &lease);
    lease.tick_id = g_timeout_add(300, tick, &lease);
    g_unix_signal_add(SIGINT, interrupted, &lease); g_unix_signal_add(SIGTERM, interrupted, &lease);
    g_main_loop_run(lease.loop); result = lease.restored && !lease.failed ? 0 : 1;
out:
    if (lease.bus) unregister_agent(&lease);
    if (lease.stdin_watch) g_source_remove(lease.stdin_watch);
    if (lease.input) g_io_channel_unref(lease.input);
    if (lease.operation) { g_cancellable_cancel(lease.operation); g_object_unref(lease.operation); }
    if (lease.loop) g_main_loop_unref(lease.loop);
    if (lease.before) g_ptr_array_unref(lease.before);
    if (lease.bus) g_object_unref(lease.bus);
    g_free(lease.wifi_path); g_free(lease.old_path); g_free(lease.target); g_free(lease.owner);
    g_free(lease.journal_path); g_free(lease.profile_root); g_free(lease.target_name_hash); g_free(lease.target_profile_hash);
    if (lease.journal) g_key_file_unref(lease.journal);
    wipe(&lease.command, sizeof(lease.command)); return result;
}
