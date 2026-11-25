/* Original P011 ConnMan lease helper. Only documented Manager, Technology,
 * Service and Agent APIs are used. Profile bytes are streamed only into hashes,
 * never parsed, copied into journals or logged. No shell or password logs.
 * Credentials arrive as base64 over a private stdin pipe, never argv.
 *
 * This independent derivative retains the original source notice above. It
 * implements ONLY a read-only observer: no Agent, lease, credentials, journal,
 * scan, connect, disconnect, property write or profile-file access is present.
 * The only hash here is the actual ConnMan executable. Service paths identify
 * DBus objects/configuration, NOT original on-disk profile bytes. stdout is
 * private IPC: object paths and owner/process/IP identities are not public logs.
 * API reference: upstream ConnMan doc/{manager,technology,service}-api.txt.
 */
#define _GNU_SOURCE
#include <gio/gio.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SCHEMA "p011-connman-network-baseline-v1"
#define BUS "net.connman"
#define MANAGER "net.connman.Manager"
#define OBSERVE_US (8 * G_TIME_SPAN_SECOND)
#define CALL_MS 2000
#define PROC_MAX 65536
#define EXE_MAX (16 * 1024 * 1024)
#define REPLY_MAX (1024 * 1024)
#define PROPERTIES_MAX 65536
#define PROPERTY_COUNT_MAX 128
#define SERVICE_COUNT_MAX 128
#define TECHNOLOGY_COUNT_MAX 32
#define WIFI_TECHNOLOGY_COUNT_MAX 8
#define OUTPUT_MAX 65536
#define FD_COUNT_MAX 64

typedef struct {
    int fd;
    gboolean attempted, closed;
} FileTicket;

typedef struct {
    GDBusConnection *bus;
    gint64 until;
    FileTicket files[FD_COUNT_MAX];
    guint file_count;
    gboolean file_unknown, output_unknown;
} Observer;

typedef struct {
    char *owner, *exe;
    char boot[37], exe_sha[65];
    guint32 pid;
    guint64 start;
    struct stat process_directory;
} Identity;

typedef struct {
    char *path;
    GString *json;
} ObjectRow;

static gboolean active(Observer *o) {
    return g_get_monotonic_time() < o->until;
}

static gboolean same_file(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
        a->st_mode == b->st_mode && a->st_uid == b->st_uid &&
        a->st_gid == b->st_gid && a->st_nlink == b->st_nlink &&
        a->st_size == b->st_size && a->st_mtim.tv_sec == b->st_mtim.tv_sec &&
        a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
        a->st_ctim.tv_sec == b->st_ctim.tv_sec &&
        a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}

static gboolean same_directory(const struct stat *a, const struct stat *b) {
    /* /proc changes legitimately as unrelated processes appear/disappear. */
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
        a->st_mode == b->st_mode && a->st_uid == b->st_uid && a->st_gid == b->st_gid;
}

static int open_file(Observer *o, int parent, const char *path, int flags) {
    int fd;
    if (!active(o) || o->file_count == FD_COUNT_MAX) return -1;
    fd = parent < 0 ? open(path, flags) : openat(parent, path, flags);
    if (fd >= 0) {
        FileTicket *t = &o->files[o->file_count++];
        t->fd = fd; t->attempted = FALSE; t->closed = FALSE;
    }
    return fd;
}

static gboolean close_file(Observer *o, int fd) {
    guint i;
    struct stat discarded;
    if (fd < 0) return TRUE;
    for (i = o->file_count; i > 0; i--) {
        FileTicket *t = &o->files[i - 1];
        if (t->fd == fd && !t->attempted) {
            int result, error;
            t->attempted = TRUE;
            result = close(fd); error = errno;
            errno = 0;
            t->closed = result == 0 && fstat(fd, &discarded) == -1 && errno == EBADF;
            if (!t->closed) o->file_unknown = TRUE;
            errno = error;
            return t->closed;
        }
    }
    /* Never retry an ambiguous close or close a numeric descriptor twice. */
    o->file_unknown = TRUE;
    return FALSE;
}

static gboolean files_closed(Observer *o) {
    guint i;
    if (o->file_unknown) return FALSE;
    for (i = 0; i < o->file_count; i++)
        if (!o->files[i].attempted || !o->files[i].closed) return FALSE;
    return TRUE;
}

static char *read_text(Observer *o, int parent, const char *path, gsize maximum) {
    struct stat before, after;
    char *data = NULL;
    gsize used = 0;
    int fd = open_file(o, parent, path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    gboolean valid = FALSE;
    if (fd < 0) return NULL;
    if (fstat(fd, &before) || !S_ISREG(before.st_mode) || before.st_uid != 0 ||
            before.st_size < 0 || (guint64)before.st_size > maximum) goto out;
    data = g_malloc(maximum + 1);
    while (active(o)) {
        ssize_t n = read(fd, data + used, maximum + 1 - used);
        if (n < 0) { if (errno == EINTR) continue; goto out; }
        if (!n) {
            if (fstat(fd, &after) || !same_file(&before, &after) ||
                    memchr(data, 0, used)) goto out;
            data[used] = 0; valid = TRUE; break;
        }
        used += (gsize)n;
        if (used > maximum) goto out;
    }
out:
    if (!close_file(o, fd)) valid = FALSE;
    if (!valid) { g_free(data); data = NULL; }
    return data;
}

static gboolean decimal(const char *text, guint64 maximum, guint64 *value) {
    const char *p;
    char *end;
    guint64 v;
    if (!text || !*text || (text[0] == '0' && text[1])) return FALSE;
    for (p = text; *p; p++) if (*p < '0' || *p > '9') return FALSE;
    errno = 0; v = g_ascii_strtoull(text, &end, 10);
    if (errno || *end || v > maximum) return FALSE;
    *value = v; return TRUE;
}

static gboolean start_time(Observer *o, int process_fd, guint32 pid, guint64 *start) {
    char *text = read_text(o, process_fd, "stat", PROC_MAX), *end, *begin;
    char **fields = NULL;
    guint64 parsed_pid, flags, value;
    gboolean valid = FALSE;
    if (!text) return FALSE;
    begin = strchr(text, ' '); end = strrchr(text, ')');
    if (!begin || begin[1] != '(' || !end || end < begin || end[1] != ' ') goto out;
    *begin = 0;
    if (!decimal(text, G_MAXUINT32, &parsed_pid) || parsed_pid != pid) goto out;
    fields = g_strsplit(end + 2, " ", 0);
    if (g_strv_length(fields) < 20 || strlen(fields[0]) != 1 ||
            !strchr("RSDI", fields[0][0]) ||
            !decimal(fields[6], G_MAXUINT32, &flags) || (flags & 0x00200000) ||
            !decimal(fields[19], G_MAXUINT64, &value) || !value) goto out;
    *start = value; valid = TRUE;
out:
    g_strfreev(fields); g_free(text); return valid;
}

static gboolean boot_id(Observer *o, char output[37]) {
    char *text = read_text(o, -1, "/proc/sys/kernel/random/boot_id", PROC_MAX);
    gsize i, size;
    gboolean valid = FALSE;
    if (!text) return FALSE;
    size = strlen(text);
    if (size == 37 && text[36] == '\n') text[--size] = 0;
    if (size != 36) goto out;
    for (i = 0; i < size; i++) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (text[i] != '-') goto out;
        } else if (!strchr("0123456789abcdef", text[i])) goto out;
    }
    memcpy(output, text, 37); valid = TRUE;
out:
    g_free(text); return valid;
}

static gboolean ascii_text(const char *text, gsize maximum, gboolean empty) {
    const unsigned char *p = (const unsigned char *)text;
    if (!text || strlen(text) > maximum || (!empty && !*text)) return FALSE;
    for (; *p; p++) if (*p < 32 || *p > 126) return FALSE;
    return TRUE;
}

static char *exe_path(int process_fd) {
    char path[PATH_MAX];
    ssize_t n = readlinkat(process_fd, "exe", path, sizeof(path) - 1);
    if (n <= 0 || n >= (ssize_t)sizeof(path) - 1) return NULL;
    path[n] = 0;
    if (path[0] != '/' || !ascii_text(path, sizeof(path) - 1, FALSE) ||
            g_str_has_suffix(path, " (deleted)") || strstr(path, "/../") ||
            strstr(path, "/./") || strstr(path, "//")) return NULL;
    return g_strdup(path);
}

static gboolean exe_hash(Observer *o, int process_fd, const char *path, char output[65]) {
    int fd;
    struct stat before, after, edge;
    GChecksum *hash = NULL;
    guint64 count = 0;
    char data[16384];
    gboolean valid = FALSE;
    /* The /proc/PID/exe magic link intentionally identifies the running image. */
    fd = open_file(o, process_fd, "exe", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return FALSE;
    if (fstat(fd, &before) || !S_ISREG(before.st_mode) || before.st_uid != 0 ||
            !before.st_nlink || before.st_size <= 0 || before.st_size > EXE_MAX ||
            stat(path, &edge) || !same_file(&before, &edge)) goto out;
    hash = g_checksum_new(G_CHECKSUM_SHA256);
    while (active(o)) {
        ssize_t n = read(fd, data, sizeof(data));
        if (n < 0) { if (errno == EINTR) continue; goto out; }
        if (!n) {
            if (count != (guint64)before.st_size || fstat(fd, &after) ||
                    !same_file(&before, &after) || stat(path, &edge) ||
                    !same_file(&before, &edge)) goto out;
            memcpy(output, g_checksum_get_string(hash), 65); valid = TRUE; break;
        }
        count += (guint64)n;
        if (count > EXE_MAX) goto out;
        g_checksum_update(hash, (const guchar *)data, (gsize)n);
    }
out:
    memset(data, 0, sizeof(data));
    if (hash) g_checksum_free(hash);
    if (!close_file(o, fd)) valid = FALSE;
    return valid;
}

static GVariant *call(Observer *o, const char *destination, const char *path,
        const char *interface, const char *method, GVariant *parameters,
        const GVariantType *type, gsize maximum) {
    GError *error = NULL;
    GVariant *reply;
    gint64 remaining = o->until - g_get_monotonic_time();
    gint timeout;
    if (!o->bus || remaining < 1000) {
        if (parameters) {
            g_variant_ref_sink(parameters);
            g_variant_unref(parameters);
        }
        return NULL;
    }
    timeout = (gint)MIN((gint64)CALL_MS, remaining / 1000);
    reply = g_dbus_connection_call_sync(o->bus, destination, path, interface,
        method, parameters, type, G_DBUS_CALL_FLAGS_NO_AUTO_START,
        timeout, NULL, &error);
    if (error) g_error_free(error); /* Never print remote message/path/SSID. */
    if (reply && (!active(o) || !g_variant_is_of_type(reply, type) ||
            g_variant_get_size(reply) > maximum)) {
        g_variant_unref(reply); reply = NULL;
    }
    return reply;
}

static void identity_free(Identity *identity) {
    g_free(identity->owner); g_free(identity->exe);
    memset(identity, 0, sizeof(*identity));
}

static gboolean identity_read(Observer *o, Identity *identity) {
    GVariant *reply = NULL;
    const char *owner;
    guint32 pid;
    char name[32], second_boot[37], *second_exe = NULL;
    guint64 second_start = 0;
    int proc_fd = -1, process_fd = -1;
    struct stat proc_before, proc_after, edge, after;
    gboolean valid = FALSE;
    reply = call(o, "org.freedesktop.DBus", "/org/freedesktop/DBus",
        "org.freedesktop.DBus", "GetNameOwner", g_variant_new("(s)", BUS),
        G_VARIANT_TYPE("(s)"), 256);
    if (!reply) goto out;
    g_variant_get(reply, "(&s)", &owner);
    if (!ascii_text(owner, 64, FALSE) || !g_dbus_is_unique_name(owner)) goto out;
    identity->owner = g_strdup(owner);
    g_variant_unref(reply); reply = NULL;
    reply = call(o, "org.freedesktop.DBus", "/org/freedesktop/DBus",
        "org.freedesktop.DBus", "GetConnectionUnixProcessID",
        g_variant_new("(s)", identity->owner), G_VARIANT_TYPE("(u)"), 64);
    if (!reply) goto out;
    g_variant_get(reply, "(u)", &pid);
    if (!pid || pid > G_MAXINT32) goto out;
    identity->pid = pid;
    g_variant_unref(reply); reply = NULL;
    proc_fd = open_file(o, -1, "/proc", O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    if (proc_fd < 0 || fstat(proc_fd, &proc_before) || !S_ISDIR(proc_before.st_mode) ||
            proc_before.st_uid != 0 || lstat("/proc", &edge) ||
            !same_directory(&proc_before, &edge)) goto out;
    g_snprintf(name, sizeof(name), "%u", (unsigned)pid);
    process_fd = open_file(o, proc_fd, name, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    if (process_fd < 0 || fstat(process_fd, &identity->process_directory) ||
            !S_ISDIR(identity->process_directory.st_mode) || identity->process_directory.st_uid != 0 ||
            fstatat(proc_fd, name, &edge, AT_SYMLINK_NOFOLLOW) ||
            !same_directory(&identity->process_directory, &edge) ||
            !start_time(o, process_fd, pid, &identity->start)) goto out;
    identity->exe = exe_path(process_fd);
    if (!identity->exe || !exe_hash(o, process_fd, identity->exe, identity->exe_sha) ||
            !boot_id(o, identity->boot) ||
            !start_time(o, process_fd, pid, &second_start) ||
            !(second_exe = exe_path(process_fd)) || !boot_id(o, second_boot) ||
            identity->start != second_start || strcmp(identity->exe, second_exe) ||
            strcmp(identity->boot, second_boot) ||
            fstat(process_fd, &after) || !same_directory(&identity->process_directory, &after) ||
            fstatat(proc_fd, name, &edge, AT_SYMLINK_NOFOLLOW) ||
            !same_directory(&identity->process_directory, &edge) ||
            fstat(proc_fd, &proc_after) || !same_directory(&proc_before, &proc_after) ||
            lstat("/proc", &edge) || !same_directory(&proc_before, &edge) || !active(o)) goto out;
    valid = TRUE;
out:
    if (reply) g_variant_unref(reply);
    g_free(second_exe);
    if (!close_file(o, process_fd)) valid = FALSE;
    if (!close_file(o, proc_fd)) valid = FALSE;
    if (!valid) identity_free(identity);
    return valid;
}

static gboolean identity_same(const Identity *a, const Identity *b) {
    return a->owner && b->owner && a->exe && b->exe &&
        !strcmp(a->owner, b->owner) && a->pid == b->pid && a->start == b->start &&
        !strcmp(a->boot, b->boot) && !strcmp(a->exe, b->exe) &&
        !strcmp(a->exe_sha, b->exe_sha) &&
        same_directory(&a->process_directory, &b->process_directory);
}

static gboolean properties_valid(GVariant *properties) {
    GVariantIter iter;
    const char *key;
    GVariant *value;
    GHashTable *seen;
    gboolean valid = TRUE;
    if (!g_variant_is_of_type(properties, G_VARIANT_TYPE("a{sv}")) ||
            g_variant_n_children(properties) > PROPERTY_COUNT_MAX ||
            g_variant_get_size(properties) > PROPERTIES_MAX) return FALSE;
    seen = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    g_variant_iter_init(&iter, properties);
    while (g_variant_iter_next(&iter, "{&sv}", &key, &value)) {
        if (!ascii_text(key, 64, FALSE) || g_hash_table_contains(seen, key)) valid = FALSE;
        else g_hash_table_add(seen, g_strdup(key));
        g_variant_unref(value);
        if (!valid) break;
    }
    g_hash_table_unref(seen); return valid;
}

static gboolean property(GVariant *properties, const char *key,
        const GVariantType *type, gboolean required, GVariant **value, gboolean *present) {
    *value = g_variant_lookup_value(properties, key, NULL);
    *present = *value != NULL;
    if (!*present) return !required;
    if (!g_variant_is_of_type(*value, type)) {
        g_variant_unref(*value); *value = NULL; return FALSE;
    }
    return TRUE;
}

static void append(Observer *o, GString *output, const char *text) {
    gsize length = strlen(text);
    if (o->output_unknown || output->len + length > OUTPUT_MAX) {
        o->output_unknown = TRUE; return;
    }
    g_string_append_len(output, text, length);
}

static void string(Observer *o, GString *output, const char *text) {
    const unsigned char *p;
    char escape[8];
    if (!text) { append(o, output, "null"); return; }
    append(o, output, "\"");
    for (p = (const unsigned char *)text; *p; p++) {
        if (*p == '\\' || *p == '"') {
            escape[0] = '\\'; escape[1] = (char)*p; escape[2] = 0;
        } else if (*p < 32 || *p > 126) {
            g_snprintf(escape, sizeof(escape), "\\u%04x", (unsigned)*p);
        } else { escape[0] = (char)*p; escape[1] = 0; }
        append(o, output, escape);
    }
    append(o, output, "\"");
}

static void number(Observer *o, GString *output, guint64 value) {
    char text[32];
    g_snprintf(text, sizeof(text), "%" G_GUINT64_FORMAT, value);
    append(o, output, text);
}

static gboolean object_path(const char *path, const char *prefix) {
    const char *p;
    if (!path || !g_str_has_prefix(path, prefix) || strlen(path) > 256) return FALSE;
    p = path + strlen(prefix);
    if (!*p) return FALSE;
    for (; *p; p++) if (!g_ascii_isalnum(*p) && *p != '_') return FALSE;
    return TRUE;
}

static void object_free(gpointer data) {
    ObjectRow *row = data;
    g_free(row->path); g_string_free(row->json, TRUE); g_free(row);
}

static gint object_compare(gconstpointer left, gconstpointer right) {
    const ObjectRow *a = *(ObjectRow *const *)left;
    const ObjectRow *b = *(ObjectRow *const *)right;
    return strcmp(a->path, b->path);
}

static gboolean required_text(GVariant *properties, const char *key, char **output) {
    GVariant *value = NULL;
    gboolean present, valid;
    const char *text;
    if (!property(properties, key, G_VARIANT_TYPE_STRING, TRUE, &value, &present)) return FALSE;
    text = g_variant_get_string(value, NULL);
    valid = ascii_text(text, 32, FALSE);
    if (valid) *output = g_strdup(text);
    g_variant_unref(value); return valid;
}

static gboolean optional_boolean(Observer *o, GString *output, GVariant *properties,
        const char *key) {
    GVariant *value = NULL;
    gboolean present;
    if (!property(properties, key, G_VARIANT_TYPE_BOOLEAN, FALSE, &value, &present)) return FALSE;
    append(o, output, present ? "{\"present\":true,\"value\":" : "{\"present\":false,\"value\":");
    append(o, output, !present ? "null" : g_variant_get_boolean(value) ? "true" : "false");
    append(o, output, "}");
    if (value) g_variant_unref(value);
    return !o->output_unknown;
}

static gboolean ip_dictionary(Observer *o, GString *output, GVariant *value, gboolean ipv6) {
    static const char *v4[] = {"Method", "Address", "Netmask", "Gateway", NULL};
    static const char *v6[] = {"Method", "Address", "PrefixLength", "Gateway", "Privacy", NULL};
    const char **keys = ipv6 ? v6 : v4;
    GVariantIter iter;
    GVariant *child;
    const char *key;
    guint i, written = 0;
    if (!properties_valid(value)) return FALSE;
    g_variant_iter_init(&iter, value);
    while (g_variant_iter_next(&iter, "{&sv}", &key, &child)) {
        gboolean found = FALSE;
        for (i = 0; keys[i]; i++) if (!strcmp(key, keys[i])) { found = TRUE; break; }
        g_variant_unref(child);
        if (!found) return FALSE; /* Do not silently truncate configuration. */
    }
    append(o, output, "{");
    for (i = 0; keys[i]; i++) {
        gboolean present;
        gboolean prefix = ipv6 && !strcmp(keys[i], "PrefixLength");
        const GVariantType *type = prefix ? G_VARIANT_TYPE_BYTE : G_VARIANT_TYPE_STRING;
        if (!property(value, keys[i], type, FALSE, &child, &present)) return FALSE;
        if (!present) continue;
        if (written++) append(o, output, ",");
        string(o, output, keys[i]); append(o, output, ":");
        if (prefix) {
            guint8 length = g_variant_get_byte(child);
            if (length > 128) { g_variant_unref(child); return FALSE; }
            number(o, output, length);
        } else {
            const char *text = g_variant_get_string(child, NULL);
            if (!ascii_text(text, 128, TRUE)) { g_variant_unref(child); return FALSE; }
            string(o, output, text);
        }
        g_variant_unref(child);
    }
    append(o, output, "}"); return !o->output_unknown;
}

static gboolean nameservers(Observer *o, GString *output, GVariant *value) {
    GVariantIter iter;
    const char *text;
    GHashTable *seen;
    guint written = 0;
    gboolean valid = TRUE;
    if (g_variant_n_children(value) > 32 || g_variant_get_size(value) > 8192) return FALSE;
    seen = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    append(o, output, "["); g_variant_iter_init(&iter, value);
    while (g_variant_iter_next(&iter, "&s", &text)) {
        if (!ascii_text(text, 255, FALSE) || g_hash_table_contains(seen, text)) { valid = FALSE; break; }
        g_hash_table_add(seen, g_strdup(text));
        if (written++) append(o, output, ",");
        string(o, output, text); /* Original priority order, NOT a sorted set. */
    }
    append(o, output, "]");
    g_hash_table_unref(seen); return valid && !o->output_unknown;
}

static gboolean optional_config(Observer *o, GString *output, GVariant *properties,
        const char *key, guint kind) {
    GVariant *value = NULL;
    gboolean present, valid = TRUE;
    const GVariantType *type = kind == 2 ? G_VARIANT_TYPE_STRING_ARRAY : G_VARIANT_TYPE("a{sv}");
    if (!property(properties, key, type, FALSE, &value, &present)) return FALSE;
    append(o, output, present ? "{\"present\":true,\"value\":" : "{\"present\":false,\"value\":");
    if (!present) append(o, output, "null");
    else valid = kind == 2 ? nameservers(o, output, value) : ip_dictionary(o, output, value, kind == 1);
    append(o, output, "}");
    if (value) g_variant_unref(value);
    return valid && !o->output_unknown;
}

static ObjectRow *technology(Observer *o, const char *path, GVariant *properties) {
    ObjectRow *row = NULL;
    GVariant *value = NULL;
    gboolean present;
    if (!property(properties, "Powered", G_VARIANT_TYPE_BOOLEAN, TRUE, &value, &present)) return NULL;
    row = g_new0(ObjectRow, 1); row->path = g_strdup(path); row->json = g_string_new(NULL);
    append(o, row->json, "{\"path\":"); string(o, row->json, path);
    append(o, row->json, ",\"powered\":");
    append(o, row->json, g_variant_get_boolean(value) ? "true}" : "false}");
    g_variant_unref(value);
    if (o->output_unknown) { object_free(row); row = NULL; }
    return row;
}

static ObjectRow *service(Observer *o, const char *path, GVariant *properties) {
    ObjectRow *row;
    char *state = NULL;
    if (!g_str_has_prefix(path, "/net/connman/service/wifi_") ||
            !required_text(properties, "State", &state)) return NULL;
    row = g_new0(ObjectRow, 1); row->path = g_strdup(path); row->json = g_string_new(NULL);
    append(o, row->json, "{\"path\":"); string(o, row->json, path);
    append(o, row->json, ",\"state\":"); string(o, row->json, state); g_free(state);
    append(o, row->json, ",\"auto_connect\":");
    if (!optional_boolean(o, row->json, properties, "AutoConnect")) goto invalid;
    append(o, row->json, ",\"favorite\":");
    if (!optional_boolean(o, row->json, properties, "Favorite")) goto invalid;
    append(o, row->json, ",\"immutable\":");
    if (!optional_boolean(o, row->json, properties, "Immutable")) goto invalid;
    append(o, row->json, ",\"ipv4\":");
    if (!optional_config(o, row->json, properties, "IPv4", 0)) goto invalid;
    append(o, row->json, ",\"ipv6\":");
    if (!optional_config(o, row->json, properties, "IPv6", 1)) goto invalid;
    append(o, row->json, ",\"nameservers\":");
    if (!optional_config(o, row->json, properties, "Nameservers", 2)) goto invalid;
    append(o, row->json, ",\"ipv4_configuration\":");
    if (!optional_config(o, row->json, properties, "IPv4.Configuration", 0)) goto invalid;
    append(o, row->json, ",\"ipv6_configuration\":");
    if (!optional_config(o, row->json, properties, "IPv6.Configuration", 1)) goto invalid;
    append(o, row->json, ",\"nameservers_configuration\":");
    if (!optional_config(o, row->json, properties, "Nameservers.Configuration", 2)) goto invalid;
    append(o, row->json, "}");
    if (!o->output_unknown) return row;
invalid:
    object_free(row); return NULL;
}

static GPtrArray *objects(Observer *o, const char *owner, gboolean wifi_technologies) {
    GVariant *reply, *rows, *properties;
    GVariantIter iter;
    const char *path;
    const char *prefix = wifi_technologies ? "/net/connman/technology/" : "/net/connman/service/";
    guint maximum = wifi_technologies ? TECHNOLOGY_COUNT_MAX : SERVICE_COUNT_MAX;
    GPtrArray *result = NULL;
    GHashTable *seen = NULL;
    gboolean valid = TRUE;
    reply = call(o, owner, "/", MANAGER, wifi_technologies ? "GetTechnologies" : "GetServices",
        NULL, G_VARIANT_TYPE("(a(oa{sv}))"), REPLY_MAX);
    if (!reply) return NULL;
    rows = g_variant_get_child_value(reply, 0);
    if (g_variant_n_children(rows) > maximum) { valid = FALSE; goto out; }
    result = g_ptr_array_new_with_free_func(object_free);
    seen = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    g_variant_iter_init(&iter, rows);
    while (g_variant_iter_next(&iter, "(&o@a{sv})", &path, &properties)) {
        char *type = NULL;
        ObjectRow *row = NULL;
        if (!active(o) || !object_path(path, prefix) || g_hash_table_contains(seen, path) ||
                !properties_valid(properties) || !required_text(properties, "Type", &type)) valid = FALSE;
        else {
            g_hash_table_add(seen, g_strdup(path));
            if (!strcmp(type, "wifi")) {
                if (wifi_technologies && result->len == WIFI_TECHNOLOGY_COUNT_MAX) valid = FALSE;
                else {
                    row = wifi_technologies ? technology(o, path, properties) : service(o, path, properties);
                    if (!row) valid = FALSE;
                    else g_ptr_array_add(result, row);
                }
            }
        }
        g_free(type); g_variant_unref(properties);
        if (!valid) break;
    }
out:
    if (seen) g_hash_table_unref(seen);
    g_variant_unref(rows); g_variant_unref(reply);
    if (!valid || !active(o)) { if (result) g_ptr_array_unref(result); return NULL; }
    g_ptr_array_sort(result, object_compare);
    return result;
}

static gboolean private_bus(Observer *o) {
    GError *error = NULL;
    char *address;
    if (!active(o)) return FALSE;
    address = g_dbus_address_get_for_bus_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
    if (address) {
        o->bus = g_dbus_connection_new_for_address_sync(address,
            G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT |
            G_DBUS_CONNECTION_FLAGS_MESSAGE_BUS_CONNECTION, NULL, NULL, &error);
    }
    g_free(address); if (error) g_error_free(error);
    if (o->bus) g_dbus_connection_set_exit_on_close(o->bus, FALSE);
    return o->bus != NULL && active(o);
}

static void array(Observer *o, GString *output, GPtrArray *rows) {
    guint i;
    if (!rows) { append(o, output, "null"); return; }
    append(o, output, "[");
    for (i = 0; i < rows->len; i++) {
        ObjectRow *row = g_ptr_array_index(rows, i);
        if (i) append(o, output, ",");
        append(o, output, row->json->str);
    }
    append(o, output, "]");
}

static GString *result(Observer *o, const Identity *identity, gboolean known,
        GPtrArray *technologies, GPtrArray *services, gboolean bus_closed, const char *reason) {
    GString *output = g_string_new(NULL);
    gboolean closed = files_closed(o);
    gboolean ok = known && technologies && services && bus_closed && closed && active(o);
    append(o, output, "{\"network_schema\":\"" SCHEMA "\",\"event\":\"network_observation\",\"ok\":");
    append(o, output, ok ? "true" : "false");
    append(o, output, ",\"identity_known\":"); append(o, output, known ? "true" : "false");
    append(o, output, ",\"connman_owner\":"); string(o, output, known ? identity->owner : NULL);
    append(o, output, ",\"connman_pid\":"); if (known) number(o, output, identity->pid); else append(o, output, "null");
    append(o, output, ",\"connman_start\":"); if (known) number(o, output, identity->start); else append(o, output, "null");
    append(o, output, ",\"boot_id\":"); string(o, output, known ? identity->boot : NULL);
    append(o, output, ",\"connman_exe\":"); string(o, output, known ? identity->exe : NULL);
    append(o, output, ",\"connman_exe_sha256\":"); string(o, output, known ? identity->exe_sha : NULL);
    append(o, output, ",\"technologies_known\":"); append(o, output, known && technologies ? "true" : "false");
    append(o, output, ",\"technologies\":"); array(o, output, known ? technologies : NULL);
    append(o, output, ",\"services_known\":"); append(o, output, known && services ? "true" : "false");
    append(o, output, ",\"services\":"); array(o, output, known ? services : NULL);
    append(o, output, ",\"bus_closed\":"); append(o, output, bus_closed ? "true" : "false");
    append(o, output, ",\"proc_files_closed\":"); append(o, output, closed ? "true" : "false");
    append(o, output, ",\"profile_bytes_observed\":false,\"reason\":"); string(o, output, reason);
    append(o, output, "}\n");
    return output;
}

int main(int argc, char **argv) {
    Observer o;
    Identity before, after;
    GPtrArray *technologies = NULL, *services = NULL;
    GString *output;
    struct itimerval timer;
    struct sigaction action;
    gint64 remaining;
    gboolean known = FALSE, bus_closed = FALSE, ok;
    const char *reason = "identity_unknown";
    int exit_code = 2;
    memset(&o, 0, sizeof(o)); memset(&before, 0, sizeof(before)); memset(&after, 0, sizeof(after));
    o.until = g_get_monotonic_time() + OBSERVE_US;
    /* Native hard timeout is armed before private-bus setup or any IO. A
     * forced exit has no success/closure output and must remain unknown. */
    memset(&action, 0, sizeof(action)); action.sa_handler = SIG_DFL;
    if (sigemptyset(&action.sa_mask) || sigaction(SIGALRM, &action, NULL)) return 2;
    remaining = o.until - g_get_monotonic_time();
    if (remaining <= 0) return 2;
    memset(&timer, 0, sizeof(timer));
    timer.it_value.tv_sec = (time_t)(remaining / G_TIME_SPAN_SECOND);
    timer.it_value.tv_usec = (suseconds_t)(remaining % G_TIME_SPAN_SECOND);
    if (setitimer(ITIMER_REAL, &timer, NULL)) return 2;
    if (argc != 2 || strcmp(argv[1], "--observe")) { reason = "fixed_mode_required"; goto close; }
    if (geteuid() != 0) { reason = "target_identity_unknown"; goto close; }
    if (!private_bus(&o)) { reason = "bus_unknown"; goto close; }
    if (!identity_read(&o, &before)) goto close;
    technologies = objects(&o, before.owner, TRUE);
    services = objects(&o, before.owner, FALSE);
    known = identity_read(&o, &after) && identity_same(&before, &after);
    if (!known) reason = "identity_changed";
    else if (!technologies || !services) reason = "inventory_unknown";
    else reason = "ok";
close:
    /* Physical close is attempted even if the activity clock has expired. */
    if (o.bus) {
        GError *error = NULL;
        gboolean returned = g_dbus_connection_close_sync(o.bus, NULL, &error);
        bus_closed = returned && !error && g_dbus_connection_is_closed(o.bus);
        if (error) g_error_free(error);
        g_object_unref(o.bus); o.bus = NULL;
    }
    if (!active(&o)) { known = FALSE; reason = "deadline"; }
    else if (!files_closed(&o)) reason = "file_close_unknown";
    else if (!bus_closed && known) reason = "bus_close_unknown";
    output = result(&o, &before, known, technologies, services, bus_closed, reason);
    ok = known && technologies && services && bus_closed && files_closed(&o) &&
        !o.output_unknown && active(&o);
    if (o.output_unknown) {
        /* Do not emit a truncated object or turn a limit into a known []. */
        o.output_unknown = FALSE; g_string_free(output, TRUE);
        output = result(&o, &before, FALSE, NULL, NULL, bus_closed, "output_budget");
        ok = FALSE;
    }
    if (technologies) g_ptr_array_unref(technologies);
    if (services) g_ptr_array_unref(services);
    identity_free(&before); identity_free(&after);
    if (output->len <= OUTPUT_MAX && fwrite(output->str, 1, output->len, stdout) == output->len &&
            fflush(stdout) == 0 && active(&o) && ok) exit_code = 0;
    g_string_free(output, TRUE);
    return exit_code;
}
