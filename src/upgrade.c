#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <pthread.h>

#include "router.h"
#include "upgrade.h"
#include "config.h"
#include "sha256.h"
#include "log.h"

static pthread_mutex_t g_up_lock = PTHREAD_MUTEX_INITIALIZER;

static struct {
    int         in_progress;
    char        new_path[1024];   /* 需大于 exe_path+".new"，防 -Wformat-truncation */
    char        exe_path[512];
    FILE       *fp;
    sha256_ctx  hc;
    int         have_sha;
    uint8_t     expect[32];
    size_t      expected;
    size_t      received;
    uint8_t     first4[4];
    size_t      nfirst;
} g_up;

static int hex_digit(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex_to_bytes(const char *hex, uint8_t *out, size_t n)
{
    size_t i;
    int hi, lo;

    if (!hex || strlen(hex) != n * 2)
        return -1;
    for (i = 0; i < n; i++) {
        hi = hex_digit(hex[i * 2]);
        lo = hex_digit(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0)
            return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

int upgrade_begin(const char *sha_hex, size_t size, char *err, size_t errsz)
{
    ssize_t got;

    if (size == 0 || size > MAX_UPLOAD) {
        snprintf(err, errsz, "bad size %zu", size);
        return -1;
    }
    pthread_mutex_lock(&g_up_lock);
    if (g_up.in_progress) {
        pthread_mutex_unlock(&g_up_lock);
        snprintf(err, errsz, "upgrade already in progress");
        return -1;
    }

    got = readlink("/proc/self/exe", g_up.exe_path, sizeof(g_up.exe_path) - 1);
    if (got <= 0) {
        pthread_mutex_unlock(&g_up_lock);
        snprintf(err, errsz, "cannot resolve /proc/self/exe");
        return -1;
    }
    g_up.exe_path[got] = 0;
    snprintf(g_up.new_path, sizeof(g_up.new_path), "%s.new", g_up.exe_path);

    g_up.fp = fopen(g_up.new_path, "w");
    if (!g_up.fp) {
        pthread_mutex_unlock(&g_up_lock);
        snprintf(err, errsz, "cannot create %s", g_up.new_path);
        return -1;
    }
    g_up.expected = size;
    g_up.received = 0;
    g_up.nfirst = 0;
    g_up.have_sha = (sha_hex && strcmp(sha_hex, "-") != 0);
    if (g_up.have_sha) {
        if (hex_to_bytes(sha_hex, g_up.expect, 32) != 0) {
            fclose(g_up.fp);
            unlink(g_up.new_path);
            g_up.in_progress = 0;
            pthread_mutex_unlock(&g_up_lock);
            snprintf(err, errsz, "bad sha256 hex");
            return -1;
        }
        sha256_init(&g_up.hc);
    }
    g_up.in_progress = 1;
    pthread_mutex_unlock(&g_up_lock);

    LOG_WARN("upgrade begin: %zu bytes -> %s", size, g_up.exe_path);
    return 0;
}

int upgrade_write(const uint8_t *data, size_t len, char *err, size_t errsz)
{
    size_t first = 4 - g_up.nfirst;

    if (g_up.received + len > g_up.expected) {
        snprintf(err, errsz, "size exceeded");
        return -1;
    }
    if (g_up.nfirst < 4) {
        if (first > len)
            first = len;
        memcpy(g_up.first4 + g_up.nfirst, data, first);
        g_up.nfirst += first;
    }
    if (fwrite(data, 1, len, g_up.fp) != len) {
        snprintf(err, errsz, "write failed");
        return -1;
    }
    if (g_up.have_sha)
        sha256_update(&g_up.hc, data, len);
    g_up.received += len;
    return 0;
}

static void upgrade_cleanup_unlocked(void)
{
    if (g_up.fp) {
        fclose(g_up.fp);
        g_up.fp = NULL;
    }
    unlink(g_up.new_path);
    g_up.in_progress = 0;
}

int upgrade_finish(char *err, size_t errsz)
{
    int rc = 0;
    uint8_t digest[32];

    pthread_mutex_lock(&g_up_lock);
    if (!g_up.in_progress) {
        pthread_mutex_unlock(&g_up_lock);
        snprintf(err, errsz, "no upgrade in progress");
        return -1;
    }
    if (g_up.received != g_up.expected) {
        snprintf(err, errsz, "short upload: got %zu want %zu", g_up.received, g_up.expected);
        upgrade_cleanup_unlocked();
        pthread_mutex_unlock(&g_up_lock);
        return -1;
    }
    if (g_up.nfirst < 4 ||
        g_up.first4[0] != 0x7f || g_up.first4[1] != 'E' ||
        g_up.first4[2] != 'L'  || g_up.first4[3] != 'F') {
        snprintf(err, errsz, "not an ELF file");
        upgrade_cleanup_unlocked();
        pthread_mutex_unlock(&g_up_lock);
        return -1;
    }
    if (g_up.have_sha) {
        sha256_final(&g_up.hc, digest);
        if (memcmp(digest, g_up.expect, 32) != 0) {
            snprintf(err, errsz, "sha256 mismatch");
            upgrade_cleanup_unlocked();
            pthread_mutex_unlock(&g_up_lock);
            return -1;
        }
    }

    if (fclose(g_up.fp) != 0) {
        g_up.fp = NULL;
        snprintf(err, errsz, "finalize write failed");
        upgrade_cleanup_unlocked();
        pthread_mutex_unlock(&g_up_lock);
        return -1;
    }
    g_up.fp = NULL;
    chmod(g_up.new_path, 0755);

    if (rename(g_up.new_path, g_up.exe_path) != 0) {
        snprintf(err, errsz, "rename failed");
        upgrade_cleanup_unlocked();
        pthread_mutex_unlock(&g_up_lock);
        return -1;
    }
    if (config_save() != 0)     /* 重启前把配置落盘 */
        LOG_WARN("upgrade: config_save failed, continuing");
    g_up.in_progress = 0;
    pthread_mutex_unlock(&g_up_lock);

    LOG_WARN("upgrade validated, new binary installed -> %s", g_up.exe_path);
    return rc;
}

void upgrade_exec(void)
{
    char *argv[2];

    argv[0] = g_up.exe_path;
    argv[1] = NULL;
    LOG_WARN("upgrade execv(%s)", g_up.exe_path);
    fflush(stdout);
    execv(g_up.exe_path, argv);
    LOG_ERR("upgrade execv failed (new binary already in place)");
}

void upgrade_abort(void)
{
    pthread_mutex_lock(&g_up_lock);
    if (g_up.in_progress)
        upgrade_cleanup_unlocked();
    pthread_mutex_unlock(&g_up_lock);
}
