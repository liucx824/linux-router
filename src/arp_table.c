#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#include "router.h"
#include "arp_table.h"
#include "utils.h"
#include "log.h"

#define ARP_BUCKETS 256

/* 哈希 256 桶，槽位用静态数组（确定性内存，无 per-entry malloc） */
typedef struct arp_entry {
    ip_t   ip;
    int    ifidx;
    uint8_t mac[6];
    _Atomic uint64_t last_seen;   /* CLOCK_MONOTONIC 秒，原子读写避免 rdlock 下刷新竞态 */
    int    used;
    int    next;                  /* 桶内链，-1 结尾 */
} arp_entry_t;

static arp_entry_t g_entries[ARP_CAP];
static int g_bucket[ARP_BUCKETS];
static pthread_rwlock_t g_lock = PTHREAD_RWLOCK_INITIALIZER;
static int g_timeout = ARP_TMO;

static uint64_t monotonic_now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec;
}

static uint32_t hash_ip(ip_t ip)
{
    return (ip * 2654435761u) >> 24;   /* 0..255 */
}

int arp_init(void)
{
    int i;
    for (i = 0; i < ARP_BUCKETS; i++)
        g_bucket[i] = -1;
    memset(g_entries, 0, sizeof(g_entries));
    for (i = 0; i < ARP_CAP; i++)
        g_entries[i].next = -1;
    g_timeout = ARP_TMO;
    LOG_INFO("arp_table: %d entries / %d buckets, timeout %ds", ARP_CAP, ARP_BUCKETS, g_timeout);
    return 0;
}

void arp_set_timeout(int sec)
{
    if (sec >= 10)
        g_timeout = sec;
}

int arp_lookup(ip_t ip, int ifidx, uint8_t mac_out[6])
{
    int idx;
    int hit = 0;
    uint64_t now = monotonic_now();

    pthread_rwlock_rdlock(&g_lock);
    idx = g_bucket[hash_ip(ip)];
    while (idx >= 0) {
        arp_entry_t *e = &g_entries[idx];
        if (e->used && e->ip == ip && e->ifidx == ifidx) {
            if (mac_out)
                memcpy(mac_out, e->mac, 6);
            atomic_store(&e->last_seen, now);   /* 命中刷新 */
            hit = 1;
            break;
        }
        idx = e->next;
    }
    pthread_rwlock_unlock(&g_lock);
    return hit;
}

/* 摘除槽位 slot 离开其所属桶链（须持写锁） */
static void bucket_remove_locked(int slot)
{
    int h = hash_ip(g_entries[slot].ip);
    int *cur = &g_bucket[h];
    while (*cur >= 0) {
        if (*cur == slot) {
            *cur = g_entries[slot].next;
            return;
        }
        cur = &g_entries[*cur].next;
    }
}

void arp_insert(ip_t ip, const uint8_t mac[6], int ifidx)
{
    uint64_t now = monotonic_now();
    int idx, free_idx = -1, i;

    pthread_rwlock_wrlock(&g_lock);

    /* 已存在：刷新 */
    idx = g_bucket[hash_ip(ip)];
    while (idx >= 0) {
        arp_entry_t *e = &g_entries[idx];
        if (e->used && e->ip == ip && e->ifidx == ifidx) {
            memcpy(e->mac, mac, 6);
            atomic_store(&e->last_seen, now);
            pthread_rwlock_unlock(&g_lock);
            return;
        }
        idx = e->next;
    }

    /* 新条目：找空槽，满则淘汰最旧 */
    for (i = 0; i < ARP_CAP; i++) {
        if (!g_entries[i].used) { free_idx = i; break; }
    }
    if (free_idx < 0) {
        uint64_t oldest = UINT64_MAX;
        for (i = 0; i < ARP_CAP; i++) {
            uint64_t t = atomic_load(&g_entries[i].last_seen);
            if (t < oldest) { oldest = t; free_idx = i; }
        }
        bucket_remove_locked(free_idx);
    }

    g_entries[free_idx].ip = ip;
    g_entries[free_idx].ifidx = ifidx;
    memcpy(g_entries[free_idx].mac, mac, 6);
    atomic_store(&g_entries[free_idx].last_seen, now);
    g_entries[free_idx].used = 1;
    g_entries[free_idx].next = g_bucket[hash_ip(ip)];
    g_bucket[hash_ip(ip)] = free_idx;

    pthread_rwlock_unlock(&g_lock);
}

void arp_delete(ip_t ip, int ifidx)
{
    int h = hash_ip(ip);
    int *cur;

    pthread_rwlock_wrlock(&g_lock);
    cur = &g_bucket[h];
    while (*cur >= 0) {
        int s = *cur;
        arp_entry_t *e = &g_entries[s];
        if (e->ip == ip && e->ifidx == ifidx) {
            *cur = e->next;
            e->used = 0;
            e->next = -1;
            break;
        }
        cur = &e->next;
    }
    pthread_rwlock_unlock(&g_lock);
}

void arp_tick(void)
{
    uint64_t now = monotonic_now();
    int i;

    pthread_rwlock_wrlock(&g_lock);
    for (i = 0; i < ARP_CAP; i++) {
        if (g_entries[i].used &&
            now - atomic_load(&g_entries[i].last_seen) > (uint64_t)g_timeout) {
            bucket_remove_locked(i);
            g_entries[i].used = 0;
            g_entries[i].next = -1;
            LOG_DEBUG("arp aging out %s on if=%d", ipbuf(g_entries[i].ip), g_entries[i].ifidx);
        }
    }
    pthread_rwlock_unlock(&g_lock);
}

int arp_count(void)
{
    int n = 0, i;

    pthread_rwlock_rdlock(&g_lock);
    for (i = 0; i < ARP_CAP; i++)
        if (g_entries[i].used)
            n++;
    pthread_rwlock_unlock(&g_lock);
    return n;
}

void arp_show(char *out, size_t outsz)
{
    size_t off = 0;
    uint64_t now = monotonic_now();
    int i;

    pthread_rwlock_rdlock(&g_lock);
    for (i = 0; i < ARP_CAP && off < outsz; i++) {
        arp_entry_t *e = &g_entries[i];
        if (e->used) {
            off += (size_t)snprintf(out + off, outsz - off,
                "%-15s  %-17s  if=%-2d  age=%llus\n",
                ipbuf(e->ip), macbuf(e->mac), e->ifidx,
                (unsigned long long)(now - atomic_load(&e->last_seen)));
        }
    }
    pthread_rwlock_unlock(&g_lock);
    if (off == 0)
        snprintf(out, outsz, "(empty)\n");
}
