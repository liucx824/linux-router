#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#include "router.h"
#include "forward.h"
#include "arp_table.h"
#include "arp_proto.h"
#include "route.h"
#include "firewall.h"
#include "interface.h"
#include "packet.h"
#include "utils.h"
#include "log.h"

/* ==================================================================
 * pending 队列：按 (nexthop, out_ifidx) 合并成帧链，一链一 ARP 请求，
 * 防止 ARP 请求风暴。帧链通过 fwd_frame.next 串接，所有权单一。
 * 锁序铁律：本模块所有路径要么只持 pend 锁、要么先 arp 后 pend，
 * 永不持 pend 锁再去取 arp 锁（防交叉等待死锁）。
 * ================================================================== */

typedef struct pend_node {
    ip_t         nexthop;
    int          ifidx;
    int          retries;
    uint64_t     last_sent;   /* CLOCK_MONOTONIC 秒 */
    fwd_frame_t *chain;
    int          chain_len;
    int          next;        /* 链表索引，-1 结尾 */
    int          used;
} pend_node_t;

static pend_node_t g_pend[PEND_MAX];
static int g_pend_head = -1;
static pthread_mutex_t g_pend_lock = PTHREAD_MUTEX_INITIALIZER;

static uint64_t monotonic_now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec;
}

static int find_pend_locked(ip_t ip, int ifidx)
{
    int idx = g_pend_head;
    while (idx >= 0) {
        if (g_pend[idx].used && g_pend[idx].nexthop == ip && g_pend[idx].ifidx == ifidx)
            return idx;
        idx = g_pend[idx].next;
    }
    return -1;
}

static void unlink_node_locked(int idx)
{
    int *cur = &g_pend_head;
    while (*cur >= 0) {
        if (*cur == idx) {
            *cur = g_pend[idx].next;
            return;
        }
        cur = &g_pend[*cur].next;
    }
}

/* 分配槽位（须持锁）；满则淘汰最旧链并释放其帧 */
static int alloc_pend_locked(void)
{
    int i, victim = -1;
    uint64_t oldest = UINT64_MAX;

    for (i = 0; i < PEND_MAX; i++) {
        if (!g_pend[i].used)
            return i;
        if (g_pend[i].last_sent < oldest) {
            oldest = g_pend[i].last_sent;
            victim = i;
        }
    }
    if (victim < 0)
        return -1;
    unlink_node_locked(victim);
    {
        fwd_frame_t *ch = g_pend[victim].chain;
        g_pend[victim].chain = NULL;
        g_pend[victim].chain_len = 0;
        while (ch) {
            fwd_frame_t *b = ch;
            ch = b->next;
            mp_free(b);
        }
    }
    g_pend_drop++;
    g_drop++;
    LOG_WARN("pend table full, evicted %s on if=%d", ipbuf(g_pend[victim].nexthop), g_pend[victim].ifidx);
    return victim;
}

static void pend_enqueue(ip_t nexthop, int ifidx, fwd_frame_t *blk)
{
    uint64_t now = monotonic_now();
    int idx;

    pthread_mutex_lock(&g_pend_lock);
    idx = find_pend_locked(nexthop, ifidx);
    if (idx >= 0) {
        pend_node_t *n = &g_pend[idx];
        if (n->chain_len >= PEND_CHAIN_MAX) {
            pthread_mutex_unlock(&g_pend_lock);
            g_pend_drop++;
            g_drop++;
            mp_free(blk);
            return;
        }
        blk->next = n->chain;      /* 头插帧链 */
        n->chain = blk;
        n->chain_len++;
        n->last_sent = now;
        pthread_mutex_unlock(&g_pend_lock);
        return;
    }

    idx = alloc_pend_locked();
    if (idx < 0) {
        pthread_mutex_unlock(&g_pend_lock);
        g_pend_drop++;
        g_drop++;
        mp_free(blk);
        return;
    }
    g_pend[idx].nexthop = nexthop;
    g_pend[idx].ifidx = ifidx;
    g_pend[idx].retries = 0;
    g_pend[idx].last_sent = now;
    g_pend[idx].chain = blk;
    g_pend[idx].chain_len = 1;
    g_pend[idx].next = g_pend_head;
    g_pend[idx].used = 1;
    g_pend_head = idx;
    pthread_mutex_unlock(&g_pend_lock);

    LOG_DEBUG("pending %s on if=%d", ipbuf(nexthop), ifidx);
}

/* 已解析下一跳后：改写 dst/src MAC、TTL-1、重算 IP 校验和，发送并释放帧 */
static void forward_send(fwd_frame_t *b, const uint8_t nexthop_mac[6])
{
    uint8_t *f = b->data;
    iface_t *out = iface_by_index(b->out_ifidx);
    int ihl;

    if (!out) {                 /* 出接口已消失 */
        mp_free(b);
        return;
    }
    memcpy(f + 0, nexthop_mac, 6);
    memcpy(f + 6, out->mac, 6);
    f[22]--;                    /* TTL-1（挂链前已校验 TTL>1） */
    ihl = (f[14] & 0x0f) * 4;
    ip_checksum_recompute(f + 14, (size_t)ihl);   /* 源/目的 IP 不变 → L4 校验和免重算 */

    if (pkt_send(f, b->len, b->out_ifidx) != 0)
        g_tx_err++;
    else
        g_tx++;
    mp_free(b);
}

void forward_flush_pending(ip_t nexthop, int out_ifidx)
{
    uint8_t mac[6];
    fwd_frame_t *chain = NULL;

    if (!arp_lookup(nexthop, out_ifidx, mac))
        return;                 /* 仍未解析 */

    pthread_mutex_lock(&g_pend_lock);
    {
        int idx = find_pend_locked(nexthop, out_ifidx);
        if (idx >= 0) {
            chain = g_pend[idx].chain;
            g_pend[idx].chain = NULL;
            g_pend[idx].chain_len = 0;
            unlink_node_locked(idx);
            g_pend[idx].used = 0;
        }
    }
    pthread_mutex_unlock(&g_pend_lock);

    while (chain) {             /* 逐帧转发，不持任何锁 */
        fwd_frame_t *b = chain;
        chain = b->next;
        forward_send(b, mac);
    }
}

void forward_task(void *arg)
{
    fwd_frame_t *blk = (fwd_frame_t *)arg;
    uint8_t *f = blk->data;
    int len = blk->len;
    int ihl, tot;
    ip_t dst;
    int out_ifidx = -1;
    ip_t nexthop = 0;
    uint8_t mac[6];
    bool connected;
    route_t rt;
    int i;

    /* 1. 长度/头校验 */
    if (len < 34 || (f[14] >> 4) != 4) {
        g_malformed++;
        g_drop++;
        mp_free(blk);
        return;
    }
    ihl = (f[14] & 0x0f) * 4;
    if (ihl < 20) {
        g_malformed++;
        g_drop++;
        mp_free(blk);
        return;
    }
    tot = get_be16(f + 16);
    if (tot < ihl || tot > len) {
        g_malformed++;
        g_drop++;
        mp_free(blk);
        return;
    }
    dst = get_be32(f + 30);

    /* 2. 防火墙 */
    if (fw_check(f, len) == FW_DROP) {
        g_fw_drop++;
        g_drop++;
        mp_free(blk);
        return;
    }

    /* 3. 目的为本机 / 广播 / 组播 → 释放交内核协议栈，不转发 */
    if (iface_with_ip(dst) || is_broadcast(dst) || is_multicast(dst)) {
        g_drop++;
        mp_free(blk);
        return;
    }

    /* 4. 直连子网匹配，否则路由查表（最长前缀 / 默认路由） */
    connected = false;
    for (i = 0; i < iface_count(); i++) {
        iface_t *it = iface_at(i);
        if (it->ip && (dst & it->netmask) == (it->ip & it->netmask)) {
            out_ifidx = it->ifindex;
            nexthop = dst;
            connected = true;
            break;
        }
    }
    if (!connected) {
        if (!route_lookup(dst, &rt)) {
            g_noroute++;
            g_drop++;
            mp_free(blk);
            return;
        }
        out_ifidx = rt.ifindex;
        nexthop = rt.gw ? rt.gw : dst;
    }

    /* 5. TTL<=1 丢弃 */
    if (f[22] <= 1) {
        g_ttl_drop++;
        g_drop++;
        mp_free(blk);
        return;
    }

    /* 6. 下一跳 ARP：命中改写发送；未命中挂 pending + 发请求 */
    blk->out_ifidx = (uint8_t)out_ifidx;
    blk->nexthop = nexthop;
    if (arp_lookup(nexthop, out_ifidx, mac)) {
        forward_send(blk, mac);
    } else {
        pend_enqueue(nexthop, out_ifidx, blk);
        arp_request(nexthop, out_ifidx);
    }
}

void pend_tick(void)
{
    struct { ip_t ip; int ifidx; } keys[PEND_MAX];
    int nkeys = 0;
    uint64_t now = monotonic_now();
    int idx, i;

    pthread_mutex_lock(&g_pend_lock);
    idx = g_pend_head;
    while (idx >= 0) {
        int next = g_pend[idx].next;
        pend_node_t *n = &g_pend[idx];
        if (n->retries >= ARP_RETRY_MAX) {
            fwd_frame_t *ch = n->chain;
            n->chain = NULL;
            n->chain_len = 0;
            unlink_node_locked(idx);
            n->used = 0;
            while (ch) {
                fwd_frame_t *b = ch;
                ch = b->next;
                mp_free(b);
            }
            g_arp_fail++;
            g_drop++;
            LOG_WARN("arp fail for %s on if=%d, frames dropped", ipbuf(n->nexthop), n->ifidx);
        } else {
            n->retries++;
            n->last_sent = now;
            if (nkeys < PEND_MAX) {
                keys[nkeys].ip = n->nexthop;
                keys[nkeys].ifidx = n->ifidx;
                nkeys++;
            }
        }
        idx = next;
    }
    pthread_mutex_unlock(&g_pend_lock);

    /* 锁外补发请求 + 重查解析（覆盖 学习-挂链 竞态） */
    for (i = 0; i < nkeys; i++) {
        arp_request(keys[i].ip, keys[i].ifidx);
        forward_flush_pending(keys[i].ip, keys[i].ifidx);
    }
}

int pend_count(void)
{
    int c = 0, idx;

    pthread_mutex_lock(&g_pend_lock);
    for (idx = g_pend_head; idx >= 0; idx = g_pend[idx].next)
        c++;
    pthread_mutex_unlock(&g_pend_lock);
    return c;
}

void pend_show(char *out, size_t outsz)
{
    size_t off = 0;
    int idx;

    pthread_mutex_lock(&g_pend_lock);
    for (idx = g_pend_head; idx >= 0 && off < outsz; idx = g_pend[idx].next) {
        pend_node_t *n = &g_pend[idx];
        off += (size_t)snprintf(out + off, outsz - off,
                "%-15s  if=%-2d  retries=%d  frames=%d\n",
                ipbuf(n->nexthop), n->ifidx, n->retries, n->chain_len);
    }
    pthread_mutex_unlock(&g_pend_lock);
    if (off == 0)
        snprintf(out, outsz, "(empty)\n");
}
