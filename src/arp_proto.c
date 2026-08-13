#include <string.h>
#include <time.h>

#include "router.h"
#include "arp_proto.h"
#include "arp_table.h"
#include "forward.h"
#include "route.h"
#include "interface.h"
#include "mempool.h"
#include "packet.h"
#include "utils.h"
#include "config.h"
#include "log.h"

/*
 * ARP 帧偏移（以太头后）：htype(14) ptype(16) hlen(18) plen(19)
 * oper(20) sha(22) spa(28) tha(32) tpa(38)，帧最小 42 字节。
 */
#define ARP_OPER_REQ 1
#define ARP_OPER_REP 2

/* 在原接收帧上原地改造成 ARP 应答并发送（零拷贝复用），随后由调用方 mp_free */
static void arp_respond(uint8_t *f, int len, int send_ifidx, iface_t *src_if)
{
    uint8_t req_sha[6];
    ip_t req_spa;

    memcpy(req_sha, f + 22, 6);        /* 请求者 MAC */
    req_spa = get_be32(f + 28);        /* 请求者 IP */

    memcpy(f + 0, req_sha, 6);         /* 目的 MAC = 请求者 MAC */
    memcpy(f + 6, src_if->mac, 6);     /* 源 MAC = 本机接口 MAC */
    put_be16(f + 20, ARP_OPER_REP);
    memcpy(f + 22, src_if->mac, 6);    /* sha */
    put_be32(f + 28, src_if->ip);      /* spa = 应答方 IP */
    memcpy(f + 32, req_sha, 6);        /* tha */
    put_be32(f + 38, req_spa);         /* tpa = 请求者 IP */

    if (pkt_send(f, (size_t)len, send_ifidx) != 0)
        g_tx_err++;
    else
        g_tx++;
}

void arp_request(ip_t ip, int ifidx)
{
    iface_t *it = iface_by_index(ifidx);
    fwd_frame_t *blk;
    uint8_t *f;
    static const uint8_t bcast[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

    if (!it)
        return;
    blk = mp_alloc();
    if (!blk)
        return;
    f = blk->data;
    memset(f, 0, 42);

    memcpy(f + 0, bcast, 6);           /* 目的 = 广播 */
    memcpy(f + 6, it->mac, 6);         /* 源 = 本机接口 MAC */
    put_be16(f + 12, ETHERTYPE_ARP);
    put_be16(f + 14, 1);               /* ethernet */
    put_be16(f + 16, 0x0800);          /* IPv4 */
    f[18] = 6;
    f[19] = 4;
    put_be16(f + 20, ARP_OPER_REQ);
    memcpy(f + 22, it->mac, 6);        /* sha */
    put_be32(f + 28, it->ip);          /* spa */
    memset(f + 32, 0, 6);              /* tha 未知 */
    put_be32(f + 38, ip);              /* tpa = 目标 IP */

    blk->len = 42;
    if (pkt_send(f, 42, ifidx) != 0)
        g_tx_err++;
    else
        g_tx++;
    mp_free(blk);
}

void arp_handle_frame(fwd_frame_t *blk, int in_ifidx)
{
    uint8_t *f = blk->data;
    int len = blk->len;
    ip_t spa, tpa;
    iface_t *in_iface;
    iface_t *ours;

    /* 帧校验 */
    if (len < 42 || get_be16(f + 14) != 1 || get_be16(f + 16) != 0x0800 ||
        f[18] != 6 || f[19] != 4) {
        g_malformed++;
        g_drop++;
        mp_free(blk);
        return;
    }
    spa = get_be32(f + 28);
    tpa = get_be32(f + 38);
    in_iface = iface_by_index(in_ifidx);

    /* 学习：仅学同入口接口子网的 spa（防 ARP 毒化） */
    if (in_iface && in_iface->ip != 0 &&
        (spa & in_iface->netmask) == (in_iface->ip & in_iface->netmask))
        arp_insert(spa, f + 22, in_ifidx);

    /* 仅请求帧需要应答 */
    if (get_be16(f + 20) != ARP_OPER_REQ) {
        mp_free(blk);
        return;
    }

    ours = iface_with_ip(tpa);
    if (!ours && cfg_arp_proxy()) {
        /* 代理应答：有覆盖 tpa 的直连路由 → 用路由出接口 MAC 应答 */
        route_t rt;
        if (route_lookup(tpa, &rt) && rt.gw == 0)
            ours = iface_by_index(rt.ifindex);
    }
    if (ours) {
        arp_respond(f, len, in_ifidx, ours);
        forward_flush_pending(spa, in_ifidx);   /* 学习后冲刷同下一跳 pending 帧 */
    }
    mp_free(blk);
}
