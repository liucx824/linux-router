#include <pthread.h>
#include <string.h>
#include <stdio.h>

#include "router.h"
#include "route.h"
#include "interface.h"
#include "utils.h"
#include "log.h"

static route_t g_routes[MAX_ROUTE];
static int g_n = 0;
static pthread_rwlock_t g_lock = PTHREAD_RWLOCK_INITIALIZER;

int route_init(void)
{
    pthread_rwlock_wrlock(&g_lock);
    g_n = 0;
    pthread_rwlock_unlock(&g_lock);
    return 0;
}

/* 清空静态路由（reload 前调用），直连路由保留，随后调 route_derive_connected 重建 */
void route_clear_static(void)
{
    int keep = 0, i;

    pthread_rwlock_wrlock(&g_lock);
    for (i = 0; i < g_n; i++)
        if (!g_routes[i].is_static)
            g_routes[keep++] = g_routes[i];
    g_n = keep;
    pthread_rwlock_unlock(&g_lock);
}

/* 重建直连路由（保留静态路由），接口 IP/掩码变化后调用 */
void route_derive_connected(void)
{
    int keep = 0, i;

    pthread_rwlock_wrlock(&g_lock);
    for (i = 0; i < g_n; i++)
        if (g_routes[i].is_static)
            g_routes[keep++] = g_routes[i];
    g_n = keep;

    for (i = 0; i < iface_count() && g_n < MAX_ROUTE; i++) {
        iface_t *it = iface_at(i);
        if (!it || it->ip == 0 || it->ifindex < 0 || it->netmask == 0)
            continue;
        g_routes[g_n].dest = it->ip & it->netmask;
        g_routes[g_n].mask = it->netmask;
        g_routes[g_n].gw = 0;
        g_routes[g_n].ifindex = it->ifindex;
        g_routes[g_n].is_static = 0;
        g_n++;
    }
    pthread_rwlock_unlock(&g_lock);

    LOG_DEBUG("route_derive_connected: %d entries", g_n);
}

int route_add(ip_t dest, ip_t mask, ip_t gw, int ifindex)
{
    int i;

    pthread_rwlock_wrlock(&g_lock);
    for (i = 0; i < g_n; i++) {
        if (g_routes[i].dest == dest && g_routes[i].mask == mask &&
            g_routes[i].gw == gw && g_routes[i].ifindex == ifindex) {
            pthread_rwlock_unlock(&g_lock);
            return 0;   /* 已存在 */
        }
    }
    if (g_n >= MAX_ROUTE) {
        pthread_rwlock_unlock(&g_lock);
        LOG_WARN("route_add: table full");
        return -1;
    }
    g_routes[g_n].dest = dest;
    g_routes[g_n].mask = mask;
    g_routes[g_n].gw = gw;
    g_routes[g_n].ifindex = ifindex;
    g_routes[g_n].is_static = 1;
    g_n++;
    pthread_rwlock_unlock(&g_lock);

    LOG_INFO("route add %s/%d via %s dev=%d",
             ipbuf(dest), prefix_len(mask), gw ? ipbuf(gw) : "direct", ifindex);
    return 0;
}

int route_del(int index)
{
    int rc = -1;

    if (index < 0)
        return -1;
    pthread_rwlock_wrlock(&g_lock);
    if (index >= g_n) {
        rc = -1;
    } else if (!g_routes[index].is_static) {
        rc = -2;   /* 拒绝删直连路由 */
    } else {
        memmove(&g_routes[index], &g_routes[index + 1],
                (size_t)(g_n - index - 1) * sizeof(route_t));
        g_n--;
        rc = 0;
    }
    pthread_rwlock_unlock(&g_lock);
    return rc;
}

int route_lookup(ip_t dst, route_t *out)
{
    int best = -1, best_len = -1, i;

    pthread_rwlock_rdlock(&g_lock);
    for (i = 0; i < g_n; i++) {
        route_t *r = &g_routes[i];
        if ((dst & r->mask) == r->dest) {
            int pl = prefix_len(r->mask);
            if (pl > best_len) { best = i; best_len = pl; }
        }
    }
    if (best >= 0)
        *out = g_routes[best];
    pthread_rwlock_unlock(&g_lock);
    return best >= 0;
}

int route_count(void)
{
    return g_n;
}

void route_show(char *out, size_t outsz)
{
    size_t off = 0;
    int i;

    pthread_rwlock_rdlock(&g_lock);
    for (i = 0; i < g_n && off < outsz; i++) {
        route_t *r = &g_routes[i];
        off += (size_t)snprintf(out + off, outsz - off,
                "%2d  %-15s/%-2d  via %-15s  if=%-2d  %s\n",
                i, ipbuf(r->dest), prefix_len(r->mask),
                r->gw ? ipbuf(r->gw) : "-", r->ifindex,
                r->is_static ? "static" : "connected");
    }
    pthread_rwlock_unlock(&g_lock);
    if (off == 0)
        snprintf(out, outsz, "(empty)\n");
}

const route_t *route_at(int index)
{
    if (index < 0 || index >= g_n)
        return NULL;
    return &g_routes[index];
}
