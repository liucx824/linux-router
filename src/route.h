#ifndef ROUTE_H
#define ROUTE_H

#include "router.h"

typedef struct route {
    ip_t dest;       /* 网络地址（网络序值） */
    ip_t mask;
    ip_t gw;         /* 0 = 直连/接口 */
    int  ifindex;    /* 出接口 */
    int  is_static;  /* 0 = 接口推导的直连路由 */
} route_t;

int  route_init(void);
void route_derive_connected(void);               /* 重建直连路由，保留静态 */
void route_clear_static(void);                   /* 清空静态路由（reload 用），保留直连 */
int  route_add(ip_t dest, ip_t mask, ip_t gw, int ifindex);  /* 成功 0，满 -1 */
int  route_del(int index);                        /* 仅静态可删：0 成功，-1 不存在，-2 非静态 */
int  route_lookup(ip_t dst, route_t *out);        /* 最长前缀命中 1 */
void route_show(char *out, size_t outsz);
int  route_count(void);
const route_t *route_at(int index);               /* index 越界返回 NULL（不加锁，读侧自行持锁/单线程） */

#endif /* ROUTE_H */
