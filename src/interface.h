#ifndef INTERFACE_H
#define INTERFACE_H

#include <net/if.h>

#include "router.h"

typedef struct iface {
    char    name[IFNAMSIZ];
    uint8_t mac[6];
    ip_t    ip;        /* 网络序值 */
    ip_t    netmask;
    int     ifindex;
    int     up;
} iface_t;

int  iface_init(void);                    /* 枚举全部带 IPv4 的接口，返回数量 */
int  iface_count(void);
iface_t *iface_at(int i);                 /* 按表内序号取 */
iface_t *iface_by_index(int ifindex);
iface_t *iface_by_name(const char *name);
iface_t *iface_with_ip(ip_t ip);
bool iface_mac_is_ours(const uint8_t mac[6]);
int  iface_add_addr(const char *name, ip_t ip, ip_t mask);  /* setip，成功 0 */
int  iface_del_addr(const char *name);                       /* delip，成功 0 */
void iface_show(char *out, size_t outsz);

#endif /* INTERFACE_H */
