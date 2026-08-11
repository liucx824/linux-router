#ifndef ARP_TABLE_H
#define ARP_TABLE_H

#include "router.h"

int  arp_init(void);
void arp_set_timeout(int sec);
int  arp_lookup(ip_t ip, int ifidx, uint8_t mac_out[6]); /* 命中 1 */
void arp_insert(ip_t ip, const uint8_t mac[6], int ifidx); /* 学习/刷新 */
void arp_delete(ip_t ip, int ifidx);
void arp_tick(void);                    /* 1s 老化扫描 */
void arp_show(char *out, size_t outsz);
int  arp_count(void);

#endif /* ARP_TABLE_H */
