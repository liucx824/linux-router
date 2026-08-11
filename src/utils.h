#ifndef UTILS_H
#define UTILS_H

#include "router.h"

/*
 * IP 表示约定（router.h 的 ip_t）：
 *   ip_t = 网络序值，即 get_be32(帧内4字节) 的结果（A<<24|B<<16|C<<8|D）。
 *   子网掩码由 mask_from_prefix() 生成（bit 位置与 ip_t 一致），
 *   因此 (ip & mask) == (net & mask) 可直接比较，无需 ntohl。
 */

int  str_to_ip(const char *s, ip_t *out);              /* 成功返回 1 */
void ip_to_str(ip_t ip, char *buf, size_t n);
int  str_to_mac(const char *s, uint8_t mac[6]);        /* 成功返回 1 */
void mac_to_str(const uint8_t mac[6], char *buf, size_t n);
const char *ipbuf(ip_t ip);                            /* 环形静态缓冲，日志/命令用 */
const char *macbuf(const uint8_t mac[6]);

ip_t mask_from_prefix(int len);                        /* /len → 掩码 */
int  prefix_len(ip_t mask);                            /* 连续掩码 → /len（__builtin_clz O(1)） */
int  parse_cidr(const char *s, ip_t *ip, ip_t *mask);  /* "a.b.c.d[/len]" 成功返回 1 */

int  find_bytes(const uint8_t *hay, size_t hlen, const uint8_t *needle, size_t nlen);
bool is_multicast(ip_t ip);                            /* 224.0.0.0/4 */
bool is_broadcast(ip_t ip);                            /* 255.255.255.255 */
int  tok_split(char *s, char **argv, int max);         /* 空白分词，返回 argc；原地改写输入 */

#endif /* UTILS_H */
