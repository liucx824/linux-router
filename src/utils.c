#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "utils.h"

/* 点分十进制 → ip_t（网络序值）。等效 inet_pton 的严格校验，自包含便于移植。 */
int str_to_ip(const char *s, ip_t *out)
{
    unsigned int a, b, c, d;
    char extra;

    if (!s)
        return 0;
    if (sscanf(s, "%u.%u.%u.%u%c", &a, &b, &c, &d, &extra) != 4)
        return 0;
    if (a > 255 || b > 255 || c > 255 || d > 255)
        return 0;
    *out = ((ip_t)a << 24) | ((ip_t)b << 16) | ((ip_t)c << 8) | (ip_t)d;
    return 1;
}

void ip_to_str(ip_t ip, char *buf, size_t n)
{
    snprintf(buf, n, "%u.%u.%u.%u",
             (unsigned)(ip >> 24) & 0xff, (unsigned)(ip >> 16) & 0xff,
             (unsigned)(ip >> 8) & 0xff, (unsigned)ip & 0xff);
}

int str_to_mac(const char *s, uint8_t mac[6])
{
    unsigned int v[6];
    if (!s || sscanf(s, "%02x:%02x:%02x:%02x:%02x:%02x",
                     &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6)
        return 0;
    for (int i = 0; i < 6; i++)
        mac[i] = (uint8_t)v[i];
    return 1;
}

void mac_to_str(const uint8_t mac[6], char *buf, size_t n)
{
    snprintf(buf, n, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* 环形静态缓冲：容忍并发格式化（日志内部已加锁，命令输出用轮转槽位） */
static char g_ipbufs[8][16];
static char g_macbufs[8][18];
static _Atomic int g_ipidx = 0;
static _Atomic int g_macidx = 0;

const char *ipbuf(ip_t ip)
{
    int i = atomic_fetch_add(&g_ipidx, 1) & 7;
    ip_to_str(ip, g_ipbufs[i], sizeof(g_ipbufs[i]));
    return g_ipbufs[i];
}

const char *macbuf(const uint8_t mac[6])
{
    int i = atomic_fetch_add(&g_macidx, 1) & 7;
    mac_to_str(mac, g_macbufs[i], sizeof(g_macbufs[i]));
    return g_macbufs[i];
}

/* /len → 掩码（ip_t 域，高位连续 1）。len=0 返回 0。 */
ip_t mask_from_prefix(int len)
{
    if (len <= 0)  return 0;
    if (len >= 32) return 0xFFFFFFFFu;
    return 0xFFFFFFFFu << (32 - len);
}

/* 连续掩码 → 前缀长度：~mask 的首零个数即为 1 的个数。 */
int prefix_len(ip_t mask)
{
    if (mask == 0) return 0;
    return __builtin_clz(~mask);
}

/* 解析 "a.b.c.d[/len]"；无 /len 时掩码为全 1（精确主机）。 */
int parse_cidr(const char *s, ip_t *ip, ip_t *mask)
{
    char buf[64];
    char *slash;
    int len;

    if (!s)
        return 0;
    snprintf(buf, sizeof(buf), "%s", s);
    slash = strchr(buf, '/');
    if (slash) {
        *slash = '\0';
        if (sscanf(slash + 1, "%d", &len) != 1)
            return 0;
        if (len < 0 || len > 32)
            return 0;
    } else {
        len = 32;
    }
    if (!str_to_ip(buf, ip))
        return 0;
    *mask = mask_from_prefix(len);
    return 1;
}

int find_bytes(const uint8_t *hay, size_t hlen,
               const uint8_t *needle, size_t nlen)
{
    size_t i, j;

    if (nlen == 0)       return 0;
    if (nlen > hlen)     return -1;
    for (i = 0; i + nlen <= hlen; i++) {
        for (j = 0; j < nlen; j++)
            if (hay[i + j] != needle[j])
                break;
        if (j == nlen)
            return (int)i;
    }
    return -1;
}

bool is_multicast(ip_t ip)
{
    return (ip >> 28) == 0xE;
}

bool is_broadcast(ip_t ip)
{
    return ip == 0xFFFFFFFFu;
}

/* 空白分词：把 s 原地改写（空白→NUL），argv[0..argc-1] 指向各词首，argv[argc]=NULL。 */
int tok_split(char *s, char **argv, int max)
{
    int n = 0;

    while (*s) {
        while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n')
            s++;
        if (!*s)
            break;
        argv[n++] = s;
        if (n >= max)
            break;
        while (*s && *s != ' ' && *s != '\t' && *s != '\r' && *s != '\n')
            s++;
        if (*s)
            *s++ = 0;
    }
    if (n < max)
        argv[n] = NULL;
    return n;
}
