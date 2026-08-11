#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "router.h"
#include "firewall.h"
#include "utils.h"
#include "log.h"

static fw_rule_t g_rules[MAX_RULE];
static int g_n = 0;
static pthread_rwlock_t g_lock = PTHREAD_RWLOCK_INITIALIZER;

int fw_init(void)
{
    pthread_rwlock_wrlock(&g_lock);
    g_n = 0;
    pthread_rwlock_unlock(&g_lock);
    return 0;
}

void fw_clear(void)
{
    pthread_rwlock_wrlock(&g_lock);
    g_n = 0;
    pthread_rwlock_unlock(&g_lock);
}

int fw_add(const fw_rule_t *rule)
{
    int rc = 0;

    if (!rule)
        return -1;
    pthread_rwlock_wrlock(&g_lock);
    if (g_n >= MAX_RULE) {
        rc = -1;
    } else {
        g_rules[g_n] = *rule;
        g_n++;
    }
    pthread_rwlock_unlock(&g_lock);
    return rc;
}

int fw_del(int index)
{
    int rc;

    pthread_rwlock_wrlock(&g_lock);
    if (index < 0 || index >= g_n) {
        rc = -1;
    } else {
        memmove(&g_rules[index], &g_rules[index + 1],
                (size_t)(g_n - index - 1) * sizeof(fw_rule_t));
        g_n--;
        rc = 0;
    }
    pthread_rwlock_unlock(&g_lock);
    return rc;
}

int fw_count(void)
{
    return g_n;
}

/* 单规则匹配（须持读锁）。逐解析点先查长度，防越界。 */
static int rule_match(const fw_rule_t *r, const uint8_t *f, int len)
{
    ip_t sip, dip;
    int ihl, l4off, is_tcpudp;
    uint16_t frag_off;
    size_t kwlen;

    if (len < 34)                      /* 14 以太头 + 20 IP 头 */
        return 0;
    if ((f[14] >> 4) != 4)             /* IPv4 */
        return 0;
    ihl = (f[14] & 0x0f) * 4;
    if (ihl < 20 || ihl > len - 14)
        return 0;

    sip = get_be32(f + 26);
    dip = get_be32(f + 30);
    if (r->sip_mask && (sip & r->sip_mask) != r->sip)
        return 0;
    if (r->dip_mask && (dip & r->dip_mask) != r->dip)
        return 0;

    if (r->proto >= 0 && f[23] != (uint8_t)r->proto)
        return 0;

    is_tcpudp = (f[23] == PROTO_TCP || f[23] == PROTO_UDP);
    l4off = ETH_HLEN + ihl;

    if (r->sport >= 0 || r->dport >= 0) {
        if (!is_tcpudp)
            return 0;
        if (l4off + 4 > len)           /* 防越界读端口 */
            return 0;
        if (r->sport >= 0 && (int)get_be16(f + l4off) != r->sport)
            return 0;
        if (r->dport >= 0 && (int)get_be16(f + l4off + 2) != r->dport)
            return 0;
    }

    if (r->keyword[0]) {
        int poff;
        frag_off = (get_be16(f + 20) & 0x1fff) * 8;
        if (frag_off != 0)
            return 0;                  /* 不做分片重组，只扫首片 */
        if (!is_tcpudp)
            return 0;
        if (f[23] == PROTO_TCP) {
            if (l4off + 13 > len)
                return 0;
            poff = l4off + ((f[l4off + 12] & 0xf0) >> 2);  /* TCP 数据偏移 */
        } else {
            poff = l4off + 8;          /* UDP */
        }
        if (poff > len)
            return 0;
        kwlen = strlen(r->keyword);
        if (find_bytes(f + poff, (size_t)(len - poff),
                       (const uint8_t *)r->keyword, kwlen) < 0)
            return 0;
    }
    return 1;
}

int fw_check(const uint8_t *frame, int len)
{
    int i, action = FW_ALLOW;

    pthread_rwlock_rdlock(&g_lock);
    for (i = 0; i < g_n; i++) {
        if (rule_match(&g_rules[i], frame, len)) {
            action = g_rules[i].action;    /* 先到先中 */
            break;
        }
    }
    pthread_rwlock_unlock(&g_lock);
    return action;
}

static const char *proto_name(int p)
{
    switch (p) {
    case PROTO_TCP:  return "tcp";
    case PROTO_UDP:  return "udp";
    case PROTO_ICMP: return "icmp";
    default:         return "any";
    }
}

void fw_show(char *out, size_t outsz)
{
    size_t off = 0;
    int i;

    pthread_rwlock_rdlock(&g_lock);
    for (i = 0; i < g_n && off < outsz; i++) {
        fw_rule_t *r = &g_rules[i];
        char sp[16], dp[16];
        snprintf(sp, sizeof(sp), "%s", r->sport >= 0 ? "" : "*");
        if (r->sport >= 0)
            snprintf(sp, sizeof(sp), "%d", r->sport);
        snprintf(dp, sizeof(dp), "%s", r->dport >= 0 ? "" : "*");
        if (r->dport >= 0)
            snprintf(dp, sizeof(dp), "%d", r->dport);
        off += (size_t)snprintf(out + off, outsz - off,
                "%3d  %-5s ip %-15s %-15s proto %-4s sport %-5s dport %-5s kw \"%s\" [%s]\n",
                i, r->action == FW_DROP ? "drop" : "allow",
                r->sip_mask ? ipbuf(r->sip & r->sip_mask) : "*",
                r->dip_mask ? ipbuf(r->dip & r->dip_mask) : "*",
                proto_name(r->proto), sp, dp,
                r->keyword, r->note);
    }
    pthread_rwlock_unlock(&g_lock);
    if (off == 0)
        snprintf(out, outsz, "(empty)\n");
}

const fw_rule_t *fw_rule_at(int index)
{
    if (index < 0 || index >= g_n)
        return NULL;
    return &g_rules[index];
}

/* 解析 addfw / 配置文件中一条防火墙规则的参数。 */
int fw_parse_rule(const char **argv, int argc, fw_rule_t *r)
{
    int i;

    memset(r, 0, sizeof(*r));
    r->proto = PROTO_ANY;
    r->sport = r->dport = -1;

    if (argc < 1)
        return -1;
    if (strcmp(argv[0], "drop") == 0)
        r->action = FW_DROP;
    else if (strcmp(argv[0], "allow") == 0)
        r->action = FW_ALLOW;
    else
        return -1;

    for (i = 1; i < argc; i++) {
        const char *tok = argv[i];
        if (strcmp(tok, "ip") == 0) {
            ip_t ip, mask;
            if (i + 1 >= argc)
                return -1;
            if (strcmp(argv[++i], "any") == 0) {
                r->sip_mask = 0;         /* 源通配 */
            } else {
                if (!parse_cidr(argv[i], &ip, &mask))
                    return -1;
                r->sip = ip & mask;
                r->sip_mask = mask;
            }
            /* 可选 dip：下一 token 含 . 或 / 或为 "any" 才当作地址（避免误吞 proto/sport） */
            if (i + 1 < argc && (strchr(argv[i + 1], '.') || strchr(argv[i + 1], '/') ||
                                 strcmp(argv[i + 1], "any") == 0)) {
                if (strcmp(argv[i + 1], "any") == 0) {
                    i++;
                    r->dip_mask = 0;
                } else {
                    if (!parse_cidr(argv[++i], &ip, &mask))
                        return -1;
                    r->dip = ip & mask;
                    r->dip_mask = mask;
                }
            }
        } else if (strcmp(tok, "proto") == 0) {
            if (i + 1 >= argc)
                return -1;
            const char *pn = argv[++i];
            if (strcmp(pn, "tcp") == 0)        r->proto = PROTO_TCP;
            else if (strcmp(pn, "udp") == 0)   r->proto = PROTO_UDP;
            else if (strcmp(pn, "icmp") == 0)  r->proto = PROTO_ICMP;
            else if (strcmp(pn, "any") == 0)   r->proto = PROTO_ANY;
            else return -1;
        } else if (strcmp(tok, "sport") == 0) {
            if (i + 1 >= argc)
                return -1;
            r->sport = atoi(argv[++i]);
            if (r->sport < 0 || r->sport > 65535)
                return -1;
        } else if (strcmp(tok, "dport") == 0) {
            if (i + 1 >= argc)
                return -1;
            r->dport = atoi(argv[++i]);
            if (r->dport < 0 || r->dport > 65535)
                return -1;
        } else if (strcmp(tok, "keyword") == 0) {
            const char *kw;
            size_t k;
            if (i + 1 >= argc)
                return -1;
            kw = argv[++i];
            if (*kw == '"') kw++;              /* 剥引号 */
            k = strlen(kw);
            if (k && kw[k - 1] == '"') k--;
            if (k >= sizeof(r->keyword))
                k = sizeof(r->keyword) - 1;
            memcpy(r->keyword, kw, k);
            r->keyword[k] = 0;
        } else {
            return -1;
        }
    }
    return 0;
}
