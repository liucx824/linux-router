#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

#include "router.h"
#include "config.h"
#include "firewall.h"
#include "route.h"
#include "interface.h"
#include "arp_table.h"
#include "log.h"
#include "utils.h"

static router_cfg_t g_cfg;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

void config_default(void)
{
    pthread_mutex_lock(&g_lock);
    memset(&g_cfg, 0, sizeof(g_cfg));
    snprintf(g_cfg.hostname, sizeof(g_cfg.hostname), "router");
    g_cfg.threads = POOL_THREADS;
    g_cfg.tcp_port = TCP_PORT;
    g_cfg.udp_port = UDP_PORT;
    g_cfg.arp_timeout = ARP_TMO;
    g_cfg.arp_proxy = 0;
    g_cfg.log_level = LOG_INFO;
    /* password 默认空 = 无鉴权 */
    pthread_mutex_unlock(&g_lock);
}

const char *cfg_hostname(void) { pthread_mutex_lock(&g_lock); const char *v = g_cfg.hostname; pthread_mutex_unlock(&g_lock); return v; }
const char *cfg_password(void) { pthread_mutex_lock(&g_lock); const char *v = g_cfg.password; pthread_mutex_unlock(&g_lock); return v; }
int cfg_threads(void)          { pthread_mutex_lock(&g_lock); int v = g_cfg.threads;    pthread_mutex_unlock(&g_lock); return v; }
int cfg_tcp_port(void)         { pthread_mutex_lock(&g_lock); int v = g_cfg.tcp_port;   pthread_mutex_unlock(&g_lock); return v; }
int cfg_udp_port(void)         { pthread_mutex_lock(&g_lock); int v = g_cfg.udp_port;   pthread_mutex_unlock(&g_lock); return v; }
int cfg_arp_timeout(void)      { pthread_mutex_lock(&g_lock); int v = g_cfg.arp_timeout; pthread_mutex_unlock(&g_lock); return v; }
int cfg_arp_proxy(void)        { pthread_mutex_lock(&g_lock); int v = g_cfg.arp_proxy;  pthread_mutex_unlock(&g_lock); return v; }
int cfg_log_level(void)        { pthread_mutex_lock(&g_lock); int v = g_cfg.log_level;  pthread_mutex_unlock(&g_lock); return v; }

/* ---------- 序列化（save 写盘 / getconf 下发共用同一份文本） ---------- */

/* cidr 串：/32 简写为纯 IP，否则 ip/len */
static void cidr_to_str(ip_t ip, ip_t mask, char *buf, size_t size)
{
    if (mask == 0xFFFFFFFFu)
        snprintf(buf, size, "%s", ipbuf(ip));
    else
        snprintf(buf, size, "%s/%d", ipbuf(ip), prefix_len(mask));
}

static int fw_rule_to_line(const fw_rule_t *r, char *buf, size_t size)
{
    size_t off = 0;
    char tmp[24];

    off += (size_t)snprintf(buf + off, size - off, "%s",
                            r->action == FW_DROP ? "drop" : "allow");
    if (r->sip_mask || r->dip_mask) {
        off += (size_t)snprintf(buf + off, size - off, " ip ");
        if (r->sip_mask) {
            cidr_to_str(r->sip, r->sip_mask, tmp, sizeof(tmp));
            off += (size_t)snprintf(buf + off, size - off, "%s", tmp);
        } else {
            off += (size_t)snprintf(buf + off, size - off, "any");  /* 占位，解析器识别 */
        }
        if (r->dip_mask) {
            cidr_to_str(r->dip, r->dip_mask, tmp, sizeof(tmp));
            off += (size_t)snprintf(buf + off, size - off, " %s", tmp);
        }
    }
    if (r->proto != PROTO_ANY) {
        const char *pn = r->proto == PROTO_TCP ? "tcp" :
                         r->proto == PROTO_UDP ? "udp" : "icmp";
        off += (size_t)snprintf(buf + off, size - off, " proto %s", pn);
    }
    if (r->sport >= 0)
        off += (size_t)snprintf(buf + off, size - off, " sport %d", r->sport);
    if (r->dport >= 0)
        off += (size_t)snprintf(buf + off, size - off, " dport %d", r->dport);
    if (r->keyword[0])
        off += (size_t)snprintf(buf + off, size - off, " keyword \"%s\"", r->keyword);
    return (int)off;
}

int config_serialize(char *buf, size_t size)
{
    size_t off = 0;
    int i, n;

    pthread_mutex_lock(&g_lock);
    off += (size_t)snprintf(buf + off, size - off, "[router]\n");
    off += (size_t)snprintf(buf + off, size - off, "hostname=%s\n", g_cfg.hostname);
    off += (size_t)snprintf(buf + off, size - off, "threads=%d\n", g_cfg.threads);
    off += (size_t)snprintf(buf + off, size - off, "tcp_port=%d\n", g_cfg.tcp_port);
    off += (size_t)snprintf(buf + off, size - off, "udp_port=%d\n", g_cfg.udp_port);
    off += (size_t)snprintf(buf + off, size - off, "arp_timeout=%d\n", g_cfg.arp_timeout);
    off += (size_t)snprintf(buf + off, size - off, "arp_proxy=%d\n", g_cfg.arp_proxy);
    off += (size_t)snprintf(buf + off, size - off, "log_level=%d\n", g_cfg.log_level);
    pthread_mutex_unlock(&g_lock);

    off += (size_t)snprintf(buf + off, size - off, "\n[filter]\n# 旧格式兼容段：drop ip X\n");

    n = fw_count();
    off += (size_t)snprintf(buf + off, size - off, "\n[firewall]\n");
    for (i = 0; i < n; i++) {
        char line[256];
        const fw_rule_t *r = fw_rule_at(i);
        if (!r)
            break;
        fw_rule_to_line(r, line, sizeof(line));
        off += (size_t)snprintf(buf + off, size - off, "%s\n", line);
    }

    n = route_count();
    off += (size_t)snprintf(buf + off, size - off, "\n[route]\n");
    for (i = 0; i < n; i++) {
        const route_t *r = route_at(i);
        if (!r)
            break;
        if (!r->is_static)
            continue;                    /* 直连路由不落盘 */
        const char *devname = "?";
        int j;
        for (j = 0; j < iface_count(); j++) {
            iface_t *it = iface_at(j);
            if (it && it->ifindex == r->ifindex) {
                devname = it->name;
                break;
            }
        }
        if (r->gw)
            off += (size_t)snprintf(buf + off, size - off, "%s/%d via %s dev %s\n",
                                    ipbuf(r->dest), prefix_len(r->mask),
                                    ipbuf(r->gw), devname);
        else
            off += (size_t)snprintf(buf + off, size - off, "%s/%d dev %s\n",
                                    ipbuf(r->dest), prefix_len(r->mask), devname);
    }
    return off < size ? (int)off : -1;
}

int config_save(void)
{
    char tmp[520];
    char *buf;
    int n, rc = 0;

    snprintf(tmp, sizeof(tmp), "%s.tmp", CONFIG_FILE);
    buf = malloc(16384);
    if (!buf)
        return -1;
    n = config_serialize(buf, 16384);
    if (n < 0) {
        free(buf);
        return -1;
    }
    FILE *fp = fopen(tmp, "w");
    if (!fp) {
        LOG_ERR("config_save: cannot open %s", tmp);
        free(buf);
        return -1;
    }
    if (fwrite(buf, 1, (size_t)n, fp) != (size_t)n)
        rc = -1;
    if (fflush(fp) != 0 || fsync(fileno(fp)) != 0)
        rc = -1;
    fclose(fp);
    free(buf);
    if (rc == 0 && rename(tmp, CONFIG_FILE) != 0) {
        LOG_ERR("config_save: rename %s -> %s failed", tmp, CONFIG_FILE);
        rc = -1;
    }
    if (rc == 0)
        LOG_INFO("config saved to %s", CONFIG_FILE);
    else
        unlink(tmp);
    return rc;
}

/* ---------- 解析 ---------- */

static void parse_router_key(const char *p)
{
    char key[40], val[128];
    const char *eq = strchr(p, '=');
    char *kp, *ep;

    if (!eq)
        return;
    snprintf(key, sizeof(key), "%.*s", (int)(eq - p), p);
    snprintf(val, sizeof(val), "%s", eq + 1);
    kp = key;
    while (*kp == ' ' || *kp == '\t') kp++;
    ep = kp + strlen(kp);
    while (ep > kp && (ep[-1] == ' ' || ep[-1] == '\t')) *--ep = 0;

    pthread_mutex_lock(&g_lock);
    if (strcmp(kp, "hostname") == 0)
        snprintf(g_cfg.hostname, sizeof(g_cfg.hostname), "%s", val);
    else if (strcmp(kp, "threads") == 0)
        g_cfg.threads = atoi(val);
    else if (strcmp(kp, "tcp_port") == 0)
        g_cfg.tcp_port = atoi(val);
    else if (strcmp(kp, "udp_port") == 0)
        g_cfg.udp_port = atoi(val);
    else if (strcmp(kp, "password") == 0)
        snprintf(g_cfg.password, sizeof(g_cfg.password), "%s", val);
    else if (strcmp(kp, "arp_timeout") == 0)
        g_cfg.arp_timeout = atoi(val);
    else if (strcmp(kp, "arp_proxy") == 0)
        g_cfg.arp_proxy = atoi(val);
    else if (strcmp(kp, "log_level") == 0)
        g_cfg.log_level = atoi(val);
    else {
        pthread_mutex_unlock(&g_lock);
        LOG_WARN("unknown router key: %s", kp);
        return;
    }
    pthread_mutex_unlock(&g_lock);

    if (strcmp(kp, "arp_timeout") == 0)
        arp_set_timeout(cfg_arp_timeout());
    if (strcmp(kp, "log_level") == 0)
        log_set_level(cfg_log_level());
}

/* 旧版 [filter]：drop ip X → fw deny 规则 */
static void parse_filter_line(char *p)
{
    const char *a = strstr(p, "ip ");
    ip_t ip, mask;
    fw_rule_t r;

    if (!a)
        return;
    if (!parse_cidr(a + 3, &ip, &mask))
        return;
    memset(&r, 0, sizeof(r));
    r.action = FW_DROP;
    r.proto = PROTO_ANY;
    r.sport = r.dport = -1;
    r.sip = ip & mask;
    r.sip_mask = mask;
    if (fw_add(&r) != 0)
        LOG_WARN("filter rule rejected (table full)");
}

static void parse_firewall_line(char *p)
{
    char *argv[16];
    const char *args[16];
    int argc, i;
    fw_rule_t r;

    while (*p == ' ' || *p == '\t') p++;
    if (*p == '/') p++;                    /* 兼容文档续行风格 */
    argc = tok_split(p, argv, 16);
    if (argc < 1)
        return;
    for (i = 0; i < argc; i++)
        args[i] = argv[i];
    if (fw_parse_rule(args, argc, &r) == 0)
        fw_add(&r);
    else
        LOG_WARN("bad firewall rule: %s", p);
}

static void parse_route_line(char *p)
{
    char *argv[16];
    int argc, i;
    ip_t dest, mask, gw = 0;
    int ifindex = -1;

    while (*p == ' ' || *p == '\t') p++;
    if (*p == '/') p++;
    argc = tok_split(p, argv, 16);
    if (argc < 1 || !parse_cidr(argv[0], &dest, &mask))
        return;
    for (i = 1; i + 1 < argc; i++) {
        if (strcmp(argv[i], "via") == 0) {
            if (!str_to_ip(argv[i + 1], &gw)) {
                LOG_WARN("bad gw %s", argv[i + 1]);
                return;
            }
        } else if (strcmp(argv[i], "dev") == 0) {
            iface_t *it = iface_by_name(argv[i + 1]);
            if (!it) {
                LOG_WARN("route: unknown dev %s", argv[i + 1]);
                return;
            }
            ifindex = it->ifindex;
        }
    }
    if (ifindex < 0) {
        LOG_WARN("route: missing dev");
        return;
    }
    route_add(dest, mask, gw, ifindex);
}

int config_load(void)
{
    FILE *fp;
    char line[512];
    char section[16] = "";
    int lineno = 0;

    fp = fopen(CONFIG_FILE, "r");
    if (!fp) {
        LOG_WARN("config_load: %s not found, generating default", CONFIG_FILE);
        config_default();
        fw_clear();
        route_clear_static();
        config_save();
        return 0;
    }

    config_default();
    fw_clear();
    route_clear_static();

    while (fgets(line, sizeof(line), fp)) {
        char *p = line;
        int n = (int)strlen(line);

        lineno++;
        if (n > 0 && line[n - 1] == '\n') line[--n] = 0;
        if (n > 0 && line[n - 1] == '\r') line[--n] = 0;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == 0 || *p == '#')
            continue;
        if (*p == '[') {
            section[0] = 0;
            sscanf(p + 1, "%15[^]]", section);
            continue;
        }
        if (strcmp(section, "router") == 0)
            parse_router_key(p);
        else if (strcmp(section, "filter") == 0)
            parse_filter_line(p);
        else if (strcmp(section, "firewall") == 0)
            parse_firewall_line(p);
        else if (strcmp(section, "route") == 0)
            parse_route_line(p);
        else
            LOG_WARN("config:%d unknown section '%s'", lineno, section);
    }
    fclose(fp);

    LOG_INFO("config loaded: %d fw rules, %d routes (host=%s)",
             fw_count(), route_count(), cfg_hostname());
    return 0;
}
