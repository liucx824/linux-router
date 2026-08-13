#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "router.h"
#include "terminal.h"
#include "config.h"
#include "interface.h"
#include "arp_table.h"
#include "route.h"
#include "firewall.h"
#include "forward.h"
#include "mempool.h"
#include "thread_pool.h"
#include "utils.h"
#include "log.h"

typedef int (*cmd_fn)(int argc, char **argv, char *out, size_t outsz);

typedef struct cmd_entry {
    const char *name;
    cmd_fn fn;
    const char *help;
} cmd_entry_t;

static int cmd_help(int argc, char **argv, char *out, size_t outsz);
static int cmd_exit(int argc, char **argv, char *out, size_t outsz);
static int cmd_setip(int argc, char **argv, char *out, size_t outsz);
static int cmd_delip(int argc, char **argv, char *out, size_t outsz);
static int cmd_showip(int argc, char **argv, char *out, size_t outsz);
static int cmd_addfw(int argc, char **argv, char *out, size_t outsz);
static int cmd_delfw(int argc, char **argv, char *out, size_t outsz);
static int cmd_showfw(int argc, char **argv, char *out, size_t outsz);
static int cmd_addroute(int argc, char **argv, char *out, size_t outsz);
static int cmd_delroute(int argc, char **argv, char *out, size_t outsz);
static int cmd_showroute(int argc, char **argv, char *out, size_t outsz);
static int cmd_showif(int argc, char **argv, char *out, size_t outsz);
static int cmd_showarp(int argc, char **argv, char *out, size_t outsz);
static int cmd_showthread(int argc, char **argv, char *out, size_t outsz);
static int cmd_showpool(int argc, char **argv, char *out, size_t outsz);
static int cmd_showpend(int argc, char **argv, char *out, size_t outsz);
static int cmd_showstat(int argc, char **argv, char *out, size_t outsz);
static int cmd_showcfg(int argc, char **argv, char *out, size_t outsz);
static int cmd_save(int argc, char **argv, char *out, size_t outsz);
static int cmd_reload(int argc, char **argv, char *out, size_t outsz);

static const cmd_entry_t g_cmd_table[] = {
    { "help",      cmd_help,      "列出全部命令" },
    { "setip",     cmd_setip,     "setip <ifname> <ip[/mask]>  设置接口 IP" },
    { "delip",     cmd_delip,     "delip <ifname>  删除接口 IP" },
    { "showip",    cmd_showip,    "显示接口 IP" },
    { "addfw",     cmd_addfw,     "addfw deny|allow ip <sip[/len]> [dip[/len]] proto tcp|udp|icmp|any [sport N] [dport N] [keyword <str>]" },
    { "delfw",     cmd_delfw,     "delfw <index>  删除防火墙规则" },
    { "showfw",    cmd_showfw,    "显示防火墙规则" },
    { "addroute",  cmd_addroute,  "addroute <dest/mask> [via <gw>] dev <ifname>" },
    { "delroute",  cmd_delroute,  "delroute <index>  删除静态路由" },
    { "showroute", cmd_showroute, "显示路由表" },
    { "showif",    cmd_showif,    "显示接口详细信息" },
    { "showarp",   cmd_showarp,   "显示 ARP 缓存" },
    { "showthread",cmd_showthread,"显示线程池状态" },
    { "showpool",  cmd_showpool,  "显示内存池状态" },
    { "showpend",  cmd_showpend,  "显示 pending 队列" },
    { "showstat",  cmd_showstat,  "显示收发统计" },
    { "showcfg",   cmd_showcfg,   "显示当前配置" },
    { "save",      cmd_save,      "保存配置到 router.conf" },
    { "reload",    cmd_reload,    "重新加载 router.conf" },
    { "exit",      cmd_exit,      "退出（本地=停机，远程=关连接）" },
};

#define N_CMDS ((int)(sizeof(g_cmd_table) / sizeof(g_cmd_table[0])))

/* ---------- 各命令实现 ---------- */

static int cmd_help(int argc, char **argv, char *out, size_t outsz)
{
    size_t off = 0;
    int i;

    (void)argc; (void)argv;
    for (i = 0; i < N_CMDS && off < outsz; i++)
        off += (size_t)snprintf(out + off, outsz - off, "  %-8s  %s\n",
                                g_cmd_table[i].name, g_cmd_table[i].help);
    return 0;
}

static int cmd_exit(int argc, char **argv, char *out, size_t outsz)
{
    (void)argc; (void)argv;
    snprintf(out, outsz, "bye\n");
    return 1;
}

static int cmd_setip(int argc, char **argv, char *out, size_t outsz)
{
    ip_t ip, mask;

    if (argc != 3 || !parse_cidr(argv[2], &ip, &mask)) {
        snprintf(out, outsz, "usage: setip <ifname> <ip[/mask]>\n");
        return -1;
    }
    if (iface_add_addr(argv[1], ip, mask) != 0) {
        snprintf(out, outsz, "setip %s failed (unknown iface or in use)\n", argv[1]);
        return -1;
    }
    route_derive_connected();
    snprintf(out, outsz, "setip %s %s/%d ok\n", argv[1], ipbuf(ip), prefix_len(mask));
    return 0;
}

static int cmd_delip(int argc, char **argv, char *out, size_t outsz)
{
    if (argc != 2) {
        snprintf(out, outsz, "usage: delip <ifname>\n");
        return -1;
    }
    if (iface_del_addr(argv[1]) != 0) {
        snprintf(out, outsz, "delip %s failed\n", argv[1]);
        return -1;
    }
    route_derive_connected();
    snprintf(out, outsz, "delip %s ok\n", argv[1]);
    return 0;
}

static int cmd_showip(int argc, char **argv, char *out, size_t outsz)
{
    int i;

    (void)argc; (void)argv;
    snprintf(out, outsz, "%-8s  %-15s  %-15s\n", "iface", "IP", "mask");
    for (i = 0; i < iface_count(); i++) {
        iface_t *it = iface_at(i);
        if (!it || it->ip == 0)
            continue;
        snprintf(out + strlen(out), outsz - strlen(out), "%-8s  %-15s  %-15s\n",
                 it->name, ipbuf(it->ip), ipbuf(it->netmask));
    }
    return 0;
}

static int cmd_addfw(int argc, char **argv, char *out, size_t outsz)
{
    fw_rule_t r;
    const char *args[16];
    int i;

    if (argc < 2) {
        snprintf(out, outsz, "usage: %s\n", g_cmd_table[4].help);
        return -1;
    }
    for (i = 1; i < argc && i < 16; i++)
        args[i - 1] = argv[i];
    if (fw_parse_rule(args, argc - 1, &r) != 0) {
        snprintf(out, outsz, "bad rule arguments\n");
        return -1;
    }
    if (fw_add(&r) != 0) {
        snprintf(out, outsz, "rule table full\n");
        return -1;
    }
    snprintf(out, outsz, "rule %d added\n", fw_count() - 1);
    return 0;
}

static int cmd_delfw(int argc, char **argv, char *out, size_t outsz)
{
    int idx;

    if (argc != 2) {
        snprintf(out, outsz, "usage: delfw <index>\n");
        return -1;
    }
    idx = atoi(argv[1]);
    if (fw_del(idx) != 0) {
        snprintf(out, outsz, "no rule %d\n", idx);
        return -1;
    }
    snprintf(out, outsz, "rule %d deleted\n", idx);
    return 0;
}

static int cmd_addroute(int argc, char **argv, char *out, size_t outsz)
{
    ip_t dest, mask, gw = 0;
    int ifindex = -1;
    int i;

    if (argc < 3 || !parse_cidr(argv[1], &dest, &mask)) {
        snprintf(out, outsz, "usage: %s\n", g_cmd_table[7].help);
        return -1;
    }
    for (i = 2; i + 1 < argc; i++) {
        if (strcmp(argv[i], "via") == 0) {
            if (!str_to_ip(argv[i + 1], &gw)) {
                snprintf(out, outsz, "bad gw %s\n", argv[i + 1]);
                return -1;
            }
        } else if (strcmp(argv[i], "dev") == 0) {
            iface_t *it = iface_by_name(argv[i + 1]);
            if (!it) {
                snprintf(out, outsz, "unknown iface %s\n", argv[i + 1]);
                return -1;
            }
            ifindex = it->ifindex;
        }
    }
    if (ifindex < 0) {
        snprintf(out, outsz, "missing dev <ifname>\n");
        return -1;
    }
    if (route_add(dest, mask, gw, ifindex) != 0) {
        snprintf(out, outsz, "route table full\n");
        return -1;
    }
    snprintf(out, outsz, "route ok\n");
    return 0;
}

static int cmd_delroute(int argc, char **argv, char *out, size_t outsz)
{
    int idx;

    if (argc != 2) {
        snprintf(out, outsz, "usage: delroute <index>\n");
        return -1;
    }
    idx = atoi(argv[1]);
    switch (route_del(idx)) {
    case 0:   snprintf(out, outsz, "route %d deleted\n", idx); return 0;
    case -2:  snprintf(out, outsz, "refuse: route %d is connected\n", idx); return -1;
    default:  snprintf(out, outsz, "no route %d\n", idx); return -1;
    }
}

static int cmd_showstat(int argc, char **argv, char *out, size_t outsz)
{
    (void)argc; (void)argv;
    snprintf(out, outsz,
        "rx=%lu tx=%lu drop=%lu fw_drop=%lu noroute=%lu self_drop=%lu\n"
        "ttl_drop=%lu arp_fail=%lu pend_drop=%lu malformed=%lu tx_err=%lu\n",
        (unsigned long)atomic_load(&g_rx), (unsigned long)atomic_load(&g_tx),
        (unsigned long)atomic_load(&g_drop), (unsigned long)atomic_load(&g_fw_drop),
        (unsigned long)atomic_load(&g_noroute), (unsigned long)atomic_load(&g_self_drop),
        (unsigned long)atomic_load(&g_ttl_drop), (unsigned long)atomic_load(&g_arp_fail),
        (unsigned long)atomic_load(&g_pend_drop), (unsigned long)atomic_load(&g_malformed),
        (unsigned long)atomic_load(&g_tx_err));
    return 0;
}

static int cmd_showfw(int argc, char **argv, char *out, size_t outsz)
{
    (void)argc; (void)argv;
    fw_show(out, outsz);
    return 0;
}

static int cmd_showroute(int argc, char **argv, char *out, size_t outsz)
{
    (void)argc; (void)argv;
    route_show(out, outsz);
    return 0;
}

static int cmd_showif(int argc, char **argv, char *out, size_t outsz)
{
    (void)argc; (void)argv;
    iface_show(out, outsz);
    return 0;
}

static int cmd_showarp(int argc, char **argv, char *out, size_t outsz)
{
    (void)argc; (void)argv;
    arp_show(out, outsz);
    return 0;
}

static int cmd_showthread(int argc, char **argv, char *out, size_t outsz)
{
    (void)argc; (void)argv;
    tpool_show(out, outsz);
    return 0;
}

static int cmd_showpool(int argc, char **argv, char *out, size_t outsz)
{
    (void)argc; (void)argv;
    mp_show(out, outsz);
    return 0;
}

static int cmd_showpend(int argc, char **argv, char *out, size_t outsz)
{
    (void)argc; (void)argv;
    pend_show(out, outsz);
    return 0;
}

static int cmd_showcfg(int argc, char **argv, char *out, size_t outsz)
{
    (void)argc; (void)argv;
    config_serialize(out, outsz);
    return 0;
}

static int cmd_save(int argc, char **argv, char *out, size_t outsz)
{
    (void)argc; (void)argv;
    if (config_save() != 0) {
        snprintf(out, outsz, "save failed\n");
        return -1;
    }
    snprintf(out, outsz, "saved to %s\n", CONFIG_FILE);
    return 0;
}

static int cmd_reload(int argc, char **argv, char *out, size_t outsz)
{
    (void)argc; (void)argv;
    if (config_load() != 0) {
        snprintf(out, outsz, "reload failed\n");
        return -1;
    }
    route_derive_connected();
    snprintf(out, outsz, "reloaded (threads=%d tcp=%d udp=%d take effect after restart)\n",
             cfg_threads(), cfg_tcp_port(), cfg_udp_port());
    return 0;
}

/* ---------- 分发 ---------- */

int cmd_dispatch(const char *line, char *out, size_t outsz)
{
    char buf[512];
    char *argv[24];
    int argc, i;

    snprintf(buf, sizeof(buf), "%s", line);
    argc = tok_split(buf, argv, 24);
    if (argc <= 0) {
        snprintf(out, outsz, "\n");
        return 0;
    }
    for (i = 0; i < N_CMDS; i++) {
        if (strcmp(argv[0], g_cmd_table[i].name) == 0) {
            if (!g_cmd_table[i].fn) {
                snprintf(out, outsz, "command '%s' is remote-only via this build\n", argv[0]);
                return -1;
            }
            return g_cmd_table[i].fn(argc, argv, out, outsz);
        }
    }
    snprintf(out, outsz, "unknown command '%s' (try 'help')\n", argv[0]);
    return -1;
}

/* ---------- 本地终端 ---------- */

static void *terminal_loop(void *arg)
{
    char line[512];
    char out[1024];
    int tty = isatty(fileno(stdin));

    (void)arg;
    LOG_INFO("terminal ready: type 'help' to list commands");
    while (!g_shutdown) {
        if (fgets(line, sizeof(line), stdin)) {
            line[strcspn(line, "\r\n")] = 0;
            if (line[0] == 0)
                continue;
            if (cmd_dispatch(line, out, sizeof(out)) == 1) {
                fputs(out, stdout);
                fflush(stdout);
                break;                      /* exit 请求停机 */
            }
            fputs(out, stdout);
            fflush(stdout);
        } else {
            if (tty)
                break;                      /* 交互终端 EOF → 停机 */
            sleep(1);                       /* 后台/无 stdin：不因 EOF 停机，等信号 */
        }
    }
    if (!g_shutdown)
        g_shutdown = 1;
    return NULL;
}

int terminal_start(void)
{
    pthread_t tid;

    if (pthread_create(&tid, NULL, terminal_loop, NULL) != 0)
        return -1;
    pthread_detach(tid);
    return 0;
}
