#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

#include "router.h"
#include "packet.h"
#include "interface.h"
#include "arp_table.h"
#include "arp_proto.h"
#include "forward.h"
#include "mempool.h"
#include "thread_pool.h"
#include "config.h"
#include "remote.h"
#include "route.h"
#include "terminal.h"
#include "log.h"
#include "utils.h"

volatile sig_atomic_t g_shutdown = 0;
int g_raw_fd = -1;

_Atomic uint64_t g_rx, g_tx, g_drop, g_fw_drop, g_noroute, g_self_drop,
                g_arp_fail, g_tx_err, g_ttl_drop, g_malformed, g_pend_drop;

#define VERSION "1.0"

static void signal_handler(int sig)
{
    (void)sig;
    g_shutdown = 1;
}

static void install_signals(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);   /* 对端断开时避免 SIGPIPE 杀进程（socket 已用 MSG_NOSIGNAL） */
}

static void usage(void)
{
    printf(
        "router %s - Linux user-space router (embedded style)\n"
        "usage: ./router [--help] [--version]\n"
        "\n"
        "  needs root (raw socket + iface ioctl):  sudo ./router\n"
        "  terminal commands: help / showif / showarp / showstat / ...\n"
        "  remote tcp:%d (MOTD/AUTH/cmd/getconf/putconf/upgrade), udp:%d (stat/arp/route/conf/ping)\n"
        "\n",
        VERSION, TCP_PORT, UDP_PORT);
}

/* 1s 定时器：ARP 老化 + pending 重试/超限丢弃 */
static void *timer_thread(void *arg)
{
    (void)arg;
    while (!g_shutdown) {
        sleep(1);
        if (g_shutdown)
            break;
        arp_tick();
        pend_tick();
    }
    return NULL;
}

/* 收包主循环：recvfrom 直收进内存池块 → 自帧过滤 → ARP 内联 / IP 入队 / 其余丢弃 */
static void rx_loop(void)
{
    while (!g_shutdown) {
        fwd_frame_t *blk = mp_alloc();
        struct sockaddr_ll sll;
        socklen_t slen;
        uint16_t etype;
        ssize_t n;

        if (!blk) {                  /* 池耗尽（不应发生，有 malloc 回退） */
            usleep(1000);
            continue;
        }
        slen = sizeof(sll);
        n = recvfrom(g_raw_fd, blk->data, MP_PAYLOAD, 0,
                     (struct sockaddr *)&sll, &slen);
        if (n <= 0) {
            if (g_shutdown)
                break;
            continue;
        }
        atomic_fetch_add(&g_rx, 1);
        blk->len = (uint16_t)n;

        /* 自帧过滤：本机发出的（PACKET_OUTGOING）或源 MAC 为本机 → 交内核，不转发 */
        if (sll.sll_pkttype == PACKET_OUTGOING ||
            (n >= 14 && iface_mac_is_ours(blk->data + 6))) {
            atomic_fetch_add(&g_self_drop, 1);
            atomic_fetch_add(&g_drop, 1);
            mp_free(blk);
            continue;
        }

        if (n < 14) {
            atomic_fetch_add(&g_malformed, 1);
            atomic_fetch_add(&g_drop, 1);
            mp_free(blk);
            continue;
        }
        etype = get_be16(blk->data + 12);

        if (etype == ETHERTYPE_ARP) {
            /* 内联处理：学习/应答不排队，防高负载下 ARP 饿死 */
            arp_handle_frame(blk, sll.sll_ifindex);
        } else if (etype == ETHERTYPE_IP) {
            int rc = tpool_submit(forward_task, blk);
            if (rc != 0) {           /* 队列满（-2）：调用方负责释放 */
                atomic_fetch_add(&g_drop, 1);
                mp_free(blk);
            }
        } else {
            atomic_fetch_add(&g_drop, 1);
            mp_free(blk);
        }
    }
}

int main(int argc, char **argv)
{
    pthread_t tid;
    int port;

    if (argc >= 2) {
        if (strcmp(argv[1], "--help") == 0) { usage(); return 0; }
        if (strcmp(argv[1], "--version") == 0) {
            printf("router %s\n", VERSION);
            return 0;
        }
    }

    install_signals();
    log_set_level(LOG_INFO);

    if (mp_init() != 0) {
        LOG_ERR("memory pool init failed");
        return 1;
    }
    if (iface_init() < 0) {
        LOG_ERR("interface enumeration failed");
        return 1;
    }

    config_load();                     /* 无文件 → 告警+生成默认，继续运行 */
    route_derive_connected();
    arp_init();
    arp_set_timeout(cfg_arp_timeout());

    if (tpool_init(cfg_threads()) != 0) {
        LOG_ERR("thread pool init failed");
        return 1;
    }

    g_raw_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (g_raw_fd < 0) {
        LOG_ERR("raw socket failed (run as root: sudo ./router)");
        return 1;
    }

    if (terminal_start() != 0)
        LOG_WARN("terminal start failed");
    if (pthread_create(&tid, NULL, timer_thread, NULL) != 0)
        LOG_WARN("timer thread start failed");
    else
        pthread_detach(tid);

    remote_init();

    port = cfg_tcp_port();
    LOG_INFO("router %s up: %d ifaces, %d threads, remote tcp:%d udp:%d",
             VERSION, iface_count(), cfg_threads(),
             port, cfg_udp_port());

    rx_loop();

    LOG_INFO("shutting down...");
    tpool_shutdown();
    if (g_raw_fd >= 0)
        close(g_raw_fd);
    return 0;
}
