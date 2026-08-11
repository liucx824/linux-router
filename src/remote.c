#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "router.h"
#include "remote.h"
#include "terminal.h"
#include "config.h"
#include "interface.h"
#include "arp_table.h"
#include "route.h"
#include "upgrade.h"
#include "utils.h"
#include "log.h"

#define CONF_TMP  (CONFIG_FILE ".new")   /* putconf 临时目标 */

enum { MODE_LINE = 0, MODE_PUTCONF = 1, MODE_UPGRADE = 2 };

typedef struct conn {
    int    fd;
    int    authed;
    int    closed;
    char   ibuf[16384];
    size_t ilen;
    int    binary;      /* 精确字节数模式 */
    size_t bleft;       /* 尚需接收的字节 */
    int    mode;
    FILE  *pcfp;        /* putconf 临时文件句柄 */
} conn_t;

/* ---------- 发送辅助（MSG_NOSIGNAL 防对端断开触发 SIGPIPE 杀进程） ---------- */

static int send_all(int fd, const char *p, size_t n)
{
    while (n > 0) {
        ssize_t w = send(fd, p, n, MSG_NOSIGNAL);
        if (w <= 0)
            return -1;
        p += w;
        n -= (size_t)w;
    }
    return 0;
}

static int send_str(int fd, const char *s)
{
    return send_all(fd, s, strlen(s));
}

/* ---------- 单条命令处理 ---------- */

static void handle_line(conn_t *c, char *line)
{
    char copy[512];
    char first[16];
    char *argv[24];
    int argc;

    if (strlen(line) >= sizeof(copy)) {
        send_str(c->fd, "line too long\r\nCMD_ERR\r\n");
        return;
    }
    snprintf(copy, sizeof(copy), "%s", line);
    argc = tok_split(copy, argv, 24);
    if (argc <= 0)
        return;
    snprintf(first, sizeof(first), "%s", argv[0]);

    if (strcmp(first, "auth") == 0) {
        const char *pw = cfg_password();
        if (pw[0] == 0 || (argc >= 2 && strcmp(argv[1], pw) == 0)) {
            c->authed = 1;
            send_str(c->fd, "AUTH_OK\r\n");
        } else {
            send_str(c->fd, "AUTH_FAIL\r\n");
        }
        return;
    }
    if (!c->authed) {
        send_str(c->fd, "AUTH_REQUIRED\r\n");
        return;
    }

    if (strcmp(first, "getconf") == 0) {
        char buf[16384];
        char hdr[64];
        int n = config_serialize(buf, sizeof(buf));
        if (n < 0)
            n = 0;
        snprintf(hdr, sizeof(hdr), "CONF_BEGIN %d\r\n", n);
        send_str(c->fd, hdr);
        send_all(c->fd, buf, (size_t)n);
        send_str(c->fd, "\r\nCONF_END\r\n");
        return;
    }
    if (strcmp(first, "putconf") == 0 && argc >= 2) {
        size_t size = strtoul(argv[1], NULL, 10);
        if (size == 0 || size > 256 * 1024) {
            send_str(c->fd, "bad size\r\nCMD_ERR\r\n");
            return;
        }
        c->pcfp = fopen(CONF_TMP, "w");
        if (!c->pcfp) {
            send_str(c->fd, "open failed\r\nCMD_ERR\r\n");
            return;
        }
        c->binary = 1;
        c->bleft = size;
        c->mode = MODE_PUTCONF;
        send_str(c->fd, "OK\r\n");
        return;
    }
    if (strcmp(first, "upgrade") == 0 && argc >= 3) {
        size_t size = strtoul(argv[1], NULL, 10);
        char err[128];
        char e[256];
        if (upgrade_begin(argv[2], size, err, sizeof(err)) != 0) {
            snprintf(e, sizeof(e), "%s\r\nCMD_ERR\r\n", err);
            send_str(c->fd, e);
            return;
        }
        c->binary = 1;
        c->bleft = size;
        c->mode = MODE_UPGRADE;
        send_str(c->fd, "OK\r\n");
        return;
    }

    /* 常规命令（本地与远程共用命令表）；exit 只关本连接 */
    {
        char out[2048];
        int rc;
        if (strcmp(first, "stat") == 0)
            rc = cmd_dispatch("showstat", out, sizeof(out));
        else
            rc = cmd_dispatch(line, out, sizeof(out));
        send_str(c->fd, out);
        if (rc == 1)
            send_str(c->fd, "\r\nCMD_OK\r\n");
        else
            send_str(c->fd, rc == 0 ? "\r\nCMD_OK\r\n" : "\r\nCMD_ERR\r\n");
        if (rc == 1)
            c->closed = 1;
    }
}

/* ---------- 行协议 + 二进制流 ---------- */

static void process_lines(conn_t *c)
{
    while (c->ilen) {
        char *nl = (char *)memchr(c->ibuf, '\n', c->ilen);
        if (!nl)
            break;                       /* 半行，等更多数据 */
        *nl = 0;
        {
            size_t linelen = (size_t)(nl - c->ibuf);
            if (linelen > 0 && c->ibuf[linelen - 1] == '\r')
                c->ibuf[linelen - 1] = 0;
            handle_line(c, c->ibuf);
        }
        {
            size_t used = (size_t)(nl - c->ibuf) + 1;
            memmove(c->ibuf, nl + 1, c->ilen - used);
            c->ilen -= used;
        }
        if (c->closed || c->binary)
            return;                      /* 切二进制模式：剩余字节即流首 */
    }
}

/* 二进制流写出（按模式路由到 putconf 文件或 upgrade） */
static int bin_write(conn_t *c, const char *p, size_t n)
{
    if (c->mode == MODE_PUTCONF) {
        if (fwrite(p, 1, n, c->pcfp) != n)
            return -1;
    } else if (c->mode == MODE_UPGRADE) {
        char err[128];
        char e[256];
        if (upgrade_write((const uint8_t *)p, n, err, sizeof(err)) != 0) {
            snprintf(e, sizeof(e), "%s\r\nCMD_ERR\r\n", err);
            send_str(c->fd, e);
            return -1;
        }
    }
    return 0;
}

/* 二进制流收满后的落地 */
static int bin_finish(conn_t *c)
{
    if (c->mode == MODE_PUTCONF) {
        fclose(c->pcfp);
        c->pcfp = NULL;
        if (rename(CONF_TMP, CONFIG_FILE) != 0) {
            unlink(CONF_TMP);
            send_str(c->fd, "rename failed\r\nCMD_ERR\r\n");
            return -1;
        }
        config_load();
        route_derive_connected();
        send_str(c->fd, "OK reloaded\r\n");
    } else if (c->mode == MODE_UPGRADE) {
        char err[128];
        char e[256];
        if (upgrade_finish(err, sizeof(err)) != 0) {
            snprintf(e, sizeof(e), "%s\r\nCMD_ERR\r\n", err);
            send_str(c->fd, e);
            return -1;
        }
        send_str(c->fd, "OK upgrading\r\n");
        upgrade_exec();                  /* execv 替换进程，正常不返回 */
    }
    return 0;
}

static void conn_pump(conn_t *c)
{
    while (!c->closed && !g_shutdown) {
        ssize_t n = recv(c->fd, c->ibuf + c->ilen,
                         sizeof(c->ibuf) - c->ilen, 0);
        if (n <= 0)
            break;                       /* 对端关闭 / 出错 */
        c->ilen += (size_t)n;

        if (c->binary) {
            size_t take = c->ilen < c->bleft ? c->ilen : c->bleft;
            if (take && bin_write(c, c->ibuf, take) != 0)
                break;
            memmove(c->ibuf, c->ibuf + take, c->ilen - take);
            c->ilen -= take;
            c->bleft -= take;
            if (c->bleft == 0) {
                c->binary = 0;
                if (bin_finish(c) != 0)
                    break;
                process_lines(c);        /* 流后可能紧跟下一条命令 */
            }
            continue;
        }

        if (c->ilen > 8192) {            /* 无换行堆积：协议错误 */
            send_str(c->fd, "protocol error\r\nCMD_ERR\r\n");
            break;
        }
        process_lines(c);
    }
}

static void *conn_thread(void *arg)
{
    conn_t *c = (conn_t *)arg;

    send_str(c->fd, "MOTD RTR v1.0\r\n");
    if (cfg_password()[0] == 0)
        c->authed = 1;                   /* 未设口令 = 免鉴权 */
    conn_pump(c);
    if (c->mode == MODE_PUTCONF && c->pcfp) {
        fclose(c->pcfp);
        unlink(CONF_TMP);
    }
    if (c->mode == MODE_UPGRADE)
        upgrade_abort();                 /* 半途断开则清理 .new */
    close(c->fd);
    free(c);
    return NULL;
}

/* ---------- TCP 监听 ---------- */

static void *tcp_thread(void *arg)
{
    int lfd, fd;
    struct sockaddr_in sa;
    int one = 1;
    pthread_t tid;

    (void)arg;
    lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0)
        return NULL;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    sa.sin_port = htons((uint16_t)cfg_tcp_port());
    if (bind(lfd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        LOG_ERR("remote tcp: bind :%d failed", cfg_tcp_port());
        close(lfd);
        return NULL;
    }
    listen(lfd, 8);
    LOG_INFO("remote tcp listening on :%d", cfg_tcp_port());

    while (!g_shutdown) {
        fd = accept(lfd, NULL, NULL);
        if (fd < 0) {
            if (g_shutdown)
                break;
            continue;
        }
        conn_t *c = calloc(1, sizeof(conn_t));
        if (!c) {
            close(fd);
            continue;
        }
        c->fd = fd;
        if (pthread_create(&tid, NULL, conn_thread, c) != 0) {
            close(fd);
            free(c);
        } else {
            pthread_detach(tid);
        }
    }
    close(lfd);
    return NULL;
}

/* ---------- UDP 状态查询（只读无鉴权） ---------- */

static void *udp_thread(void *arg)
{
    int fd;
    struct sockaddr_in sa, peer;
    socklen_t plen;
    char buf[1500];
    char out[1472];

    (void)arg;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return NULL;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    sa.sin_port = htons((uint16_t)cfg_udp_port());
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        LOG_ERR("remote udp: bind :%d failed", cfg_udp_port());
        close(fd);
        return NULL;
    }
    LOG_INFO("remote udp listening on :%d", cfg_udp_port());

    while (!g_shutdown) {
        plen = sizeof(peer);
        ssize_t n = recvfrom(fd, buf, sizeof(buf) - 1, 0,
                             (struct sockaddr *)&peer, &plen);
        if (n <= 0)
            continue;
        buf[n] = 0;

        char *argv[8];
        char first[16];
        int argc = tok_split(buf, argv, 8);
        if (argc <= 0)
            continue;
        snprintf(first, sizeof(first), "%s", argv[0]);

        if (strcmp(first, "ping") == 0) {
            snprintf(out, sizeof(out), "pong");
        } else if (strcmp(first, "stat") == 0) {
            cmd_dispatch("showstat", out, sizeof(out));
        } else if (strcmp(first, "arp") == 0) {
            arp_show(out, sizeof(out));
        } else if (strcmp(first, "route") == 0) {
            route_show(out, sizeof(out));
        } else if (strcmp(first, "conf") == 0) {
            if (config_serialize(out, sizeof(out)) < 0)
                snprintf(out, sizeof(out), "config too large\n");
        } else {
            snprintf(out, sizeof(out), "ERR unknown cmd\n");
        }
        sendto(fd, out, strlen(out), 0, (struct sockaddr *)&peer, plen);
    }
    close(fd);
    return NULL;
}

int remote_init(void)
{
    pthread_t tid;

    if (pthread_create(&tid, NULL, tcp_thread, NULL) != 0)
        return -1;
    pthread_detach(tid);
    if (pthread_create(&tid, NULL, udp_thread, NULL) != 0)
        return -1;
    pthread_detach(tid);
    return 0;
}
