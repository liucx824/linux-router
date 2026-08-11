#ifndef CONFIG_H
#define CONFIG_H

#include "router.h"

/* 运行时配置：由 router.conf 加载，reload/save 更新。
 * g_cfg 为 config.c 内部实现，外部一律经访问器读取（互斥保护，TSAN 友好）。 */
typedef struct router_cfg {
    char hostname[32];
    char password[64];      /* 空 = TCP 远程无鉴权 */
    int  threads;           /* 线程池 worker 数（启动时生效） */
    int  tcp_port;          /* 远程 TCP 端口（启动时生效） */
    int  udp_port;          /* 远程 UDP 端口（启动时生效） */
    int  arp_timeout;       /* ARP 老化秒数 */
    int  arp_proxy;         /* 0/1 代理 ARP */
    int  log_level;         /* LOG_ERR..LOG_DEBUG */
} router_cfg_t;

void config_default(void);
int  config_load(void);                /* 加载 router.conf；无文件 → 告警+生成默认+继续。成功 0 */
int  config_save(void);                /* 临时文件+rename 原子写回。成功 0 */
int  config_serialize(char *buf, size_t size); /* 序列化当前配置（getconf/conf 命令用），返回长度或 -1 */

const char *cfg_hostname(void);
const char *cfg_password(void);
int  cfg_threads(void);
int  cfg_tcp_port(void);
int  cfg_udp_port(void);
int  cfg_arp_timeout(void);
int  cfg_arp_proxy(void);
int  cfg_log_level(void);

#endif /* CONFIG_H */
