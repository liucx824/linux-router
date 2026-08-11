#ifndef REMOTE_H
#define REMOTE_H

#include "router.h"

/* 启动远程管理：
 *   TCP <tcp_port>   MOTD → AUTH → 行命令 + getconf/putconf/upgrade 精确字节数模式
 *   UDP <udp_port>   stat/arp/route/conf/ping（只读无鉴权，≤1472B）
 * 端口启动时生效。成功返回 0。 */
int remote_init(void);

#endif /* REMOTE_H */
