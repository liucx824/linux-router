#ifndef ARP_PROTO_H
#define ARP_PROTO_H

#include "router.h"

/* 内联处理 ARP 帧（主收包循环调用，不排队，防止高负载下 ARP 饿死）：
 * 学习（防毒化：仅学同子网 spa）→ 应答 → 触发 pending flush */
void arp_handle_frame(fwd_frame_t *blk, int in_ifidx);
/* 主动广播 ARP 请求 */
void arp_request(ip_t ip, int ifidx);

#endif /* ARP_PROTO_H */
