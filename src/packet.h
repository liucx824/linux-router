#ifndef PACKET_H
#define PACKET_H

#include "router.h"

/* RFC 1071 校验和，输入为大端字节流，返回大端校验和值 */
uint16_t ip_checksum(const uint8_t *hdr, size_t len);
/* 清零 IP 头校验和字段后全量重算填入 */
void ip_checksum_recompute(uint8_t *ip_hdr, size_t hdr_len);
/* 通过原始套接字发送整帧，目的 MAC 取帧头前 6 字节；成功 0，失败 -1 */
int pkt_send(const uint8_t *frame, size_t len, int ifindex);
uint16_t eth_type(const uint8_t *frame);

#endif /* PACKET_H */
