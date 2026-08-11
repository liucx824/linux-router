#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>

#include "router.h"
#include "packet.h"
#include "log.h"

uint16_t ip_checksum(const uint8_t *buf, size_t len)
{
    uint32_t sum = 0;

    while (len >= 2) {
        sum += get_be16(buf);
        buf += 2;
        len -= 2;
    }
    if (len)
        sum += (uint16_t)*buf << 8;
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

void ip_checksum_recompute(uint8_t *ip, size_t hdr_len)
{
    if (hdr_len < 12)
        return;
    ip[10] = 0;
    ip[11] = 0;
    put_be16(ip + 10, ip_checksum(ip, hdr_len));
}

uint16_t eth_type(const uint8_t *frame)
{
    return get_be16(frame + 12);
}

int pkt_send(const uint8_t *frame, size_t len, int ifindex)
{
    struct sockaddr_ll sll;
    ssize_t n;

    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = eth_type(frame);
    sll.sll_ifindex = ifindex;
    sll.sll_halen = 6;
    memcpy(sll.sll_addr, frame, 6);

    n = sendto(g_raw_fd, frame, len, 0, (struct sockaddr *)&sll, sizeof(sll));
    if (n < 0 || (size_t)n != len)
        return -1;
    return 0;
}
