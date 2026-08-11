#ifndef __ARP_LINK_H__
#define __ARP_LINK_H__

//arp 链表
typedef struct arp_link
{
    unsigned char ip[4]; //ip 地址 4 个字节，指网络字节序的 32 位的 ip 地址
    unsigned char mac[6]; //mac 地址 6 个字节
    struct arp_link *next; //指向下一个节点的指针 
}ARP_LINK;

extern ARP_LINK *arp_head; //arp 链表头节点

/**
 * 插入 ARP 链表
 * 参数：
 * ARP_LINK *head: ARP 链表头结点
 * ARP_LINK *p: 待插入的节点
 * 返回值 ARP_LINK*: ARP 链表头结点
 */
extern ARP_LINK *inner_arp_link(ARP_LINK *head, ARP_LINK *p);

/**
 * 打印 ARP 链表
 * 参数:
 * ARP_LINK *head: ARP 链表头结点
 * 返回值：无
 */
extern void printf_arp_link(ARP_LINK *head);

/**
 * 根据 ip 找到对应的 mac
 * 参数：
 * ARP_LINK *head: ARP 链表头结点
 * unsigned char *ip: ip 地址
 * 返回值 ARP_LINK *: 找到的 ARP 节点
 */
extern ARP_LINK *find_arp_from_ip(ARP_LINK *head, unsigned char *ip);

/**
 * 释放 ARP 链表
 * 参数：
 * ARP_LINK *head: ARP 链表头结点
 * 返回值: 无
 */
extern void free_arp_link(ARP_LINK *head);

#endif // !__ARP_LINK_H__