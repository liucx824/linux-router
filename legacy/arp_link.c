#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "arp_link.h"

ARP_LINK *arp_head = NULL; //arp 链表头节点

/**
 * 释放 ARP 链表
 * 参数：
 * ARP_LINK *head: ARP 链表头结点
 * 返回值: 无
 */
void free_arp_link(ARP_LINK *head)
{
    ARP_LINK *pb = head;
    while(head)
    {
        pb = head->next;
        free(head);
        head = pb;
    }
}

/**
 * 打印 ARP 链表
 * 参数:
 * ARP_LINK *head: ARP 链表头结点
 * 返回值：无
 */
void printf_arp_link(ARP_LINK *head)
{
    printf("\n\n--------arp_link_start--------\n");
    ARP_LINK *pb = head;
    while (pb)
    {
        printf("%d.%d.%d.%d--->", pb->ip[0], pb->ip[1], pb->ip[2], pb->ip[3]);
        printf("%02x:%02x:%02x:%02x:%02x:%02x\n", 
            pb->mac[0], pb->mac[1], pb->mac[2], pb->mac[3], pb->mac[4], pb->mac[5]);
        pb = pb->next;
    }
    printf("--------arp_link_end--------\n\n");
}

/**
 * 根据 ip 找到对应的 mac
 * 参数：
 * ARP_LINK *head: ARP 链表头结点
 * unsigned char *ip: ip 地址
 * 返回值 ARP_LINK *: 找到的 ARP 节点
 */
ARP_LINK *find_arp_from_ip(ARP_LINK *head, unsigned char *ip)
{
    ARP_LINK *pb = head;
    while (pb)
    {
        if(memcmp(pb->ip, ip, 4) == 0)
        {
            break;
        }
        pb = pb->next;
    }
    return pb;
}

/**
 * 插入 ARP 链表
 * 参数：
 * ARP_LINK *head: ARP 链表头结点
 * ARP_LINK *p: 待插入的节点
 * 返回值 ARP_LINK*: ARP 链表头结点
 */
ARP_LINK *inner_arp_link(ARP_LINK *head, ARP_LINK *p)
{
    ARP_LINK *pb = find_arp_from_ip(head, p->ip); //查找是否有该记录
    if(pb == NULL) //未找到，直接插入链表，直接插入在头部
    {
        p->next = head;
        head = p;
    }
    else //否则就是找到了对应的 ip，修改链表
    {
        memcpy(pb->mac, p->mac, 6); //拷贝 mac 地址
    }
    return head;
}s