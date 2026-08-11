#include <unistd.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "arp_pthread.h"
#include "arp_link.h"

/**
 * ARP 包处理线程函数：将源 MAC 和源 IP 保存
 */
void *arp_pthread(void *arg)
{
    ARP_LINK *p = (ARP_LINK *)arg;
    arp_head = inner_arp_link(arp_head, p); //添加新节点到 ARP 链表
    return NULL;
}