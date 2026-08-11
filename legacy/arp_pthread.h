#ifndef __ARP_PTHREAD_H__
#define __ARP_PTHREAD_H__

/**
 * ARP 包处理线程函数：将源 MAC 和源 IP 保存
 */
extern void *arp_pthread(void *arg);

#endif // !__ARP_PTHREAD_H__