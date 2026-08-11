#ifndef __IP_LINK_H__
#define __IP_LINK_H__

//ip 链表
typedef struct ip_link
{
    unsigned char ip[4];//ip 地址 4 个字节：网络字节序的 32 位数据的 ip 地址
    struct ip_link *next; //指向下一个节点
}IP_LINK;

extern IP_LINK *ip_head; //头节点

/**
 * 插入 ip 过滤链表
 * 参数：
 * IP_LINK *head: ip 过滤链表头节点
 * IP_LINK *p: 待插入的节点
 * 返回值 IP_LINK*: 返回头节点
 */
extern IP_LINK *inner_ip_link(IP_LINK *head, IP_LINK *p);

/**
 * 打印 ip 过滤链表
 * 参数：
 * IP_LINK *head: ip 过滤链表头节点
 * 返回值: 无
 */
extern void printf_ip_link(IP_LINK *head);

/**
 * 查找 ip 过滤链表中对应的 ip
 * 参数：
 * IP_LINK *head: ip 过滤链表头节点
 * unsigned char *ip: 待查找的 ip
 * 返回值 IP_LINK *: 找到的 ip 节点
 */
extern IP_LINK *find_ip(IP_LINK *head, unsigned char *ip);

/**
 * 释放 ip 过滤链表
 * 参数：
 * IP_LINK *head: ip 过滤链表头节点
 * 返回值: 无
 */
extern void free_ip_link(IP_LINK *head);

/**
 * 删除 ip 过滤链表对应的 ip 节点
 * 参数：
 * IP_LINK *head: ip 过滤链表头节点
 * unsigned char *ip: 待删除的 ip
 * 返回值 IP_LINK *: ip 过滤链表头节点
 */
extern IP_LINK *del_ip_for_link(IP_LINK *head, unsigned char *ip);

/**
 * 读取配置文件数据到 ip 过滤链表
 * 参数：无
 * 返回值: 无
 */
extern void init_ip_link();

/**
 * 保存 ip 过滤链表数据到配置文件
 * 参数: 无
 * 返回值: 无
 */
extern void save_ip_link();

#endif // !__IP_LINK_H__