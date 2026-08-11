#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "ip_link.h"

#define ip_config_name "ip_config" //ip 配置文件名称

IP_LINK *ip_head = NULL; //链表头节点

/**
 * 保存 ip 过滤链表数据到配置文件
 * 参数: 无
 * 返回值: 无
 */
void save_ip_link()
{
    FILE *ip_config = fopen(ip_config_name, "wb+"); //wb+: 可读可写打开文件，创建长度为 0 的新文件
    if(ip_config == NULL)
    {
        perror("configure file, in main.c");
        _exit(-1);
    }
    char buff[20] = "";
    IP_LINK *pb = ip_head; //pb 指向当前节点
    while(pb != NULL)
    {
        sprintf(buff, "%d.%d.%d.%d\n", pb->ip[0], pb->ip[1], pb->ip[2], pb->ip[3]);+--
        fputs(buff, ip_config); //写一行
        pb = pb->next; //pb 指向下一个节点
    }
    fclose(ip_config);
}

/**
 * 读取配置文件数据到 ip 过滤链表
 * 参数：无
 * 返回值: 无
 */
void init_ip_link()
{
    FILE *ip_config = NULL;
    ip_config = fopen(ip_config_name, "rb+"); //rb+: 可读可写打开文件，不创建新文件
    if(ip_config == NULL)
    {
        perror("configure file, in main.c");
        _exit(-1);
    }
    while (1)
    {
        char buff[500] = "";
        bzero(buff, sizeof(buff)); //清零
        int ip;
        if(fgets(buff, sizeof(buff), ip_config) == NULL)
        {
            break; //读完配置文件就退出循环，一次读取一行
        }
        buff[strlen(buff) - 1] = 0; //去除每一行的 '\n'
        inet_pton(AF_INET, buff, &ip); //点分十进制 ip 字符串转网络字节序的 32 位 ip 地址
        IP_LINK *pb = (IP_LINK *)malloc(sizeof(IP_LINK)); //新节点
        memcpy(pb->ip, &ip, 4);
        ip_head = inner_ip_link(ip_head, pb); //往 ip 过滤链表中插入新节点
    }
    printf_ip_link(ip_head); //打印 ip 过滤链表
    fclose(ip_config);
}

/**
 * 释放 ip 过滤链表
 * 参数：
 * IP_LINK *head: ip 过滤链表头节点
 * 返回值: 无
 */
void free_ip_link(IP_LINK *head)
{
    IP_LINK *pb = head;
    while (head)
    {
        pb = head->next;
        free(head);
        head = pb;
    }
}

/**
 * 打印 ip 过滤链表
 * 参数：
 * IP_LINK *head: ip 过滤链表头节点
 * 返回值: 无
 */
void printf_ip_link(IP_LINK *head)
{
    printf("\n---------ip_link_start---------\n");
    IP_LINK *pb = head; //pb 代表当前节点
    while (pb != NULL)
    {
        printf("%d.%d.%d.%d\n", pb->ip[0], pb->ip[1], pb->ip[2], pb->ip[3]);
        pb = pb->next;
    }
    printf("---------ip_link_end---------\n\n");
}

/**
 * 查找 ip 过滤链表中对应的 ip
 * 参数：
 * IP_LINK *head: ip 过滤链表头节点
 * unsigned char *ip: 待查找的 ip
 * 返回值 IP_LINK *: 找到的 ip 节点
 */
IP_LINK *find_ip(IP_LINK *head, unsigned char *ip)
{
    IP_LINK *pb = head;
    while(pb)
    {
        if(memcmp(pb->ip, ip, 4) == 0) //如果参数 ip 的值和某个节点 ip 的值相同，则找到了 
        {
            break;
        }
        pb = pb->next;
    }
    return pb; //pb 就是当前要找的节点
}

/**
 * 插入 ip 过滤链表
 * 参数：
 * IP_LINK *head: ip 过滤链表头节点
 * IP_LINK *p: 待插入的节点
 * 返回值 IP_LINK*: 返回头节点
 */
IP_LINK *inner_ip_link(IP_LINK *head, IP_LINK *p)
{
    //查找是否有该记录
    IP_LINK *pb = find_ip(head, p->ip);
    if(pb == NULL) //未找到，就插入这个节点 p，直接插入在表头
    {
        p->next = head;
        head = p;
    }
    else
    {
        //如果节点 p 已经存在，则需要释放，避免重复插入
        free(p);
    }
    return head;
}

/**
 * 删除 ip 过滤链表对应的 ip 节点
 * 参数：
 * IP_LINK *head: ip 过滤链表头节点
 * unsigned char *ip: 待删除的 ip
 * 返回值 IP_LINK *: ip 过滤链表头节点
 */
IP_LINK *del_ip_for_link(IP_LINK *head, unsigned char *ip)
{
    IP_LINK *pf, *pb; //pf 指前驱节点, pb 指当前节点
    pf = pb = head;
    while(pb)
    {
        if(memcmp(pb->ip, ip, 4) == 0) //如果某个节点的 ip 和待删除的参数 ip 相同，证明这个节点 pb 就是待删除节点
        {
            break;
        }
        pf = pb; //更新前驱节点
        pb = pb->next; //更新当前节点
    }
    if(pb != NULL)
    {
        if(pb == head)
        {
            head = head->next;
        }
        else
        {
            pf->next = pb->next;
        }
        free(pb);//释放待删除节点
        pb = NULL;
    }
    return head;
}