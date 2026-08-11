#include <unistd.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "ip_link.h"
#include "arp_link.h"


typedef void (*FUN)(char *);

typedef struct cmd //执行的命令的结构体
{
    char cmd_str[20];
    FUN fun;
}KEY_CMD;

/**
 * 添加 IP 过滤
 * 参数: char *msg: 待过滤的 IP
 * 返回值: 无
 */
void setip(char *msg)
{
    unsigned char msg_ip[4];
    int ip;
    //将点分十进制 ip 字符串转换为网络字节序 32 位 ip 地址
    inet_pton(AF_INET, msg, &ip);
    memcpy(msg_ip, &ip, 4); //将 ip 的 4 个字节按顺序拷贝到 msg_ip 数组中，完成字节级拆分
    printf("%d.%d.%d.%d", msg_ip[0], msg_ip[1], msg_ip[2], msg_ip[3]);
    //msg_ip[3] == 0: 网络地址，msg_ip[3] == 255: 广播地址, msg_ip[0] == 0: 保留地址(0.0.0.0)，都不应该过滤
    if((msg_ip[3] == 0) || (msg_ip[3] == 255) || (msg_ip[0] == 0))
    {
        return;
    }
    IP_LINK *p = (IP_LINK *)malloc(sizeof(IP_LINK));
    memcpy(p->ip, msg_ip, 4);
    ip_head = inner_ip_link(ip_head, p); //插入 IP 过滤链表
    printf_ip_link(ip_head); //打印 IP 过滤链表
}

/**
 * 删除 IP 过滤
 * 参数 char *msg: 待删除的 IP
 * 返回值: 无
 */
void delip(char *msg)
{
    unsigned char msg_ip[4];
    int ip;
    //将点分十进制 ip 字符串转换为网络字节序 32 位 ip 地址
    inet_pton(AF_INET, msg, &ip);
    memcpy(msg_ip, &ip, 4); //将 ip 的 4 个字节按顺序拷贝到 msg_ip 数组中，完成字节级拆分
    printf("%d.%d.%d.%d", msg_ip[0], msg_ip[1], msg_ip[2], msg_ip[3]);
    //msg_ip[3] == 0: 网络地址，msg_ip[3] == 255: 广播地址, msg_ip[0] == 0: 保留地址(0.0.0.0)，都不应该过滤
    if((msg_ip[3] == 0) || (msg_ip[3] == 255) || (msg_ip[0] == 0))
    {
        return;
    }
    ip_head = del_ip_for_link(ip_head, msg_ip); //删除 IP 过滤链表节点
    printf_ip_link(ip_head); //打印 IP 过滤链表
}

/**
 * 帮助信息
 * 参数: 无
 * 返回值: 无
 */
void help(char *msg)
{
    printf("=------------------------=\n");
	printf("=---setip:172.20.226.4---=\n");
	printf("=---delip:172.20.226.4---=\n");
	printf("=---saveset--------------=\n");
	printf("=---showip---------------=\n"); 
	printf("=---showarp--------------=\n");
	printf("=------------------------=\n");	
}

/**
 * 显示 IP 过滤列表
 * 参数: 无
 * 返回值: 无
 */
void showip(char *msg)
{
    printf_ip_link(ip_head); //打印 IP 过滤链表
}

/**
 * 显示 ARP 列表
 * 参数: 无
 * 返回值: 无
 */
void showarp(char *msg)
{
    printf_arp_link(arp_head);
}

/**
 * 将链表中的过滤 IP 保存到配置文档
 * 参数: 无
 * 返回值: 无
 */
void saveset(char *msg)
{
    save_ip_link();
}

/**
 * 退出程序
 * 参数: 无
 * 返回值: 无
 */
void exit_route(char *msg)
{
    save_ip_link();
    free_ip_link(ip_head);
    free_arp_link(arp_head);
    _exit(1);
}

//定义字符串和函数指针的映射
KEY_CMD key_cmd[] = {
    {"help", help},
    {"setip", setip},
    {"delip", delip},
    {"showip", showip},
    {"showarp", showarp},
    {"saveset", saveset},
    {"exit", exit_route}
};

/**
 * 键盘输入处理线程函数
 * 参数: void*
 * 返回值: void*
 */
void *key_pthread(void *arg)
{
    printf("--------key_pthread--------");
    help("-");
    while (1)
    {
        char buff[100] = "";
        char cmd[100] = "";
        char msg[100] = "";
        fgets(buff, sizeof(buff), stdin); //获取键盘输入，放入 buff
        buff[strlen(buff) - 1] = '\0'; //去掉上面输入的换行符
        //例如命令：setip:172.20.226.4, "%[^:]": 取出冒号以外的，cmd=setip, ":%s": 取出冒号后面内容，msg=172.20.226.4
        sscanf(buff, "%[^:]:%s", cmd, msg);
        int i;
        for(i = 0; i < (sizeof(key_cmd)/sizeof(KEY_CMD)); i++)
        {
            if(strcmp(cmd, key_cmd[i].cmd_str) == 0) //如果输入的 cmd 等于 key_cmd 中的某个命令
            {
                key_cmd[i].fun(msg); //就调用对应的函数
                break;
            }
        }
    }
    return NULL;
}