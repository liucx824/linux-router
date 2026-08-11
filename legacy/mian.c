#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h> //htons
#include <netinet/ether.h> //ETH_P_ALL
#include <pthread.h> //线程
#include "main.h"
#include "ip_link.h"
#include "arp_link.h"
#include "key_pthread.h"
#include "get_interface.h"
#include "arp_pthread.h"
#include "ip_pthread.h"

int main(int argc, char const *argv[])
{
    //初始化配置文件
    init_ip_link();
    //获取接口信息
    getinterface();

    //创建键盘处理线程并分离
    pthread_t KEY_T;
    pthread_create(&KEY_T, NULL, key_pthread, NULL);
    pthread_detach(KEY_T); //让键盘处理线程结束时，系统自动回收其资源

    //创建原始套接字，监听所有以太网数据包（包括ARP、IP、ICMP等）
    //PF_PACKET: 数据链路层套接字，SOCK_RAW: 原始套接字，ETH_P_ALL: 捕获所有类型协议
    raw_sock_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    char recv_buf[RECV_SIZE] = ""; //原始套接字数据包大约 1500 字节
    ssize_t recv_len = 0;
    while(1)
    {
        //清空缓冲区，避免残留数据干扰
        bzero(recv_buf, sizeof(recv_buf));
        recv_len = recvfrom(raw_sock_fd, recv_buf, sizeof(recv_buf), 0, NULL, NULL);
        if(recv_len <= 0 || recv_len > RECV_SIZE)
        {
            perror("recvfrom");
            continue;
        }
        if((recv_buf[12] == 0x08) && (recv_buf[13] == 0x06)) //ARP 协议包
        {
            ARP_LINK *p = (ARP_LINK *)malloc(sizeof(ARP_LINK));
            if(p == NULL)
            {
                perror("malloc");
                continue;
            }
            memcpy(p->mac, recv_buf + 22, 6); //源 MAC 地址
            memcpy(p->ip, recv_buf + 28, 4); //源 IP 地址
            printf("%d.%d.%d.%d", p->ip[0], p->ip[1], p->ip[2], p->ip[3]);
            //创建线程处理该 ARP 包
            pthread_t ARP_T;
            pthread_create(&ARP_T, NULL, arp_pthread, (void *)p);
            pthread_detach(ARP_T);
        }
        if((recv_buf[12] == 0x08) && (recv_buf[13] == 0x00)) //IP 协议包
        {
            //目的 ip 是否过滤
            IP_LINK *ip_pb = find_ip(ip_head, (unsigned char *)recv_buf + 30);
            if(ip_pb != NULL)
            {
                continue;
            }
            RECV_DATA *recv = (RECV_DATA *)malloc(sizeof(RECV_DATA));
            recv->data_len = recv_len;
            memcpy(recv->data, recv_buf, recv_len);
            //创建转发数据包处理线程
            pthread_t IP_T;
            pthread_create(&IP_T, NULL, ip_pthread, (void *)recv);
            pthread_detach(IP_T);
        }
    }

    return 0;
}
