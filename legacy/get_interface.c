#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/ether.h>
#include "get_interface.h"

int interface_num = 0; //接口数量
INTERFACE net_interface[MAXINTERFACES]; //接口数据，全局变量

/**
 * 获取实际接口数量
 * 参数：无
 * 返回值：接口数量
 */
int get_interface_num()
{
    return interface_num;
}

/**
 * 获取接口信息
 * 参数: 无
 * 返回值: 无
 */
void getinterface()
{
    //定义最大接口数组，每个 ifreq 接口提存储一个接口的详细信息
    struct ifreq buf[MAXINTERFACES]; //ifreq 结构数组
    //ifconf 结构用于批量获取接口列表，包含缓冲区指针和长度
    struct ifconf ifc; //ifconf 接口：用于 SIOCGIFCONF ioctl 的输入输出参数

    //创建延时套接字，ETH_P_ALL：捕获所有以太网协议类型（包括ARP，IP等）
    int sock_raw_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    //初始化 ifconf 接口
    ifc.ifc_len = sizeof(buf); //设置缓冲区大小为整个 ifreq 数组
    ifc.ifc_buf = (caddr_t)buf; //指向缓冲区其实地址，ioctl 将填充接口信息

    //获取接口列表
    if(ioctl(sock_raw_fd, SIOCGIFCONF, (char *)&ifc) == -1)
    {
        perror("SIOCGIFCONF ioctl");
        return;
    }
    //得到接口的数量
    interface_num = ifc.ifc_len / sizeof(struct ifreq); //所有接口所占字节数 / 每个接口所占字节数
    printf("interface_num=%d\n\n", interface_num);
    char buff[20] = "";
    int ip;
    int if_len = interface_num; //接口数量, if_len 作为数组下标
    while (if_len-- > 0) //遍历每个接口
    {
        //打印接口名称(如 ens33, wlan0, ens38)
        printf("%s\n", buf[if_len].ifr_name); //接口名称
        //复制接口名称到接口全局数组的接口名称中
        sprintf(net_interface[if_len].name, "%s", buf[if_len].ifr_name); //接口名称
        //调试输出：接口索引(下标 if_len)和名称，便于调试程序
        printf("-%d-%s--\n", if_len, net_interface[if_len].name);
        //获得当前接口标志
        if(!(ioctl(sock_raw_fd, SIOCGIFFLAGS, (char *)&buf[if_len])))
        {
            //接口状态
            if(buf[if_len].ifr_flags & IFF_UP) //当前接口状态为 UP 状态
            {
                printf("UP\n");
                net_interface[if_len].flag = 1; //标记为当前接口状态为激活状态，与 setip() 中的过滤逻辑联动
            }
            else
            {
                printf("DOWN\n");
                net_interface[if_len].flag = 0; //标记为当前接口状态为未激活状态
            }
        }
        else
        {
            char str[256];
            sprintf(str, "SIOCGIFFLAGS ioctl %s", buf[if_len].ifr_name);
            perror(str);
        }

        //获取当前网卡对应 IP 地址
        if(!(ioctl(sock_raw_fd, SIOCGIFADDR, (char *)&buf[if_len])))
        {
            //将网络字节序的 32 位 ip 地址转为点分十进制 ip 字符串
            printf("IP: %s\n", (char *)inet_ntoa(((struct sockaddr_in *)(&buf[if_len].ifr_addr))->sin_addr));
            bzero(buff, sizeof(buff));
            //将字符串格式的 ip 存入缓冲区
            sprintf(buff, "%s", (char *)inet_ntoa(((struct sockaddr_in *)(&buf[if_len].ifr_addr))->sin_addr));
            //将点分十进制的 ip(buff)，转为网络字节序的 32 位 ip地址
            inet_pton(AF_INET, buff, &ip);
            memcpy(net_interface[if_len].ip, &ip, 4);
        }
        else
        {
            char str[256];
            sprintf(str, "SIOCGIFADDR ioctl %s", buf[if_len].ifr_name);
            perror(str);
        }

        //获取当前网卡对应子网掩码
        if(!(ioctl(sock_raw_fd, SIOCGIFNETMASK, (char *)&buf[if_len])))
        {
            //将网络字节序的 32 位 ip 地址转为点分十进制 ip 字符串
            printf("netmask: %s\n", (char *)inet_ntoa(((struct sockaddr_in *)(&buf[if_len].ifr_addr))->sin_addr));
            bzero(buff, sizeof(buff));
            //将字符串格式的 ip 存入缓冲区
            sprintf(buff, "%s", (char *)inet_ntoa(((struct sockaddr_in *)(&buf[if_len].ifr_addr))->sin_addr));
            //将点分十进制的 ip(buff)，转为网络字节序的 32 位 ip地址
            inet_pton(AF_INET, buff, &ip);
            memcpy(net_interface[if_len].netmask, &ip, 4);
        }
        else
        {
            char str[256];
            sprintf(str, "SIOCGIFNETMASK ioctl %s", buf[if_len].ifr_name);
            perror(str);
        }

        //获取当前网卡对应广播地址
        if(!(ioctl(sock_raw_fd, SIOCGIFBRDADDR, (char *)&buf[if_len])))
        {
            //将网络字节序的 32 位 ip 地址转为点分十进制 ip 字符串
            printf("br_ip: %s\n", (char *)inet_ntoa(((struct sockaddr_in *)(&buf[if_len].ifr_addr))->sin_addr));
            bzero(buff, sizeof(buff));
            //将字符串格式的 ip 存入缓冲区
            sprintf(buff, "%s", (char *)inet_ntoa(((struct sockaddr_in *)(&buf[if_len].ifr_addr))->sin_addr));
            //将点分十进制的 ip(buff)，转为网络字节序的 32 位 ip地址
            inet_pton(AF_INET, buff, &ip);
            memcpy(net_interface[if_len].br_ip, &ip, 4);
        }
        else
        {
            char str[256];
            sprintf(str, "SIOCGIFBRDADDR ioctl %s", buf[if_len].ifr_name);
            perror(str);
        }

        //获取当前网卡的 MAC 地址
        if(!(ioctl(sock_raw_fd, SIOCGIFHWADDR, (char *)&buf[if_len])))
        {
            printf("MAC:%02x:%02x:%02x:%02x:%02x:%02x\n\n",
                (unsigned char)buf[if_len].ifr_hwaddr.sa_data[0],
                (unsigned char)buf[if_len].ifr_hwaddr.sa_data[1],
                (unsigned char)buf[if_len].ifr_hwaddr.sa_data[2],
                (unsigned char)buf[if_len].ifr_hwaddr.sa_data[3],
                (unsigned char)buf[if_len].ifr_hwaddr.sa_data[4],
                (unsigned char)buf[if_len].ifr_hwaddr.sa_data[5]);
            memcpy(net_interface[if_len].mac, (unsigned char *)buf[if_len].ifr_hwaddr.sa_data, 6);
        }
        else
        {
            char str[256];
            sprintf(str, "SIOCGIFHWADDR ioctl %s", buf[if_len].ifr_name);
            perror(str);
        }
    }// while end
    close(sock_raw_fd); //关闭 socket
}