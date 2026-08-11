#ifndef __GET_INTERFACE_H__
#define __GET_INTERFACE_H__

#define MAXINTERFACES 16 //最大接口数(网卡数)

typedef struct interface //网络接口(网卡)
{
    char name[20]; //接口名称(网卡名称)
    unsigned char ip[4]; //ip 地址，网络字节序的 32 位 ip 地址
    unsigned char mac[6]; //mac 地址
    unsigned char netmask[4]; //子网掩码
    unsigned char br_ip[4]; //广播地址
    int flag; //网卡状态
}INTERFACE;

extern INTERFACE net_interface[MAXINTERFACES]; //接口数据，全局变量，对外声明

/**
 * 获取接口信息
 * 参数: 无
 * 返回值: 无
 */
extern void getinterface();

/**
 * 获取实际接口数量
 * 参数：无
 * 返回值：接口数量
 */
extern int get_interface_num();

#endif // !_GET_INTERFACE_H__