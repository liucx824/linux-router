#ifndef __MAIN_H__
#define __MAIN_H__

//原始套接字
int raw_sock_fd;

#define RECV_SIZE 2048
typedef struct recv_data //收到的数据
{
    ssize_t data_len; //数据长度
    unsigned char data[RECV_SIZE]; //接收缓冲区
}RECV_DATA;

#endif