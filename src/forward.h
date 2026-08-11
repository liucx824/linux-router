#ifndef FORWARD_H
#define FORWARD_H

#include "router.h"

/* 线程池 worker 入口：arg = fwd_frame_t*（帧所有权由本函数负责） */
void forward_task(void *arg);
/* 1s 定时器：补发 ARP 请求 / 超限丢弃整链 / 重查解析后冲刷 */
void pend_tick(void);
/* ARP 学习后冲刷某 (nexthop, out_ifidx) 的 pending 帧（顺序取锁，不嵌套） */
void forward_flush_pending(ip_t nexthop, int out_ifidx);
int  pend_count(void);
void pend_show(char *out, size_t outsz);

#endif /* FORWARD_H */
