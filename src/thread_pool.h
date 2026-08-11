#ifndef THREAD_POOL_H
#define THREAD_POOL_H

#include "router.h"

typedef void (*task_fn)(void *arg);

int  tpool_init(int nthreads);             /* 成功 0 */
int  tpool_submit(task_fn fn, void *arg);  /* 0 入队；-2 队列满（调用方负责释放 arg） */
void tpool_shutdown(void);                 /* 排空在途任务后 join 全部 worker */
void tpool_show(char *out, size_t outsz);
uint64_t tpool_executed(void);
uint64_t tpool_drops(void);

#endif /* THREAD_POOL_H */
