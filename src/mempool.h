#ifndef MEMPOOL_H
#define MEMPOOL_H

#include "router.h"

/* 启动预分配 arena（MP_COUNT×MP_BLOCK ≈2MB）+ 空闲栈；栈空回退 malloc（安全降级） */
int  mp_init(void);
fwd_frame_t *mp_alloc(void);
void mp_free(fwd_frame_t *blk);
void mp_show(char *out, size_t outsz);
uint64_t mp_allocs(void);
uint64_t mp_frees(void);
uint64_t mp_fallbacks(void);

#endif /* MEMPOOL_H */
