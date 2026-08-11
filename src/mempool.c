#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdio.h>

#include "router.h"
#include "mempool.h"
#include "log.h"

static uint8_t *g_arena;
static uint32_t g_free_top;
static uint32_t g_free_stack[MP_COUNT];
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static _Atomic uint64_t g_allocs, g_frees, g_fallbacks;

int mp_init(void)
{
    uint32_t i;

    g_arena = malloc((size_t)MP_COUNT * MP_BLOCK);
    if (!g_arena) {
        LOG_ERR("mp_init: arena (%d blocks x %d B) alloc failed",
                MP_COUNT, MP_BLOCK);
        return -1;
    }
    g_free_top = 0;
    for (i = 0; i < MP_COUNT; i++)
        g_free_stack[g_free_top++] = i;
    g_allocs = g_frees = g_fallbacks = 0;
    LOG_INFO("mempool: arena %.2fMB (%d x %d B), payload %d B",
             (double)(MP_COUNT * MP_BLOCK) / (1024.0 * 1024.0),
             MP_COUNT, MP_BLOCK, MP_PAYLOAD);
    return 0;
}

fwd_frame_t *mp_alloc(void)
{
    fwd_frame_t *b = NULL;

    pthread_mutex_lock(&g_lock);
    if (g_free_top > 0) {
        uint32_t idx = g_free_stack[--g_free_top];
        b = (fwd_frame_t *)(g_arena + (size_t)idx * MP_BLOCK);
    }
    pthread_mutex_unlock(&g_lock);

    if (b) {
        b->next = NULL;
        b->len = 0;
        b->out_ifidx = 0;
        b->nexthop = 0;
    } else {
        g_fallbacks++;          /* 池耗尽：malloc 回退，安全降级 */
        b = malloc(MP_BLOCK);
        if (b) {
            b->next = NULL;
            b->len = 0;
            b->out_ifidx = 0;
            b->nexthop = 0;
        }
    }
    g_allocs++;
    return b;
}

void mp_free(fwd_frame_t *b)
{
    uintptr_t p, a;

    if (!b)
        return;
    p = (uintptr_t)b;
    a = (uintptr_t)g_arena;
    if (p >= a && p < a + (size_t)MP_COUNT * MP_BLOCK) {
        uint32_t idx = (uint32_t)((p - a) / MP_BLOCK);
        pthread_mutex_lock(&g_lock);
        if (g_free_top < MP_COUNT)
            g_free_stack[g_free_top++] = idx;
        pthread_mutex_unlock(&g_lock);
    } else {
        free(b);
    }
    g_frees++;
}

uint64_t mp_allocs(void)   { return atomic_load(&g_allocs); }
uint64_t mp_frees(void)    { return atomic_load(&g_frees); }
uint64_t mp_fallbacks(void){ return atomic_load(&g_fallbacks); }

void mp_show(char *out, size_t outsz)
{
    uint64_t a = mp_allocs(), f = mp_frees();
    snprintf(out, outsz,
             "mempool: blocks=%d  block=%d  arena=%.2fMB\n"
             "         allocs=%llu  frees=%llu  fallbacks=%llu  outstanding=%lld\n",
             MP_COUNT, MP_BLOCK, (double)(MP_COUNT * MP_BLOCK) / (1024.0 * 1024.0),
             (unsigned long long)a, (unsigned long long)f,
             (unsigned long long)mp_fallbacks(),
             (long long)(a - f));
}
