#include <pthread.h>
#include <stdio.h>

#include "router.h"
#include "thread_pool.h"
#include "log.h"

typedef struct task {
    task_fn fn;
    void  *arg;
} task_t;

typedef struct tpool {
    task_t q[TASK_CAP];
    unsigned head, tail, count;
    pthread_mutex_t lock;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
    pthread_t threads[POOL_THREADS];
    int nthreads;
    int shutdown;
    _Atomic uint64_t submitted, executed, drops;
} tpool_t;

static tpool_t g_pool;

static void *worker_main(void *arg)
{
    (void)arg;
    for (;;) {
        task_t t;

        pthread_mutex_lock(&g_pool.lock);
        while (g_pool.count == 0 && !g_pool.shutdown)
            pthread_cond_wait(&g_pool.not_empty, &g_pool.lock);
        if (g_pool.count == 0 && g_pool.shutdown) {
            pthread_mutex_unlock(&g_pool.lock);
            break;
        }
        t = g_pool.q[g_pool.head];
        g_pool.head = (g_pool.head + 1) % TASK_CAP;
        g_pool.count--;
        pthread_cond_signal(&g_pool.not_full);
        pthread_mutex_unlock(&g_pool.lock);

        t.fn(t.arg);
        atomic_fetch_add(&g_pool.executed, 1);
    }
    return NULL;
}

int tpool_init(int nthreads)
{
    pthread_attr_t attr;
    int i;

    if (nthreads <= 0)
        nthreads = POOL_THREADS;
    if (nthreads > POOL_THREADS)
        nthreads = POOL_THREADS;
    g_pool.nthreads = nthreads;

    pthread_mutex_init(&g_pool.lock, NULL);
    pthread_cond_init(&g_pool.not_empty, NULL);
    pthread_cond_init(&g_pool.not_full, NULL);

    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 64 * 1024);   /* 4 线程栈共 256KB，嵌入式可控 */
    for (i = 0; i < nthreads; i++) {
        if (pthread_create(&g_pool.threads[i], &attr, worker_main, NULL) != 0) {
            LOG_ERR("tpool_init: pthread_create #%d failed", i);
            pthread_attr_destroy(&attr);
            return -1;
        }
    }
    pthread_attr_destroy(&attr);
    LOG_INFO("thread_pool: %d workers, task queue cap=%d", nthreads, TASK_CAP);
    return 0;
}

int tpool_submit(task_fn fn, void *arg)
{
    pthread_mutex_lock(&g_pool.lock);
    if (g_pool.count == TASK_CAP || g_pool.shutdown) {
        pthread_mutex_unlock(&g_pool.lock);
        if (!g_pool.shutdown)
            atomic_fetch_add(&g_pool.drops, 1);   /* 仅队列满计 drop */
        return -2;
    }
    g_pool.q[g_pool.tail].fn = fn;
    g_pool.q[g_pool.tail].arg = arg;
    g_pool.tail = (g_pool.tail + 1) % TASK_CAP;
    g_pool.count++;
    atomic_fetch_add(&g_pool.submitted, 1);
    pthread_cond_signal(&g_pool.not_empty);
    pthread_mutex_unlock(&g_pool.lock);
    return 0;
}

void tpool_shutdown(void)
{
    int i;

    pthread_mutex_lock(&g_pool.lock);
    g_pool.shutdown = 1;
    pthread_cond_broadcast(&g_pool.not_empty);
    pthread_mutex_unlock(&g_pool.lock);

    for (i = 0; i < g_pool.nthreads; i++)
        pthread_join(g_pool.threads[i], NULL);   /* 排空在途任务，优雅停机 */
}

uint64_t tpool_executed(void) { return atomic_load(&g_pool.executed); }
uint64_t tpool_drops(void)    { return atomic_load(&g_pool.drops); }

void tpool_show(char *out, size_t outsz)
{
    unsigned depth;

    pthread_mutex_lock(&g_pool.lock);
    depth = g_pool.count;
    pthread_mutex_unlock(&g_pool.lock);

    snprintf(out, outsz,
             "thread_pool: workers=%d  queue_cap=%d  q_depth=%u\n"
             "             submitted=%llu  executed=%llu  drops=%llu\n",
             g_pool.nthreads, TASK_CAP, depth,
             (unsigned long long)atomic_load(&g_pool.submitted),
             (unsigned long long)tpool_executed(),
             (unsigned long long)tpool_drops());
}
