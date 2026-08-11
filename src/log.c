#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <pthread.h>

#include "log.h"

static _Atomic int g_level = LOG_INFO;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static const char *const g_names[] = { "ERR", "WRN", "INF", "DBG" };

void log_set_level(int level)
{
    if (level >= LOG_ERR && level <= LOG_DEBUG)
        atomic_store(&g_level, level);
}

int log_get_level(void)
{
    return atomic_load(&g_level);
}

void log_msg(int level, const char *fmt, ...)
{
    struct timespec ts;
    struct tm tm;
    char stamp[24];
    va_list ap;

    if (level > atomic_load(&g_level))
        return;

    clock_gettime(CLOCK_REALTIME, &ts);

    pthread_mutex_lock(&g_lock);
    /* localtime 返回静态缓冲，但 g_lock 已串行化日志，安全 */
    if (localtime(&ts.tv_sec))
        tm = *localtime(&ts.tv_sec);
    else
        tm.tm_sec = tm.tm_min = tm.tm_hour = 0;
    strftime(stamp, sizeof(stamp), "%H:%M:%S", &tm);
    printf("[%s] %s ", stamp, g_names[level]);
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
    fflush(stdout);
    pthread_mutex_unlock(&g_lock);
}
