#ifndef LOG_H
#define LOG_H

#include "router.h"

enum {
    LOG_ERR = 0,
    LOG_WARN = 1,
    LOG_INFO = 2,
    LOG_DEBUG = 3
};

void log_set_level(int level);
int  log_get_level(void);
void log_msg(int level, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

#define LOG_ERR(...)   log_msg(LOG_ERR, __VA_ARGS__)
#define LOG_WARN(...)  log_msg(LOG_WARN, __VA_ARGS__)
#define LOG_INFO(...)  log_msg(LOG_INFO, __VA_ARGS__)
#define LOG_DEBUG(...) log_msg(LOG_DEBUG, __VA_ARGS__)

#endif /* LOG_H */
