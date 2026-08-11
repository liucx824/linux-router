#ifndef TERMINAL_H
#define TERMINAL_H

#include "router.h"

/* 本地 stdin 命令线程（detach 后台运行） */
int  terminal_start(void);
/* 通用命令分发：line 为不含换行的命令，结果写 out（绝不 printf 到 stdout）。
 * 本地 stdin 与远程 TCP 共用，输出经 out 缓冲隔离，防串线。
 * 返回 0 正常，-1 未知命令/参数错误，1 请求退出（远程=关连接，本地=停机）。 */
int  cmd_dispatch(const char *line, char *out, size_t outsz);

#endif /* TERMINAL_H */
