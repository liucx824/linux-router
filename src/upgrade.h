#ifndef UPGRADE_H
#define UPGRADE_H

#include "router.h"

/* 在线升级：对 /proc/self/exe 对应的可执行文件执行
 *   upgrade_begin 创建 <exe>.new + 记录期望 size/sha
 *   upgrade_write 流式写入（校验中途大小不超限）
 *   upgrade_finish 校验（size/ELF 魔数/sha）→ rename → config_save+fsync → 0
 *   upgrade_exec   execv 替换进程（完成后不再返回）
 *   upgrade_abort  放弃：删除 .new
 * 任何一步失败均保持旧程序可运行。同一时刻只允许一个升级会话。
 */
int  upgrade_begin(const char *sha_hex, size_t size, char *err, size_t errsz);
int  upgrade_write(const uint8_t *data, size_t len, char *err, size_t errsz);
int  upgrade_finish(char *err, size_t errsz);
void upgrade_exec(void);
void upgrade_abort(void);

#endif /* UPGRADE_H */
