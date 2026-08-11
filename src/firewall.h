#ifndef FIREWALL_H
#define FIREWALL_H

#include "router.h"

enum {
    FW_DROP = 0,
    FW_ALLOW = 1
};
enum {
    PROTO_ANY = -1,
    PROTO_ICMP = 1,
    PROTO_TCP = 6,
    PROTO_UDP = 17
};

typedef struct fw_rule {
    int   action;        /* FW_DROP / FW_ALLOW */
    ip_t  sip, dip;      /* 网络序值 */
    ip_t  sip_mask, dip_mask;   /* 0 = 通配 */
    int   proto;         /* PROTO_ANY 通配 */
    int   sport, dport;  /* -1 通配 */
    char  keyword[64];   /* 空 = 不限 */
    char  note[48];
} fw_rule_t;

int  fw_init(void);
void fw_clear(void);                       /* 清空（reload 用） */
int  fw_add(const fw_rule_t *rule);        /* 成功 0，满 -1 */
int  fw_del(int index);                    /* 成功 0，不存在 -1 */
int  fw_check(const uint8_t *frame, int len); /* 首条命中规则的 action；无命中 FW_ALLOW */
void fw_show(char *out, size_t outsz);
int  fw_count(void);
const fw_rule_t *fw_rule_at(int index);    /* index 越界返回 NULL（须自行按需持读锁，此函数不加锁） */
/* 解析 addfw / [firewall] 规则参数。argv[0]=action("drop"/"allow")，
 * 其后为 "ip <sip[/len]> [dip[/len]]" "proto tcp|udp|icmp|any" "sport N" "dport N" "keyword <str>"。
 * 返回 0 成功并填 r，-1 参数错误。 */
int fw_parse_rule(const char **argv, int argc, fw_rule_t *r);

#endif /* FIREWALL_H */
