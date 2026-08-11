#ifndef ROUTER_H
#define ROUTER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <signal.h>

/* ================================================================== */
/* 公共类型 / 常量 / 约定（升级文档 §4.2、技术选型 §2.9）              */
/* ================================================================== */

/* ---- 容量常量 ---- */
#define MAX_IFACE      16      /* 接口数 */
#define MAX_FRAME      2048    /* 帧长上限（含 VLAN tag 余量） */
#define MAX_RULE       128     /* 防火墙规则 */
#define MAX_ROUTE      64      /* 路由表条目 */
#define PEND_MAX       256     /* pending 队列节点 */
#define TASK_CAP       768     /* 线程池任务队列（< MP_COUNT） */
#define POOL_THREADS   4       /* 线程池默认线程数 */
#define MP_BLOCK       2048    /* 内存池块 */
#define MP_COUNT       1024    /* 内存池块数（≈2MB arena） */
#define ARP_CAP        256     /* ARP 缓存条目 */
#define PEND_CHAIN_MAX 32      /* 同 nexthop 帧链上限 */

/* ---- 时间参数 ---- */
#define ARP_TMO        300     /* ARP 老化秒数（静态拓扑>Linux 默认 60s） */
#define ARP_RETRY_MAX  3       /* ARP 请求重试上限 */
#define ARP_RETRY_INT  1       /* 重试间隔秒 */

/* ---- 端口 / 文件 ---- */
#define TCP_PORT       8899
#define UDP_PORT       8900
#define CONFIG_FILE    "router.conf"
#define MAX_UPLOAD     (8 * 1024 * 1024)  /* 在线升级 size 上限 */

/* ---- 基础类型：IP 一律网络字节序 ---- */
typedef uint32_t ip_t;

/* ---- 2 字节 / 4 字节大端读写（ARM 未对齐防护，禁止 packed 强转） ---- */
static inline uint16_t get_be16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}
static inline void put_be16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xff);
}
static inline uint32_t get_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
}
static inline void put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v & 0xff);
}

/* ---- 帧块：内存池单元，头 16B + 柔性载荷（零拷贝 recvfrom 目标） ---- */
typedef struct fwd_frame {
    struct fwd_frame *next;   /* pending 链 */
    uint16_t len;             /* data[] 有效长度 */
    uint8_t  out_ifidx;       /* 出接口索引（转发时填充） */
    uint8_t  pad;
    ip_t     nexthop;         /* 下一跳（网络字节序，转发时填充） */
    uint8_t  data[];          /* 帧数据，块内偏移 16 */
} fwd_frame_t;

#define MP_PAYLOAD (MP_BLOCK - (int)offsetof(fwd_frame_t, data))
/* 头宽随指针位宽在 12B(32位)/16B(64位) 间变化，只要求足够放最大帧即可 */
_Static_assert(offsetof(fwd_frame_t, data) <= 32, "frame header too large");
_Static_assert(MP_PAYLOAD >= 1518, "pool payload must hold max ethernet frame (1518)");

/* ---- 以太网 / IP 常量 ---- */
#define ETH_HLEN       14
#define ETHERTYPE_ARP  0x0806
#define ETHERTYPE_IP   0x0800
#define ETH_BCAST_MAC  {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

/* ---- 全局收发统计（_Atomic 无锁更新） ---- */
extern _Atomic uint64_t g_rx;         /* 收包 */
extern _Atomic uint64_t g_tx;         /* 转发成功 */
extern _Atomic uint64_t g_drop;       /* 丢弃合计 */
extern _Atomic uint64_t g_fw_drop;    /* 防火墙拦截 */
extern _Atomic uint64_t g_noroute;    /* 无路由 */
extern _Atomic uint64_t g_self_drop;  /* 自收帧 */
extern _Atomic uint64_t g_arp_fail;   /* ARP 解析失败 */
extern _Atomic uint64_t g_tx_err;     /* sendto 失败 */
extern _Atomic uint64_t g_ttl_drop;   /* TTL<=1 */
extern _Atomic uint64_t g_malformed;  /* 畸形包 */
extern _Atomic uint64_t g_pend_drop;  /* pending 满丢弃 */

/* ---- 全局运行状态 ---- */
extern volatile sig_atomic_t g_shutdown; /* 信号置位，优雅停机 */
extern int g_raw_fd;                     /* 原始套接字（main.c 打开） */

#endif /* ROUTER_H */
