# Linux 用户态路由器（User-Space Router）

纯 C（C11 / POSIX）在 Linux **用户态**实现的嵌入式网络设备风格路由器：通过 `PF_PACKET / SOCK_RAW` 原始套接字直接读写二层以太帧，自行完成 **ARP 学习/请求/应答、最长前缀路由转发、防火墙过滤**，不依赖内核 `net.ipv4.ip_forward`，并内置 **配置持久化、远程管理、在线升级** 等控制面能力。约 4400 行代码，零第三方依赖，支持 ARM 交叉编译，总内存占用约 2.4MB。

- 编程语言：C（C11 / POSIX，无第三方库）
- 抓包方式：`PF_PACKET / SOCK_RAW`（数据链路层）
- 并发模型：单线程收包主循环 + 固定 4 线程线程池 + 有界任务队列
- 内存管理：约 2MB 固定块内存池，转发路径零拷贝、无 malloc
- 构建：`make` 零警告门禁（`-Wall -Wextra -Werror`），支持 `make CROSS=...` 交叉编译、`make TSAN=1` / `make ASAN=1` 检测

---

## 功能特性

**数据面（二层转发全链路）**

- **原始套接字收包**：`recvfrom` 直接收进内存池块，零拷贝；`sockaddr_ll` 获取入口接口
- **ARP 协议**：被动学习 + 主动请求 + 应答，256 桶哈希缓存、300s 老化；仅学习同子网 `spa` 防 ARP 毒化
- **IP 转发**：直连子网匹配 + 最长前缀路由查表；改写源/目的 MAC、TTL 递减并重算 IP 校验和，跨网段转发
- **防火墙**：无状态五元组过滤（IP/协议/端口/载荷关键字），128 条规则先到先中，命中丢弃
- **pending 队列**：下一跳未解析时按下一跳合并帧链、一链一 ARP 请求、3 次重试，从机制上防 ARP 请求风暴
- **自收帧过滤**：`PACKET_OUTGOING` / 源 MAC 为本机即丢弃，防转发环回死循环

**控制面**

- **本地终端**：函数指针命令表，20 余条命令统一分发
- **远程管理**：TCP 8899 鉴权 + 命令 + 配置上下传（`getconf` / `putconf`）；UDP 8900 只读状态查询
- **在线升级**：长度 + ELF 头 + SHA-256 三重校验后 `rename` 原子替换 + `execv` 自重启，失败不碰旧程序
- **配置持久化**：`router.conf` 节式读写，`tmp + fsync + rename` 原子落盘，首启自动生成默认配置

**工程化**

- 确定性资源：内存池（1024 块）> 任务队列（768），收包主循环永不因资源耗尽而阻塞
- 并发安全：读写锁 + 互斥锁 + C11 `_Atomic` 计数器分层，锁序铁律 `arp → pend` 防死锁，TSAN 冒烟验证
- 可观测：`showstat` 11 项 `_Atomic` 计数器、`showpool` / `showthread` 资源使用可量化

---

## 架构总览

```
收包主循环(单线程, recvfrom 直接收进内存池块)
   ├─ ARP 帧 → 内联处理（学习/应答，不排队，防止 ARP 饿死）
   └─ IP 帧 → 提交线程池(默认4线程) → 转发引擎(worker 内执行)
            转发: 防火墙匹配 → 路由查表(直连/最长前缀/默认) → ARP 查下一跳
                  → 未命中挂 pending 队列发ARP请求 → 命中改写MAC/TTL/重算校验和 → sendto
   └─ 控制面: terminal(本地命令) + remote(TCP/UDP 管理, 配置上下载, 在线升级)
   └─ 配置: config (router.conf 持久化: 过滤/防火墙/路由/管理端口/线程数)
```

- **数据面**（main / forward / arp / route / firewall / thread_pool / mempool）：收包、查表、转发，性能敏感
- **控制面**（terminal / remote / config / upgrade）：低频管理操作，与数据面通过各表的 rwlock 隔离，阻塞不影响转发

---

## 目录结构

```
router/
├── src/                      # 全部源码（18 个模块，约 4400 行）
│   ├── main.c                收包主循环 + 线程池调度 + 信号处理
│   ├── packet.c/h            以太/ARP/IP 头组包解析、RFC 1071 校验和
│   ├── interface.c/h         ioctl 枚举网卡（IP/MAC/掩码/索引）
│   ├── arp_table.c/h         ARP 哈希缓存 + 老化
│   ├── arp_proto.c/h         ARP 学习/请求/应答
│   ├── forward.c/h           转发引擎 + pending 队列（核心）
│   ├── route.c/h             最长前缀静态路由 + 默认路由
│   ├── firewall.c/h          防火墙规则数组（IP/proto/port/keyword）
│   ├── config.c/h            router.conf 读写 + 原子落盘
│   ├── thread_pool.c/h       固定线程池 + 有界环形队列
│   ├── mempool.c/h           固定块内存池 + malloc 回退
│   ├── terminal.c/h          本地终端命令（函数指针命令表）
│   ├── remote.c/h            TCP 8899 管理 + UDP 8900 状态
│   ├── upgrade.c/h           在线升级（校验 → 原子替换 → 自重启）
│   ├── sha256.c/h            内置公版 SHA-256（免 openssl）
│   ├── log.c/h / utils.c/h   分级日志 / IP-MAC 解析、find_bytes
│   └── router.h              公共类型/常量/约定
├── tools/setup_kernel.sh     关闭内核 ip_forward，让用户态路由器独占转发
├── router.conf               配置示例（首启自动生成默认）
├── Makefile                  make / make CROSS=... / make TSAN=1 / ASAN=1
└── legacy/                   旧课程代码（每包一线程 + 无锁链表，保留对照）
```

---

## 快速开始

### 环境要求

- Linux（x86 本地开发，或 ARM 板交叉编译），需要 root 权限（原始套接字）
- GCC（C11）、`make`、`build-essential`

### 编译（零警告门禁）

```bash
make                      # 本地编译，-std=c11 -Wall -Wextra -Werror，必须零警告
make clean

# 交叉编译（嵌入式板，二选一）
make CROSS=arm-linux-gnueabihf-        # 或 aarch64-linux-gnu-

# 竞态 / 内存检测
make clean && make TSAN=1              # ThreadSanitizer
make clean && make ASAN=1              # AddressSanitizer
```

### 冒烟启动

```bash
sudo ./router --help                  # 打印用法，干净退出
sudo ./router --version               # router 1.0

sudo sh tools/setup_kernel.sh         # 关内核 ip_forward，让用户态路由器独占转发
sudo ./router                         # 交互终端启动
```

启动后依次敲 `showif` / `showarp` / `showroute` / `showpool` / `showthread` / `showstat` / `showcfg` 观察各表与计数器。

### 最小跨网段转发测试

```
PC1 (eth0 10.1.0.10/24)
        │
     ┌──┴──┐
     │ router │  eth0=10.1.0.1/24   eth1=20.1.0.1/24
     └──┬──┘
        │
PC2 (eth1 20.1.0.10/24)
```

```bash
# router 上配置双网卡
sudo ip addr add 10.1.0.1/24 dev eth0
sudo ip addr add 20.1.0.1/24 dev eth1
sudo ip link set eth0 up && sudo ip link set eth1 up
sudo ./router

# PC1 上
sudo ip route add 20.1.0.0/24 via 10.1.0.1 dev eth0
ping -c 3 20.1.0.10                  # 通，丢包 0
```

`ping` 通后，router 终端 `showarp` 应出现两侧 MAC，`showstat` 的 `rx`/`tx` 增长、`fw_drop`/`noroute`/`arp_fail` 保持 0。

> 完整分步验证（含 pending 重试、防火墙 5 类拦截、配置持久化、远程管理、在线升级、多级级联、高压压测、TSAN/ASAN）见 `docs/测试验证指南.md`。

---

## 终端命令参考

本地终端与远程 TCP 8899 共用同一张命令表：

| 命令 | 说明 |
|------|------|
| `showif` / `showip` | 接口信息 / 接口 IP |
| `setip <if> <ip/mask>` / `delip <if>` | 设置 / 删除接口 IP |
| `showarp` | ARP 缓存 |
| `showroute` / `addroute <dest/mask> [via <gw>] dev <if>` / `delroute` | 路由表 / 静态路由增删 |
| `showfw` / `addfw deny ...` / `delfw <idx>` | 防火墙规则增删查 |
| `showstat` / `showpool` / `showthread` | 计数器 / 内存池 / 线程池 |
| `showcfg` / `save` / `reload` | 配置查看 / 原子保存 / 热加载 |
| `exit` | save + 优雅停机 |

**远程独有**：`auth <pw>`、`getconf`、`putconf <size>`、`upgrade <size> <sha256>`、`stat`；远程 `exit` 只关连接。

---

## 设计要点

1. **零拷贝**：`recvfrom` 直接收进内存池块头部，转发只改指针不搬数据，ARP 应答直接原帧改造
2. **确定性内存**：启动预分配 1024×2048≈2MB arena，转发路径无 malloc；`TASK_CAP(768) < MP_COUNT(1024)` 保证收包永不因池空阻塞
3. **防 ARP 风暴**：同一未解析下一跳的帧合并成链（上限 32），一链只发一个 ARP 请求，3 次重试
4. **非 NAT 转发免重算 L4 校验和**：转发不动源/目的 IP → TCP/UDP 伪头不变 → 校验和仍有效
5. **锁序铁律 `arp → pend`**：全项目唯一双锁路径固定顺序，从结构上消灭交叉等待死锁；计数器全 `_Atomic` 无锁
6. **原子升级**：长度 + ELF 头 + SHA-256 三重校验通过后才 `rename` 替换 + `execv` 自重启，任何失败不破坏运行中旧程序
7. **字节序安全**：2 字节字段统一 `get_be16`/`put_be16`，禁止 packed 结构强转（ARM 未对齐 fault 防护）

---

## 性能指标

| 指标 | 值 |
|------|-----|
| 转发能力 | 100Mbps 全速（最小帧约 148.8k pps，每包预算约 6.7µs） |
| 单包纯 CPU 成本 | 约 1–2µs（头校验 + 防火墙 + 路由查表 + ARP 哈希 + 校验和） |
| 内存占用 | 约 2.4MB（内存池 2MB + 各表/队列/栈） |
| 线程池 | 4 线程（四核 ARM 最优），任务队列 768 有界、非阻塞提交 |
| 老化/重试 | ARP 300s 老化；下一跳重试 3 次 × 1s，收敛 ≤3s |

> 定位为课程设计级 100Mbps 全速转发；1Gbps 全速 64B 最小帧受 syscall 开销限制无法打满，属预期范围。

---

## 嵌入式移植说明

- 交叉编译：`make CROSS=arm-linux-gnueabihf-`，只需工具链，全部自包含、无第三方依赖
- 未对齐访问：全部走 `get_be16`/`put_be16` 内联读写，ARM 上安全
- 大小端：IP 统一按网络字节序存储，子网运算直接掩码比较，无需字节序转换
- 内存裁剪：线程栈可降 32KB、`MP_COUNT` 可按吞吐调整，整体可放入 8MB / 16MB 内存设备
- 时间：超时一律 `CLOCK_MONOTONIC`，不受系统时间调整影响

---

## 课程需求覆盖

| 课程要求 | 实现 |
|----------|------|
| 转发数据包 | `forward.c` + 收包主循环，转发状态机完整落地 |
| 自动获取对方 MAC | ARP 主动请求 + 被动学习 + 应答，防毒化 |
| 终端控制功能 | `terminal.c` 函数指针命令表 |
| 过滤指定 IP 报文 | `firewall.c` + 内核不转发（关 ip_forward） |
| IP 过滤配置文档有效 | `config.c` 节式持久化，save/reload |
| 防火墙：port / tcp-udp / 关键字 | 五元组 + 载荷关键字规则 |
| 远程配置 udp/tcp 通信 | TCP 8899 管理 + UDP 8900 状态 |
| 下载/上传配置文档 | `getconf` / `putconf` 字节流，原子替换 |
| 在线升级 | 流式接收 → 校验 → 原子替换 → 自重启 |
| 提高性能·线程池 | 固定线程池 + 有界队列 + 零拷贝内存池 |
| 多级路由器级联 | 最长前缀路由 + 默认路由 + pending 队列 |

---

## 文档索引

| 文档 | 内容 |
|------|------|
| `docs/升级文档.md` | 需求、现状诊断、总体架构、实施计划、验证清单 |
| `docs/技术选型和代码实现文档.md` | 为什么这么选 + 怎么实现（算法/锁序/边界） |
| `docs/测试验证指南.md` | 分步验证指南（编译/冒烟/组网/防火墙/远程/升级） |
| `docs/路由器原理与代码讲解.md` | 路由器原理 + 代码逐模块讲解 |
| `docs/面试考点.md` | 常见面试问答与数字清单 |
| `docs/简历项目描述.md` | 简历版项目描述（简历版 + 复习版） |
