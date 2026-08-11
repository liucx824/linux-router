#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

#include "router.h"
#include "interface.h"
#include "utils.h"
#include "log.h"

static iface_t g_ifaces[MAX_IFACE];
static int g_nif = 0;
static int g_ctl_fd = -1;

static int ctl_sock(void)
{
    if (g_ctl_fd < 0)
        g_ctl_fd = socket(AF_INET, SOCK_DGRAM, 0);
    return g_ctl_fd;
}

static bool name_present(const char *name)
{
    int i;
    for (i = 0; i < g_nif; i++)
        if (strcmp(g_ifaces[i].name, name) == 0)
            return true;
    return false;
}

int iface_init(void)
{
    struct ifaddrs *ifap = NULL, *ifa;
    int fd = ctl_sock();

    g_nif = 0;
    if (fd < 0 || getifaddrs(&ifap) != 0) {
        LOG_ERR("iface_init: socket/getifaddrs failed");
        return 0;
    }

    for (ifa = ifap; ifa && g_nif < MAX_IFACE; ifa = ifa->ifa_next) {
        struct sockaddr_in *sin;
        struct sockaddr_in *sm;
        struct ifreq ifr;
        uint8_t b[4];
        iface_t *it;

        if (!ifa->ifa_name || strcmp(ifa->ifa_name, "lo") == 0)
            continue;
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET)
            continue;
        if (name_present(ifa->ifa_name))
            continue;   /* 同接口多 IP 只保留一条，保证 ifindex 语义单一 */

        it = &g_ifaces[g_nif];
        memset(it, 0, sizeof(*it));
        snprintf(it->name, sizeof(it->name), "%s", ifa->ifa_name);

        sin = (struct sockaddr_in *)ifa->ifa_addr;
        memcpy(b, &sin->sin_addr, 4);
        it->ip = get_be32(b);
        sm = (struct sockaddr_in *)ifa->ifa_netmask;
        if (sm) {
            memcpy(b, &sm->sin_addr, 4);
            it->netmask = get_be32(b);
        } else {
            it->netmask = 0xFFFFFFFFu;
        }
        it->up = (ifa->ifa_flags & IFF_UP) != 0;

        memset(&ifr, 0, sizeof(ifr));
        snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", it->name);
        if (ioctl(fd, SIOCGIFINDEX, &ifr) == 0)
            it->ifindex = ifr.ifr_ifindex;
        else
            it->ifindex = -1;

        memset(&ifr, 0, sizeof(ifr));
        snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", it->name);
        if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0)
            memcpy(it->mac, ifr.ifr_hwaddr.sa_data, 6);
        else
            memset(it->mac, 0, 6);

        LOG_INFO("iface %s index=%d %s IP %s/%d MAC %02x:%02x:%02x:%02x:%02x:%02x",
                 it->name, it->ifindex, it->up ? "UP" : "DOWN",
                 ipbuf(it->ip), prefix_len(it->netmask),
                 it->mac[0], it->mac[1], it->mac[2],
                 it->mac[3], it->mac[4], it->mac[5]);
        g_nif++;
    }
    freeifaddrs(ifap);
    return g_nif;
}

int iface_count(void)
{
    return g_nif;
}

iface_t *iface_at(int i)
{
    if (i < 0 || i >= g_nif)
        return NULL;
    return &g_ifaces[i];
}

iface_t *iface_by_index(int ifindex)
{
    int i;
    for (i = 0; i < g_nif; i++)
        if (g_ifaces[i].ifindex == ifindex)
            return &g_ifaces[i];
    return NULL;
}

iface_t *iface_by_name(const char *name)
{
    int i;
    if (!name)
        return NULL;
    for (i = 0; i < g_nif; i++)
        if (strcmp(g_ifaces[i].name, name) == 0)
            return &g_ifaces[i];
    return NULL;
}

iface_t *iface_with_ip(ip_t ip)
{
    int i;
    for (i = 0; i < g_nif; i++)
        if (g_ifaces[i].ip == ip)
            return &g_ifaces[i];
    return NULL;
}

bool iface_mac_is_ours(const uint8_t mac[6])
{
    int i;
    for (i = 0; i < g_nif; i++)
        if (memcmp(g_ifaces[i].mac, mac, 6) == 0)
            return true;
    return false;
}

static struct in_addr ip_to_inaddr(ip_t ip)
{
    struct in_addr a;
    uint8_t b[4];
    put_be32(b, ip);
    memcpy(&a, b, 4);
    return a;
}

int iface_add_addr(const char *name, ip_t ip, ip_t mask)
{
    struct ifreq ifr;
    struct sockaddr_in *sin;
    uint8_t b[4];
    iface_t *it;
    int fd = ctl_sock();

    if (fd < 0 || !(it = iface_by_name(name)))
        return -1;

    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", name);
    sin = (struct sockaddr_in *)&ifr.ifr_addr;
    sin->sin_family = AF_INET;
    sin->sin_addr = ip_to_inaddr(ip);
    if (ioctl(fd, SIOCSIFADDR, &ifr) != 0) {
        LOG_WARN("SIOCSIFADDR %s failed", name);
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", name);
    sin = (struct sockaddr_in *)&ifr.ifr_netmask;
    sin->sin_family = AF_INET;
    sin->sin_addr = ip_to_inaddr(mask);
    if (ioctl(fd, SIOCSIFNETMASK, &ifr) != 0)
        LOG_WARN("SIOCSIFNETMASK %s failed", name);

    /* 修改本地表并确认接口 UP */
    it->ip = ip;
    it->netmask = mask;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", name);
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) == 0) {
        ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
        ioctl(fd, SIOCSIFFLAGS, &ifr);
        it->up = 1;
    }
    put_be32(b, ip);
    LOG_INFO("iface %s set IP %s/%d", name, ipbuf(ip), prefix_len(mask));
    return 0;
}

int iface_del_addr(const char *name)
{
    struct ifreq ifr;
    struct sockaddr_in *sin;
    iface_t *it;
    int fd = ctl_sock();

    if (fd < 0 || !(it = iface_by_name(name)))
        return -1;

    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", name);
    sin = (struct sockaddr_in *)&ifr.ifr_addr;
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = INADDR_ANY;
    ioctl(fd, SIOCSIFADDR, &ifr);

    it->ip = 0;
    it->netmask = 0;
    LOG_INFO("iface %s IP cleared", name);
    return 0;
}

void iface_show(char *out, size_t outsz)
{
    size_t off = 0;
    int i;

    for (i = 0; i < g_nif && off < outsz; i++) {
        iface_t *it = &g_ifaces[i];
        off += (size_t)snprintf(out + off, outsz - off,
            "%-6s idx=%2d %s  %s/%d  %02x:%02x:%02x:%02x:%02x:%02x\n",
            it->name, it->ifindex, it->up ? "UP" : "DOWN",
            ipbuf(it->ip), prefix_len(it->netmask),
            it->mac[0], it->mac[1], it->mac[2],
            it->mac[3], it->mac[4], it->mac[5]);
    }
}
