#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <fcntl.h>

#if defined(SIOCGIFHWADDR)
#include <net/if.h>
#include <ifaddrs.h>
#include <linux/sockios.h>
#endif

#include <errno.h>

#include "hostid.h"
#include "libclamav/md5.h"

struct device *get_device_entry(struct device *devices, size_t *ndevices, const char *name)
{
    struct device *device;
    void *p;
    size_t i;

    if ((devices)) {
        int found = 0;

        for (device = devices; device < devices + *ndevices; device++) {
            if (!strcmp(device->name, name)) {
                found = 1;
                break;
            }
        }

        if (!found) {
            p = realloc(devices, sizeof(struct device) * (*ndevices + 1));
            if (!(p)) {
                for (i=0; i < *ndevices; i++)
                    free(devices[i].name);
                free(devices);
                return NULL;
            }

            devices = p;
            device = devices + *ndevices;
            (*ndevices)++;
            memset(device, 0x00, sizeof(struct device));
        }
    } else {
        devices = calloc(1, sizeof(device));
        if (!(devices))
            return NULL;

        device = devices;
        *ndevices = 1;
    }

    if (!(device->name))
        device->name = strdup(name);
    return devices;
}

#if HAVE_GETIFADDRS && !HAVE_SYSCTLBYNAME
struct device *get_devices(void)
{
    struct ifaddrs *addrs, *addr;
    struct device *devices=NULL, *device=NULL;
    size_t ndevices=0, i;
    void *p;
    uint8_t *mac;
    int sock;
    struct ifreq ifr;

    if (getifaddrs(&addrs))
        return NULL;

    for (addr = addrs; addr != NULL; addr = addr->ifa_next) {
        if (!(addr->ifa_addr))
            continue;

        if (addr->ifa_addr->sa_family != AF_PACKET)
            continue;

        devices = get_device_entry(devices, &ndevices, addr->ifa_name);
        if (!(devices)) {
            freeifaddrs(addrs);
            return NULL;
        }
    }

    if (addrs) {
        freeifaddrs(addrs);
        addrs = NULL;
    }

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        goto err;

#if defined(SIOCGIFHWADDR)
    for (device = devices; device < devices + (ndevices); device++) {
        memset(&ifr, 0x00, sizeof(struct ifreq));
        strcpy(ifr.ifr_name, device->name);
        if (ioctl(sock, SIOCGIFHWADDR, &ifr)) {
            close(sock);
            goto err;
        }

        mac = ((uint8_t *)(ifr.ifr_ifru.ifru_hwaddr.sa_data));
        for (i=0; i<6; i++)
            snprintf(device->mac+strlen(device->mac), sizeof(device->mac)-strlen(device->mac)-1, "%02x:", mac[i]);
    }
#endif

    close(sock);
    
    p = realloc(devices, sizeof(struct device) * (ndevices + 1));
    if (!(p))
        goto err;

    devices = p;
    devices[ndevices].name =  NULL;
    memset(devices[ndevices].mac, 0x00, sizeof(devices[ndevices].mac));

    return devices;

err:
    if (addrs)
        freeifaddrs(addrs);
    if (devices) {
        for (device = devices; device < devices + ndevices; device++)
            if (device->name)
                free(device->name);

        free(devices);
    }

    return NULL;
}
#else
struct device *get_devices(void)
{
    return NULL;
}
#endif /* HAVE_GETIFADDRS */

#if !HAVE_SYSCTLBYNAME && !defined(_WIN32)
char *internal_get_host_id(void)
{
    size_t i;
    unsigned char raw_md5[16];
    char *printable_md5;
    cli_md5_ctx ctx;
    struct device *devices;

    devices = get_devices();
    if (!(devices))
        return NULL;

    printable_md5 = calloc(1, 33);
    if (!(printable_md5))
        return NULL;

    cli_md5_init(&ctx);
    for (i=0; devices[i].name != NULL; i++)
        cli_md5_update(&ctx, devices[i].mac, sizeof(devices[i].mac));

    cli_md5_final(raw_md5, &ctx);

    for (i=0; devices[i].name != NULL; i++)
        free(devices[i].name);
    free(devices);

    for (i=0; i < sizeof(raw_md5); i++)
        sprintf(printable_md5+(i*2), "%02x", raw_md5[i]);

    return printable_md5;
}
#endif
