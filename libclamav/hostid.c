/*
 *  Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 *
 *  Author: Shawn Webb
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <sys/types.h>
#include <fcntl.h>

#if !defined(_WIN32)
#include <sys/socket.h>
#include <netdb.h>
#include <sys/ioctl.h>
#endif

#if defined(HAVE_GETIFADDRS)
#include <net/if.h>
#if defined(HAVE_NET_IF_DL_H)
#include <net/if_dl.h>
#endif
#include <ifaddrs.h>
#endif

#if defined(SIOCGIFHWADDR) && !defined(__GNU__)
#if defined(_AIX)
#include <sys/ndd_var.h>
#include <sys/kinfo.h>
#else
#include <linux/sockios.h>
#endif
#endif

#include <errno.h>

#include "clamav.h"
#include "hostid.h"
#include "libclamav/others.h"

struct device *get_device_entry(struct device *devices, size_t *ndevices, const char *name);

struct device *get_device_entry(struct device *devices, size_t *ndevices, const char *name)
{
    void *p;
    size_t i;

    if ((devices)) {
        int found = 0;

        for (i = 0; i < *ndevices; i++) {
            if (!strcmp(devices[i].name, name)) {
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

            memset(devices + *ndevices, 0x00, sizeof(struct device));
            *ndevices = *ndevices + 1;
        }
    } else {
        devices = calloc(1, sizeof(struct device));
        if (!(devices))
            return NULL;

        *ndevices = 1;
    }

    if (*ndevices && !(devices[*ndevices - 1].name) && name)
        devices[*ndevices - 1].name = strdup(name);

    return devices;
}

#if HAVE_GETIFADDRS
struct device *get_devices(void)
{
    struct ifaddrs *addrs=NULL, *addr;
    struct device *devices=NULL;
    size_t ndevices=0, i, j;
    void *p;
    uint8_t *mac;
    int sock;

#if defined(SIOCGIFHWADDR) && !defined(__GNU__)
    struct ifreq ifr;
#else
    struct sockaddr_dl *sdl;
#endif

    if (getifaddrs(&addrs))
        return NULL;

    for (addr = addrs; addr != NULL; addr = addr->ifa_next) {
        if (!(addr->ifa_addr))
            continue;

        /*
         * Even though POSIX (BSD) sockets define AF_LINK, Linux decided to be clever
         * and use AF_PACKET instead.
         */
#if defined(AF_PACKET)
        if (addr->ifa_addr->sa_family != AF_PACKET)
            continue;
#elif defined(AF_LINK)
        if (addr->ifa_addr->sa_family != AF_LINK)
            continue;
#else
        break; /* We don't support anything else */
#endif

        devices = get_device_entry(devices, &ndevices, addr->ifa_name);
        if (!(devices)) {
            freeifaddrs(addrs);
            return NULL;
        }

        /*
         * Grab the MAC address for all devices that have them.
         * Linux doesn't support (struct sockaddr_dl) as POSIX (BSD) sockets require.
         * Instead, Linux uses its own ioctl. This code only runs if we're not Linux,
         * Windows, or FreeBSD.
         */
#if !defined(SIOCGIFHWADDR) || defined(__GNU__)
        for (i=0; i < ndevices; i++) {
            if (!(strcmp(devices[i].name, addr->ifa_name))) {
                sdl = (struct sockaddr_dl *)(addr->ifa_addr);

#if defined(LLADDR)
                mac = LLADDR(sdl);
#else
                mac = ((uint8_t *)(sdl->sdl_data + sdl->sdl_nlen));
#endif
                for (j=0; j<6; j++)
                    snprintf(devices[i].mac+strlen(devices[i].mac), sizeof(devices[i].mac)-strlen(devices[i].mac)-1, "%02x:", mac[j]);

                break;
            }
        }
#endif
    }

    if (addrs) {
        freeifaddrs(addrs);
        addrs = NULL;
    }

    /* This is the Linux version of getting the MAC addresses */
#if defined(SIOCGIFHWADDR) && !defined(__GNU__)
    for (i=0; i < ndevices; i++) {
        if (!(devices[i].name))
            continue;

        memset(&ifr, 0x00, sizeof(struct ifreq));
        memset(devices[i].mac, 0x00, sizeof(devices[i].mac));

        strcpy(ifr.ifr_name, devices[i].name);

        sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0)
            goto err;

        if (ioctl(sock, SIOCGIFHWADDR, &ifr)) {
            close(sock);
            goto err;
        }
        close(sock);

        mac = ((uint8_t *)(ifr.ifr_ifru.ifru_hwaddr.sa_data));
        if (!(mac))
            continue;

        for (j=0; j<6; j++)
            snprintf(devices[i].mac+strlen(devices[i].mac), sizeof(devices[i].mac)-strlen(devices[i].mac)-1, "%02x:", mac[j]);
    }
#endif

    p = realloc(devices, sizeof(struct device) * (ndevices + 1));
    if (!(p))
        goto err;

    devices = p;
    devices[ndevices].name =  NULL;
    memset(devices[ndevices].mac, 0x00, sizeof(devices[ndevices].mac));

    return devices;

err:
    if (devices) {
        for (i=0; i < ndevices; i++)
            if (devices[i].name)
                free(devices[i].name);

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
/*
 * Since we're getting potentially sensitive data (MAC addresses for all devices on the system),
 * hash all the MAC addresses to provide basic anonymity and security.
 */
char *internal_get_host_id(void)
{
    size_t i;
    unsigned char raw_md5[16];
    char *printable_md5;
    struct device *devices;
    void *ctx;

    devices = get_devices();
    if (!(devices))
        return NULL;

    printable_md5 = calloc(1, 37);
    if (!(printable_md5)) {
        free(devices);
        return NULL;
    }

    ctx = cl_hash_init("md5");
    if (!(ctx)) {
        for (i=0; devices[i].name != NULL; i++)
            free(devices[i].name);

        free(devices);
        free(printable_md5);

        return NULL;
    }

    for (i=0; devices[i].name != NULL; i++)
        cl_update_hash(ctx, devices[i].mac, sizeof(devices[i].mac));

    cl_finish_hash(ctx, raw_md5);

    for (i=0; devices[i].name != NULL; i++)
        free(devices[i].name);
    free(devices);

    for (i=0; i < sizeof(raw_md5); i++) {
        size_t len = strlen(printable_md5);
        switch (len) {
            case 8:
            case 13:
            case 18:
            case 23:
                printable_md5[len++] = '-';
                break;
        }

        sprintf(printable_md5+len, "%02x", raw_md5[i]);
    }

    return printable_md5;
}
#endif
