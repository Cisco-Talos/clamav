/*
 *  Copyright (C) 2002-2013 Tomasz Kojm <tkojm@clamav.net>
 *  HTTP/1.1 compliance by Arkadiusz Miskiewicz <misiek@pld.org.pl>
 *  Proxy support by Nigel Horne <njh@bandsman.co.uk>
 *  Proxy authorization support by Gernot Tenchio <g.tenchio@telco-tech.de>
 *		     (uses fmt_base64() from libowfat (http://www.fefe.de))
 *  CDIFF code (C) 2006 Sensory Networks, Inc.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
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

/* for strptime, it is POSIX, but defining _XOPEN_SOURCE to 600
 * fails on Solaris because it would require a c99 compiler,
 * 500 fails completely on Solaris, and FreeBSD, and w/o _XOPEN_SOURCE
 * strptime is not defined on Linux */
#define __EXTENSIONS

#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <string.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#include <ctype.h>
#ifndef _WIN32
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#endif
#include <sys/types.h>
#include <time.h>
#include <fcntl.h>
#ifndef	_WIN32
#include <sys/wait.h>
#endif
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <zlib.h>

#include "target.h"

#include "freshclamcodes.h"
#include "manager.h"
#include "notify.h"
#include "dns.h"
#include "execute.h"
#include "nonblock.h"
#include "mirman.h"

#include "shared/optparser.h"
#include "shared/output.h"
#include "shared/misc.h"
#include "shared/cdiff.h"
#include "shared/tar.h"
#include "shared/clamdcom.h"

#include "libclamav/clamav.h"
#include "libclamav/others.h"
#include "libclamav/str.h"
#include "libclamav/cvd.h"
#include "libclamav/regex_list.h"

extern char updtmpdir[512], dbdir[512];
char g_label[33];

#define CHDIR_ERR(x)				\
	if(chdir(x) == -1)			\
	    logg("!Can't chdir to %s\n", x);


static int
textrecordfield (const char * dbname)
{
    if (!strcmp (dbname, "main"))
    {
        return 1;
    }
    else if (!strcmp (dbname, "daily"))
    {
        return 2;
    }
    else if (!strcmp (dbname, "bytecode"))
    {
        return 7;
    }
    else if (!strcmp (dbname, "safebrowsing"))
    {
        return 6;
    }
    return 0;
}

static int
getclientsock (const char *localip, int prot)
{
    int socketfd = -1;

#ifdef SUPPORT_IPv6
    if (prot == AF_INET6)
        socketfd = socket (AF_INET6, SOCK_STREAM, 0);
    else
#endif
        socketfd = socket (AF_INET, SOCK_STREAM, 0);
    if (socketfd < 0)
    {
        logg ("!Can't create new socket: %s\n", strerror(errno));
        return -1;
    }

    if (localip)
    {
        struct addrinfo *res;
        int ret;

        ret = getaddrinfo (localip, NULL, NULL, &res);
        if (ret)
        {
            logg ("!Could not resolve local ip address '%s': %s\n", localip,
                  gai_strerror (ret));
            logg ("^Using standard local ip address and port for fetching.\n");
        }
        else
        {
            char ipaddr[46];

            if (bind (socketfd, res->ai_addr, (socklen_t)res->ai_addrlen) != 0)
            {
                logg ("!Could not bind to local ip address '%s': %s\n",
                      localip, strerror (errno));
                logg ("^Using default client ip.\n");
            }
            else
            {
                void *addr;

#ifdef SUPPORT_IPv6
                if (res->ai_family == AF_INET6)
                    addr = &((struct sockaddr_in6 *) res->ai_addr)->sin6_addr;
                else
#endif
                    addr = &((struct sockaddr_in *) res->ai_addr)->sin_addr;

                if (inet_ntop (res->ai_family, addr, ipaddr, sizeof (ipaddr)))
                    logg ("*Using ip '%s' for fetching.\n", ipaddr);
            }
            freeaddrinfo (res);
        }

    }

    return socketfd;
}

static int
qcompare (const void *a, const void *b)
{
    return (*(const struct addrinfo **) a)->ai_flags -
        (*(const struct addrinfo **) b)->ai_flags;
}

static int
wwwconnect (const char *server, const char *proxy, int pport, char *ip,
            const char *localip, int ctimeout, struct mirdat *mdat,
            int logerr, unsigned int can_whitelist, unsigned int attempt)
{
    mir_status_t mirror_status = MIRROR_OK;
    int socketfd, port, ret;
    unsigned int ips = 0, ignored = 0, i;
    struct addrinfo hints, *res = NULL, *rp, *loadbal_rp = NULL, *addrs[128];
    char port_s[6], loadbal_ipaddr[46];
    uint32_t loadbal = 1, minsucc = 0xffffffff, minfail =
        0xffffffff, addrnum = 0;
    int ipv4start = -1, ipv4end = -1;
    struct mirdat_ip *md = NULL;
    char ipaddr[46];
    const char *hostpt;

    if (ip)
        strcpy (ip, "UNKNOWN");

    if (proxy)
    {
        hostpt = proxy;

        if (!(port = pport))
        {
            const struct servent *webcache =
                getservbyname ("webcache", "TCP");

            if (webcache)
                port = ntohs (webcache->s_port);
            else
                port = 8080;

            endservent ();
        }

    }
    else
    {
        hostpt = server;
        port = 80;
    }

    memset (&hints, 0, sizeof (hints));
#ifdef SUPPORT_IPv6
    hints.ai_family = AF_UNSPEC;
#else
    hints.ai_family = AF_INET;
#endif
    hints.ai_socktype = SOCK_STREAM;
#ifdef AI_ADDRCONFIG
    hints.ai_flags    = AI_ADDRCONFIG;
#endif
    snprintf (port_s, sizeof (port_s), "%d", port);
    port_s[sizeof (port_s) - 1] = 0;
    ret = getaddrinfo (hostpt, port_s, &hints, &res);
    if (ret)
    {
        logg ("%cCan't get information about %s: %s\n", logerr ? '!' : '^',
              hostpt, gai_strerror (ret));
        return -1;
    }

    for (rp = res; rp && addrnum < 128; rp = rp->ai_next)
    {
        rp->ai_flags = cli_rndnum (1024);
        addrs[addrnum] = rp;
        if (rp->ai_family == AF_INET)
        {
            if (ipv4start == -1)
                ipv4start = addrnum;
        }
        else if (ipv4end == -1 && ipv4start != -1)
        {
            ipv4end = addrnum - 1;
        }
        if (!rp->ai_next && ipv4end == -1)
            ipv4end = addrnum;
        addrnum++;
    }
    if (ipv4end != -1 && ipv4start != -1 && ipv4end - ipv4start + 1 > 1)
        qsort (&addrs[ipv4start], ipv4end - ipv4start + 1,
               sizeof (struct addrinfo *), qcompare);

    if (attempt > 1)
        loadbal = 0;

    for (i = 0; i < addrnum;)
    {
        void *addr;

        rp = addrs[i];
        ips++;
#ifdef SUPPORT_IPv6
        if (rp->ai_family == AF_INET6)
            addr = &((struct sockaddr_in6 *) rp->ai_addr)->sin6_addr;
        else
#endif
            addr = &((struct sockaddr_in *) rp->ai_addr)->sin_addr;

        if (!inet_ntop (rp->ai_family, addr, ipaddr, sizeof (ipaddr)))
        {
            logg ("%cinet_ntop() failed\n", logerr ? '!' : '^');
            freeaddrinfo (res);
            return -1;
        }

        if (mdat)
        {
            if (FC_SUCCESS != (ret = mirman_check (addr, rp->ai_family, mdat, &md, &mirror_status)))
            {
                logg ("!Failed to check mirrors.dat!\n");
                return -1;
            }
            else if (MIRROR_OK != mirror_status)
            {
                if (MIRROR_IGNORE__PREV_ERRS == mirror_status)
                    logg ("*Ignoring mirror %s (due to previous errors)\n", ipaddr);
                else if (MIRROR_IGNORE__OUTDATED_VERSION == mirror_status)
                    logg ("*Ignoring mirror %s (has connected too many times with an outdated version)\n", ipaddr);

                ignored++;
                if (!loadbal || i + 1 < addrnum)
                {
                    i++;
                    continue;
                }
            }
        }

        if (mdat && loadbal)
        {
            if (MIRROR_OK == mirror_status)
            {
                if (!md)
                {
                    loadbal_rp = rp;
                    strncpy (loadbal_ipaddr, ipaddr, sizeof (loadbal_ipaddr));
                }
                else
                {
                    if (md->succ <= minsucc && md->fail <= minfail)
                    {
                        minsucc = md->succ;
                        minfail = md->fail;
                        loadbal_rp = rp;
                        strncpy (loadbal_ipaddr, ipaddr,
                                 sizeof (loadbal_ipaddr));
                    }
                    if (i + 1 < addrnum)
                    {
                        i++;
                        continue;
                    }
                }
            }

            if (!loadbal_rp)
            {
                if (i + 1 == addrnum)
                {
                    loadbal = 0;
                    i = 0;
                }
                continue;
            }
            rp = loadbal_rp;
            strncpy (ipaddr, loadbal_ipaddr, sizeof (ipaddr));
#ifdef SUPPORT_IPv6
            if (rp->ai_family == AF_INET6)
                addr = &((struct sockaddr_in6 *) rp->ai_addr)->sin6_addr;
            else
#endif
                addr = &((struct sockaddr_in *) rp->ai_addr)->sin_addr;
        }
        else if (loadbal_rp == rp)
        {
            i++;
            continue;
        }

        if (ip)
            strcpy (ip, ipaddr);

        if (rp != loadbal_rp && rp != addrs[0])
            logg ("Trying host %s (%s)...\n", hostpt, ipaddr);

        socketfd = getclientsock (localip, rp->ai_family);
        if (socketfd < 0)
        {
            freeaddrinfo (res);
            return -1;
        }

#ifdef SO_ERROR
        if (wait_connect (socketfd, rp->ai_addr, rp->ai_addrlen, ctimeout) ==
            -1)
        {
#else
        if (connect (socketfd, rp->ai_addr, rp->ai_addrlen) == -1)
        {
#endif
            logg ("Can't connect to port %d of host %s (IP: %s)\n", port,
                  hostpt, ipaddr);
            closesocket (socketfd);
            if (loadbal)
            {
                loadbal = 0;
                i = 0;
            }
            else
                i++;
            if (mdat)
                mirman_update (addr, rp->ai_family, mdat, FCE_CONNECTION);
            continue;
        }
        else
        {
            if (mdat)
            {
                if (rp->ai_family == AF_INET)
                    mdat->currip[0] = *((uint32_t *) addr);
                else
                    memcpy (mdat->currip, addr, 4 * sizeof (uint32_t));
                mdat->af = rp->ai_family;
            }
            freeaddrinfo (res);
            return socketfd;
        }
        i++;
    }
    freeaddrinfo (res);

    if (mdat && can_whitelist && ips && (ips == ignored))
        mirman_whitelist (mdat, 1);

    return -2;
}

static unsigned int
fmt_base64 (char *dest, const char *src, unsigned int len)
{
    unsigned short bits = 0, temp = 0;
    unsigned long written = 0;
    unsigned int i;
    const char base64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";


    for (i = 0; i < len; i++)
    {
        temp <<= 8;
        temp += src[i];
        bits += 8;
        while (bits > 6)
        {
            dest[written] = base64[((temp >> (bits - 6)) & 63)];
            written++;
            bits -= 6;
        }
    }

    if (bits)
    {
        temp <<= (6 - bits);
        dest[written] = base64[temp & 63];
        written++;
    }

    while (written & 3)
    {
        dest[written] = '=';
        written++;
    }

    return written;
}

static char *
proxyauth (const char *user, const char *pass)
{
    int len;
    char *buf, *userpass, *auth;


    userpass = malloc (strlen (user) + strlen (pass) + 2);
    if (!userpass)
    {
        logg ("!proxyauth: Can't allocate memory for 'userpass'\n");
        return NULL;
    }
    sprintf (userpass, "%s:%s", user, pass);

    buf = malloc ((strlen (pass) + strlen (user)) * 2 + 4);
    if (!buf)
    {
        logg ("!proxyauth: Can't allocate memory for 'buf'\n");
        free (userpass);
        return NULL;
    }

    len = fmt_base64 (buf, userpass, strlen (userpass));
    free (userpass);
    buf[len] = '\0';
    auth = malloc (strlen (buf) + 30);
    if (!auth)
    {
        free (buf);
        logg ("!proxyauth: Can't allocate memory for 'authorization'\n");
        return NULL;
    }

    sprintf (auth, "Proxy-Authorization: Basic %s\r\n", buf);
    free (buf);

    return auth;
}

static int
Rfc2822DateTime (char *buf, time_t mtime)
{
    struct tm *gmt;

    gmt = gmtime (&mtime);
    if (!gmt)
    {
        logg ("gmtime: %s\n", strerror (errno));
        strcpy (buf, "ERROR");
        return -1;
    }
    return strftime (buf, 36, "%a, %d %b %Y %X GMT", gmt);
}

static struct cl_cvd *
remote_cvdhead (const char *cvdfile, const char *localfile,
                const char *hostname, char *ip, const char *localip,
                const char *proxy, int port, const char *user,
                const char *pass, const char *uas, int *ims, int ctimeout,
                int rtimeout, struct mirdat *mdat, int logerr,
                unsigned int can_whitelist, unsigned int attempt)
{
    char cmd[512], head[513], buffer[FILEBUFF], ipaddr[46], *ch, *tmp;
    int bread, cnt, sd;
    unsigned int i, j;
    char *remotename = NULL, *authorization = NULL;
    struct cl_cvd *cvd;
    char last_modified[36], uastr[128];

    /* Initialize mirror status variable to unknown */
    *ims = -1;

    if (proxy)
    {
        remotename = malloc (strlen (hostname) + 8);
        if (!remotename)
        {
            logg ("!remote_cvdhead: Can't allocate memory for 'remotename'\n");
            return NULL;
        }
        sprintf (remotename, "http://%s", hostname);

        if (user)
        {
            authorization = proxyauth (user, pass);
            if (!authorization)
            {
                free (remotename);
                return NULL;
            }
        }
    }

    if (!access (localfile, R_OK))
    {
        cvd = cl_cvdhead (localfile);
        if (!cvd)
        {
            logg ("!remote_cvdhead: Can't parse file %s\n", localfile);
            free (remotename);
            free (authorization);
            return NULL;
        }
        Rfc2822DateTime (last_modified, (time_t) cvd->stime);
        cl_cvdfree (cvd);
    }
    else
    {
        time_t mtime = 1104119530;

        Rfc2822DateTime (last_modified, mtime);
        logg ("*Assuming modification time in the past\n");
    }

    logg ("*If-Modified-Since: %s\n", last_modified);

    logg ("Reading CVD header (%s): ", cvdfile);

    if (uas)
        strncpy (uastr, uas, sizeof (uastr));
    else
        snprintf (uastr, sizeof (uastr),
                  PACKAGE "/%s (OS: " TARGET_OS_TYPE ", ARCH: "
                  TARGET_ARCH_TYPE ", CPU: " TARGET_CPU_TYPE ")",
                  get_version ());
    uastr[sizeof (uastr) - 1] = 0;

    snprintf (cmd, sizeof (cmd),
              "GET %s/%s HTTP/1.0\r\n"
              "Host: %s\r\n%s"
              "User-Agent: %s\r\n"
              "Connection: close\r\n"
              "Range: bytes=0-511\r\n"
              "If-Modified-Since: %s\r\n"
              "\r\n", (remotename != NULL) ? remotename : "", cvdfile,
              hostname, (authorization != NULL) ? authorization : "", uastr,
              last_modified);

    free (remotename);
    free (authorization);

    memset (ipaddr, 0, sizeof (ipaddr));

    if (ip[0])                  /* use ip to connect */
        sd = wwwconnect (ip, proxy, port, ipaddr, localip, ctimeout, mdat,
                         logerr, can_whitelist, attempt);
    else
        sd = wwwconnect (hostname, proxy, port, ipaddr, localip, ctimeout,
                         mdat, logerr, can_whitelist, attempt);

    if (sd < 0)
    {
        return NULL;
    }
    else
    {
        if (proxy)
            logg ("*Connected to %s.\n", hostname);
        else
            logg ("*Connected to %s (IP: %s).\n", hostname, ipaddr);
        logg ("*Trying to retrieve CVD header of http://%s/%s\n", hostname,
              cvdfile);
    }

    if (!ip[0])
        strcpy (ip, ipaddr);

    if (send (sd, cmd, strlen (cmd), 0) < 0)
    {
        logg ("%cremote_cvdhead: write failed\n", logerr ? '!' : '^');
        closesocket (sd);
        return NULL;
    }

    tmp = buffer;
    cnt = FILEBUFF;
#ifdef SO_ERROR
    while ((bread = wait_recv (sd, tmp, cnt, 0, rtimeout)) > 0)
    {
#else
    while ((bread = recv (sd, tmp, cnt, 0)) > 0)
    {
#endif
        tmp += bread;
        cnt -= bread;
        if (cnt <= 0)
            break;
    }
    closesocket (sd);

    if (bread == -1)
    {
        logg ("%cremote_cvdhead: Error while reading CVD header from %s\n",
              logerr ? '!' : '^', hostname);
        mirman_update (mdat->currip, mdat->af, mdat, FCE_FAILEDGET);
        return NULL;
    }

    if ((strstr (buffer, "HTTP/1.1 404")) != NULL
        || (strstr (buffer, "HTTP/1.0 404")) != NULL)
    {
        logg ("%c%s not found on remote server\n", logerr ? '!' : '^',
              cvdfile);
        mirman_update (mdat->currip, mdat->af, mdat, FCE_FAILEDGET);
        return NULL;
    }

    /* check whether the resource is up-to-date */
    if ((strstr (buffer, "HTTP/1.1 304")) != NULL
        || (strstr (buffer, "HTTP/1.0 304")) != NULL)
    {
        /* mirror status: up to date */
        *ims = 0;
        logg ("OK (IMS)\n");
        mirman_update (mdat->currip, mdat->af, mdat, FC_SUCCESS);
        return NULL;
    }
    else
    {
        /* mirror status: newer versin available */
        *ims = 1;
    }

    if (!strstr (buffer, "HTTP/1.1 200") && !strstr (buffer, "HTTP/1.0 200")
        && !strstr (buffer, "HTTP/1.1 206")
        && !strstr (buffer, "HTTP/1.0 206"))
    {
        char * respcode = NULL;
        if ((NULL != (respcode = strstr (buffer, "HTTP/1.0 "))) ||
            (NULL != (respcode = strstr (buffer, "HTTP/1.1 ")))) {
            /* There was some sort of response code...*/
            char * httpcode = calloc(MIN(FILEBUFF - (size_t)(respcode - buffer), 13) + 1, 1);
            memcpy(httpcode, respcode, MIN(FILEBUFF - (size_t)(respcode - buffer), 13));
            logg ("%cremote_cvdhead: Unknown response from %s (IP: %s): %s\n", logerr ? '!' : '^', hostname, ipaddr, httpcode);
            free (httpcode);
        } else {
            logg ("%cremote_cvdhead: Unknown response from %s (IP: %s)\n", logerr ? '!' : '^', hostname, ipaddr);
        }
        mirman_update (mdat->currip, mdat->af, mdat, FCE_FAILEDGET);
        return NULL;
    }

    i = 3;
    ch = buffer + i;
    while (i < sizeof (buffer))
    {
        if (*ch == '\n' && *(ch - 1) == '\r' && *(ch - 2) == '\n'
            && *(ch - 3) == '\r')
        {
            ch++;
            i++;
            break;
        }
        ch++;
        i++;
    }

    if (sizeof (buffer) - i < 512)
    {
        logg ("%cremote_cvdhead: Malformed CVD header (too short)\n",
              logerr ? '!' : '^');
        mirman_update (mdat->currip, mdat->af, mdat, FCE_BADCVD);
        return NULL;
    }

    memset (head, 0, sizeof (head));

    for (j = 0; j < 512; j++)
    {
        if (!ch || (ch && !*ch) || (ch && !isprint (ch[j])))
        {
            logg ("%cremote_cvdhead: Malformed CVD header (bad chars)\n",
                  logerr ? '!' : '^');
            mirman_update (mdat->currip, mdat->af, mdat, FCE_BADCVD);
            return NULL;
        }
        head[j] = ch[j];
    }

    if (!(cvd = cl_cvdparse (head)))
    {
        logg ("%cremote_cvdhead: Malformed CVD header (can't parse)\n",
              logerr ? '!' : '^');
        mirman_update (mdat->currip, mdat->af, mdat, FCE_BADCVD);
    }
    else
    {
        logg ("OK\n");
        mirman_update (mdat->currip, mdat->af, mdat, FC_SUCCESS);
    }

    return cvd;
}

static fc_error_t
getfile_mirman (const char *srcfile, const char *destfile,
                const char *hostname, char *ip, const char *localip,
                const char *proxy, int port, const char *user,
                const char *pass, const char *uas, int ctimeout, int rtimeout,
                struct mirdat *mdat, int logerr, unsigned int can_whitelist,
                const char *ims, const char *ipaddr, int sd)
{
    char cmd[512], uastr[128], buffer[FILEBUFF], *ch;
    int bread, fd, totalsize = 0, rot = 0, totaldownloaded = 0,
        percentage = 0;
    unsigned int i;
    char *remotename = NULL, *authorization = NULL, *headerline;
    const char *rotation = "|/-\\", *fname;

    UNUSEDPARAM(localip);
    UNUSEDPARAM(port);
    UNUSEDPARAM(ctimeout);
    UNUSEDPARAM(can_whitelist);

    memset (buffer, 0, sizeof(FILEBUFF));

    if (proxy)
    {
        remotename = malloc (strlen (hostname) + 8);
        if (!remotename)
        {
            logg ("!getfile: Can't allocate memory for 'remotename'\n");
            return FCE_MEM;
        }
        sprintf (remotename, "http://%s", hostname);

        if (user)
        {
            authorization = proxyauth (user, pass);
            if (!authorization)
            {
                free (remotename);
                return FCE_MEM;
            }
        }
    }

    if (ims)
        logg ("*If-Modified-Since: %s\n", ims);

    if (uas)
        strncpy (uastr, uas, sizeof (uastr));
    else
        snprintf (uastr, sizeof (uastr),
                  PACKAGE "/%s (OS: " TARGET_OS_TYPE ", ARCH: "
                  TARGET_ARCH_TYPE ", CPU: " TARGET_CPU_TYPE ")",
                  get_version ());
    uastr[sizeof (uastr) - 1] = 0;

    snprintf (cmd, sizeof (cmd),
              "GET %s/%s HTTP/1.0\r\n" "Host: %s\r\n%s" "User-Agent: %s\r\n"
#ifdef FRESHCLAM_NO_CACHE
              "Cache-Control: no-cache\r\n"
#endif
              "Connection: close\r\n"
              "%s%s%s"
              "\r\n", (remotename != NULL) ? remotename : "", srcfile,
              hostname, (authorization != NULL) ? authorization : "", uastr,
              ims ? "If-Modified-Since: " : "", ims ? ims : "",
              ims ? "\r\n" : "");

    if (remotename)
        free (remotename);

    if (authorization)
        free (authorization);

    if (proxy)
        logg ("*Trying to download http://%s/%s\n", hostname, srcfile);
    else
        logg ("*Trying to download http://%s/%s (IP: %s)\n", hostname, srcfile,
              ipaddr);

    if (ip && !ip[0])
        strcpy (ip, ipaddr);

    if (send (sd, cmd, strlen (cmd), 0) < 0)
    {
        logg ("%cgetfile: Can't write to socket\n", logerr ? '!' : '^');
        return FCE_CONNECTION;
    }

    /* read http headers */
    ch = buffer;
    i = 0;
    while (1)
    {
        /* recv one byte at a time, until we reach \r\n\r\n */
#ifdef SO_ERROR
        if ((i >= sizeof (buffer) - 1)
            || wait_recv (sd, buffer + i, 1, 0, rtimeout) == -1)
        {
#else
        if ((i >= sizeof (buffer) - 1) || recv (sd, buffer + i, 1, 0) == -1)
        {
#endif
            if (proxy)
                logg ("%cgetfile: Error while reading database from %s: %s\n", logerr ? '!' : '^', hostname, strerror (errno));
            else
                logg ("%cgetfile: Error while reading database from %s (IP: %s): %s\n", logerr ? '!' : '^', hostname, ipaddr, strerror (errno));
            if (mdat)
                mirman_update (mdat->currip, mdat->af, mdat, FCE_FAILEDGET);
            return FCE_CONNECTION;
        }

        if (i > 2 && *ch == '\n' && *(ch - 1) == '\r' && *(ch - 2) == '\n'
            && *(ch - 3) == '\r')
        {
            i++;
            break;
        }
        ch++;
        i++;
    }

    buffer[i] = 0;

    /* check whether the resource actually existed or not */
    if ((strstr (buffer, "HTTP/1.1 404")) != NULL
        || (strstr (buffer, "HTTP/1.0 404")) != NULL)
    {
        if (proxy)
            logg ("^getfile: %s not found on %s\n", srcfile, hostname);
        else
            logg ("^getfile: %s not found on %s (IP: %s)\n", srcfile, hostname,
                  ipaddr);

        if (mdat)
            mirman_update (mdat->currip, mdat->af, mdat, FCE_FAILEDGET);
        return FCE_FAILEDGET;
    }

    /* If-Modified-Since */
    if (strstr (buffer, "HTTP/1.1 304") || strstr (buffer, "HTTP/1.0 304"))
    {
        if (mdat)
            mirman_update (mdat->currip, mdat->af, mdat, FC_SUCCESS);
        return FC_UPTODATE;
    }

    if (!strstr (buffer, "HTTP/1.1 200") && !strstr (buffer, "HTTP/1.0 200")
        && !strstr (buffer, "HTTP/1.1 206")
        && !strstr (buffer, "HTTP/1.0 206"))
    {
        char * respcode = NULL;
        if ((NULL != (respcode = strstr (buffer, "HTTP/1.0 "))) ||
            (NULL != (respcode = strstr (buffer, "HTTP/1.1 ")))) {
            /* There was some sort of response code...*/
            char * httpcode = calloc(MIN(FILEBUFF - (size_t)(respcode - buffer), 13) + 1, 1);
            memcpy(httpcode, respcode, MIN(FILEBUFF - (size_t)(respcode - buffer), 13));
            if (proxy)
                logg ("%cgetfile: Unknown response from %s: %s\n",
                    logerr ? '!' : '^', hostname, httpcode);
            else
                logg ("%cgetfile: Unknown response from %s (IP: %s): %s\n",
                    logerr ? '!' : '^', hostname, ipaddr, httpcode);
            free (httpcode);
        }
        else {
            if (proxy)
                logg ("%cgetfile: Unknown response from %s\n",
                    logerr ? '!' : '^', hostname);
            else
                logg ("%cgetfile: Unknown response from %s (IP: %s)\n",
                    logerr ? '!' : '^', hostname, ipaddr);
        }
        if (mdat)
            mirman_update (mdat->currip, mdat->af, mdat, FCE_FAILEDGET);
        return FCE_FAILEDGET;
    }

    /* get size of resource */
    for (i = 0; (headerline = cli_strtok (buffer, i, "\n")); i++)
    {
        if (strstr (headerline, "Content-Length:"))
        {
            if ((ch = cli_strtok (headerline, 1, ": ")))
            {
                totalsize = atoi (ch);
                free (ch);
            }
            else
            {
                totalsize = 0;
            }
        }
        free (headerline);
    }

    if ((fd =
         open (destfile, O_WRONLY | O_CREAT | O_EXCL | O_BINARY, 0644)) == -1)
    {
        char currdir[512];

        if (getcwd (currdir, sizeof (currdir)))
            logg ("!getfile: Can't create new file %s in %s\n", destfile,
                  currdir);
        else
            logg ("!getfile: Can't create new file %s in the current directory\n", destfile);

        logg ("Hint: The database directory must be writable for UID %d or GID %d\n", getuid (), getgid ());
        return FCE_DBDIRACCESS;
    }

    if ((fname = strrchr (srcfile, '/')))
        fname++;
    else
        fname = srcfile;

#ifdef SO_ERROR
    while ((bread = wait_recv (sd, buffer, FILEBUFF, 0, rtimeout)) > 0)
    {
#else
    while ((bread = recv (sd, buffer, FILEBUFF, 0)) > 0)
    {
#endif
        if (write (fd, buffer, bread) != bread)
        {
            logg ("getfile: Can't write %d bytes to %s\n", bread, destfile);
            close (fd);
            unlink (destfile);
            return FCE_DBDIRACCESS;
        }

        totaldownloaded += bread;
        if (totalsize > 0)
            percentage = (int) (100 * (float) totaldownloaded / totalsize);

#ifdef HAVE_UNISTD_H
        if (!mprintf_quiet && (mprintf_progress || isatty(fileno(stdout))))
#else
        if (!mprintf_quiet)
#endif
        {
            if (totalsize > 0)
            {
                mprintf ("Downloading %s [%3i%%]\r", fname, percentage);
            }
            else
            {
                mprintf ("Downloading %s [%c]\r", fname, rotation[rot]);
                rot++;
                rot %= 4;
            }
            fflush (stdout);
        }
    }
    close (fd);

    if (bread == -1)
    {
        if (proxy)
            logg ("%cgetfile: Download interrupted: %s (Host: %s)\n",
                  logerr ? '!' : '^', strerror (errno), hostname);
        else
            logg ("%cgetfile: Download interrupted: %s (IP: %s)\n",
                  logerr ? '!' : '^', strerror (errno), ipaddr);
        if (mdat)
            mirman_update (mdat->currip, mdat->af, mdat, FCE_CONNECTION);
        return FCE_CONNECTION;
    }

    if (!totaldownloaded)
        return FCE_EMPTYFILE;

    if (totalsize > 0)
        logg ("Downloading %s [100%%]\n", fname);
    else
        logg ("Downloading %s [*]\n", fname);

    if (mdat)
        mirman_update (mdat->currip, mdat->af, mdat, FC_SUCCESS);
    return FC_SUCCESS;
}

static int
getfile (const char *srcfile, const char *destfile, const char *hostname,
         char *ip, const char *localip, const char *proxy, int port,
         const char *user, const char *pass, const char *uas, int ctimeout,
         int rtimeout, struct mirdat *mdat, int logerr,
         unsigned int can_whitelist, const char *ims,
         const struct optstruct *opts, unsigned int attempt)
{
    int ret, sd;
    char ipaddr[46];

    UNUSEDPARAM(opts);

    memset (ipaddr, 0, sizeof (ipaddr));
    if (ip && ip[0])            /* use ip to connect */
        sd = wwwconnect (ip, proxy, port, ipaddr, localip, ctimeout, mdat,
                         logerr, can_whitelist, attempt);
    else
        sd = wwwconnect (hostname, proxy, port, ipaddr, localip, ctimeout,
                         mdat, logerr, can_whitelist, attempt);

    if (sd < 0)
        return FCE_CONNECTION;

    ret = getfile_mirman (srcfile, destfile, hostname, ip, localip, proxy, port,
                        user, pass, uas, ctimeout, rtimeout, mdat, logerr,
                        can_whitelist, ims, ipaddr, sd);
    closesocket (sd);

    if (mdat) {
        /* Update mirrors.dat */
        (void) mirman_write ("mirrors.dat", dbdir, mdat);
    }

    return ret;
}

static int
getcvd (const char *cvdfile, const char *newfile, const char *hostname,
        char *ip, const char *localip, const char *proxy, int port,
        const char *user, const char *pass, const char *uas,
        unsigned int newver, int ctimeout, int rtimeout, struct mirdat *mdat,
        int logerr, unsigned int can_whitelist, const struct optstruct *opts,
        unsigned int attempt)
{
    struct cl_cvd *cvd;
    int ret;
    char *newfile2;


    logg ("*Retrieving http://%s/%s\n", hostname, cvdfile);

    if ((ret =
         getfile (cvdfile, newfile, hostname, ip, localip, proxy, port, user,
                  pass, uas, ctimeout, rtimeout, mdat, logerr, can_whitelist,
                  NULL, opts, attempt)))
    {
        logg ("%cCan't download %s from %s\n", logerr ? '!' : '^', cvdfile,
              hostname);
        unlink (newfile);
        return ret;
    }

    /* bb#10983 - temporarily rename newfile to correct extension for verification */
    newfile2 = strdup (newfile);
    if (!newfile2)
    {
        logg ("!Can't allocate memory for filename!\n");
        unlink (newfile);
        return FCE_MEM;
    }
    strncpy(newfile2 + strlen (newfile2) - 4, cvdfile + strlen (cvdfile) - 4, 4);
    if (rename (newfile, newfile2) == -1)
    {
        logg ("!Can't rename %s to %s: %s\n", newfile, newfile2,
              strerror (errno));
        unlink (newfile);
        free(newfile2);
        return FCE_DBDIRACCESS;
    }

    if ((ret = cl_cvdverify (newfile2)))
    {
        logg ("!Verification: %s\n", cl_strerror (ret));
        unlink (newfile2);
        free(newfile2);
        return FCE_BADCVD;
    }

    if (!(cvd = cl_cvdhead (newfile2)))
    {
        logg ("!Can't read CVD header of new %s database.\n", cvdfile);
        unlink (newfile2);
        free(newfile2);
        return FCE_BADCVD;
    }

    if (rename (newfile2, newfile) == -1)
    {
        logg ("!Can't rename %s to %s: %s\n", newfile2, newfile,
              strerror (errno));
        unlink (newfile2);
        free(newfile2);
        return FCE_DBDIRACCESS;
    }
    free(newfile2);

    if (cvd->version < newver)
    {
        logg ("^Mirror %s is not synchronized.\n", ip);
        unlink (newfile);
        if (cvd->version < newver - 1)
        {
            logg ("^Mirror is more than 1 version out of date. Recording mirror failure.\n");
            mirman_update (mdat->currip, mdat->af, mdat, FCE_MIRRORNOTSYNC);
            cl_cvdfree (cvd);
            return FCE_MIRRORNOTSYNC;
        }

        cl_cvdfree (cvd);
        return FC_UPTODATE;
    }

    cl_cvdfree (cvd);
    return FC_SUCCESS;
}

static int
chdir_tmp (const char *dbname, const char *tmpdir)
{
    char cvdfile[32];

    if (access (tmpdir, R_OK | W_OK) == -1)
    {
        int ret;
        ret = snprintf (cvdfile, sizeof(cvdfile), "%s.cvd", dbname);
        if (ret >= sizeof(cvdfile) || ret == -1) {
            logg ("!chdir_tmp: dbname parameter value too long to create cvd file name: %s\n", dbname);
            return -1;
        }
        if (access (cvdfile, R_OK) == -1)
        {
            ret = snprintf (cvdfile, sizeof(cvdfile), "%s.cld", dbname);
            if (ret >= sizeof(cvdfile) || ret == -1) {
                logg ("!chdir_tmp: dbname parameter value too long to create cld file name: %s\n", dbname);
                return -1;
            }
            if (access (cvdfile, R_OK) == -1)
            {
                logg ("!chdir_tmp: Can't access local %s database\n", dbname);
                return -1;
            }
        }

        if (mkdir (tmpdir, 0755) == -1)
        {
            logg ("!chdir_tmp: Can't create directory %s\n", tmpdir);
            return -1;
        }

        if (cli_cvdunpack (cvdfile, tmpdir) == -1)
        {
            logg ("!chdir_tmp: Can't unpack %s into %s\n", cvdfile, tmpdir);
            cli_rmdirs (tmpdir);
            return -1;
        }
    }

    if (chdir (tmpdir) == -1)
    {
        logg ("!chdir_tmp: Can't change directory to %s\n", tmpdir);
        return -1;
    }

    return 0;
}

static int
getpatch (const char *dbname, const char *tmpdir, int version,
          const char *hostname, char *ip, const char *localip,
          const char *proxy, int port, const char *user, const char *pass,
          const char *uas, int ctimeout, int rtimeout, struct mirdat *mdat,
          int logerr, unsigned int can_whitelist,
          const struct optstruct *opts, unsigned int attempt)
{
    char *tempname, patch[32], olddir[512];
    int ret, fd;


    if (!getcwd (olddir, sizeof (olddir)))
    {
        logg ("!getpatch: Can't get path of current working directory\n");
        return FCE_DIRECTORY;
    }

    if (chdir_tmp (dbname, tmpdir) == -1)
        return FCE_DIRECTORY;

    tempname = cli_gentemp (".");
    if(!tempname) {
        CHDIR_ERR (olddir);
        return FCE_MEM;
    }
    snprintf (patch, sizeof (patch), "%s-%d.cdiff", dbname, version);

    logg ("*Retrieving http://%s/%s\n", hostname, patch);
    if ((ret =
         getfile (patch, tempname, hostname, ip, localip, proxy, port, user,
                  pass, uas, ctimeout, rtimeout, mdat, logerr, can_whitelist,
                  NULL, opts, attempt)))
    {
        if (ret == FCE_EMPTYFILE)
            logg ("Empty script %s, need to download entire database\n",
                  patch);
        else
            logg ("%cgetpatch: Can't download %s from %s\n",
                  logerr ? '!' : '^', patch, hostname);
        unlink (tempname);
        free (tempname);
        CHDIR_ERR (olddir);
        return ret;
    }

    if ((fd = open (tempname, O_RDONLY | O_BINARY)) == -1)
    {
        logg ("!getpatch: Can't open %s for reading\n", tempname);
        unlink (tempname);
        free (tempname);
        CHDIR_ERR (olddir);
        return FCE_FILE;
    }

    if (cdiff_apply (fd, 1) == -1)
    {
        logg ("!getpatch: Can't apply patch\n");
        close (fd);
        unlink (tempname);
        free (tempname);
        CHDIR_ERR (olddir);
        return FCE_FAILEDUPDATE;
    }

    close (fd);
    unlink (tempname);
    free (tempname);
    if (chdir (olddir) == -1)
    {
        logg ("!getpatch: Can't chdir to %s\n", olddir);
        return FCE_DIRECTORY;
    }
    return FC_SUCCESS;
}

static struct cl_cvd *
currentdb (const char *dbname, char *localname)
{
    char db[32];
    struct cl_cvd *cvd = NULL;


    snprintf (db, sizeof (db), "%s.cvd", dbname);
    if (localname)
        strcpy (localname, db);

    if (access (db, R_OK) == -1)
    {
        snprintf (db, sizeof (db), "%s.cld", dbname);
        if (localname)
            strcpy (localname, db);
    }

    if (!access (db, R_OK))
        cvd = cl_cvdhead (db);

    return cvd;
}

static int
buildcld (const char *tmpdir, const char *dbname, const char *newfile,
          unsigned int compr)
{
    DIR *dir;
    char cwd[512], info[32], buff[513], *pt;
    struct dirent *dent;
    int fd, err = 0;
    gzFile gzs = NULL;

    if (!getcwd (cwd, sizeof (cwd)))
    {
        logg ("!buildcld: Can't get path of current working directory\n");
        return -1;
    }

    if (chdir (tmpdir) == -1)
    {
        logg ("!buildcld: Can't access directory %s\n", tmpdir);
        return -1;
    }

    snprintf (info, sizeof (info), "%s.info", dbname);
    if ((fd = open (info, O_RDONLY | O_BINARY)) == -1)
    {
        logg ("!buildcld: Can't open %s\n", info);
        CHDIR_ERR (cwd);
        return -1;
    }

    if (read (fd, buff, 512) == -1)
    {
        logg ("!buildcld: Can't read %s\n", info);
        CHDIR_ERR (cwd);
        close (fd);
        return -1;
    }
    buff[512] = 0;
    close (fd);

    if (!(pt = strchr (buff, '\n')))
    {
        logg ("!buildcld: Bad format of %s\n", info);
        CHDIR_ERR (cwd);
        return -1;
    }
    memset (pt, ' ', 512 + buff - pt);

    if ((fd =
         open (newfile, O_WRONLY | O_CREAT | O_EXCL | O_BINARY, 0644)) == -1)
    {
        logg ("!buildcld: Can't open %s for writing\n", newfile);
        CHDIR_ERR (cwd);
        return -1;
    }
    if (write (fd, buff, 512) != 512)
    {
        logg ("!buildcld: Can't write to %s\n", newfile);
        CHDIR_ERR (cwd);
        close (fd);
        unlink (newfile);
        return -1;
    }

    if ((dir = opendir (".")) == NULL)
    {
        logg ("!buildcld: Can't open directory %s\n", tmpdir);
        CHDIR_ERR (cwd);
        close (fd);
        unlink (newfile);
        return -1;
    }

    if (compr)
    {
        close (fd);
        if (!(gzs = gzopen (newfile, "ab9f")))
        {
            logg ("!buildcld: gzopen() failed for %s\n", newfile);
            CHDIR_ERR (cwd);
            closedir (dir);
            unlink (newfile);
            return -1;
        }
    }

    if (access ("COPYING", R_OK))
    {
        logg ("!buildcld: COPYING file not found\n");
        err = 1;
    }
    else
    {
        if (tar_addfile (fd, gzs, "COPYING") == -1)
        {
            logg ("!buildcld: Can't add COPYING to new %s.cld - please check if there is enough disk space available\n", dbname);
            if (!strcmp (dbname, "main") || !strcmp (dbname, "safebrowsing"))
                logg ("Updates to main.cvd or safebrowsing.cvd may require 200MB of disk space or more\n");
            err = 1;
        }
    }

    if (!err && !access (info, R_OK))
    {
        if (tar_addfile (fd, gzs, info) == -1)
        {
            logg ("!buildcld: Can't add %s to new %s.cld - please check if there is enough disk space available\n", info, dbname);
            if (!strcmp (dbname, "main") || !strcmp (dbname, "safebrowsing"))
                logg ("Updates to main.cvd or safebrowsing.cvd may require 200MB of disk space or more\n");
            err = 1;
        }
    }

    if (!err && !access ("daily.cfg", R_OK))
    {
        if (tar_addfile (fd, gzs, "daily.cfg") == -1)
        {
            logg ("!buildcld: Can't add daily.cfg to new %s.cld - please check if there is enough disk space available\n", dbname);
            err = 1;
        }
    }

    if (err)
    {
        CHDIR_ERR (cwd);
        if (gzs)
            gzclose (gzs);
        else
            close (fd);
        closedir (dir);
        unlink (newfile);
        return -1;
    }

    while ((dent = readdir (dir)))
    {
        if (dent->d_ino)
        {
            if (!strcmp (dent->d_name, ".") || !strcmp (dent->d_name, "..")
                || !strcmp (dent->d_name, "COPYING")
                || !strcmp (dent->d_name, "daily.cfg")
                || !strcmp (dent->d_name, info))
                continue;

            if (tar_addfile (fd, gzs, dent->d_name) == -1)
            {
                logg ("!buildcld: Can't add %s to new %s.cld - please check if there is enough disk space available\n", dent->d_name, dbname);
                if (!strcmp (dbname, "main")
                    || !strcmp (dbname, "safebrowsing"))
                    logg ("Updates to main.cvd or safebrowsing.cvd may require 200MB of disk space or more\n");
                CHDIR_ERR (cwd);
                if (gzs)
                    gzclose (gzs);
                else
                    close (fd);
                closedir (dir);
                unlink (newfile);
                return -1;
            }
        }
    }
    closedir (dir);

    if (gzs)
    {
        if (gzclose (gzs))
        {
            logg ("!buildcld: gzclose() failed for %s\n", newfile);
            unlink (newfile);
            return -1;
        }
    }
    else
    {
        if (close (fd) == -1)
        {
            logg ("!buildcld: close() failed for %s\n", newfile);
            unlink (newfile);
            return -1;
        }
    }

    if (chdir (cwd) == -1)
    {
        logg ("!buildcld: Can't return to previous directory %s\n", cwd);
        return -1;
    }

    return 0;
}

static int
test_database (const char *newfile, const char *newdb, int bytecode)
{
    struct cl_engine *engine;
    unsigned newsigs = 0;
    int ret;

    logg ("*Loading signatures from %s\n", newdb);
    if (!(engine = cl_engine_new ()))
    {
        return FCE_TESTFAIL;
    }
    cl_engine_set_clcb_stats_submit(engine, NULL);

    if ((ret =
         cl_load (newfile, engine, &newsigs,
                  CL_DB_PHISHING | CL_DB_PHISHING_URLS | CL_DB_BYTECODE |
                  CL_DB_PUA | CL_DB_ENHANCED)) != CL_SUCCESS)
    {
        logg ("!Failed to load new database: %s\n", cl_strerror (ret));
        cl_engine_free (engine);
        return FCE_TESTFAIL;
    }
    if (bytecode
        && (ret =
            cli_bytecode_prepare2 (engine, &engine->bcs,
                                   engine->dconf->
                                   bytecode
                                   /*FIXME: dconf has no sense here */ )))
    {
        logg ("!Failed to compile/load bytecode: %s\n", cl_strerror (ret));
        cl_engine_free (engine);
        return FCE_TESTFAIL;
    }
    logg ("*Properly loaded %u signatures from new %s\n", newsigs, newdb);
    if (engine->domainlist_matcher
        && engine->domainlist_matcher->sha256_pfx_set.keys)
        cli_hashset_destroy (&engine->domainlist_matcher->sha256_pfx_set);
    cl_engine_free (engine);
    return FC_SUCCESS;
}

#ifndef WIN32
static int
test_database_wrap (const char *file, const char *newdb, int bytecode)
{
    char firstline[256];
    char lastline[256];
    int pipefd[2];
    pid_t pid;
    int status = 0, ret;
    FILE *f;

    if (pipe (pipefd) == -1)
    {
        logg ("^pipe() failed: %s\n", strerror (errno));
        return test_database (file, newdb, bytecode);
    }

    switch (pid = fork ())
    {
    case 0:
        close (pipefd[0]);
        if (dup2 (pipefd[1], 2) == -1)
            logg("^dup2() failed: %s\n", strerror(errno));
        exit (test_database (file, newdb, bytecode));
    case -1:
        close (pipefd[0]);
        close (pipefd[1]);
        logg ("^fork() failed: %s\n", strerror (errno));
        return test_database (file, newdb, bytecode);
    default:
        /* read first / last line printed by child */
        close (pipefd[1]);
        f = fdopen (pipefd[0], "r");
        firstline[0] = 0;
        lastline[0] = 0;
        do
        {
            if (!fgets (firstline, sizeof (firstline), f))
                break;
            /* ignore warning messages, otherwise the outdated warning will
             * make us miss the important part of the error message */
        }
        while (!strncmp (firstline, "LibClamAV Warning:", 18));
        /* must read entire output, child doesn't like EPIPE */
        while (fgets (lastline, sizeof (firstline), f))
        {
            /* print the full output only when LogVerbose or -v is given */
            logg ("*%s", lastline);
        }
        fclose (f);

        while ((ret = waitpid (pid, &status, 0)) == -1 && errno == EINTR);
        if (ret == -1 && errno != ECHILD)
            logg ("^waitpid() failed: %s\n", strerror (errno));
        cli_chomp (firstline);
        cli_chomp (lastline);
        if (firstline[0])
        {
            logg ("!During database load : %s%s%s\n",
                  firstline, lastline[0] ? " [...] " : "", lastline);
        }
        if (WIFEXITED (status))
        {
            ret = WEXITSTATUS (status);
            if (ret)
            {
                logg ("^Database load exited with status %d\n", ret);
                return ret;
            }
            if (firstline[0])
                logg ("^Database successfully loaded, but there is stderr output\n");
            return FC_SUCCESS;
        }
        if (WIFSIGNALED (status))
        {
            logg ("!Database load killed by signal %d\n", WTERMSIG (status));
            return FCE_TESTFAIL;
        }
        logg ("^Unknown status from wait: %d\n", status);
        return FCE_TESTFAIL;
    }
}
#else
static int
test_database_wrap (const char *file, const char *newdb, int bytecode)
{
    int ret = FCE_TESTFAIL;
    __try
    {
        ret = test_database (file, newdb, bytecode);
    }
    __except (logg ("!Exception during database testing, code %08x\n",
                    GetExceptionCode ()), EXCEPTION_CONTINUE_SEARCH)
    {
    }
    return ret;
}
#endif

static int
checkdbdir (void)
{
    DIR *dir;
    struct dirent *dent;
    char fname[512], broken[513];
    int ret, fret = 0;

    if (!(dir = opendir (dbdir)))
    {
        logg ("!checkdbdir: Can't open directory %s\n", dbdir);
        return -1;
    }

    while ((dent = readdir (dir)))
    {
        if (dent->d_ino)
        {
            if (cli_strbcasestr (dent->d_name, ".cld")
                || cli_strbcasestr (dent->d_name, ".cvd"))
            {
                snprintf (fname, sizeof (fname), "%s" PATHSEP "%s", dbdir,
                          dent->d_name);
                if ((ret = cl_cvdverify (fname)))
                {
                    fret = -1;
                    mprintf ("!Corrupted database file %s: %s\n", fname,
                             cl_strerror (ret));
                    snprintf (broken, sizeof (broken), "%s.broken", fname);
                    if (!access (broken, R_OK))
                        unlink (broken);
                    if (rename (fname, broken))
                    {
                        if (unlink (fname))
                            mprintf
                                ("!Can't remove broken database file %s, please delete it manually and restart freshclam\n",
                                 fname);
                    }
                    else
                    {
                        mprintf ("Corrupted database file renamed to %s\n",
                                 broken);
                    }
                }
            }
        }
    }

    closedir (dir);
    return fret;
}

static const char * dns_label(const char * ip)
{
    static const char hex[] = "0123456789ABCDEF";
    char *c, *n = NULL, *m = g_label, *cc = g_label;
    const char *p, *q;
    int r, cs = 0;
    int has_ipv4 = strchr(ip, '.')?1:0;

    strcpy(g_label, "0000000000000000"
                    "0000000000000000");

    if (strchr(ip, ':')) { /* IPv6 */
        p = ip;
        c = g_label;
        while ((q = strchr(p, ':'))) {
            r = q - p;
            if (r>0 && r<5) {
                memcpy(c+4-r, p, r);
                c+=4;
            }
            p = q + 1;
            if (++cs > 7)
                break;
            if (*p == ':') { /* check :: */
		cc = c - 1;
                if (has_ipv4)
                    n = g_label + 23;
                else
                    n = g_label + 31;
                break;
            }
        }
        if (q == NULL) {
            /* do last ipv6 segment */
            q = p+strlen(p);
            r = q - p;
            if (r>0 && r<5)
                memcpy(c+4-r, p, r);
        }
        if (n) { /* go backward to :: */
            int k = 0;
            if (has_ipv4)
                q = strrchr(p, ':');
            else
                q = p + strlen(p) - 1;
            if (!(*q == ':' && *--q == ':'))
                while (n > cc) {
                    if (*q == ':') {
                        if (*(q-1) == ':')
                            break;
                        n -= 4-k;
                        k = 0;
                    } else {
                        *n = *q;
                        n--;
                        k++;
                    }
                    q--;
                }
        }
        if (has_ipv4) {
            m = g_label + 24;
            ip = strrchr(ip, ':') + 1;
        }
    }

    if (has_ipv4) {
        uint8_t x;
        do {
            x = atoi(ip);
            *m++ = hex[x>>4];
            *m++ = hex[x&0x0F];
            ip = strchr(ip, '.');
        } while (ip++ && *m && *(m+1));
        *m = '\0';
    }

    return g_label;
}

extern int sigchld_wait;

static int
updatedb (const char *dbname, const char *hostname, char *ip, int *signo,
          const struct optstruct *opts, const char *dnsreply, char *localip,
          int outdated, struct mirdat *mdat, int logerr, int extra,
          unsigned int attempt)
{
    struct cl_cvd *current, *remote;
    const struct optstruct *opt;
    unsigned int nodb = 0, currver = 0, newver = 0, port = 0, i, j;
    int ret, ims = -1, iscld = 0, field = 0;
    char *pt, cvdfile[32], cldfile[32], localname[32], *tmpdir =
        NULL, *newfile, *newfile2, newdb[32];
    char extradbinfo[256], *extradnsreply = NULL, squery[256];
    const char *proxy = NULL, *user = NULL, *pass = NULL, *uas = NULL;
    unsigned int flevel = cl_retflevel (), remote_flevel = 0, maxattempts;
    unsigned int can_whitelist = 0, mirror_stats = 0;
#ifdef _WIN32
    unsigned int w32 = 1;
#else
    unsigned int w32 = 0;
#endif
    int ctimeout, rtimeout;


    if (cli_strbcasestr (hostname, ".clamav.net"))
        mirror_stats = 1;

    snprintf (cvdfile, sizeof (cvdfile), "%s.cvd", dbname);
    snprintf (cldfile, sizeof (cldfile), "%s.cld", dbname);

    if (!extra)
    {
        field = textrecordfield(dbname);
    }

    if (!(current = currentdb (dbname, localname)))
    {
        nodb = 1;
    }
    else
    {
        mdat->dbflevel = current->fl;
    }

    if (!nodb && !extra && dnsreply)
    {
        if (!field)
        {
            logg ("!updatedb: Unknown database name (%s) passed.\n", dbname);
            cl_cvdfree (current);
            return FCE_FAILEDUPDATE;
        }

        if ((pt = cli_strtok (dnsreply, field, ":")))
        {
            if (!cli_isnumber (pt))
            {
                logg ("^Broken database version in TXT record.\n");
            }
            else
            {
                newver = atoi (pt);
                logg ("*%s version from DNS: %d\n", cvdfile, newver);
            }
            free (pt);
        }
        else
        {
            logg ("^Invalid DNS reply. Falling back to HTTP mode.\n");
        }
    }
#ifdef HAVE_RESOLV_H
    else if (!nodb && extra && !optget (opts, "no-dns")->enabled)
    {
        snprintf (extradbinfo, sizeof (extradbinfo), "%s.cvd.clamav.net",
                  dbname);
        if ((extradnsreply = dnsquery (extradbinfo, T_TXT, NULL)))
        {
            if ((pt = cli_strtok (extradnsreply, 1, ":")))
            {
                int rt;
                time_t ct;

                rt = atoi (pt);
                free (pt);
                time (&ct);
                if ((int) ct - rt > 10800)
                {
                    logg ("^DNS record is older than 3 hours.\n");
                    free (extradnsreply);
                    extradnsreply = NULL;
                }
            }
            else
            {
                logg ("^No timestamp in TXT record for %s\n", cvdfile);
                free (extradnsreply);
                extradnsreply = NULL;
            }
            if ((pt = cli_strtok (extradnsreply, 0, ":")))
            {
                if (!cli_isnumber (pt))
                {
                    logg ("^Broken database version in TXT record for %s\n",
                          cvdfile);
                }
                else
                {
                    newver = atoi (pt);
                    logg ("*%s version from DNS: %d\n", cvdfile, newver);
                }
                free (pt);
            }
            else
            {
                logg ("^Invalid DNS reply. Falling back to HTTP mode.\n");
            }
        }
    }
#endif

    if (dnsreply && !extra)
    {
        if ((pt = cli_strtok (dnsreply, 5, ":")))
        {
            remote_flevel = atoi (pt);
            free (pt);
            if (remote_flevel && (remote_flevel - flevel < 4))
                can_whitelist = 1;
        }
    }

    /* Initialize proxy settings */
    if ((opt = optget (opts, "HTTPProxyServer"))->enabled)
    {
        proxy = opt->strarg;
        if (strncasecmp (proxy, "http://", 7) == 0)
            proxy += 7;

        if ((opt = optget (opts, "HTTPProxyUsername"))->enabled)
        {
            user = opt->strarg;
            if ((opt = optget (opts, "HTTPProxyPassword"))->enabled)
            {
                pass = opt->strarg;
            }
            else
            {
                logg ("HTTPProxyUsername requires HTTPProxyPassword\n");
                if (current)
                    cl_cvdfree (current);
                return FCE_CONFIG;
            }
        }

        if ((opt = optget (opts, "HTTPProxyPort"))->enabled)
            port = opt->numarg;

        logg ("Connecting via %s\n", proxy);
    }

    if ((opt = optget (opts, "HTTPUserAgent"))->enabled)
        uas = opt->strarg;

    ctimeout = optget (opts, "ConnectTimeout")->numarg;
    rtimeout = optget (opts, "ReceiveTimeout")->numarg;

    if (!nodb && !newver)
    {
        if (optget (opts, "PrivateMirror")->enabled)
        {
            /*
             * For a private mirror, get the CLD instead of the CVD.
             */
            remote =
                remote_cvdhead (cldfile, localname, hostname, ip, localip,
                                proxy, port, user, pass, uas, &ims, ctimeout,
                                rtimeout, mdat, logerr, can_whitelist,
                                attempt);
            if (!remote && (ims != 0)) {
                /*
                 * Failed to get CLD update, and it's unknown if the status is up-to-date.
                 * Attempt to get the CVD instead.
                 */
                iscld = -1;
                remote =
                    remote_cvdhead (cvdfile, localname, hostname, ip, localip,
                                    proxy, port, user, pass, uas, &ims,
                                    ctimeout, rtimeout, mdat, logerr,
                                    can_whitelist, attempt);
            }
        }
        else
            remote =
                remote_cvdhead (cvdfile, localname, hostname, ip, localip,
                                proxy, port, user, pass, uas, &ims, ctimeout,
                                rtimeout, mdat, logerr, can_whitelist,
                                attempt);

        if (!nodb && !ims)
        {
            logg ("%s is up to date (version: %d, sigs: %d, f-level: %d, builder: %s)\n", localname, current->version, current->sigs, current->fl, current->builder);
            *signo += current->sigs;
#ifdef HAVE_RESOLV_H
            if (mirror_stats && strlen (ip))
            {
                snprintf (squery, sizeof (squery),
                          "%s.%u.%u.%u.%u.%s.ping.clamav.net", dbname,
                          current->version, flevel, 1, w32, dns_label(ip));
                dnsquery (squery, T_A, NULL);
            }
#endif
            cl_cvdfree (current);
            return FC_UPTODATE;
        }

        if (!remote)
        {
            if (proxy)
                logg ("^Can't read %s header from %s\n", cvdfile, hostname);
            else
                logg ("^Can't read %s header from %s (IP: %s)\n", cvdfile,
                      hostname, ip);
#ifdef HAVE_RESOLV_H
            if (mirror_stats && strlen (ip))
            {
                snprintf (squery, sizeof (squery),
                          "%s.%u.%u.%u.%u.%s.ping.clamav.net", dbname,
                          current->version + 1, flevel, 0, w32, dns_label(ip));
                dnsquery (squery, T_A, NULL);
            }
#endif
            cl_cvdfree (current);
            return FCE_FAILEDGET;
        }

        newver = remote->version;
        cl_cvdfree (remote);
    }

    if (!nodb && (current->version >= newver))
    {
        logg ("%s is up to date (version: %d, sigs: %d, f-level: %d, builder: %s)\n", localname, current->version, current->sigs, current->fl, current->builder);

        if (!outdated && flevel < current->fl)
        {
            /* display warning even for already installed database */
            logg ("^Current functionality level = %d, recommended = %d\n",
                  flevel, current->fl);
            logg ("Please check if ClamAV tools are linked against the proper version of libclamav\n");
            logg ("DON'T PANIC! Read https://www.clamav.net/documents/installing-clamav\n");
        }

        *signo += current->sigs;
        cl_cvdfree (current);
        return FC_UPTODATE;
    }

    if (current)
    {
        currver = current->version;
        cl_cvdfree (current);
    }

    if (!optget (opts, "ScriptedUpdates")->enabled)
        nodb = 1;

    newfile = cli_gentemp (updtmpdir);
    if(!newfile)
        return FCE_MEM;

    if (nodb)
    {
        if (optget (opts, "PrivateMirror")->enabled)
        {
            ret = 0;
            if (iscld >= 0)
                ret =
                    getcvd (cldfile, newfile, hostname, ip, localip, proxy,
                            port, user, pass, uas, newver, ctimeout, rtimeout,
                            mdat, logerr, can_whitelist, opts, attempt);
            if (ret || iscld < 0)
                ret =
                    getcvd (cvdfile, newfile, hostname, ip, localip, proxy,
                            port, user, pass, uas, newver, ctimeout, rtimeout,
                            mdat, logerr, can_whitelist, opts, attempt);
            else
                iscld = 1;
        }
        else
        {
            ret =
                getcvd (cvdfile, newfile, hostname, ip, localip, proxy, port,
                        user, pass, uas, newver, ctimeout, rtimeout, mdat,
                        logerr, can_whitelist, opts, attempt);
        }

        if (ret)
        {
#ifdef HAVE_RESOLV_H
            if (mirror_stats && strlen (ip))
            {
                snprintf (squery, sizeof (squery),
                          "%s.%u.%u.%u.%u.%s.ping.clamav.net", dbname, 0,
                          flevel, 0, w32, dns_label(ip));
                dnsquery (squery, T_A, NULL);
            }
#endif
            memset (ip, 0, 16);
            free (newfile);
            return ret;
        }
        if (iscld > 0)
            snprintf (newdb, sizeof (newdb), "%s.cld", dbname);
        else
            snprintf (newdb, sizeof (newdb), "%s.cvd", dbname);

    }
    else
    {
        ret = 0;

        tmpdir = cli_gentemp (updtmpdir);
	if(!tmpdir){
	    free(newfile);
	    return FCE_MEM;
	}

        maxattempts = optget (opts, "MaxAttempts")->numarg;
        for (i = currver + 1; i <= newver; i++)
        {
            for (j = 1; j <= maxattempts; j++)
            {
                int llogerr = logerr;
                if (logerr)
                    llogerr = (j == maxattempts);
                ret =
                    getpatch (dbname, tmpdir, i, hostname, ip, localip, proxy,
                              port, user, pass, uas, ctimeout, rtimeout, mdat,
                              llogerr, can_whitelist, opts,
                              attempt == 1 ? j : attempt);
                if (ret == FCE_CONNECTION || ret == FCE_FAILEDGET)
                {
#ifdef HAVE_RESOLV_H
                    if (mirror_stats && strlen (ip))
                    {
                        snprintf (squery, sizeof (squery),
                                  "%s.%u.%u.%u.%u.%s.ping.clamav.net", dbname,
                                  i, flevel, 0, w32, dns_label(ip));
                        dnsquery (squery, T_A, NULL);
                    }
#endif
                    memset (ip, 0, 16);
                    continue;
                }
                else
                {
                    break;
                }
            }
            if (ret)
                break;
        }

        if (ret)
        {
            cli_rmdirs (tmpdir);
            free (tmpdir);
            if (ret != FCE_EMPTYFILE)
                logg ("^Incremental update failed, trying to download %s\n",
                      cvdfile);
            mirman_whitelist (mdat, 2);
            ret =
                getcvd (cvdfile, newfile, hostname, ip, localip, proxy, port,
                        user, pass, uas, newver, ctimeout, rtimeout, mdat,
                        logerr, can_whitelist, opts, attempt);
            if (ret)
            {
#ifdef HAVE_RESOLV_H
                if (mirror_stats && strlen (ip))
                {
                    snprintf (squery, sizeof (squery),
                              "%s.%u.%u.%u.%u.%s.ping.clamav.net", dbname, 0,
                              flevel, 0, w32, dns_label(ip));
                    dnsquery (squery, T_A, NULL);
                }
#endif
                free (newfile);
                return ret;
            }
            snprintf (newdb, sizeof (newdb), "%s.cvd", dbname);
        }
        else
        {
            if (buildcld
                (tmpdir, dbname, newfile,
                 optget (opts, "CompressLocalDatabase")->enabled) == -1)
            {
                logg ("!Can't create local database\n");
                cli_rmdirs (tmpdir);
                free (tmpdir);
                free (newfile);
                return FCE_FAILEDUPDATE;
            }
            snprintf (newdb, sizeof (newdb), "%s.cld", dbname);
            cli_rmdirs (tmpdir);
            free (tmpdir);
        }
    }

    if (!(current = cl_cvdhead (newfile)))
    {
        logg ("!Can't parse new database %s\n", newfile);
        unlink (newfile);
        free (newfile);
        return FCE_FILE;
    }

    if (optget (opts, "TestDatabases")->enabled && strlen (newfile) > 4)
    {
        newfile2 = strdup (newfile);
        if (!newfile2)
        {
            logg ("!Can't allocate memory for filename!\n");
            unlink (newfile);
            free (newfile);
            cl_cvdfree(current);
            return FCE_TESTFAIL;
        }
        newfile2[strlen (newfile2) - 4] = '.';
        newfile2[strlen (newfile2) - 3] = 'c';
        newfile2[strlen (newfile2) - 2] = strstr (newdb, ".cld") ? 'l' : 'v';
        newfile2[strlen (newfile2) - 1] = 'd';
        if (rename (newfile, newfile2) == -1)
        {
            logg ("!Can't rename %s to %s: %s\n", newfile, newfile2,
                  strerror (errno));
            unlink (newfile);
            free (newfile);
            free (newfile2);
            cl_cvdfree(current);
            return FCE_DBDIRACCESS;
        }
        free (newfile);
        newfile = newfile2;
        sigchld_wait = 0;       /* we need to wait() for the child ourselves */
        if (test_database_wrap
            (newfile, newdb, optget (opts, "Bytecode")->enabled))
        {
            logg ("!Failed to load new database\n");
            unlink (newfile);
            free (newfile);
            cl_cvdfree(current);
            return FCE_TESTFAIL;
        }
        sigchld_wait = 1;
    }

#ifdef _WIN32
    if (!access (newdb, R_OK) && unlink (newdb))
    {
        logg ("!Can't unlink %s. Please fix the problem manually and try again.\n", newdb);
        unlink (newfile);
        free (newfile);
        cl_cvdfree (current);
        return FCE_EMPTYFILE;
    }
#endif

    if (rename (newfile, newdb) == -1)
    {
        logg ("!Can't rename %s to %s: %s\n", newfile, newdb,
              strerror (errno));
        unlink (newfile);
        free (newfile);
        cl_cvdfree (current);
        return FCE_DBDIRACCESS;
    }
    free (newfile);

    if (!nodb && !access (localname, R_OK) && strcmp (newdb, localname))
        if (unlink (localname))
            logg ("^Can't unlink the old database file %s. Please remove it manually.\n", localname);

    if (!optget (opts, "ScriptedUpdates")->enabled && !optget (opts, "PrivateMirror")->enabled)
    {
        snprintf (localname, sizeof (localname), "%s.cld", dbname);
        if (!access (localname, R_OK))
            if (unlink (localname))
                logg ("^Can't unlink the old database file %s. Please remove it manually.\n", localname);
    }

    logg ("%s updated (version: %d, sigs: %d, f-level: %d, builder: %s)\n",
          newdb, current->version, current->sigs, current->fl,
          current->builder);

    if (flevel < current->fl)
    {
        logg ("^Your ClamAV installation is OUTDATED!\n");
        logg ("^Current functionality level = %d, recommended = %d\n", flevel,
              current->fl);
        logg ("DON'T PANIC! Read https://www.clamav.net/documents/installing-clamav\n");

    }

    *signo += current->sigs;
#ifdef HAVE_RESOLV_H
    if (mirror_stats && strlen (ip))
    {
        snprintf (squery, sizeof (squery),
                  "%s.%u.%u.%u.%u.%s.ping.clamav.net", dbname,
                  current->version, flevel, 1, w32, dns_label(ip));
        dnsquery (squery, T_A, NULL);
    }
#endif
    cl_cvdfree (current);
    return FC_SUCCESS;
}

static int
updatecustomdb (const char *url, int *signo, const struct optstruct *opts,
                char *localip, int logerr)
{
    const struct optstruct *opt;
    unsigned int port = 0, sigs = 0;
    int ret;
    char *pt, *host, urlcpy[256], *newfile = NULL, mtime[36], *newfile2;
    const char *proxy = NULL, *user = NULL, *pass = NULL, *uas =
        NULL, *rpath, *dbname;
    int ctimeout, rtimeout;
    STATBUF sb;
    struct cl_cvd *cvd;

    if (strlen (url) > sizeof (urlcpy) - 1)
    {
        logg ("!DatabaseCustomURL: URL must be shorter than %llu\n",
              (long long unsigned)sizeof (urlcpy));
        return FCE_FAILEDUPDATE;
    }

    if (!strncasecmp (url, "http://", 7))
    {
        strncpy (urlcpy, url, sizeof (urlcpy));
        urlcpy[sizeof(urlcpy)-1] = '\0';
        host = &urlcpy[7];
        if (!(pt = strchr (host, '/')))
        {
            logg ("!DatabaseCustomURL: Incorrect URL\n");
            return FCE_FAILEDUPDATE;
        }
        *pt = 0;
        rpath = &url[pt - urlcpy + 1];
        dbname = strrchr (url, '/') + 1;
        if (!dbname || strlen (dbname) < 4)
        {
            logg ("DatabaseCustomURL: Incorrect URL\n");
            return FCE_FAILEDUPDATE;
        }

        /* Initialize proxy settings */
        if ((opt = optget (opts, "HTTPProxyServer"))->enabled)
        {
            proxy = opt->strarg;
            if (strncasecmp (proxy, "http://", 7) == 0)
                proxy += 7;

            if ((opt = optget (opts, "HTTPProxyUsername"))->enabled)
            {
                user = opt->strarg;
                if ((opt = optget (opts, "HTTPProxyPassword"))->enabled)
                {
                    pass = opt->strarg;
                }
                else
                {
                    logg ("HTTPProxyUsername requires HTTPProxyPassword\n");
                    return FCE_CONFIG;
                }
            }
            if ((opt = optget (opts, "HTTPProxyPort"))->enabled)
                port = opt->numarg;
            logg ("Connecting via %s\n", proxy);
        }

        if ((opt = optget (opts, "HTTPUserAgent"))->enabled)
            uas = opt->strarg;

        ctimeout = optget (opts, "ConnectTimeout")->numarg;
        rtimeout = optget (opts, "ReceiveTimeout")->numarg;

        *mtime = 0;
        if (CLAMSTAT (dbname, &sb) != -1)
            Rfc2822DateTime (mtime, sb.st_mtime);

        newfile = cli_gentemp (updtmpdir);
        ret =
            getfile (rpath, newfile, host, NULL, localip, proxy, port, user,
                     pass, uas, ctimeout, rtimeout, NULL, logerr, 0,
                     *mtime ? mtime : NULL, opts, 1);
        if (ret == 1)
        {
            logg ("%s is up to date (version: custom database)\n", dbname);
            unlink (newfile);
            free (newfile);
            return FC_UPTODATE;
        }
        else if (ret > 1)
        {
            logg ("%cCan't download %s from %s\n", logerr ? '!' : '^', dbname,
                  host);
            unlink (newfile);
            free (newfile);
            return ret;
        }

    }
    else if (!strncasecmp (url, "file://", 7))
    {
        time_t dbtime, rtime;
        rpath = &url[7];
#ifdef _WIN32
        dbname = strrchr (rpath, '\\');
#else
        dbname = strrchr (rpath, '/');
#endif
        if (!dbname || strlen (dbname++) < 5)
        {
            logg ("DatabaseCustomURL: Incorrect URL\n");
            return FCE_FAILEDUPDATE;
        }

        if (CLAMSTAT (rpath, &sb) == -1)
        {
	    logg ("DatabaseCustomURL: file %s missing\n", rpath);
	    return FCE_FAILEDUPDATE;
        }
        rtime = sb.st_mtime;
        dbtime = (CLAMSTAT (dbname, &sb) != -1) ? sb.st_mtime : 0;
        if (dbtime > rtime)
        {
            logg ("%s is up to date (version: custom database)\n", dbname);
            return FC_UPTODATE;
        }

        newfile = cli_gentemp (updtmpdir);
        if (!newfile)
            return FCE_FAILEDUPDATE;

        /* FIXME: preserve file permissions, calculate % */
        if (cli_filecopy (rpath, newfile) == -1)
        {
            logg ("DatabaseCustomURL: Can't copy file %s into database directory\n", rpath);
            free (newfile);
            return FCE_FAILEDUPDATE;
        }
        logg ("Downloading %s [100%%]\n", dbname);
    }
    else
    {
        logg ("!DatabaseCustomURL: Not supported protocol\n");
        return FCE_FAILEDUPDATE;
    }

    if (optget (opts, "TestDatabases")->enabled && strlen (newfile) > 4)
    {
        newfile2 = malloc (strlen (newfile) + strlen (dbname) + 1);
        if (!newfile2)
        {
            unlink (newfile);
            free (newfile);
            return FCE_TESTFAIL;
        }
        sprintf (newfile2, "%s%s", newfile, dbname);
        newfile2[strlen (newfile) + strlen (dbname)] = 0;
        if (rename (newfile, newfile2) == -1)
        {
            logg ("!Can't rename %s to %s: %s\n", newfile, newfile2,
                  strerror (errno));
            unlink (newfile);
            free (newfile);
            free (newfile2);
            return FCE_DBDIRACCESS;
        }
        free (newfile);
        newfile = newfile2;
        sigchld_wait = 0;       /* we need to wait() for the child ourselves */
        if (test_database_wrap
            (newfile, dbname, optget (opts, "Bytecode")->enabled))
        {
            logg ("!Failed to load new database\n");
            unlink (newfile);
            free (newfile);
            return FCE_TESTFAIL;
        }
        sigchld_wait = 1;
    }

#ifdef _WIN32
    if (!access (dbname, R_OK) && unlink (dbname))
    {
        logg ("!Can't unlink %s. Please fix the problem manually and try again.\n", dbname);
        unlink (newfile);
        free (newfile);
        return FCE_EMPTYFILE;
    }
#endif

    if (rename (newfile, dbname) == -1)
    {
        logg ("!Can't rename %s to %s: %s\n", newfile, dbname,
              strerror (errno));
        unlink (newfile);
        free (newfile);
        return FCE_DBDIRACCESS;
    }
    free (newfile);

    if (cli_strbcasestr (dbname, ".cld") || cli_strbcasestr (dbname, ".cvd"))
    {
        if ((cvd = cl_cvdhead (dbname)))
        {
            sigs = cvd->sigs;
            cl_cvdfree (cvd);
        }
    }
    else if (cli_strbcasestr (dbname, ".cbc"))
    {
        sigs = 1;
    }
    else
    {
        sigs = countlines (dbname);
    }

    logg ("%s updated (version: custom database, sigs: %u)\n", dbname, sigs);
    *signo += sigs;
    return FC_SUCCESS;
}

/**
 * @brief Compare two version strings.
 *
 * @param v1 Version string 1
 * @param v2 Version string 2
 * @return int 1 if v1 is greater, 0 if equal, -1 if smaller.
 */
int version_string_compare(char *v1, size_t v1_len, char *v2, size_t v2_len)
{
    size_t i, j;
    int vnum1 = 0, vnum2 = 0;

    for (i = 0, j = 0; (i < v1_len || j < v2_len);) {
        while (i < v1_len && v1[i] != '.') {
            vnum1 = vnum1 * 10 + (v1[i] - '0');
            i++;
        }

        while (j < v2_len && v2[j] != '.') {
            vnum2 = vnum2 * 10 + (v2[j] - '0');
            j++;
        }

        if (vnum1 > vnum2)
            return 1;
        if (vnum2 > vnum1)
            return -1;

        vnum1 = vnum2 = 0;
        i++;
        j++;
    }
    return 0;
}

int
downloadmanager (const struct optstruct *opts, const char *hostname,
                 unsigned int attempt)
{
    int ret, custret = 0, updated = 0, outdated = 0, signo = 0, logerr;
    unsigned int ttl;
    char ipaddr[46], *dnsreply = NULL, *pt, *localip = NULL, *newver = NULL;
    const struct optstruct *opt;
    struct mirdat mdat;
#ifdef HAVE_RESOLV_H
    const char *dnsdbinfo;
#endif

    logerr = (optget (opts, "MaxAttempts")->numarg == attempt);

    pt = cli_gentemp (dbdir);
    if (!pt)
        return FCE_DBDIRACCESS;
    strncpy (updtmpdir, pt, sizeof (updtmpdir));
    updtmpdir[sizeof (updtmpdir) - 1] = '\0';
    free (pt);
    if (mkdir (updtmpdir, 0755))
    {
        logg ("!Can't create temporary directory %s\n", updtmpdir);
        logg ("Hint: The database directory must be writable for UID %d or GID %d\n", getuid (), getgid ());
        return FCE_DBDIRACCESS;
    }

#ifdef HAVE_RESOLV_H
    dnsdbinfo = optget (opts, "DNSDatabaseInfo")->strarg;

    if (optget (opts, "no-dns")->enabled)
    {
        dnsreply = NULL;
    }
    else
    {
        if ((dnsreply = dnsquery (dnsdbinfo, T_TXT, &ttl)))
        {
            logg ("*TTL: %d\n", ttl);

            if ((pt = cli_strtok (dnsreply, 3, ":")))
            {
                int rt;
                time_t ct;

                rt = atoi (pt);
                free (pt);
                time (&ct);
                if ((int) ct - rt > 10800)
                {
                    logg ("^DNS record is older than 3 hours.\n");
                    free (dnsreply);
                    dnsreply = NULL;
                }

            }
            else
            {
                free (dnsreply);
                dnsreply = NULL;
            }

            if (dnsreply)
            {
                int vwarning = 1;

                if ((pt = cli_strtok (dnsreply, 4, ":")))
                {
                    if (*pt == '0')
                        vwarning = 0;

                    free (pt);
                }

                if ((newver = cli_strtok (dnsreply, 0, ":")))
                {
                    char vstr[32];

                    logg ("*Software version from DNS: %s\n", newver);
                    strncpy (vstr, get_version (), 32);
                    vstr[31] = 0;
                    if (vwarning && !strstr (vstr, "devel")
                        && !strstr (vstr, "beta")
                        && !strstr (vstr, "rc"))
                    {
                        pt = strchr (vstr, '-');
                        if ((pt && (0 > version_string_compare(vstr, pt - vstr, newver, strlen(newver)))) ||
                            (!pt && (0 > version_string_compare(vstr, strlen(vstr), newver, strlen(newver)))))
                        {
                            logg ("^Your ClamAV installation is OUTDATED!\n");
                            logg ("^Local version: %s Recommended version: %s\n", vstr, newver);
                            logg ("DON'T PANIC! Read https://www.clamav.net/documents/upgrading-clamav\n");
                            outdated = 1;
                        }
                    }
                }
            }
        }

        if (!dnsreply)
        {
            logg ("^Invalid DNS reply. Falling back to HTTP mode.\n");
        }
    }
#endif /* HAVE_RESOLV_H */

    if ((opt = optget (opts, "LocalIPAddress"))->enabled)
        localip = opt->strarg;

    if (optget (opts, "HTTPProxyServer")->enabled
        || optget (opts, "PrivateMirror")->enabled)
        mirman_read ("mirrors.dat", &mdat, 0);
    else
        mirman_read ("mirrors.dat", &mdat, 1);

    memset (ipaddr, 0, sizeof (ipaddr));

    /* custom dbs */
    if ((opt = optget (opts, "DatabaseCustomURL"))->enabled)
    {
        while (opt)
        {
            if ((custret =
                 updatecustomdb (opt->strarg, &signo, opts, localip,
                                 logerr)) == 0)
                updated = 1;
            opt = opt->nextarg;
        }
    }

    if ((opt = optget (opts, "update-db"))->enabled)
    {
        const char *u_dnsreply;
        int u_extra;

        while (opt)
        {
            if (!strcmp (opt->strarg, "custom"))
            {
                if (!optget (opts, "DatabaseCustomURL")->enabled)
                {
                    logg ("!--update-db=custom requires DatabaseCustomURL\n");
                    custret = FCE_CONFIG;
                }
                free (dnsreply);
                free (newver);
                (void) mirman_write ("mirrors.dat", dbdir, &mdat);
                mirman_free (&mdat);
                cli_rmdirs (updtmpdir);
                return custret;
            }

            if (!strcmp (opt->strarg, "main")
                || !strcmp (opt->strarg, "daily")
                || !strcmp (opt->strarg, "safebrowsing")
                || !strcmp (opt->strarg, "bytecode"))
            {
                u_dnsreply = dnsreply;
                u_extra = 0;
            }
            else
            {
                u_dnsreply = NULL;
                u_extra = 1;
            }
            if ((ret =
                 updatedb (opt->strarg, hostname, ipaddr, &signo, opts,
                           u_dnsreply, localip, outdated, &mdat, logerr,
                           u_extra, attempt)) > 50)
            {
                if (dnsreply)
                    free (dnsreply);
                if (newver)
                    free (newver);
                (void) mirman_write ("mirrors.dat", dbdir, &mdat);
                mirman_free (&mdat);
                cli_rmdirs (updtmpdir);
                return ret;
            }
            else if (ret == 0)
                updated = 1;

            opt = opt->nextarg;
        }

    }
    else
    {
        if ((ret =
             updatedb ("main", hostname, ipaddr, &signo, opts, dnsreply,
                       localip, outdated, &mdat, logerr, 0, attempt)) > 50)
        {
            if (dnsreply)
                free (dnsreply);
            if (newver)
                free (newver);
            (void) mirman_write ("mirrors.dat", dbdir, &mdat);
            mirman_free (&mdat);
            cli_rmdirs (updtmpdir);
            return ret;
        }
        else if (ret == 0)
            updated = 1;

        /* if ipaddr[0] != 0 it will use it to connect to the web host */
        if ((ret =
             updatedb ("daily", hostname, ipaddr, &signo, opts, dnsreply,
                       localip, outdated, &mdat, logerr, 0, attempt)) > 50)
        {
            if (dnsreply)
                free (dnsreply);
            if (newver)
                free (newver);
            (void) mirman_write ("mirrors.dat", dbdir, &mdat);
            mirman_free (&mdat);
            cli_rmdirs (updtmpdir);
            return ret;
        }
        else if (ret == 0)
            updated = 1;

        if (!optget (opts, "SafeBrowsing")->enabled)
        {
            const char *safedb = NULL;

            if (!access ("safebrowsing.cvd", R_OK))
                safedb = "safebrowsing.cvd";
            else if (!access ("safebrowsing.cld", R_OK))
                safedb = "safebrowsing.cld";

            if (safedb)
            {
                if (unlink (safedb))
                    logg ("^SafeBrowsing is disabled but can't remove old %s\n", safedb);
                else
                    logg ("*%s removed\n", safedb);
            }
        }
        else if ((ret =
                  updatedb ("safebrowsing", hostname, ipaddr, &signo, opts,
                            dnsreply, localip, outdated, &mdat, logerr, 0,
                            attempt)) > 50)
        {
            if (dnsreply)
                free (dnsreply);
            if (newver)
                free (newver);
            (void) mirman_write ("mirrors.dat", dbdir, &mdat);
            mirman_free (&mdat);
            cli_rmdirs (updtmpdir);
            return ret;
        }
        else if (ret == 0)
            updated = 1;

        if (!optget (opts, "Bytecode")->enabled)
        {
            const char *dbname = NULL;

            if (!access ("bytecode.cvd", R_OK))
                dbname = "bytecode.cvd";
            else if (!access ("bytecode.cld", R_OK))
                dbname = "bytecode.cld";

            if (dbname)
            {
                if (unlink (dbname))
                    logg ("^Bytecode is disabled but can't remove old %s\n",
                          dbname);
                else
                    logg ("*%s removed\n", dbname);
            }
        }
        else if ((ret =
                  updatedb ("bytecode", hostname, ipaddr, &signo, opts,
                            dnsreply, localip, outdated, &mdat, logerr, 0,
                            attempt)) > 50)
        {
            if (dnsreply)
                free (dnsreply);
            if (newver)
                free (newver);
            (void) mirman_write ("mirrors.dat", dbdir, &mdat);
            mirman_free (&mdat);
            cli_rmdirs (updtmpdir);
            return ret;
        }
        else if (ret == 0)
            updated = 1;

        /* handle extra dbs */
        if ((opt = optget (opts, "ExtraDatabase"))->enabled)
        {
            while (opt)
            {
                if ((ret =
                     updatedb (opt->strarg, hostname, ipaddr, &signo, opts,
                               NULL, localip, outdated, &mdat, logerr, 1,
                               attempt)) > 50)
                {
                    if (dnsreply)
                        free (dnsreply);
                    if (newver)
                        free (newver);
                    (void) mirman_write ("mirrors.dat", dbdir, &mdat);
                    mirman_free (&mdat);
                    cli_rmdirs (updtmpdir);
                    return ret;
                }
                else if (ret == 0)
                    updated = 1;
                opt = opt->nextarg;
            }
        }
    }

    if (dnsreply)
        free (dnsreply);

    (void) mirman_write ("mirrors.dat", dbdir, &mdat);
    mirman_free (&mdat);

    cli_rmdirs (updtmpdir);

    if (updated && checkdbdir () < 0)
    {
        if (newver)
            free (newver);
        return FCE_BADCVD;
    }

    if (updated)
    {
        if (optget (opts, "HTTPProxyServer")->enabled || !ipaddr[0])
        {
            logg ("Database updated (%d signatures) from %s\n", signo,
                  hostname);
        }
        else
        {
            logg ("Database updated (%d signatures) from %s (IP: %s)\n",
                  signo, hostname, ipaddr);
        }

#ifdef BUILD_CLAMD
        if ((opt = optget (opts, "NotifyClamd"))->active)
            notify (opt->strarg);
#endif

        if ((opt = optget (opts, "OnUpdateExecute"))->enabled)
            execute ("OnUpdateExecute", opt->strarg, opts);
    }

    if (outdated)
    {
        if ((opt = optget (opts, "OnOutdatedExecute"))->enabled)
        {
            char *cmd = strdup (opt->strarg);

            if (!cmd)
            {
                free (newver);
                return FCE_MEM;
            }

            if ((pt = newver))
            {
                while (*pt)
                {
                    if (!strchr ("0123456789.", *pt))
                    {
                        logg ("!downloadmanager: OnOutdatedExecute: Incorrect version number string\n");
                        free (newver);
                        newver = NULL;
                        break;
                    }
                    pt++;
                }
            }

            if (newver && (pt = strstr (cmd, "%v")))
            {
                char *buffer =
                    (char *) malloc (strlen (cmd) + strlen (newver) + 10);

                if (!buffer)
                {
                    logg ("!downloadmanager: Can't allocate memory for buffer\n");
                    free (cmd);
                    if (newver)
                        free (newver);
                    return FCE_MEM;
                }

                *pt = 0;
                pt += 2;
                strcpy (buffer, cmd);
                strcat (buffer, newver);
                strcat (buffer, pt);
                free (cmd);
                cmd = strdup (buffer);
                free (buffer);
                if (!cmd)
                {
                    free (newver);
                    return FCE_MEM;
                }
            }

            if (newver)
                execute ("OnOutdatedExecute", cmd, opts);

            free (cmd);
        }
    }

    if (newver)
        free (newver);

    return updated ? 0 : FC_UPTODATE;
}
