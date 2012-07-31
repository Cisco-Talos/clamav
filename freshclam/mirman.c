/*
 *  Copyright (C) 2007 Tomasz Kojm <tkojm@clamav.net>
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
#include <string.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>

#ifndef _WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include "mirman.h"

#include "libclamav/cltypes.h"
#include "libclamav/clamav.h"

#include "shared/output.h"

#ifndef HAVE_GETADDRINFO
#ifndef AF_INET6
#define AF_INET6    0xbeef      /* foo */
#endif
#endif

#define IGNORE_LONG	3 * 86400
#define IGNORE_SHORT	6 * 3600

void
mirman_free (struct mirdat *mdat)
{
    if (mdat && mdat->num)
    {
        free (mdat->mirtab);
        mdat->num = 0;
    }
}

int
mirman_read (const char *file, struct mirdat *mdat, uint8_t active)
{
    struct mirdat_ip mip;
    int fd, bread;


    memset (mdat, 0, sizeof (struct mirdat));

    if (!(mdat->active = active))
        return 0;

    if ((fd = open (file, O_RDONLY | O_BINARY)) == -1)
        return -1;

    while ((bread = read (fd, &mip, sizeof (mip))) == sizeof (mip))
    {
        mdat->mirtab =
            (struct mirdat_ip *) realloc (mdat->mirtab,
                                          (mdat->num + 1) * sizeof (mip));
        if (!mdat->mirtab)
        {
            logg ("!Can't allocate memory for mdat->mirtab\n");
            mirman_free (mdat);
            close (fd);
            return -1;
        }
        memcpy (&mdat->mirtab[mdat->num], &mip, sizeof (mip));
        mdat->num++;
    }

    close (fd);

    if (bread)
    {
        logg ("^Removing broken %s file.\n", file);
        unlink (file);
        mirman_free (mdat);
        return -1;
    }

    return 0;
}

int
mirman_check (uint32_t * ip, int af, struct mirdat *mdat,
              struct mirdat_ip **md)
{
    unsigned int i, flevel = cl_retflevel ();


    if (md)
        *md = NULL;

    if (!mdat->active)
        return 0;

    for (i = 0; i < mdat->num; i++)
    {

        if ((af == AF_INET && mdat->mirtab[i].ip4 == *ip)
            || (af == AF_INET6
                && !memcmp (mdat->mirtab[i].ip6, ip, 4 * sizeof (uint32_t))))
        {

            if (!mdat->mirtab[i].atime && !mdat->mirtab[i].ignore)
            {
                if (md)
                    *md = &mdat->mirtab[i];
                return 0;
            }

            if (mdat->dbflevel && (mdat->dbflevel > flevel)
                && (mdat->dbflevel - flevel > 3))
                if (time (NULL) - mdat->mirtab[i].atime <
                    (mdat->dbflevel - flevel) * 3600)
                    return 2;

            if (mdat->mirtab[i].ignore)
            {
                if (!mdat->mirtab[i].atime)
                    return 1;

                if (time (NULL) - mdat->mirtab[i].atime > IGNORE_LONG)
                {
                    mdat->mirtab[i].ignore = 0;
                    if (md)
                        *md = &mdat->mirtab[i];
                    return 0;
                }
                else
                {
                    if (mdat->mirtab[i].ignore == 2
                        && (time (NULL) - mdat->mirtab[i].atime >
                            IGNORE_SHORT))
                    {
                        if (md)
                            *md = &mdat->mirtab[i];
                        return 0;
                    }
                    return 1;
                }
            }

            if (md)
                *md = &mdat->mirtab[i];
            return 0;
        }
    }

    return 0;
}

static int
mirman_update_int (uint32_t * ip, int af, struct mirdat *mdat, uint8_t broken,
                   int succ, int fail)
{
    unsigned int i, found = 0;


    if (!mdat->active)
        return 0;

    for (i = 0; i < mdat->num; i++)
    {
        if ((af == AF_INET && mdat->mirtab[i].ip4 == *ip)
            || (af == AF_INET6
                && !memcmp (mdat->mirtab[i].ip6, ip, 4 * sizeof (uint32_t))))
        {
            found = 1;
            break;
        }
    }

    if (found)
    {
        mdat->mirtab[i].atime = 0;  /* will be updated in mirman_write() */
        if (succ || fail)
        {
            if ((int) mdat->mirtab[i].fail + fail < 0)
                mdat->mirtab[i].fail = 0;
            else
                mdat->mirtab[i].fail += fail;

            if ((int) mdat->mirtab[i].succ + succ < 0)
                mdat->mirtab[i].succ = 0;
            else
                mdat->mirtab[i].succ += succ;
        }
        else
        {
            if (broken)
                mdat->mirtab[i].fail++;
            else
                mdat->mirtab[i].succ++;

            if (broken == 2)
            {
                mdat->mirtab[i].ignore = 2;
            }
            else
            {
                /*
                 * If the total number of failures is less than 3 then never
                 * mark a permanent failure, in other case use the real status.
                 */
                if (mdat->mirtab[i].fail < 3)
                    mdat->mirtab[i].ignore = 0;
                else
                    mdat->mirtab[i].ignore = broken;
            }
        }
    }
    else
    {
        mdat->mirtab =
            (struct mirdat_ip *) realloc (mdat->mirtab,
                                          (mdat->num +
                                           1) * sizeof (struct mirdat_ip));
        if (!mdat->mirtab)
        {
            logg ("!Can't allocate memory for new element in mdat->mirtab\n");
            return -1;
        }
        if (af == AF_INET)
        {
            mdat->mirtab[mdat->num].ip4 = *ip;
        }
        else
        {
            mdat->mirtab[mdat->num].ip4 = 0;
            memcpy (mdat->mirtab[mdat->num].ip6, ip, 4 * sizeof (uint32_t));
        }
        mdat->mirtab[mdat->num].atime = 0;
        mdat->mirtab[mdat->num].succ = (succ > 0) ? succ : 0;
        mdat->mirtab[mdat->num].fail = (fail > 0) ? fail : 0;
        mdat->mirtab[mdat->num].ignore = (broken == 2) ? 2 : 0;
        memset (&mdat->mirtab[mdat->num].res, 0xff,
                sizeof (mdat->mirtab[mdat->num].res));
        if (!succ && !fail)
        {
            if (broken)
                mdat->mirtab[mdat->num].fail++;
            else
                mdat->mirtab[mdat->num].succ++;
        }
        mdat->num++;
    }

    return 0;
}

int
mirman_update (uint32_t * ip, int af, struct mirdat *mdat, uint8_t broken)
{
    return mirman_update_int (ip, af, mdat, broken, 0, 0);
}

int
mirman_update_sf (uint32_t * ip, int af, struct mirdat *mdat, int succ,
                  int fail)
{
    return mirman_update_int (ip, af, mdat, 0, succ, fail);
}

void
mirman_list (const struct mirdat *mdat)
{
    unsigned int i;
    time_t tm;
    char ip[46];


    for (i = 0; i < mdat->num; i++)
    {
        printf ("Mirror #%u\n", i + 1);
#ifdef HAVE_GETADDRINFO
        if (mdat->mirtab[i].ip4)
            printf ("IP: %s\n",
                    inet_ntop (AF_INET, &mdat->mirtab[i].ip4, ip,
                               sizeof (ip)));
        else
            printf ("IP: %s\n",
                    inet_ntop (AF_INET6, mdat->mirtab[i].ip6, ip,
                               sizeof (ip)));
#else
        if (mdat->mirtab[i].ip4)
            printf ("IP: %s\n",
                    inet_ntoa (*(struct in_addr *) &mdat->mirtab[i].ip4));
#endif
        printf ("Successes: %u\n", mdat->mirtab[i].succ);
        printf ("Failures: %u\n", mdat->mirtab[i].fail);
        tm = mdat->mirtab[i].atime;
        printf ("Last access: %s", ctime ((const time_t *) &tm));
        printf ("Ignore: %s\n", mdat->mirtab[i].ignore ? "Yes" : "No");
        if (i != mdat->num - 1)
            printf ("-------------------------------------\n");
    }
}

void
mirman_whitelist (struct mirdat *mdat, unsigned int mode)
{
    unsigned int i;

    logg ("*Whitelisting %s blacklisted mirrors\n",
          mode == 1 ? "all" : "short-term");
    for (i = 0; i < mdat->num; i++)
        if (mode == 1 || (mode == 2 && mdat->mirtab[i].ignore == 2))
            mdat->mirtab[i].ignore = 0;
}

int
mirman_write (const char *file, const char *dir, struct mirdat *mdat)
{
    int fd;
    unsigned int i;
    char path[512];

    snprintf (path, sizeof (path), "%s/%s", dir, file);
    path[sizeof (path) - 1] = 0;

    if (!mdat->num)
        return 0;

    if ((fd =
         open (path, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0600)) == -1)
    {
        logg ("!Can't open %s for writing\n", path);
        return -1;
    }

    for (i = 0; i < mdat->num; i++)
        if (!mdat->mirtab[i].atime)
            mdat->mirtab[i].atime = (uint32_t) time (NULL);

    if (write (fd, mdat->mirtab, mdat->num * sizeof (struct mirdat_ip)) == -1)
    {
        logg ("!Can't write to %s\n", path);
        close (fd);
        return -1;
    }

    close (fd);
    return 0;
}
