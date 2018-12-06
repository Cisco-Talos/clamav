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

#include "libclamav/clamav.h"

#include "shared/output.h"

#ifndef HAVE_GETADDRINFO
#ifndef AF_INET6
#define AF_INET6    0xbeef      /* foo */
#endif
#endif

#define IGNORE_SHORT    (3600)              /* 1 hour */
#define IGNORE_LONG     (6 * IGNORE_SHORT)  /* 6 hours */

void
mirman_free(struct mirdat *mdat)
{
    if (mdat && mdat->num)
    {
        free (mdat->mirtab);
        mdat->num = 0;
    }
}

fc_error_t mirman_read(const char *file, struct mirdat *mdat, uint8_t active)
{
    struct mirdat_ip mip;
    int fd, bread;

    memset (mdat, 0, sizeof(struct mirdat));

    if (!(mdat->active = active))
        return FC_SUCCESS;

    if ((fd = open (file, O_RDONLY | O_BINARY)) == -1)
        return FCE_OPEN;

    while ((bread = read (fd, &mip, sizeof(mip))) == sizeof(mip))
    {
        mdat->mirtab =
            (struct mirdat_ip *) realloc (mdat->mirtab,
                                          (mdat->num + 1) * sizeof(mip));
        if (!mdat->mirtab)
        {
            logg("!Can't allocate memory for mdat->mirtab\n");
            mirman_free (mdat);
            close (fd);
            return FCE_MEM;
        }
        memcpy (&mdat->mirtab[mdat->num], &mip, sizeof(mip));
        mdat->num++;
    }

    close (fd);

    if (bread)
    {
        logg("^Removing broken %s file.\n", file);
        unlink (file);
        mirman_free (mdat);
        return FCE_FILE;
    }

    return FC_SUCCESS;
}

fc_error_t mirman_check(uint32_t * ip, int af, struct mirdat *mdat,
                        struct mirdat_ip **md, mir_status_t *mirror_status)
{
    fc_error_t status = FC_SUCCESS;
    unsigned int i;
    unsigned int flevel = cl_retflevel ();

    if (NULL == md || NULL == mdat || NULL == ip) {
        logg("!mirman_check: Invalid arguments.\n");
        status = FCE_ARG;
        goto done;
    }

    *md = NULL;

    if (!mdat->active)
    {
        *mirror_status = MIRROR_OK;
        goto done;
    }

    for (i = 0; i < mdat->num; i++)
    {
        if ((af == AF_INET && mdat->mirtab[i].ip4 == *ip) ||
            ((af == AF_INET6) && (!memcmp (mdat->mirtab[i].ip6, ip, 4 * sizeof(uint32_t)))))
        {
            /*
             * Mirror found in mirror table.
             */

            if (mdat->dbflevel && (mdat->dbflevel > flevel) && (mdat->dbflevel - flevel > 3))
            {
                /* Functionality level of database is lower than
                 * level of the database we already have */
                if (difftime(time(NULL), mdat->mirtab[i].atime) < (mdat->dbflevel - flevel) * 3600)
                {
                    *mirror_status = MIRROR_IGNORE__OUTDATED_VERSION;
                    goto done;
                }
            }

            if ((mdat->mirtab[i].atime > 0) &&
                (IGNORE_NO != mdat->mirtab[i].ignore))
            {
                /*
                 * Found, but the ignore flag is set.
                 */
                if (difftime(time(NULL), mdat->mirtab[i].atime) > IGNORE_LONG)
                {
                    /* Long-Ignore timeout expired,
                     * the mirror can be attempted again */
                    mdat->mirtab[i].ignore = IGNORE_NO;
                }
                else if ((mdat->mirtab[i].ignore == IGNORE_SHORTTERM) &&
                        (difftime(time(NULL), mdat->mirtab[i].atime) > IGNORE_SHORT))
                {
                    /* Mirror was only set to Short-Term ignore...
                     * the Short-Ignore timeout expired,
                     * the mirror can be attempted again */
                    mdat->mirtab[i].ignore = IGNORE_NO;
                }
                else
                {
                    *mirror_status = MIRROR_IGNORE__PREV_ERRS;
                    goto done;
                }
            }

            /* Mirror found, and is ok to try. */
            *md = &mdat->mirtab[i];
            *mirror_status = MIRROR_OK;
            goto done;
        }
    }

    /* Mirror wasn't in mirror table. */
    *mirror_status = MIRROR_OK;

done:

    return status;
}

fc_error_t mirman_update(uint32_t * ip, int af, struct mirdat *mdat, fc_error_t error)
{
    fc_error_t status = FCE_ARG;
    unsigned int i = 0;
    struct mirdat_ip *mirror = NULL;

    if (!mdat->active) {
        /* Disable mirrors.dat management when using a proxy. */
        return FC_SUCCESS;
    }

    /*
     * Attempt to find the ip in the mirror table.
     */
    for (i = 0; i < mdat->num; i++)
    {
        if (((af == AF_INET) && (mdat->mirtab[i].ip4 == *ip)) ||
            ((af == AF_INET6) && (!memcmp(mdat->mirtab[i].ip6, ip, 4 * sizeof(uint32_t)))))
        {
            mirror = &mdat->mirtab[i];
            break;
        }
    }

    if (NULL == mirror)
    {
        /*
         * Allocate space in the mirror table for the new mirror IP
         */
        mdat->mirtab =
            (struct mirdat_ip *) realloc(mdat->mirtab,
                                        (mdat->num + 1) * sizeof(struct mirdat_ip));
        if (!mdat->mirtab)
        {
            logg("!Can't allocate memory for new element in mdat->mirtab\n");
            return FCE_MEM;
        }
        memset (&mdat->mirtab[mdat->num], 0, sizeof(struct mirdat_ip));
        if (af == AF_INET)
        {
            mdat->mirtab[mdat->num].ip4 = *ip;
        }
        else
        {
            mdat->mirtab[mdat->num].ip4 = 0;
            memcpy (mdat->mirtab[mdat->num].ip6, ip, 4 * sizeof(uint32_t));
        }
        mdat->mirtab[mdat->num].atime = 0;
        mdat->mirtab[mdat->num].succ = 0;
        mdat->mirtab[mdat->num].fail = 0;
        mdat->mirtab[mdat->num].ignore = 0;

        mirror = &mdat->mirtab[mdat->num];
        mdat->num++;
    }

    mirror->atime = 0;  /* will be updated in mirman_write() */

    if (FC_SUCCESS == error) {
        mirror->succ++;
        mirror->fail = 0;
    }
    else
    {
        mirror->succ = 0;
        mirror->fail++;
    }

    if (mirror->fail >= 6)
    {
        mirror->ignore = IGNORE_LONGTERM;
    }
    else if (mirror->fail >= 3)
    {
        mirror->ignore = IGNORE_SHORTTERM;
    }
    else
    {
        mirror->ignore = IGNORE_NO;
    }

    return FC_SUCCESS;
}

void mirman_list(const struct mirdat *mdat)
{
    unsigned int i;
    time_t tm;
    char ip[46];

    for (i = 0; i < mdat->num; i++)
    {
        printf("Mirror #%u\n", i + 1);
#ifdef HAVE_GETADDRINFO
        if (mdat->mirtab[i].ip4)
            printf("IP: %s\n",
                inet_ntop(AF_INET, &mdat->mirtab[i].ip4, ip, sizeof(ip)));
        else
            printf("IP: %s\n",
                inet_ntop(AF_INET6, mdat->mirtab[i].ip6, ip, sizeof(ip)));
#else
        if (mdat->mirtab[i].ip4)
            printf("IP: %s\n",
                inet_ntoa(*(struct in_addr *)&mdat->mirtab[i].ip4));
#endif
        printf("Successes: %u\n", mdat->mirtab[i].succ);
        printf("Failures: %u\n", mdat->mirtab[i].fail);
        tm = mdat->mirtab[i].atime;
        printf("Last access: %s", ctime((const time_t *) &tm));
        if (mdat->mirtab[i].ignore) {
            time_t ignore_expires = tm + ((mdat->mirtab[i].ignore == IGNORE_LONGTERM) ? IGNORE_LONG
                                                                                      : IGNORE_SHORT);
            double difference = difftime(ignore_expires, time(NULL));
            if (difference > 0) {
                uint32_t remaining = difference;
                uint32_t seconds, minutes, hours;
                seconds = remaining % 60;
                remaining = remaining / 60;
                minutes = remaining % 60;
                remaining = remaining / 60;
                hours = remaining % 60;

                printf("Ignore: Yes,  %d hours %d minutes %d seconds remaining.\n",
                    hours, minutes, seconds);
            } else {
                printf("Ignore: No\n");
            }
        } else {
            printf("Ignore: No\n");
        }
        if (i != mdat->num - 1)
            printf("-------------------------------------\n");
    }
}

void mirman_whitelist(struct mirdat *mdat, unsigned int mode)
{
    unsigned int i;

    if (NULL == mdat) {
        logg("!mirman_whitelist: Invalid arguments!\n");
        return;
    }

    switch (mode)
    {
    case 1:
        logg("*Whitelisting all blacklisted mirrors\n");
        break;
    case 2:
        logg("*Whitelisting short-term blacklisted mirrors\n");
        break;
    default:
        logg("!mirman_whitelist: Unexpected mode argument: %u\n", mode);
        return;
    }

    for (i = 0; i < mdat->num; i++)
    {
        if (mode == 1)
        {
            mdat->mirtab[i].ignore = IGNORE_NO;
        }
        else if ((mode == 2) && (IGNORE_SHORTTERM == mdat->mirtab[i].ignore))
        {
            mdat->mirtab[i].ignore = IGNORE_NO;
        }
    }

    return;
}

fc_error_t mirman_write(const char *file, const char *dir, struct mirdat *mdat)
{
    int fd;
    unsigned int i;
    char path[512];

    snprintf(path, sizeof(path), "%s/%s", dir, file);
    path[sizeof(path) - 1] = 0;

    if (!mdat->num)
        return FC_SUCCESS;

    if ((fd =
         open(path, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0600)) == -1)
    {
        logg("!Can't open %s for writing\n", path);
        return FCE_OPEN;
    }

    for (i = 0; i < mdat->num; i++)
        if (!mdat->mirtab[i].atime)
            mdat->mirtab[i].atime = (uint32_t) time(NULL);

    if (write(fd, mdat->mirtab, mdat->num * sizeof(struct mirdat_ip)) == -1)
    {
        logg("!Can't write to %s\n", path);
        close(fd);
        return FCE_FILE;
    }

    close(fd);
    return FC_SUCCESS;
}
