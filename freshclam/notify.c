/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2002-2013 Sourcefire, Inc.
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

#ifdef BUILD_CLAMD

#include <stdio.h>
#ifdef	HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/types.h>
#ifndef	_WIN32
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif
#include <string.h>
#include <errno.h>

#include "shared/optparser.h"
#include "shared/output.h"
#include "shared/clamdcom.h"

#include "notify.h"

int
clamd_connect (const char *cfgfile, const char *option)
{
#ifndef	_WIN32
    struct sockaddr_un server;
#endif

    struct addrinfo hints, *res, *p;
    char port[6];
    int ret;

    struct optstruct *opts;
    const struct optstruct *opt;
    int sockd;


    if ((opts = optparse (cfgfile, 0, NULL, 1, OPT_CLAMD, 0, NULL)) == NULL)
    {
        logg ("!%s: Can't find or parse configuration file %s\n", option,
              cfgfile);
        return -11;
    }

#ifndef	_WIN32
    if ((opt = optget (opts, "LocalSocket"))->enabled)
    {
        memset(&server, 0x00, sizeof(server));
        server.sun_family = AF_UNIX;
        strncpy (server.sun_path, opt->strarg, sizeof (server.sun_path));
        server.sun_path[sizeof (server.sun_path) - 1] = '\0';

        if ((sockd = socket (AF_UNIX, SOCK_STREAM, 0)) < 0)
        {
            logg ("^Clamd was NOT notified: Can't create socket endpoint for %s: %s\n",
                opt->strarg, strerror(errno));
            optfree (opts);
            return -1;
        }

        if (connect
            (sockd, (struct sockaddr *) &server,
             sizeof (struct sockaddr_un)) < 0)
        {
            logg ("^Clamd was NOT notified: Can't connect to clamd through %s: %s\n",
                opt->strarg, strerror(errno));
            closesocket (sockd);
            optfree (opts);
            return -11;
        }

        return sockd;

    }
    else
#endif
    if ((opt = optget (opts, "TCPSocket"))->enabled)
    {
        memset (&hints, 0, sizeof (hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_PASSIVE;

        snprintf (port, sizeof (port), "%u", (unsigned int) opt->numarg);
        port[5] = 0;

        opt = optget(opts, "TCPAddr");
        while (opt) {
            ret = getaddrinfo (opt->strarg, port, &hints, &res);

            if (ret)
            {
                logg ("!%s: Can't resolve hostname %s (%s)\n", option,
                      opt->strarg ? opt->strarg : "",
                      (ret ==
                       EAI_SYSTEM) ? strerror (errno) : gai_strerror (ret));
                opt = opt->nextarg;
                continue;
            }

            for (p = res; p != NULL; p = p->ai_next) {
                if ((sockd = socket (p->ai_family, p->ai_socktype, p->ai_protocol)) < 0)
                {
                    logg ("!%s: Can't create TCP socket to connect to %s: %s\n",
                          option, opt->strarg ? opt->strarg : "localhost", strerror(errno));
                    continue;
                }

                if (connect (sockd, p->ai_addr, p->ai_addrlen) == -1)
                {
                    logg ("!%s: Can't connect to clamd on %s:%s: %s\n", option,
                          opt->strarg ? opt->strarg : "localhost", port, strerror(errno));
                    closesocket (sockd);
                    continue;
                }

                optfree(opts);
                freeaddrinfo(res);

                return sockd;
            }

            freeaddrinfo (res);
            opt = opt->nextarg;
        }
    }
    else
    {
        logg ("!%s: No communication socket specified in %s\n", option,
              cfgfile);
        optfree (opts);
        return 1;
    }

    optfree (opts);
    return -1;
}

int
notify (const char *cfgfile)
{
    char buff[20];
    int sockd, bread;

    if ((sockd = clamd_connect (cfgfile, "NotifyClamd")) < 0)
        return 1;

    if (sendln (sockd, "RELOAD", 7) < 0)
    {
        logg ("!NotifyClamd: Could not write to clamd socket: %s\n", strerror(errno));
        closesocket (sockd);
        return 1;
    }

    memset (buff, 0, sizeof (buff));
    if ((bread = recv (sockd, buff, sizeof (buff), 0)) > 0)
    {
        if (!strstr (buff, "RELOADING"))
        {
            logg ("!NotifyClamd: Unknown answer from clamd: '%s'\n", buff);
            closesocket (sockd);
            return -1;
        }
    }

    closesocket (sockd);
    logg ("Clamd successfully notified about the update.\n");
    return 0;
}
#endif
