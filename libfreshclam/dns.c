/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *  Copyright (C) 2004-2007 Tomasz Kojm <tkojm@clamav.net>2004 Tomasz Kojm <tkojm@clamav.net>
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

#include <stdio.h>

#include "dns.h"
#ifdef HAVE_RESOLV_H

#include <string.h>
#include <sys/types.h>
#ifndef _WIN32
#include <netinet/in.h>
#include <arpa/nameser.h>
#endif
#include <resolv.h>

#include "output.h"

#ifndef PACKETSZ
#define PACKETSZ 512
#endif

char *
dnsquery(const char *domain, int qtype, unsigned int *ttl)
{
    unsigned char answer[PACKETSZ], *answend, *pt;
    char *txt, host[128];
    int len, type;
    unsigned int cttl, size, txtlen = 0;

    if (ttl)
        *ttl = 0;
    if (res_init() < 0) {
        logg(LOGG_WARNING, "res_init failed\n");
        return NULL;
    }

    logg(LOGG_DEBUG, "Querying %s\n", domain);

    memset(answer, 0, PACKETSZ);
    if ((len = res_query(domain, C_IN, qtype, answer, PACKETSZ)) < 0 || len > PACKETSZ) {
#ifdef FRESHCLAM_DNS_FIX
        /*  The DNS server in the SpeedTouch Alcatel 510 modem can't
         *  handle a TXT-query, but it can resolve an ANY-query to a
         *  TXT-record, so we try an ANY-query now.  The thing we try
         *  to resolve normally only has a TXT-record anyway.
         */
        memset(answer, 0, PACKETSZ);
        if (qtype == T_TXT)
            qtype = T_ANY;
        if ((len = res_query(domain, C_IN, qtype, answer, PACKETSZ)) < 0) {
            logg((qtype == T_TXT || qtype == T_ANY) ? LOGG_WARNING : LOGG_DEBUG, "Can't query %s\n",
                 domain);
            return NULL;
        }
#else
        logg((qtype == T_TXT) ? LOGG_WARNING : LOGG_DEBUG, "Can't query %s\n", domain);
        return NULL;
#endif
    }
    if (qtype != T_TXT && qtype != T_ANY) {
        if (ttl)
            *ttl = 2;
        return NULL;
    }

    answend = answer + len;
    pt      = answer + sizeof(HEADER);

    if ((len = dn_expand(answer, answend, pt, host, sizeof(host))) < 0) {
        logg(LOGG_WARNING, "dn_expand failed\n");
        return NULL;
    }

    pt += len;
    if (pt > answend - 4) {
        logg(LOGG_WARNING, "Bad (too short) DNS reply\n");
        return NULL;
    }

    GETSHORT(type, pt);
    if (type != qtype) {
        logg(LOGG_WARNING, "Broken DNS reply.\n");
        return NULL;
    }

    pt += INT16SZ; /* class */
    size = 0;
    do { /* recurse through CNAME rr's */
        pt += size;
        if ((len = dn_expand(answer, answend, pt, host, sizeof(host))) < 0) {
            logg(LOGG_WARNING, "second dn_expand failed\n");
            return NULL;
        }
        pt += len;
        if (pt > answend - 10) {
            logg(LOGG_WARNING, "Bad (too short) DNS reply\n");
            return NULL;
        }
        GETSHORT(type, pt);
        pt += INT16SZ; /* class */
        GETLONG(cttl, pt);
        GETSHORT(size, pt);
        if (pt + size < answer || pt + size > answend) {
            logg(LOGG_WARNING, "DNS rr overflow\n");
            return NULL;
        }
    } while (type == T_CNAME);

    if (type != T_TXT) {
        logg(LOGG_WARNING, "Not a TXT record\n");
        return NULL;
    }

    if (!size || (txtlen = *pt) >= size || !txtlen) {
        logg(LOGG_WARNING, "Broken TXT record (txtlen = %d, size = %d)\n", txtlen, size);
        return NULL;
    }

    if (!(txt = (char *)malloc(txtlen + 1)))
        return NULL;

    memcpy(txt, pt + 1, txtlen);
    txt[txtlen] = 0;
    if (ttl)
        *ttl = cttl;

    return txt;
}

#else

char *
dnsquery(const char *domain, int qtype, unsigned int *ttl)
{
    if (ttl)
        *ttl = 1; /* ttl of 1 combined with a NULL return distinguishes a failed lookup from DNS queries not being available */
    return NULL;
}

#endif
