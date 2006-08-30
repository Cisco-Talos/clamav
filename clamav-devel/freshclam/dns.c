/*
 *  Copyright (C) 2004 Tomasz Kojm <tkojm@clamav.net>
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

#ifdef HAVE_RESOLV_H

#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <sys/types.h>

#include "shared/memory.h"
#include "shared/output.h"

#include "dns.h"

#ifndef PACKETSZ
#define PACKETSZ 512
#endif

char *txtquery(const char *domain, unsigned int *ttl)
{
	unsigned char answer[PACKETSZ], host[128], *pt, *txt;
	int len, exp, cttl, size, txtlen, type;


    if(res_init() < 0) {
	logg("^res_init failed\n");
	return NULL;
    }

    logg("*Querying %s\n", domain);

    memset(answer, 0, PACKETSZ);
    if((len = res_query(domain, C_IN, T_TXT, answer, PACKETSZ)) < 0) {
	logg("^Can't query %s\n", domain);
	return NULL;
    }

    pt = answer + sizeof(HEADER);

    if((exp = dn_expand(answer, answer + len, pt, host, sizeof(host))) < 0) {
	logg("^dn_expand failed\n");
	return NULL;
    }

    pt += exp;

    GETSHORT(type, pt);
    if(type != T_TXT) {
	logg("^Broken DNS reply.\n");
	return NULL;
    }

    pt += INT16SZ; /* class */

    if((exp = dn_expand(answer, answer + len, pt, host, sizeof(host))) < 0) {
	logg("^second dn_expand failed\n");
	return NULL;
    }

    pt += exp;
    GETSHORT(type, pt);
    if(type != T_TXT) {
	logg("^Not a TXT record\n");
	return NULL;
    }

    pt += INT16SZ; /* class */
    GETLONG(cttl, pt);
    *ttl = cttl;
    GETSHORT(size, pt);
    txtlen = *pt;

    if(txtlen >= size || !txtlen) {
	logg("^Broken TXT record (txtlen = %d, size = %d)\n", txtlen, size);
	return NULL;
    }

    if(!(txt = mmalloc(txtlen + 1)))
	return NULL;

    pt++;
    strncpy(txt, pt, txtlen);
    txt[txtlen] = 0;

    return txt;
}

#else

char *txtquery(const char *domain, unsigned int *ttl)
{
    return NULL;
}

#endif
