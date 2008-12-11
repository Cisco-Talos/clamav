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

#include "dns.h"
#ifdef HAVE_RESOLV_H

#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <sys/types.h>

#include "shared/output.h"


#ifndef PACKETSZ
#define PACKETSZ 512
#endif

char *txtquery(const char *domain, unsigned int *ttl)
{
	unsigned char answer[PACKETSZ], *answend, *pt;
	char *txt, host[128];
	int len, type, qtype;
	unsigned int cttl, size, txtlen = 0;


    *ttl = 0;
    if(res_init() < 0) {
	logg("^res_init failed\n");
	return NULL;
    }

    logg("*Querying %s\n", domain);

    memset(answer, 0, PACKETSZ);
    qtype = T_TXT;
    if((len = res_query(domain, C_IN, qtype, answer, PACKETSZ)) < 0 || len > PACKETSZ) {
#ifdef FRESHCLAM_DNS_FIX
	/*  The DNS server in the SpeedTouch Alcatel 510 modem can't
	 *  handle a TXT-query, but it can resolve an ANY-query to a
	 *  TXT-record, so we try an ANY-query now.  The thing we try
	 *  to resolve normally only has a TXT-record anyway.  
	 */
	memset(answer, 0, PACKETSZ);
	qtype=T_ANY;
	if((len = res_query(domain, C_IN, qtype, answer, PACKETSZ)) < 0) {
	    logg("^Can't query %s\n", domain);
	    return NULL;
	}
#else
	logg("^Can't query %s\n", domain);
	return NULL;
#endif
    }

    answend = answer + len;
    pt = answer + sizeof(HEADER);

    if((len = dn_expand(answer, answend, pt, host, sizeof(host))) < 0) {
	logg("^dn_expand failed\n");
	return NULL;
    }

    pt += len;
    if(pt > answend-4) {
	logg("^Bad (too short) DNS reply\n");
	return NULL;
    }

    GETSHORT(type, pt);
    if(type != qtype) {
	logg("^Broken DNS reply.\n");
	return NULL;
    }

    pt += INT16SZ; /* class */
    size = 0;
    do { /* recurse through CNAME rr's */
	pt += size;
    	if((len = dn_expand(answer, answend, pt, host, sizeof(host))) < 0) {
	    logg("^second dn_expand failed\n");
	    return NULL;
	}
	pt += len;
	if(pt > answend-10) {
	    logg("^Bad (too short) DNS reply\n");
	    return NULL;
	}
	GETSHORT(type, pt);
	pt += INT16SZ; /* class */
	GETLONG(cttl, pt);
	GETSHORT(size, pt);
	if(pt + size < answer || pt + size > answend) {
	    logg("^DNS rr overflow\n");
	    return NULL;
	}
    } while(type == T_CNAME);

    if(type != T_TXT) {
	logg("^Not a TXT record\n");
	return NULL;
    }

    if(!size || (txtlen = *pt) >= size || !txtlen) {
	logg("^Broken TXT record (txtlen = %d, size = %d)\n", txtlen, size);
	return NULL;
    }

    if(!(txt = (char *) malloc(txtlen + 1)))
	return NULL;

    memcpy(txt, pt+1, txtlen);
    txt[txtlen] = 0;
    *ttl = cttl;

    return txt;
}

#elif defined(C_WINDOWS)

/*
 * Note: Needs to link with dnsapi.lib.  
 * The dll behind this library is available from Windows 2000 onward.
 * Written by Mark Pizzolato
 */
#include <winsock.h>
#include <string.h>
#include <windows.h>
#include <windns.h>
#include "shared/output.h"

char *txtquery(const char *domain, unsigned int *ttl)
{
	PDNS_RECORD pDnsRecord;
	char *txt = NULL;

    *ttl = 0;
    mprintf("*Querying %s\n", domain);

   if(DnsQuery_UTF8(domain, DNS_TYPE_TEXT, DNS_QUERY_TREAT_AS_FQDN, NULL, &pDnsRecord, NULL) != 0)
	return NULL;

    if((pDnsRecord->Data.TXT.dwStringCount > 0) && pDnsRecord->Data.TXT.pStringArray[0]) {
	txt = malloc(strlen(pDnsRecord->Data.TXT.pStringArray[0]) + 1);
	if(txt)
	    strcpy(txt, pDnsRecord->Data.TXT.pStringArray[0]);
	*ttl = pDnsRecord->dwTtl;
    }
    DnsRecordListFree(pDnsRecord, DnsFreeRecordList);

    return txt;
}

#else

char *txtquery(const char *domain, unsigned int *ttl)
{
    *ttl = 1;  /* ttl of 1 combined with a NULL return distinguishes a failed lookup from DNS queries not being available */
    return NULL;
}

#endif
