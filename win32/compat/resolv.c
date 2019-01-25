/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2009-2013 Sourcefire, Inc.
 *
 *  Authors: aCaB <acab@clamav.net>
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

/* a fake libresolv-like res_query interface */

#include "resolv.h"

int res_init(void) {
    return 0;
}

int res_query(const char *dname, int class, int type, unsigned char *answer, int anslen) {
    DNS_RECORD *rrs, *rr;
    DNS_STATUS s;
    HEADER *h = (HEADER *)answer;
    int ret = -1;

    if(anslen <= sizeof(HEADER))
	return -1;

    s = DnsQuery(dname, (WORD)type, DNS_QUERY_BYPASS_CACHE | DNS_QUERY_NO_HOSTS_FILE | DNS_QUERY_DONT_RESET_TTL_VALUES, NULL, &rrs, NULL);
    if(s)
	return -1;

    /* We don't use the header data */
    h->id = 1;
    answer += sizeof(HEADER);
    anslen -= sizeof(HEADER);

    rr = rrs;
    do {
	if(rr->wType == (WORD)type && rr->wDataLength > sizeof(DWORD) && rr->Data.TXT.dwStringCount && rr->Data.TXT.pStringArray[0]) {
	    unsigned int len = strlen(dname), txtlen = strlen(rr->Data.TXT.pStringArray[0]);
	    if(txtlen > 255) continue;
	    len++;
	    if(len*2 + txtlen + 15 > anslen) break;
	    memcpy(answer, dname, len);
	    answer += len;
	    answer[0] = type >> 8; /* type */
	    answer[1] = type;
	    answer[2] = class >> 8; /* class */
	    answer[3] = class & 0xff;
	    answer += 4;
	    memcpy(answer, dname, len);
	    answer += len;
	    answer[0] = type >> 8; /* type */
	    answer[1] = type;
	    answer[2] = class >> 8; /* class */
	    answer[3] = class & 0xff;
	    answer[4] = rr->dwTtl >> 24;
	    answer[5] = rr->dwTtl >> 16;
	    answer[6] = rr->dwTtl >> 8;
	    answer[7] = rr->dwTtl;
	    answer[8] = (txtlen+1) >> 8; /* rdata len */
	    answer[9] = txtlen+1;
	    answer[10] = txtlen;
	    memcpy(&answer[11], rr->Data.TXT.pStringArray[0], txtlen);
	    ret = len*2 + txtlen + 15 + sizeof(HEADER);
	    break;
	}
    } while ((rr = rr->pNext));

    DnsRecordListFree(rrs, DnsFreeRecordList);
    return ret;
}

int dn_expand(unsigned char *msg, unsigned char *eomorig, unsigned char *comp_dn, char *exp_dn, int length) {
    int len, maxlen;

    /* names are simple C strings, not compressed not len encoded */
    if(comp_dn < msg || comp_dn >= eomorig)
	return -1;
    maxlen = eomorig - comp_dn;
    len = strnlen(comp_dn, maxlen) + 1;
    if(len > maxlen || len > length)
	return -1;
    memcpy(exp_dn, msg, len);
    return len;
}

