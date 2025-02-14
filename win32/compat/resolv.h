/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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

#ifndef __RESOLV_H
#define __RESOLV_H

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <Windns.h>
#include "clamav-types.h"

#define C_IN 1

#define T_A DNS_TYPE_A
#define T_NS DNS_TYPE_NS
#define T_MD DNS_TYPE_MD
#define T_MF DNS_TYPE_MF
#define T_CNAME DNS_TYPE_CNAME
#define T_SOA DNS_TYPE_SOA 0
#define T_MB DNS_TYPE_MB
#define T_MG DNS_TYPE_MG
#define T_MR DNS_TYPE_MR
#define T_NULL DNS_TYPE_NULL
#define T_WKS DNS_TYPE_WKS
#define T_PTR DNS_TYPE_PTR
#define T_HINFO DNS_TYPE_HINFO
#define T_MINFO DNS_TYPE_MINFO
#define T_MX DNS_TYPE_MX
#define T_TXT DNS_TYPE_TEXT
#define T_RP DNS_TYPE_RP
#define T_AFSDB DNS_TYPE_AFSDB
#define T_X25 DNS_TYPE_X25
#define T_ISDN DNS_TYPE_ISDN
#define T_RT DNS_TYPE_RT
#define T_NSAP DNS_TYPE_NSAP
#define T_NSAP_PTR DNS_TYPE_NSAPPTR
#define T_SIG DNS_TYPE_SIG
#define T_KEY DNS_TYPE_KEY
#define T_PX DNS_TYPE_PX
#define T_GPOS DNS_TYPE_GPOS
#define T_AAAA DNS_TYPE_AAAA
#define T_LOC DNS_TYPE_LOC
#define T_NXT DNS_TYPE_NXT
#define T_EID DNS_TYPE_EID
#define T_NIMLOC DNS_TYPE_NIMLOC
#define T_SRV DNS_TYPE_SRV
#define T_ATMA DNS_TYPE_ATMA
#define T_NAPTR DNS_TYPE_NAPTR
#define T_KX DNS_TYPE_KX
#define T_CERT DNS_TYPE_CERT
#define T_A6 DNS_TYPE_A6
#define T_DNAME DNS_TYPE_DNAME
#define T_SINK DNS_TYPE_SINK
#define T_OPT DNS_TYPE_OPT
#define T_DS DNS_TYPE_DS
#define T_RRSIG DNS_TYPE_RRSIG
#define T_NSEC DNS_TYPE_NSEC
#define T_DNSKEY DNS_TYPE_DNSKEY
#define T_DHCID DNS_TYPE_DHCID
#define T_UINFO DNS_TYPE_UINFO
#define T_UID DNS_TYPE_UID
#define T_GID DNS_TYPE_GID
#define T_UNSPEC DNS_TYPE_UNSPEC
#define T_ADDRS DNS_TYPE_ADDRS
#define T_TKEY DNS_TYPE_TKEY
#define T_TSIG DNS_TYPE_TSIG
#define T_IXFR DNS_TYPE_IXFR
#define T_AXFR DNS_TYPE_AXFR
#define T_MAILB DNS_TYPE_MAILB
#define T_MAILA DNS_TYPE_MAILA
#define T_ALL DNS_TYPE_ALL
#define T_ANY DNS_TYPE_ANY
#define T_WINS DNS_TYPE_WINS
#define T_WINSR DNS_TYPE_WINSR
#define T_NBSTAT DNS_TYPE_NBSTAT

#ifndef DNS_QUERY_NO_HOSTS_FILE
#define DNS_QUERY_NO_HOSTS_FILE 0
#endif

typedef struct {
    unsigned short id; /* fake stuff */
} HEADER;

#define INT16SZ 2

#define GETSHORT(var, ptr)                          \
    do {                                            \
        var = ((uint16_t)(*(uint8_t *)ptr++)) << 8; \
        var |= *(uint8_t *)ptr++;                   \
    } while (0)

#define GETLONG(var, ptr)                            \
    do {                                             \
        var = ((uint32_t)(*(uint8_t *)ptr++)) << 24; \
        var = ((uint32_t)(*(uint8_t *)ptr++)) << 16; \
        var = ((uint32_t)(*(uint8_t *)ptr++)) << 8;  \
        var |= *(uint8_t *)ptr++;                    \
    } while (0)

int res_init(void);
int res_query(const char *dname, int class, int type, unsigned char *answer, int anslen);
int dn_expand(unsigned char *msg, unsigned char *eomorig, unsigned char *comp_dn, char *exp_dn, int length);

#endif
