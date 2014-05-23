/*
 *  Copyright (C) 2011 Sourcefire, Inc.
 *
 *  Authors: aCaB
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

#include <time.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include "libclamav/crypto.h"

#include "asn1.h"
#include "bignum.h"
#include "matcher-hash.h"

/* --------------------------------------------------------------------------- OIDS */
#define OID_1_3_14_3_2_26 "\x2b\x0e\x03\x02\x1a"
#define OID_sha1 OID_1_3_14_3_2_26

#define OID_1_3_14_3_2_29 "\x2b\x0e\x03\x02\x1d"
#define OID_sha1WithRSA OID_1_3_14_3_2_29

#define OID_1_2_840_113549_1_1_1 "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01"
#define OID_rsaEncryption OID_1_2_840_113549_1_1_1

#define OID_1_2_840_113549_1_1_2 "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x02"
#define OID_md2WithRSAEncryption OID_1_2_840_113549_1_1_2

#define OID_1_2_840_113549_1_1_4 "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x04"
#define OID_md5WithRSAEncryption OID_1_2_840_113549_1_1_4

#define OID_1_2_840_113549_1_1_5 "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x05"
#define OID_sha1WithRSAEncryption OID_1_2_840_113549_1_1_5

#define OID_1_2_840_113549_1_1_11 "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b"
#define OID_sha256WithRSAEncryption OID_1_2_840_113549_1_1_11

#define OID_1_2_840_113549_1_1_13 "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0d"
#define OID_sha512WithRSAEncryption OID_1_2_840_113549_1_1_13

#define OID_1_2_840_113549_1_7_1 "\x2a\x86\x48\x86\xf7\x0d\x01\x07\x01"
#define OID_pkcs7_data OID_1_2_840_113549_1_7_1

#define OID_1_2_840_113549_1_7_2 "\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02"
#define OID_signedData OID_1_2_840_113549_1_7_2

#define OID_1_2_840_113549_1_9_3 "\x2a\x86\x48\x86\xf7\x0d\x01\x09\x03"
#define OID_contentType OID_1_2_840_113549_1_9_3

#define OID_1_2_840_113549_1_9_4 "\x2a\x86\x48\x86\xf7\x0d\x01\x09\x04"
#define OID_messageDigest OID_1_2_840_113549_1_9_4

#define OID_1_2_840_113549_1_9_5 "\x2a\x86\x48\x86\xf7\x0d\x01\x09\x05"
#define OID_signingTime OID_1_2_840_113549_1_9_5

#define OID_1_2_840_113549_2_5 "\x2a\x86\x48\x86\xf7\x0d\x02\x05"
#define OID_md5 OID_1_2_840_113549_2_5

#define OID_1_2_840_113549_1_9_6 "\x2a\x86\x48\x86\xf7\x0d\x01\x09\x06"
#define OID_countersignature OID_1_2_840_113549_1_9_6


#define OID_1_3_6_1_4_1_311_2_1_4 "\x2b\x06\x01\x04\x01\x82\x37\x02\x01\x04"
#define OID_SPC_INDIRECT_DATA_OBJID OID_1_3_6_1_4_1_311_2_1_4

#define OID_1_3_6_1_4_1_311_2_1_15 "\x2b\x06\x01\x04\x01\x82\x37\x02\x01\x0f"
#define OID_SPC_PE_IMAGE_DATA_OBJID OID_1_3_6_1_4_1_311_2_1_15

#define OID_1_3_6_1_4_1_311_2_1_25 "\x2b\x06\x01\x04\x01\x82\x37\x02\x01\x19"
#define OID_SPC_CAB_DATA_OBJID OID_1_3_6_1_4_1_311_2_1_25

#define OID_1_3_6_1_4_1_311_10_1 "\x2b\x06\x01\x04\x01\x82\x37\x0a\x01"
#define OID_szOID_CTL OID_1_3_6_1_4_1_311_10_1

#define OID_1_3_6_1_4_1_311_12_1_1 "\x2b\x06\x01\x04\x01\x82\x37\x0c\x01\x01"
#define OID_szOID_CATALOG_LIST OID_1_3_6_1_4_1_311_12_1_1

#define OID_1_3_6_1_4_1_311_12_1_2 "\x2b\x06\x01\x04\x01\x82\x37\x0c\x01\x02"
#define OID_szOID_CATALOG_LIST_MEMBER OID_1_3_6_1_4_1_311_12_1_2

#define lenof(x) (sizeof((x))-1)
/* --------------------------------------------------------------------------- OIDS */

struct cli_asn1 {
    uint8_t type;
    unsigned int size;
    const void *content;
    const void *next;
};

static int map_sha1(fmap_t *map, const void *data, unsigned int len, uint8_t sha1[SHA1_HASH_SIZE]) {
    if(!fmap_need_ptr_once(map, data, len)) {
	cli_dbgmsg("map_sha1: failed to read hash data\n");
	return 1;
    }
    return (cl_sha1(data, len, sha1, NULL) == NULL);
}

static int map_md5(fmap_t *map, const void *data, unsigned int len, uint8_t *md5) {
    if(!fmap_need_ptr_once(map, data, len)) {
	cli_dbgmsg("map_md5: failed to read hash data\n");
	return 1;
    }
    return (cl_hash_data("md5", data, len, md5, NULL) == NULL);
}


static int asn1_get_obj(fmap_t *map, const void *asn1data, unsigned int *asn1len, struct cli_asn1 *obj) {
    unsigned int asn1_sz = *asn1len;
    unsigned int readbytes = MIN(6, asn1_sz), i;
    const uint8_t *data;

    if(asn1_sz < 2) {
	cli_dbgmsg("asn1_get_obj: insufficient data length\n");
	return 1;
    }
    data = fmap_need_ptr_once(map, asn1data, readbytes);
    if(!data) {
	cli_dbgmsg("asn1_get_obj: obj out of file\n");
	return 1;
    }

    obj->type = data[0];
    i = data[1];
    data+=2;
    if(i & 0x80) {
	if(i == 0x80) {
	    /* Not allowed in DER */
	    cli_dbgmsg("asn1_get_obj: unsupported indefinite length object\n");
	    return 1;
	}
	i &= ~0x80;
	if(i > readbytes - 2) {
	    cli_dbgmsg("asn1_get_obj: len octets overflow (or just too many)\n");
	    return 1;
	}
	obj->size = 0;
	while(i--) {
	    obj->size <<= 8;
	    obj->size |= *data;
	    data ++;
	}
    } else
	obj->size = i;

    asn1_sz -= data - (uint8_t *)asn1data;
    if(obj->size > asn1_sz) {
	cli_dbgmsg("asn1_get_obj: content overflow\n");
	return 1;
    }

    obj->content = data;
    if(obj->size == asn1_sz)
	obj->next = NULL;
    else
	obj->next = data + obj->size;
    *asn1len = asn1_sz - obj->size;
    return 0;
}

static int asn1_expect_objtype(fmap_t *map, const void *asn1data, unsigned int *asn1len, struct cli_asn1 *obj, uint8_t type) {
    int ret = asn1_get_obj(map, asn1data, asn1len, obj);
    if(ret)
	return ret;
    if(obj->type != type) {
	cli_dbgmsg("asn1_expect_objtype: expected type %02x, got %02x\n", type, obj->type);
	return 1;
    }
    return 0;
}

static int asn1_expect_obj(fmap_t *map, const void **asn1data, unsigned int *asn1len, uint8_t type, unsigned int size, const void *content) {
    struct cli_asn1 obj;
    int ret = asn1_expect_objtype(map, *asn1data, asn1len, &obj, type);
    if(ret)
	return ret;
    if(obj.size != size) {
	cli_dbgmsg("asn1_expect_obj: expected size %u, got %u\n", size, obj.size);
	return 1;
    }
    if(size) {
	if(!fmap_need_ptr_once(map, obj.content, size)) {
	    cli_dbgmsg("asn1_expect_obj: failed to read content\n");
	    return 1;
	}
	if(memcmp(obj.content, content, size)) {
	    cli_dbgmsg("asn1_expect_obj: content mismatch\n");
	    return 1;
	}
    }
    *asn1data = obj.next;
    return 0;
}

static int asn1_expect_algo(fmap_t *map, const void **asn1data, unsigned int *asn1len, unsigned int algo_size, const void *algo) {
    struct cli_asn1 obj;
    unsigned int avail;
    int ret;
    if((ret = asn1_expect_objtype(map, *asn1data, asn1len, &obj, 0x30))) /* SEQUENCE */
	return ret;
    avail = obj.size;
    *asn1data = obj.next;

    if((ret = asn1_expect_obj(map, &obj.content, &avail, 0x06, algo_size, algo))) /* ALGO */
	return ret;
    if(avail && (ret = asn1_expect_obj(map, &obj.content, &avail, 0x05, 0, NULL))) /* NULL */
	return ret;
    if(avail) {
	cli_dbgmsg("asn1_expect_algo: extra data found in SEQUENCE\n");
	return 1;
    }
    return 0;
}


static int asn1_expect_rsa(fmap_t *map, const void **asn1data, unsigned int *asn1len, cli_crt_hashtype *hashtype) {
    struct cli_asn1 obj;
    unsigned int avail;
    int ret;
    if((ret = asn1_expect_objtype(map, *asn1data, asn1len, &obj, 0x30))) /* SEQUENCE */
	return ret;
    avail = obj.size;
    *asn1data = obj.next;

    if(asn1_expect_objtype(map, obj.content, &avail, &obj, 0x06))
	return 1;
    if(obj.size != lenof(OID_sha1WithRSA) && obj.size != lenof(OID_sha1WithRSAEncryption)) { /* lenof(OID_sha1WithRSAEncryption) = lenof(OID_md5WithRSAEncryption) = 9 */
	cli_dbgmsg("asn1_expect_rsa: expecting OID with size 5 or 9, got %02x with size %u\n", obj.type, obj.size);
	return 1;
    }
    if(!fmap_need_ptr_once(map, obj.content, obj.size)) {
	cli_dbgmsg("asn1_expect_rsa: failed to read OID\n");
	return 1;
    }
    if(obj.size == lenof(OID_sha1WithRSA) && !memcmp(obj.content, OID_sha1WithRSA, lenof(OID_sha1WithRSA)))
	*hashtype = CLI_SHA1RSA; /* Obsolete sha1rsa 1.3.14.3.2.29 */
    else if(obj.size == lenof(OID_sha1WithRSAEncryption) && !memcmp(obj.content, OID_sha1WithRSAEncryption, lenof(OID_sha1WithRSAEncryption)))
	*hashtype = CLI_SHA1RSA; /* sha1withRSAEncryption 1.2.840.113549.1.1.5 */
    else if(obj.size == lenof(OID_md5WithRSAEncryption) && !memcmp(obj.content, OID_md5WithRSAEncryption, lenof(OID_md5WithRSAEncryption)))
	*hashtype = CLI_MD5RSA; /* md5withRSAEncryption 1.2.840.113549.1.1.4 */
    else if(obj.size == lenof(OID_md2WithRSAEncryption) && !memcmp(obj.content, OID_md2WithRSAEncryption, lenof(OID_md2WithRSAEncryption))) {
	cli_dbgmsg("asn1_expect_rsa: MD2 with RSA (not yet supported)\n");
	return 1;
    }
    else if(obj.size == lenof(OID_sha256WithRSAEncryption) && !memcmp(obj.content, OID_sha256WithRSAEncryption, lenof(OID_sha256WithRSAEncryption))) {
	cli_dbgmsg("asn1_expect_rsa: SHA256 with RSA (not yet supported)\n");
	return 1;
    }
    else if(obj.size == lenof(OID_sha512WithRSAEncryption) && !memcmp(obj.content, OID_sha512WithRSAEncryption, lenof(OID_sha512WithRSAEncryption))) {
	cli_dbgmsg("asn1_expect_rsa: SHA512 with RSA (not yet supported)\n");
	return 1;
    }
    else {
	cli_dbgmsg("asn1_expect_rsa: OID mismatch (size %u)\n", obj.size);
	return 1;
    }
    if((ret = asn1_expect_obj(map, &obj.next, &avail, 0x05, 0, NULL))) /* NULL */
	return ret;
    if(avail) {
	cli_dbgmsg("asn1_expect_rsa: extra data found in SEQUENCE\n");
	return 1;
    }
    return 0;
}

static int asn1_getnum(const char *s) {
    if(s[0] < '0' || s[0] >'9' || s[1] < '0' || s[1] > '9') {
	cli_dbgmsg("asn1_getnum: expecting digits, found '%c%c'\n", s[0], s[1]);
	return -1;
    }
    return (s[0] - '0')*10 + (s[1] - '0');
}

static int asn1_get_time(fmap_t *map, const void **asn1data, unsigned int *size, time_t *tm) {
    struct cli_asn1 obj;
    int ret = asn1_get_obj(map, *asn1data, size, &obj);
    unsigned int len;
    char *ptr;
    struct tm t;
    int n;

    if(ret)
	return ret;

    if(obj.type == 0x17) /* UTCTime - YYMMDDHHMMSSZ */
	len = 13;
    else if(obj.type == 0x18) /* GeneralizedTime - YYYYMMDDHHMMSSZ */
	len = 15;
    else {
	cli_dbgmsg("asn1_get_time: expected UTCTime or GeneralizedTime, got %02x\n", obj.type);
	return 1;
    }

    if(!fmap_need_ptr_once(map, obj.content, len)) {
	cli_dbgmsg("asn1_get_time: failed to read content\n");
	return 1;
    }

    memset(&t, 0, sizeof(t));
    ptr = (char *)obj.content;
    if(obj.type == 0x18) {
	t.tm_year = asn1_getnum(ptr) * 100;
	if(t.tm_year < 0)
	    return 1;
	n = asn1_getnum(ptr);
	if(n<0)
	    return 1;
	t.tm_year += n;
	ptr+=4;
    } else {
	n = asn1_getnum(ptr);
	if(n<0)
	    return 1;
	if(n>=50)
	    t.tm_year = 1900 + n;
	else
	    t.tm_year = 2000 + n;
	ptr += 2;
    }
    t.tm_year -= 1900;
    n = asn1_getnum(ptr);
    if(n<1 || n>12) {
	cli_dbgmsg("asn1_get_time: invalid month %u\n", n);
	return 1;
    }
    t.tm_mon = n - 1;
    ptr+=2;

    n = asn1_getnum(ptr);
    if(n<1 || n>31) {
	cli_dbgmsg("asn1_get_time: invalid day %u\n", n);
	return 1;
    }
    t.tm_mday = n;
    ptr+=2;

    n = asn1_getnum(ptr);
    if(n<0 || n>23) {
	cli_dbgmsg("asn1_get_time: invalid hour %u\n", n);
	return 1;
    }
    t.tm_hour = n;
    ptr+=2;

    n = asn1_getnum(ptr);
    if(n<0 || n>59) {
	cli_dbgmsg("asn1_get_time: invalid minute %u\n", n);
	return 1;
    }
    t.tm_min = n;
    ptr+=2;

    n = asn1_getnum(ptr);
    if(n<0 || n>59) {
	cli_dbgmsg("asn1_get_time: invalid second %u\n", n);
	return 1;
    }
    t.tm_sec = n;
    ptr+=2;

    if(*ptr != 'Z') {
	cli_dbgmsg("asn1_get_time: expected UTC time 'Z', got '%c'\n", *ptr);
	return 1;
    }

    *tm = mktime(&t);
    *asn1data = obj.next;
    return 0;
}

static int asn1_get_rsa_pubkey(fmap_t *map, const void **asn1data, unsigned int *size, cli_crt *x509) {
    struct cli_asn1 obj;
    unsigned int avail, avail2;

    if(asn1_expect_objtype(map, *asn1data, size, &obj, 0x30)) /* subjectPublicKeyInfo */
	return 1;
    *asn1data = obj.next;

    avail = obj.size;
    if(asn1_expect_algo(map, &obj.content, &avail, lenof(OID_rsaEncryption), OID_rsaEncryption)) /* rsaEncryption */
       return 1;

    if(asn1_expect_objtype(map, obj.content, &avail, &obj, 0x03)) /* BIT STRING - subjectPublicKey */
	return 1;
    if(avail) {
	cli_dbgmsg("asn1_get_rsa_pubkey: found unexpected extra data in subjectPublicKeyInfo\n");
	return 1;
    }
    /* if(obj.size != 141 && obj.size != 271) /\* encoded len of 1024 and 2048 bit public keys *\/ */
    /*	return 1; */

    if(!fmap_need_ptr_once(map, obj.content, 1)) {
	cli_dbgmsg("asn1_get_rsa_pubkey: cannot read public key content\n");
	return 1;
    }
    if(((uint8_t *)obj.content)[0] != 0) { /* no byte fragments */
	cli_dbgmsg("asn1_get_rsa_pubkey: unexpected byte frags in public key\n");
	return 1;
    }

    avail = obj.size - 1;
    obj.content = ((uint8_t *)obj.content) + 1;
    if(asn1_expect_objtype(map, obj.content, &avail, &obj, 0x30)) /* SEQUENCE */
	return 1;
    if(avail) {
	cli_dbgmsg("asn1_get_rsa_pubkey: found unexpected extra data in public key content\n");
	return 1;
    }

    avail = obj.size;
    if(asn1_expect_objtype(map, obj.content, &avail, &obj, 0x02)) /* INTEGER - mod */
	return 1;
    if(obj.size < 1024/8 || obj.size > 4096/8+1) {
	cli_dbgmsg("asn1_get_rsa_pubkey: modulus has got an unsupported length (%u)\n",	 obj.size * 8);
	return 1;
    }
    avail2 = obj.size;
    if(!fmap_need_ptr_once(map, obj.content, avail2)) {
	cli_dbgmsg("asn1_get_rsa_pubkey: cannot read n\n");
	return 1;
    }
    if(mp_read_unsigned_bin(&x509->n, obj.content, avail2)) {
	cli_dbgmsg("asn1_get_rsa_pubkey: cannot convert n to big number\n");
	return 1;
    }

    if(asn1_expect_objtype(map, obj.next, &avail, &obj, 0x02)) /* INTEGER - exp */
	return 1;
    if(avail) {
	cli_dbgmsg("asn1_get_rsa_pubkey: found unexpected extra data after exp\n");
	return 1;
    }
    if(obj.size < 1 || obj.size > avail2) {
	cli_dbgmsg("asn1_get_rsa_pubkey: exponent has got an unsupported length (%u)\n",  obj.size * 8);
	return 1;
    }
    if(!fmap_need_ptr_once(map, obj.content, obj.size)) {
	cli_dbgmsg("asn1_get_rsa_pubkey: cannot read e\n");
	return 1;
    }
    if(mp_read_unsigned_bin(&x509->e, obj.content, obj.size)) {
	cli_dbgmsg("asn1_get_rsa_pubkey: cannot convert e to big number\n");
	return 1;
    }
    return 0;
}

static int asn1_get_x509(fmap_t *map, const void **asn1data, unsigned int *size, crtmgr *master, crtmgr *other) {
    struct cli_asn1 crt, tbs, obj;
    unsigned int avail, tbssize, issuersize;
    cli_crt_hashtype hashtype1, hashtype2;
    cli_crt x509;
    const uint8_t *tbsdata;
    const void *next, *issuer;

    if(cli_crt_init(&x509))
	return 1;

    do {
	if(asn1_expect_objtype(map, *asn1data, size, &crt, 0x30)) /* SEQUENCE */
	    break;
	*asn1data = crt.next;

	tbsdata = crt.content;
	if(asn1_expect_objtype(map, crt.content, &crt.size, &tbs, 0x30)) /* SEQUENCE - TBSCertificate */
	    break;
	tbssize = (uint8_t *)tbs.next - tbsdata;

	if(asn1_expect_objtype(map, tbs.content, &tbs.size, &obj, 0xa0)) /* [0] */
	    break;
	avail = obj.size;
	next = obj.next;
	if(asn1_expect_obj(map, &obj.content, &avail, 0x02, 1, "\x02")) /* version 3 only */
	    break;
	if(avail) {
	    cli_dbgmsg("asn1_get_x509: found unexpected extra data in version\n");
	    break;
	}

	if(asn1_expect_objtype(map, next, &tbs.size, &obj, 0x02)) /* serialNumber */
	    break;
	if(map_sha1(map, obj.content, obj.size, x509.serial))
	    break;

	if(asn1_expect_rsa(map, &obj.next, &tbs.size, &hashtype1)) /* algo = sha1WithRSAEncryption | md5WithRSAEncryption */
	    break;

	if(asn1_expect_objtype(map, obj.next, &tbs.size, &obj, 0x30)) /* issuer */
	    break;
	issuer = obj.content;
	issuersize = obj.size;

	if(asn1_expect_objtype(map, obj.next, &tbs.size, &obj, 0x30)) /* validity */
	    break;
	avail = obj.size;
	next = obj.content;

	if(asn1_get_time(map, &next, &avail, &x509.not_before)) /* notBefore */
	    break;
	if(asn1_get_time(map, &next, &avail, &x509.not_after)) /* notAfter */
	    break;
	if(x509.not_before >= x509.not_after) {
	    cli_dbgmsg("asn1_get_x509: bad validity\n");
	    break;
	}
	if(avail) {
	    cli_dbgmsg("asn1_get_x509: found unexpected extra data in validity\n");
	    break;
	}

	if(asn1_expect_objtype(map, obj.next, &tbs.size, &obj, 0x30)) /* subject */
	    break;
	if(map_sha1(map, obj.content, obj.size, x509.subject))
	    break;
	if(asn1_get_rsa_pubkey(map, &obj.next, &tbs.size, &x509))
	    break;

	avail = 0;
	while(tbs.size) {
	    if(asn1_get_obj(map, obj.next, &tbs.size, &obj)) {
		tbs.size = 1;
		break;
	    }
	    if(obj.type <= 0xa0 + avail || obj.type > 0xa3) {
		cli_dbgmsg("asn1_get_x509: found type %02x in extensions, expecting a1, a2 or a3\n", obj.type);
		tbs.size = 1;
		break;
	    }
	    avail = obj.type - 0xa0;
	    if(obj.type == 0xa3) {
		struct cli_asn1 exts;
		int have_ext_key = 0;
		if(asn1_expect_objtype(map, obj.content, &obj.size, &exts, 0x30)) {
		    tbs.size = 1;
		    break;
		}
		if(obj.size) {
		    cli_dbgmsg("asn1_get_x509: found unexpected extra data in extensions\n");
		    break;
		}
		while(exts.size) {
		    struct cli_asn1 ext, id, value;
		    if(asn1_expect_objtype(map, exts.content, &exts.size, &ext, 0x30)) {
			exts.size = 1;
			break;
		    }
		    exts.content = ext.next;
		    if(asn1_expect_objtype(map, ext.content, &ext.size, &id, 0x06)) {
			exts.size = 1;
			break;
		    }
		    if(asn1_get_obj(map, id.next, &ext.size, &value)) {
			exts.size = 1;
			break;
		    }
		    if(value.type == 0x01) {
			/* critical flag */
			if(value.size != 1) {
			    cli_dbgmsg("asn1_get_x509: found boolean with wrong length\n");
			    exts.size = 1;
			    break;
			}
			if(asn1_get_obj(map, value.next, &ext.size, &value)) {
			    exts.size = 1;
			    break;
			}
		    }
		    if(value.type != 0x04) {
			cli_dbgmsg("asn1_get_x509: bad extension value type %u\n", value.type);
			exts.size = 1;
			break;
		    }
		    if(ext.size) {
			cli_dbgmsg("asn1_get_x509: extra data in extension\n");
			exts.size = 1;
			break;
		    }
		    if(id.size != 3)
			continue;

		    if(!fmap_need_ptr_once(map, id.content, 3)) {
			exts.size = 1;
			break;
		    }
		    if(!memcmp("\x55\x1d\x0f", id.content, 3)) {
			/* KeyUsage 2.5.29.15 */
			const uint8_t *keyusage = value.content;
			uint8_t usage;
			if(value.size < 4 || value.size > 5) {
			    cli_dbgmsg("asn1_get_x509: bad KeyUsage\n");
			    exts.size = 1;
			    break;
			}
			if(!fmap_need_ptr_once(map, value.content, value.size)) {
			    exts.size = 1;
			    break;
			}
			if(keyusage[0] != 0x03 || keyusage[1] != value.size - 2 || keyusage[2] > 7) {
			    cli_dbgmsg("asn1_get_x509: bad KeyUsage\n");
			    exts.size = 1;
			    break;
			}
			usage = keyusage[3];
			if(value.size == 4)
			    usage &= ~((1 << keyusage[2])-1);
			x509.certSign = ((usage & 4) != 0);
			continue;
		    }
		    if(!memcmp("\x55\x1d\x25", id.content, 3)) {
			/* ExtKeyUsage 2.5.29.37 */
			struct cli_asn1 keypurp;
			have_ext_key = 1;
			if(asn1_expect_objtype(map, value.content, &value.size, &keypurp, 0x30)) {
			    exts.size = 1;
			    break;
			}
			if(value.size) {
			    cli_dbgmsg("asn1_get_x509: extra data in ExtKeyUsage\n");
			    exts.size = 1;
			    break;
			}
			ext.next = keypurp.content;
			while(keypurp.size) {
			    if(asn1_expect_objtype(map, ext.next, &keypurp.size, &ext, 0x06)) {
				exts.size = 1;
				break;
			    }
			    if(ext.size != 8)
				continue;
			    if(!fmap_need_ptr_once(map, ext.content, 8)) {
				exts.size = 1;
				break;
			    }
			    if(!memcmp("\x2b\x06\x01\x05\x05\x07\x03\x03", ext.content, 8)) /* id_kp_codeSigning */
				x509.codeSign = 1;
			    else if(!memcmp("\x2b\x06\x01\x05\x05\x07\x03\x08", ext.content, 8)) /* id_kp_timeStamping */
				x509.timeSign = 1;
			}
			continue;
		    }
		    if(!memcmp("\x55\x1d\x13", id.content, 3)) {
			/* Basic Constraints 2.5.29.19 */
			struct cli_asn1 constr;
			if(asn1_expect_objtype(map, value.content, &value.size, &constr, 0x30)) {
			    exts.size = 1;
			    break;
			}
			if(!constr.size)
			    x509.certSign = 0;
			else {
			    if(asn1_expect_objtype(map, constr.content, &constr.size, &ext, 0x01)) {
				exts.size = 1;
				break;
			    }
			    if(ext.size != 1) {
				cli_dbgmsg("asn1_get_x509: wrong bool size in basic constraint %u\n", ext.size);
				exts.size = 1;
				break;
			    }
			    if(!fmap_need_ptr_once(map, ext.content, 1)) {
				exts.size = 1;
				break;
			    }
			    x509.certSign = (((uint8_t *)(ext.content))[0] != 0);
			}
		    }
		}
		if(exts.size) {
		    tbs.size = 1;
		    break;
		}
		if(!have_ext_key)
		    x509.codeSign = x509.timeSign = 1;
	    }
	}
	if(tbs.size)
	    break;


	if(crtmgr_lookup(master, &x509) || crtmgr_lookup(other, &x509)) {
	    cli_dbgmsg("asn1_get_x509: certificate already exists\n");
	    cli_crt_clear(&x509);
	    return 0;
	}

	if(map_sha1(map, issuer, issuersize, x509.issuer))
	    break;

	if(asn1_expect_rsa(map, &tbs.next, &crt.size, &hashtype2)) /* signature algo = sha1WithRSAEncryption | md5WithRSAEncryption */
	    break;

	if(hashtype1 != hashtype2) {
	    cli_dbgmsg("asn1_get_x509: found conflicting rsa hash types\n");
	    break;
	}
	x509.hashtype = hashtype1;

	if(asn1_expect_objtype(map, tbs.next, &crt.size, &obj, 0x03)) /* signature */
	    break;
	if(obj.size > 513) {
	    cli_dbgmsg("asn1_get_x509: signature too long\n");
	    break;
	}
	if(!fmap_need_ptr_once(map, obj.content, obj.size)) {
	    cli_dbgmsg("asn1_get_x509: cannot read signature\n");
	    break;
	}
	if(mp_read_unsigned_bin(&x509.sig, obj.content, obj.size)) {
	    cli_dbgmsg("asn1_get_x509: cannot convert signature to big number\n");
	    break;
	}
	if(crt.size) {
	    cli_dbgmsg("asn1_get_x509: found unexpected extra data in signature\n");
	    break;
	}

	if((x509.hashtype == CLI_SHA1RSA && map_sha1(map, tbsdata, tbssize, x509.tbshash)) || (x509.hashtype == CLI_MD5RSA && (map_md5(map, tbsdata, tbssize, x509.tbshash))))
	    break;

	if(crtmgr_add(other, &x509))
	    break;
	cli_crt_clear(&x509);
	return 0;
    } while(0);
    cli_crt_clear(&x509);
    return 1;
}

static int asn1_parse_mscat(fmap_t *map, size_t offset, unsigned int size, crtmgr *cmgr, int embedded, const void **hashes, unsigned int *hashes_size, struct cl_engine *engine) {
    struct cli_asn1 asn1, deep, deeper;
    uint8_t sha1[SHA1_HASH_SIZE], issuer[SHA1_HASH_SIZE], md[SHA1_HASH_SIZE], serial[SHA1_HASH_SIZE];
    const uint8_t *message, *attrs;
    unsigned int dsize, message_size, attrs_size;
    cli_crt_hashtype hashtype;
    cli_crt *x509;
    void *ctx;
    int result;
    int isBlacklisted = 0;

    cli_dbgmsg("in asn1_parse_mscat\n");

    do {
	if(!(message = fmap_need_off_once(map, offset, 1))) {
	    cli_dbgmsg("asn1_parse_mscat: failed to read pkcs#7 entry\n");
	    break;
	}

	if(asn1_expect_objtype(map, message, &size, &asn1, 0x30)) /* SEQUENCE */
	    break;
	/* if(size) { */
	/*     cli_dbgmsg("asn1_parse_mscat: found extra data after pkcs#7 %u\n", size); */
	/*     break; */
	/* } */
	size = asn1.size;
	if(asn1_expect_obj(map, &asn1.content, &size, 0x06, lenof(OID_signedData), OID_signedData)) /* OBJECT 1.2.840.113549.1.7.2 - contentType = signedData */
	    break;
	if(asn1_expect_objtype(map, asn1.content, &size, &asn1, 0xa0)) /* [0] - content */
	    break;
	if(size) {
	    cli_dbgmsg("asn1_parse_mscat: found extra data in pkcs#7\n");
	    break;
	}
	size = asn1.size;
	if(asn1_expect_objtype(map, asn1.content, &size, &asn1, 0x30)) /* SEQUENCE */
	    break;
	if(size) {
	    cli_dbgmsg("asn1_parse_mscat: found extra data in signedData\n");
	    break;
	}
	size = asn1.size;
	if(asn1_expect_obj(map, &asn1.content, &size, 0x02, 1, "\x01")) /* INTEGER - VERSION 1 */
	    break;

	if(asn1_expect_objtype(map, asn1.content, &size, &asn1, 0x31)) /* SET OF DigestAlgorithmIdentifier */
	    break;

	if(asn1_expect_algo(map, &asn1.content, &asn1.size, lenof(OID_sha1), OID_sha1)) /* DigestAlgorithmIdentifier[0] == sha1 */
	    break;
	if(asn1.size) {
	    cli_dbgmsg("asn1_parse_mscat: only one digestAlgorithmIdentifier is allowed\n");
	    break;
	}

	if(asn1_expect_objtype(map, asn1.next, &size, &asn1, 0x30)) /* SEQUENCE - contentInfo */
	    break;
	/* Here there is either a PKCS #7 ContentType Object Identifier for Certificate Trust List (szOID_CTL)
	 * or a single SPC_INDIRECT_DATA_OBJID */
	if(
	   (!embedded && asn1_expect_obj(map, &asn1.content, &asn1.size, 0x06, lenof(OID_szOID_CTL), OID_szOID_CTL)) ||
	   (embedded && asn1_expect_obj(map, &asn1.content, &asn1.size, 0x06, lenof(OID_SPC_INDIRECT_DATA_OBJID), OID_SPC_INDIRECT_DATA_OBJID))
	   )
	    break;

	if(asn1_expect_objtype(map, asn1.content, &asn1.size, &deep, 0xa0))
	    break;
	if(asn1.size) {
	    cli_dbgmsg("asn1_parse_mscat: found extra data in contentInfo\n");
	    break;
	}
	dsize = deep.size;
	if(asn1_expect_objtype(map, deep.content, &dsize, &deep, 0x30))
	    break;
	if(dsize) {
	    cli_dbgmsg("asn1_parse_mscat: found extra data in content\n");
	    break;
	}
	*hashes = deep.content;
	*hashes_size = deep.size;

	if(asn1_expect_objtype(map, asn1.next, &size, &asn1, 0xa0)) /* certificates */
	    break;

	dsize = asn1.size;
	if(dsize) {
	    crtmgr newcerts;
	    crtmgr_init(&newcerts);
	    while(dsize) {
		if(asn1_get_x509(map, &asn1.content, &dsize, cmgr, &newcerts)) {
		    dsize = 1;
		    break;
		}
	    }
	    if(dsize)
		break;
	    if(newcerts.crts) {
		x509 = newcerts.crts;
		cli_dbgmsg("asn1_parse_mscat: %u new certificates collected\n", newcerts.items);
		while(x509) {
		    cli_crt *parent = crtmgr_verify_crt(cmgr, x509);

            /* Dump the cert if requested before anything happens to it */
            if (engine->dconf->pe & PE_CONF_DUMPCERT) {
                char issuer[SHA1_HASH_SIZE*2+1], subject[SHA1_HASH_SIZE*2+1], serial[SHA1_HASH_SIZE*2+1];
                char mod[1024], exp[1024];
                int j=1024;

                fp_toradix_n(&x509->n, mod, 16, j);
                fp_toradix_n(&x509->e, exp, 16, j);
                for (j=0; j < SHA1_HASH_SIZE; j++) {
                    sprintf(&issuer[j*2], "%02x", x509->issuer[j]);
                    sprintf(&subject[j*2], "%02x", x509->subject[j]);
                    sprintf(&serial[j*2], "%02x", x509->serial[j]);
                }

                cli_dbgmsg_internal("cert subject:%s serial:%s pubkey:%s i:%s %lu->%lu %s %s %s\n", subject, serial, mod, issuer, (unsigned long)x509->not_before, (unsigned long)x509->not_after, x509->certSign ? "cert" : "", x509->codeSign ? "code" : "", x509->timeSign ? "time" : "");
            }

		    if(parent) {
                if (parent->isBlacklisted) {
                    isBlacklisted = 1;
                    cli_dbgmsg("asn1_parse_mscat: Authenticode certificate %s is revoked. Flagging sample as virus.\n", (parent->name ? parent->name : "(no name)"));
                }

			x509->codeSign &= parent->codeSign;
			x509->timeSign &= parent->timeSign;
            if(crtmgr_add(cmgr, x509))
                break;
            crtmgr_del(&newcerts, x509);
			x509 = newcerts.crts;
			continue;
		    }
		    x509 = x509->next;
		}
		if(x509)
		    break;
		if(newcerts.items)
		    cli_dbgmsg("asn1_parse_mscat: %u certificates did not verify\n", newcerts.items);
		crtmgr_free(&newcerts);
	    }
	}

	if(asn1_get_obj(map, asn1.next, &size, &asn1))
	    break;
	if(asn1.type == 0xa1 && asn1_get_obj(map, asn1.next, &size, &asn1)) /* crls - unused shouldn't be present */
	    break;
	if(asn1.type != 0x31) { /* signerInfos */
	    cli_dbgmsg("asn1_parse_mscat: unexpected type %02x for signerInfos\n", asn1.type);
	    break;
	}
	if(size) {
	    cli_dbgmsg("asn1_parse_mscat: unexpected extra data after signerInfos\n");
	    break;
	}
	size = asn1.size;
	if(asn1_expect_objtype(map, asn1.content, &size, &asn1, 0x30))
	    break;
	if(size) {
	    cli_dbgmsg("asn1_parse_mscat: only one signerInfo shall be present\n");
	    break;
	}
	size = asn1.size;
	if(asn1_expect_obj(map, &asn1.content, &size, 0x02, 1, "\x01")) /* Version = 1 */
	    break;
	if(asn1_expect_objtype(map, asn1.content, &size, &asn1, 0x30)) /* issuerAndSerialNumber */
	    break;
	dsize = asn1.size;
	if(asn1_expect_objtype(map, asn1.content, &dsize, &deep, 0x30)) /* issuer */
	    break;
	if(map_sha1(map, deep.content, deep.size, issuer))
	    break;

	if(asn1_expect_objtype(map, deep.next, &dsize, &deep, 0x02)) /* serial */
	    break;
	if(map_sha1(map, deep.content, deep.size, serial))
	    break;
	if(dsize) {
	    cli_dbgmsg("asn1_parse_mscat: extra data inside issuerAndSerialNumber\n");
	    break;
	}
	if(asn1_expect_algo(map, &asn1.next, &size, lenof(OID_sha1), OID_sha1)) /* digestAlgorithm == sha1 */
	    break;

	attrs = asn1.next;
	if(asn1_expect_objtype(map, asn1.next, &size, &asn1, 0xa0)) /* authenticatedAttributes */
	    break;
	attrs_size = (uint8_t *)(asn1.next) - attrs;
	if(attrs_size < 2) {
	    cli_dbgmsg("asn1_parse_mscat: authenticatedAttributes size is too small\n");
	    break;
	}

	dsize = asn1.size;
	deep.next = asn1.content;
	result = 0;
	while(dsize) {
	    struct cli_asn1 cobj;
	    int content;
	    if(asn1_expect_objtype(map, deep.next, &dsize, &deep, 0x30)) { /* attribute */
		dsize = 1;
		break;
	    }
	    if(asn1_expect_objtype(map, deep.content, &deep.size, &deeper, 0x06)) { /* attribute type */
		dsize = 1;
		break;
	    }
	    if(deeper.size != lenof(OID_contentType))
		continue;
	    if(!fmap_need_ptr_once(map, deeper.content, lenof(OID_contentType))) {
		cli_dbgmsg("asn1_parse_mscat: failed to read authenticated attribute\n");
		dsize = 1;
		break;
	    }
	    if(!memcmp(deeper.content, OID_contentType, lenof(OID_contentType)))
		content = 0; /* contentType */
	    else if(!memcmp(deeper.content, OID_messageDigest, lenof(OID_messageDigest)))
		content = 1; /* messageDigest */
	    else
		continue;
	    if(asn1_expect_objtype(map, deeper.next, &deep.size, &deeper, 0x31)) { /* set - contents */
		dsize = 1;
		break;
	    }
	    if(deep.size) {
		cli_dbgmsg("asn1_parse_mscat: extra data in authenticated attributes\n");
		dsize = 1;
		break;
	    }

	    if(result & (1<<content)) {
		cli_dbgmsg("asn1_parse_mscat: contentType or messageDigest appear twice\n");
		dsize = 1;
		break;
	    }

	    if(content == 0) { /* contentType */
		if(
		   (!embedded && asn1_expect_obj(map, &deeper.content, &deeper.size, 0x06, lenof(OID_szOID_CTL), OID_szOID_CTL)) || /* cat file */
		   (embedded && asn1_expect_obj(map, &deeper.content, &deeper.size, 0x06, lenof(OID_SPC_INDIRECT_DATA_OBJID), OID_SPC_INDIRECT_DATA_OBJID)) /* embedded cat */
		  ) {
		    dsize = 1;
		    break;
		}
		result |= 1;
	    } else { /* messageDigest */
		if(asn1_expect_objtype(map, deeper.content, &deeper.size, &cobj, 0x04)) {
		    dsize = 1;
		    break;
		}
		if(cobj.size != SHA1_HASH_SIZE) {
		    cli_dbgmsg("asn1_parse_mscat: messageDigest attribute has got the wrong size (%u)\n", cobj.size);
		    dsize = 1;
		    break;
		}
		if(!fmap_need_ptr_once(map, cobj.content, SHA1_HASH_SIZE)) {
		    cli_dbgmsg("asn1_parse_mscat: failed to read authenticated attribute\n");
		    dsize = 1;
		    break;
		}
		memcpy(md, cobj.content, SHA1_HASH_SIZE);
		result |= 2;
	    }
	    if(deeper.size) {
		cli_dbgmsg("asn1_parse_mscat: extra data in authenticated attribute\n");
		dsize = 1;
		break;
	    }
	}
	if(dsize)
	    break;
	if(result != 3) {
	    cli_dbgmsg("asn1_parse_mscat: contentType or messageDigest are missing\n");
	    break;
	}

	if(asn1_expect_algo(map, &asn1.next, &size, lenof(OID_rsaEncryption), OID_rsaEncryption)) /* digestEncryptionAlgorithm == sha1 */
	    break;

	if(asn1_expect_objtype(map, asn1.next, &size, &asn1, 0x04)) /* encryptedDigest */
	    break;
	if(asn1.size > 513) {
	    cli_dbgmsg("asn1_parse_mscat: encryptedDigest too long\n");
	    break;
	}
	if(map_sha1(map, *hashes, *hashes_size, sha1))
	    break;
	if(memcmp(sha1, md, sizeof(sha1))) {
	    cli_dbgmsg("asn1_parse_mscat: messageDigest mismatch\n");
	    break;
	}

	if(!fmap_need_ptr_once(map, attrs, attrs_size)) {
	    cli_dbgmsg("asn1_parse_mscat: failed to read authenticatedAttributes\n");
	    break;
	}

    ctx = cl_hash_init("sha1");
    if (!(ctx))
        break;

	cl_update_hash(ctx, "\x31", 1);
	cl_update_hash(ctx, attrs + 1, attrs_size - 1);
	cl_finish_hash(ctx, sha1);

	if(!fmap_need_ptr_once(map, asn1.content, asn1.size)) {
	    cli_dbgmsg("asn1_parse_mscat: failed to read encryptedDigest\n");
	    break;
	}
	if(!(x509 = crtmgr_verify_pkcs7(cmgr, issuer, serial, asn1.content, asn1.size, CLI_SHA1RSA, sha1, VRFY_CODE))) {
	    cli_dbgmsg("asn1_parse_mscat: pkcs7 signature verification failed\n");
	    break;
	}
	message = asn1.content;
	message_size = asn1.size;

	if(!size) {
	    cli_dbgmsg("asn1_parse_mscat: countersignature is missing\n");
	    break;
	}

	if(size && asn1_expect_objtype(map, asn1.next, &size, &asn1, 0xa1)) /* unauthenticatedAttributes */
	    break;

	if(size) {
	    cli_dbgmsg("asn1_parse_mscat: extra data inside signerInfo\n");
	    break;
	}

	size = asn1.size;
	if(asn1_expect_objtype(map, asn1.content, &size, &asn1, 0x30))
	    break;
	if(size) {
	    cli_dbgmsg("asn1_parse_mscat: extra data inside unauthenticatedAttributes\n");
	    break;
	}

	size = asn1.size;
	/* 1.2.840.113549.1.9.6 - counterSignature */
	if(asn1_expect_obj(map, &asn1.content, &size, 0x06, lenof(OID_countersignature), OID_countersignature))
	    break;
	if(asn1_expect_objtype(map, asn1.content, &size, &asn1, 0x31))
	    break;
	if(size) {
	    cli_dbgmsg("asn1_parse_mscat: extra data inside counterSignature\n");
	    break;
	}

	size = asn1.size;
	if(asn1_expect_objtype(map, asn1.content, &size, &asn1, 0x30))
	    break;
	if(size) {
	    cli_dbgmsg("asn1_parse_mscat: extra data inside unauthenticatedAttributes\n");
	    break;
	}

	size = asn1.size;
	if(asn1_expect_obj(map, &asn1.content, &size, 0x02, 1, "\x01")) /* Version = 1*/
	    break;

	if(asn1_expect_objtype(map, asn1.content, &size, &asn1, 0x30)) /* issuerAndSerialNumber */
	    break;

	if(asn1_expect_objtype(map, asn1.content, &asn1.size, &deep, 0x30)) /* issuer */
	    break;
	if(map_sha1(map, deep.content, deep.size, issuer))
	    break;

	if(asn1_expect_objtype(map, deep.next, &asn1.size, &deep, 0x02)) /* serial */
	    break;
	if(map_sha1(map, deep.content, deep.size, serial))
	    break;

	if(asn1.size) {
	    cli_dbgmsg("asn1_parse_mscat: extra data inside countersignature issuer\n");
	    break;
	}

	if(asn1_expect_objtype(map, asn1.next, &size, &asn1, 0x30)) /* digestAlgorithm */
	    break;
	if(asn1_expect_objtype(map, asn1.content, &asn1.size, &deep, 0x06))
	    break;
	if(deep.size != lenof(OID_sha1) && deep.size != lenof(OID_md5)) {
	    cli_dbgmsg("asn1_parse_mscat: wrong digestAlgorithm size\n");
	    break;
	}
	if(!fmap_need_ptr_once(map, deep.content, deep.size)) {
	    cli_dbgmsg("asn1_parse_mscat: failed to read digestAlgorithm OID\n");
	    break;
	}
	if(deep.size == lenof(OID_sha1) && !memcmp(deep.content, OID_sha1, lenof(OID_sha1))) {
	    hashtype = CLI_SHA1RSA;
	    if(map_sha1(map, message, message_size, md))
		break;
	} else if(deep.size == lenof(OID_md5) && !memcmp(deep.content, OID_md5, lenof(OID_md5))) {
	    hashtype = CLI_MD5RSA;
	    if(map_md5(map, message, message_size, md))
		break;
	} else {
	    cli_dbgmsg("asn1_parse_mscat: unknown digest oid in countersignature\n");
	    break;
	}
	if(asn1.size && asn1_expect_obj(map, &deep.next, &asn1.size, 0x05, 0, NULL))
	    break;
	if(asn1.size) {
	    cli_dbgmsg("asn1_parse_mscat: extra data in countersignature oid\n");
	    break;
	}

	attrs = asn1.next;
	if(asn1_expect_objtype(map, asn1.next, &size, &asn1, 0xa0)) /* authenticatedAttributes */
	    break;
	attrs_size = (uint8_t *)(asn1.next) - attrs;
	if(attrs_size < 2) {
	    cli_dbgmsg("asn1_parse_mscat: countersignature authenticatedAttributes are too small\n");
	    break;
	}
	result = 0;
	dsize = asn1.size;
	deep.next = asn1.content;
	while(dsize) {
	    int content;
	    if(asn1_expect_objtype(map, deep.next, &dsize, &deep, 0x30)) { /* attribute */
		dsize = 1;
		break;
	    }
	    if(asn1_expect_objtype(map, deep.content, &deep.size, &deeper, 0x06)) { /* attribute type */
		dsize = 1;
		break;
	    }
	    if(deeper.size != lenof(OID_contentType)) /* lenof(contentType) = lenof(messageDigest) = lenof(signingTime) = 9 */
		continue;

	    if(!fmap_need_ptr_once(map, deeper.content, lenof(OID_contentType))) {
		dsize = 1;
		break;
	    }
	    if(!memcmp(deeper.content, OID_contentType, lenof(OID_contentType)))
		content = 0; /* contentType */
	    else if(!memcmp(deeper.content, OID_messageDigest, lenof(OID_messageDigest)))
		content = 1; /* messageDigest */
	    else if(!memcmp(deeper.content, OID_signingTime, lenof(OID_signingTime)))
		content = 2; /* signingTime */
	    else
		continue;
	    if(result & (1<<content)) {
		cli_dbgmsg("asn1_parse_mscat: duplicate field in countersignature\n");
		dsize = 1;
		break;
	    }
	    result |= (1<<content);
	    if(asn1_expect_objtype(map, deeper.next, &deep.size, &deeper, 0x31)) { /* attribute type */
		dsize = 1;
		break;
	    }
	    if(deep.size) {
		cli_dbgmsg("asn1_parse_mscat: extra data in countersignature value\n");
		dsize = 1;
		break;
	    }
	    deep.size = deeper.size;
	    switch(content) {
	    case 0:  /* contentType = pkcs7-data */
		if(asn1_expect_obj(map, &deeper.content, &deep.size, 0x06, lenof(OID_pkcs7_data), OID_pkcs7_data))
		    deep.size = 1;
		else if(deep.size)
		    cli_dbgmsg("asn1_parse_mscat: extra data in countersignature content-type\n");
		break;
	    case 1:  /* messageDigest */
		if(asn1_expect_obj(map, &deeper.content, &deep.size, 0x04, (hashtype == CLI_SHA1RSA) ? SHA1_HASH_SIZE : 16, md)) {
		    deep.size = 1;
		    cli_dbgmsg("asn1_parse_mscat: countersignature hash mismatch\n");
		} else if(deep.size)
		    cli_dbgmsg("asn1_parse_mscat: extra data in countersignature message-digest\n");
		break;
	    case 2:  /* signingTime */
		{
		    time_t sigdate; /* FIXME shall i use it?! */
		    if(asn1_get_time(map, &deeper.content, &deep.size, &sigdate))
			deep.size = 1;
		    else if(deep.size)
			cli_dbgmsg("asn1_parse_mscat: extra data in countersignature signing-time\n");
		    else if(sigdate < x509->not_before || sigdate > x509->not_after) {
			cli_dbgmsg("asn1_parse_mscat: countersignature timestamp outside cert validity\n");
			deep.size = 1;
		    }
		    break;
		}
	    }
	    if(deep.size) {
		dsize = 1;
		break;
	    }
	}
	if(dsize)
	    break;
	if(result != 7) {
	    cli_dbgmsg("asn1_parse_mscat: some important attributes are missing in countersignature\n");
	    break;
	}

	if(asn1_expect_objtype(map, asn1.next, &size, &asn1, 0x30)) /* digestEncryptionAlgorithm == sha1 */
	    break;
	if(asn1_expect_objtype(map, asn1.content, &asn1.size, &deep, 0x06)) /* digestEncryptionAlgorithm == sha1 */
	    break;
	if(deep.size != lenof(OID_rsaEncryption)) { /* lenof(OID_rsaEncryption) = lenof(OID_sha1WithRSAEncryption) = 9 */
	    cli_dbgmsg("asn1_parse_mscat: wrong digestEncryptionAlgorithm size in countersignature\n");
	    break;
	}
	if(!fmap_need_ptr_once(map, deep.content, lenof(OID_rsaEncryption))) {
	    cli_dbgmsg("asn1_parse_mscat: cannot read digestEncryptionAlgorithm in countersignature\n");
	    break;
	}
	/* rsaEncryption or sha1withRSAEncryption */
	if(memcmp(deep.content, OID_rsaEncryption, lenof(OID_rsaEncryption)) && memcmp(deep.content, OID_sha1WithRSAEncryption, lenof(OID_sha1WithRSAEncryption))) {
	    cli_dbgmsg("asn1_parse_mscat: digestEncryptionAlgorithm in countersignature is not sha1\n");
	    break;
	}
	if(asn1.size && asn1_expect_obj(map, &deep.next, &asn1.size, 0x05, 0, NULL))
	    break;
	if(asn1.size) {
	    cli_dbgmsg("asn1_parse_mscat: extra data in digestEncryptionAlgorithm in countersignature\n");
	    break;
	}

	if(asn1_expect_objtype(map, asn1.next, &size, &asn1, 0x04)) /* encryptedDigest */
	    break;
	if(asn1.size > 513) {
	    cli_dbgmsg("asn1_parse_mscat: countersignature encryptedDigest too long\n");
	    break;
	}
	if(size) {
	    cli_dbgmsg("asn1_parse_mscat: extra data inside countersignature\n");
	    break;
	}
	if(!fmap_need_ptr_once(map, attrs, attrs_size)) {
	    cli_dbgmsg("asn1_parse_mscat: failed to read authenticatedAttributes\n");
	    break;
	}

	if(hashtype == CLI_SHA1RSA) {
        ctx = cl_hash_init("sha1");
        if (!(ctx))
            break;

        cl_update_hash(ctx, "\x31", 1);
        cl_update_hash(ctx, attrs + 1, attrs_size - 1);
        cl_finish_hash(ctx, sha1);
	} else {
        ctx = cl_hash_init("md5");
        if (!(ctx))
            break;

        cl_update_hash(ctx, "\x31", 1);
        cl_update_hash(ctx, attrs + 1, attrs_size - 1);
        cl_finish_hash(ctx, sha1);
	}

	if(!fmap_need_ptr_once(map, asn1.content, asn1.size)) {
	    cli_dbgmsg("asn1_parse_mscat: failed to read countersignature encryptedDigest\n");
	    break;
	}
	if(!crtmgr_verify_pkcs7(cmgr, issuer, serial, asn1.content, asn1.size, hashtype, sha1, VRFY_TIME)) {
	    cli_dbgmsg("asn1_parse_mscat: pkcs7 countersignature verification failed\n");
	    break;
	}

	cli_dbgmsg("asn1_parse_mscat: catalog successfully parsed\n");
    if (isBlacklisted) {
        return 1;
    }
	return 0;
    } while(0);

    cli_dbgmsg("asn1_parse_mscat: failed to parse catalog\n");
    return 1;
}

int asn1_load_mscat(fmap_t *map, struct cl_engine *engine) {
    struct cli_asn1 c;
    unsigned int size;
    struct cli_matcher *db;
    int i;

    if(asn1_parse_mscat(map, 0, map->len, &engine->cmgr, 0, &c.next, &size, engine))
        return 1;

    if(asn1_expect_objtype(map, c.next, &size, &c, 0x30))
	return 1;
    if(asn1_expect_obj(map, &c.content, &c.size, 0x06, lenof(OID_szOID_CATALOG_LIST), OID_szOID_CATALOG_LIST))
	return 1;
    if(c.size) {
	cli_dbgmsg("asn1_load_mscat: found extra data in szOID_CATALOG_LIST content\n");
	return 1;
    }
    if(asn1_expect_objtype(map, c.next, &size, &c, 0x4)) /* List ID */
	return 1;
    if(asn1_expect_objtype(map, c.next, &size, &c, 0x17)) /* Effective date - WTF?! */
	return 1;
    if(asn1_expect_algo(map, &c.next, &size, lenof(OID_szOID_CATALOG_LIST_MEMBER), OID_szOID_CATALOG_LIST_MEMBER)) /* szOID_CATALOG_LIST_MEMBER */
	return 1;
    if(asn1_expect_objtype(map, c.next, &size, &c, 0x30)) /* hashes here */
	return 1;
    /* [0] is next but we don't care as it's really descriptives stuff */

    size = c.size;
    c.next = c.content;
    while(size) {
	struct cli_asn1 tag;
	if(asn1_expect_objtype(map, c.next, &size, &c, 0x30))
	    return 1;
	if(asn1_expect_objtype(map, c.content, &c.size, &tag, 0x04)) /* TAG NAME */
	    return 1;
	if(asn1_expect_objtype(map, tag.next, &c.size, &tag, 0x31)) /* set */
	    return 1;
	if(c.size) {
	    cli_dbgmsg("asn1_load_mscat: found extra data in tag\n");
	    return 1;
	}
	while(tag.size) {
	    struct cli_asn1 tagval1, tagval2, tagval3;
	    int hashtype;

	    if(asn1_expect_objtype(map, tag.content, &tag.size, &tagval1, 0x30))
		return 1;
	    tag.content = tagval1.next;

	    if(asn1_expect_objtype(map, tagval1.content, &tagval1.size, &tagval2, 0x06))
		return 1;
	    if(tagval2.size != lenof(OID_SPC_INDIRECT_DATA_OBJID))
		continue;

	    if(!fmap_need_ptr_once(map, tagval2.content, lenof(OID_SPC_INDIRECT_DATA_OBJID))) {
		cli_dbgmsg("asn1_load_mscat: cannot read SPC_INDIRECT_DATA\n");
		return 1;
	    }
	    if(memcmp(tagval2.content, OID_SPC_INDIRECT_DATA_OBJID, lenof(OID_SPC_INDIRECT_DATA_OBJID)))
		continue; /* stuff like CAT_NAMEVALUE_OBJID(1.3.6.1.4.1.311.12.2.1) and CAT_MEMBERINFO_OBJID(.2).. */

	    if(asn1_expect_objtype(map, tagval2.next, &tagval1.size, &tagval2, 0x31))
		return 1;
	    if(tagval1.size) {
		cli_dbgmsg("asn1_load_mscat: found extra data in tag value\n");
		return 1;
	    }

	    if(asn1_expect_objtype(map, tagval2.content, &tagval2.size, &tagval1, 0x30))
		return 1;
	    if(tagval2.size) {
		cli_dbgmsg("asn1_load_mscat: found extra data in SPC_INDIRECT_DATA_OBJID tag\n");
		return 1;
	    }

	    if(asn1_expect_objtype(map, tagval1.content, &tagval1.size, &tagval2, 0x30))
		return 1;

	    if(asn1_expect_objtype(map, tagval2.content, &tagval2.size, &tagval3, 0x06)) /* shall have an obj 1.3.6.1.4.1.311.2.1.15 or 1.3.6.1.4.1.311.2.1.25 inside */
		return 1;
	    if(tagval3.size != lenof(OID_SPC_PE_IMAGE_DATA_OBJID)) { /* lenof(OID_SPC_PE_IMAGE_DATA_OBJID) = lenof(OID_SPC_CAB_DATA_OBJID) = 10*/
		cli_dbgmsg("asn1_load_mscat: bad hash type size\n");
		return 1;
	    }
	    if(!fmap_need_ptr_once(map, tagval3.content, lenof(OID_SPC_PE_IMAGE_DATA_OBJID))) {
		cli_dbgmsg("asn1_load_mscat: cannot read hash type\n");
		return 1;
	    }
	    if(!memcmp(tagval3.content, OID_SPC_PE_IMAGE_DATA_OBJID, lenof(OID_SPC_PE_IMAGE_DATA_OBJID)))
		hashtype = 2;
	    else if(!memcmp(tagval3.content, OID_SPC_CAB_DATA_OBJID, lenof(OID_SPC_CAB_DATA_OBJID)))
		hashtype = 1;
	    else {
		cli_dbgmsg("asn1_load_mscat: unexpected hash type\n");
		return 1;
	    }

	    if(asn1_expect_objtype(map, tagval2.next, &tagval1.size, &tagval2, 0x30))
		return 1;
	    if(tagval1.size) {
		cli_dbgmsg("asn1_load_mscat: found extra data after hash\n");
		return 1;
	    }

	    if(asn1_expect_algo(map, &tagval2.content, &tagval2.size, lenof(OID_sha1), OID_sha1)) /* objid 1.3.14.3.2.26 - sha1 */
		return 1;

	    if(asn1_expect_objtype(map, tagval2.content, &tagval2.size, &tagval3, 0x04))
		return 1;
	    if(tagval2.size) {
		cli_dbgmsg("asn1_load_mscat: found extra data in hash\n");
		return 1;
	    }
	    if(tagval3.size != SHA1_HASH_SIZE) {
		cli_dbgmsg("asn1_load_mscat: bad hash size %u\n", tagval3.size);
		return 1;
	    }
	    if(!fmap_need_ptr_once(map, tagval3.content, SHA1_HASH_SIZE)) {
		cli_dbgmsg("asn1_load_mscat: cannot read hash\n");
		return 1;
	    }

	    if(cli_debug_flag) {
		char sha1[SHA1_HASH_SIZE*2+1];
		for(i=0;i<SHA1_HASH_SIZE;i++)
		    sprintf(&sha1[i*2], "%02x", ((uint8_t *)(tagval3.content))[i]);
		cli_dbgmsg("asn1_load_mscat: got hash %s (%s)\n", sha1, (hashtype == 2) ? "PE" : "CAB");
	    }
	    if(!engine->hm_fp) {
		if(!(engine->hm_fp = mpool_calloc(engine->mempool, 1, sizeof(*db)))) {
		    tag.size = 1;;
		    return 1;
		}
#ifdef USE_MPOOL
		engine->hm_fp->mempool = engine->mempool;
#endif
	    }
	    if(hm_addhash_bin(engine->hm_fp, tagval3.content, CLI_HASH_SHA1, hashtype, NULL)) {
		cli_warnmsg("asn1_load_mscat: failed to add hash\n");
		return 1;
	    }
	}
    }

    return 0;
}

int asn1_check_mscat(struct cl_engine *engine, fmap_t *map, size_t offset, unsigned int size, uint8_t *computed_sha1) {
    unsigned int content_size;
    struct cli_asn1 c;
    const void *content;
    crtmgr certs;
    int ret;

    if (engine->dconf->pe & PE_CONF_DISABLECERT)
        return CL_VIRUS;

    cli_dbgmsg("in asn1_check_mscat (offset: %lu)\n", offset);
    crtmgr_init(&certs);
    if(crtmgr_add_roots(engine, &certs)) {
	crtmgr_free(&certs);
	return CL_VIRUS;
    }
    ret = asn1_parse_mscat(map, offset, size, &certs, 1, &content, &content_size, engine);
    crtmgr_free(&certs);
    if(ret)
	return CL_VIRUS;

    if(asn1_expect_objtype(map, content, &content_size, &c, 0x30))
	return CL_VIRUS;
    if(asn1_expect_obj(map, &c.content, &c.size, 0x06, lenof(OID_SPC_PE_IMAGE_DATA_OBJID), OID_SPC_PE_IMAGE_DATA_OBJID))
	return CL_VIRUS;
    if(asn1_expect_objtype(map, c.next, &content_size, &c, 0x30))
	return CL_VIRUS;
    if(content_size) {
	cli_dbgmsg("asn1_check_mscat: extra data in content\n");
	return CL_VIRUS;
    }
    if(asn1_expect_algo(map, &c.content, &c.size, lenof(OID_sha1), OID_sha1))
	return CL_VIRUS;

    if(asn1_expect_obj(map, &c.content, &c.size, 0x04, SHA1_HASH_SIZE, computed_sha1))
	return CL_VIRUS;

    cli_dbgmsg("asn1_check_mscat: file with valid authenicode signature, whitelisted\n");
    return CL_CLEAN;
}
