/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2011-2013 Sourcefire, Inc.
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

#include "clamav.h"
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

#define OID_1_2_840_113549_1_1_12 "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0c"
#define OID_sha384WithRSAEncryption OID_1_2_840_113549_1_1_12

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

#define OID_1_2_840_113549_1_9_16_1_4 "\x2a\x86\x48\x86\xf7\x0d\x01\x09\x10\x01\x04"
#define OID_timestampToken OID_1_2_840_113549_1_9_16_1_4


#define OID_1_3_6_1_4_1_311_2_1_4 "\x2b\x06\x01\x04\x01\x82\x37\x02\x01\x04"
#define OID_SPC_INDIRECT_DATA_OBJID OID_1_3_6_1_4_1_311_2_1_4

#define OID_1_3_6_1_4_1_311_2_1_15 "\x2b\x06\x01\x04\x01\x82\x37\x02\x01\x0f"
#define OID_SPC_PE_IMAGE_DATA_OBJID OID_1_3_6_1_4_1_311_2_1_15

#define OID_1_3_6_1_4_1_311_2_1_25 "\x2b\x06\x01\x04\x01\x82\x37\x02\x01\x19"
#define OID_SPC_CAB_DATA_OBJID OID_1_3_6_1_4_1_311_2_1_25

#define OID_1_3_6_1_4_1_311_2_4_1 "\x2b\x06\x01\x04\x01\x82\x37\x02\x04\x01"
#define OID_nestedSignatures OID_1_3_6_1_4_1_311_2_4_1

#define OID_1_3_6_1_4_1_311_10_1 "\x2b\x06\x01\x04\x01\x82\x37\x0a\x01"
#define OID_szOID_CTL OID_1_3_6_1_4_1_311_10_1

#define OID_1_3_6_1_4_1_311_12_1_1 "\x2b\x06\x01\x04\x01\x82\x37\x0c\x01\x01"
#define OID_szOID_CATALOG_LIST OID_1_3_6_1_4_1_311_12_1_1

#define OID_1_3_6_1_4_1_311_12_1_2 "\x2b\x06\x01\x04\x01\x82\x37\x0c\x01\x02"
#define OID_szOID_CATALOG_LIST_MEMBER OID_1_3_6_1_4_1_311_12_1_2

#define OID_2_16_840_1_101_3_4_2_1 "\x60\x86\x48\x01\x65\x03\x04\x02\x01"
#define OID_sha256 OID_2_16_840_1_101_3_4_2_1

#define OID_2_16_840_1_101_3_4_2_2 "\x60\x86\x48\x01\x65\x03\x04\x02\x02"
#define OID_sha384 OID_2_16_840_1_101_3_4_2_2

#define OID_2_16_840_1_101_3_4_2_3 "\x60\x86\x48\x01\x65\x03\x04\x02\x03"
#define OID_sha512 OID_2_16_840_1_101_3_4_2_3

/* --------------------------------------------------------------------------- OIDS */
#define lenof(x) (sizeof((x))-1)

#define ASN1_TYPE_BOOLEAN 0x01
#define ASN1_TYPE_INTEGER 0x02
#define ASN1_TYPE_BIT_STRING 0x03
#define ASN1_TYPE_OCTET_STRING 0x04
#define ASN1_TYPE_NULL 0x05
#define ASN1_TYPE_OBJECT_ID 0x06
#define ASN1_TYPE_SEQUENCE 0x30
#define ASN1_TYPE_SET 0x31

#define MAX_HASH_SIZE SHA512_HASH_SIZE

struct cli_asn1 {
    uint8_t type;
    unsigned int size;
    const void *content;
    const void *next;
};

static int map_raw(fmap_t *map, const void *data, unsigned int len, uint8_t raw[CRT_RAWMAXLEN]) {
    unsigned int elen = MIN(len, CRT_RAWMAXLEN-1);

    if(!fmap_need_ptr_once(map, data, elen)) {
        cli_dbgmsg("map_raw: failed to read map data\n");
        return 1;
    }
    memset(raw, 0, CRT_RAWMAXLEN);
    raw[0] = (uint8_t)elen;
    memcpy(&raw[1], data, elen);
    return 0;
}

static int map_sha512(fmap_t *map, const void *data, unsigned int len, uint8_t sha512[SHA512_HASH_SIZE]) {
    if(!fmap_need_ptr_once(map, data, len)) {
        cli_dbgmsg("map_sha512: failed to read hash data\n");
        return 1;
    }
    return (cl_sha512(data, len, sha512, NULL) == NULL);
}

static int map_sha384(fmap_t *map, const void *data, unsigned int len, uint8_t sha384[SHA384_HASH_SIZE]) {
    if(!fmap_need_ptr_once(map, data, len)) {
        cli_dbgmsg("map_sha384: failed to read hash data\n");
        return 1;
    }
    return (cl_sha384(data, len, sha384, NULL) == NULL);
}

static int map_sha256(fmap_t *map, const void *data, unsigned int len, uint8_t sha256[SHA256_HASH_SIZE]) {
    if(!fmap_need_ptr_once(map, data, len)) {
        cli_dbgmsg("map_sha256: failed to read hash data\n");
        return 1;
    }
    return (cl_sha256(data, len, sha256, NULL) == NULL);
}

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

static int map_hash(fmap_t *map, const void *data, unsigned int len, uint8_t *out_hash, cli_crt_hashtype hashtype) {

    if(hashtype == CLI_SHA1RSA) {
        if(map_sha1(map, data, len, out_hash)) {
            return 1;
        }
    } else if(hashtype == CLI_MD5RSA) {
        if(map_md5(map, data, len, out_hash)) {
            return 1;
        }
    } else if(hashtype == CLI_SHA256RSA) {
        if(map_sha256(map, data, len, out_hash)) {
            return 1;
        }
    } else if(hashtype == CLI_SHA384RSA) {
        if(map_sha384(map, data, len, out_hash)) {
            return 1;
        }
    } else if(hashtype == CLI_SHA512RSA) {
        if(map_sha512(map, data, len, out_hash)) {
            return 1;
        }
    } else {
        cli_dbgmsg("asn1_map_hash: unsupported hashtype\n");
        return 1;
    }
    return 0;
}

static void * get_hash_ctx(cli_crt_hashtype hashtype) {
    void *ctx = NULL;
    if(hashtype == CLI_SHA1RSA) {
        ctx = cl_hash_init("sha1");
    } else if (hashtype == CLI_MD5RSA) {
        ctx = cl_hash_init("md5");
    } else if (hashtype == CLI_SHA256RSA) {
        ctx = cl_hash_init("sha256");
    } else if (hashtype == CLI_SHA384RSA) {
        ctx = cl_hash_init("sha384");
    } else if (hashtype == CLI_SHA512RSA) {
        ctx = cl_hash_init("sha512");
    } else {
        cli_dbgmsg("asn1_get_hash_ctx: unsupported hashtype\n");
    }
    return ctx;
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
    if((ret = asn1_expect_objtype(map, *asn1data, asn1len, &obj, ASN1_TYPE_SEQUENCE))) /* SEQUENCE */
        return ret;
    avail = obj.size;
    *asn1data = obj.next;

    if((ret = asn1_expect_obj(map, &obj.content, &avail, ASN1_TYPE_OBJECT_ID, algo_size, algo))) /* ALGO */
        return ret;

    // The specification says that the NULL is a required parameter for this
    // data type, but in practice it doesn't always exist in the ASN1. If
    // there is something after the ALGO OID, assume it's the NULL
    if(avail && (ret = asn1_expect_obj(map, &obj.content, &avail, ASN1_TYPE_NULL, 0, NULL))) { /* NULL */
        cli_dbgmsg("asn1_expect_algo: expected NULL after AlgorithmIdentifier OID\n");
        return ret;
    }
    if(avail) {
        cli_dbgmsg("asn1_expect_algo: extra data found in SEQUENCE\n");
        return 1;
    }
    return 0;
}

static int asn1_expect_hash_algo(fmap_t *map, const void **asn1data, unsigned int *asn1len, cli_crt_hashtype *hashtype, unsigned int *hashsize) {
    struct cli_asn1 obj;
    unsigned int avail;
    int ret;

    if(ret = asn1_expect_objtype(map, *asn1data, asn1len, &obj, ASN1_TYPE_SEQUENCE)) {
        cli_dbgmsg("asn1_expect_hash_algo: expected SEQUENCE to start AlgorithmIdentifier\n");
        return ret;
    }
    avail = obj.size;
    *asn1data = obj.next;
    if(ret = asn1_expect_objtype(map, obj.content, &avail, &obj, ASN1_TYPE_OBJECT_ID)) {
        cli_dbgmsg("asn1_expect_hash_algo: unexpected object type inside AlgorithmIdentifier SET\n");
        return ret;
    }
    /* Cases to consider for the length check:
     *  - obj.size == 5:
     *     - OID_sha1
     *  - obj.size == 8:
     *     - OID_md5
     *  - obj.size == 9:
     *     - OID_sha256
     *     - OID_sha1WithRSAEncryption
     *     - OID_md5WithRSAEncryption
     *     - OID_sha256WithRSAEncryption
     *     - OID_sha384
     *     - OID_sha384WithRSAEncryption
     *     - OID_sha512
     *     - OID_sha512WithRSAEncryption
     */
    if(obj.size != lenof(OID_sha1) && obj.size != lenof(OID_md5) && obj.size != lenof(OID_sha256)) {
        cli_dbgmsg("asn1_expect_hash_algo: unsupported algorithm OID size for AlgorithmIdentifier\n");
        return 1;
    }
    if(!fmap_need_ptr_once(map, obj.content, obj.size)) {
        cli_dbgmsg("asn1_expect_hash_algo: failed to get AlgorithmIdentifier OID\n");
        return 1;
    }
    if((obj.size == lenof(OID_sha1) && !memcmp(obj.content, OID_sha1, lenof(OID_sha1))) ||
       (obj.size == lenof(OID_sha1WithRSAEncryption) && !memcmp(obj.content, OID_sha1WithRSAEncryption, lenof(OID_sha1WithRSAEncryption)))) {
        *hashtype = CLI_SHA1RSA;
        *hashsize = SHA1_HASH_SIZE;
    } else if((obj.size == lenof(OID_md5) && !memcmp(obj.content, OID_md5, lenof(OID_md5))) ||
              (obj.size == lenof(OID_md5WithRSAEncryption) && !memcmp(obj.content, OID_md5WithRSAEncryption, lenof(OID_md5WithRSAEncryption)))) {
        *hashtype = CLI_MD5RSA;
        *hashsize = MD5_HASH_SIZE;
    } else if((obj.size == lenof(OID_sha256) && !memcmp(obj.content, OID_sha256, lenof(OID_sha256))) ||
              (obj.size == lenof(OID_sha256WithRSAEncryption) && !memcmp(obj.content, OID_sha256WithRSAEncryption, lenof(OID_sha256WithRSAEncryption)))) {
        *hashtype = CLI_SHA256RSA;
        *hashsize = SHA256_HASH_SIZE;
    } else if((obj.size == lenof(OID_sha384) && !memcmp(obj.content, OID_sha384, lenof(OID_sha384))) ||
              (obj.size == lenof(OID_sha384WithRSAEncryption) && !memcmp(obj.content, OID_sha384WithRSAEncryption, lenof(OID_sha384WithRSAEncryption)))) {
        *hashtype = CLI_SHA384RSA;
        *hashsize = SHA384_HASH_SIZE;
    } else if((obj.size == lenof(OID_sha512) && !memcmp(obj.content, OID_sha512, lenof(OID_sha512))) ||
              (obj.size == lenof(OID_sha512WithRSAEncryption) && !memcmp(obj.content, OID_sha512WithRSAEncryption, lenof(OID_sha512WithRSAEncryption)))) {
        *hashtype = CLI_SHA512RSA;
        *hashsize = SHA512_HASH_SIZE;
    } else {
        cli_dbgmsg("asn1_expect_hash_algo: unknown digest OID in AlgorithmIdentifier\n");
        return 1;
    }
    // The specification says that the NULL is a required parameter for this
    // data type, but in practice it doesn't always exist in the ASN1. If
    // there is something after the ALGO OID, assume it's the NULL
    if(avail && (ret = asn1_expect_obj(map, &obj.next, &avail, ASN1_TYPE_NULL, 0, NULL))) {
        cli_dbgmsg("asn1_expect_hash_algo: expected NULL after AlgorithmIdentifier OID\n");
        return ret;
    }
    if(avail) {
        cli_dbgmsg("asn1_expect_hash_algo: extra data in AlgorithmIdentifier\n");
        return 1;
    }
    return 0;
}


static int asn1_expect_rsa(fmap_t *map, const void **asn1data, unsigned int *asn1len, cli_crt_hashtype *hashtype) {
    struct cli_asn1 obj;
    unsigned int avail;
    int ret;
    if((ret = asn1_expect_objtype(map, *asn1data, asn1len, &obj, ASN1_TYPE_SEQUENCE))) { /* SEQUENCE */
        cli_dbgmsg("asn1_expect_rsa: expecting SEQUENCE at the start of the RSA algo\n");
        return ret;
    }
    avail = obj.size;
    *asn1data = obj.next;

    if(asn1_expect_objtype(map, obj.content, &avail, &obj, ASN1_TYPE_OBJECT_ID)) {
        cli_dbgmsg("asn1_expect_rsa: expected OID in RSA algo\n");
        return 1;
    }

    // Two cases to check for:
    // obj.size == 5:
    //  - OID_sha1WithRSA
    //
    // obj.size == 9:
    //  - OID_rsaEncryption
    //  - OID_md2WithRSAEncryption
    //  - OID_md5WithRSAEncryption
    //  - OID_sha1WithRSAEncryption
    //  - OID_sha256WithRSAEncryption
    //  - OID_sha384WithRSAEncryption
    //  - OID_sha512WithRSAEncryption
    if(obj.size != lenof(OID_sha1WithRSA) && obj.size != lenof(OID_sha1WithRSAEncryption)) {
        cli_dbgmsg("asn1_expect_rsa: expecting OID with size 5 or 9, got %02x with size %u\n", obj.type, obj.size);
        return 1;
    }
    if(!fmap_need_ptr_once(map, obj.content, obj.size)) {
        cli_dbgmsg("asn1_expect_rsa: failed to read OID\n");
        return 1;
    }
    if(obj.size == lenof(OID_sha1WithRSA)) {

        if(!memcmp(obj.content, OID_sha1WithRSA, lenof(OID_sha1WithRSA))) {
            *hashtype = CLI_SHA1RSA; /* Obsolete sha1rsa 1.3.14.3.2.29 */
        }
        else {
            cli_dbgmsg("asn1_expect_rsa: unknown OID (length 5)\n");
            return 1;
        }

    } else if (obj.size == lenof(OID_sha1WithRSAEncryption)) {

        if(!memcmp(obj.content, OID_sha1WithRSAEncryption, lenof(OID_sha1WithRSAEncryption)))
            *hashtype = CLI_SHA1RSA; /* sha1withRSAEncryption 1.2.840.113549.1.1.5 */

        else if(!memcmp(obj.content, OID_md5WithRSAEncryption, lenof(OID_md5WithRSAEncryption)))
            *hashtype = CLI_MD5RSA; /* md5withRSAEncryption 1.2.840.113549.1.1.4 */

        else if(!memcmp(obj.content, OID_rsaEncryption, lenof(OID_rsaEncryption)))
            *hashtype = CLI_RSA; /* rsaEncryption 1.2.840.113549.1.1.1 */

        else if(!memcmp(obj.content, OID_md2WithRSAEncryption, lenof(OID_md2WithRSAEncryption))) {
            *hashtype = CLI_MD2RSA; /* md2withRSAEncryption 1.2.840.113549.1.1.2 */
        }
        else if(!memcmp(obj.content, OID_sha256WithRSAEncryption, lenof(OID_sha256WithRSAEncryption))) {
            *hashtype = CLI_SHA256RSA; /* sha256WithRSAEncryption 1.2.840.113549.1.1.11 */
        }
        else if(!memcmp(obj.content, OID_sha384WithRSAEncryption, lenof(OID_sha384WithRSAEncryption))) {
            *hashtype = CLI_SHA384RSA; /* sha384WithRSAEncryption 1.2.840.113549.1.1.12 */
        }
        else if(!memcmp(obj.content, OID_sha512WithRSAEncryption, lenof(OID_sha512WithRSAEncryption))) {
            *hashtype = CLI_SHA512RSA; /* sha512WithRSAEncryption 1.2.840.113549.1.1.13 */
        }
        else {
            cli_dbgmsg("asn1_expect_rsa: unknown OID (length 9)\n");
            return 1;
        }
    }
    else {
        cli_dbgmsg("asn1_expect_rsa: OID mismatch (size %u)\n", obj.size);
        return 1;
    }
    // The specification says that the NULL is a required parameter for this
    // data type, but in practice it doesn't always exist in the ASN1. If
    // there is something after the ALGO OID, assume it's the NULL
    if(avail && (ret = asn1_expect_obj(map, &obj.next, &avail, ASN1_TYPE_NULL, 0, NULL))) { /* NULL */
        cli_dbgmsg("asn1_expect_rsa: expected NULL following RSA OID\n");
        return ret;
    }
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

    if(asn1_expect_objtype(map, *asn1data, size, &obj, ASN1_TYPE_SEQUENCE)) /* subjectPublicKeyInfo */
        return 1;
    *asn1data = obj.next;

    avail = obj.size;
    if(asn1_expect_algo(map, &obj.content, &avail, lenof(OID_rsaEncryption), OID_rsaEncryption)) { /* rsaEncryption */
       cli_dbgmsg("asn1_get_rsa_pubkey: AlgorithmIdentifier other than RSA not yet supported\n");
       return 1;
    }

    if(asn1_expect_objtype(map, obj.content, &avail, &obj, ASN1_TYPE_BIT_STRING)) /* BIT STRING - subjectPublicKey */
        return 1;
    if(avail) {
        cli_dbgmsg("asn1_get_rsa_pubkey: found unexpected extra data in subjectPublicKeyInfo\n");
        return 1;
    }
    /* if(obj.size != 141 && obj.size != 271) /\* encoded len of 1024 and 2048 bit public keys *\/ */
    /*  return 1; */

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
    if(asn1_expect_objtype(map, obj.content, &avail, &obj, ASN1_TYPE_SEQUENCE)) /* SEQUENCE */
        return 1;
    if(avail) {
        cli_dbgmsg("asn1_get_rsa_pubkey: found unexpected extra data in public key content\n");
        return 1;
    }

    avail = obj.size;
    if(asn1_expect_objtype(map, obj.content, &avail, &obj, ASN1_TYPE_INTEGER)) /* INTEGER - mod */
        return 1;
    if(obj.size < 1024/8 || obj.size > 4096/8+1) {
        cli_dbgmsg("asn1_get_rsa_pubkey: modulus has got an unsupported length (%u)\n",  obj.size * 8);
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

    if(asn1_expect_objtype(map, obj.next, &avail, &obj, ASN1_TYPE_INTEGER)) /* INTEGER - exp */
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


#define ASN1_GET_X509_SUCCESS 0
#define ASN1_GET_X509_CERT_ERROR 1
#define ASN1_GET_X509_UNRECOVERABLE_ERROR 2

/* Parse the asn1data associated with an x509 certificate and add the cert
 * to the crtmgr certs if it doesn't already exist there.
 * ASN1_GET_X509_CERT_ERROR will be returned in the case that an invalid x509
 * certificate is encountered but asn1data and size are suitable for continued
 * signature parsing.  ASN1_GET_X509_UNRECOVERABLE_ERROR will be returned in
 * the case where asn1data and size are not suitable for continued use. */
static int asn1_get_x509(fmap_t *map, const void **asn1data, unsigned int *size, crtmgr *crts) {
    struct cli_asn1 crt, tbs, obj;
    unsigned int avail, tbssize, issuersize;
    cli_crt_hashtype hashtype1, hashtype2;
    cli_crt x509;
    const uint8_t *tbsdata;
    const void *next, *issuer;
    int ret = ASN1_GET_X509_UNRECOVERABLE_ERROR;
    unsigned int version;

    if(cli_crt_init(&x509))
        return ret;

    do {
        if(asn1_expect_objtype(map, *asn1data, size, &crt, ASN1_TYPE_SEQUENCE)) { /* SEQUENCE */
            cli_dbgmsg("asn1_get_x509: expected SEQUENCE at the x509 start\n");
            break;
        }
        *asn1data = crt.next;

        /* After this point, an error is recoverable because asn1data and size
         * will be suitable for continued use by the caller, so change ret */
        ret = ASN1_GET_X509_CERT_ERROR;

        tbsdata = crt.content;
        if(asn1_expect_objtype(map, crt.content, &crt.size, &tbs, ASN1_TYPE_SEQUENCE)) { /* SEQUENCE - TBSCertificate */
            cli_dbgmsg("asn1_get_x509: expected SEQUENCE at the TBSCertificate start\n");
            break;
        }
        tbssize = (uint8_t *)tbs.next - tbsdata;

        /* The version field of the x509 certificate is optional, defaulting
         * to 1 if the field is not present.  Version 3 is backward compatible,
         * adding the optional issuerUniqueID, sujectUniqueID, and extensions
         * fields.  We'll try to handle both cases, since the Windows API
         * appears to allow for both (despite the fact that the 2008 spec doc
         * says that v3 certificates are used for everything) */

        if (asn1_get_obj(map, tbs.content, &tbs.size, &obj)) {
            cli_dbgmsg("asn1_get_x509: failed to get first item in the TBSCertificate\n");
            break;
        }
        if(0xa0 == obj.type) { /* [0] */
            avail = obj.size;
            next = obj.next;
            // TODO Should we support v2 certs?  Supposedly they are not widely used...
            if(asn1_expect_obj(map, &obj.content, &avail, ASN1_TYPE_INTEGER, 1, "\x02")) { /* version 3 only (indicated by '\x02')*/
                cli_dbgmsg("asn1_get_x509: unexpected type or value for TBSCertificate version\n");
                break;
            }
            if(avail) {
                cli_dbgmsg("asn1_get_x509: found unexpected extra data in version\n");
                break;
            }
            version = 3;

            if(asn1_expect_objtype(map, next, &tbs.size, &obj, ASN1_TYPE_INTEGER)) { /* serialNumber */
                cli_dbgmsg("asn1_get_x509: expected x509 serial INTEGER\n");
                break;
            }
        } else if (ASN1_TYPE_INTEGER == obj.type) {
            /* The version field is missing, so we'll assume that this is a
             * version 1 certificate.  obj points to the serialNumber
             * INTEGER, then, so just continue on to map it. */
            version = 1;

            /* v1 certificates don't have enough information to convey the
             * purpose of the certificate.  I've only ever seen these used
             * in the timestamp signing chain, so set the flags to indicate
             * that. */
            x509.certSign = 1;
            x509.codeSign = 0;
            x509.timeSign = 1;

        } else {
            cli_dbgmsg("asn1_get_x509: expected version or serialNumber as the first item in TBSCertificate\n");
            break;
        }

        if(map_raw(map, obj.content, obj.size, x509.raw_serial))
            break;
        if(map_sha1(map, obj.content, obj.size, x509.serial))
            break;

        if(asn1_expect_rsa(map, &obj.next, &tbs.size, &hashtype1)) { /* algo - Ex: sha1WithRSAEncryption */
            cli_dbgmsg("asn1_get_x509: unable to parse AlgorithmIdentifier\n");
            break;
        }

        if(asn1_expect_objtype(map, obj.next, &tbs.size, &obj, ASN1_TYPE_SEQUENCE)) { /* issuer */
            cli_dbgmsg("asn1_get_x509: expected SEQUENCE when parsing cert issuer\n");
            break;
        }
        issuer = obj.content;
        issuersize = obj.size;

        if(asn1_expect_objtype(map, obj.next, &tbs.size, &obj, ASN1_TYPE_SEQUENCE)) { /* validity */
            cli_dbgmsg("asn1_get_x509: expected SEQUENCE when parsing cert validity\n");
            break;
        }
        avail = obj.size;
        next = obj.content;

        if(asn1_get_time(map, &next, &avail, &x509.not_before)) { /* notBefore */
            cli_dbgmsg("asn1_get_x509: unable to extract the notBefore time\n");
            break;
        }
        if(asn1_get_time(map, &next, &avail, &x509.not_after)) { /* notAfter */
            cli_dbgmsg("asn1_get_x509: unable to extract the notAfter time\n");
            break;
        }
        if(x509.not_before >= x509.not_after) {
            cli_dbgmsg("asn1_get_x509: bad validity\n");
            break;
        }
        if(avail) {
            cli_dbgmsg("asn1_get_x509: found unexpected extra data in validity\n");
            break;
        }

        if(asn1_expect_objtype(map, obj.next, &tbs.size, &obj, ASN1_TYPE_SEQUENCE)) { /* subject */
            cli_dbgmsg("asn1_get_x509: expected SEQUENCE when parsing cert subject\n");
            break;
        }
        if(map_raw(map, obj.content, obj.size, x509.raw_subject))
            break;
        if(map_sha1(map, obj.content, obj.size, x509.subject))
            break;
        if(asn1_get_rsa_pubkey(map, &obj.next, &tbs.size, &x509)) { /* subjectPublicKeyInfo */
            cli_dbgmsg("asn1_get_x509: failed to get RSA public key\n");
            break;
        }

        if (1 == version && tbs.size) {
            cli_dbgmsg("asn1_get_x509: TBSCertificate should not contain fields beyond subjectPublicKeyInfo if version == 1\n");
            break;
        }

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
                int have_key_usage = 0;
                int have_ext_key = 0;
                if(asn1_expect_objtype(map, obj.content, &obj.size, &exts, ASN1_TYPE_SEQUENCE)) {
                    tbs.size = 1;
                    break;
                }
                if(obj.size) {
                    cli_dbgmsg("asn1_get_x509: found unexpected extra data in extensions\n");
                    break;
                }
                while(exts.size) {
                    struct cli_asn1 ext, id, value;
                    if(asn1_expect_objtype(map, exts.content, &exts.size, &ext, ASN1_TYPE_SEQUENCE)) {
                        exts.size = 1;
                        break;
                    }
                    exts.content = ext.next;
                    if(asn1_expect_objtype(map, ext.content, &ext.size, &id, ASN1_TYPE_OBJECT_ID)) {
                        exts.size = 1;
                        break;
                    }
                    if(asn1_get_obj(map, id.next, &ext.size, &value)) {
                        exts.size = 1;
                        break;
                    }
                    if(value.type == ASN1_TYPE_BOOLEAN) {
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
                    if(value.type != ASN1_TYPE_OCTET_STRING) {
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
                        have_key_usage = 1;
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
                        if(asn1_expect_objtype(map, value.content, &value.size, &keypurp, ASN1_TYPE_SEQUENCE)) {
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
                            if(asn1_expect_objtype(map, ext.next, &keypurp.size, &ext, ASN1_TYPE_OBJECT_ID)) {
                                exts.size = 1;
                                break;
                            }
                            if(ext.size != 8 && ext.size != 10)
                                continue;
                            if(!fmap_need_ptr_once(map, ext.content, ext.size)) {
                                exts.size = 1;
                                break;
                            }
                            if(!memcmp("\x2b\x06\x01\x05\x05\x07\x03\x03", ext.content, 8)) /* id_kp_codeSigning */
                                x509.codeSign = 1;
                            else if(!memcmp("\x2b\x06\x01\x05\x05\x07\x03\x08", ext.content, 8)) /* id_kp_timeStamping */
                                x509.timeSign = 1;
                            else if(!memcmp("\x2b\x06\x01\x04\x01\x82\x37\x0a\x03\x0d", ext.content, 10)) /* id_kp_lifetimeSigning */
                                cli_dbgmsg("asn1_get_x509: lifetime signing specified but enforcing this is not currently supported\n");
                        }
                        continue;
                    }
                    if(!memcmp("\x55\x1d\x13", id.content, 3)) {
                        /* Basic Constraints 2.5.29.19 */
                        struct cli_asn1 constr;
                        if(asn1_expect_objtype(map, value.content, &value.size, &constr, ASN1_TYPE_SEQUENCE)) {
                            exts.size = 1;
                            break;
                        }
                        if(!constr.size)
                            x509.certSign = 0;
                        else {
                            if(asn1_expect_objtype(map, constr.content, &constr.size, &ext, ASN1_TYPE_BOOLEAN)) {
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

                /* The 2008 spec doc says that for a certificate to be used for
                 * code signing, it must either have an EKU indicating code
                 * signing or the entire certificate chain must not have any
                 * EKUs.
                 * TODO We should actually enforce that last check.
                 * For time stamping, the doc says the EKU must be present, and
                 * makes no exception for EKUs being missing.
                 * TODO Should we not set timeSign = 1 in this case, then? */
                if(!have_ext_key)
                    x509.codeSign = x509.timeSign = 1;

                /* RFC 3280 section 4.2.1.3 says that if a certificate is
                 * used to validate digital signatures on other public key
                 * certificates, it MUST have a key usage extension with the
                 * appropriate bits set.  However, the MS MD5 root authority
                 * certificate (A43489159A520F0D93D032CCAF37E7FE20A8B419)
                 * doesn't have a KU or any EKUs, and PEs with it in the
                 * chain validate successfully.
                 * TODO Flip the certSign bit for now, but revisit if
                 * a clarification on this becomes available */
                if(!have_key_usage)
                    x509.certSign = 1;
            }
        }
        if(tbs.size) {
            cli_dbgmsg("asn1_get_x509: An error occurred when parsing x509 extensions\n");
            break;
        }

        if (!x509.certSign && !x509.codeSign && !x509.timeSign) {
            cli_dbgmsg("asn1_get_x509: encountered a certificate with no cert, code, or time signing capabilities\n");
        }


        if(crtmgr_lookup(crts, &x509)) {
            cli_dbgmsg("asn1_get_x509: duplicate embedded certificates detected\n");
            cli_crt_clear(&x509);
            return ASN1_GET_X509_SUCCESS;
        }

        if(map_raw(map, issuer, issuersize, x509.raw_issuer))
            break;
        if(map_sha1(map, issuer, issuersize, x509.issuer))
            break;

        if(asn1_expect_rsa(map, &tbs.next, &crt.size, &hashtype2)) /* signature algo - Ex: sha1WithRSAEncryption */
            break;

        if(hashtype1 != hashtype2) {
            cli_dbgmsg("asn1_get_x509: found conflicting RSA hash types\n");
            break;
        }
        x509.hashtype = hashtype1;

        if(asn1_expect_objtype(map, tbs.next, &crt.size, &obj, ASN1_TYPE_BIT_STRING)) { /* signature */
            cli_dbgmsg("asn1_get_x509: Failed to parse x509 signature BIT STRING\n");
            break;
        }
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

        if(map_hash(map, tbsdata, tbssize, x509.tbshash, x509.hashtype)) {
            cli_dbgmsg("asn1_get_x509: Unsupported hashtype or hash computation failed\n");
            break;

        }

        if(crtmgr_add(crts, &x509))
            break;
        cli_crt_clear(&x509);
        return ASN1_GET_X509_SUCCESS;
    } while(0);
    cli_crt_clear(&x509);
    return ret;
}

static int asn1_parse_countersignature(fmap_t *map, const void **asn1data, unsigned int *size, crtmgr *cmgr, const uint8_t *message, const unsigned int message_size, time_t not_before, time_t not_after) {

    struct cli_asn1 asn1, deep, deeper;
    uint8_t issuer[SHA1_HASH_SIZE], serial[SHA1_HASH_SIZE];
    const uint8_t *attrs;
    unsigned int dsize, attrs_size;
    unsigned int avail;
    uint8_t hash[MAX_HASH_SIZE];
    cli_crt_hashtype hashtype;
    cli_crt_hashtype hashtype2;
    unsigned int hashsize;
    uint8_t md[MAX_HASH_SIZE];
    int result;
    void *ctx;

    do {
        if(asn1_expect_objtype(map, *asn1data, size, &asn1, ASN1_TYPE_SEQUENCE)) {
            cli_dbgmsg("asn1_parse_countersignature: expected SEQUENCE inside counterSignature SET\n");
            break;
        }

        avail = asn1.size;

        if (asn1_expect_objtype(map, asn1.content, &avail, &deep, ASN1_TYPE_INTEGER)) {
            cli_dbgmsg("asn1_parse_countersignature: expected INTEGER for counterSignature version");
            break;
        }

        if(deep.size != 1) {
            cli_dbgmsg("asn1_parse_countersignature: expected INTEGER of size 1, got size %u\n", deep.size);
            break;
        }

        if(!fmap_need_ptr_once(map, deep.content, 1)) {
            cli_dbgmsg("asn1_parse_countersignature: failed to read version\n");
            break;
        }
        /* Allow either '0' or '1' for the version. The specification says
         * that this field must be 1, but some binaries have 0 here and
         * they appear to validate just fine via the Windows API */
        if(memcmp(deep.content, "\x01", 1) && memcmp(deep.content, "\x00", 1)) {
            cli_dbgmsg("asn1_parse_countersignature: counterSignature version is not 1 or 0\n");
            break;
        }
        asn1.content = deep.next;

        if(asn1_expect_objtype(map, asn1.content, &avail, &asn1, ASN1_TYPE_SEQUENCE)) { /* issuerAndSerialNumber */
            cli_dbgmsg("asn1_parse_countersignature: unable to parse issuerAndSerialNumber SEQUENCE in counterSignature\n");
            break;
        }

        if(asn1_expect_objtype(map, asn1.content, &asn1.size, &deep, ASN1_TYPE_SEQUENCE)) { /* issuer */
            cli_dbgmsg("asn1_parse_countersignature: unable to parse issuer SEQUENCE in counterSignature\n");
            break;
        }
        // Compute the hash of the issuer section
        if(map_sha1(map, deep.content, deep.size, issuer)) {
            cli_dbgmsg("asn1_parse_countersignature: error in call to map_sha1 for counterSignature issuer\n");
            break;
        }

        if(asn1_expect_objtype(map, deep.next, &asn1.size, &deep, ASN1_TYPE_INTEGER)) { /* serial */
            cli_dbgmsg("asn1_parse_countersignature: expected ASN1_TYPE_INTEGER serial for counterSignature\n");
            break;
        }

        // Compute the hash of the serial INTEGER
        if(map_sha1(map, deep.content, deep.size, serial)) {
            cli_dbgmsg("asn1_parse_countersignature: error in call to map_sha1 for counterSignature serial\n");
            break;
        }

        if(asn1.size) {
            cli_dbgmsg("asn1_parse_countersignature: extra data inside counterSignature issuer\n");
            break;
        }

        if(asn1_expect_hash_algo(map, &asn1.next, &avail, &hashtype, &hashsize)) {
            cli_dbgmsg("asn1_parse_countersignature: error parsing counterSignature digestAlgorithm\n");
            break;
        }

        if(map_hash(map, message, message_size, md, hashtype)) {
            cli_dbgmsg("asn1_parse_countersignature: failed to map in message/compute countersignature hash\n");
            break;

        }

        attrs = asn1.next;
        if(asn1_expect_objtype(map, asn1.next, &avail, &asn1, 0xa0)) { /* authenticatedAttributes */
            cli_dbgmsg("asn1_parse_countersignature: unable to parse counterSignature authenticatedAttributes section\n");
            break;
        }
        attrs_size = (uint8_t *)(asn1.next) - attrs;
        if(asn1.next == NULL && attrs_size < 2) {
            cli_dbgmsg("asn1_parse_countersignature: counterSignature authenticatedAttributes are too small\n");
            break;
        }
        result = 0;
        dsize = asn1.size;
        deep.next = asn1.content;
        while(dsize) {
            int content;
            if(asn1_expect_objtype(map, deep.next, &dsize, &deep, ASN1_TYPE_SEQUENCE)) { /* attribute */
                cli_dbgmsg("asn1_parse_countersignature: expected counterSignature attribute SEQUENCE\n");
                dsize = 1;
                break;
            }
            if(asn1_expect_objtype(map, deep.content, &deep.size, &deeper, ASN1_TYPE_OBJECT_ID)) { /* attribute type */
                cli_dbgmsg("asn1_parse_countersignature: expected attribute type inside counterSignature attribute SEQUENCE\n");
                dsize = 1;
                break;
            }
            if(deeper.size != lenof(OID_contentType)) /* lenof(contentType) = lenof(messageDigest) = lenof(signingTime) = 9 */
                continue;

            if(!fmap_need_ptr_once(map, deeper.content, lenof(OID_contentType))) {
                cli_dbgmsg("asn1_parse_countersignature: failed to read counterSignature authenticated attribute\n");
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
                cli_dbgmsg("asn1_parse_countersignature: duplicate field in countersignature\n");
                dsize = 1;
                break;
            }
            result |= (1<<content);
            if(asn1_expect_objtype(map, deeper.next, &deep.size, &deeper, ASN1_TYPE_SET)) { /* set - contents */
                cli_dbgmsg("asn1_parse_countersignature: failed to read counterSignature authenticated attribute\n");
                dsize = 1;
                break;
            }
            if(deep.size) {
                cli_dbgmsg("asn1_parse_countersignature: extra data in countersignature value\n");
                dsize = 1;
                break;
            }
            deep.size = deeper.size;
            switch(content) {
            case 0:
            {  /* contentType = pkcs7-data */
                const void *backupPtr = deeper.content;
                unsigned int backupSize = deep.size;
                if(asn1_expect_obj(map, &deeper.content, &deep.size, ASN1_TYPE_OBJECT_ID, lenof(OID_pkcs7_data), OID_pkcs7_data)) {
                    cli_dbgmsg("asn1_parse_countersignature: contentType != pkcs7-data, checking for timestampToken instead\n");
                    /* Some signatures use OID_timestampToken instead, so allow
                     * that also (despite the 2008 spec saying that this value
                     * must be pkcs7-data) */
                    deeper.content = backupPtr;
                    deep.size = backupSize;
                    if(asn1_expect_obj(map, &deeper.content, &deep.size, ASN1_TYPE_OBJECT_ID, lenof(OID_timestampToken), OID_timestampToken)) {
                        cli_dbgmsg("asn1_parse_countersignature: contentType != timestampToken\n");
                        deep.size = 1;
                        break;
                    }
                }

                if(deep.size)
                    cli_dbgmsg("asn1_parse_countersignature: extra data in countersignature content-type\n");
                break;
            }
            case 1:  /* messageDigest */
                if(asn1_expect_obj(map, &deeper.content, &deep.size, ASN1_TYPE_OCTET_STRING, hashsize, md)) {
                    deep.size = 1;
                    cli_dbgmsg("asn1_parse_countersignature: countersignature hash mismatch\n");
                } else if(deep.size)
                    cli_dbgmsg("asn1_parse_countersignature: extra data in countersignature message-digest\n");
                break;
            case 2:  /* signingTime */
                {
                    time_t sigdate; /* FIXME shall i use it?! */
                    if(asn1_get_time(map, &deeper.content, &deep.size, &sigdate)) {
                        cli_dbgmsg("asn1_parse_countersignature: an error occurred when getting the time\n");
                        deep.size = 1;
                    } else if(deep.size)
                        cli_dbgmsg("asn1_parse_countersignature: extra data in countersignature signing-time\n");
                    else if(sigdate < not_before || sigdate > not_after) {
                        cli_dbgmsg("asn1_parse_countersignature: countersignature timestamp outside cert validity\n");
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
            cli_dbgmsg("asn1_parse_countersignature: some important attributes are missing in countersignature\n");
            break;
        }

        // TODO For some reason there tends to be more variability here than
        // when parsing the regular signature - we have to support at least
        // szOID_RSA_RSA and szOID_RSA_SHA1RSA based on samples seen in the
        // wild.  The spec says this should only be the RSA and DSA OIDs,
        // though.
        if (asn1_expect_rsa(map, &asn1.next, &avail, &hashtype2)) {
            cli_dbgmsg("asn1_parse_countersignature: unable to parse the digestEncryptionAlgorithm\n");
            break;
        }

        if (hashtype2 != CLI_RSA && hashtype2 != hashtype) {
            cli_dbgmsg("asn1_parse_countersignature: digestEncryptionAlgorithm conflicts with digestAlgorithm\n");
            break;
        }

        if(asn1_expect_objtype(map, asn1.next, &avail, &asn1, ASN1_TYPE_OCTET_STRING)) { /* encryptedDigest */
            cli_dbgmsg("asn1_parse_countersignature: unexpected encryptedDigest value in counterSignature\n");
            break;
        }
        if(asn1.size > 513) {
            cli_dbgmsg("asn1_parse_countersignature: countersignature encryptedDigest too long\n");
            break;
        }
        if(avail) {
            cli_dbgmsg("asn1_parse_countersignature: extra data inside countersignature\n");
            break;
        }
        if(!fmap_need_ptr_once(map, attrs, attrs_size)) {
            cli_dbgmsg("asn1_parse_countersignature: failed to read authenticatedAttributes\n");
            break;
        }

        if (NULL == (ctx = get_hash_ctx(hashtype))) {
            break;
        }

        cl_update_hash(ctx, "\x31", 1);
        cl_update_hash(ctx, (void *)(attrs + 1), attrs_size - 1);
        cl_finish_hash(ctx, hash);

        if(!fmap_need_ptr_once(map, asn1.content, asn1.size)) {
            cli_dbgmsg("asn1_parse_countersignature: failed to read countersignature encryptedDigest\n");
            break;
        }
        if(!crtmgr_verify_pkcs7(cmgr, issuer, serial, asn1.content, asn1.size, hashtype, hash, VRFY_TIME)) {
            cli_dbgmsg("asn1_parse_countersignature: pkcs7 countersignature verification failed\n");
            break;
        }

        cli_dbgmsg("asn1_parse_countersignature: countersignature verification completed successfully\n");

        return 0;

    } while(0);

    return 1;
}

static cl_error_t asn1_parse_mscat(fmap_t *map, size_t offset, unsigned int size, crtmgr *cmgr, int embedded, const void **hashes, unsigned int *hashes_size, struct cl_engine *engine) {
    struct cli_asn1 asn1, deep, deeper;
    uint8_t issuer[SHA1_HASH_SIZE], serial[SHA1_HASH_SIZE];
    const uint8_t *message, *attrs;
    unsigned int dsize, message_size, attrs_size;
    // hash is used to hold the hashes we compute as part of sig verification
    uint8_t hash[MAX_HASH_SIZE];
    cli_crt_hashtype hashtype, hashtype2;
    unsigned int hashsize;
    // md is used to hold the message digest we extract from the signature
    uint8_t md[MAX_HASH_SIZE];
    cli_crt *x509;
    void *ctx;
    int result;
    cl_error_t ret = CL_EPARSE;

    cli_dbgmsg("in asn1_parse_mscat\n");

    do {
        if(!(message = fmap_need_off_once(map, offset, 1))) {
            cli_dbgmsg("asn1_parse_mscat: failed to read pkcs#7 entry\n");
            break;
        }

        if(asn1_expect_objtype(map, message, &size, &asn1, ASN1_TYPE_SEQUENCE)){ /* SEQUENCE */
            cli_dbgmsg("asn1_parse_mscat: expected SEQUENCE at top level\n");
            break;
        }

        // Many signatures have zero bytes at the end (padding?)
        /* if(size) { */
        /*     cli_dbgmsg("asn1_parse_mscat: found extra data after pkcs#7 %u\n", size); */
        /*     break; */
        /* } */
        size = asn1.size;
        if(asn1_expect_obj(map, &asn1.content, &size, ASN1_TYPE_OBJECT_ID, lenof(OID_signedData), OID_signedData)){ /* OBJECT 1.2.840.113549.1.7.2 - contentType = signedData */
            cli_dbgmsg("asn1_parse_mscat: expected contentType == signedData\n");
            break;
        }
        if(asn1_expect_objtype(map, asn1.content, &size, &asn1, 0xa0)){ /* [0] - content */
            cli_dbgmsg("asn1_parse_mscat: expected '[0] - content' following signedData contentType\n");
            break;
        }
        if(size) {
            cli_dbgmsg("asn1_parse_mscat: found extra data in pkcs#7\n");
            break;
        }
        size = asn1.size;
        if(asn1_expect_objtype(map, asn1.content, &size, &asn1, ASN1_TYPE_SEQUENCE)){ /* SEQUENCE */
            cli_dbgmsg("asn1_parse_mscat: expected SEQUENCE inside signedData '[0] - content'\n");
            break;
        }
        if(size) {
            cli_dbgmsg("asn1_parse_mscat: found extra data in signedData\n");
            break;
        }

        size = asn1.size;
        if(asn1_expect_obj(map, &asn1.content, &size, ASN1_TYPE_INTEGER, 1, "\x01")){ /* INTEGER - VERSION 1 */
            cli_dbgmsg("asn1_parse_mscat: expected 'INTEGER - VERSION 1' for signedData version\n");
            break;
        }

        if(asn1_expect_objtype(map, asn1.content, &size, &asn1, ASN1_TYPE_SET)){ /* SET OF DigestAlgorithmIdentifier */
            cli_dbgmsg("asn1_parse_mscat: expected SET OF DigestAlgorithmIdentifier inside signedData\n");
            break;
        }

        // At this point asn1.next points to the SEQUENCE following the
        // DigestAlgorithmIdentifier SET, so we'll want to preserve it so
        // we can continue parsing laterally.  We also want to preserve
        // size, since it tracks how much is left in the SignedData section.
        if (asn1_expect_hash_algo(map, &asn1.content, &asn1.size, &hashtype, &hashsize)) {
            cli_dbgmsg("asn1_parse_mscat: error parsing SignedData digestAlgorithm\n");
            break;
        }
        if (asn1.size) {
            cli_dbgmsg("asn1_parse_mscat: found extra data in the SignerData digestAlgorithm SET\n");
            break;
        }

        // We've finished parsing the DigestAlgorithmIdentifiers SET, so start
        // back parsing the SignedData
        if(asn1_expect_objtype(map, asn1.next, &size, &asn1, ASN1_TYPE_SEQUENCE)){ /* SEQUENCE - contentInfo */
            cli_dbgmsg("asn1_parse_mscat: expected 'SEQUENCE - contentInfo' inside SignedData following DigestAlgorithmIdentifiers\n");
            break;
        }
        // Parse the contentInfo SEQUENCE.  asn1.next and size point to the
        // certificates, so these need to be preserved

        /* Here there is either a PKCS #7 ContentType Object Identifier for Certificate Trust List (szOID_CTL)
         * or a single SPC_INDIRECT_DATA_OBJID */
        if(
           (!embedded && asn1_expect_obj(map, &asn1.content, &asn1.size, ASN1_TYPE_OBJECT_ID, lenof(OID_szOID_CTL), OID_szOID_CTL)) ||
           (embedded && asn1_expect_obj(map, &asn1.content, &asn1.size, ASN1_TYPE_OBJECT_ID, lenof(OID_SPC_INDIRECT_DATA_OBJID), OID_SPC_INDIRECT_DATA_OBJID))
           ){
            cli_dbgmsg("asn1_parse_mscat: unexpected ContentType for embedded mode %d\n", embedded);
            break;
        }

        if(asn1_expect_objtype(map, asn1.content, &asn1.size, &deep, 0xa0)){
            cli_dbgmsg("asn1_parse_mscat: expected '[0] - content' following DigestAlgorithmIdentifier contentType\n");
            break;
        }
        if(asn1.size) {
            cli_dbgmsg("asn1_parse_mscat: found extra data in contentInfo\n");
            break;
        }
        dsize = deep.size;
        if(asn1_expect_objtype(map, deep.content, &dsize, &deep, ASN1_TYPE_SEQUENCE))
        {
            cli_dbgmsg("asn1_parse_mscat: expected SEQUENCE in DigestAlgorithmIdentifier '[0] - contentInfo'\n");
            break;
        }
        if(dsize) {
            cli_dbgmsg("asn1_parse_mscat: found extra data in content\n");
            break;
        }

        /*
         * Hashes should look like:
         * SEQUENCE(2 elem)
         *    OBJECT IDENTIFIER 1.3.6.1.4.1.311.2.1.15 spcPEImageData
         *    SEQUENCE(2 elem)
         *        BIT STRING(0 elem)
         *        [0](1 elem)
         *            [2](1 elem)
         *                [0]
         * SEQUENCE(2 elem)
         *    SEQUENCE(2 elem)
         *        OBJECT IDENTIFIER 1.3.14.3.2.26 sha1 (OIW)
         *        NULL
         *    OCTET STRING(20 byte)
         */

        *hashes = deep.content;
        *hashes_size = deep.size;

        // Now resume parsing SignedData - certificates

        if(asn1_expect_objtype(map, asn1.next, &size, &asn1, 0xa0)){ /* certificates */
            cli_dbgmsg("asn1_parse_mscat: expected 0xa0 certificates entry\n");
            break;
        }

        dsize = asn1.size;
        if(dsize) {
            crtmgr newcerts;
            crtmgr_init(&newcerts);
            while(dsize) {
                result = asn1_get_x509(map, &asn1.content, &dsize, &newcerts);
                if(ASN1_GET_X509_UNRECOVERABLE_ERROR == result) {
                    dsize = 1;
                    break;
                }
                else if(ASN1_GET_X509_CERT_ERROR == result) {
                    cli_dbgmsg("asn1_parse_mscat: skipping x509 certificate with errors\n");
                }
            }
            if(dsize) {
                crtmgr_free(&newcerts);
                cli_dbgmsg("asn1_parse_mscat: an unrecoverable error occurred while extracting x509 certificates\n");
                break;
            }
            if(newcerts.crts) {
                x509 = newcerts.crts;
                cli_dbgmsg("asn1_parse_mscat: %u embedded certificates collected\n", newcerts.items);
                if (engine->engine_options & ENGINE_OPTIONS_PE_DUMPCERTS) {
                    /* Dump the certs if requested before anything happens to them */
                    while(x509) {
                        char raw_issuer[CRT_RAWMAXLEN*2+1], raw_subject[CRT_RAWMAXLEN*2+1], raw_serial[CRT_RAWMAXLEN*3+1];
                        char issuer[SHA1_HASH_SIZE*2+1], subject[SHA1_HASH_SIZE*2+1], serial[SHA1_HASH_SIZE*2+1];
                        char mod[1024+1], exp[1024+1];
                        int j=1024;

                        fp_toradix_n(&x509->n, mod, 16, j+1);
                        fp_toradix_n(&x509->e, exp, 16, j+1);
                        memset(raw_issuer, 0, CRT_RAWMAXLEN*2+1);
                        memset(raw_subject, 0, CRT_RAWMAXLEN*2+1);
                        memset(raw_serial, 0, CRT_RAWMAXLEN*2+1);
                        for (j=0; j < x509->raw_issuer[0]; j++)
                            sprintf(&raw_issuer[j*2], "%02x", x509->raw_issuer[j+1]);
                        for (j=0; j < x509->raw_subject[0]; j++)
                            sprintf(&raw_subject[j*2], "%02x", x509->raw_subject[j+1]);
                        for (j=0; j < x509->raw_serial[0]; j++)
                            sprintf(&raw_serial[j*3], "%02x%c", x509->raw_serial[j+1], (j != x509->raw_serial[0]-1) ? ':' : '\0');
                        for (j=0; j < SHA1_HASH_SIZE; j++) {
                            sprintf(&issuer[j*2], "%02x", x509->issuer[j]);
                            sprintf(&subject[j*2], "%02x", x509->subject[j]);
                            sprintf(&serial[j*2], "%02x", x509->serial[j]);
                        }

                        cli_dbgmsg_internal("cert:\n");
                        cli_dbgmsg_internal("  subject: %s\n", subject);
                        cli_dbgmsg_internal("  serial: %s\n", serial);
                        cli_dbgmsg_internal("  pubkey: %s\n", mod);
                        cli_dbgmsg_internal("  i: %s %lu->%lu %s%s%s\n", issuer, (unsigned long)x509->not_before, (unsigned long)x509->not_after, x509->codeSign ? "code " : "", x509->timeSign ? "time " : "", x509->certSign ? "cert " : "");
                        cli_dbgmsg_internal("  ==============RAW==============\n");
                        cli_dbgmsg_internal("  raw_subject: %s\n", raw_subject);
                        cli_dbgmsg_internal("  raw_serial: %s\n", raw_serial);
                        cli_dbgmsg_internal("  raw_issuer: %s\n", raw_issuer);

                        x509 = x509->next;
                    }
                    x509 = newcerts.crts;
                }

                while(x509) {
                    cli_crt *parent;

                    /* If the certificate is in the trust store already, remove
                     * it from the newcerts list */
                    if (crtmgr_lookup(cmgr, x509)) {
                        cli_crt *tmp = x509->next;
                        cli_dbgmsg("asn1_parse_mscat: found embedded certificate matching one in the trust store\n");
                        crtmgr_del(&newcerts, x509);
                        x509 = tmp;
                        continue;
                    }

                    /* Determine whether the cert is signed by one in our trust
                     * store or has a blacklist entry */
                    parent = crtmgr_verify_crt(cmgr, x509);

                    if(parent) {
                        if (parent->isBlacklisted) {
                            // NOTE: In this case, parent is a blacklist entry
                            // in cmgr for this certificate, not a blacklist
                            // entry for this certificate's parent
                            ret = CL_VIRUS;
                            cli_dbgmsg("asn1_parse_mscat: Authenticode certificate %s is revoked. Flagging sample as virus.\n", (parent->name ? parent->name : "(no name)"));
                            crtmgr_free(&newcerts);
                            goto finish;
                        }

                        // TODO Why is this done?
                        x509->codeSign &= parent->codeSign;
                        x509->timeSign &= parent->timeSign;

                        if(crtmgr_add(cmgr, x509)) {
                            cli_dbgmsg("asn1_parse_mscat: adding x509 cert to crtmgr failed\n");
                            break;
                        }
                        crtmgr_del(&newcerts, x509);

                        /* Start at the beginning of newcerts so that we can see
                         * whether adding this new trusted cert causes more
                         * certs to be trusted (via chaining).  Otherwise we
                         * might miss valid certs if the ordering in the binary
                         * doesn't align with the chain ordering. */
                        x509 = newcerts.crts;
                        continue;
                    }

                    x509 = x509->next;
                }
                if(x509) {
                    crtmgr_free(&newcerts);
                    break;
                }
                if(newcerts.items)
                    cli_dbgmsg("asn1_parse_mscat: %u certificates did not verify\n", newcerts.items);
                crtmgr_free(&newcerts);
            }
        }

        // Parse the final section in SignedData - SignerInfos
        if(asn1_get_obj(map, asn1.next, &size, &asn1)) {
            cli_dbgmsg("asn1_parse_mscat: failed to get next ASN1 section\n");
            break;
        }
        if(asn1.type == 0xa1 && asn1_get_obj(map, asn1.next, &size, &asn1)){ /* crls - unused shouldn't be present */
            cli_dbgmsg("asn1_parse_mscat: unexpected CRL entries were found\n");
            break;
        }
        if(asn1.type != ASN1_TYPE_SET) { /* signerInfos */
            cli_dbgmsg("asn1_parse_mscat: unexpected type %02x for signerInfo\n", asn1.type);
            break;
        }
        if(size) {
            cli_dbgmsg("asn1_parse_mscat: unexpected extra data after signerInfos\n");
            break;
        }
        size = asn1.size;
        if(asn1_expect_objtype(map, asn1.content, &size, &asn1, ASN1_TYPE_SEQUENCE)) {
            cli_dbgmsg("asn1_parse_mscat: expected SEQUENCE in signerInfos");
            break;
        }
        if(size) {
            cli_dbgmsg("asn1_parse_mscat: only one signerInfo shall be present\n");
            break;
        }
        size = asn1.size;
        if(asn1_expect_obj(map, &asn1.content, &size, ASN1_TYPE_INTEGER, 1, "\x01")){ /* Version = 1 */
            cli_dbgmsg("asn1_parse_mscat: expected Version == 1 for signerInfo\n");
            break;
        }
        if(asn1_expect_objtype(map, asn1.content, &size, &asn1, ASN1_TYPE_SEQUENCE)){ /* issuerAndSerialNumber */
            cli_dbgmsg("asn1_parse_mscat: expected issuerAndSerialNumber SEQUENCE\n");
            break;
        }
        // asn1.next and size must be preserved so we can continue parsing
        // SignerInfos, so switch to deep
        dsize = asn1.size;
        if(asn1_expect_objtype(map, asn1.content, &dsize, &deep, ASN1_TYPE_SEQUENCE)){ /* issuer */
            cli_dbgmsg("asn1_parse_mscat: expected issuer SEQUENCE\n");
            break;
        }

        /* Make sure the issuer ID is mapped into memory and then compute the
         * SHA1 of it so we can use this value in verification later on. This
         * will be a hash over all the values in the issuer SEQUENCE, which
         * looks something like:
         * SET(1 elem)
         *     SEQUENCE(2 elem)
         *         OBJECT IDENTIFIER 2.5.4.6 countryName (X.520 DN component)
         *         PrintableString
         * SET(1 elem)
         *     SEQUENCE(2 elem)
         *         OBJECT IDENTIFIER2.5.4.8 stateOrProvinceName (X.520 DN component)
         *         PrintableString
         * SET(1 elem)
         *     SEQUENCE(2 elem)
         *         OBJECT IDENTIFIER2.5.4.7 localityName (X.520 DN component)
         *         PrintableString
         * SET(1 elem)
         *     SEQUENCE(2 elem)
         *         OBJECT IDENTIFIER2.5.4.10 organizationName (X.520 DN component)
         *         PrintableString
         * SET(1 elem)
         *     SEQUENCE(2 elem)
         *         OBJECT IDENTIFIER2.5.4.3commonName(X.520 DN component)
         *         PrintableString
         */
        if(map_sha1(map, deep.content, deep.size, issuer)){
            cli_dbgmsg("asn1_parse_mscat: error in call to map_sha1 for issuer\n");
            break;
        }

        if(asn1_expect_objtype(map, deep.next, &dsize, &deep, ASN1_TYPE_INTEGER)){ /* serial */
            cli_dbgmsg("asn1_parse_mscat: expected ASN1_TYPE_INTEGER serial\n");
            break;
        }

        /* Make sure the serial INTEGER is mapped into memory and compute the
         * SHA1 of it so we can use this value in verification later on. */
        if(map_sha1(map, deep.content, deep.size, serial)){
            cli_dbgmsg("asn1_parse_mscat: error in call to map_sha1 for serial\n");
            break;
        }
        if(dsize) {
            cli_dbgmsg("asn1_parse_mscat: extra data inside issuerAndSerialNumber\n");
            break;
        }

        // Resume parsing the SignerInfos using asn1.next and size
        if (asn1_expect_hash_algo(map, &asn1.next, &size, &hashtype2, &hashsize)) {
            cli_dbgmsg("asn1_parse_mscat: error parsing SignerInfo digestAlgorithm\n");
            break;
        }

        // Verify that the SignerInfo digestAlgorithm matches the one from the SignedData section
        if (hashtype != hashtype2) {
                cli_dbgmsg("asn1_parse_mscat: SignerInfo digestAlgorithm is not the same as the algorithm in SignedData\n");
                break;
        }

        // Continue on to the authenticatedAttributes section within SignerInfo
        attrs = asn1.next;
        if(asn1_expect_objtype(map, asn1.next, &size, &asn1, 0xa0)){ /* authenticatedAttributes */
            cli_dbgmsg("asn1_parse_mscat: unable to parse authenticatedAttributes section\n");
            break;
        }
        attrs_size = (uint8_t *)(asn1.next) - attrs;
        if(asn1.next == NULL || attrs_size < 2) {
            cli_dbgmsg("asn1_parse_mscat: authenticatedAttributes size is too small\n");
            break;
        }

        dsize = asn1.size;
        deep.next = asn1.content;
        result = 0;
        while(dsize) {
            struct cli_asn1 cobj;
            int content;
            if(asn1_expect_objtype(map, deep.next, &dsize, &deep, ASN1_TYPE_SEQUENCE)) { /* attribute */
                cli_dbgmsg("asn1_parse_mscat: expected attribute SEQUENCE\n");
                dsize = 1;
                break;
            }
            if(asn1_expect_objtype(map, deep.content, &deep.size, &deeper, ASN1_TYPE_OBJECT_ID)) { /* attribute type */
                cli_dbgmsg("asn1_parse_mscat: expected attribute type inside attribute SEQUENCE\n");
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
            if(asn1_expect_objtype(map, deeper.next, &deep.size, &deeper, ASN1_TYPE_SET)) { /* set - contents */
                cli_dbgmsg("asn1_parse_mscat: expected 'set - contents' for authenticated attribute\n");
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
                   (!embedded && asn1_expect_obj(map, &deeper.content, &deeper.size, ASN1_TYPE_OBJECT_ID, lenof(OID_szOID_CTL), OID_szOID_CTL)) || /* cat file */
                   (embedded && asn1_expect_obj(map, &deeper.content, &deeper.size, ASN1_TYPE_OBJECT_ID, lenof(OID_SPC_INDIRECT_DATA_OBJID), OID_SPC_INDIRECT_DATA_OBJID)) /* embedded cat */
                  ) {
                    cli_dbgmsg("asn1_parse_mscat: unexpected ContentType for embedded mode %d (for authenticated attribute)\n", embedded);
                    dsize = 1;
                    break;
                }
                result |= 1;
            } else { /* messageDigest */
                if(asn1_expect_objtype(map, deeper.content, &deeper.size, &cobj, ASN1_TYPE_OCTET_STRING)) {
                    cli_dbgmsg("asn1_parse_mscat: unexpected messageDigest value\n");
                    dsize = 1;
                    break;
                }
                if(cobj.size != hashsize) {
                    cli_dbgmsg("asn1_parse_mscat: messageDigest attribute has the wrong size (%u)\n", cobj.size);
                    dsize = 1;
                    break;
                }
                if(!fmap_need_ptr_once(map, cobj.content, hashsize)) {
                    cli_dbgmsg("asn1_parse_mscat: failed to read authenticated attribute\n");
                    dsize = 1;
                    break;
                }
                memcpy(md, cobj.content, hashsize);
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

        if(asn1_expect_algo(map, &asn1.next, &size, lenof(OID_rsaEncryption), OID_rsaEncryption)) { /* digestEncryptionAlgorithm == rsa */
            cli_dbgmsg("asn1_parse_mscat: digestEncryptionAlgorithms other than RSA are not yet supported\n");
            break;
        }

        if(asn1_expect_objtype(map, asn1.next, &size, &asn1, ASN1_TYPE_OCTET_STRING)) { /* encryptedDigest */
            cli_dbgmsg("asn1_parse_mscat: unexpected encryptedDigest value\n");
            break;
        }

        // TODO Make this a #define with the greatest possible length (SHA512)
        if(asn1.size > 513) {
            cli_dbgmsg("asn1_parse_mscat: encryptedDigest too long\n");
            break;
        }

        if(map_hash(map, *hashes, *hashes_size, hash, hashtype)) {
            cli_dbgmsg("asn1_parse_mscat: failed to map in message/compute message digest\n");
            break;

        }

        if(memcmp(hash, md, hashsize)) {
            cli_dbgmsg("asn1_parse_mscat: messageDigest mismatch\n");
            break;
        }

        if(!fmap_need_ptr_once(map, attrs, attrs_size)) {
            cli_dbgmsg("asn1_parse_mscat: failed to read authenticatedAttributes\n");
            break;
        }

        if (NULL == (ctx = get_hash_ctx(hashtype))) {
            break;
        }

        cl_update_hash(ctx, "\x31", 1);
        cl_update_hash(ctx, (void *)(attrs + 1), attrs_size - 1);
        cl_finish_hash(ctx, hash);

        if(!fmap_need_ptr_once(map, asn1.content, asn1.size)) {
            cli_dbgmsg("asn1_parse_mscat: failed to read encryptedDigest\n");
            break;
        }

        // Verify the authenticatedAttributes
        if(!(x509 = crtmgr_verify_pkcs7(cmgr, issuer, serial, asn1.content, asn1.size, hashtype, hash, VRFY_CODE))) {
            cli_dbgmsg("asn1_parse_mscat: pkcs7 signature verification failed\n");
            ret = CL_EVERIFY;
            break;
        }
        message = asn1.content;
        message_size = asn1.size;

        cli_dbgmsg("asn1_parse_mscat: authenticatedAttributes successfully parsed and verified\n");

        /* We need to verify the time validity of the certificate.  If a
         * signature has a time-stamping countersignature, then we just need to
         * verify that countersignature.  Otherwise, we should determine
         * whether the signing certificate is still valid (time-based, since at
         * this point in the code no matching blacklist rules fired). */

        if(!size) {
            time_t now;

            // No countersignature, so judge validity based on time
            now = time(NULL);

            if(now < x509->not_before || now > x509->not_after) {
                cli_dbgmsg("asn1_parse_mscat: no countersignature (unauthAttrs missing) and signing certificate has expired\n");
                ret = CL_EVERIFY;
                break;
            }

            cli_dbgmsg("asn1_parse_mscat: no countersignature (unauthAttrs missing) but the signing certificate is still valid\n");
            ret = CL_CLEAN;
            goto finish;
        }

        if(size && asn1_expect_objtype(map, asn1.next, &size, &asn1, 0xa1)) { /* unauthenticatedAttributes */
            cli_dbgmsg("asn1_parse_mscat: unable to find unauthenticatedAttributes section\n");
            break;
        }

        if(size) {
            cli_dbgmsg("asn1_parse_mscat: extra data inside signerInfo\n");
            break;
        }

        // Parse the unauthenticated attributes

        dsize = asn1.size;
        deep.next = asn1.content;
        result = 0;
        while(dsize) {
            int content;
            if(asn1_expect_objtype(map, deep.next, &dsize, &deep, ASN1_TYPE_SEQUENCE)) {
                cli_dbgmsg("asn1_parse_mscat: expected SEQUENCE starting an unauthenticatedAttribute\n");
                dsize = 1;
                break;
            }
            if(asn1_expect_objtype(map, deep.content, &deep.size, &deeper, ASN1_TYPE_OBJECT_ID)) {
                cli_dbgmsg("asn1_parse_mscat: expected OID inside unauthenticatedAttribute SEQUENCE\n");
                dsize = 1;
                break;
            }
            // Supported OIDs include:
            // - 1.2.840.113549.1.9.6 - counterSignature
            // - 1.3.6.1.4.1.311.2.4.1 - nested signatures

            // I've seen some other ones like 1.3.6.1.4.1.3845.3.9876.1.1.1,
            // and the presence of those doesn't seem to mess up verification
            // through the Windows API, so just skip those

            if(deeper.size != lenof(OID_countersignature) && deeper.size != lenof(OID_nestedSignatures)) {
                continue;
            }

            if(!fmap_need_ptr_once(map, deeper.content, deeper.size)) {
                cli_dbgmsg("asn1_parse_mscat: failed to read unauthenticated attribute OID\n");
                dsize = 1;
                break;
            }

            if(!memcmp(deeper.content, OID_countersignature, deeper.size))
                content = 0; /* counterSignature */
            else if(!memcmp(deeper.content, OID_nestedSignatures, deeper.size))
                content = 1; /* nested */
            else {
                continue;
            }

            if(asn1_expect_objtype(map, deeper.next, &deep.size, &deeper, ASN1_TYPE_SET)) { /* set - contents */
                cli_dbgmsg("asn1_parse_mscat: expected 'set - contents' inside unauthenticated attribute\n");
                dsize = 1;
                break;
            }
            if(deep.size) {
                cli_dbgmsg("asn1_parse_mscat: extra data in unauthenticated attribute\n");
                dsize = 1;
                break;
            }

            if(result & (1<<content)) {
                cli_dbgmsg("asn1_parse_mscat: counterSignature or nestedSignature appear twice\n");
                dsize = 1;
                break;
            }

            if(content == 0) { /* counterSignature */

                if(asn1_parse_countersignature(map, &deeper.content, &deeper.size, cmgr, message, message_size, x509->not_before, x509->not_after)) {
                    dsize = 1;
                    break;
                }

                result |= 1;

            } else { /* nestedSignature */

                // TODO Support parsing these out in the future
                cli_dbgmsg("asn1_parse_mscat: nested signatures detected but parsing them is not currently supported\n");

                deeper.size = 0;
                result |= 2;
            }
            if(deeper.size) {
                cli_dbgmsg("asn1_parse_mscat: extra data in unauthenticated attribute\n");
                dsize = 1;
                break;
            }
        }
        if(dsize)
            break;

        cli_dbgmsg("asn1_parse_mscat: unauthenticatedAttributes successfully parsed\n");

        if (1 != (result & 1)) {
            time_t now;

            // No countersignature, so judge validity based on time
            now = time(NULL);

            if(now < x509->not_before || now > x509->not_after) {
                cli_dbgmsg("asn1_parse_mscat: no countersignature and signing certificate has expired\n");
                ret = CL_EVERIFY;
                break;
            }

            cli_dbgmsg("asn1_parse_mscat: no countersignature but the signing certificate is still valid\n");
        }

        ret = CL_CLEAN;

    } while(0);

finish:
    if (CL_EPARSE == ret) {
        cli_dbgmsg("asn1_parse_mscat: failed to parse authenticode section\n");
    }
    return ret;
}

int asn1_load_mscat(fmap_t *map, struct cl_engine *engine) {
    struct cli_asn1 c;
    unsigned int size;
    struct cli_matcher *db;
    int i;

    // TODO As currently implemented, loading in a .cat file with -d requires
    // an accompanying .crb with whitelist entries that will cause the .cat
    // file signatures to verify successfully.  If a user is specifying a .cat
    // file to use, though, we should assume they trust it and at least add the
    // covered hashes from it to hm_fp
    // TODO Since we pass engine->cmgr directly here, the whole chain of trust
    // for this .cat file will get added to the global trust store assuming it
    // verifies successfully.  Is this a bug for a feature?
    if(CL_CLEAN != asn1_parse_mscat(map, 0, map->len, &engine->cmgr, 0, &c.next, &size, engine))
        return 1;

    if(asn1_expect_objtype(map, c.next, &size, &c, ASN1_TYPE_SEQUENCE))
        return 1;
    if(asn1_expect_obj(map, &c.content, &c.size, ASN1_TYPE_OBJECT_ID, lenof(OID_szOID_CATALOG_LIST), OID_szOID_CATALOG_LIST))
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
    if(asn1_expect_objtype(map, c.next, &size, &c, ASN1_TYPE_SEQUENCE)) /* hashes here */
        return 1;
    /* [0] is next but we don't care as it's really descriptives stuff */

    size = c.size;
    c.next = c.content;
    while(size) {
        struct cli_asn1 tag;
        if(asn1_expect_objtype(map, c.next, &size, &c, ASN1_TYPE_SEQUENCE))
            return 1;
        if(asn1_expect_objtype(map, c.content, &c.size, &tag, ASN1_TYPE_OCTET_STRING)) /* TAG NAME */
            return 1;
        if(asn1_expect_objtype(map, tag.next, &c.size, &tag, ASN1_TYPE_SET)) /* set */
            return 1;
        if(c.size) {
            cli_dbgmsg("asn1_load_mscat: found extra data in tag\n");
            return 1;
        }
        while(tag.size) {
            struct cli_asn1 tagval1, tagval2, tagval3;
            int hashtype;

            if(asn1_expect_objtype(map, tag.content, &tag.size, &tagval1, ASN1_TYPE_SEQUENCE))
                return 1;
            tag.content = tagval1.next;

            if(asn1_expect_objtype(map, tagval1.content, &tagval1.size, &tagval2, ASN1_TYPE_OBJECT_ID))
                return 1;
            if(tagval2.size != lenof(OID_SPC_INDIRECT_DATA_OBJID))
                continue;

            if(!fmap_need_ptr_once(map, tagval2.content, lenof(OID_SPC_INDIRECT_DATA_OBJID))) {
                cli_dbgmsg("asn1_load_mscat: cannot read SPC_INDIRECT_DATA\n");
                return 1;
            }
            if(memcmp(tagval2.content, OID_SPC_INDIRECT_DATA_OBJID, lenof(OID_SPC_INDIRECT_DATA_OBJID)))
                continue; /* stuff like CAT_NAMEVALUE_OBJID(1.3.6.1.4.1.311.12.2.1) and CAT_MEMBERINFO_OBJID(.2).. */

            if(asn1_expect_objtype(map, tagval2.next, &tagval1.size, &tagval2, ASN1_TYPE_SET))
                return 1;
            if(tagval1.size) {
                cli_dbgmsg("asn1_load_mscat: found extra data in tag value\n");
                return 1;
            }

            if(asn1_expect_objtype(map, tagval2.content, &tagval2.size, &tagval1, ASN1_TYPE_SEQUENCE))
                return 1;
            if(tagval2.size) {
                cli_dbgmsg("asn1_load_mscat: found extra data in SPC_INDIRECT_DATA_OBJID tag\n");
                return 1;
            }

            if(asn1_expect_objtype(map, tagval1.content, &tagval1.size, &tagval2, ASN1_TYPE_SEQUENCE))
                return 1;

            if(asn1_expect_objtype(map, tagval2.content, &tagval2.size, &tagval3, ASN1_TYPE_OBJECT_ID)) /* shall have an obj 1.3.6.1.4.1.311.2.1.15 or 1.3.6.1.4.1.311.2.1.25 inside */
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

            if(asn1_expect_objtype(map, tagval2.next, &tagval1.size, &tagval2, ASN1_TYPE_SEQUENCE))
                return 1;
            if(tagval1.size) {
                cli_dbgmsg("asn1_load_mscat: found extra data after hash\n");
                return 1;
            }

            if(asn1_expect_algo(map, &tagval2.content, &tagval2.size, lenof(OID_sha1), OID_sha1)) { /* objid 1.3.14.3.2.26 - sha1 */
                cli_dbgmsg("asn1_load_mscat: currently only SHA1 hashes are supported for .cat file signatures\n");
                return 1;
            }

            if(asn1_expect_objtype(map, tagval2.content, &tagval2.size, &tagval3, ASN1_TYPE_OCTET_STRING))
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

/* Check an embedded PE Authenticode section to determine whether it's trusted.
 * This will return CL_CLEAN if the file should be trusted, CL_EPARSE if an
 * error occurred while parsing the signature, CL_EVERIFY if parsing was
 * successful but there were no whitelist rules for the signature, and
 * CL_VIRUS if a blacklist rule was found for an embedded certificate. */
cl_error_t asn1_check_mscat(struct cl_engine *engine, fmap_t *map, size_t offset, unsigned int size, struct cli_mapped_region *regions, uint32_t nregions) {
    unsigned int content_size;
    struct cli_asn1 c;
    cli_crt_hashtype hashtype;
    uint8_t hash[MAX_HASH_SIZE];
    unsigned int hashsize;
    const void *content;
    crtmgr certs;
    int ret;
    void *ctx;
    unsigned int i;

    // TODO Move these into cli_checkfp_pe
    if (!(engine->dconf->pe & PE_CONF_CERTS))
        return CL_EVERIFY;
    if (engine->engine_options & ENGINE_OPTIONS_DISABLE_PE_CERTS)
        return CL_EVERIFY;

    cli_dbgmsg("in asn1_check_mscat (offset: %llu)\n", (long long unsigned)offset);
    crtmgr_init(&certs);
    if(crtmgr_add_roots(engine, &certs)) {
        crtmgr_free(&certs);
        return CL_EVERIFY;
    }
    ret = asn1_parse_mscat(map, offset, size, &certs, 1, &content, &content_size, engine);
    crtmgr_free(&certs);
    if(CL_CLEAN != ret)
        return ret;

    if(asn1_expect_objtype(map, content, &content_size, &c, ASN1_TYPE_SEQUENCE)) {
        cli_dbgmsg("asn1_check_mscat: expected SEQUENCE at top level of hash container\n");
        return CL_EPARSE;
    }
    if(asn1_expect_obj(map, &c.content, &c.size, ASN1_TYPE_OBJECT_ID, lenof(OID_SPC_PE_IMAGE_DATA_OBJID), OID_SPC_PE_IMAGE_DATA_OBJID)) {
        cli_dbgmsg("asn1_check_mscat: expected spcPEImageData OID in the first hash SEQUENCE\n");
        return CL_EPARSE;
    }

    // TODO Should we do anything with the underlying SEQUENCE and data?  From
    // the 2008 spec doc it doesn't sound like many of the fields are used, so
    // ignoring is probably fine for now

    if(asn1_expect_objtype(map, c.next, &content_size, &c, ASN1_TYPE_SEQUENCE)) {
        cli_dbgmsg("asn1_check_mscat: expected second hash container object to be a SEQUENCE\n");
        return CL_EPARSE;
    }
    if(content_size) {
        cli_dbgmsg("asn1_check_mscat: extra data in hash SEQUENCE\n");
        return CL_EPARSE;
    }

    if(asn1_expect_hash_algo(map, &c.content, &c.size, &hashtype, &hashsize)) {
        cli_dbgmsg("asn1_check_mscat: unexpected file hash algo\n");
        return CL_EPARSE;
    }

    if (NULL == (ctx = get_hash_ctx(hashtype))) {
        return CL_EPARSE;
    }

    // Now that we know the hash algorithm, compute the authenticode hash
    // across the required regions of memory.
    for(i = 0; i < nregions; i++) {
        const uint8_t *hptr;
        if (0 == regions[i].size) {
            continue;
        }
        if(!(hptr = fmap_need_off_once(map, regions[i].offset, regions[i].size))){
            return CL_EVERIFY;
        }

        cl_update_hash(ctx, hptr, regions[i].size);
    }

    cl_finish_hash(ctx, hash);

    if(cli_debug_flag) {
        char hashtxt[MAX_HASH_SIZE*2+1];
        for(i=0; i<hashsize; i++)
            sprintf(&hashtxt[i*2], "%02x", hash[i]);
        cli_dbgmsg("Authenticode: %s\n", hashtxt);
    }

    if(asn1_expect_obj(map, &c.content, &c.size, ASN1_TYPE_OCTET_STRING, hashsize, hash)) {
        cli_dbgmsg("asn1_check_mscat: computed authenticode hash did not match stored value\n");
        return CL_EVERIFY;
    }
    if(c.size) {
        cli_dbgmsg("asn1_check_mscat: extra data after the stored authenticode hash\n");
        return CL_EPARSE;
    }

    cli_dbgmsg("asn1_check_mscat: file with valid authenticode signature, whitelisted\n");
    return CL_CLEAN;
}
