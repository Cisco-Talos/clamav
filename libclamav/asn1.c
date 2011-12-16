#include "asn1.h"
#include "others.h"
#include "bignum.h"


int asn1_get_obj(fmap_t *map, void *asn1data, unsigned int *asn1len, struct cli_asn1 *obj) {
    unsigned int asn1_sz = *asn1len;
    unsigned int readbytes = MIN(6, asn1_sz), i;
    uint8_t *data;

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
	    /* FIXME: double NULL terminated */
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

int asn1_expect_objtype(fmap_t *map, void *asn1data, unsigned int *asn1len, struct cli_asn1 *obj, uint8_t type) {
    int ret = asn1_get_obj(map, asn1data, asn1len, obj);
    if(ret)
	return ret;
    if(obj->type != type) {
	cli_dbgmsg("asn1_expect_objtype: expected type %02x, got %02x\n", type, obj->type);
	return 1;
    }
    return 0;
}

int asn1_expect_obj(fmap_t *map, void *asn1data, unsigned int *asn1len, struct cli_asn1 *obj, uint8_t type, unsigned int size, const void *content) {
    int ret = asn1_expect_objtype(map, asn1data, asn1len, obj, type);
    if(ret)
	return ret;
    if(obj->size != size) {
	cli_dbgmsg("asn1_expect_obj: expected size %u, got %u\n", size, obj->size);
	return 1;
    }
    if(size) {
	if(!fmap_need_ptr_once(map, obj->content, size)) {
	    cli_dbgmsg("asn1_expect_obj: failed to read content\n");
	    return 1;
	}
	if(memcmp(obj->content, content, size)) {
	    cli_dbgmsg("asn1_expect_obj: content mismatch\n");
	    return 1;
	}
    }
    return 0;
}

int asn1_expect_algo(fmap_t *map, void **asn1data, unsigned int *asn1len, unsigned int algo_size, const void *algo) {
    struct cli_asn1 obj;
    unsigned int avail;
    int ret;
    if((ret = asn1_expect_objtype(map, *asn1data, asn1len, &obj, 0x30))) /* SEQUENCE */
	return ret;
    avail = obj.size;
    *asn1data = obj.next;

    if((ret = asn1_expect_obj(map, obj.content, &avail, &obj, 0x06, algo_size, algo))) /* ALGO */
	return ret;
    if((ret = asn1_expect_obj(map, obj.next, &avail, &obj, 0x05, 0, NULL))) /* NULL */
	return ret;
    if(avail) {
	cli_dbgmsg("asn1_expect_algo: extra data found in SEQUENCE\n");
	return 1;
    }
    return 0;
}

int ms_asn1_get_sha1(fmap_t *map, void *asn1data, unsigned int avail, uint8_t sha1[SHA1_HASH_SIZE]) {
    struct cli_asn1 obj;

    if(asn1_expect_obj(map, asn1data, &avail, &obj, 0x06, 10, "\x2b\x06\x01\x04\x01\x82\x37\x02\x01\x04")) /* OBJECT 1.3.6.1.4.1.311.2.1.4 - SPC_INDIRECT_DATA_OBJID */
	return 1;

    if(asn1_get_obj(map, obj.next, &avail, &obj))
	return 1;
    if(obj.type != 0xa0 && obj.type != 0x31) {
	cli_dbgmsg("ms_asn1_get_sha1: expected [0] or SET - got %02x\n", obj.type);
	return 1;
    }

    avail = obj.size;
    if(asn1_expect_objtype(map, obj.content, &avail, &obj, 0x30)) /* SEQUENCE */
	return 1;

    avail = obj.size;
    if(asn1_get_obj(map, obj.content, &avail, &obj)) /* data - contains an objid 1.3.6.1.4.1.311.2.1.15 or 1.3.6.1.4.1.311.2.1.25 for embedded or detached */
	return 1;

    if(asn1_expect_objtype(map, obj.next, &avail, &obj, 0x30)) /* messageDigest */
	return 1;

    avail = obj.size;
    if(asn1_expect_algo(map, &obj.content, &avail, 5, "\x2b\x0e\x03\x02\x1a")) /* objid 1.3.14.3.2.26 - sha1 */
       return 1;

    if(asn1_expect_objtype(map, obj.content, &avail, &obj, 0x04))
	return 1;
    if(avail) {
	cli_dbgmsg("ms_asn1_get_sha1: found unexpected extra data\n");
	return 1;
    }
    if(obj.size != SHA1_HASH_SIZE) {
	cli_dbgmsg("ms_asn1_get_sha1: expected sha1 lenght(%u), but got %u\n", SHA1_HASH_SIZE, obj.size);
	return 1;
    }

    if(!fmap_need_ptr_once(map, obj.content, SHA1_HASH_SIZE)) {
	cli_dbgmsg("ms_asn1_get_sha1: failed to read sha1 content\n");
	return 1;
    }
    memcpy(sha1, obj.content, SHA1_HASH_SIZE);

    return 0;
}

static int asn1_getnum(const char *s) {
    if(s[0] < '0' || s[0] >'9' || s[1] < '0' || s[1] > '9') {
	cli_dbgmsg("asn1_getnum: expecting digits, found '%c%c'\n", s[0], s[1]);
	return -1;
    }
    return (s[0] - '0')*10 + (s[1] - '0');
}

int asn1_get_time(fmap_t *map, void **asn1data, unsigned int *size, time_t *time) {
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
    n = asn1_getnum(ptr);
    if(n<1 || n>12) {
	cli_dbgmsg("asn1_get_time: invalid month %u\n", n);
	return 1;
    }
    t.tm_mon = n;
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

    *time = mktime(&t);
    *asn1data = obj.next;
    return 0;
}

int asn1_get_rsa_pubkey(fmap_t *map, void **asn1data, unsigned int *size) {
    struct cli_asn1 obj;
    unsigned int avail, avail2;
    mp_int n, e;

    if(asn1_expect_objtype(map, *asn1data, size, &obj, 0x30)) /* subjectPublicKeyInfo */
	return 1;
    *asn1data = obj.next;

    avail = obj.size;
    if(asn1_expect_algo(map, &obj.content, &avail, 9, "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01")) /* rsaEncryption */
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
	cli_dbgmsg("asn1_get_rsa_pubkey: modulus has got an unsupported length (%u)\n",  obj.size * 8);
	return 1;
    }
    avail2 = obj.size;
    if(!fmap_need_ptr_once(map, obj.content, avail2)) {
	cli_dbgmsg("asn1_get_rsa_pubkey: cannot read n\n");
	return 1;
    }
    if(mp_init(&n) || mp_read_signed_bin(&n, obj.content, avail2)) {
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
    if(mp_init(&e) || mp_read_signed_bin(&n, obj.content, obj.size)) {
	cli_dbgmsg("asn1_get_rsa_pubkey: cannot convert e to big number\n");
	return 1;
    }
    return 0;
}

int asn1_get_x509(fmap_t *map, void **asn1data, unsigned int *size) {
    struct cli_asn1 crt, tbs, obj;
    unsigned int avail;
    time_t not_before, not_after;
    void *next;

    if(asn1_expect_objtype(map, *asn1data, size, &crt, 0x30)) /* SEQUENCE */
	return 1;

    if(asn1_expect_objtype(map, crt.content, &crt.size, &tbs, 0x30)) /* SEQUENCE - TBSCertificate */
	return 1;

    if(asn1_expect_objtype(map, tbs.content, &tbs.size, &obj, 0xa0)) /* [0] */
	return 1;
    avail = obj.size;
    next = obj.next;
    if(asn1_expect_obj(map, obj.content, &avail, &obj, 0x02, 1, "\x02")) /* version 3 only */
	return 1;
    if(avail) {
	cli_dbgmsg("asn1_get_x509: found unexpected extra data in version\n");
	return 1;
    }

    if(asn1_expect_objtype(map, next, &tbs.size, &obj, 0x02)) /* serialNumber */
	return 1;

    if(asn1_expect_algo(map, &obj.next, &tbs.size, 9, "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x05")) /* algo = sha1WithRSAEncryption */
       return 1;

    if(asn1_expect_objtype(map, obj.next, &tbs.size, &obj, 0x30)) /* issuer */
	return 1;

    if(asn1_expect_objtype(map, obj.next, &tbs.size, &obj, 0x30)) /* validity */
	return 1;
    avail = obj.size;
    next = obj.content;
    if(asn1_get_time(map, &next, &avail, &not_before)) /* notBefore */
	return 1;
    if(asn1_get_time(map, &next, &avail, &not_after)) /* notAfter */
	return 1;
    if(avail) {
	cli_dbgmsg("asn1_get_x509: found unexpected extra data in validity\n");
	return 1;
    }

    if(asn1_expect_objtype(map, obj.next, &tbs.size, &obj, 0x30)) /* subject */
	return 1;

    if(asn1_get_rsa_pubkey(map, &obj.next, &tbs.size))
       return 1;

    avail = 0;
    while(tbs.size) {
	/* extensions */
	if(asn1_get_obj(map, obj.next, &tbs.size, &obj))
	    return 1;
	if(obj.type <= 0xa0 + avail || obj.type > 0xa3) {
	    cli_dbgmsg("asn1_get_x509: found type %02x in extensions, expecting a1, a2 or a3\n");
	    return 1;
	}
	avail = obj.type - 0xa0;
    }

    if(asn1_expect_algo(map, &tbs.next, &crt.size, 9, "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x05")) /* signature algo = sha1WithRSAEncryption */
       return 1;

    if(asn1_expect_objtype(map, tbs.next, &crt.size, &obj, 0x03)) /* signature */
	return 1;
    if(crt.size) {
	cli_dbgmsg("asn1_get_x509: found unexpected extra data in signature\n");
	return 1;
    }

    *asn1data = crt.next;
    return 0;
}








int asn1_parse_mscat(FILE *f) {
    struct cli_asn1 asn1;
    unsigned int size;
    fmap_t *map;
    void *next;

    if(!(map = fmap(fileno(f), 0, 0)))
	return 1;
    do {
	if(!(next = fmap_need_off_once(map, 0, 1))) {
	    cli_errmsg("asn1_parse_mscat: failed to read cat\n");
	    break;
	}
	size = map->len;
	if(asn1_expect_objtype(map, next, &size, &asn1, 0x30)) { /* SEQUENCE */
	    cli_errmsg("asn1_parse_mscat: \n");
	    break;
	}
    } while(0);
    /* do { */
    /* 	if(asn1_expect_objtype(map, hptr, &hlen, &asn1, 0x30)) /\* SEQUENCE *\/ */
    /* 	    break; */
    /* 		hlen = asn1.size; */
    /* 		if(asn1_expect_obj(map, asn1.content, &hlen, &asn1, 0x06, 9, "\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02")) /\* OBJECT 1.2.840.113549.1.7.2 - pkcs7 signedData *\/ */
    /* 		    break; */
    /* 		if(asn1_expect_objtype(map, asn1.next, &hlen, &asn1, 0xa0)) /\* [0] *\/ */
    /* 		    break; */
    /* 		hlen = asn1.size; */
    /* 		if(asn1_expect_objtype(map, asn1.content, &hlen, &asn1, 0x30)) /\* SEQUENCE *\/ */
    /* 		    break; */
    /* 		hlen = asn1.size; */
    /* 		if(asn1_expect_obj(map, asn1.content, &hlen, &asn1, 0x02, 1, "\x01")) /\* INTEGER - VERSION 1 *\/ */
    /* 		    break; */

    /* 		if(!asn1_expect_objtype(map, asn1.next, &hlen, &asn1, 0x31)) { /\* SET OF DigestAlgorithmIdentifier *\/ */
    /* 		    success = 0; */
    /* 		    old_hlen = hlen; */
    /* 		    old_next = asn1.next; */

    /* 		    hlen = asn1.size; */
    /* 		    if(asn1_expect_objtype(map, asn1.content, &hlen, &asn1, 0x30)) /\* SEQUENCE *\/ */
    /* 			break; */
    /* 		    asn1.next = asn1.content; */
    /* 		    hlen = asn1.size; */
    /* 		    while(hlen) { */
    /* 			if(asn1_get_obj(map, asn1.next, &hlen, &asn1)) */
    /* 			    break; */
    /* 			if(asn1.type == 0x05 && asn1.size == 0) { /\* NULL or *\/ */
    /* 			    success++; */
    /* 			    break; */
    /* 			} */
    /* 			if(asn1.type != 0x06) /\* Algo ID *\/ */
    /* 			    break; */
    /* 			if(asn1.size == 5 && fmap_need_ptr_once(map, asn1.content, 5) && !memcmp(asn1.content, "\x2b\x0e\x03\x02\x1a", 5)) /\* but only sha1 *\/ */
    /* 			    if(!success) */
    /* 				success++; */
    /* 		    } */
    /* 		    if(success < 2) */
    /* 			break; */
    /* 		    hlen = old_hlen; */
    /* 		    asn1.next = old_next; */
    /* 		} else */
    /* 		    break; */

    /* 		if(asn1_expect_objtype(map, asn1.next, &hlen, &asn1, 0x30)) /\* SEQUENCE *\/ */
    /* 		    break; */

    /* 		if(ms_asn1_get_sha1(map, asn1.content, asn1.size, crt_sha1)) */
    /* 		    break; */

    /* 		for(i=0; i<sizeof(crt_sha1); i++) */
    /* 		    sprintf(&shatxt[i*2], "%02x", crt_sha1[i]); */
    /* 		cli_errmsg("CRT sha: %s\n", shatxt); */

    /* 		if(memcmp(crt_sha1, shash1, sizeof(crt_sha1))) */
    /* 		    break; */

    /* 		if(asn1_expect_objtype(map, asn1.next, &hlen, &asn1, 0xa0)) /\* certificates *\/ */
    /* 		    break; */

    /* 		old_hlen = hlen; */
    /* 		old_next = asn1.next; */
    /* 		hlen = asn1.size; */
    /* 		asn1.next = asn1.content; */
    /* 		success = 1; */
    /* 		while(hlen) { */
    /* 		    if(!asn1_get_x509(map, &asn1.next, &hlen)) */
    /* 			continue; */
    /* 		    success = 0; */
    /* 		    break; */
    /* 		} */
    /* 		if(!success) */
    /* 		    break; */

    /* 		hlen = old_hlen; */
    /* 		if(asn1_get_obj(map, old_next, &hlen, &asn1)) */
    /* 		    break; */
    /* 		if(asn1.type == 0xa1 && asn1_get_obj(map, asn1.next, &hlen, &asn1)) /\* crls - unused shouldn't be present *\/ */
    /* 		    break; */

    /* 		if(asn1.type != 0x31) /\* signerInfos *\/ */
    /* 		    break; */

    /* 		cli_errmsg("good %u - %p\n", hlen, asn1.next); */
    /* 	    } while(0); */
    return 1;
	}
