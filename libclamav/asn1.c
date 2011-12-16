#include "asn1.h"
#include "others.h"
#include "bignum.h"


int asn1_get_obj(fmap_t *map, void *asn1data, unsigned int *asn1len, struct cli_asn1 *obj) {
    unsigned int asn1_sz = *asn1len;
    unsigned int readbytes = MIN(6, asn1_sz), i;
    uint8_t *data;

    if(asn1_sz < 2) {
	cli_errmsg("asn1_get_obj: insufficient data length\n");
	return 1;
    }
    data = fmap_need_ptr_once(map, asn1data, readbytes);
    if(!data) {
	cli_errmsg("asn1_get_obj: obj out of file\n");
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
    if(obj->type != type)
	return 1;
    return 0;
}

int asn1_expect_obj(fmap_t *map, void *asn1data, unsigned int *asn1len, struct cli_asn1 *obj, uint8_t type, unsigned int size, const void *content) {
    int ret = asn1_expect_objtype(map, asn1data, asn1len, obj, type);
    if(ret)
	return ret;
    if(obj->size != size)
	return 1;
    if(size) {
	if(!fmap_need_ptr_once(map, obj->content, size))
	    return 1;
	if(memcmp(obj->content, content, size))
	    return 1;
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
    if(avail)
	return 1;

    return 0;
}

int ms_asn1_get_sha1(fmap_t *map, void *asn1data, unsigned int avail, uint8_t sha1[SHA1_HASH_SIZE]) {
    struct cli_asn1 obj;

    if(asn1_expect_obj(map, asn1data, &avail, &obj, 0x06, 10, "\x2b\x06\x01\x04\x01\x82\x37\x02\x01\x04")) /* OBJECT 1.3.6.1.4.1.311.2.1.4 - SPC_INDIRECT_DATA_OBJID */
	return 1;

    if(asn1_get_obj(map, obj.next, &avail, &obj))
	return 1;
    if(obj.type != 0xa0 && obj.type != 0x31)
	return 1;

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

    if(asn1_expect_objtype(map, obj.content, &avail, &obj, 0x04) || avail || obj.size != SHA1_HASH_SIZE)
	return 1;

    if(!fmap_need_ptr_once(map, obj.content, SHA1_HASH_SIZE))
	return 1;
    memcpy(sha1, obj.content, SHA1_HASH_SIZE);

    return 0;
}

static int getnum(const char *s) {
    if(s[0] < '0' || s[0] >'9' || s[1] < '0' || s[1] > '9')
	return -1;
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
    else
	return 1;

    if(!fmap_need_ptr_once(map, obj.content, len))
	return 1;

    memset(&t, 0, sizeof(t));
    ptr = (char *)obj.content;
    if(obj.type == 0x18) {
	t.tm_year = getnum(ptr) * 100;
	if(t.tm_year < 0)
	    return 1;
	n = getnum(ptr);
	if(n<0)
	    return 1;
	t.tm_year += n;
	ptr+=4;
    } else {
	n = getnum(ptr);
	if(n<0)
	    return 1;
	if(n>=50)
	    t.tm_year = 1900 + n;
	else
	    t.tm_year = 2000 + n;
	ptr += 2;
    }
    n = getnum(ptr);
    if(n<1 || n>12)
	return 1;
    t.tm_mon = n;
    ptr+=2;

    n = getnum(ptr);
    if(n<1 || n>31)
	return 1;
    t.tm_mday = n;
    ptr+=2;

    n = getnum(ptr);
    if(n<0 || n>23)
	return 1;
    t.tm_hour = n;
    ptr+=2;

    n = getnum(ptr);
    if(n<0 || n>59)
	return 1;
    t.tm_min = n;
    ptr+=2;

    n = getnum(ptr);
    if(n<0 || n>59)
	return 1;
    t.tm_sec = n;
    ptr+=2;

    if(*ptr != 'Z')
	return 1;

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

    if(asn1_expect_objtype(map, obj.content, &avail, &obj, 0x03) || avail) /* BIT STRING - subjectPublicKey */
	return 1;
    /* if(obj.size != 141 && obj.size != 271) /\* encoded len of 1024 and 2048 bit public keys *\/ */
    /*	return 1; */

    if(!fmap_need_ptr_once(map, obj.content, 1))
	return 1;
    if(((uint8_t *)obj.content)[0] != 0) /* no byte fragments */
	return 1;

    avail = obj.size - 1;
    obj.content = ((uint8_t *)obj.content) + 1;
    if(asn1_expect_objtype(map, obj.content, &avail, &obj, 0x30) || avail) /* SEQUENCE */
	return 1;

    avail = obj.size;
    if(asn1_expect_objtype(map, obj.content, &avail, &obj, 0x02)) /* INTEGER - mod */
	return 1;
    if(obj.size < 1024/8 || obj.size > 4096/8+1)
	return 1;
    avail2 = obj.size;
    if(!fmap_need_ptr_once(map, obj.content, avail2))
	return 1;
    if(mp_init(&n) || mp_read_signed_bin(&n, obj.content, obj.size))
	return 1;

    if(asn1_expect_objtype(map, obj.next, &avail, &obj, 0x02) || avail) /* INTEGER - exp */
	return 1;
    if(obj.size < 1 || obj.size > avail2)
	return 1;
    if(!fmap_need_ptr_once(map, obj.content, obj.size))
	return 1;
    if(mp_init(&e) || mp_read_signed_bin(&n, obj.content, obj.size))
	return 1;

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
    if(asn1_expect_obj(map, obj.content, &avail, &obj, 0x02, 1, "\x02") || avail) /* version 3 only */
	return 1;

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
    if(avail)
	return 1;

    if(asn1_expect_objtype(map, obj.next, &tbs.size, &obj, 0x30)) /* subject */
	return 1;

    if(asn1_get_rsa_pubkey(map, &obj.next, &tbs.size))
       return 1;

    avail = 0;
    while(tbs.size) {
	/* extensions */
	if(asn1_get_obj(map, obj.next, &tbs.size, &obj))
	    return 1;
	if(obj.type <= 0xa0 + avail || obj.type > 0xa3)
	    return 1;
	avail = obj.type - 0xa0;
    }

    if(asn1_expect_algo(map, &tbs.next, &crt.size, 9, "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x05")) /* signature algo = sha1WithRSAEncryption */
       return 1;

    if(asn1_expect_objtype(map, tbs.next, &crt.size, &obj, 0x03) || crt.size) /* signature */
	return 1;

    *asn1data = crt.next;

    return 0;
}

