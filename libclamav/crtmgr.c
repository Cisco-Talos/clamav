#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include "crtmgr.h"
#include "others.h"

int cli_crt_init(cli_crt *x509) {
    int ret;
    if((ret = mp_init_multi(&x509->n, &x509->e, &x509->sig, NULL))) {
	cli_errmsg("cli_crt_init: mp_init_multi failed with %d\n", ret);
	return 1;
    }
    x509->not_before = x509->not_after = 0;
    x509->prev = x509->next = NULL;
    return 0;
}

void cli_crt_clear(cli_crt *x509) {
    mp_clear_multi(&x509->n, &x509->e, &x509->sig, NULL);
}

static cli_crt *crtmgr_lookup(crtmgr *m, cli_crt *x509) {
    cli_crt *i = m->crts;
    while(i) {
	if(x509->not_before == i->not_before && x509->not_after == i->not_after && !memcmp(x509->subject, i->subject, sizeof(i->subject))) {
	    if(mp_cmp(&x509->n, &i->n) || mp_cmp(&x509->e, &i->e))
		cli_dbgmsg("crtmgr_add: conflicting pk for the same cert\n");
	    return i;
	}
	i = i->next;
    }
    return NULL;
}

int crtmgr_add(crtmgr *m, cli_crt *x509) {
    cli_crt *i = crtmgr_lookup(m, x509);

    if(i)
	return 0;
    i = cli_malloc(sizeof(*i));
    if(!i)
	return 1;

    if(mp_init_multi(&i->n, &i->e, &i->sig, NULL)) {
	free(i);
	return 1;
    }
    if(mp_copy(&x509->n, &i->n) || mp_copy(&x509->e, &i->e) || mp_copy(&x509->sig, &i->sig)) {
	cli_crt_clear(i);
	free(i);
	return 1;
    }
    memcpy(i->subject, x509->subject, sizeof(i->subject));
    memcpy(i->issuer, x509->issuer, sizeof(i->issuer));
    i->not_before = x509->not_before;
    i->not_after = x509->not_after;
    i->hashtype = x509->hashtype;
    i->next = m->crts;
    i->prev = NULL;
    if(m->crts)
	m->crts->prev = i;
    m->crts = i;

    {
	char issuer[SHA1_HASH_SIZE*2+1], subject[SHA1_HASH_SIZE*2+1], mod[1024], exp[1024];
	int j;
	mp_toradix_n(&i->n, mod, 16, sizeof(mod));
	mp_toradix_n(&i->e, exp, 16, sizeof(exp));
	for(j=0; j<SHA1_HASH_SIZE; j++) {
	    sprintf(&issuer[j*2], "%02x", i->issuer[j]);
	    sprintf(&subject[j*2], "%02x", i->subject[j]);
	}
	cli_dbgmsg("crtmgr_add: added cert s:%s i:%s n:%s e:%s\n", subject, issuer, mod, exp);
    }
    return 0;
}


int crtmgr_verify(crtmgr *m, cli_crt *x509) {
    uint8_t d[513];
    cli_crt *i = m->crts;
    mp_int x;
    int ret, j, siglen = mp_unsigned_bin_size(&x509->sig), hashlen;

    if((ret = mp_init(&x))) {
	cli_errmsg("crtmgr_verify: mp_init failed with %d\n", ret);
	return 1;
    }
    for(i = m->crts; i; i = i->next) {
	if(!memcmp(x509->issuer, i->subject, sizeof(i->subject)) && siglen == mp_unsigned_bin_size(&i->n)) {
	    if((ret = mp_exptmod(&x509->sig, &i->e, &i->n, &x))) {
		cli_warnmsg("crtmgr_verify: verification failed: mp_exptmod failed with %d\n", ret);
		continue;
	    }
	    if(mp_unsigned_bin_size(&x) != siglen - 1)
		continue;
	    if((ret = mp_to_unsigned_bin(&x, d))) {
		cli_warnmsg("crtmgr_verify: mp_unsigned_bin_size failed with %d\n", ret);
		continue;
	    }
	    if(*d != 1) /* block type 1 */
		continue;

	    siglen -= 1; /* sizeof(x) */
	    for(j=1; j<siglen-2; j++) /* upto sizeof(x) - 2 */
		if(d[j] != 0xff)
		    break;
	    if(j == siglen - 2)
		continue;
	    if(d[j] != 0)
		continue;

	    j++;
	    siglen -= j; /* asn1 size */

	    if(siglen < 2 || d[j] != 0x30 || d[j+1] + 2 != siglen)
		continue;
	    siglen -= 2;
	    j+=2;

	    if(siglen <2 || d[j] != 0x30 || (hashlen = d[j+1]) != 9) {/* FIXME - md5 */
		cli_errmsg("crtmgr_verify: ACAB HERE MD5 MISSING!!!\n");
		continue;
	    }
	    siglen -= 2;
	    j+=2;
	    if(siglen < hashlen || memcmp(&d[j], "\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00", hashlen)) {
		cli_errmsg("crtmgr_verify: ACAB HERE MD5 MISSING!!!\n");
		continue;
	    }
	    siglen -= hashlen;
	    j += hashlen;
	    hashlen = x509->hashtype == CLI_SHA1RSA ? SHA1_HASH_SIZE : 16;
	    if(siglen < 2 || d[j] != 0x04 || d[j+1] != hashlen)
		continue;
	    siglen -= 2;
	    j+=2;
	    if(siglen != hashlen)
		continue;
	    if(memcmp(&d[j], x509->tbshash, hashlen))
		continue;
	    /* SEQ { SEQ { OID, NULL }, OCTET STRING */
	    {
		char buf[1024];
		mp_toradix_n(&x, buf, 16, sizeof(buf));
		cli_dbgmsg("crtmgr_verify: %u, %u, %u, %s\n", siglen, d[j+1], hashlen, buf);
	    }
	    return 0;
	}
    }
    return 1;
}


const uint8_t MSCA_SUBJECT[] = "\x11\x3b\xd8\x6b\xed\xde\xbc\xd4\xc5\xf1\x0a\xa0\x7a\xb2\x02\x6b\x98\x2f\x4b\x92";
const uint8_t MSCA_MOD[] = "\
\x00\xf3\x5d\xfa\x80\x67\xd4\x5a\xa7\xa9\x0c\x2c\x90\x20\xd0\
\x35\x08\x3c\x75\x84\xcd\xb7\x07\x89\x9c\x89\xda\xde\xce\xc3\
\x60\xfa\x91\x68\x5a\x9e\x94\x71\x29\x18\x76\x7c\xc2\xe0\xc8\
\x25\x76\x94\x0e\x58\xfa\x04\x34\x36\xe6\xdf\xaf\xf7\x80\xba\
\xe9\x58\x0b\x2b\x93\xe5\x9d\x05\xe3\x77\x22\x91\xf7\x34\x64\
\x3c\x22\x91\x1d\x5e\xe1\x09\x90\xbc\x14\xfe\xfc\x75\x58\x19\
\xe1\x79\xb7\x07\x92\xa3\xae\x88\x59\x08\xd8\x9f\x07\xca\x03\
\x58\xfc\x68\x29\x6d\x32\xd7\xd2\xa8\xcb\x4b\xfc\xe1\x0b\x48\
\x32\x4f\xe6\xeb\xb8\xad\x4f\xe4\x5c\x6f\x13\x94\x99\xdb\x95\
\xd5\x75\xdb\xa8\x1a\xb7\x94\x91\xb4\x77\x5b\xf5\x48\x0c\x8f\
\x6a\x79\x7d\x14\x70\x04\x7d\x6d\xaf\x90\xf5\xda\x70\xd8\x47\
\xb7\xbf\x9b\x2f\x6c\xe7\x05\xb7\xe1\x11\x60\xac\x79\x91\x14\
\x7c\xc5\xd6\xa6\xe4\xe1\x7e\xd5\xc3\x7e\xe5\x92\xd2\x3c\x00\
\xb5\x36\x82\xde\x79\xe1\x6d\xf3\xb5\x6e\xf8\x9f\x33\xc9\xcb\
\x52\x7d\x73\x98\x36\xdb\x8b\xa1\x6b\xa2\x95\x97\x9b\xa3\xde\
\xc2\x4d\x26\xff\x06\x96\x67\x25\x06\xc8\xe7\xac\xe4\xee\x12\
\x33\x95\x31\x99\xc8\x35\x08\x4e\x34\xca\x79\x53\xd5\xb5\xbe\
\x63\x32\x59\x40\x36\xc0\xa5\x4e\x04\x4d\x3d\xdb\x5b\x07\x33\
\xe4\x58\xbf\xef\x3f\x53\x64\xd8\x42\x59\x35\x57\xfd\x0f\x45\
\x7c\x24\x04\x4d\x9e\xd6\x38\x74\x11\x97\x22\x90\xce\x68\x44\
\x74\x92\x6f\xd5\x4b\x6f\xb0\x86\xe3\xc7\x36\x42\xa0\xd0\xfc\
\xc1\xc0\x5a\xf9\xa3\x61\xb9\x30\x47\x71\x96\x0a\x16\xb0\x91\
\xc0\x42\x95\xef\x10\x7f\x28\x6a\xe3\x2a\x1f\xb1\xe4\xcd\x03\
\x3f\x77\x71\x04\xc7\x20\xfc\x49\x0f\x1d\x45\x88\xa4\xd7\xcb\
\x7e\x88\xad\x8e\x2d\xec\x45\xdb\xc4\x51\x04\xc9\x2a\xfc\xec\
\x86\x9e\x9a\x11\x97\x5b\xde\xce\x53\x88\xe6\xe2\xb7\xfd\xac\
\x95\xc2\x28\x40\xdb\xef\x04\x90\xdf\x81\x33\x39\xd9\xb2\x45\
\xa5\x23\x87\x06\xa5\x55\x89\x31\xbb\x06\x2d\x60\x0e\x41\x18\
\x7d\x1f\x2e\xb5\x97\xcb\x11\xeb\x15\xd5\x24\xa5\x94\xef\x15\
\x14\x89\xfd\x4b\x73\xfa\x32\x5b\xfc\xd1\x33\x00\xf9\x59\x62\
\x70\x07\x32\xea\x2e\xab\x40\x2d\x7b\xca\xdd\x21\x67\x1b\x30\
\x99\x8f\x16\xaa\x23\xa8\x41\xd1\xb0\x6e\x11\x9b\x36\xc4\xde\
\x40\x74\x9c\xe1\x58\x65\xc1\x60\x1e\x7a\x5b\x38\xc8\x8f\xbb\
\x04\x26\x7c\xd4\x16\x40\xe5\xb6\x6b\x6c\xaa\x86\xfd\x00\xbf\
\xce\xc1\x35";
const uint8_t MSCA_EXP[] = "\x01\x00\x01";

int crtmgr_add_roots(crtmgr *m) {
    cli_crt msca;
    if(cli_crt_init(&msca))
	return 1;
    memset(msca.issuer, '\xca', sizeof(msca.issuer));
    memcpy(msca.subject, MSCA_SUBJECT, sizeof(msca.subject));
    if(mp_read_unsigned_bin(&msca.n, MSCA_MOD, sizeof(MSCA_MOD)-1) || mp_read_unsigned_bin(&msca.e, MSCA_EXP, sizeof(MSCA_EXP)-1)) {
	cli_crt_clear(&msca);
	return 1;
    }
    msca.not_before = 989450362; /* May  9 23:19:22 2001 GMT */
    msca.not_after = 1620602293; /* May  9 23:28:13 2021 GMT */
    return crtmgr_add(m, &msca);
}

/* typedef struct { */
/*     cli_crt *certs; */
/*     unsigned int ncerts; */
/* } *crtmgr;  */

/*     /\* if(mp_init(&n) || mp_read_signed_bin(&n, obj.content, obj.size)) *\/ */


/* void crt_destroy(cli_crt *crt) { */
/*     mp_clear_multi(&crt->n, &crt->e); */
/*     free(crt); */
/* } */

/* void crt_set_issuer(cli_crt *crt, const char issuer[SHA1_HASH_SIZE]) { */
/*     memcpy(crt->issuer, issuer, sizeof(issuer)); */
/* } */

/* int crt_set_rsa(cli_crt *crt, int exp, void *bn, unsigned int bn_len) { */
/*     if(mp_read_signed_bin(exp ? &crt->e : &crt->n, bn, bn_len)) */
/* 	return 1; */
/*     return 0; */
/* } */

/* void crt_set_validity(cli_crt *crt, int before, time_t t) { */
/*     if(before) */
/* 	crt->not_before = t; */
/*     else */
/* 	crt->not_after = t; */
/* } */


