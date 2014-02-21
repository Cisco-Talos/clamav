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

#include <openssl/ssl.h>
#include <openssl/err.h>
#include "libclamav/crypto.h"

#include "others.h"
#include "crtmgr.h"

int cli_crt_init(cli_crt *x509) {
    int ret;
    if((ret = mp_init_multi(&x509->n, &x509->e, &x509->sig, NULL))) {
	cli_errmsg("cli_crt_init: mp_init_multi failed with %d\n", ret);
	return 1;
    }
    x509->name = NULL;
    x509->isBlacklisted = 0;
    x509->not_before = x509->not_after = 0;
    x509->prev = x509->next = NULL;
    x509->certSign = x509->codeSign = x509->timeSign = 0;
    return 0;
}

void cli_crt_clear(cli_crt *x509) {
    mp_clear_multi(&x509->n, &x509->e, &x509->sig, NULL);
}

cli_crt *crtmgr_lookup(crtmgr *m, cli_crt *x509) {
    cli_crt *i;
    for(i = m->crts; i; i = i->next) {
	if(x509->not_before >= i->not_before &&
	   x509->not_after <= i->not_after &&
	   (i->certSign | x509->certSign) == i->certSign &&
	   (i->codeSign | x509->codeSign) == i->codeSign &&
	   (i->timeSign | x509->timeSign) == i->timeSign &&
	   !memcmp(x509->subject, i->subject, sizeof(i->subject)) &&
	   !memcmp(x509->serial, i->serial, sizeof(i->serial)) &&
	   !mp_cmp(&x509->n, &i->n) &&
	   !mp_cmp(&x509->e, &i->e) && !(i->isBlacklisted)) {
	    return i;
	}
    }
    return NULL;
}

int crtmgr_add(crtmgr *m, cli_crt *x509) {
    cli_crt *i;
    int ret = 0;

    for(i = m->crts; i; i = i->next) {
	if(!memcmp(x509->subject, i->subject, sizeof(i->subject)) &&
	   !memcmp(x509->serial, i->subject, sizeof(i->serial)) &&
	   !mp_cmp(&x509->n, &i->n) &&
	   !mp_cmp(&x509->e, &i->e)) {
	    if(x509->not_before >= i->not_before && x509->not_after <= i->not_after) {
		/* Already same or broader */
		ret = 1;
	    }
	    if(i->not_before > x509->not_before && i->not_before <= x509->not_after) {
		/* Extend left */
		i->not_before = x509->not_before;
		ret = 1;
	    }
	    if(i->not_after >= x509->not_before && i->not_after < x509->not_after) {
		/* Extend right */
		i->not_after = x509->not_after;
		ret = 1;
	    }
	    if(!ret)
		continue;
	    i->certSign |= x509->certSign;
	    i->codeSign |= x509->codeSign;
	    i->timeSign |= x509->timeSign;

	    return 0;
	}

    /* If certs match, we're likely just revoking it */
    if (!memcmp(x509->subject, i->subject, sizeof(x509->subject)) &&
        !memcmp(x509->issuer, i->issuer, sizeof(x509->issuer)) &&
        !memcmp(x509->serial, i->serial, sizeof(x509->serial)) &&
        !mp_cmp(&x509->n, &i->n) &&
        !mp_cmp(&x509->e, &i->e)) {
            if (i->isBlacklisted != x509->isBlacklisted)
                i->isBlacklisted = x509->isBlacklisted;

            return 0;
    }
    }

    i = cli_malloc(sizeof(*i));
    if(!i)
	return 1;

    if((ret = mp_init_multi(&i->n, &i->e, &i->sig, NULL))) {
	cli_warnmsg("crtmgr_add: failed to mp_init failed with %d\n", ret);
	free(i);
	return 1;
    }
    if((ret = mp_copy(&x509->n, &i->n)) || (ret = mp_copy(&x509->e, &i->e)) || (ret = mp_copy(&x509->sig, &i->sig))) {
	cli_warnmsg("crtmgr_add: failed to mp_init failed with %d\n", ret);
	cli_crt_clear(i);
	free(i);
	return 1;
    }

    if ((x509->name))
        i->name = strdup(x509->name);
    else
        i->name = NULL;

    memcpy(i->subject, x509->subject, sizeof(i->subject));
    memcpy(i->serial, x509->serial, sizeof(i->serial));
    memcpy(i->issuer, x509->issuer, sizeof(i->issuer));
    memcpy(i->tbshash, x509->tbshash, sizeof(i->tbshash));
    i->not_before = x509->not_before;
    i->not_after = x509->not_after;
    i->hashtype = x509->hashtype;
    i->certSign = x509->certSign;
    i->codeSign = x509->codeSign;
    i->timeSign = x509->timeSign;
    i->isBlacklisted = x509->isBlacklisted;
    i->next = m->crts;
    i->prev = NULL;
    if(m->crts)
	m->crts->prev = i;
    m->crts = i;

    m->items++;
    return 0;
}

void crtmgr_init(crtmgr *m) {
    m->crts = NULL;
    m->items = 0;
}

void crtmgr_del(crtmgr *m, cli_crt *x509) {
    cli_crt *i;
    for(i = m->crts; i; i = i->next) {
	if(i==x509) {
	    if(i->prev)
		i->prev->next = i->next;
	    else
		m->crts = i->next;
	    if(i->next)
		i->next->prev = i->prev;
	    cli_crt_clear(x509);
        if ((x509->name))
            free(x509->name);
	    free(x509);
	    m->items--;
	    return;
	}
    }
}

void crtmgr_free(crtmgr *m) {
    while(m->items)
	crtmgr_del(m, m->crts);
}

static int crtmgr_rsa_verify(cli_crt *x509, mp_int *sig, cli_crt_hashtype hashtype, const uint8_t *refhash) {
    int keylen = mp_unsigned_bin_size(&x509->n), siglen = mp_unsigned_bin_size(sig);
    int ret, j, objlen, hashlen = (hashtype == CLI_SHA1RSA) ? SHA1_HASH_SIZE : 16;
    uint8_t d[513];
    mp_int x;

    if((ret = mp_init(&x))) {
	cli_errmsg("crtmgr_rsa_verify: mp_init failed with %d\n", ret);
	return 1;
    }

    do {
	if(MAX(keylen, siglen) - MIN(keylen, siglen) > 1)
	    break;
	if((ret = mp_exptmod(sig, &x509->e, &x509->n, &x))) {
	    cli_warnmsg("crtmgr_rsa_verify: verification failed: mp_exptmod failed with %d\n", ret);
	    break;
	}
	if(mp_unsigned_bin_size(&x) != keylen - 1)
	    break;
	if((ret = mp_to_unsigned_bin(&x, d))) {
	    cli_warnmsg("crtmgr_rsa_verify: mp_unsigned_bin_size failed with %d\n", ret);
	    break;
	}
	if(*d != 1) /* block type 1 */
	    break;

	keylen -= 1; /* 0xff padding */
	for(j=1; j<keylen-2; j++)
	    if(d[j] != 0xff)
		break;
	if(j == keylen - 2)
	    break;
	if(d[j] != 0) /* 0x00 separator */
	    break;

	j++;
	keylen -= j; /* asn1 size */

	if(keylen < hashlen)
	    break;
	if(keylen > hashlen) {
	    /* hash is asn1 der encoded */
	    /* SEQ { SEQ { OID, NULL }, OCTET STRING */
	    if(keylen < 2 || d[j] != 0x30 || d[j+1] + 2 != keylen)
		break;
	    keylen -= 2;
	    j+=2;

	    if(keylen <2 || d[j] != 0x30)
		break;

	    objlen = d[j+1];

	    keylen -= 2;
	    j+=2;
	    if(keylen < objlen)
		break;
	    if(objlen == 9) {
		if(hashtype != CLI_SHA1RSA || memcmp(&d[j], "\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00", 9)) {
		    cli_errmsg("crtmgr_rsa_verify: FIXME ACAB - CRYPTO MISSING?\n");
		    break;
		}
	    } else if(objlen == 12) {
		if(hashtype != CLI_MD5RSA || memcmp(&d[j], "\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00", 12)) {
		    cli_errmsg("crtmgr_rsa_verify: FIXME ACAB - CRYPTO MISSING?\n");
		    break;
		}
	    } else {
		cli_errmsg("crtmgr_rsa_verify: FIXME ACAB - CRYPTO MISSING?\n");
		break;
	    }

	    keylen -= objlen;
	    j += objlen;
	    if(keylen < 2 || d[j] != 0x04 || d[j+1] != hashlen)
		break;
	    keylen -= 2;
	    j+=2;
	    if(keylen != hashlen)
		break;
	}
	if(memcmp(&d[j], refhash, hashlen))
	    break;

	mp_clear(&x);
	return 0;

    } while(0);

    mp_clear(&x);
    return 1;
}


cli_crt *crtmgr_verify_crt(crtmgr *m, cli_crt *x509) {
    cli_crt *i = m->crts, *best = NULL;
    int score = 0;

    for (i = m->crts; i; i = i->next) {
        if (!memcmp(i->subject, x509->subject, sizeof(i->subject)) &&
            !memcmp(i->serial, x509->serial, sizeof(i->serial))) {
            if (i->isBlacklisted)
                return i;
        }
    }

    for(i = m->crts; i; i = i->next) {
	if(i->certSign &&
	   !memcmp(i->subject, x509->issuer, sizeof(i->subject)) &&
	   !crtmgr_rsa_verify(i, &x509->sig, x509->hashtype, x509->tbshash)) {
	    int curscore;
	    if((x509->codeSign & i->codeSign) == x509->codeSign && (x509->timeSign & i->timeSign) == x509->timeSign)
		return i;
	    curscore = (x509->codeSign & i->codeSign) + (x509->timeSign & i->timeSign);
	    if(curscore > score) {
		best = i;
		score = curscore;
	    }
	}
    }
    return best;
}

cli_crt *crtmgr_verify_pkcs7(crtmgr *m, const uint8_t *issuer, const uint8_t *serial, const void *signature, unsigned int signature_len, cli_crt_hashtype hashtype, const uint8_t *refhash, cli_vrfy_type vrfytype) {
    cli_crt *i;
    mp_int sig;
    int ret;

    if(signature_len < 1024/8 || signature_len > 4096/8+1) {
	cli_dbgmsg("crtmgr_verify_pkcs7: unsupported sig len: %u\n", signature_len);
	return NULL;
    }
    if((ret = mp_init(&sig))) {
	cli_errmsg("crtmgr_verify_pkcs7: mp_init failed with %d\n", ret);
	return NULL;
    }

    if((ret=mp_read_unsigned_bin(&sig, signature, signature_len))) {
	cli_warnmsg("crtmgr_verify_pkcs7: mp_read_unsigned_bin failed with %d\n", ret);
	return NULL;
    }

    for(i = m->crts; i; i = i->next) {
	if(vrfytype == VRFY_CODE && !i->codeSign)
	    continue;
	if(vrfytype == VRFY_TIME && !i->timeSign)
	    continue;
	if(!memcmp(i->issuer, issuer, sizeof(i->issuer)) &&
	   !memcmp(i->serial, serial, sizeof(i->serial)) &&
	   !crtmgr_rsa_verify(i, &sig, hashtype, refhash)) {
	    break;
        }
    }
    mp_clear(&sig);
    return i;
}

/* DC=com, DC=microsoft, CN=Microsoft Root Certificate Authority */
static const uint8_t MSCA_SUBJECT[] = "\x11\x3b\xd8\x6b\xed\xde\xbc\xd4\xc5\xf1\x0a\xa0\x7a\xb2\x02\x6b\x98\x2f\x4b\x92";
static const uint8_t MSCA_MOD[] = "\
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
static const uint8_t MSCA_EXP[] = "\x01\x00\x01";

/* OU=Copyright (c) 1997 Microsoft Corp., OU=Microsoft Corporation, CN=Microsoft Root Authority */
static const uint8_t MSA_SUBJECT[] = "\xad\xf7\x98\x77\x06\x5e\xf3\x05\xeb\x95\xb5\x6d\xbc\xa9\xe6\x3e\x9a\xb4\x0d\x3b";
static const uint8_t MSA_MOD[] = "\
\x00\xa9\x02\xbd\xc1\x70\xe6\x3b\xf2\x4e\x1b\x28\x9f\x97\x78\
\x5e\x30\xea\xa2\xa9\x8d\x25\x5f\xf8\xfe\x95\x4c\xa3\xb7\xfe\
\x9d\xa2\x20\x3e\x7c\x51\xa2\x9b\xa2\x8f\x60\x32\x6b\xd1\x42\
\x64\x79\xee\xac\x76\xc9\x54\xda\xf2\xeb\x9c\x86\x1c\x8f\x9f\
\x84\x66\xb3\xc5\x6b\x7a\x62\x23\xd6\x1d\x3c\xde\x0f\x01\x92\
\xe8\x96\xc4\xbf\x2d\x66\x9a\x9a\x68\x26\x99\xd0\x3a\x2c\xbf\
\x0c\xb5\x58\x26\xc1\x46\xe7\x0a\x3e\x38\x96\x2c\xa9\x28\x39\
\xa8\xec\x49\x83\x42\xe3\x84\x0f\xbb\x9a\x6c\x55\x61\xac\x82\
\x7c\xa1\x60\x2d\x77\x4c\xe9\x99\xb4\x64\x3b\x9a\x50\x1c\x31\
\x08\x24\x14\x9f\xa9\xe7\x91\x2b\x18\xe6\x3d\x98\x63\x14\x60\
\x58\x05\x65\x9f\x1d\x37\x52\x87\xf7\xa7\xef\x94\x02\xc6\x1b\
\xd3\xbf\x55\x45\xb3\x89\x80\xbf\x3a\xec\x54\x94\x4e\xae\xfd\
\xa7\x7a\x6d\x74\x4e\xaf\x18\xcc\x96\x09\x28\x21\x00\x57\x90\
\x60\x69\x37\xbb\x4b\x12\x07\x3c\x56\xff\x5b\xfb\xa4\x66\x0a\
\x08\xa6\xd2\x81\x56\x57\xef\xb6\x3b\x5e\x16\x81\x77\x04\xda\
\xf6\xbe\xae\x80\x95\xfe\xb0\xcd\x7f\xd6\xa7\x1a\x72\x5c\x3c\
\xca\xbc\xf0\x08\xa3\x22\x30\xb3\x06\x85\xc9\xb3\x20\x77\x13\
\x85\xdf";
static const uint8_t MSA_EXP[] = "\x01\x00\x01";


/* C=ZA, ST=Western Cape, L=Durbanville, O=Thawte, OU=Thawte Certification, CN=Thawte Timestamping CA */
static const uint8_t THAW_SUBJECT[] = "\x9a\x02\x27\x8e\x9c\xb1\x28\x76\xc4\x7a\xb0\xbc\x75\xdd\x69\x4e\x72\xd1\xb2\xbc";
static const uint8_t THAW_MOD[] = "\
\x00\xd6\x2b\x58\x78\x61\x45\x86\x53\xea\x34\x7b\x51\x9c\xed\
\xb0\xe6\x2e\x18\x0e\xfe\xe0\x5f\xa8\x27\xd3\xb4\xc9\xe0\x7c\
\x59\x4e\x16\x0e\x73\x54\x60\xc1\x7f\xf6\x9f\x2e\xe9\x3a\x85\
\x24\x15\x3c\xdb\x47\x04\x63\xc3\x9e\xc4\x94\x1a\x5a\xdf\x4c\
\x7a\xf3\xd9\x43\x1d\x3c\x10\x7a\x79\x25\xdb\x90\xfe\xf0\x51\
\xe7\x30\xd6\x41\x00\xfd\x9f\x28\xdf\x79\xbe\x94\xbb\x9d\xb6\
\x14\xe3\x23\x85\xd7\xa9\x41\xe0\x4c\xa4\x79\xb0\x2b\x1a\x8b\
\xf2\xf8\x3b\x8a\x3e\x45\xac\x71\x92\x00\xb4\x90\x41\x98\xfb\
\x5f\xed\xfa\xb7\x2e\x8a\xf8\x88\x37";
const uint8_t THAW_EXP[] = "\x01\x00\x01";


/* C=US, O=VeriSign, Inc., OU=Class 3 Public Primary Certification Authority */
static const uint8_t VER_SUBJECT[] = "\x29\xdb\xd4\xb8\x8f\x78\x5f\x33\x41\x92\x87\xe1\xaf\x46\x50\xe1\x77\xa4\x6f\xc0";
static const uint8_t VER_MOD[] = "\
\x00\xc9\x5c\x59\x9e\xf2\x1b\x8a\x01\x14\xb4\x10\xdf\x04\x40\
\xdb\xe3\x57\xaf\x6a\x45\x40\x8f\x84\x0c\x0b\xd1\x33\xd9\xd9\
\x11\xcf\xee\x02\x58\x1f\x25\xf7\x2a\xa8\x44\x05\xaa\xec\x03\
\x1f\x78\x7f\x9e\x93\xb9\x9a\x00\xaa\x23\x7d\xd6\xac\x85\xa2\
\x63\x45\xc7\x72\x27\xcc\xf4\x4c\xc6\x75\x71\xd2\x39\xef\x4f\
\x42\xf0\x75\xdf\x0a\x90\xc6\x8e\x20\x6f\x98\x0f\xf8\xac\x23\
\x5f\x70\x29\x36\xa4\xc9\x86\xe7\xb1\x9a\x20\xcb\x53\xa5\x85\
\xe7\x3d\xbe\x7d\x9a\xfe\x24\x45\x33\xdc\x76\x15\xed\x0f\xa2\
\x71\x64\x4c\x65\x2e\x81\x68\x45\xa7";
static const uint8_t VER_EXP[] = "\x01\x00\x01";


int crtmgr_add_roots(struct cl_engine *engine, crtmgr *m) {
    cli_crt ca;
    cli_crt *crt, *new_crt;

    /*
     * Certs are cached in engine->cmgr. Copy from there.
     */
    if (m != &(engine->cmgr)) {
       for (crt = engine->cmgr.crts; crt != NULL; crt = crt->next) {
           if (crtmgr_add(m, crt)) {
               crtmgr_free(m);
               return 1;
           }
       }

       return 0;
    }

    return 0;
}
