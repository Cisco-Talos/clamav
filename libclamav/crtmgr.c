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

#include "clamav.h"
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
    UNUSEDPARAM(x509);
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

int crtmgr_add_roots(struct cl_engine *engine, crtmgr *m) {
    cli_crt *crt;
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
