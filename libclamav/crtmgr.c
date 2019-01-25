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

#include "clamav.h"
#include "others.h"
#include "crtmgr.h"

#define OID_1_2_840_113549_2_5 "\x2a\x86\x48\x86\xf7\x0d\x02\x05"
#define OID_md5 OID_1_2_840_113549_2_5

#define OID_1_3_14_3_2_26 "\x2b\x0e\x03\x02\x1a"
#define OID_sha1 OID_1_3_14_3_2_26

#define OID_2_16_840_1_101_3_4_2_1 "\x60\x86\x48\x01\x65\x03\x04\x02\x01"
#define OID_sha256 OID_2_16_840_1_101_3_4_2_1

#define OID_2_16_840_1_101_3_4_2_2 "\x60\x86\x48\x01\x65\x03\x04\x02\x02"
#define OID_sha384 OID_2_16_840_1_101_3_4_2_2

#define OID_2_16_840_1_101_3_4_2_3 "\x60\x86\x48\x01\x65\x03\x04\x02\x03"
#define OID_sha512 OID_2_16_840_1_101_3_4_2_3


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

/* Look for an existing certificate in the trust store m.  This search allows
 * the not_before / not_after / certSign / codeSign / timeSign fields to be
 * more restrictive than the values associated with a cert in the trust store,
 * but not less.  It's probably overkill to not do exact matching on those
 * fields... TODO Is there a case where this is needed
 *
 * There are two ways that things get added to the whitelist - through the CRB
 * rules, and through embedded signatures / catalog files that we parse.  CRB
 * rules only specify the subject, serial, public key, and whether the cert
 * can be used for cert/code/time signing, so in those cases the issuer and
 * hashtype get set to a hardcoded value.  Those values are important for
 * doing signature verification, though, so we include them when doing this
 * lookup.  That way, certs with more specific values can get added to the
 * whitelist by functions like crtmgr_add and increase the probability of
 * successful signature verification. */
cli_crt *crtmgr_whitelist_lookup(crtmgr *m, cli_crt *x509) {
    cli_crt *i;
    for(i = m->crts; i; i = i->next) {
        if(!i->isBlacklisted &&
           x509->not_before >= i->not_before &&
           x509->not_after <= i->not_after &&
           (i->certSign | x509->certSign) == i->certSign &&
           (i->codeSign | x509->codeSign) == i->codeSign &&
           (i->timeSign | x509->timeSign) == i->timeSign &&
           !memcmp(x509->subject, i->subject, sizeof(i->subject)) &&
           !memcmp(x509->serial, i->serial, sizeof(i->serial)) &&
           !memcmp(x509->issuer, i->issuer, sizeof(i->issuer)) &&
           x509->hashtype == i->hashtype &&
           !mp_cmp(&x509->n, &i->n) &&
           !mp_cmp(&x509->e, &i->e)) {
            return i;
        }
    }
    return NULL;
}

cli_crt *crtmgr_blacklist_lookup(crtmgr *m, cli_crt *x509) {
    cli_crt *i;
    for (i = m->crts; i; i = i->next) {
        // The CRB rules are based on subject, serial, and public key,
        // so do blacklist queries based on those fields

        // TODO Handle the case where these items aren't specified in a CRB
        // rule entry - substitute in default values instead.

        if (i->isBlacklisted &&
            !memcmp(i->subject, x509->subject, sizeof(i->subject)) &&
            !memcmp(i->serial, x509->serial, sizeof(i->serial)) &&
            !mp_cmp(&x509->n, &i->n) &&
            !mp_cmp(&x509->e, &i->e)) {
            return i;
        }
    }
    return NULL;
}

/* Determine whether x509 already exists in m. The fields compared depend on
 * whether x509 is a blacklist entry or a trusted certificate */
cli_crt *crtmgr_lookup(crtmgr *m, cli_crt *x509) {
    if (x509->isBlacklisted) {
        return crtmgr_blacklist_lookup(m, x509);
    } else {
        return crtmgr_whitelist_lookup(m, x509);
    }
}

int crtmgr_add(crtmgr *m, cli_crt *x509) {
    cli_crt *i;
    int ret = 0;

    if (x509->isBlacklisted) {
        if (crtmgr_blacklist_lookup(m, x509)) {
            cli_dbgmsg("crtmgr_add: duplicate blacklist entry detected - not adding\n");
            return 0;
        }
    } else {
        if (crtmgr_whitelist_lookup(m, x509)) {
            cli_dbgmsg("crtmgr_add: duplicate trusted certificate detected - not adding\n");
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

    memcpy(i->raw_subject, x509->raw_subject, sizeof(i->raw_subject));
    memcpy(i->raw_issuer, x509->raw_issuer, sizeof(i->raw_issuer));
    memcpy(i->raw_serial, x509->raw_serial, sizeof(i->raw_serial));
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
    int ret, j, objlen, hashlen;
    uint8_t d[513];
    mp_int x;

    if (hashtype == CLI_SHA1RSA) {
        hashlen = SHA1_HASH_SIZE;
    } else if (hashtype == CLI_MD5RSA) {
        hashlen = MD5_HASH_SIZE;
    } else if (hashtype == CLI_SHA256RSA) {
        hashlen = SHA256_HASH_SIZE;
    } else if (hashtype == CLI_SHA384RSA) {
        hashlen = SHA384_HASH_SIZE;
    } else if (hashtype == CLI_SHA512RSA) {
        hashlen = SHA512_HASH_SIZE;
    } else {
        cli_errmsg("crtmgr_rsa_verify: Unsupported hashtype: %d\n", hashtype);
        return 1;
    }

    if((ret = mp_init(&x))) {
        cli_errmsg("crtmgr_rsa_verify: mp_init failed with %d\n", ret);
        return 1;
    }

    do {
        if(MAX(keylen, siglen) - MIN(keylen, siglen) > 1) {
            cli_dbgmsg("crtmgr_rsa_verify: keylen and siglen differ by more than one\n");
            break;
        }
        if((ret = mp_exptmod(sig, &x509->e, &x509->n, &x))) {
            cli_warnmsg("crtmgr_rsa_verify: verification failed: mp_exptmod failed with %d\n", ret);
            break;
        }
        if(mp_unsigned_bin_size(&x) != keylen - 1){
            cli_dbgmsg("crtmgr_rsa_verify: keylen-1 doesn't match expected size of exptmod result\n");
            break;
        }
        if(((unsigned int) mp_unsigned_bin_size(&x)) > sizeof(d)) {
            cli_dbgmsg("crtmgr_rsa_verify: exptmod result would overrun working buffer\n");
            break;
        }
        if((ret = mp_to_unsigned_bin(&x, d))) {
            cli_warnmsg("crtmgr_rsa_verify: mp_unsigned_bin_size failed with %d\n", ret);
            break;
        }
        if(*d != 1) {/* block type 1 */
            cli_dbgmsg("crtmgr_rsa_verify: expected block type 1 at d[0]\n");
            break;
        }

        keylen -= 1; /* 0xff padding */
        for(j=1; j<keylen-2; j++)
            if(d[j] != 0xff)
                break;
        if(j == keylen - 2) {
            cli_dbgmsg("crtmgr_rsa_verify: only encountered 0xFF padding parsing cert\n");
            break;
        }
        if(d[j] != 0) { /* 0x00 separator */
            cli_dbgmsg("crtmgr_rsa_verify: expected 0x00 separator\n");
            break;
        }

        j++;
        keylen -= j; /* asn1 size */

        if(keylen < hashlen) {
            cli_dbgmsg("crtmgr_rsa_verify: encountered keylen less than hashlen\n");
            break;
        }
        if(keylen > hashlen) {
            /* hash is asn1 der encoded */
            /* SEQ { SEQ { OID, NULL }, OCTET STRING */
            if(keylen < 2 || d[j] != 0x30 || d[j+1] + 2 != keylen) {
                cli_dbgmsg("crtmgr_rsa_verify: unexpected hash to be ASN1 DER encoded\n");
                break;
            }
            keylen -= 2;
            j+=2;

            if(keylen <2 || d[j] != 0x30) {
                cli_dbgmsg("crtmgr_rsa_verify: expected SEQUENCE at beginning of cert AlgorithmIdentifier\n");
                break;
            }

            objlen = d[j+1];

            keylen -= 2;
            j+=2;
            if(keylen < objlen) {
                cli_dbgmsg("crtmgr_rsa_verify: key length mismatch in ASN1 DER hash encoding\n");
                break;
            }
            if(objlen == 9) {
                // Check for OID type indicating a length of 5, OID_sha1, and the NULL type/value
                if(hashtype != CLI_SHA1RSA || memcmp(&d[j], "\x06\x05" OID_sha1 "\x05\x00", 9)) {
                    cli_errmsg("crtmgr_rsa_verify: FIXME ACAB - CRYPTO MISSING?\n");
                    break;
                }
            } else if(objlen == 12) {
                // Check for OID type indicating a length of 8, OID_md5, and the NULL type/value
                if(hashtype != CLI_MD5RSA || memcmp(&d[j], "\x06\x08" OID_md5 "\x05\x00", 12)) {
                    cli_errmsg("crtmgr_rsa_verify: FIXME ACAB - CRYPTO MISSING?\n");
                    break;
                }
            } else if(objlen == 13) {
                if (hashtype == CLI_SHA256RSA) {
                    // Check for OID type indicating a length of 9, OID_sha256, and the NULL type/value
                    if (0 != memcmp(&d[j], "\x06\x09" OID_sha256 "\x05\x00", 13)) {
                        cli_dbgmsg("crtmgr_rsa_verify: invalid AlgorithmIdentifier block for SHA256 hash\n");
                        break;
                    }

                } else if (hashtype == CLI_SHA384RSA) {
                    // Check for OID type indicating a length of 9, OID_sha384, and the NULL type/value
                    if (0 != memcmp(&d[j], "\x06\x09" OID_sha384 "\x05\x00", 13)) {
                        cli_dbgmsg("crtmgr_rsa_verify: invalid AlgorithmIdentifier block for SHA384 hash\n");
                        break;
                    }

                } else if (hashtype == CLI_SHA512RSA) {
                    // Check for OID type indicating a length of 9, OID_sha512, and the NULL type/value
                    if (0 != memcmp(&d[j], "\x06\x09" OID_sha512 "\x05\x00", 13)) {
                        cli_dbgmsg("crtmgr_rsa_verify: invalid AlgorithmIdentifier block for SHA512 hash\n");
                        break;
                    }

                } else {
                    cli_errmsg("crtmgr_rsa_verify: FIXME ACAB - CRYPTO MISSING?\n");
                    break;
                }
            } else {
                cli_errmsg("crtmgr_rsa_verify: FIXME ACAB - CRYPTO MISSING?\n");
                break;
            }

            keylen -= objlen;
            j += objlen;
            if(keylen < 2 || d[j] != 0x04 || d[j+1] != hashlen) {
                cli_dbgmsg("crtmgr_rsa_verify: hash length mismatch in ASN1 DER hash encoding\n");
                break;
            }
            keylen -= 2;
            j+=2;
            if(keylen != hashlen) {
                cli_dbgmsg("crtmgr_rsa_verify: extra data in the ASN1 DER hash encoding\n");
                break;
            }
        }
        if(memcmp(&d[j], refhash, hashlen)) {
            // This is a common error case if we are using crtmgr_rsa_verify to
            // determine whether we've found the right issuer certificate based
            // (as is done by crtmgr_verify_crt).  If we are pretty sure that
            // x509 is the correct cert to use for verification, then this
            // case is more of a concern.
            break;
        }

        mp_clear(&x);
        return 0;

    } while(0);

    mp_clear(&x);
    return 1;
}

/* For a given cli_crt, returns an existing blacklisted cert in crtmgr if one
 * is present.  Otherwise returns a pointer to the signer x509 certificate if
 * one is found in the crtmgr and it's signature can be validated (NULL is
 * returned otherwise.) */
cli_crt *crtmgr_verify_crt(crtmgr *m, cli_crt *x509) {
    cli_crt *i = m->crts, *best = NULL;
    int score = 0;
    unsigned int possible = 0;

    if (NULL != (i = crtmgr_blacklist_lookup(m, x509))) {
        return i;
    }

    // TODO Technically we should loop through all of the blacklisted certs
    // first to see whether one of those is used to sign x509.  This case
    // will get handled if the blacklisted certificate is embedded, since we
    // will call crtmgr_verify_crt on it and match against the blacklist entry
    // that way, but the cert doesn't HAVE to be embedded.  This case seems
    // unlikely enough to ignore, though.

    for(i = m->crts; i; i = i->next) {
        if(i->certSign &&
           !i->isBlacklisted &&
           !memcmp(i->subject, x509->issuer, sizeof(i->subject)) &&
           !crtmgr_rsa_verify(i, &x509->sig, x509->hashtype, x509->tbshash)) {
            int curscore;
            if((x509->codeSign & i->codeSign) == x509->codeSign && (x509->timeSign & i->timeSign) == x509->timeSign)
                return i;
            possible++;
            curscore = (x509->codeSign & i->codeSign) + (x509->timeSign & i->timeSign);
            if(curscore > score) {
                best = i;
                score = curscore;
            }
        }
    }

    if (possible > 1) {
        // If this is ever triggered, it's probably an indication of an error
        // in the CRB being used.
        cli_warnmsg("crtmgr_verify_crt: choosing between codeSign cert and timeSign cert without enough info - errors may result\n");
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
        cli_dbgmsg("crtmgr_verify_pkcs7: mp_init failed with %d\n", ret);
        return NULL;
    }

    if((ret=mp_read_unsigned_bin(&sig, signature, signature_len))) {
        cli_dbgmsg("crtmgr_verify_pkcs7: mp_read_unsigned_bin failed with %d\n", ret);
        return NULL;
    }

    for(i = m->crts; i; i = i->next) {
        if(vrfytype == VRFY_CODE && !i->codeSign)
            continue;
        if(vrfytype == VRFY_TIME && !i->timeSign)
            continue;
        if(!memcmp(i->issuer, issuer, sizeof(i->issuer)) &&
           !memcmp(i->serial, serial, sizeof(i->serial))) {
            if(!crtmgr_rsa_verify(i, &sig, hashtype, refhash)) {
                break;
            }
            cli_dbgmsg("crtmgr_verify_pkcs7: found cert with matching issuer and serial but RSA verification failed\n");
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
