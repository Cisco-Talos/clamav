/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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

static int cli_crt_init_fps(cli_crt *x509)
{
    x509->n   = BN_new();
    x509->e   = BN_new();
    x509->sig = BN_new();

    if (!x509->n || !x509->e || !x509->sig) {
        BN_free(x509->n);
        BN_free(x509->e);
        BN_free(x509->sig);

        x509->n   = NULL;
        x509->e   = NULL;
        x509->sig = NULL;
        return -1;
    }
    return 0;
}

int cli_crt_init(cli_crt *x509)
{
    memset(x509, 0, sizeof(*x509));
    return cli_crt_init_fps(x509);
}

void cli_crt_clear(cli_crt *x509)
{
    BN_free(x509->n);
    BN_free(x509->e);
    BN_free(x509->sig);
    x509->n   = NULL;
    x509->e   = NULL;
    x509->sig = NULL;
}

/* Look for an existing certificate in the trust store `m`.  This search allows
 * the not_before / not_after / certSign / codeSign / timeSign fields to be
 * more restrictive than the values associated with a cert in the trust store,
 * but not less.  It's probably overkill to not do exact matching on those
 * fields... TODO Is there a case where this is needed
 *
 * There are two ways that things get added to the trust list - through the CRB
 * rules, and through embedded signatures / catalog files that we parse.  CRB
 * rules don't currently allow the issuer and hashtype to be specified, so the
 * code sets those to sentinel values (0xca repeating and CLI_HASHTYPE_ANY
 * respectively). Also, the exponent field gets set to a fixed value for CRB
 * rules, and the serial number field is allowed to be empty as well (in this
 * case it will get set to 0xca repeating).
 *
 * There are two ways we'd like to use this function:
 *
 *  - To see whether x509 already exists in m (when adding new CRB sig certs
 *    and when adding certs that are embedded in Authenticode signatures) to
 *    prevent duplicate entries. In this case, we want to take x509's
 *    hashtype, issuer, serial, and exponent field into account, so a CRB sig
 *    cert entry isn't returned for an embedded cert duplicate check, and so
 *    that two embedded certs with different hash types, issuers, serials, or
 *    exponents aren't treated as being the same. A non-NULL return when used
 *    this way means that the cert need not be added to the trust store.
 *
 *  - To see whether a CRB sig matches against x509, deeming it worthy to be
 *    added to the trust store.  In this case, we don't want to compare
 *    hashtype and issuer, since the embedded sig will have the actual values
 *    and the CRB sig cert will have placeholder values. A non-NULL return
 *    value when used this way means that the cert doesn't match against an
 *    existing CRB rule and should not be added to the trust store.
 *
 * Use crb_crts_only to distinguish between the two cases.  If True, it will
 * ignore all crts not added from CRB rules and ignore x509's issuer and
 * hashtype fields.
 *
 */
cli_crt *crtmgr_trust_list_lookup(crtmgr *m, cli_crt *x509, int crb_crts_only)
{
    cli_crt *i;
    for (i = m->crts; i; i = i->next) {

        if (i->isBlocked) {
            continue;
        }

        if (crb_crts_only) {
            if (i->hashtype != CLI_HASHTYPE_ANY) {
                continue;
            }
        } else {
            /* Almost all of the rules in m will be CRB rules, so optimize for
             * the case where we are trying to determine whether an embedded
             * cert already exists in m (by checking the hashtype first). Do
             * the other non-CRB rule cert checks here too to simplify the
             * code. */

            if (x509->hashtype != i->hashtype ||
                memcmp(x509->issuer, i->issuer, sizeof(i->issuer)) ||
                x509->ignore_serial != i->ignore_serial ||
                BN_cmp(x509->e, i->e)) {
                continue;
            }
        }

        if (!i->ignore_serial) {
            if (memcmp(x509->serial, i->serial, sizeof(i->serial))) {
                continue;
            }
        }

        if (x509->not_before >= i->not_before &&
            x509->not_after <= i->not_after &&
            (i->certSign | x509->certSign) == i->certSign &&
            (i->codeSign | x509->codeSign) == i->codeSign &&
            (i->timeSign | x509->timeSign) == i->timeSign &&
            !memcmp(x509->subject, i->subject, sizeof(i->subject)) &&
            !BN_cmp(x509->n, i->n)) {
            return i;
        }
    }
    return NULL;
}

cli_crt *crtmgr_block_list_lookup(crtmgr *m, cli_crt *x509)
{
    cli_crt *i;
    for (i = m->crts; i; i = i->next) {
        /* The CRB rules are based on subject, serial, and public key,
         * so do block list lookups based on those fields. The serial
         * number field can also be blank, which effectively blocks
         * all possible serial numbers using the specified subject and
         * public key. Sometimes when people go to have their cert
         * renewed, they'll opt to have the subject and public key be
         * the same, but the CA must issue a new serial number for the
         * new cert. A blank issuer in a CRB rule allows blocking
         * all of these at once. */

        // TODO the rule format specifies CodeSign / TimeSign / CertSign
        // which we could also match on, but we just ignore those fields
        // for blocked certs for now

        // TODO the rule format allows the exponent to be specified as well,
        // but that gets ignored when CRB rules are parsed (and set to a fixed
        // value), so ignore that field when looking at certs

        if (!i->isBlocked ||
            memcmp(i->subject, x509->subject, sizeof(i->subject)) ||
            BN_cmp(x509->n, i->n)) {
            continue;
        }

        if (!i->ignore_serial) {
            if (memcmp(i->serial, x509->serial, sizeof(i->serial))) {
                continue;
            }
        }
        return i;
    }
    return NULL;
}

/* Determine whether x509 already exists in m. The fields compared depend on
 * whether x509 is a block entry or a trusted certificate */
cli_crt *crtmgr_lookup(crtmgr *m, cli_crt *x509)
{
    if (x509->isBlocked) {
        return crtmgr_block_list_lookup(m, x509);
    } else {
        return crtmgr_trust_list_lookup(m, x509, 0);
    }
}

bool crtmgr_add(crtmgr *m, cli_crt *x509)
{
    bool failed = true;
    cli_crt *i  = NULL;

    if (x509->isBlocked) {
        if (crtmgr_block_list_lookup(m, x509)) {
            cli_dbgmsg("crtmgr_add: duplicate blocked certificate detected - not adding\n");
            failed = false;
            goto done;
        }
    } else {
        if (crtmgr_trust_list_lookup(m, x509, 0)) {
            cli_dbgmsg("crtmgr_add: duplicate trusted certificate detected - not adding\n");
            failed = false;
            goto done;
        }
    }

    i = malloc(sizeof(*i));
    if (i == NULL) {
        goto done;
    }

    if (cli_crt_init_fps(i) < 0) {
        goto done;
    }

    if (!BN_copy(i->n, x509->n)) {
        goto done;
    }
    if (!BN_copy(i->e, x509->e)) {
        goto done;
    }
    if (!BN_copy(i->sig, x509->sig)) {
        goto done;
    }

    if (x509->name) {
        i->name = strdup(x509->name);
        if (!i->name)
            goto done;
    } else {
        i->name = NULL;
    }

    memcpy(i->raw_subject, x509->raw_subject, sizeof(i->raw_subject));
    memcpy(i->raw_issuer, x509->raw_issuer, sizeof(i->raw_issuer));
    memcpy(i->raw_serial, x509->raw_serial, sizeof(i->raw_serial));
    memcpy(i->subject, x509->subject, sizeof(i->subject));
    memcpy(i->serial, x509->serial, sizeof(i->serial));
    memcpy(i->issuer, x509->issuer, sizeof(i->issuer));
    memcpy(i->tbshash, x509->tbshash, sizeof(i->tbshash));
    i->ignore_serial = x509->ignore_serial;
    i->not_before    = x509->not_before;
    i->not_after     = x509->not_after;
    i->hashtype      = x509->hashtype;
    i->certSign      = x509->certSign;
    i->codeSign      = x509->codeSign;
    i->timeSign      = x509->timeSign;
    i->isBlocked     = x509->isBlocked;
    i->next          = m->crts;
    i->prev          = NULL;
    if (m->crts) {
        m->crts->prev = i;
    }
    m->crts = i;

    m->items++;

    failed = false;
    i      = NULL;

done:
    if (i != NULL) {
        cli_crt_clear(i);
        free(i);
    }

    return failed;
}

void crtmgr_init(crtmgr *m)
{
    m->crts  = NULL;
    m->items = 0;
}

void crtmgr_del(crtmgr *m, cli_crt *x509)
{
    cli_crt *i;
    for (i = m->crts; i; i = i->next) {
        if (i == x509) {
            if (i->prev)
                i->prev->next = i->next;
            else
                m->crts = i->next;
            if (i->next)
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

void crtmgr_free(crtmgr *m)
{
    while (m->items)
        crtmgr_del(m, m->crts);
}

static cl_error_t _padding_check_PKCS1_type_1(uint8_t **to, int *tlen,
                                              uint8_t *from, unsigned int flen,
                                              unsigned int num)
{
    int i, j;
    unsigned char *p;

    p = from;

    /*
     * The format is
     * 00 || 01 || PS || 00 || D
     * PS - padding string, at least 8 bytes of FF
     * D  - data.
     */

    if (num < 11) /* RSA_PKCS1_PADDING_SIZE */
        return CL_EPARSE;

    /* Accept inputs with and without the leading 0-byte. */
    if (num == flen) {
        if ((*p++) != 0x00) {
            cli_dbgmsg("%s: Bad padding\n", __func__);
            return CL_EPARSE;
        }
        flen--;
    }

    if ((num != (flen + 1)) || (*(p++) != 0x01)) {
        cli_dbgmsg("%s: Bad block type\n", __func__);
        return CL_EPARSE;
    }

    /* scan over padding data */
    j = flen - 1; /* one for type. */
    for (i = 0; i < j; i++) {
        if (*p != 0xff) { /* should decrypt to 0xff */
            if (*p == 0) {
                p++;
                break;
            } else {
                cli_dbgmsg("%s: Bad header\n", __func__);
                return CL_EPARSE;
            }
        }
        p++;
    }

    if (i == j) {
        cli_dbgmsg("%s: Bad header\n", __func__);
        return CL_EPARSE;
    }

    if (i < 8) {
        cli_dbgmsg("%s: Bad padding\n", __func__);
        return CL_EPARSE;
    }
    i++; /* Skip over the '\0' */
    j -= i;
    *tlen = j;
    *to   = p;

    return CL_SUCCESS;
}

static cl_error_t crtmgr_get_recov_data(BIGNUM *sig, cli_crt *x509,
                                        uint8_t **buffer, uint8_t **payload,
                                        int *payload_len)
{
    BN_CTX *bnctx = NULL;
    int pad_size;
    int keylen;
    uint8_t *d = NULL;
    BIGNUM *x  = NULL;
    cl_error_t ret;

    *buffer      = NULL;
    *payload     = NULL;
    *payload_len = 0;
    ret          = CL_ERROR;

    keylen = BN_num_bytes(x509->n);
    bnctx  = BN_CTX_new();
    if (!bnctx)
        goto done;

    x = BN_new();
    if (!x)
        goto done;

    CLI_MALLOC_OR_GOTO_DONE(d, keylen);

    if (!BN_mod_exp(x, sig, x509->e, x509->n, bnctx)) {
        cli_warnmsg("crtmgr_rsa_verify: verification failed: BN_mod_exp failed.\n");
        goto done;
    }

    pad_size = BN_bn2bin(x, d);
    if (pad_size < 0) {
        cli_dbgmsg("crtmgr_rsa_verify: buffer too small.\n");
        goto done;
    }

    ret = _padding_check_PKCS1_type_1(payload, payload_len, d, pad_size, keylen);
    if (ret != CL_SUCCESS) {
        cli_dbgmsg("crtmgr_rsa_verify: RSA_padding_check_PKCS1_type_1() failed\n");
        goto done;
    }
    *buffer = d;
    d       = NULL;
    ret     = CL_SUCCESS;

done:
    BN_CTX_free(bnctx);
    BN_free(x);
    free(d);
    return ret;
}

static int crtmgr_rsa_verify(cli_crt *x509, BIGNUM *sig, cli_crt_hashtype hashtype, const uint8_t *refhash)
{
    int keylen = BN_num_bytes(x509->n), siglen = BN_num_bytes(sig);
    int j, objlen, hashlen;
    uint8_t *d;
    uint8_t *buff;
    int len;
    cl_error_t ret;

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

    if (MAX(keylen, siglen) - MIN(keylen, siglen) > 1) {
        cli_dbgmsg("crtmgr_rsa_verify: keylen and siglen differ by more than one\n");
        return 1;
    }

    ret = crtmgr_get_recov_data(sig, x509, &buff, &d, &len);
    if (ret != CL_SUCCESS)
        return 1;

    do {
        j = 0;

        if (len <= hashlen) {
            cli_dbgmsg("crtmgr_rsa_verify: encountered len less than hashlen\n");
            break;
        }
        /* hash is asn1 der encoded */
        /* SEQ { SEQ { OID, NULL }, OCTET STRING */
        if (len < 2 || d[j] != 0x30 || d[j + 1] != len - 2) {
            cli_dbgmsg("crtmgr_rsa_verify: unexpected hash to be ASN1 DER encoded.\n");
            break;
        }
        len -= 2;
        j += 2;

        if (len < 2 || d[j] != 0x30) {
            cli_dbgmsg("crtmgr_rsa_verify: expected SEQUENCE at beginning of cert AlgorithmIdentifier\n");
            break;
        }

        objlen = d[j + 1];

        len -= 2;
        j += 2;
        if (len < objlen) {
            cli_dbgmsg("crtmgr_rsa_verify: key length mismatch in ASN1 DER hash encoding\n");
            break;
        }
        if (objlen == 9) {
            // Check for OID type indicating a length of 5, OID_sha1, and the NULL type/value
            if (hashtype != CLI_SHA1RSA || memcmp(&d[j], "\x06\x05" OID_sha1 "\x05\x00", 9)) {
                cli_errmsg("crtmgr_rsa_verify: FIXME ACAB - CRYPTO MISSING?\n");
                break;
            }
        } else if (objlen == 12) {
            // Check for OID type indicating a length of 8, OID_md5, and the NULL type/value
            if (hashtype != CLI_MD5RSA || memcmp(&d[j], "\x06\x08" OID_md5 "\x05\x00", 12)) {
                cli_errmsg("crtmgr_rsa_verify: FIXME ACAB - CRYPTO MISSING?\n");
                break;
            }
        } else if (objlen == 13) {
            if (hashtype == CLI_SHA256RSA) {
                // Check for OID type indicating a length of 9, OID_sha256, and the NULL type/value
                if (0 != memcmp(&d[j], "\x06\x09" OID_sha256 "\x05\x00", 13)) {
                    cli_dbgmsg("crtmgr_rsa_verify: invalid AlgorithmIdentifier block for SHA2-256 hash\n");
                    break;
                }

            } else if (hashtype == CLI_SHA384RSA) {
                // Check for OID type indicating a length of 9, OID_sha384, and the NULL type/value
                if (0 != memcmp(&d[j], "\x06\x09" OID_sha384 "\x05\x00", 13)) {
                    cli_dbgmsg("crtmgr_rsa_verify: invalid AlgorithmIdentifier block for SHA2-384 hash\n");
                    break;
                }

            } else if (hashtype == CLI_SHA512RSA) {
                // Check for OID type indicating a length of 9, OID_sha512, and the NULL type/value
                if (0 != memcmp(&d[j], "\x06\x09" OID_sha512 "\x05\x00", 13)) {
                    cli_dbgmsg("crtmgr_rsa_verify: invalid AlgorithmIdentifier block for SHA2-512 hash\n");
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

        len -= objlen;
        j += objlen;
        if (len < 2 || d[j] != 0x04 || d[j + 1] != hashlen) {
            cli_dbgmsg("crtmgr_rsa_verify: hash length mismatch in ASN1 DER hash encoding\n");
            break;
        }
        j += 2;
        len -= 2;
        if (len != hashlen) {
            cli_dbgmsg("crtmgr_rsa_verify: extra data in the ASN1 DER hash encoding\n");
            break;
        }

        if (memcmp(&d[j], refhash, hashlen)) {
            // This is a common error case if we are using crtmgr_rsa_verify to
            // determine whether we've found the right issuer certificate based
            // (as is done by crtmgr_verify_crt).  If we are pretty sure that
            // x509 is the correct cert to use for verification, then this
            // case is more of a concern.
            break;
        }

        free(buff);
        return 0;

    } while (0);

    free(buff);
    return 1;
}

/* For a given cli_crt, returns a pointer to the signer x509 certificate if
 * one is found in the crtmgr and its signature can be validated (NULL is
 * returned otherwise.) */
cli_crt *crtmgr_verify_crt(crtmgr *m, cli_crt *x509)
{
    cli_crt *i = m->crts, *best = NULL;
    int score             = 0;
    unsigned int possible = 0;

    // Loop through each of the certificates in our trust store and see whether
    // x509 is signed with it.  If it is, it's trusted

    // TODO Technically we should loop through all of the blocked certs
    // first to see whether one of those is used to sign x509.  This case
    // will get handled if the blocked certificate is embedded, since we
    // will call crtmgr_verify_crt on it and match against the block entry
    // that way, but the cert doesn't HAVE to be embedded.  This case seems
    // unlikely enough to ignore, though.  If we ever want to block a
    // stolen CA cert or something, then we will need to revisit this.

    for (i = m->crts; i; i = i->next) {
        if (i->certSign &&
            !i->isBlocked &&
            !memcmp(i->subject, x509->issuer, sizeof(i->subject)) &&
            !crtmgr_rsa_verify(i, x509->sig, x509->hashtype, x509->tbshash)) {
            int curscore;
            if ((x509->codeSign & i->codeSign) == x509->codeSign && (x509->timeSign & i->timeSign) == x509->timeSign)
                return i;
            possible++;
            curscore = (x509->codeSign & i->codeSign) + (x509->timeSign & i->timeSign);
            if (curscore > score) {
                best  = i;
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

cli_crt *crtmgr_verify_pkcs7(crtmgr *m, const uint8_t *issuer, const uint8_t *serial, const void *signature, unsigned int signature_len, cli_crt_hashtype hashtype, const uint8_t *refhash, cli_vrfy_type vrfytype)
{
    cli_crt *i;
    BIGNUM *sig;

    if (signature_len < 1024 / 8 || signature_len > 4096 / 8 + 1) {
        cli_dbgmsg("crtmgr_verify_pkcs7: unsupported sig len: %u\n", signature_len);
        return NULL;
    }

    sig = BN_new();
    if (!sig)
        return NULL;

    BN_bin2bn(signature, signature_len, sig);

    for (i = m->crts; i; i = i->next) {
        if (vrfytype == VRFY_CODE && !i->codeSign)
            continue;
        if (vrfytype == VRFY_TIME && !i->timeSign)
            continue;
        if (!memcmp(i->issuer, issuer, sizeof(i->issuer)) &&
            !memcmp(i->serial, serial, sizeof(i->serial))) {
            if (!crtmgr_rsa_verify(i, sig, hashtype, refhash)) {
                break;
            }
            cli_dbgmsg("crtmgr_verify_pkcs7: found cert with matching issuer and serial but RSA verification failed\n");
        }
    }
    BN_free(sig);
    return i;
}

int crtmgr_add_roots(struct cl_engine *engine, crtmgr *m, int exclude_bl_crts)
{
    cli_crt *crt;
    /*
     * Certs are cached in engine->cmgr. Copy from there.
     */
    if (m != &(engine->cmgr)) {
        for (crt = engine->cmgr.crts; crt != NULL; crt = crt->next) {
            if (exclude_bl_crts && crt->isBlocked) {
                continue;
            }
            if (crtmgr_add(m, crt)) {
                crtmgr_free(m);
                return 1;
            }
        }

        return 0;
    }

    return 0;
}
