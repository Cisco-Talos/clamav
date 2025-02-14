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

#ifndef __CRTMGR_H
#define __CRTMGR_H

#include <time.h>
#include <stdbool.h>
#include <openssl/bn.h>

typedef enum { CLI_HASHTYPE_ANY, /* used by crts added from .CRB rules */
               CLI_SHA1RSA,
               CLI_MD5RSA,
               CLI_MD2RSA,
               CLI_RSA,
               CLI_SHA256RSA,
               CLI_SHA384RSA,
               CLI_SHA512RSA } cli_crt_hashtype;
typedef enum { VRFY_CODE,
               VRFY_TIME } cli_vrfy_type;

#ifndef CRT_RAWMAXLEN
#define CRT_RAWMAXLEN 64
#endif

/* If CRT_RAWMAXLEN is > 256 it will break the way raw data is stored. If
   larger values are needed, we will need to update the code (ex: look at
   map_raw) */
#if CRT_RAWMAXLEN > 256
#error CRT_RAWMAXLEN cannot be greater than 256
#endif

typedef struct cli_crt_t {
    char *name;
    uint8_t raw_subject[CRT_RAWMAXLEN];
    uint8_t raw_issuer[CRT_RAWMAXLEN];
    uint8_t raw_serial[CRT_RAWMAXLEN];
    uint8_t subject[SHA1_HASH_SIZE];
    uint8_t issuer[SHA1_HASH_SIZE];
    uint8_t serial[SHA1_HASH_SIZE];
    /* The serial hash is an optional CRB field, so ignore_serial will be
     * set for certs backing CRB rules where this is the case */
    int ignore_serial;
    /* tbshash holds the hash we'll use for verification with data in the sig,
     * so it must have at least enough space for the largest hash in
     * cli_crt_hashtype */
    uint8_t tbshash[SHA512_HASH_SIZE];
    BIGNUM *n;
    BIGNUM *e;
    BIGNUM *sig;
    int64_t not_before;
    int64_t not_after;
    cli_crt_hashtype hashtype;
    int certSign;
    int codeSign;
    int timeSign;
    int isBlocked;
    struct cli_crt_t *prev;
    struct cli_crt_t *next;
} cli_crt;

typedef struct {
    cli_crt *crts;
    unsigned int items;
} crtmgr;

int cli_crt_init(cli_crt *x509);
void cli_crt_clear(cli_crt *x509);
void crtmgr_init(crtmgr *m);
void crtmgr_free(crtmgr *m);
bool crtmgr_add(crtmgr *m, cli_crt *x509);
cli_crt *crtmgr_lookup(crtmgr *m, cli_crt *x509);
cli_crt *crtmgr_block_list_lookup(crtmgr *m, cli_crt *x509);
cli_crt *crtmgr_trust_list_lookup(crtmgr *m, cli_crt *x509, int crb_crts_only);
void crtmgr_del(crtmgr *m, cli_crt *x509);
cli_crt *crtmgr_verify_crt(crtmgr *m, cli_crt *x509);
cli_crt *crtmgr_verify_pkcs7(crtmgr *m, const uint8_t *issuer, const uint8_t *serial, const void *signature, unsigned int signature_len, cli_crt_hashtype hashtype, const uint8_t *refhash, cli_vrfy_type vrfytype);
int crtmgr_add_roots(struct cl_engine *engine, crtmgr *m, int exclude_bl_crts);

#endif
