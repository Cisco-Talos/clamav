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

#ifndef __CRTMGR_H
#define __CRTMGR_H

#include <time.h>

#include "bignum.h"

typedef enum {CLI_SHA1RSA, CLI_MD5RSA, CLI_MD2RSA, CLI_RSA, CLI_SHA256RSA, CLI_SHA384RSA, CLI_SHA512RSA } cli_crt_hashtype;
typedef enum {VRFY_CODE, VRFY_TIME} cli_vrfy_type;

#define CRT_RAWMAXLEN 64
typedef struct cli_crt_t {
    char *name;
    uint8_t raw_subject[CRT_RAWMAXLEN];
    uint8_t raw_issuer[CRT_RAWMAXLEN];
    uint8_t raw_serial[CRT_RAWMAXLEN];
    uint8_t subject[SHA1_HASH_SIZE];
    uint8_t issuer[SHA1_HASH_SIZE];
    uint8_t serial[SHA1_HASH_SIZE];
    /* tbshash holds the hash we'll use for verification with data in the sig,
     * so it must have at least enough space for the largest hash in
     * cli_crt_hashtype */
    uint8_t tbshash[SHA512_HASH_SIZE];
    mp_int n;
    mp_int e;
    mp_int sig;
    time_t not_before;
    time_t not_after;
    cli_crt_hashtype hashtype;
    int certSign;
    int codeSign;
    int timeSign;
    int isBlacklisted;
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
int crtmgr_add(crtmgr *m, cli_crt *x509);
cli_crt *crtmgr_lookup(crtmgr *m, cli_crt *x509);
void crtmgr_del(crtmgr *m, cli_crt *x509);
cli_crt *crtmgr_verify_crt(crtmgr *m, cli_crt *x509);
cli_crt *crtmgr_verify_pkcs7(crtmgr *m, const uint8_t *issuer, const uint8_t *serial, const void *signature, unsigned int signature_len, cli_crt_hashtype hashtype, const uint8_t *refhash, cli_vrfy_type vrfytype);
int crtmgr_add_roots(struct cl_engine *engine, crtmgr *m);


#endif
