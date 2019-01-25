/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm
 * 
 *  Acknowledgements: The idea of number encoding comes from yyyRSA by 
 *                    Erik Thiele.
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include "clamav.h"
#include "others.h"
#include "dsig.h"
#include "str.h"
#include "bignum.h"

#define CLI_NSTR "118640995551645342603070001658453189751527774412027743746599405743243142607464144767361060640655844749760788890022283424922762488917565551002467771109669598189410434699034532232228621591089508178591428456220796841621637175567590476666928698770143328137383952820383197532047771780196576957695822641224262693037"

#define CLI_ESTR "100001027"

static char cli_ndecode(unsigned char value)
{
	unsigned int i;
	char ncodec[] = {
	    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 
	    'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 
	    'y', 'z',
	    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 
	    'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 
	    'Y', 'Z',
	    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
	    '+', '/'
	};


    for(i = 0; i < 64; i++)
	if(ncodec[i] == value)
	    return i;

    cli_errmsg("cli_ndecode: value out of range\n");
    return -1;
}

static unsigned char *cli_decodesig(const char *sig, unsigned int plen, mp_int e, mp_int n)
{
	int i, slen = strlen(sig), dec;
	unsigned char *plain;
	mp_int r, p, c;


    mp_init(&r);
    mp_init(&c);
    for(i = 0; i < slen; i++) {
	if((dec = cli_ndecode(sig[i])) < 0) {
	    mp_clear(&r);
	    mp_clear(&c);
	    return NULL;
	}
	mp_set_int(&r, dec);
	mp_mul_2d(&r, 6 * i, &r);
	mp_add(&r, &c, &c);
    }

    plain = (unsigned char *) cli_calloc(plen + 1, sizeof(unsigned char));
    if(!plain) {
	cli_errmsg("cli_decodesig: Can't allocate memory for 'plain'\n");
	mp_clear(&r);
	mp_clear(&c);
	return NULL;
    }
    mp_init(&p);
    mp_exptmod(&c, &e, &n, &p); /* plain = cipher^e mod n */
    mp_clear(&c);
    mp_set_int(&c, 256);
    for(i = plen - 1; i >= 0; i--) { /* reverse */
	mp_div(&p, &c, &p, &r);
	plain[i] = mp_get_int(&r);
    }
    mp_clear(&c);
    mp_clear(&p);
    mp_clear(&r);

    return plain;
}

int cli_versig(const char *md5, const char *dsig)
{
	mp_int n, e;
	char *pt, *pt2;

    if(strlen(md5) != 32 || !isalnum(md5[0])) {
	/* someone is trying to fool us with empty/malformed MD5 ? */
	cli_errmsg("SECURITY WARNING: MD5 basic test failure.\n");
	return CL_EVERIFY;
    }

    mp_init(&n);
    mp_read_radix(&n, CLI_NSTR, 10);
    mp_init(&e);
    mp_read_radix(&e, CLI_ESTR, 10);

    if(!(pt = (char *) cli_decodesig(dsig, 16, e, n))) {
	mp_clear(&n);
	mp_clear(&e);
	return CL_EVERIFY;
    }

    pt2 = cli_str2hex(pt, 16);
    free(pt);

    cli_dbgmsg("cli_versig: Decoded signature: %s\n", pt2);

    if(strncmp(md5, pt2, 32)) {
	cli_dbgmsg("cli_versig: Signature doesn't match.\n");
	free(pt2);
	mp_clear(&n);
	mp_clear(&e);
	return CL_EVERIFY;
    }

    free(pt2);
    mp_clear(&n);
    mp_clear(&e);

    cli_dbgmsg("cli_versig: Digital signature is correct.\n");
    return CL_SUCCESS;
}

#define HASH_LEN    32
#define SALT_LEN    32
#define PAD_LEN	    (2048 / 8)
#define BLK_LEN	    (PAD_LEN - HASH_LEN - 1)
int cli_versig2(const unsigned char *sha256, const char *dsig_str, const char *n_str, const char *e_str)
{
	unsigned char *decoded, digest1[HASH_LEN], digest2[HASH_LEN], digest3[HASH_LEN], *salt;
	unsigned char mask[BLK_LEN], data[BLK_LEN], final[8 + 2 * HASH_LEN], c[4];
	unsigned int i, rounds;
    void *ctx;
	mp_int n, e;

    mp_init(&e);
    mp_read_radix(&e, e_str, 10);
    mp_init(&n);
    mp_read_radix(&n, n_str, 10);

    decoded = cli_decodesig(dsig_str, PAD_LEN, e, n);
    mp_clear(&n);
    mp_clear(&e);
    if(!decoded)
	return CL_EVERIFY;

    if(decoded[PAD_LEN - 1] != 0xbc) {
	free(decoded);
	return CL_EVERIFY;
    }

    memcpy(mask, decoded, BLK_LEN);
    memcpy(digest2, &decoded[BLK_LEN], HASH_LEN);
    free(decoded);

    c[0] = c[1] = 0;
    rounds = (BLK_LEN + HASH_LEN - 1) / HASH_LEN;
    for(i = 0; i < rounds; i++) {
	c[2] = (unsigned char) (i / 256);
	c[3] = (unsigned char) i;

    ctx = cl_hash_init("sha256");
    if (!(ctx))
        return CL_EMEM;

	cl_update_hash(ctx, digest2, HASH_LEN);
	cl_update_hash(ctx, c, 4);
	cl_finish_hash(ctx, digest3);
	if(i + 1 == rounds)
            memcpy(&data[i * 32], digest3, BLK_LEN - i * HASH_LEN);
	else
	    memcpy(&data[i * 32], digest3, HASH_LEN);
    }

    for(i = 0; i < BLK_LEN; i++)
	data[i] ^= mask[i];
    data[0] &= (0xff >> 1);

    if(!(salt = memchr(data, 0x01, BLK_LEN)))
	return CL_EVERIFY;
    salt++;

    if(data + BLK_LEN - salt != SALT_LEN)
	return CL_EVERIFY;

    memset(final, 0, 8);
    memcpy(&final[8], sha256, HASH_LEN);
    memcpy(&final[8 + HASH_LEN], salt, SALT_LEN);

    ctx = cl_hash_init("sha256");
    if (!(ctx))
        return CL_EMEM;

	cl_update_hash(ctx, final, sizeof(final));
	cl_finish_hash(ctx, digest1);

    return memcmp(digest1, digest2, HASH_LEN) ? CL_EVERIFY : CL_SUCCESS;
}
