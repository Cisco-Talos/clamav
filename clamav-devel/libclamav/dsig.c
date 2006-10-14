/*
 *  Copyright (C) 2003 - 2006 Tomasz Kojm <tkojm@clamav.net>
 *
 *  Number encoding rutines are based on yyyRSA by Erik Thiele
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
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

#ifdef HAVE_GMP

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <gmp.h>

#include "clamav.h"
#include "others.h"
#include "dsig.h"
#include "str.h"
#include "sha256.h"

#define CLI_NSTR "118640995551645342603070001658453189751527774412027743746599405743243142607464144767361060640655844749760788890022283424922762488917565551002467771109669598189410434699034532232228621591089508178591428456220796841621637175567590476666928698770143328137383952820383197532047771780196576957695822641224262693037"

#define CLI_ESTR "100001027"

#define CLI_NSTRPSS "14783905874077467090262228516557917570254599638376203532031989214105552847269687489771975792123442185817287694951949800908791527542017115600501303394778618535864845235700041590056318230102449612217458549016089313306591388590790796515819654102320725712300822356348724011232654837503241736177907784198700834440681124727060540035754699658105895050096576226753008596881698828185652424901921668758326578462003247906470982092298106789657211905488986281078346361469524484829559560886227198091995498440676639639830463593211386055065360288422394053998134458623712540683294034953818412458362198117811990006021989844180721010947"

#define CLI_ESTRPSS "100002053"

#define PSS_NBITS 2048
#define PSS_DIGEST_LENGTH 32


static char cli_ndecode(char value)
{
	int i;
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

static unsigned char *cli_decodesig(const char *sig, int plainlen, mpz_t e, mpz_t n)
{
	int i, siglen = strlen(sig), dec;
	unsigned char *decoded;
	mpz_t r, p, c;


    mpz_init(r);
    mpz_init(c);

    for(i = 0; i < siglen; i++) {
	if((dec = cli_ndecode(sig[i])) < 0) {
	    mpz_clear(r);
	    mpz_clear(c);
	    return NULL;
	}

	mpz_set_ui(r, dec);
	mpz_mul_2exp(r, r, 6 * i);
	mpz_add(c, c, r);
    }

    decoded = (unsigned char *) cli_calloc(plainlen + 1, sizeof(unsigned char));
    if(!decoded) {
	cli_errmsg("cli_decodesig: Can't allocate memory\n");
	mpz_clear(r);
	mpz_clear(c);
	return NULL;
    }

    mpz_init(p);
    mpz_powm(p, c, e, n); /* plain = cipher^e mod n */
    mpz_clear(c);

    for(i = plainlen - 1; i >= 0; i--) { /* reverse */
	mpz_tdiv_qr_ui(p, r, p, 256);
	decoded[i] = mpz_get_ui(r);
    }

    mpz_clear(p);
    mpz_clear(r);

    return decoded;
}
static void cli_mgf(unsigned char *in, unsigned int inlen, unsigned char *out, unsigned int outlen)
{
	SHA256_CTX ctx;
	unsigned int i, laps;
	unsigned char cnt[4], digest[PSS_DIGEST_LENGTH];


    laps = (outlen + PSS_DIGEST_LENGTH - 1) / PSS_DIGEST_LENGTH;

    for(i = 0; i < laps; i++) {
	cnt[0] = (unsigned char) 0;
	cnt[1] = (unsigned char) 0;
	cnt[2] = (unsigned char) (i / 256);
	cnt[3] = (unsigned char) i;

	sha256_init(&ctx);
	sha256_update(&ctx, in, inlen);
	sha256_update(&ctx, cnt, sizeof(cnt));
	sha256_final(&ctx);
	sha256_digest(&ctx, digest);

	if(i != laps - 1)
	    memcpy(&out[i * PSS_DIGEST_LENGTH], digest, PSS_DIGEST_LENGTH);
	else
	    memcpy(&out[i * PSS_DIGEST_LENGTH], digest, outlen - i * PSS_DIGEST_LENGTH);
    }
}

int cli_versigpss(const unsigned char *sha256, const char *dsig)
{
	mpz_t n, e;
	SHA256_CTX ctx;
	unsigned char *pt, digest1[PSS_DIGEST_LENGTH], digest2[PSS_DIGEST_LENGTH], *salt;
	unsigned int plen = PSS_NBITS / 8, hlen, slen, i;
	unsigned char dblock[PSS_NBITS / 8 - PSS_DIGEST_LENGTH - 1];
	unsigned char mblock[PSS_NBITS / 8 - PSS_DIGEST_LENGTH - 1];
	unsigned char fblock[8 + 2 * PSS_DIGEST_LENGTH];


    hlen = slen = PSS_DIGEST_LENGTH;
    mpz_init_set_str(n, CLI_NSTRPSS, 10);
    mpz_init_set_str(e, CLI_ESTRPSS, 10);

    if(!(pt = cli_decodesig(dsig, plen, e, n))) {
	mpz_clear(n);
	mpz_clear(e);
	return CL_EDSIG;
    }

    mpz_clear(n);
    mpz_clear(e);

    if(pt[plen - 1] != 0xbc) {
	cli_dbgmsg("cli_versigpss: Incorrect signature syntax (0xbc)\n");
	free(pt);
	return CL_EDSIG;
    }

    memcpy(mblock, pt, plen - hlen - 1);
    memcpy(digest2, &pt[plen - hlen - 1], hlen);
    free(pt);

    cli_mgf(digest2, hlen, dblock, plen - hlen - 1);

    for(i = 0; i < plen - hlen - 1; i++)
	dblock[i] ^= mblock[i];

    dblock[0] &= (0xff >> 1);

    salt = memchr(dblock, 0x01, sizeof(dblock));
    if(!salt) {
	cli_dbgmsg("cli_versigpss: Can't find salt\n");
	return CL_EDSIG;
    }
    salt++;

    if((unsigned int) (dblock + sizeof(dblock) - salt) != slen) {
	cli_dbgmsg("cli_versigpss: Bad salt size\n");
	return CL_EDSIG;
    }

    memset(fblock, 0, 8);
    memcpy(&fblock[8], sha256, hlen);
    memcpy(&fblock[8 + hlen], salt, slen);

    sha256_init(&ctx);
    sha256_update(&ctx, fblock, sizeof(fblock));
    sha256_final(&ctx);
    sha256_digest(&ctx, digest1);

    if(memcmp(digest1, digest2, hlen)) {
	cli_dbgmsg("cli_versigpss: Signature doesn't match.\n");
	return CL_EDSIG;
    }

    cli_dbgmsg("cli_versigpss: Digital signature is correct.\n");
    return CL_SUCCESS;
}

int cli_versig(const char *md5, const char *dsig)
{
	mpz_t n, e;
	char *pt, *pt2;


    if(strlen(md5) != 32 || !isalnum(md5[0])) {
	/* someone is trying to fool us with empty/malformed MD5 ? */
	cli_errmsg("SECURITY WARNING: MD5 basic test failure.\n");
	return CL_EMD5;
    }

    mpz_init_set_str(n, CLI_NSTR, 10);
    mpz_init_set_str(e, CLI_ESTR, 10);

    if(!(pt = (char *) cli_decodesig(dsig, 16, e, n))) {
	mpz_clear(n);
	mpz_clear(e);
	return CL_EDSIG;
    }

    pt2 = cli_str2hex(pt, 16);
    free(pt);

    cli_dbgmsg("cli_versig: Decoded signature: %s\n", pt2);

    if(strncmp(md5, pt2, 32)) {
	cli_dbgmsg("cli_versig: Signature doesn't match.\n");
	free(pt2);
	mpz_clear(n);
	mpz_clear(e);
	return CL_EDSIG;
    }

    free(pt2);
    mpz_clear(n);
    mpz_clear(e);

    cli_dbgmsg("cli_versig: Digital signature is correct.\n");
    return CL_SUCCESS;
}
#endif
