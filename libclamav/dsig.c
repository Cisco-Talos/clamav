/*
 *  Copyright (C) 2003 - 2006 Tomasz Kojm <tkojm@clamav.net>
 *
 *  Number encoding rutines are based on yyyRSA by Erik Thiele
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

#define CLI_NSTR "118640995551645342603070001658453189751527774412027743746599405743243142607464144767361060640655844749760788890022283424922762488917565551002467771109669598189410434699034532232228621591089508178591428456220796841621637175567590476666928698770143328137383952820383197532047771780196576957695822641224262693037"

#define CLI_ESTR "100001027"

static unsigned char cli_ndecode(unsigned char value)
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

unsigned char *cli_decodesig(const char *sig, unsigned int plen, mpz_t e, mpz_t n)
{
	int i, slen = strlen(sig), dec;
	unsigned char *plain;
	mpz_t r, p, c;


    mpz_init(r);
    mpz_init(c);

    for(i = 0; i < slen; i++) {
	if((dec = cli_ndecode(sig[i])) < 0) {
	    mpz_clear(r);
	    mpz_clear(c);
	    return NULL;
	}

	mpz_set_ui(r, dec);
	mpz_mul_2exp(r, r, 6 * i);
	mpz_add(c, c, r);
    }

    plain = (unsigned char *) cli_calloc(plen + 1, sizeof(unsigned char));
    if(!plain) {
	cli_errmsg("cli_decodesig: Can't allocate memory for 'plain'\n");
	mpz_clear(r);
	mpz_clear(c);
	return NULL;
    }

    mpz_init(p);
    mpz_powm(p, c, e, n); /* plain = cipher^e mod n */
    mpz_clear(c);

    for(i = plen - 1; i >= 0; i--) { /* reverse */
	mpz_tdiv_qr_ui(p, r, p, 256);
	plain[i] = mpz_get_ui(r);
    }

    mpz_clear(p);
    mpz_clear(r);

    return plain;
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
