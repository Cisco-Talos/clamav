/*
 *  Copyright (C) 2003 - 2004 Tomasz Kojm <tkojm@clamav.net>
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
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
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

static const char *cli_nstr = "118640995551645342603070001658453189751527774412027743746599405743243142607464144767361060640655844749760788890022283424922762488917565551002467771109669598189410434699034532232228621591089508178591428456220796841621637175567590476666928698770143328137383952820383197532047771780196576957695822641224262693037"; /* 1024 bits */

static const char *cli_estr = "100001027";


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

static char *cli_decodesig(const char *sig, int plainlen, mpz_t e, mpz_t n)
{
	int i, siglen = strlen(sig), dec;
	char *decoded;
	mpz_t r, p, c;


    mpz_init(r);
    mpz_init(c);

    for(i = 0; i < siglen; i++) {
	if((dec = cli_ndecode(sig[i])) < 0)
	    return NULL;

	mpz_set_ui(r, dec);
	mpz_mul_2exp(r, r, 6 * i);
	mpz_add(c, c, r);
    }

    mpz_init(p);
    decoded = (char *) calloc(plainlen + 1, sizeof(char));

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

int cli_versig(const char *md5, const char *dsig)
{
	mpz_t n, e;
	char *pt, *pt2;

    if(strlen(md5) != 32 || !isalnum(md5[0])) {
	/* someone is trying to fool us with empty/malformed MD5 ? */
	cli_errmsg("SECURITY WARNING: MD5 basic test failure.\n");
	return CL_EMD5;
    }

    mpz_init_set_str(n, cli_nstr, 10);
    mpz_init_set_str(e, cli_estr, 10);

    if(!(pt = cli_decodesig(dsig, 16, e, n))) {
	mpz_clear(n);
	mpz_clear(e);
	return CL_EDSIG;
    }

    pt2 = cli_str2hex(pt, 16);
    free(pt);

    cli_dbgmsg("Decoded signature: %s\n", pt2);

    if(strncmp(md5, pt2, 32)) {
	cli_dbgmsg("Signature doesn't match.\n");
	free(pt2);
	mpz_clear(n);
	mpz_clear(e);
	return CL_EDSIG;
    }

    free(pt2);
    mpz_clear(n);
    mpz_clear(e);

    cli_dbgmsg("Digital signature is correct.\n");
    return 0;
}

#endif
