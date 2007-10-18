/*
 *  Copyright (C) 2003 Tomasz Kojm <tkojm@clamav.net>
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

#ifndef __DSIG_H
#define __DSIG_H

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#ifdef HAVE_GMP
#include <gmp.h>

int cli_versig(const char *md5, const char *dsig);
unsigned char *cli_decodesig(const char *sig, unsigned int plen, mpz_t e, mpz_t n);

#endif /* HAVE_GMP */
#endif
