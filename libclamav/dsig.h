/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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

#ifndef __DSIG_H
#define __DSIG_H

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

cl_error_t cli_versig(const char *md5, const char *dsig);
cl_error_t cli_versig2(const unsigned char *sha2_256, const char *dsig_str, const char *n_str, const char *e_str);

/**
 * @brief Connect to a signing server, send the data to be signed, and return the digital signature.
 *
 * Caller is responsible for freeing the returned dsig.
 *
 * @param host
 * @param user
 * @param data
 * @param datalen
 * @param mode
 * @return char*
 */
char *cli_getdsig(const char *host, const char *user, const unsigned char *data, unsigned int datalen, unsigned short mode);

#endif
