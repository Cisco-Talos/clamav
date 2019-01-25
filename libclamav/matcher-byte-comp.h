/*
 *  Support for matcher using byte compare
 *
 *  Copyright (C) 2018-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  Authors: Mickey Sola
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

#ifndef __MATCHER_BCOMP_H
#define __MATCHER_BCOMP_H

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <sys/types.h>

#include "clamav-types.h"
#include "dconf.h"
#include "mpool.h"

#define CLI_BCOMP_MAX_BIN_BLEN 8
#define CLI_BCOMP_MAX_HEX_BLEN 18

#define CLI_BCOMP_HEX   0x0001
#define CLI_BCOMP_DEC   0x0002
#define CLI_BCOMP_BIN   0x0004
#define CLI_BCOMP_AUTO  0x0008
#define CLI_BCOMP_LE    0x0010
#define CLI_BCOMP_BE    0x0020
#define CLI_BCOMP_EXACT 0x0100

struct cli_bcomp_meta {
    char *virname;
    uint16_t ref_subsigid; /* identifies the dependent subsig from which we will do comparisons */
    uint32_t lsigid[3];
    ssize_t offset; /* offset from the referenced subsig, handled at match-time */
    uint16_t options; /* bitmask */
    size_t byte_len;
    struct cli_bcomp_comp **comps;
    uint32_t comp_count;
};

/* each byte compare subsig can perform multiple comparisons on the same extracted byte sequence */
struct cli_bcomp_comp {
    char comp_symbol; /* <, >, = are supported */
    int64_t comp_value;
};

cl_error_t cli_bcomp_addpatt(struct cli_matcher *root, const char *virname, const char* hexsig, const uint32_t *lsigid, unsigned int options);
cl_error_t cli_bcomp_scanbuf(const unsigned char *buffer, size_t buffer_length, const char **virname, struct cli_ac_result **res, const struct cli_matcher *root, struct cli_ac_data *mdata, cli_ctx *ctx);
cl_error_t cli_bcomp_compare_check(const unsigned char *f_buffer, size_t buffer_length, int offset, struct cli_bcomp_meta *bm);
void cli_bcomp_freemeta(struct cli_matcher *root, struct cli_bcomp_meta *bm);
uint16_t cli_bcomp_chk_hex(const unsigned char* buffer, uint16_t opt, uint32_t len, uint32_t check_only);
unsigned char* cli_bcomp_normalize_buffer(const unsigned char* buffer, uint32_t byte_len, uint32_t *pad_len,  uint16_t opt, uint16_t whitespace_only);


#endif
