/*
 *  Support for PCRE regex variant
 *
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Kevin Lin
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

#ifndef _REGEX_PCRE_H_
#define _REGEX_PCRE_H_

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

#include "clamav-types.h"
#include "mpool.h"

/* used for setting overrides */
#define CLI_PCREMATCH_NOOFFSETOVERRIDE -1
/* must be multiple of 3 */
#define OVECCOUNT 300

struct cli_pcre_data {
    pcre2_code *re;            /* compiled pcre regex */
    pcre2_match_context *mctx; /* match context */
    int options;               /* pcre options */
    char *expression;          /* copied regular expression */
    uint32_t search_offset;    /* start offset to search at for pcre_exec */
};

struct cli_pcre_results {
    cl_error_t err;
    uint32_t match[2]; /* populated by cli_pcre_match to be start (0) and end (1) offset of match */

    pcre2_match_data *match_data;
};

cl_error_t cli_pcre_init_internal(void);
cl_error_t cli_pcre_addoptions(struct cli_pcre_data *pd, const char **opt, int errout);
cl_error_t cli_pcre_compile(struct cli_pcre_data *pd, long long unsigned match_limit, long long unsigned match_limit_recursion, unsigned int options, int opt_override);

/**
 * @brief perform a pcre match on a string
 *
 * @param pd
 * @param buffer
 * @param buflen
 * @param override_offset
 * @param options
 * @param results
 * @return int greater than zero if a match. 0 if no match. A PCRE2_ERROR_* error code if something went wrong.
 */
int cli_pcre_match(struct cli_pcre_data *pd, const unsigned char *buffer, size_t buflen, size_t override_offset, int options, struct cli_pcre_results *results);
void cli_pcre_report(const struct cli_pcre_data *pd, const unsigned char *buffer, size_t buflen, int rc, struct cli_pcre_results *results);

cl_error_t cli_pcre_results_reset(struct cli_pcre_results *results, const struct cli_pcre_data *pd);
void cli_pcre_results_free(struct cli_pcre_results *results);
void cli_pcre_free_single(struct cli_pcre_data *pd);

#endif /*_REGEX_PCRE_H_*/
