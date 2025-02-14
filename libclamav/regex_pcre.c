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

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

#include "clamav.h"
#include "others.h"
#include "regex_pcre.h"

/* NOTE: pcre2 could use mpool through ext */
void *cli_pcre_malloc(size_t size, void *ext)
{
    UNUSEDPARAM(ext);
    return cli_max_malloc(size);
}

void cli_pcre_free(void *ptr, void *ext)
{
    UNUSEDPARAM(ext);
    free(ptr);
}

cl_error_t cli_pcre_addoptions(struct cli_pcre_data *pd, const char **opt, int errout)
{
    if (!pd || !opt || !(*opt))
        return CL_ENULLARG;

    while (**opt != '\0') {
        switch (**opt) {
            case 'i':
                pd->options |= PCRE2_CASELESS;
                break;
            case 's':
                pd->options |= PCRE2_DOTALL;
                break;
            case 'm':
                pd->options |= PCRE2_MULTILINE;
                break;
            case 'x':
                pd->options |= PCRE2_EXTENDED;
                break;

                /* these are pcre2 specific... don't work with perl */
            case 'A':
                pd->options |= PCRE2_ANCHORED;
                break;
            case 'E':
                pd->options |= PCRE2_DOLLAR_ENDONLY;
                break;
            case 'U':
                pd->options |= PCRE2_UNGREEDY;
                break;
            default:
                if (errout) {
                    cli_errmsg("cli_pcre_addoptions: unknown/extra pcre option encountered %c\n", **opt);
                    return CL_EMALFDB;
                } else
                    return CL_EPARSE; /* passed to caller to handle */
        }
        (*opt)++;
    }

    return CL_SUCCESS;
}

cl_error_t cli_pcre_compile(struct cli_pcre_data *pd, long long unsigned match_limit, long long unsigned match_limit_recursion, unsigned int options, int opt_override)
{
    int errornum;
    PCRE2_SIZE erroffset;
    pcre2_general_context *gctx;
    pcre2_compile_context *cctx;

    if (!pd || !pd->expression) {
        cli_errmsg("cli_pcre_compile: NULL pd or NULL pd->expression\n");
        return CL_ENULLARG;
    }

    gctx = pcre2_general_context_create(cli_pcre_malloc, cli_pcre_free, NULL);
    if (!gctx) {
        cli_errmsg("cli_pcre_compile: Unable to allocate memory for general context\n");
        return CL_EMEM;
    }

    cctx = pcre2_compile_context_create(gctx);
    if (!cctx) {
        cli_errmsg("cli_pcre_compile: Unable to allocate memory for compile context\n");
        pcre2_general_context_free(gctx);
        return CL_EMEM;
    }

    /* compile the pcre2 regex last arg is charset, allow for options override */
    if (opt_override)
        pd->re = pcre2_compile((PCRE2_SPTR8)pd->expression, PCRE2_ZERO_TERMINATED, options, &errornum, &erroffset, cctx); /* pd->re handled by pcre2 -> call pcre_free() -> calls free() */
    else
        pd->re = pcre2_compile((PCRE2_SPTR8)pd->expression, PCRE2_ZERO_TERMINATED, pd->options, &errornum, &erroffset, cctx); /* pd->re handled by pcre2 -> call pcre_free() -> calls free() */
    if (pd->re == NULL) {
        PCRE2_UCHAR errmsg[256];
        pcre2_get_error_message(errornum, errmsg, sizeof(errmsg));
        cli_errmsg("cli_pcre_compile: PCRE2 compilation failed at offset %llu: %s\n",
                   (long long unsigned)erroffset, errmsg);
        pcre2_compile_context_free(cctx);
        pcre2_general_context_free(gctx);
        return CL_EMALFDB;
    }

    /* setup matching context and set the match limits */
    pd->mctx = pcre2_match_context_create(gctx);
    if (!pd->mctx) {
        cli_errmsg("cli_pcre_compile: Unable to allocate memory for match context\n");
        pcre2_compile_context_free(cctx);
        pcre2_general_context_free(gctx);
        return CL_EMEM;
    }

    pcre2_set_match_limit(pd->mctx, match_limit);
    pcre2_set_recursion_limit(pd->mctx, match_limit_recursion);

    /* non-dynamic allocated fields set by caller */
    pcre2_compile_context_free(cctx);
    pcre2_general_context_free(gctx);
    return CL_SUCCESS;
}

int cli_pcre_match(struct cli_pcre_data *pd, const unsigned char *buffer, size_t buflen, size_t override_offset, int options, struct cli_pcre_results *results)
{
    int rc;

    PCRE2_SIZE *ovector;
    size_t startoffset;

    /* set the startoffset, override if a value is specified */
    startoffset = pd->search_offset;
    if (override_offset != pd->search_offset)
        startoffset = override_offset;

    /* execute the pcre and return */
    rc = pcre2_match(pd->re, buffer, buflen, startoffset, options, results->match_data, pd->mctx);
    if (rc < 0 && rc != PCRE2_ERROR_NOMATCH) {
        switch (rc) {
            case PCRE2_ERROR_CALLOUT:
                break;
            case PCRE2_ERROR_NOMEMORY:
                cli_errmsg("cli_pcre_match: pcre_exec: out of memory\n");
                results->err = CL_EMEM;
                break;
            case PCRE2_ERROR_MATCHLIMIT:
                cli_dbgmsg("cli_pcre_match: pcre_exec: match limit exceeded\n");
                break;
            case PCRE2_ERROR_RECURSIONLIMIT:
                cli_dbgmsg("cli_pcre_match: pcre_exec: recursive limit exceeded\n");
                break;
            default:
                cli_errmsg("cli_pcre_match: pcre_exec: returned error %d\n", rc);
                results->err = CL_BREAK;
        }
    } else if (rc > 0) {
        ovector = pcre2_get_ovector_pointer(results->match_data);

        results->match[0] = ovector[0];
        results->match[1] = ovector[1];
    } else {
        results->match[0] = results->match[1] = 0;
    }

    return rc;
}

#define DISABLE_PCRE_REPORT 0
#define MATCH_MAXLEN 1028 /*because lolz*/

/* TODO: audit this function */
static void named_substr_print(const struct cli_pcre_data *pd, const unsigned char *buffer, PCRE2_SIZE *ovector)
{
    int i, namecount, trunc;

    PCRE2_SIZE length, j;

    unsigned char *tabptr;
    int name_entry_size;
    unsigned char *name_table;
    const char *start;
    char outstr[2 * MATCH_MAXLEN + 1];

    /* determine if there are named substrings */
    (void)pcre2_pattern_info(pd->re, PCRE2_INFO_NAMECOUNT, &namecount);

    if (namecount <= 0) {
        cli_dbgmsg("cli_pcre_report: no named substrings\n");
    } else {
        cli_dbgmsg("cli_pcre_report: named substrings\n");

        /* extract named substring translation table */
        (void)pcre2_pattern_info(pd->re, PCRE2_INFO_NAMETABLE, &name_table);
        (void)pcre2_pattern_info(pd->re, PCRE2_INFO_NAMEENTRYSIZE, &name_entry_size);

        /* print named substring information */
        tabptr = name_table;
        for (i = 0; i < namecount; i++) {
            int n = (tabptr[0] << 8) | tabptr[1];

            start  = (const char *)buffer + ovector[2 * n];
            length = ovector[2 * n + 1] - ovector[2 * n];

            trunc = 0;
            if (length > MATCH_MAXLEN) {
                trunc  = 1;
                length = MATCH_MAXLEN;
            }

            for (j = 0; j < length; ++j)
                snprintf(outstr + (2 * j), sizeof(outstr) - (2 * j), "%02x", (unsigned int)*(start + j));

            cli_dbgmsg("cli_pcre_report: (%d) %*s: %s%s\n", n, name_entry_size - 3, tabptr + 2,
                       outstr, trunc ? " (trunc)" : "");
            /*
            cli_dbgmsg("named_substr:  (%d) %*s: %.*s%s\n", n, name_entry_size - 3, tabptr + 2,
                       length, start, trunc ? " (trunc)":"");
            */
            tabptr += name_entry_size;
        }
    }
}

/* TODO: audit this function */
void cli_pcre_report(const struct cli_pcre_data *pd, const unsigned char *buffer, size_t buflen, int rc, struct cli_pcre_results *results)
{
    int i, trunc;

    PCRE2_SIZE length, j;

    const char *start;
    char outstr[2 * MATCH_MAXLEN + 1];

    PCRE2_SIZE *ovector;
    ovector = pcre2_get_ovector_pointer(results->match_data);

    /* print out additional diagnostics if cli_debug_flag is set */
    if (!DISABLE_PCRE_REPORT) {
        cli_dbgmsg("\n");
        cli_dbgmsg("cli_pcre_report: PCRE2 Execution Report:\n");
        cli_dbgmsg("cli_pcre_report: running regex /%s/ returns %d\n", pd->expression, rc);

        if (rc > 0) {
            /* print out full-match and capture groups */
            for (i = 0; i < rc; ++i) {
                start  = (const char *)buffer + ovector[2 * i];
                length = ovector[2 * i + 1] - ovector[2 * i];

                if (ovector[2 * i + 1] > buflen) {
                    cli_warnmsg("cli_pcre_report: reported match goes outside buffer\n");
                    continue;
                }

                trunc = 0;
                if (length > MATCH_MAXLEN) {
                    trunc  = 1;
                    length = MATCH_MAXLEN;
                }

                for (j = 0; j < length; ++j)
                    snprintf(outstr + (2 * j), sizeof(outstr) - (2 * j), "%02x", (unsigned int)*(start + j));

                cli_dbgmsg("cli_pcre_report:  %d: %s%s\n", i, outstr, trunc ? " (trunc)" : "");
                // cli_dbgmsg("cli_pcre_report:  %d: %.*s%s\n", i, length, start, trunc ? " (trunc)":"");
            }

            named_substr_print(pd, buffer, ovector);
        } else if (rc == 0 || rc == PCRE2_ERROR_NOMATCH) {
            cli_dbgmsg("cli_pcre_report: no match found\n");
        } else {
            cli_dbgmsg("cli_pcre_report: error occurred in pcre_match: %d\n", rc);
            /* error handled by caller */
        }
        cli_dbgmsg("cli_pcre_report: PCRE Execution Report End\n");
        cli_dbgmsg("\n");
    }
}

cl_error_t cli_pcre_results_reset(struct cli_pcre_results *results, const struct cli_pcre_data *pd)
{
    results->err      = CL_SUCCESS;
    results->match[0] = results->match[1] = 0;

    if (results->match_data)
        pcre2_match_data_free(results->match_data);

    results->match_data = pcre2_match_data_create_from_pattern(pd->re, NULL);
    if (!results->match_data)
        return CL_EMEM;

    return CL_SUCCESS;
}

void cli_pcre_results_free(struct cli_pcre_results *results)
{
    if (results->match_data)
        pcre2_match_data_free(results->match_data);
}

void cli_pcre_free_single(struct cli_pcre_data *pd)
{
    if (pd->re) {
        pcre2_code_free(pd->re);
        pd->re = NULL;
    }

    if (pd->mctx) {
        pcre2_match_context_free(pd->mctx);
        pd->mctx = NULL;
    }

    if (pd->expression) {
        free(pd->expression);
        pd->expression = NULL;
    }
}
