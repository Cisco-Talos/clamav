/*
 *  Support for PCRE regex variant
 *
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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

#if HAVE_PCRE
#if USING_PCRE2
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#else
#include <pcre.h>
#endif

#include "clamav.h"
#include "others.h"
#include "regex_pcre.h"

#if USING_PCRE2
/* NOTE: pcre2 could use mpool through ext */
void *cli_pcre_malloc(size_t size, void *ext)
{
    UNUSEDPARAM(ext);
    return cli_malloc(size);
}

void cli_pcre_free(void *ptr, void *ext)
{
    UNUSEDPARAM(ext);
    free(ptr);
}
#endif

/* cli_pcre_init_internal: redefine pcre_malloc and pcre_free; pcre2 does this during compile */
int cli_pcre_init_internal()
{
#if !USING_PCRE2
    pcre_malloc = cli_malloc;
    pcre_free = free;
    pcre_stack_malloc = cli_malloc;
    pcre_stack_free = free;
#endif

    return CL_SUCCESS;
}

int cli_pcre_addoptions(struct cli_pcre_data *pd, const char **opt, int errout)
{
    if (!pd || !opt || !(*opt))
        return CL_ENULLARG;

    while (**opt != '\0') {
        switch(**opt) {
#if USING_PCRE2
        case 'i':  pd->options |= PCRE2_CASELESS;            break;
        case 's':  pd->options |= PCRE2_DOTALL;              break;
        case 'm':  pd->options |= PCRE2_MULTILINE;           break;
        case 'x':  pd->options |= PCRE2_EXTENDED;            break;

            /* these are pcre2 specific... don't work with perl */
        case 'A':  pd->options |= PCRE2_ANCHORED;            break;
        case 'E':  pd->options |= PCRE2_DOLLAR_ENDONLY;      break;
        case 'U':  pd->options |= PCRE2_UNGREEDY;            break;
#else
        case 'i':  pd->options |= PCRE_CASELESS;            break;
        case 's':  pd->options |= PCRE_DOTALL;              break;
        case 'm':  pd->options |= PCRE_MULTILINE;           break;
        case 'x':  pd->options |= PCRE_EXTENDED;            break;

            /* these are pcre specific... don't work with perl */
        case 'A':  pd->options |= PCRE_ANCHORED;            break;
        case 'E':  pd->options |= PCRE_DOLLAR_ENDONLY;      break;
        case 'U':  pd->options |= PCRE_UNGREEDY;            break;
#endif
        default:
            if (errout) {
                cli_errmsg("cli_pcre_addoptions: unknown/extra pcre option encountered %c\n", **opt);
                return CL_EMALFDB;
            }
            else
                return CL_EPARSE; /* passed to caller to handle */
        }
        (*opt)++;
    }

    return CL_SUCCESS;
}

#if USING_PCRE2
int cli_pcre_compile(struct cli_pcre_data *pd, long long unsigned match_limit, long long unsigned match_limit_recursion, unsigned int options, int opt_override)
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
        pd->re = pcre2_compile(pd->expression, PCRE2_ZERO_TERMINATED, options, &errornum, &erroffset, cctx); /* pd->re handled by pcre2 -> call pcre_free() -> calls free() */
    else
        pd->re = pcre2_compile(pd->expression, PCRE2_ZERO_TERMINATED, pd->options, &errornum, &erroffset, cctx); /* pd->re handled by pcre2 -> call pcre_free() -> calls free() */
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
#else
int cli_pcre_compile(struct cli_pcre_data *pd, long long unsigned match_limit, long long unsigned match_limit_recursion, unsigned int options, int opt_override)
{
    const char *error;
    int erroffset;

    if (!pd || !pd->expression) {
        cli_errmsg("cli_pcre_compile: NULL pd or NULL pd->expression\n");
        return CL_ENULLARG;
    }

    /* compile the pcre regex last arg is charset, allow for options override */
    if (opt_override)
        pd->re = pcre_compile(pd->expression, options, &error, &erroffset, NULL); /* pd->re handled by pcre -> call pcre_free() -> calls free() */
    else
        pd->re = pcre_compile(pd->expression, pd->options, &error, &erroffset, NULL); /* pd->re handled by pcre -> call pcre_free() -> calls free() */
    if (pd->re == NULL) {
        cli_errmsg("cli_pcre_compile: PCRE compilation failed at offset %d: %s\n", erroffset, error);
        return CL_EMALFDB;
    }

    /* now study it... (section totally not from snort) */
    pd->ex = pcre_study(pd->re, 0, &error);
    if (!(pd->ex)) {
        pd->ex = (pcre_extra *)cli_calloc(1, sizeof(*(pd->ex)));
        if (!(pd->ex)) {
            cli_errmsg("cli_pcre_compile: Unable to allocate memory for extra data\n");
            return CL_EMEM;
        }
    }

    /* set the match limits */
    if (pd->ex->flags & PCRE_EXTRA_MATCH_LIMIT) {
        pd->ex->match_limit = match_limit;
    }
    else {
        pd->ex->flags |= PCRE_EXTRA_MATCH_LIMIT;
        pd->ex->match_limit = match_limit;
    }

    /* set the recursion match limits */
#ifdef PCRE_EXTRA_MATCH_LIMIT_RECURSION
    if (pd->ex->flags & PCRE_EXTRA_MATCH_LIMIT_RECURSION) {
        pd->ex->match_limit_recursion = match_limit_recursion;
    }
    else {
        pd->ex->flags |= PCRE_EXTRA_MATCH_LIMIT_RECURSION;
        pd->ex->match_limit_recursion = match_limit_recursion;
    }
#endif /* PCRE_EXTRA_MATCH_LIMIT_RECURSION */

    /* non-dynamic allocated fields set by caller */
    return CL_SUCCESS;
}
#endif

int cli_pcre_match(struct cli_pcre_data *pd, const unsigned char *buffer, uint32_t buflen, int override_offset, int options, struct cli_pcre_results *results)
{
    int rc, startoffset;
#if USING_PCRE2
    pcre2_general_context *pc2ctx;
    PCRE2_SIZE *ovector;
#endif

    /* set the startoffset, override if a value is specified */
    startoffset = pd->search_offset;
    if (override_offset >= 0)
        startoffset = override_offset;

    /* execute the pcre and return */
#if USING_PCRE2
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
#else
    rc = pcre_exec(pd->re, pd->ex, (const char *)buffer, buflen, startoffset, options, results->ovector, OVECCOUNT);
    if (rc < 0 && rc != PCRE_ERROR_NOMATCH) {
        switch (rc) {
        case PCRE_ERROR_CALLOUT:
            break;
        case PCRE_ERROR_NOMEMORY:
            cli_errmsg("cli_pcre_match: pcre_exec: out of memory\n");
            results->err = CL_EMEM;
            break;
        case PCRE_ERROR_MATCHLIMIT:
            cli_dbgmsg("cli_pcre_match: pcre_exec: match limit exceeded\n");
            break;
        case PCRE_ERROR_RECURSIONLIMIT:
            cli_dbgmsg("cli_pcre_match: pcre_exec: recursive limit exceeded\n");
            break;
        default:
            cli_errmsg("cli_pcre_match: pcre_exec: returned error %d\n", rc);
            results->err = CL_BREAK;
        }
    } else if (rc > 0) {
        results->match[0] = results->ovector[0];
        results->match[1] = results->ovector[1];
    } else {
        results->match[0] = results->match[1] = 0;
    }
#endif
    return rc;
}

#define DISABLE_PCRE_REPORT 0
#define MATCH_MAXLEN 1028 /*because lolz*/

/* TODO: audit this function */
static void named_substr_print(const struct cli_pcre_data *pd, const unsigned char *buffer, int *ovector)
{
    int i, j, length, namecount, trunc;
    unsigned char *tabptr;
    int name_entry_size;
    unsigned char *name_table;
    const char *start;
    char outstr[2*MATCH_MAXLEN+1];

    /* determine if there are named substrings */
#if USING_PCRE2
    (void)pcre2_pattern_info(pd->re, PCRE2_INFO_NAMECOUNT, &namecount);
#else
    (void)pcre_fullinfo(pd->re, pd->ex, PCRE_INFO_NAMECOUNT, &namecount);
#endif
    if (namecount <= 0) {
        cli_dbgmsg("cli_pcre_report: no named substrings\n");
    }
    else {
        cli_dbgmsg("cli_pcre_report: named substrings\n");

        /* extract named substring translation table */
#if USING_PCRE2
        (void)pcre2_pattern_info(pd->re, PCRE2_INFO_NAMETABLE, &name_table);
        (void)pcre2_pattern_info(pd->re, PCRE2_INFO_NAMEENTRYSIZE, &name_entry_size);
#else
        (void)pcre_fullinfo(pd->re, pd->ex, PCRE_INFO_NAMETABLE, &name_table);
        (void)pcre_fullinfo(pd->re, pd->ex, PCRE_INFO_NAMEENTRYSIZE, &name_entry_size);
#endif

        /* print named substring information */
        tabptr = name_table;
        for (i = 0; i < namecount; i++) {
            int n = (tabptr[0] << 8) | tabptr[1];

            start = (const char *)buffer + ovector[2*n];
            length = ovector[2*n+1] - ovector[2*n];

            trunc = 0;
            if (length > MATCH_MAXLEN) {
                trunc = 1;
                length = MATCH_MAXLEN;
            }

            for (j = 0; j < length; ++j)
                snprintf(outstr+(2*j), sizeof(outstr)-(2*j), "%02x", (unsigned int)*(start+j));

            cli_dbgmsg("cli_pcre_report: (%d) %*s: %s%s\n", n, name_entry_size - 3, tabptr + 2,
                       outstr, trunc ? " (trunc)":"");
            /*
            cli_dbgmsg("named_substr:  (%d) %*s: %.*s%s\n", n, name_entry_size - 3, tabptr + 2,
                       length, start, trunc ? " (trunc)":"");
            */
            tabptr += name_entry_size;
        }
    }
}

/* TODO: audit this function */
void cli_pcre_report(const struct cli_pcre_data *pd, const unsigned char *buffer, uint32_t buflen, int rc, struct cli_pcre_results *results)
{
    int i, j, length, trunc;
    const char *start;
    char outstr[2*MATCH_MAXLEN+1];
#if USING_PCRE2
    PCRE2_SIZE *ovector;
    ovector = pcre2_get_ovector_pointer(results->match_data);
#else
    int *ovector = results->ovector;
#endif

    /* print out additional diagnostics if cli_debug_flag is set */
    if (!DISABLE_PCRE_REPORT) {
        cli_dbgmsg("\n");
#if USING_PCRE2
        cli_dbgmsg("cli_pcre_report: PCRE2 Execution Report:\n");
#else
        cli_dbgmsg("cli_pcre_report: PCRE Execution Report:\n");
#endif
        cli_dbgmsg("cli_pcre_report: running regex /%s/ returns %d\n", pd->expression, rc);
        if (rc > 0) {
            /* print out full-match and capture groups */
            for (i = 0; i < rc; ++i) {
                start = (const char *)buffer + ovector[2*i];
                length = ovector[2*i+1] - ovector[2*i];

                if (ovector[2*i+1] > buflen) {
                    cli_warnmsg("cli_pcre_report: reported match goes outside buffer\n");
                    continue;
                }

                trunc = 0;
                if (length > MATCH_MAXLEN) {
                    trunc = 1;
                    length = MATCH_MAXLEN;
                }

                for (j = 0; j < length; ++j) 
                    snprintf(outstr+(2*j), sizeof(outstr)-(2*j), "%02x", (unsigned int)*(start+j));

                cli_dbgmsg("cli_pcre_report:  %d: %s%s\n", i, outstr, trunc ? " (trunc)":"");
                //cli_dbgmsg("cli_pcre_report:  %d: %.*s%s\n", i, length, start, trunc ? " (trunc)":"");
            }

            named_substr_print(pd, buffer, ovector);
        }
#if USING_PCRE2
        else if (rc == 0 || rc == PCRE2_ERROR_NOMATCH) {
#else
        else if (rc == 0 || rc == PCRE_ERROR_NOMATCH) {
#endif
            cli_dbgmsg("cli_pcre_report: no match found\n");
        }
        else {
            cli_dbgmsg("cli_pcre_report: error occurred in pcre_match: %d\n", rc);
            /* error handled by caller */
        }
        cli_dbgmsg("cli_pcre_report: PCRE Execution Report End\n");
        cli_dbgmsg("\n");
    }
}


int cli_pcre_results_reset(struct cli_pcre_results *results, const struct cli_pcre_data *pd)
{
    results->err = CL_SUCCESS;
    results->match[0] = results->match[1] = 0;
#if USING_PCRE2
    if (results->match_data)
        pcre2_match_data_free(results->match_data);

    results->match_data = pcre2_match_data_create_from_pattern(pd->re, NULL);
    if (!results->match_data)
        return CL_EMEM;
#else
    memset(results->ovector, 0, OVECCOUNT);
#endif
    return CL_SUCCESS;
}

void cli_pcre_results_free(struct cli_pcre_results *results)
{
#if USING_PCRE2
    if (results->match_data)
        pcre2_match_data_free(results->match_data);
#endif
}

void cli_pcre_free_single(struct cli_pcre_data *pd)
{
#if USING_PCRE2
    if (pd->re) {
        pcre2_code_free(pd->re);
        pd->re = NULL;
    }

    if (pd->mctx) {
        pcre2_match_context_free(pd->mctx);
        pd->mctx = NULL;
    }
#else
    if (pd->re) {
        pcre_free(pd->re);
        pd->re = NULL;
    }
    if (pd->ex) {
        free(pd->ex);
        pd->ex = NULL;
    }
#endif
    if (pd->expression) {
        free(pd->expression);
        pd->expression = NULL;
    }
}
#endif /* HAVE_PCRE */
