/*
 *  Support for PCRE regex variant
 *
 *  Copyright (C) 2015 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *  All Rights Reserved.
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
#include <pcre.h>

#include "clamav.h"
#include "cltypes.h"
#include "others.h"
#include "regex_pcre.h"

/* TODO: cli_pcre_init_internal: redefine pcre_malloc and pcre_free, setup callback function? */
int cli_pcre_init_internal()
{
    pcre_malloc = cli_malloc;
    pcre_free = free;
    pcre_stack_malloc = cli_malloc;
    pcre_stack_free = free;

    return CL_SUCCESS;
}

int cli_pcre_addoptions(struct cli_pcre_data *pd, const char **opt, int errout)
{
    if (!pd || !opt || !(*opt))
        return CL_ENULLARG;

    while (**opt != '\0') {
        switch(**opt) {
        case 'i':  pd->options |= PCRE_CASELESS;            break;
        case 's':  pd->options |= PCRE_DOTALL;              break;
        case 'm':  pd->options |= PCRE_MULTILINE;           break;
        case 'x':  pd->options |= PCRE_EXTENDED;            break;

            /* these are pcre specific... don't work with perl */
        case 'A':  pd->options |= PCRE_ANCHORED;            break;
        case 'E':  pd->options |= PCRE_DOLLAR_ENDONLY;      break;
        case 'U':  pd->options |= PCRE_UNGREEDY;            break;

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
        pd->re = pcre_compile(pd->expression, options, &error, &erroffset, NULL); /* pd->re handled by libpcre -> call pcre_free() -> calls free() */
    else
        pd->re = pcre_compile(pd->expression, pd->options, &error, &erroffset, NULL); /* pd->re handled by libpcre -> call pcre_free() -> calls free() */
    if (pd->re == NULL) {
        cli_errmsg("cli_pcre_parse: PCRE compilation failed at offset %d: %s\n", erroffset, error);
        return CL_EMALFDB;
    }

    /* now study it... (section totally not from snort) */
    pd->ex = pcre_study(pd->re, 0, &error);
    if (!(pd->ex)) {
        pd->ex = (pcre_extra *)cli_calloc(1, sizeof(*(pd->ex)));
        if (!(pd->ex)) {
            cli_errmsg("cli_pcre_parse: Unable to allocate memory\n");
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

int cli_pcre_match(struct cli_pcre_data *pd, const unsigned char *buffer, uint32_t buflen, int override_offset, int options, int *ovector, size_t ovlen)
{
    int startoffset;

    if (ovlen % 3) {
        cli_dbgmsg("cli_pcre_match: ovector length is not a multiple of 3\n");
        return CL_EARG;
    }

    /* set the startoffset, override if a value is specified */
    startoffset = pd->search_offset;
    if (override_offset >= 0)
        startoffset = override_offset;

    /* execute the pcre and return */
    return pcre_exec(pd->re, pd->ex, buffer, buflen, startoffset, options, ovector, ovlen);
}

#define DISABLE_PCRE_REPORT 0
#define MATCH_MAXLEN 1028 /*because lolz*/

/* TODO: audit this function */
static void named_substr_print(const struct cli_pcre_data *pd, const unsigned char *buffer, int *ovector, size_t ovlen)
{
    int i, j, length, namecount, trunc;
    unsigned char *tabptr;
    int name_entry_size;
    unsigned char *name_table;
    const char *start;
    char outstr[2*MATCH_MAXLEN+1];

    /* determine if there are named substrings */
    (void)pcre_fullinfo(pd->re, pd->ex, PCRE_INFO_NAMECOUNT, &namecount);
    if (namecount <= 0) {
        cli_dbgmsg("cli_pcre_report: no named substrings\n");
    }
    else {
        cli_dbgmsg("cli_pcre_report: named substrings\n");

        /* extract named substring translation table */
        (void)pcre_fullinfo(pd->re, pd->ex, PCRE_INFO_NAMETABLE, &name_table);
        (void)pcre_fullinfo(pd->re, pd->ex, PCRE_INFO_NAMEENTRYSIZE, &name_entry_size);

        /* print named substring information */
        tabptr = name_table;
        for (i = 0; i < namecount; i++) {
            int n = (tabptr[0] << 8) | tabptr[1];

            start = buffer + ovector[2*n];
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
void cli_pcre_report(const struct cli_pcre_data *pd, const unsigned char *buffer, uint32_t buflen, int rc, int *ovector, size_t ovlen)
{
    int i, j, length, trunc;
    const char *start;
    char outstr[2*MATCH_MAXLEN+1];

    /* print out additional diagnostics if cli_debug_flag is set */
    if (!DISABLE_PCRE_REPORT) {
        cli_dbgmsg("\n");
        cli_dbgmsg("cli_pcre_report: PCRE Execution Report:\n");
        cli_dbgmsg("cli_pcre_report: running regex /%s/ returns %d\n", pd->expression, rc);
        if (rc > 0) {
            /* print out full-match and capture groups */
            for (i = 0; i < rc; ++i) {
                start = buffer + ovector[2*i];
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

            named_substr_print(pd, buffer, ovector, ovlen);
        }
        else if (rc == 0 || rc == PCRE_ERROR_NOMATCH) {
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

void cli_pcre_free_single(struct cli_pcre_data *pd)
{
    if (pd->re) {
        pcre_free(pd->re);
        pd->re = NULL;
    }
    if (pd->ex) {
        free(pd->ex);
        pd->ex = NULL;
    }
    if (pd->expression) {
        free(pd->expression);
        pd->expression = NULL;
    }
}
#endif /* HAVE_PCRE */
