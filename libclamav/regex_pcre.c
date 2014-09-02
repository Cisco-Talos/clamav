/*
 *  Support for PCRE regex variant
 *
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *  Copyright (C) 2014 Cisco Systems, Inc.
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

/* TODO: redefine pcre_malloc and pcre_free */

int cli_pcre_parse(struct cli_pcre_data *pd, const char *pattern)
{
    if (!pd || !pattern) {
        cli_errmsg("cli_pcre_parse: NULL pd or NULL pattern\n");
        return CL_ENULLARG;
    }

    /* copy expression to struct cli_pcre_data */
    pd->expression = cli_strdup(pattern);
    if (!(pd->expression)) {
        cli_errmsg("cli_pcre_parse: Unable to allocate memory\n");
        return CL_EMEM;
    }

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
        case 'G':  pd->options |= PCRE_UNGREEDY;            break;

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
        return CL_EPARSE; /* TODO - change ERRORCODE */
    }

    /* now study it... (section totally not from snort) */
    pd->ex = pcre_study(pd->re, 0, &error);
    if (!(pd->ex)) {
        /* TODO: this is complicated because pcre will use system malloc */
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

/* TODO: fix this function */
int cli_pcre_match(struct cli_pcre_data *pd, const unsigned char *buffer, uint32_t buflen, int override_offset, int options, int *ovector, size_t ovlen)
{
    int rc, startoffset;

    if (ovlen % 3) {
        cli_dbgmsg("cli_pcre_match: ovector length is not a multiple of 3\n");
        return CL_EARG;
    }

    startoffset = pd->search_offset;
    if (override_offset >= 0)
        startoffset = override_offset;

    rc = pcre_exec(pd->re, pd->ex, buffer, buflen, startoffset, options, ovector, ovlen);

    return rc;
}

void cli_pcre_free_single(struct cli_pcre_data *pd)
{
    if (pd->re) {
        pcre_free(pd->re);
    }
    if (pd->ex) {
        free(pd->ex);
    }
    if (pd->expression) {
        free(pd->expression);
    }
}
#endif /* HAVE_PCRE */
