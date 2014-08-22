/*
 *  Support for matcher using PCRE
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

#include <pcre.h>

#include "clamav.h"
#include "cltypes.h"
#include "others.h"
#include "matcher-pcre.h"
#include "mpool.h"
#include "regex_pcre.h"

//int pcre_add_pattern(struct pcre_matcher *matcher, const char *pattern, int options)
/* TODO - memory cleanup on error */
int cli_pcre_addpatt(struct cli_matcher *root, const char *pattern, const uint32_t *lsigid, unsigned int options)
{
    struct cli_pcre_data **newdata, *pd;
    struct cli_pcre_refentry **newreftable, *refe;
    uint32_t new_numpcres;
    int ret = CL_SUCCESS;

    if (!root || !pattern) {
        cli_errmsg("pcre_add_pattern: NULL root or NULL pattern\n");
        return CL_ENULLARG;
    }

    /* TODO: regex checking */
    //cli_pcre_free_single(pd);

    /* allocating entries */
    pd = (struct cli_pcre_data *)mpool_calloc(root->mempool, 1, sizeof(*pd));
    if (!pd) {
        cli_errmsg("cli_pcre_addpatt: Unable to allocate memory\n");
        return CL_EMEM;
    }

    refe = (struct cli_pcre_refentry *)cli_calloc(1, sizeof(struct cli_pcre_refentry));
    if (!refe) {
        cli_errmsg("cli_pcre_addpatt: failed to allocate space\n");
        return CL_EMEM;
    }

    cli_dbgmsg("cli_pcre_addpatt: Compiling regex: %s\n", pattern);
    /* parse the regex - TODO: set start_offset  */
    if ((ret = cli_pcre_parse(pd, pattern, options)) != CL_SUCCESS) {
        cli_errmsg("cli_pcre_addpatt: failed to parse pcre regex\n");
        return ret;
    }

    /* set the refentry */
    refe->lsigid[0] = lsigid[0];
    refe->lsigid[1] = lsigid[1];
    refe->next = NULL; /* for now, all regex have single reference - TODO */

    /* add pcre data and refentry to root after reallocation */
    new_numpcres = root->num_pcres+1;
    newdata = (struct cli_pcre_data **)mpool_realloc(root->mempool, root->all_pcres,
                                         new_numpcres * sizeof(struct cli_pcre_data *));
    if (!newdata) {
        cli_errmsg("cli_pcre_addpatt: Unable to allocate memory\n");
        return CL_EMEM;
    }

    newreftable = (struct cli_pcre_refentry **)mpool_realloc(root->mempool, root->pcre_reftable,
                                                 new_numpcres * sizeof(struct cli_pcre_refentry *));
    if (!newreftable) {
        cli_errmsg("cli_pcre_addpatt: Unable to allocate memory\n");
        return CL_EMEM;
    }

    cli_dbgmsg("cli_pcre_addpatt: Adding /%s/ for subsig %d on engine->root[%d]\n",
               pattern, refe->lsigid[1], refe->lsigid[0]);

    newdata[new_numpcres-1] = pd;
    newreftable[new_numpcres-1] = refe;
    root->pcre_reftable = newreftable;
    root->all_pcres = newdata;

    root->num_pcres = new_numpcres;

    return CL_SUCCESS;
}

int cli_pcre_scanbuf()
{
}

void cli_pcre_free(struct cli_matcher *root)
{
    uint32_t i;
    struct cli_pcre_data *pd;
    struct cli_pcre_refentry *p_rt, *p_del;

    for (i = 0; i < root->num_pcres; ++i) {
        /* free compiled pcre */
        pd = root->all_pcres[i];
        cli_pcre_free_single(pd);

        /* free reference table */
        p_rt = root->pcre_reftable[i];
        while (p_rt) {
            p_del = p_rt;
            p_rt = p_rt->next;
            free(p_del);
        }
    }

    /* free holding structures */
    mpool_free(root->mempool, root->all_pcres);
    mpool_free(root->mempool, root->pcre_reftable);

    root->all_pcres = NULL;
    root->pcre_reftable = NULL;
}
