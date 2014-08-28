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

#if HAVE_PCRE
#include "clamav.h"
#include "cltypes.h"
#include "others.h"
#include "matcher-pcre.h"
#include "mpool.h"
#include "regex_pcre.h"

//int pcre_add_pattern(struct pcre_matcher *matcher, const char *pattern, int options)
/* TODO - memory cleanup on error */
int cli_pcre_adducondpatt(struct cli_matcher *root, const char *pattern, const uint32_t *lsigid)
{
    struct cli_pcre_data **newdata, *pd;
    struct cli_pcre_refentry **newreftable, *refe;
    uint32_t new_numpcres;
    int ret = CL_SUCCESS;

    if (!root || !pattern) {
        cli_errmsg("pcre_adducondpatt: NULL root or NULL pattern\n");
        return CL_ENULLARG;
    }

    /* TODO: regex checking (string length limitations) */
    //cli_pcre_free_single(pd);

    /* allocating entries */
    pd = (struct cli_pcre_data *)mpool_calloc(root->mempool, 1, sizeof(*pd));
    if (!pd) {
        cli_errmsg("cli_pcre_adducondpatt: Unable to allocate memory\n");
        return CL_EMEM;
    }

    pd->expression = strdup(pattern);

    refe = (struct cli_pcre_refentry *)cli_calloc(1, sizeof(struct cli_pcre_refentry));
    if (!refe) {
        cli_errmsg("cli_pcre_adducondpatt: failed to allocate space\n");
        return CL_EMEM;
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
        cli_errmsg("cli_pcre_adducondpatt: Unable to allocate memory\n");
        return CL_EMEM;
    }

    newreftable = (struct cli_pcre_refentry **)mpool_realloc(root->mempool, root->pcre_reftable,
                                                 new_numpcres * sizeof(struct cli_pcre_refentry *));
    if (!newreftable) {
        cli_errmsg("cli_pcre_adducondpatt: Unable to allocate memory\n");
        return CL_EMEM;
    }

    cli_dbgmsg("cli_pcre_adducondpatt: Adding /%s/ as subsig %d for lsigid %d\n",
               pattern, refe->lsigid[1], refe->lsigid[0]);

    newdata[new_numpcres-1] = pd;
    newreftable[new_numpcres-1] = refe;
    root->pcre_reftable = newreftable;
    root->all_pcres = newdata;

    root->num_pcres = new_numpcres;

    return CL_SUCCESS;
}

int cli_pcre_ucondbuild(struct cli_matcher *root, long long unsigned match_limit, long long unsigned recmatch_limit, unsigned int options)
{
    int i, ret;
    struct cli_pcre_data *pd;

    for (i = 0; i < root->num_pcres; ++i) {
        pd = root->all_pcres[i];

        cli_dbgmsg("cli_pcre_ucondbuild: Compiling regex: %s\n", pd->expression);
        /* parse the regex - TODO: set start_offset  */
        if ((ret = cli_pcre_compile(pd, match_limit, recmatch_limit, options)) != CL_SUCCESS) {
            cli_errmsg("cli_pcre_ucondbuild: failed to parse pcre regex\n");
            return ret;
        }
    }

    return CL_SUCCESS;
}

static inline void lsig_sub_matched(const struct cli_matcher *root, struct cli_ac_data *mdata, uint32_t lsigid1, uint32_t lsigid2, uint32_t realoff, int partial)
{
	const struct cli_lsig_tdb *tdb = &root->ac_lsigtable[lsigid1]->tdb;

    if(realoff != CLI_OFF_NONE) {
	if(mdata->lsigsuboff_first[lsigid1][lsigid2] == CLI_OFF_NONE)
	    mdata->lsigsuboff_first[lsigid1][lsigid2] = realoff;
	if(mdata->lsigsuboff_last[lsigid1][lsigid2] != CLI_OFF_NONE && ((!partial && realoff <= mdata->lsigsuboff_last[lsigid1][lsigid2]) || (partial && realoff < mdata->lsigsuboff_last[lsigid1][lsigid2])))
	    return;
	mdata->lsigcnt[lsigid1][lsigid2]++;
	if(mdata->lsigcnt[lsigid1][lsigid2] <= 1 || !tdb->macro_ptids || !tdb->macro_ptids[lsigid2])
	    mdata->lsigsuboff_last[lsigid1][lsigid2] = realoff;
    }

    if (mdata->lsigcnt[lsigid1][lsigid2] > 1) {
	/* Check that the previous match had a macro match following it at the 
	 * correct distance. This check is only done after the 1st match.*/
	const struct cli_ac_patt *macropt;
	uint32_t id, last_macro_match, smin, smax, last_macroprev_match;
	if (!tdb->macro_ptids)
	    return;
	id = tdb->macro_ptids[lsigid2];
	if (!id)
	    return;
	macropt = root->ac_pattable[id];
	smin = macropt->ch_mindist[0];
	smax = macropt->ch_maxdist[0];
	/* start of last macro match */
	last_macro_match = mdata->macro_lastmatch[macropt->sigid];
	/* start of previous lsig subsig match */
	last_macroprev_match = mdata->lsigsuboff_last[lsigid1][lsigid2];
	if (last_macro_match != CLI_OFF_NONE)
	    cli_dbgmsg("Checking macro match: %u + (%u - %u) == %u\n",
		       last_macroprev_match, smin, smax, last_macro_match);
	if (last_macro_match == CLI_OFF_NONE ||
	    last_macroprev_match + smin > last_macro_match ||
	    last_macroprev_match + smax < last_macro_match) {
	    cli_dbgmsg("Canceled false lsig macro match\n");
	    /* Previous match was false - cancel it */
	    mdata->lsigcnt[lsigid1][lsigid2]--;
	    mdata->lsigsuboff_last[lsigid1][lsigid2] = realoff;
	} else {
	    /* mark the macro sig itself matched */
	    mdata->lsigcnt[lsigid1][lsigid2+1]++;
	    mdata->lsigsuboff_last[lsigid1][lsigid2+1] = last_macro_match;
	}
    }
}

int cli_pcre_ucondscanbuf(const unsigned char *buffer, uint32_t length, const struct cli_matcher *root, struct cli_ac_data *mdata, cli_ctx *ctx)
{
    struct cli_pcre_data **data = root->all_pcres, *pd;
    struct cli_pcre_refentry **reftable = root->pcre_reftable, *refe;
    uint32_t cnt = root->num_pcres;
    int i, rc;
    int ovector[OVECCOUNT];

    for (i = 0; i < cnt; ++i) {
        pd = data[i];
        refe = reftable[i];

        cli_dbgmsg("cli_pcre_scanbuf: running regex /%s/\n", pd->expression);

        rc = cli_pcre_match(pd, buffer, length, CLI_PCREMATCH_NOOVERRIDE, ovector, OVECCOUNT);

        cli_dbgmsg("cli_pcre_scanbuf: running regex /%s/ returns %d\n", pd->expression, rc);
        if (rc > 0) { /* matched at least once */
            cli_dbgmsg("cli_pcre_scanbuf: assigning lsigcnt[%d][%d] to %d, located @ %d\n",
                       refe->lsigid[0], refe->lsigid[1], rc, ovector[0]);

            lsig_sub_matched(root, mdata, refe->lsigid[0], refe->lsigid[1], ovector[0], 0);
            //(mdata->lsigcnt)[refe->lsigid[0]][refe->lsigid[1]] = rc;
        }
        else if (rc ==0 || rc == PCRE_ERROR_NOMATCH) { /* no match */
            cli_dbgmsg("cli_pcre_scanbuf: no match\n");
        }
        else { /* error occurred */
            cli_errmsg("cli_pcre_scanbuf: cli_pcre_match: pcre_exec: returned error %d\n", rc);
            return CL_BREAK;
        }
    }

    cli_dbgmsg("cli_pcre_scanbuf: successful return!\n");
    return CL_SUCCESS;
}

void cli_pcre_ucondfree(struct cli_matcher *root)
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
#endif /* HAVE_PCRE */
