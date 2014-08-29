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

int cli_pcre_addpatt(struct cli_matcher *root, const char *trigger, const char *pattern, const uint32_t *lsigid, int options)
{
    struct cli_pcre_meta **newmetatable = NULL, *pm = NULL;
    uint32_t pcre_count;
    int ret = CL_SUCCESS;

    if (!root || !trigger || !pattern) {
        cli_errmsg("pcre_addpatt: NULL root or NULL trigger or NULL pattern\n");
        return CL_ENULLARG;
    }

    /* TODO: trigger and regex checking (string length limitations) */

    /* allocating entries */
    pm = (struct cli_pcre_meta *)mpool_calloc(root->mempool, 1, sizeof(*pm));
    if (!pm) {
        cli_errmsg("cli_pcre_addpatt: Unable to allocate memory for new pcre meta\n");
        return CL_EMEM;
    }

    pm->trigger = strdup(trigger);
    if (!pm->trigger) {
        cli_errmsg("cli_pcre_addpatt: Unable to allocate memory for trigger string\n");
        cli_pcre_freemeta(pm);
        mpool_free(root->mempool, pm);
        return CL_EMEM;
    }

    pm->pdata.expression = strdup(pattern);
    if (!pm->pdata.expression) {
        cli_errmsg("cli_pcre_addpatt: Unable to allocate memory for expression\n");
        cli_pcre_freemeta(pm);
        mpool_free(root->mempool, pm);
        return CL_EMEM;
    }

    pm->lsigid[0] = lsigid[0];
    pm->lsigid[1] = lsigid[1];

    /* add pcre data and refentry to root after reallocation */
    pcre_count = root->pcre_metas+1;
    newmetatable = (struct cli_pcre_meta **)mpool_realloc(root->mempool, root->pcre_metatable,
                                         pcre_count * sizeof(struct cli_pcre_meta *));
    if (!newmetatable) {
        cli_errmsg("cli_pcre_addpatt: Unable to allocate memory for new pcre meta table\n");
        cli_pcre_freemeta(pm);
        mpool_free(root->mempool, pm);
        return CL_EMEM;
    }

    cli_dbgmsg("cli_pcre_addpatt: Adding /%s/ triggered on (%s) as subsig %d for lsigid %d\n",
               pm->pdata.expression, pm->trigger, pm->lsigid[1], pm->lsigid[0]);

    newmetatable[pcre_count-1] = pm;
    root->pcre_metatable = newmetatable;

    root->pcre_metas = pcre_count;

    return CL_SUCCESS;
}
/*
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

    // TODO: regex checking (string length limitations)
    //cli_pcre_free_single(pd);

    // allocating entries
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

    // set the refentry
    refe->lsigid[0] = lsigid[0];
    refe->lsigid[1] = lsigid[1];
    refe->next = NULL; // for now, all regex have single reference - TODO

    // add pcre data and refentry to root after reallocation
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
*/
int cli_pcre_build(struct cli_matcher *root, long long unsigned match_limit, long long unsigned recmatch_limit, int options)
{
    unsigned int i;
    int ret;
    struct cli_pcre_meta *pm = NULL;

    for (i = 0; i < root->pcre_metas; ++i) {
        pm = root->pcre_metatable[i];

        if (!pm) {
            cli_errmsg("cli_pcre_build: metadata for pcre %d is missing\n", i);
            return CL_ENULLARG;
        }    

        cli_dbgmsg("cli_pcre_build: Compiling regex: %s\n", pm->pdata.expression);
        /* parse the regex - TODO: set start_offset (at the addpatt phase?) */
        if ((ret = cli_pcre_compile(&(pm->pdata), match_limit, recmatch_limit, options)) != CL_SUCCESS) {
            cli_errmsg("cli_pcre_build: failed to parse pcre regex\n");
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

/* TODO - fix this function; currently only single match */
int cli_pcre_scanbuf(const unsigned char *buffer, uint32_t length, const struct cli_matcher *root, struct cli_ac_data *mdata, cli_ctx *ctx)
{
    struct cli_pcre_meta **metatable = root->pcre_metatable, *pm = NULL;
    struct cli_pcre_data *pd;
    unsigned int i, evalcnt;
    uint64_t evalids;
    int rc;
    int ovector[OVECCOUNT];

    for (i = 0; i < root->pcre_metas; ++i) {
        pm = root->pcre_metatable[i];

        /* check the evaluation of the trigger */
        if ((strcmp(pm->trigger, PCRE_BYPASS)) && (cli_ac_chklsig(pm->trigger, pm->trigger + strlen(pm->trigger), mdata->lsigcnt[pm->lsigid[0]], &evalcnt, &evalids, 0) != 1))
            continue;

        cli_dbgmsg("cli_pcre_scanbuf: trigger %s running regex /%s/\n", pm->trigger, pd->expression);

        rc = cli_pcre_match(pd, buffer, length, CLI_PCREMATCH_NOOVERRIDE, ovector, OVECCOUNT);

        cli_dbgmsg("cli_pcre_scanbuf: running regex /%s/ returns %d\n", pd->expression, rc);
        if (rc > 0) { /* matched at least once */
            cli_dbgmsg("cli_pcre_scanbuf: assigning lsigcnt[%d][%d], located @ %d\n",
                       pm->lsigid[0], pm->lsigid[1], ovector[0]);

            lsig_sub_matched(root, mdata, pm->lsigid[0], pm->lsigid[1], ovector[0], 0);
        }
        else if (rc == 0 || rc == PCRE_ERROR_NOMATCH) { /* no match */
            cli_dbgmsg("cli_pcre_scanbuf: no match\n");
        }
        else { /* error occurred */
            cli_errmsg("cli_pcre_scanbuf: cli_pcre_match: pcre_exec: returned error %d\n", rc);
            return CL_BREAK;
        }
    }

    return CL_SUCCESS;
}

/* TODO - fix this function; currently only single match */
int cli_pcre_ucondscanbuf(const unsigned char *buffer, uint32_t length, const struct cli_matcher *root, struct cli_ac_data *mdata, cli_ctx *ctx)
{
    struct cli_pcre_meta **metatable = root->pcre_metatable, *pm = NULL;
    struct cli_pcre_data *pd = NULL;
    unsigned int i;
    int rc;
    int ovector[OVECCOUNT];

    for (i = 0; i < root->pcre_metas; ++i) {
        pm = metatable[i];
        pd = &(pm->pdata);

        cli_dbgmsg("cli_pcre_ucondscanbuf: running regex /%s/\n", pd->expression);

        rc = cli_pcre_match(pd, buffer, length, CLI_PCREMATCH_NOOVERRIDE, ovector, OVECCOUNT);

        cli_dbgmsg("cli_pcre_ucondscanbuf: running regex /%s/ returns %d\n", pd->expression, rc);
        if (rc > 0) { /* matched at least once */
            cli_dbgmsg("cli_pcre_ucondscanbuf: assigning lsigcnt[%d][%d], located @ %d\n",
                       pm->lsigid[0], pm->lsigid[1], ovector[0]);

            lsig_sub_matched(root, mdata, pm->lsigid[0], pm->lsigid[1], ovector[0], 0);
        }
        else if (rc == 0 || rc == PCRE_ERROR_NOMATCH) { /* no match */
            cli_dbgmsg("cli_pcre_ucondscanbuf: no match\n");
        }
        else { /* error occurred */
            cli_errmsg("cli_pcre_ucondscanbuf: cli_pcre_match: pcre_exec: returned error %d\n", rc);
            return CL_BREAK;
        }
    }

    cli_dbgmsg("cli_pcre_ucondscanbuf: successful return!\n");
    return CL_SUCCESS;
}

void cli_pcre_freemeta(struct cli_pcre_meta *pm)
{
    if (!pm)
        return;

    if (pm->trigger)
        free(pm->trigger);

    cli_pcre_free_single(&(pm->pdata));
}

void cli_pcre_freetable(struct cli_matcher *root)
{
    uint32_t i;
    struct cli_pcre_meta *pm = NULL;

    for (i = 0; i < root->pcre_metas; ++i) {
        /* free pcre meta*/
        pm = root->pcre_metatable[i];
        cli_pcre_freemeta(pm);
        mpool_free(root->mempool, pm);
    }

    /* free holding structures and set count to zero */
    mpool_free(root->mempool, root->pcre_metatable);
    root->pcre_metatable = NULL;
    root->pcre_metas = 0;
}
#endif /* HAVE_PCRE */
