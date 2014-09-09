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
#include "matcher.h"
#include "matcher-pcre.h"
#include "mpool.h"
#include "regex_pcre.h"

int cli_pcre_addpatt(struct cli_matcher *root, const char *trigger, const char *pattern, const char *cflags, const char *offset, const uint32_t *lsigid)
{
    struct cli_pcre_meta **newmetatable = NULL, *pm = NULL;
    uint32_t pcre_count;
    const char *opt;
    int ret = CL_SUCCESS, options = 0, rssigs;

    if (!root || !trigger || !pattern || !offset) {
        cli_errmsg("pcre_addpatt: NULL root or NULL trigger or NULL pattern or NULL offset\n");
        return CL_ENULLARG;
    }

    /* TODO: trigger and regex checking (string length limitations?) */

    /* validate the lsig trigger */
    rssigs = cli_ac_chklsig(trigger, trigger + strlen(trigger), NULL, NULL, NULL, 1);
    if((strcmp(trigger, PCRE_BYPASS)) && (rssigs == -1)) {
        cli_errmsg("cli_pcre_addpatt: regex subsig %d is missing a valid logical trigger\n", lsigid[1]);
        return CL_EMALFDB;
    }
    if (rssigs > lsigid[1]) {
        cli_errmsg("cli_pcre_addpatt: regex subsig %d logical trigger refers to subsequent subsig %d\n", lsigid[1], rssigs);
        return CL_EMALFDB;
    }
    if (rssigs == lsigid[1]) {
        cli_errmsg("cli_pcre_addpatt: regex subsig %d logical trigger is self-referential\n", lsigid[1]);
        return CL_EMALFDB;
    }

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

    /* offset parsing and usage, similar to cli_ac_addsig */
    /* type-specific offsets and type-specific scanning handled during scan (cli_target_info stuff?) */
    ret = cli_caloff(offset, NULL, root->type, pm->offdata, &(pm->offset_min), &(pm->offset_max));
    if (ret != CL_SUCCESS) {
        cli_errmsg("cli_pcre_addpatt: cannot calculate offset data: %s for pattern: %s\n", offset, pattern);
        cli_pcre_freemeta(pm);
        mpool_free(root->mempool, pm);
        return ret;
    }
    if(pm->offdata[0] != CLI_OFF_ANY) {
        if(pm->offdata[0] == CLI_OFF_ABSOLUTE)
            root->pcre_absoff_num++;
        else
            root->pcre_reloff_num++;
    }

    /* parse and add options, also totally not from snort */
    if (cflags) {
        cli_dbgmsg("cli_pcre_addpatt: parsing pcre compile flags: %s\n", cflags);
        opt = cflags;

        /* cli_pcre_addoptions handles pcre specific options */
        while (cli_pcre_addoptions(&(pm->pdata), &opt, 0) != CL_SUCCESS) {
            /* handle matcher specific options here */
            switch (*opt) {
                /* no matcher-specific options atm */
            case 'g':  pm->flags |= CLI_PCRE_GLOBAL;            break;
            case 'e':  pm->flags |= CLI_PCRE_ENCOMPASS;         break;
            default:
                cli_errmsg("cli_pcre_addpatt: unknown/extra pcre option encountered %c\n", *opt);
                cli_pcre_freemeta(pm);
                mpool_free(root->mempool, pm);
                return CL_EMALFDB;
            }
            opt++;
        }

        cli_dbgmsg("PCRE_CASELESS       %08x\n", PCRE_CASELESS);
        cli_dbgmsg("PCRE_DOTALL         %08x\n", PCRE_DOTALL);
        cli_dbgmsg("PCRE_MULTILINE      %08x\n", PCRE_MULTILINE);
        cli_dbgmsg("PCRE_EXTENDED       %08x\n", PCRE_EXTENDED);

        cli_dbgmsg("PCRE_ANCHORED       %08x\n", PCRE_ANCHORED);
        cli_dbgmsg("PCRE_DOLLAR_ENDONLY %08x\n", PCRE_DOLLAR_ENDONLY);
        cli_dbgmsg("PCRE_UNGREEDY       %08x\n", PCRE_UNGREEDY);

        cli_dbgmsg("PCRE_OPTIONS        %08x\n", pm->pdata.options);
    }

    /* add pcre data to root after reallocation */
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

int cli_pcre_build(struct cli_matcher *root, long long unsigned match_limit, long long unsigned recmatch_limit)
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
        /* parse the regex - TODO: set start_offset (at the addpatt phase?), also no options override  */
        if ((ret = cli_pcre_compile(&(pm->pdata), match_limit, recmatch_limit, 0, 0)) != CL_SUCCESS) {
            cli_errmsg("cli_pcre_build: failed to parse pcre regex\n");
            return ret;
        }
    }

    return CL_SUCCESS;
}

int cli_pcre_recaloff(struct cli_matcher *root, struct cli_pcre_off *data, struct cli_target_info *info)
{
    /* TODO: fix the relative offset data maintained in cli_ac_data (generate own data?) */
    int ret;
    unsigned int i;
    struct cli_pcre_meta *pm;
    uint32_t endoff;

    if (!data) {
        return CL_ENULLARG;
    }
    if (!root || !root->pcre_metatable || !info) {
        data->shift = NULL;
        data->offset = NULL;
        return CL_SUCCESS;
    }

    /* allocate data structures */
    data->shift = (uint32_t *) cli_calloc(root->pcre_metas, sizeof(uint32_t));
    if (!data->shift) {
        cli_errmsg("cli_pcre_initoff: cannot allocate memory for data->shift\n");
        return CL_EMEM;
    }
    data->offset = (uint32_t *) cli_calloc(root->pcre_metas, sizeof(uint32_t));
    if (!data->offset) {
        cli_errmsg("cli_pcre_initoff: cannot allocate memory for data->offset\n");
        free(data->shift);
        return CL_EMEM;
    }

    /* iterate across all pcre metadata and recalc offsets */
    for (i = 0; i < root->pcre_metas; ++i) {
        pm = root->pcre_metatable[i];

        if (pm->offdata[0] == CLI_OFF_ANY) {
            data->offset[i] = 0;
            data->shift[i] = 0;
        }
        else if (pm->offdata[0] == CLI_OFF_ABSOLUTE) {
            data->offset[i] = pm->offdata[1];
            data->shift[i] = pm->offdata[2];
        }
        else if (pm->offdata[0] == CLI_OFF_EOF_MINUS) {
            data->offset[i] = pm->offdata[1];
            data->shift[i] = pm->offdata[2];
        }
        else {
            ret = cli_caloff(NULL, info, root->type, pm->offdata, &data->offset[i], &endoff);
            if (ret != CL_SUCCESS) {
                cli_errmsg("cli_pcre_recaloff: cannot calculate relative offset in signature for sig[%u,%u]\n", pm->lsigid[0], pm->lsigid[1]);
                free(data->shift);
                free(data->offset);
                return ret;
            }
            data->shift[i] = endoff-(data->offset[i]);
        }

        cli_dbgmsg("info->fsize: %lu\n", (long unsigned)info->fsize);
        if (pm->offdata[0]>9)
            cli_dbgmsg("offdata[0] type:     %x\n", pm->offdata[0]);
        else
            cli_dbgmsg("offdata[0] type:     %u\n", pm->offdata[0]);
        cli_dbgmsg("offdata[1] offset:   %u\n", pm->offdata[1]);
        cli_dbgmsg("offdata[2] maxshift: %u\n", pm->offdata[2]);
        cli_dbgmsg("offdata[3] section:  %u\n", pm->offdata[3]);
        cli_dbgmsg("offset_min: %u\n", pm->offset_min);
        cli_dbgmsg("offset_max: %u\n", pm->offset_max);

    }

    for (i = 0; i < root->pcre_metas; ++i) {
        cli_dbgmsg("data[%u]: (%u, %u)\n", i, data->offset[i], data->shift[i]);
    }

    return CL_SUCCESS;
}

void cli_pcre_freeoff(struct cli_pcre_off *data)
{
    if (data) {
        free(data->offset);
        data->offset = NULL;
        free(data->shift);
        data->shift = NULL;
    }
}

/* this fuction is static in matcher-ac.c; should we open it up to cli or maintain a copy here? */
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

int cli_pcre_scanbuf(const unsigned char *buffer, uint32_t length, const struct cli_matcher *root, struct cli_ac_data *mdata, const struct cli_pcre_off *data, cli_ctx *ctx)
{
    struct cli_pcre_meta **metatable = root->pcre_metatable, *pm = NULL;
    struct cli_pcre_data *pd;
    uint32_t adjbuffer, adjshift, adjlength;
    unsigned int i, evalcnt;
    uint64_t evalids;
    uint32_t global, encompass;
    int rc, offset, ovector[OVECCOUNT];

    if (!root->pcre_metatable) {
        return CL_SUCCESS;
    }

    for (i = 0; i < root->pcre_metas; ++i) {
        pm = root->pcre_metatable[i];
        pd = &(pm->pdata);

        /* check the evaluation of the trigger */
        cli_dbgmsg("cli_pcre_scanbuf: checking %s; running regex /%s/\n", pm->trigger, pd->expression);
        if ((strcmp(pm->trigger, PCRE_BYPASS)) && (cli_ac_chklsig(pm->trigger, pm->trigger + strlen(pm->trigger), mdata->lsigcnt[pm->lsigid[0]], &evalcnt, &evalids, 0) != 1))
            continue;

        global = (pm->flags & CLI_PCRE_GLOBAL);       /* search for all matches */
        encompass = (pm->flags & CLI_PCRE_ENCOMPASS); /* encompass search to offset->offset+maxshift */
        offset = pd->search_offset;                   /* this is usually 0 */

        cli_dbgmsg("cli_pcre_scanbuf: triggered %s; running regex /%s/%s\n", pm->trigger, pd->expression, global ? " (global)":"");

        /* adjust the buffer sent to cli_pcre_match for offset and maxshift */
        if (!data) {
            /* default to scanning whole buffer but try to use existing offdata */
            if (pm->offdata[0] == CLI_OFF_ABSOLUTE) {
                adjbuffer = pm->offdata[1];
                adjshift = pm->offdata[2];
            }
            else if (pm->offdata[0] == CLI_OFF_EOF_MINUS) {
                if (length > pm->offdata[1]) {
                    adjbuffer = length - pm->offdata[1];
                    adjshift = pm->offdata[2];
                }
                else {
                    /* EOF is invalid */
                    continue;
                }
            }
            else {
                /* you could call cli_caloff here but you should call cli_pcre_recaloff before */
                adjbuffer = 0;
                adjshift = 0;
            }
        }
        else {
            adjbuffer = data->offset[i];
            adjshift = data->shift[i];
        }

        /* check the offset bounds */
        if (adjbuffer < length) {
            /* handle encompass flag */
            if (encompass && adjshift != 0 && adjshift != CLI_OFF_NONE) {
                    if (adjbuffer+adjshift > length)
                        adjlength = length - adjbuffer;
                    else
                        adjlength = adjshift;
            }
            else {
                adjlength = length - adjbuffer;
            }
        }
        else {
            /* starting offset is outside bounds of file, skip pcre execution */
            cli_dbgmsg("cli_pcre_scanbuf: starting offset is outside bounds of file %u >= %u\n", adjbuffer, length);
            continue;
        }

        cli_dbgmsg("cli_pcre_scanbuf: passed buffer adjusted to %u +%u(%u)[%u]%s\n", adjbuffer, adjlength, adjbuffer+adjlength, adjshift, encompass ? " (encompass)":"");

        /* if the global flag is set, loop through the scanning - TODO: how does this affect really big files? */
        do {
            rc = cli_pcre_match(pd, buffer+adjbuffer, adjlength, offset, 0, ovector, OVECCOUNT);
            cli_dbgmsg("cli_pcre_scanbuf: running regex /%s/ returns %d\n", pd->expression, rc);

            /* matched, rc shouldn't be >0 unless a full match occurs */
            if (rc > 0) {
                /* check if we've gone over offset+shift */
                if (!encompass && adjshift) {
                    if (ovector[0] > adjshift) {
                        /* ignore matched offset (outside of maxshift) */
                        cli_dbgmsg("cli_pcre_scanbuf: match found outside of maxshift @%u\n", adjbuffer+ovector[0]);
                        break;
                    }
                }

                cli_dbgmsg("cli_pcre_scanbuf: assigning lsigcnt[%d][%d], located @ %d\n",
                           pm->lsigid[0], pm->lsigid[1], adjbuffer+ovector[0]);

                lsig_sub_matched(root, mdata, pm->lsigid[0], pm->lsigid[1], adjbuffer+ovector[0], 0);
            }

            /* move off to the end of the match for next match; offset is relative to adjbuffer
             * NOTE: misses matches starting within the last match */
            offset = ovector[1];

            /* clear the ovector results (they fall through the pcre_match) */
            memset(ovector, 0, sizeof(ovector));
        } while (global && rc > 0 && offset < adjlength);

        /* handle error codes */
        if (rc < 0 && rc != PCRE_ERROR_NOMATCH) {
            cli_errmsg("cli_pcre_scanbuf: cli_pcre_match: pcre_exec: returned error %d\n", rc);
            /* TODO: convert the pcre error codes to clamav error codes, handle match_limit and match_limit_recursion exceeded */
            return CL_BREAK;
        }
    }

    return CL_SUCCESS;
}

int cli_pcre_ucondscanbuf(const unsigned char *buffer, uint32_t length, const struct cli_matcher *root, struct cli_ac_data *mdata, struct cli_pcre_off *data, cli_ctx *ctx)
{
    /* TODO: copy cli_pcre_scanbuf - trigger */
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
