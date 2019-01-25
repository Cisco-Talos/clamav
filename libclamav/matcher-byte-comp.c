/*
 *  Byte comparison matcher support functions
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

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <errno.h>

#include "clamav.h"
#include "others.h"
#include "matcher.h"
#include "matcher-ac.h"
#include "matcher-byte-comp.h"
#include "mpool.h"
#include "readdb.h"
#include "str.h"

/* DEBUGGING */
//#define MATCHER_BCOMP_DEBUG
#ifdef MATCHER_BCOMP_DEBUG
#  define bcm_dbgmsg(...) cli_dbgmsg( __VA_ARGS__)
#else
#  define bcm_dbgmsg(...)
#endif
#undef MATCHER_BCOMP_DEBUG

/* BCOMP MATCHER FUNCTIONS */


/**
 * @brief function to add the byte compare subsig into the matcher root struct
 *
 * @param root the matcher root struct in question, houses all relevant lsig and subsig info
 * @param virname virusname as given by the signature
 * @param hexsig the raw sub signature buffer itself which we will be checking/parsing
 * @param lsigid the numeric internal reference number which can be used to access this lsig in the root struct
 * @param options additional options for pattern matching, stored as a bitmask
 *
 */
cl_error_t cli_bcomp_addpatt(struct cli_matcher *root, const char *virname, const char *hexsig, const uint32_t *lsigid, unsigned int options) {

    size_t len = 0;
    uint32_t i = 0;
    const char *buf_start = NULL;
    const char *buf_end = NULL;
    char *buf = NULL;
    const char *tokens[4];
    size_t toks = 0;
    int16_t ref_subsigid = -1;
    int64_t offset_param = 0;
    int64_t ret = CL_SUCCESS;
    size_t byte_length = 0;
    int64_t comp_val = 0;
    char *comp_buf = NULL;
    char *comp_start = NULL;
    char *comp_end = NULL;
    char *hexcpy = NULL;

    if (!hexsig || !(*hexsig) || !root || !virname) {
        return CL_ENULLARG;
    }

    /* we'll be using these to help the root matcher struct keep track of each loaded byte compare pattern */
    struct cli_bcomp_meta **newmetatable; 
    uint32_t bcomp_count = 0;

    /* zero out our byte compare data struct and tie it to the root struct's mempool instance */
    struct cli_bcomp_meta *bcomp;
    bcomp = (struct cli_bcomp_meta *) mpool_calloc(root->mempool, 1, sizeof(*bcomp));
    if (!bcomp) {
        cli_errmsg("cli_bcomp_addpatt: Unable to allocate memory for new byte compare meta\n");
        return CL_EMEM;
    }

    /* allocate virname space with the root structure's mempool instance */
    bcomp->virname = (char *) cli_mpool_virname(root->mempool, virname, options & CL_DB_OFFICIAL);
    if(!bcomp->virname) {
        cli_errmsg("cli_bcomp_addpatt: Unable to allocate memory for virname or NULL virname\n");
        cli_bcomp_freemeta(root, bcomp);
        return CL_EMEM;
    }

    /* bring along the standard lsigid vector, first param marks validity of vector, 2nd is lsigid, 3rd is subsigid */
    if (lsigid) {
        root->ac_lsigtable[lsigid[0]]->virname = bcomp->virname;

        bcomp->lsigid[0] = 1;
        bcomp->lsigid[1] = lsigid[0];
        bcomp->lsigid[2] = lsigid[1];
    }
    else {
        /* sigtool */
        bcomp->lsigid[0] = 0;
    }

    /* first need to grab the subsig reference, we'll use this later to determine our offset */
    buf_start = hexsig;
    buf_end = hexsig;

    ref_subsigid = strtol(buf_start, (char**) &buf_end, 10);
    if (buf_end && buf_end[0] != '(') {
        cli_errmsg("cli_bcomp_addpatt: while byte compare subsig parsing, reference subsig id was invalid or included non-decimal character\n");
        cli_bcomp_freemeta(root, bcomp);
        return CL_EMALFDB;
    }

    bcomp->ref_subsigid = ref_subsigid;

    /* use the passed hexsig buffer to find the start and ending parens and store the param length (minus starting paren) */
    buf_start = buf_end;
    if (buf_start[0] == '(') {
        if (( buf_end = strchr(buf_start, ')') )) {
            len = (size_t) (buf_end - ++buf_start);
        }
        else {
            cli_errmsg("cli_bcomp_addpatt: ending paren not found\n");
            cli_bcomp_freemeta(root, bcomp);
            return CL_EMALFDB;
        }
    }
    else {
            cli_errmsg("cli_bcomp_addpatt: opening paren not found\n");
            cli_bcomp_freemeta(root, bcomp);
            return CL_EMALFDB;
    }

    /* make a working copy of the param buffer */
    buf = cli_strndup(buf_start, len);

    /* break up the new param buffer into its component strings and verify we have exactly 3 */
    toks = cli_strtokenize(buf, '#', 3+1, tokens);
    if (3 != toks) {
        cli_errmsg("cli_bcomp_addpatt: %zu (or more) params provided, 3 expected\n", toks);
        free(buf);
        cli_bcomp_freemeta(root, bcomp);
        return CL_EMALFDB;
    }
    tokens[3] = NULL;

    /* since null termination is super guaranteed thanks to strndup and cli_strokenize, we can use strtol to grab the
     * offset params. this has the added benefit of letting us parse hex values too */
    buf_end = NULL;
    buf_start = tokens[0];
    switch (buf_start[0]) {
        case '<':
            if ((++buf_start)[0] == '<') {
                offset_param = strtol(++buf_start, (char**) &buf_end, 0);
                if (buf_end && buf_end+1 != tokens[1]) {
                    cli_errmsg("cli_bcomp_addpatt: while parsing (%s#%s#%s), offset parameter included invalid characters\n", tokens[0], tokens[1], tokens[2]);
                    free(buf);
                    cli_bcomp_freemeta(root, bcomp);
                    return CL_EMALFDB;
                }
                /* two's-complement for negative value */
                offset_param = (~offset_param) + 1;

             } else {
                    cli_errmsg("cli_bcomp_addpatt: while parsing (%s#%s#%s), shift operator not valid\n", tokens[0], tokens[1], tokens[2]);
                    free(buf);
                    cli_bcomp_freemeta(root, bcomp);
                    return CL_EMALFDB;
             }
            break;

        case '>':
            if ((++buf_start)[0] == '>') {
                offset_param = strtol(++buf_start, (char**) &buf_end, 0);
                if (buf_end && buf_end+1 != tokens[1]) {
                    cli_errmsg("cli_bcomp_addpatt: while parsing (%s#%s#%s), offset parameter included invalid characters\n", tokens[0], tokens[1], tokens[2]);
                    free(buf);
                    cli_bcomp_freemeta(root, bcomp);
                    return CL_EMALFDB;
                }
                break;
            } else {
                    cli_errmsg("cli_bcomp_addpatt: while parsing (%s#%s#%s), shift operator and/or offset not valid\n", tokens[0], tokens[1], tokens[2]);
                    free(buf);
                    cli_bcomp_freemeta(root, bcomp);
                    return CL_EMALFDB;
            }
        case '0':
        case '\0':
            offset_param = 0;
            break;

        default:
            cli_errmsg("cli_bcomp_addpatt: while parsing (%s#%s#%s), shift operator included invalid characters\n", tokens[0], tokens[1], tokens[2]);
            free(buf);
            cli_bcomp_freemeta(root, bcomp);
            return CL_EMALFDB;
    }

    bcomp->offset = offset_param;

    /* the byte length indicator options are stored in a bitmask--by design each option gets its own nibble */
    buf_start = tokens[1];

    while (!isdigit(*buf_start)) {

        switch (*buf_start) {
            case 'h':
                /* hex, decimal, auto, and binary options are mutually exclusive parameters */
                if (bcomp->options & CLI_BCOMP_DEC || bcomp->options & CLI_BCOMP_BIN || bcomp->options & CLI_BCOMP_AUTO) {
                    ret = CL_EMALFDB;
                } else {
                    bcomp->options |= CLI_BCOMP_HEX;
                } break;

            case 'd':
                /* hex, decimal, auto, and binary options are mutually exclusive parameters */
                /* decimal may not be used with little-endian. big-endian is implied. */
                if (bcomp->options & CLI_BCOMP_HEX || bcomp->options & CLI_BCOMP_BIN || bcomp->options & CLI_BCOMP_AUTO || bcomp->options & CLI_BCOMP_LE) {
                    ret = CL_EMALFDB;
                } else {
                    bcomp->options |= CLI_BCOMP_DEC;
                    bcomp->options |= CLI_BCOMP_BE;
                } break;

            case 'i':
                /* hex, decimal, auto, and binary options are mutually exclusive parameters */
                if (bcomp->options & CLI_BCOMP_HEX || bcomp->options & CLI_BCOMP_DEC || bcomp->options & CLI_BCOMP_AUTO) {
                    ret = CL_EMALFDB;
                } else {
                    bcomp->options |= CLI_BCOMP_BIN;
                } break;

            case 'a':
                /* for automatic hex or decimal run-time detection */
                /* hex, decimal, auto, and binary options are mutually exclusive parameters */
                if (bcomp->options & CLI_BCOMP_HEX || bcomp->options & CLI_BCOMP_DEC || bcomp->options & CLI_BCOMP_BIN) {
                    ret = CL_EMALFDB;
                } else {
                    bcomp->options |= CLI_BCOMP_AUTO;
                } break;

            case 'l':
                /* little and big endian options are mutually exclusive parameters */
                /* decimal may not be used with little-endian */
                if (bcomp->options & CLI_BCOMP_BE || bcomp->options & CLI_BCOMP_DEC) {
                    ret = CL_EMALFDB;
                } else {
                    bcomp->options |= CLI_BCOMP_LE;
                } break;

            case 'b':
                /* little and big endian options are mutually exclusive parameters */
                if (bcomp->options & CLI_BCOMP_LE) {
                    ret = CL_EMALFDB;
                } else {
                    bcomp->options |= CLI_BCOMP_BE;
                } break;

            case 'e':
                /* for exact byte length matches */
                bcomp->options |= CLI_BCOMP_EXACT;
                break;

            default:
                ret = CL_EMALFDB;
                break;
        }

        if (CL_EMALFDB == ret) {
            cli_errmsg("cli_bcomp_addpatt: while parsing (%s#%s#%s), option parameter was found invalid\n", tokens[0], tokens[1], tokens[2]);
            free(buf);
            cli_bcomp_freemeta(root, bcomp);
            return ret;
        }
        buf_start++;
    }

    /* parse out the byte length parameter */
    buf_end = NULL;
    byte_length = strtol(buf_start, (char **) &buf_end, 0);
    if (buf_end && buf_end+1 != tokens[2]) {
        cli_errmsg("cli_bcomp_addpatt: while parsing (%s#%s#%s), byte length parameter included invalid characters\n", tokens[0], tokens[1], tokens[2]);
        free(buf);
        cli_bcomp_freemeta(root, bcomp);
        return CL_EMALFDB;
    }

    if (bcomp->options & CLI_BCOMP_BIN && (byte_length > CLI_BCOMP_MAX_BIN_BLEN || CLI_BCOMP_MAX_BIN_BLEN % byte_length)) {
        cli_errmsg("cli_bcomp_addpatt: while parsing (%s#%s#%s), byte length was either too long or not a valid number of bytes\n", tokens[0], tokens[1], tokens[2]);
        free(buf);
        cli_bcomp_freemeta(root, bcomp);
        return CL_EMALFDB;
    }

    /* same deal with hex byte lengths */
    if (bcomp->options & CLI_BCOMP_HEX && (byte_length > CLI_BCOMP_MAX_HEX_BLEN)) {
        cli_errmsg("cli_bcomp_addpatt: while parsing (%s#%s#%s), byte length was too long\n", tokens[0], tokens[1], tokens[2]);
        free(buf);
        cli_bcomp_freemeta(root, bcomp);
        return CL_EMALFDB;
    }

    bcomp->byte_len = byte_length;

    /* we can have up to two comparison eval statements, each sperated by a comma, let's parse them in a separate string */
    comp_buf = cli_strdup(tokens[2]);
    if (!comp_buf) {
        cli_errmsg("cli_bcomp_addpatt: Unable to allocate memory for comparison buffer\n");
        cli_bcomp_freemeta(root, bcomp);
        return CL_EMEM;
    }
    /* use different buffer start and end markers so we can keep track of what we need to free later */
    buf_start = comp_buf;
    comp_start = strchr(comp_buf, ',');
    comp_end = strrchr(comp_buf, ',');

    /* check to see if we have exactly one comma, then set our count and tokenize our string apropriately */
    if (comp_start && comp_end) {
        if (comp_end == comp_start) {
            comp_start[0] = '\0';
            bcomp->comp_count = 2;

        } else {
            cli_errmsg("cli_bcomp_addpatt: while parsing (%s#%s#%s), too many commas found in comparison string\n", tokens[0], tokens[1], tokens[2]);
            cli_bcomp_freemeta(root, bcomp);
            free(buf);
            free((void*)buf_start);
            return CL_EPARSE;
        }
    } else {
        comp_start = comp_buf;
        bcomp->comp_count = 1;
    }

    /* allocate comp struct list space with the root structure's mempool instance */
    bcomp->comps = (struct cli_bcomp_comp **) mpool_calloc(root->mempool, bcomp->comp_count, sizeof(struct cli_bcomp_comp *));
    if(!bcomp->comps) {
        cli_errmsg("cli_bcomp_addpatt: unable to allocate memory for comp struct pointers\n");
        free(buf);
        free((void*)buf_start);
        cli_bcomp_freemeta(root, bcomp);
        return CL_EMEM;
    }

    /* loop through our new list, allocate, and parse out the needed comparison evaluation bits for this subsig */
    for (i = 0; i < bcomp->comp_count; i++) {

        bcomp->comps[i] = (struct cli_bcomp_comp*) mpool_calloc(root->mempool, 1, sizeof(struct cli_bcomp_comp));
        if(!bcomp->virname) {
            cli_errmsg("cli_bcomp_addpatt: unable to allocate memory for comp struct\n");
            free(buf);
            free((void*)buf_start);
            cli_bcomp_freemeta(root, bcomp);
            return CL_EMEM;
        }

        /* currently only >, <, and = are supported comparison symbols--this makes parsing very simple */
        switch (*comp_buf) {
            case '<':
            case '>':
            case '=':
                bcomp->comps[i]->comp_symbol = *comp_buf;    break;

            default:
                cli_errmsg("cli_bcomp_addpatt: while parsing (%s#%s#%s), byte comparison symbol was invalid (>, <, = are supported operators) %s\n", tokens[0], tokens[1], tokens[2], comp_buf);
                free(buf);
                free((void*)buf_start);
                cli_bcomp_freemeta(root, bcomp);
                return CL_EMALFDB;
        }

        /* grab the comparison value itself */
        comp_end = NULL;
        comp_buf++;
        comp_val = strtoll(comp_buf, (char **) &comp_end, 0);
        if (*comp_end) {
            cli_errmsg("cli_bcomp_addpatt: while parsing (%s#%s#%s), comparison value contained invalid input\n", tokens[0], tokens[1], tokens[2]);
            free(buf);
            free((void*)buf_start);
            cli_bcomp_freemeta(root, bcomp);
            return CL_EMALFDB;
        }

        bcomp->comps[i]->comp_value = comp_val;

        /* a bit of tricksy pointer stuffs which handles all count cases, taking advantage of where strtoll drops endptr */
        if (comp_end == comp_start) {
            comp_buf = comp_start;
            comp_buf++;
        }

        /* manually verify successful pattern parsing */
        bcm_dbgmsg("Matcher Byte Compare: (%s%ld#%c%c%s%zu#%c%ld)\n",
                bcomp->offset ==  0 ? "" :
                (bcomp->offset < 0 ? "<<" : ">>"),
                bcomp->offset,
                bcomp->options & CLI_BCOMP_HEX ? 'h' : (bcomp->options & CLI_BCOMP_DEC ? 'd' : 'i'),
                bcomp->options & CLI_BCOMP_LE ? 'l' : 'b',
                bcomp->options & CLI_BCOMP_EXACT ? "e" : "",
                bcomp->byte_len,
                bcomp->comps[i]->comp_symbol,
                bcomp->comps[i]->comp_value);
    }

    free((void*)buf_start);
    buf_start = NULL;
    /* add byte compare info to the root after reallocation */
    bcomp_count = root->bcomp_metas+1;

    /* allocate space for new meta table to store in root structure and increment number of byte compare patterns added */
    newmetatable = (struct cli_bcomp_meta **) mpool_realloc(root->mempool, root->bcomp_metatable, bcomp_count * sizeof(struct cli_bcomp_meta *));
    if(!newmetatable) {
        cli_errmsg("cli_bcomp_addpatt: Unable to allocate memory for new bcomp meta table\n");
        cli_bcomp_freemeta(root, bcomp);
        return CL_EMEM;
    }

    newmetatable[bcomp_count-1] = bcomp;
    root->bcomp_metatable = newmetatable;

    root->bcomp_metas = bcomp_count;

    /* if everything went well bcomp has been totally populated, which means we can cleanup and exit */
    free(buf);
    return CL_SUCCESS;
}

/**
 * @brief function to perform all byte compare matching on the file buffer
 *
 * @param map the file map to perform logical byte comparison upon
 * @param res the result structure, primarily used by sigtool
 * @param root the root structure in which all byte compare lsig and subsig information is stored
 * @param mdata the ac data struct which contains offset information from recent subsig matches
 * @param ctx the clamav context struct
 *
 */
cl_error_t cli_bcomp_scanbuf(const unsigned char *buffer, size_t buffer_length, const char **virname, struct cli_ac_result **res, const struct cli_matcher *root, struct cli_ac_data *mdata, cli_ctx *ctx) {

    int64_t i = 0, rc = 0, ret = CL_SUCCESS;
    uint32_t lsigid, ref_subsigid;
    uint32_t offset = 0;
    uint8_t viruses_found = 0;
    struct cli_bcomp_meta *bcomp = NULL;
    struct cli_ac_result *newres = NULL;

    uint32_t evalcnt = 0;
    uint64_t evalids = 0;
    char *subsigid = NULL;

    if (!(root) || !(root->bcomp_metas) || !(root->bcomp_metatable) || !(mdata) || !(mdata->offmatrix) || !(ctx)) {
        return CL_SUCCESS;
    }

    for(i = 0; i < root->bcomp_metas; i++) {

        bcomp = root->bcomp_metatable[i];
        lsigid = bcomp->lsigid[1];
        ref_subsigid = bcomp->ref_subsigid;

        /* check to see if we are being run in sigtool or not */
        if (bcomp->lsigid[0]) {

            subsigid = cli_calloc(3, sizeof(char));
            sprintf(subsigid, "%hu", bcomp->ref_subsigid);

            /* verify the ref_subsigid */
            if (cli_ac_chklsig(subsigid, subsigid + strlen(subsigid),
                        mdata->lsigcnt[bcomp->lsigid[1]], &evalcnt, &evalids, 0) != 1) {
                bcm_dbgmsg("cli_bcomp_scanbuf: could not verify a match for lsig reference subsigid (%s)\n", subsigid);
                continue;
            }

            /* ensures the referenced subsig matches as expected, and also ensures mdata has the needed offset */
            if (( ret = lsig_sub_matched(root, mdata, lsigid, ref_subsigid, CLI_OFF_NONE, 0) )) {
                break;
            }

            /* grab the needed offset using from the last matched subsig offset matrix, i.e. the match performed above */
            if (mdata->lsigsuboff_last[lsigid]) {
                offset = mdata->lsigsuboff_last[lsigid][ref_subsigid];
            } else {
                ret = CL_SUCCESS;
                continue;
            }
        } else {
            /* can't run lsig_sub_matched in sigtool, and mdata isn't populated so run the raw matcher stuffs */
            if(res) {
                newres = (struct cli_ac_result *)cli_calloc(1, sizeof(struct cli_ac_result));
                if(!newres) {
                    cli_errmsg("cli_bcomp_scanbuf: can't allocate memory for new result\n");
                    ret = CL_EMEM;
                    break;
                }
                newres->virname = bcomp->virname;
                newres->customdata = NULL;
                newres->next = *res;
                *res = newres;
            }
        }

        /* no offset available, make a best effort */
        if (offset == CLI_OFF_NONE) {
            offset = 0;
        }

        /* now we have all the pieces of the puzzle, so lets do our byte compare check */
        ret = cli_bcomp_compare_check(buffer, buffer_length, offset, bcomp);

        /* set and append our lsig's virus name if the comparison came back positive */
        if (CL_VIRUS == ret) {
            viruses_found = 1;

            if (virname) {
                *virname = bcomp->virname;
            }
            /* if we aren't scanning all, let's just exit here */
            if (!SCAN_ALLMATCHES) {
                break;
            } else {
                ret = cli_append_virus(ctx, (const char *)bcomp->virname);
            }
        }
    }

    if (ret == CL_SUCCESS && viruses_found) {
        return CL_VIRUS;
    }
    return ret;
}

/**
 * @brief does a numerical, logical byte comparison on a particular offset given a filemapping and the offset
 *
 * @param map the file buffer we'll be accessing to do our comparison check
 * @param offset the offset of the referenced subsig match from the start of the file buffer
 * @param bm the byte comparison meta data struct, contains all the other info needed to do the comparison
 *
 */
cl_error_t cli_bcomp_compare_check(const unsigned char* f_buffer, size_t buffer_length, int offset, struct cli_bcomp_meta *bm)
{

    uint32_t byte_len = 0;
    uint32_t pad_len = 0;
    uint32_t norm_len = 0;
    uint32_t length = 0;
    uint32_t i = 0;
    cl_error_t ret = 0;
    uint16_t opt = 0;
    uint16_t opt_val = 0;
    int64_t value = 0;
    uint64_t bin_value = 0;
    int16_t compare_check = 0;
    unsigned char* end_buf = NULL;
    unsigned char* buffer = NULL;
    unsigned char* tmp_buffer = NULL;

    if (!f_buffer || !bm) {
        bcm_dbgmsg("cli_bcomp_compare_check: a param is null\n");
        return CL_ENULLARG;
    }

    byte_len = bm->byte_len;
    length = buffer_length;
    opt = bm->options;

    /* ensure we won't run off the end of the file buffer */
    if (bm->offset > 0) {
        if (!((offset + bm->offset + byte_len <= length))) {
            bcm_dbgmsg("cli_bcomp_compare_check: %u bytes requested at offset %zu would go past file buffer of %u\n", byte_len, (offset + bm->offset), length);
            return CL_CLEAN; 
        }
    } else {
        if (!(offset + bm->offset > 0)) {
            bcm_dbgmsg("cli_bcomp_compare_check: negative offset would underflow buffer\n");
            return CL_CLEAN; 
        }
    }

    /* jump to byte compare offset, then store off specified bytes into a null terminated buffer */
    offset += bm->offset;
    f_buffer += offset;

    bcm_dbgmsg("cli_bcomp_compare_check: literal extracted bytes before comparison %.*s\n", byte_len, f_buffer);

    /* normalize buffer for whitespace */

    opt_val = opt & 0x000F;
    if ( !(opt_val & CLI_BCOMP_BIN) ) {
        buffer = cli_bcomp_normalize_buffer(f_buffer, byte_len, &pad_len, opt, 1);
        if (NULL == buffer) {
            cli_errmsg("cli_bcomp_compare_check: unable to whitespace normalize temp buffer, allocation failed\n");
            return CL_EMEM;
        }

        /* adjust byte_len accordingly */
        byte_len -= pad_len;
    }

    /* normalize buffer for little endian vals */
    opt_val = opt & 0x00F0;
    if (opt_val == CLI_BCOMP_LE) {
        opt_val = opt & 0x000F;
        if ( !(opt_val & CLI_BCOMP_BIN) ) {
            tmp_buffer = cli_bcomp_normalize_buffer(buffer, byte_len, NULL, opt, 0);
            if (NULL == tmp_buffer) {
                cli_errmsg("cli_bcomp_compare_check: unable to normalize temp, allocation failed\n");
                return CL_EMEM;
            }
        }
    }

    opt_val = opt;
    if (opt_val & CLI_BCOMP_AUTO) {
        opt = cli_bcomp_chk_hex(buffer, opt_val, byte_len, 0);
    }

    /* grab the first byte to handle byte length options to convert the string appropriately */
    switch(opt & 0x00FF) {
        /*hl*/
        case CLI_BCOMP_HEX | CLI_BCOMP_LE:
            if (byte_len != 1) {
                norm_len = (byte_len % 2) == 0 ? byte_len : byte_len + 1;
            } else {
                norm_len = 1;
            }
            errno = 0;
            value = cli_strntol((char*) tmp_buffer, norm_len, (char**) &end_buf, 16);
            if ((((value == LONG_MAX) || (value == LONG_MIN)) && errno == ERANGE) || NULL == end_buf) {

                free(tmp_buffer);
                bcm_dbgmsg("cli_bcomp_compare_check: little endian hex conversion unsuccessful\n");
                return CL_CLEAN;
            }
            /*hle*/
            if (opt & CLI_BCOMP_EXACT) {
                if (tmp_buffer+byte_len != end_buf || pad_len != 0) {

                    free(tmp_buffer);
                    free(buffer);
                    bcm_dbgmsg("cli_bcomp_compare_check: couldn't extract the exact number of requested bytes\n");
                    return CL_CLEAN;
                }
            }

            break;

        /*hb*/  
        case CLI_BCOMP_HEX | CLI_BCOMP_BE:
            value = cli_strntol((char*) buffer, byte_len, (char**) &end_buf, 16);
            if ((((value == LONG_MAX) || (value == LONG_MIN)) && errno == ERANGE) || NULL == end_buf) {

                bcm_dbgmsg("cli_bcomp_compare_check: big endian hex conversion unsuccessful\n");
                return CL_CLEAN;
            }
            /*hbe*/
            if (opt & CLI_BCOMP_EXACT) {
                if (buffer+byte_len != end_buf || pad_len != 0) {

                    free(buffer);
                    bcm_dbgmsg("cli_bcomp_compare_check: couldn't extract the exact number of requested bytes\n");
                    return CL_CLEAN;
                }
            }

            break;

        /*dl*/
        case CLI_BCOMP_DEC | CLI_BCOMP_LE:
            /* it may be possible for the auto option to proc this */

            if (buffer) {
                free(buffer);
            }
            bcm_dbgmsg("cli_bcomp_compare_check: auto detection found ascii decimal for specified little endian byte extraction, which is unsupported\n");
            return CL_CLEAN;
            break;

        /*db*/
        case CLI_BCOMP_DEC | CLI_BCOMP_BE:
            value = cli_strntol((char*) buffer, byte_len, (char**) &end_buf, 10);
            if ((((value == LONG_MAX) || (value == LONG_MIN)) && errno == ERANGE) || NULL == end_buf) {

                free(buffer);
                bcm_dbgmsg("cli_bcomp_compare_check: big endian decimal conversion unsuccessful\n");
                return CL_CLEAN;
            }
            /*dbe*/
            if (opt & CLI_BCOMP_EXACT) {
                if (buffer+byte_len != end_buf || pad_len != 0) {

                    free(buffer);
                    bcm_dbgmsg("cli_bcomp_compare_check: couldn't extract the exact number of requested bytes\n");
                    return CL_CLEAN;
                }
            }

            break;

        /*il*/
        case CLI_BCOMP_BIN | CLI_BCOMP_LE:
            /* exact byte_length option is implied for binary extraction */
            switch (byte_len) {
                case 1: bin_value = (*(uint8_t*) f_buffer);                           break;
                case 2: bin_value =   (uint16_t) le16_to_host( *(uint16_t*) f_buffer); break;
                case 4: bin_value =   (uint32_t) le32_to_host( *(uint32_t*) f_buffer); break;
                case 8: bin_value =   (uint64_t) le64_to_host( *(uint64_t*) f_buffer); break;

                default:
                    bcm_dbgmsg("cli_bcomp_compare_check: invalid byte size for binary integer field (%u)\n", byte_len);
                    free(buffer);
                    return CL_EARG;
            }
            break;

        /*ib*/
        case CLI_BCOMP_BIN | CLI_BCOMP_BE:
            /* exact byte_length option is implied for binary extraction */
            switch (byte_len) {
                case 1: bin_value = ( *(uint8_t*) f_buffer);                           break;
                case 2: bin_value =    (uint16_t) be16_to_host( *(uint16_t*) f_buffer); break;
                case 4: bin_value =    (uint32_t) be32_to_host( *(uint32_t*) f_buffer); break;
                case 8: bin_value =    (uint64_t) be64_to_host( *(uint64_t*) f_buffer); break;

                default:
                    bcm_dbgmsg("cli_bcomp_compare_check: invalid byte size for binary integer field (%u)\n", byte_len);
                    free(buffer);
                    return CL_EARG;
            }
            break;

        default:
            bcm_dbgmsg("cli_bcomp_compare_check: options were found invalid\n");
            if (tmp_buffer) {
                free(tmp_buffer);
            }

            if(buffer) {
                free(buffer);
            }
            return CL_ENULLARG;
    }

    if (tmp_buffer) {
        free(tmp_buffer);
    }

    if (buffer) {
        free(buffer);
    }

    /* do the actual comparison */
    ret = CL_CLEAN;
    for (i = 0; i < bm->comp_count; i++) {
        if (bm->comps && bm->comps[i]) {
            switch (bm->comps[i]->comp_symbol) {

                case '>':
                    if (opt & CLI_BCOMP_BIN) {
                        compare_check = (bin_value > bm->comps[i]->comp_value);
                    } else {
                        compare_check = (value > bm->comps[i]->comp_value);
                    }
                    if (compare_check) {
                        bcm_dbgmsg("cli_bcomp_compare_check: extracted value (%ld) greater than comparison value (%ld)\n", (opt & CLI_BCOMP_BIN) ? bin_value : value, bm->comps[i]->comp_value);
                        ret = CL_VIRUS;
                    } else {
                        ret = CL_CLEAN;
                    }
                    break;

                case '<':
                    if (opt & CLI_BCOMP_BIN) {
                        compare_check = (bin_value < bm->comps[i]->comp_value);
                    } else {
                        compare_check = (value < bm->comps[i]->comp_value);
                    }
                    if (compare_check) {
                        bcm_dbgmsg("cli_bcomp_compare_check: extracted value (%ld) less than comparison value (%ld)\n", (opt & CLI_BCOMP_BIN) ? bin_value : value, bm->comps[i]->comp_value);
                        ret = CL_VIRUS;
                    } else {
                        ret = CL_CLEAN;
                    }
                    break;

                case '=':
                    if (opt & CLI_BCOMP_BIN) {
                        compare_check = (bin_value == bm->comps[i]->comp_value);
                    } else {
                        compare_check = (value == bm->comps[i]->comp_value);
                    }
                    if (compare_check) {
                        bcm_dbgmsg("cli_bcomp_compare_check: extracted value (%ld) equal to comparison value (%ld)\n", (opt & CLI_BCOMP_BIN) ? bin_value : value, bm->comps[i]->comp_value);
                        ret = CL_VIRUS;
                    } else {
                        ret = CL_CLEAN;
                    }
                    break;

                default:
                    bcm_dbgmsg("cli_bcomp_compare_check: comparison symbol (%c) invalid\n", bm->comps[i]->comp_symbol);
                    return CL_ENULLARG;
            }

            if (CL_CLEAN == ret) {
                /* comparison was not successful */
                bcm_dbgmsg("cli_bcomp_compare_check: extracted value (%ld) was not %c %ld\n", (opt & CLI_BCOMP_BIN) ? bin_value : value, bm->comps[i]->comp_symbol, bm->comps[i]->comp_value);
                return CL_CLEAN;
            }
        }
    }

    return ret;
}

/**
 * @brief checks to see if an ascii buffer should be considered hex or not
 *
 * @param buffer is the buffer to evaluate
 * @param opts the bcomp opts bitfield to set/evaluate during the check
 * @param len the length of the buffer, must be larger than 3 bytes
 * @param check_only specifies whether to return true/false or the modified opt value
 *
 * @return if check only is set, it will return true or false, otherwise it returns a modifiied byte compare bitfield
 */
uint16_t cli_bcomp_chk_hex(const unsigned char* buffer, uint16_t opt, uint32_t len, uint32_t check_only) {

    uint16_t check = 0;

    if (!buffer || len < 3) {
        if (buffer && len < 3) {
            if ((opt & 0x00F0) & CLI_BCOMP_AUTO) {
                opt |= CLI_BCOMP_DEC;
                opt ^= CLI_BCOMP_AUTO;
            }
        }
        return check_only ? check : opt;
    }

    if(!strncmp((char*) buffer, "0x", 2) || !strncmp((char*) buffer, "0X", 2)) {
        opt |= CLI_BCOMP_HEX;
        check = 1;
    } else {
        opt |= CLI_BCOMP_DEC;
        check = 0;
    }
    opt ^= CLI_BCOMP_AUTO;

    return check_only ? check : opt;
}

/**
 * @brief multipurpose buffer normalization support function for bytcompare
 *
 * Currently can be used to normalize a little endian hex buffer to big endian.
 * Can also be used to trim whitespace from the front of the buffer.
 *
 * @param buffer is the ascii bytes which are to be normalized
 * @param byte_len is the length of these bytes
 * @param pad_len if the address passed is non-null function will store the amount of whitespace found in bytes
 * @param opt the byte compare option bitfield
 * @param whitespace_only if true will only do whitespace normalization, will not perform whitespace
 * normalization if set to no
 *
 * @return returns an allocated, normalized buffer or NULL if an allocation error has occurred
 */
unsigned char* cli_bcomp_normalize_buffer(const unsigned char* buffer, uint32_t byte_len, uint32_t *pad_len,  uint16_t opt, uint16_t whitespace_only) {
    uint32_t norm_len = 0;
    uint32_t pad = 0;
    uint32_t i = 0;
    uint16_t opt_val = 0;
    uint16_t hex = 0;
    unsigned char* tmp_buffer = NULL;
    unsigned char* hex_buffer = NULL;

    if (!buffer) {
        cli_errmsg("cli_bcomp_compare_check: unable to normalize temp buffer, params null\n");
        return NULL;
    }

    if (whitespace_only) {
        for(i = 0; i < byte_len; i++) {
            if (isspace(buffer[i])) {
                bcm_dbgmsg("cli_bcomp_compare_check: buffer has whitespace \n");
                pad++;
            } else {
                /* break on first non-padding whitespace */
                break;
            }
        }
        /* keep in mind byte_len is a stack variable so this won't change byte_len in our calling functioning */
        byte_len = byte_len - pad;
        tmp_buffer = cli_calloc(byte_len+1, sizeof(char));
        if (NULL == tmp_buffer) {
            cli_errmsg("cli_bcomp_compare_check: unable to allocate memory for whitespace normalized temp buffer\n");
            return NULL;
        }
        memset(tmp_buffer, '0', byte_len+1);
        memcpy(tmp_buffer, buffer+pad, byte_len);
        tmp_buffer[byte_len] = '\0';
        if (pad_len) {
            *pad_len = pad;
        }
        return tmp_buffer;
    }

    opt_val = opt & 0x000F;
    if (opt_val & CLI_BCOMP_HEX || opt_val & CLI_BCOMP_AUTO) {
        norm_len = (byte_len % 2) == 0 ? byte_len : byte_len + 1;
        tmp_buffer = cli_calloc(norm_len+1, sizeof(char));
        if (NULL == tmp_buffer) {
            cli_errmsg("cli_bcomp_compare_check: unable to allocate memory for normalized temp buffer\n");
            return NULL;
        }

        hex_buffer = cli_calloc(norm_len+1, sizeof(char));
        if(NULL == hex_buffer) {
            free(tmp_buffer);
            cli_errmsg("cli_bcomp_compare_check: unable to reallocate memory for hex buffer\n");
            return NULL;
        }

        memset(tmp_buffer, '0', norm_len+1);
        memset(hex_buffer, '0', norm_len+1);

        if (byte_len == 1) {
            tmp_buffer[0] = buffer[0];
        } else {

            if (norm_len == byte_len + 1) {
                opt_val = opt;
                if (cli_bcomp_chk_hex(buffer, opt_val, byte_len, 1)) {
                    memcpy(hex_buffer+3, buffer+2, byte_len-2);
                    hex_buffer[0] = 'x';
                } else {
                    memcpy(hex_buffer+1, buffer, byte_len);
                }
            } else {
                opt_val = opt;
                memcpy(hex_buffer, buffer, byte_len);
                if (cli_bcomp_chk_hex(buffer, opt_val, byte_len, 1)) {
                    hex_buffer[0] = 'x';
                }
            }

            for (i = 0; i < norm_len; i = i+2) {
                if (((int32_t) norm_len - (int32_t) i) - 2 >= 0) {
                    /* 0000BA -> B0000A */
                    if ( isxdigit(hex_buffer[norm_len-i-2]) || toupper(hex_buffer[norm_len-i-2]) == 'X' ) {
                        if ( isxdigit(hex_buffer[norm_len-i-2]) ) {
                            hex = 1;
                        }
                        tmp_buffer[i] = hex_buffer[norm_len-i-2];
                    } else {
                        /* non-hex detected, our current buffer is invalid so zero it out and continue */
                        memset(tmp_buffer, '0', norm_len+1);
                        hex = 0;
                        /* nibbles after this are non-good, so skip them */
                        continue;
                    }
                }

                /* 0000BA -> 0A00B0 */
                if ( isxdigit(hex_buffer[norm_len-i-1]) || toupper(hex_buffer[norm_len-i-1]) == 'X' ) {
                        if ( isxdigit(hex_buffer[norm_len-i-2]) ) {
                            hex = 1;
                        }
                        tmp_buffer[i+1] = hex_buffer[norm_len-i-1];
                } else {
                    /* non-hex detected, our current buffer is invalid so zero it out and continue */
                    memset(tmp_buffer, '0', norm_len+1);
                    hex = 0;
                }
            }
        }
        tmp_buffer[norm_len+1] = '\0';
        bcm_dbgmsg("cli_bcomp_compare_check: normalized extracted bytes before comparison %.*s\n", norm_len, tmp_buffer);
    }

    return tmp_buffer;
}

/**
 * @brief cleans up the byte compare data struct
 *
 * @param root the root matcher struct whose mempool instance the bcomp struct has been allocated with
 * @param bm the bcomp struct to be freed
 *
 */
void cli_bcomp_freemeta(struct cli_matcher *root, struct cli_bcomp_meta *bm) {

    int i = 0;

    if(!root || !bm) {
        return;
    }
    
    if (bm->virname) {
        mpool_free(root->mempool, bm->virname);
        bm->virname = NULL;
    }

    /* can never have more than 2 */
    if (bm->comps) {
        for (i = 0; i < 2; i++) {
            if (bm->comps[i]) {
                mpool_free(root->mempool, bm->comps[i]);
                bm->comps[i] = NULL;
            }
        }

        mpool_free(root->mempool, bm->comps);
        bm->comps = NULL;
    }

    mpool_free(root->mempool, bm);
    bm = NULL;

    return;
}
