/*
 *  Byte comparison matcher support functions
 *
 *  Copyright (C) 2018 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  All Rights Reserved.
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
#include "cltypes.h"
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
        if (buf_end = strchr(buf_start, ')')) {
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
                /* hex, decimal, and binary options are mutually exclusive parameters */
                if (bcomp->options & CLI_BCOMP_DEC || bcomp->options & CLI_BCOMP_BIN) {
                    ret = CL_EMALFDB;
                } else {
                    bcomp->options |= CLI_BCOMP_HEX;
                } break;
            case 'd':
                /* hex, decimal, and binary options are mutually exclusive parameters */
                if (bcomp->options & CLI_BCOMP_HEX || bcomp->options & CLI_BCOMP_BIN) {
                    ret = CL_EMALFDB;
                } else {
                    bcomp->options |= CLI_BCOMP_DEC;
                } break;
            case 'i':
                /* hex, decimal, and binary options are mutually exclusive parameters */
                if (bcomp->options & CLI_BCOMP_HEX || bcomp->options & CLI_BCOMP_DEC) {
                    ret = CL_EMALFDB;
                } else {
                    bcomp->options |= CLI_BCOMP_BIN;
                } break;
            case 'l':
                /* little and big endian options are mutually exclusive parameters */
                if (bcomp->options & CLI_BCOMP_BE) {
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

    bcomp->byte_len = byte_length;

    /* currently only >, <, and = are supported comparison symbols--this makes parsing very simple */
    buf_start = tokens[2];
    switch (*buf_start) {
        case '<':
        case '>':
        case '=':
            bcomp->comp_symbol = *buf_start;    break;

        default:
            cli_errmsg("cli_bcomp_addpatt: while parsing (%s#%s#%s), byte comparison symbol was invalid (>, <, = are supported operators)\n", tokens[0], tokens[1], tokens[2]);
            free(buf);
            cli_bcomp_freemeta(root, bcomp);
            return CL_EMALFDB;
    }


    /* no more tokens after this, so we take advantage of strtoll and check if the buf_end is null terminated or not */
    buf_start++;
    buf_end = NULL;
    comp_val = strtoll(buf_start, (char **) &buf_end, 0);
    if (*buf_end) {
        cli_errmsg("cli_bcomp_addpatt: while parsing (%s#%s#%s), comparison value contained invalid input\n", tokens[0], tokens[1], tokens[2]);
        free(buf);
        cli_bcomp_freemeta(root, bcomp);
        return CL_EMALFDB;
    }

    bcomp->comp_value = comp_val;

    /* manually verify successful pattern parsing */
    bcm_dbgmsg("Matcher Byte Compare: (%s%ld#%c%c%s%zu#%c%ld)\n",
                    bcomp->offset ==  0 ? "" : 
                    (bcomp->offset < 0 ? "<<" : ">>"),
                    bcomp->offset,
                    bcomp->options & CLI_BCOMP_HEX ? 'h' : (bcomp->options & CLI_BCOMP_DEC ? 'd' : 'i'),
                    bcomp->options & CLI_BCOMP_LE ? 'l' : 'b',
                    bcomp->options & CLI_BCOMP_EXACT ? "e" : "",
                    bcomp->byte_len,
                    bcomp->comp_symbol,
                    bcomp->comp_value);

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
cl_error_t cli_bcomp_scanbuf(fmap_t *map, const char **virname, struct cli_ac_result **res, const struct cli_matcher *root, struct cli_ac_data *mdata, cli_ctx *ctx) {

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
            if (ret = lsig_sub_matched(root, mdata, lsigid, ref_subsigid, CLI_OFF_NONE, 0)) {
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
        ret = cli_bcomp_compare_check(map, offset, bcomp);

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
cl_error_t cli_bcomp_compare_check(fmap_t *map, int offset, struct cli_bcomp_meta *bm)
{

    uint32_t byte_len = 0;
    uint32_t length = 0;
    uint16_t opt = 0;
    const unsigned char *buffer = NULL;
    unsigned char *conversion_buf = NULL;
    int64_t value = 0;
    const unsigned char* end_buf = NULL;

    if (!map || !bm) {
        bcm_dbgmsg("cli_bcomp_compare_check: a param is null\n");
        return CL_ENULLARG;
    }

    byte_len = bm->byte_len;
    length = map->len;
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
    buffer = fmap_need_off_once(map, offset, byte_len);
    if (!buffer) {
        bcm_dbgmsg("cli_bcomp_compare_check: could not extract bytes from buffer offset\n");
        return CL_EMEM;
    }
    bcm_dbgmsg("cli_bcomp_compare_check: literal extracted bytes before comparison %s\n", buffer);

    /* grab the first byte to handle byte length options to convert the string appropriately */
    switch((opt & 0x00FF)) {
        /*hl*/
        case CLI_BCOMP_HEX | CLI_BCOMP_LE:
            errno = 0;
            value = cli_strntol((char*) buffer, byte_len, (char**) &end_buf, 16);
            if ((((value == LONG_MAX) || (value == LONG_MIN)) && errno == ERANGE) || NULL == end_buf) {

                bcm_dbgmsg("cli_bcomp_compare_check: little endian hex conversion unsuccessful\n");
                return CL_CLEAN;
            }
            /*hle*/
            if (opt & CLI_BCOMP_EXACT) {
                if (buffer+byte_len != end_buf) {

                    bcm_dbgmsg("cli_bcomp_compare_check: couldn't extract the exact number of requested bytes\n");
                    return CL_CLEAN;
                }
            }

            value = le64_to_host(value);
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
                if (buffer+byte_len != end_buf) {

                    bcm_dbgmsg("cli_bcomp_compare_check: couldn't extract the exact number of requested bytes\n");
                    return CL_CLEAN;
                }
            }

            value = be64_to_host(value);
            break;

        /*dl*/
        case CLI_BCOMP_DEC | CLI_BCOMP_LE:
            value = cli_strntol((char*) buffer, byte_len, (char**) &end_buf, 10);
            if ((((value == LONG_MAX) || (value == LONG_MIN)) && errno == ERANGE) || NULL == end_buf) {

                bcm_dbgmsg("cli_bcomp_compare_check: little endian decimal conversion unsuccessful\n");
                return CL_CLEAN;
            }
            /*dle*/
            if (opt & CLI_BCOMP_EXACT) {
                if (buffer+byte_len != end_buf) {

                    bcm_dbgmsg("cli_bcomp_compare_check: couldn't extract the exact number of requested bytes\n");
                    return CL_CLEAN;
                }
            }

            value = le64_to_host(value);
            break;

        /*db*/
        case CLI_BCOMP_DEC | CLI_BCOMP_BE:
            value = cli_strntol((char*) buffer, byte_len, (char**) &end_buf, 10);
            if ((((value == LONG_MAX) || (value == LONG_MIN)) && errno == ERANGE) || NULL == end_buf) {

                bcm_dbgmsg("cli_bcomp_compare_check: big endian decimal conversion unsuccessful\n");
                return CL_CLEAN;
            }
            /*dbe*/
            if (opt & CLI_BCOMP_EXACT) {
                if (buffer+byte_len != end_buf) {

                    bcm_dbgmsg("cli_bcomp_compare_check: couldn't extract the exact number of requested bytes\n");
                    return CL_CLEAN;
                }
            }

            value = be64_to_host(value);
            break;

        /*il*/
        case CLI_BCOMP_BIN | CLI_BCOMP_LE:
            /* exact byte_length option is implied for binary extraction */
            switch (byte_len) {
                case 1: value = (*(int8_t*) buffer);                           break;
                case 2: value =   (int16_t) le16_to_host( *(int16_t*) buffer); break;
                case 4: value =   (int32_t) le32_to_host( *(int32_t*) buffer); break;
                case 8: value =   (int64_t) le64_to_host( *(int64_t*) buffer); break;

                default:
                    bcm_dbgmsg("cli_bcomp_compare_check: invalid byte size for binary integer field (%u)\n", byte_len);
                    return CL_EARG;
            }
            break;

        /*ib*/
        case CLI_BCOMP_BIN | CLI_BCOMP_BE:
            /* exact byte_length option is implied for binary extraction */
            switch (byte_len) {
                case 1: value = ( *(int8_t*) buffer);                           break;
                case 2: value =    (int16_t) be16_to_host( *(int16_t*) buffer); break;
                case 4: value =    (int32_t) be32_to_host( *(int32_t*) buffer); break;
                case 8: value =    (int64_t) be64_to_host( *(int64_t*) buffer); break;

                default:
                    bcm_dbgmsg("cli_bcomp_compare_check: invalid byte size for binary integer field (%u)\n", byte_len);
                    return CL_EARG;
            }
            break;

        default:
            return CL_ENULLARG;
    }

    /* do the actual comparison */
    switch (bm->comp_symbol) {

        case '>':
            if (value > bm->comp_value) {
                bcm_dbgmsg("cli_bcomp_compare_check: extracted value (%ld) greater than comparison value (%ld)\n", value, bm->comp_value);
                return CL_VIRUS;
            }
            break;

        case '<':
            if (value < bm->comp_value) {
                bcm_dbgmsg("cli_bcomp_compare_check: extracted value (%ld) less than comparison value (%ld)\n", value, bm->comp_value);
                return CL_VIRUS;
            }
            break;

        case '=':
            if (value == bm->comp_value) {
                bcm_dbgmsg("cli_bcomp_compare_check: extracted value (%ld) equal to comparison value (%ld)\n", value, bm->comp_value);
                return CL_VIRUS;
            }
            break;

        default:
            bcm_dbgmsg("cli_bcomp_compare_check: comparison symbol (%c) invalid\n", bm->comp_symbol);
            return CL_ENULLARG;
    }

    /* comparison was not successful */
    bcm_dbgmsg("cli_bcomp_compare_check: extracted value was not %c %ld\n", bm->comp_symbol, bm->comp_value);
    return CL_CLEAN;
}

/**
 * @brief cleans up the byte compare data struct
 *
 * @param root the root matcher struct whose mempool instance the bcomp struct has been allocated with
 * @param bm the bcomp struct to be freed
 *
 */
void cli_bcomp_freemeta(struct cli_matcher *root, struct cli_bcomp_meta *bm) {

    if(!root || !bm) {
        return;
    }
    
    if (bm->virname) {
        mpool_free(root->mempool, bm->virname);
        bm->virname = NULL;
    }
    
    mpool_free(root->mempool, bm);
    bm = NULL;

    return;
}
