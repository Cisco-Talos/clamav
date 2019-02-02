/*
 * Copyright (c) 1988-1997 Sam Leffler
 * Copyright (c) 1991-1997 Silicon Graphics, Inc.
 *
 * Permission to use, copy, modify, distribute, and sell this software and
 * its documentation for any purpose is hereby granted without fee, provided
 * that (i) the above copyright notices and this permission notice appear in
 * all copies of the software and related documentation, and (ii) the names of
 * Sam Leffler and Silicon Graphics may not be used in any advertising or
 * publicity relating to the software without the specific, prior written
 * permission of Sam Leffler and Silicon Graphics.
 *
 * THE SOFTWARE IS PROVIDED "AS-IS" AND WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS, IMPLIED OR OTHERWISE, INCLUDING WITHOUT LIMITATION, ANY
 * WARRANTY OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.
 *
 * IN NO EVENT SHALL SAM LEFFLER OR SILICON GRAPHICS BE LIABLE FOR
 * ANY SPECIAL, INCIDENTAL, INDIRECT OR CONSEQUENTIAL DAMAGES OF ANY KIND,
 * OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
 * WHETHER OR NOT ADVISED OF THE POSSIBILITY OF DAMAGE, AND ON ANY THEORY OF
 * LIABILITY, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
 * OF THIS SOFTWARE.
 */
/*
 *  Portions Copyright (C) 2016 Cisco and/or its affiliates. All rights reserved.
 *
 *  Modified by: Kevin Lin
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
 *
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations
 *  including the two.
 *  
 *  You must obey the GNU General Public License in all respects
 *  for all of the code used other than OpenSSL.  If you modify
 *  file(s) with this exception, you may extend this exception to your
 *  version of the file(s), but you are not obligated to do so.  If you
 *  do not wish to do so, delete this exception statement from your
 *  version.  If you delete this exception statement from all source
 *  files in the program, then also delete it here.
 */
#include <stdio.h>

#include <assert.h>
#include <stdint.h>
#include "lzwdec.h"
#include "../others.h"

#define MAXCODE(n)  ((1L<<(n))-1)
/*
 * The spec specifies that encoded bit
 * strings SHOULD range from 9 to 12 bits.
 */
#define BITS_MIN    9       /* start with 9 bits */
#define BITS_VALID  12      /* 12 bit codes are the max valid */
#define BITS_MAX    14      /* max of 14 bit codes (2 bits extension) */
/* predefined codes */
#define CODE_BASIC  256     /* last basic code + 1 */
#define CODE_CLEAR  256     /* code to clear string table */
#define CODE_EOI    257     /* end-of-information code */
#define CODE_FIRST  258     /* first free code entry */
#define CODE_VALID  MAXCODE(BITS_VALID)
#define CODE_MAX    MAXCODE(BITS_MAX)

#define CSIZE       (MAXCODE(BITS_MAX)+1L)

typedef uint16_t hcode_t;     /* codes fit in 16 bits */

/*
 * Decoding-specific state.
 */
typedef struct code_ent {
    struct code_ent *next;
    uint16_t length;         /* string len, including this token */
    uint8_t  value;          /* data value */
    uint8_t  firstchar;      /* first token of string */
} code_t;

struct lzw_internal_state {
    /* general state */
    uint16_t    nbits;      /* # of bits/code */
    unsigned long nextdata; /* next bits of i/o */
    long        nextbits;   /* # of valid bits in lzw_nextdata */

    /* decoding-specific state */
    long    dec_nbitsmask;  /* lzw_nbits 1 bits, right adjusted */
    long    dec_restart;    /* restart count */
    code_t *dec_codep;      /* current recognized code */
    code_t *dec_oldcodep;   /* previously recognized code */
    code_t *dec_free_entp;  /* next free entry */
    code_t *dec_maxcodep;   /* max available entry */
    code_t *dec_codetab;    /* kept separate for small machines */
};

static void code_print(code_t *code);
static void dict_print(code_t *codetab, uint16_t start, uint16_t maxcode);

#define GetNextCode(code) {                                           \
    if (have == 0)                                                    \
        break;                                                        \
    nextdata = nextdata << 8 | *(from)++;                             \
    have--;                                                           \
    nextbits += 8;                                                    \
    if (nextbits < nbits) {                                           \
        if (have == 0)                                                \
break;                                                    \
        nextdata = nextdata << 8 | *(from)++;                         \
        have--;                                                       \
        nextbits += 8;                                                \
    }                                                                 \
    code = (hcode_t)((nextdata >> (nextbits-nbits)) & nbitsmask);     \
    nextbits -= nbits;                                                \
}

#define CodeClear(code) {                                               \
    free_code = CODE_FIRST;                                             \
    free_entp = state->dec_codetab + CODE_FIRST;                        \
    nbits = BITS_MIN;                                                   \
    nbitsmask = MAXCODE(BITS_MIN);                                      \
    maxcodep = state->dec_codetab + nbitsmask-1;                        \
    while (code == CODE_CLEAR) /* clears out consecutive CODE_CLEARs */ \
        GetNextCode(code);                                              \
    if (code < CODE_BASIC)                                              \
        *to++ = code, left--;                                           \
    else if (code == CODE_EOI)                                          \
        ret = LZW_STREAM_END;                                           \
    else if (code >= CODE_FIRST) {                                      \
        /* cannot reference unpopulated dictionary entries */           \
        strm->msg = "cannot reference unpopulated dictionary entries";  \
        ret = LZW_DATA_ERROR;                                           \
    }                                                                   \
    oldcodep = state->dec_codetab + code;                               \
}

int lzwInit(lzw_streamp strm)
{
    struct lzw_internal_state *state;
    hcode_t code;

    state = cli_malloc(sizeof(struct lzw_internal_state));
    if (state == NULL) {
        strm->msg = "failed to allocate state";
        return LZW_MEM_ERROR;
    }

    /* general state setup */
    state->nbits = BITS_MIN;
    state->nextdata = 0;
    state->nextbits = 0;

    /* dictionary setup */
    state->dec_codetab = cli_calloc(CSIZE, sizeof(code_t));
    if (state->dec_codetab == NULL) {
        free(state);
        strm->msg = "failed to allocate code table";
        return LZW_MEM_ERROR;
    }

    for (code = 0; code < CODE_BASIC; code++) {
        state->dec_codetab[code].next = NULL;
        state->dec_codetab[code].length = 1;
        state->dec_codetab[code].value = code;
        state->dec_codetab[code].firstchar = code;
    }

    state->dec_restart = 0;
    state->dec_nbitsmask = MAXCODE(BITS_MIN);
    state->dec_free_entp = state->dec_codetab + CODE_FIRST;
    state->dec_oldcodep = &state->dec_codetab[CODE_CLEAR];
    state->dec_maxcodep = &state->dec_codetab[state->dec_nbitsmask-1];

    strm->state = state;
    return LZW_OK;
}

int lzwInflate(lzw_streamp strm)
{
    struct lzw_internal_state *state;
    uint8_t *from, *to;
    unsigned in, out;
    unsigned have, left;
    long nbits, nextbits, nbitsmask;
    unsigned long nextdata;
    code_t *codep, *free_entp, *maxcodep, *oldcodep;

    uint8_t *wp;
    hcode_t code, free_code;
    int echg, cext, ret = LZW_OK;
    uint32_t flags;

    if (strm == NULL || strm->state == NULL || strm->next_out == NULL ||
        (strm->next_in == NULL && strm->avail_in != 0))
        return LZW_STREAM_ERROR;

    /* load state */
    to = strm->next_out;
    out = left = strm->avail_out;

    from = strm->next_in;
    in = have = strm->avail_in;

    flags = strm->flags;
    state = strm->state;

    nbits = state->nbits;
    nextdata = state->nextdata;
    nextbits = state->nextbits;
    nbitsmask = state->dec_nbitsmask;
    oldcodep = state->dec_oldcodep;
    free_entp = state->dec_free_entp;
    maxcodep = state->dec_maxcodep;

    echg = flags & LZW_FLAG_EARLYCHG;
    cext = flags & LZW_FLAG_EXTNCODE;
    free_code = free_entp - &state->dec_codetab[0];

    if (oldcodep == &state->dec_codetab[CODE_EOI])
        return LZW_STREAM_END;

    /*
     * Restart interrupted output operation.
     */
    if (state->dec_restart) {
        long residue;

        codep = state->dec_codep;
        residue = codep->length - state->dec_restart;
        if (residue > left) {
            /*
             * Residue from previous decode is sufficient
             * to satisfy decode request.  Skip to the
             * start of the decoded string, place decoded
             * values in the output buffer, and return.
             */
            state->dec_restart += left;
            do {
                codep = codep->next;
            } while (--residue > left);
            to = wp = to + left;
            do {
                *--wp = codep->value;
                codep = codep->next;
            } while (--left);
            goto inf_end;
        }
        /*
         * Residue satisfies only part of the decode request.
         */
        to += residue, left -= residue;
        wp = to;
        do {
            *--wp = codep->value;
            codep = codep->next;
        } while (--residue);
        state->dec_restart = 0;
    }

    /* guarantee valid initial state */
    if (left > 0 && (oldcodep == &state->dec_codetab[CODE_CLEAR])) {
        code = CODE_CLEAR;
        CodeClear(code);
        if (ret != LZW_OK)
            goto inf_end;
    }

    while (left > 0) {
        GetNextCode(code);
        if (code == CODE_EOI) {
            ret = LZW_STREAM_END;
            break;
        }
        if (code == CODE_CLEAR) {
            CodeClear(code);
            if (ret != LZW_OK)
                break;
            continue;
        }
        codep = state->dec_codetab + code;

        /* cap dictionary codes to valid range (12-bits) */
        if (free_code < CODE_VALID+1 || cext) {
            /* non-earlychange bit expansion */
            if (!echg && free_entp > maxcodep) {
                if (++nbits > BITS_VALID) {
                    if (!cext)
                        nbits = BITS_VALID;
                    else if (nbits > BITS_MAX)
                        nbits = BITS_MAX;
                }
                nbitsmask = MAXCODE(nbits);
                maxcodep = state->dec_codetab + nbitsmask-1;
            }
            /*
             * Add the new entry to the code table.
             */
            if (&state->dec_codetab[0] > free_entp || free_entp >= &state->dec_codetab[CSIZE]) {
                cli_dbgmsg("%p <= %p, %p < %p(%ld)\n", &state->dec_codetab[0], free_entp, free_entp, &state->dec_codetab[CSIZE], CSIZE);
                strm->msg = "full dictionary, cannot add new entry";
                flags |= LZW_FLAG_FULLDICT;
                ret = LZW_DICT_ERROR;
                break;
            }
            free_entp->next = oldcodep;
            free_entp->firstchar = free_entp->next->firstchar;
            free_entp->length = free_entp->next->length+1;
            free_entp->value = (codep < free_entp) ?
                codep->firstchar : free_entp->firstchar;
            free_entp++;
            /* earlychange bit expansion */
            if (echg && free_entp > maxcodep) {
                if (++nbits > BITS_VALID) {
                    if (!cext)
                        nbits = BITS_VALID;
                    else if (nbits > BITS_MAX)
                        nbits = BITS_MAX;
                }
                nbitsmask = MAXCODE(nbits);
                maxcodep = state->dec_codetab + nbitsmask-1;
            }
            if (free_code++ > CODE_VALID)
                flags |= LZW_FLAG_EXTNCODEUSE;
            oldcodep = codep;
        } else
            flags |= LZW_FLAG_FULLDICT;
        if (code >= CODE_BASIC) {
            /* check if code is valid */
            if (code >= free_code) {
                strm->msg = "cannot reference unpopulated dictionary entries";
                flags |= LZW_FLAG_INVALIDCODE;
                ret = LZW_DATA_ERROR;
                break;
            }

            /*
             * Code maps to a string, copy string
             * value to output (written in reverse).
             */
            if (codep->length > left) {
                /*
                 * String is too long for decode buffer,
                 * locate portion that will fit, copy to
                 * the decode buffer, and setup restart
                 * logic for the next decoding call.
                 */
                state->dec_codep = codep;
                do {
                    codep = codep->next;
                } while (codep->length > left);
                state->dec_restart = left;
                to = wp = to + left;
                do  {
                    *--wp = codep->value;
                    codep = codep->next;
                }  while (--left);
                goto inf_end;
            }

            to += codep->length, left -= codep->length;
            wp = to;
            do {
                *--wp = codep->value;
                codep = codep->next;
            } while(codep != NULL);
        } else
            *to++ = code, left--;
    }

inf_end:
    /* restore state */
    strm->next_out = to;
    strm->avail_out = left;
    strm->next_in = from;
    strm->avail_in = have;
    strm->flags = flags;

    state->nbits = (uint16_t)nbits;
    state->nextdata = nextdata;
    state->nextbits = nextbits;
    state->dec_nbitsmask = nbitsmask;
    state->dec_oldcodep = oldcodep;
    state->dec_free_entp = free_entp;
    state->dec_maxcodep = maxcodep;

    /* update state */
    in -= strm->avail_in;
    out -= strm->avail_out;
    strm->total_in += in;
    strm->total_out += out;

    if ((in == 0 && out == 0) && ret == LZW_OK) {
        strm->msg = "no data was processed";
        ret = LZW_BUF_ERROR;
    }
    return ret;
}

int lzwInflateEnd(lzw_streamp strm)
{
    free(strm->state->dec_codetab);
    free(strm->state);
    strm->state = NULL;
    return LZW_OK;
}

static void code_print(code_t *code)
{
    code_t *cpt = code;
    uint8_t *string;
    int i = 0;

    string = cli_calloc(code->length+1, sizeof(uint8_t));
    if (!string)
        return;

    while (cpt && (i < code->length)) {
        if (isalnum(cpt->value))
            string[code->length - i - 1] = cpt->value;
        else
            string[code->length - i - 1] = '*';

        i++;
        cpt = cpt->next;
    }

    printf("%s\n", string);
    free(string);
}

static void dict_print(code_t *codetab, uint16_t start, uint16_t maxcode)
{
    int i;

    for (i = start; i < maxcode; i++) {
        printf("%d: ", i);
        code_print(codetab + i);
    }
}
