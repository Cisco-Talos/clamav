/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2013 Sourcefire, Inc.
 *
 *  Authors: David Raynor <draynor@sourcefire.com>
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

#include <stdio.h>
#include <errno.h>
#if HAVE_STRING_H
#include <string.h>
#endif

#include "clamav.h"
#include "others.h"
#include "adc.h"

/* #define DEBUG_ADC */

#ifdef DEBUG_ADC
#  define adc_dbgmsg(...) cli_dbgmsg( __VA_ARGS__ )
#else
#  define adc_dbgmsg(...) ;
#endif

/* Initialize values and collect buffer
 * NOTE: buffer size must be larger than largest lookback offset */
int adc_decompressInit(adc_stream *strm)
{
    if (strm == NULL) {
        return ADC_IO_ERROR;
    }
    if (strm->state != ADC_STATE_UNINIT) {
        return ADC_DATA_ERROR;
    }

    /* Have to buffer maximum backward lookup */
    strm->buffer = (uint8_t *)calloc(ADC_BUFF_SIZE, 1);
    if (strm->buffer == NULL) {
        return ADC_MEM_ERROR;
    }
    strm->buffered = 0;
    strm->state = ADC_STATE_GETTYPE;
    strm->length = 0;
    strm->offset = 0;
    strm->curr = strm->buffer;

    return ADC_OK;
}

/* Decompress routine
 * NOTE: Reaching end of input buffer does not mean end of output.
 * It may fill the output buffer but have more to output.
 * It will only return ADC_STREAM_END if output buffer is not full.
 * It will return ADC_DATA_ERROR if it ends in the middle of a phrase
 * (i.e. in the middle of a lookback code or data run)
 */
int adc_decompress(adc_stream *strm)
{
    uint8_t bData;
    uint8_t didNothing = 1;

    /* first, the error returns based on strm */
    if ((strm == NULL) || (strm->next_in == NULL) || (strm->next_out == NULL)) {
        return ADC_IO_ERROR;
    }
    if (strm->state == ADC_STATE_UNINIT) {
        return ADC_DATA_ERROR;
    }

    cli_dbgmsg("adc_decompress: avail_in %llu avail_out %llu state %u\n",
               (long long unsigned)strm->avail_in, (long long unsigned)strm->avail_out, strm->state);

    while (strm->avail_out) {
        /* Exit if needs more in bytes and none available */
        int needsInput;
        switch (strm->state) {
           case ADC_STATE_SHORTLOOK:
           case ADC_STATE_LONGLOOK:
               needsInput = 0;
               break;
           default:
               needsInput = 1;
               break;
        }
        if (needsInput && (strm->avail_in == 0)) {
            break;
        }
        else {
            didNothing = 0;
        }

        /* Find or execute statecode */
        switch (strm->state) {
            case ADC_STATE_GETTYPE: {
                /* Grab action code */
                bData = *(strm->next_in);
                strm->next_in++;
                strm->avail_in--;
                if (bData & 0x80) {
                    strm->state = ADC_STATE_RAWDATA;
                    strm->offset = 0;
                    strm->length = (bData & 0x7F) + 1;
                }
                else if (bData & 0x40) {
                    strm->state = ADC_STATE_LONGOP2;
                    strm->offset = 0;
                    strm->length = (bData & 0x3F) + 4;
                }
                else {
                    strm->state = ADC_STATE_SHORTOP;
                    strm->offset = (bData & 0x3) * 0x100;
                    strm->length = ((bData & 0x3C) >> 2) + 3;
                }
                adc_dbgmsg("adc_decompress: GETTYPE bData %x state %u offset %u length %u\n",
                           bData, strm->state, strm->offset, strm->length);
                break;
           }
           case ADC_STATE_LONGOP2: {
                /* Grab first offset byte */
                bData = *(strm->next_in);
                strm->next_in++;
                strm->avail_in--;
                strm->offset = bData * 0x100;
                strm->state = ADC_STATE_LONGOP1;
                adc_dbgmsg("adc_decompress: LONGOP2 bData %x state %u offset %u length %u\n",
                           bData, strm->state, strm->offset, strm->length);
                break;
           }
           case ADC_STATE_LONGOP1: {
                /* Grab second offset byte */
                bData = *(strm->next_in);
                strm->next_in++;
                strm->avail_in--;
                strm->offset += bData + 1;
                strm->state = ADC_STATE_LONGLOOK;
                adc_dbgmsg("adc_decompress: LONGOP1 bData %x state %u offset %u length %u\n",
                           bData, strm->state, strm->offset, strm->length);
                break;
           }
           case ADC_STATE_SHORTOP: {
                /* Grab offset byte */
                bData = *(strm->next_in);
                strm->next_in++;
                strm->avail_in--;
                strm->offset += bData + 1;
                strm->state = ADC_STATE_SHORTLOOK;
                adc_dbgmsg("adc_decompress: SHORTOP bData %x state %u offset %u length %u\n",
                           bData, strm->state, strm->offset, strm->length);
                break;
           }

           case ADC_STATE_RAWDATA: {
                /* Grab data */
                adc_dbgmsg("adc_decompress: RAWDATA offset %u length %u\n", strm->offset, strm->length);
                while ((strm->avail_in > 0) && (strm->avail_out > 0) && (strm->length > 0)) {
                    bData = *(strm->next_in);
                    strm->next_in++;
                    strm->avail_in--;
                    /* store to output */
                    *(strm->next_out) = bData;
                    strm->next_out++;
                    strm->avail_out--;
                    /* store to buffer */
                    if (strm->curr >= (strm->buffer + ADC_BUFF_SIZE)) {
                        strm->curr = strm->buffer;
                    }
                    *(strm->curr) = bData;
                    strm->curr++;
                    if (strm->buffered < ADC_BUFF_SIZE) {
                        strm->buffered++;
                    }
                    strm->length--;
                }
                if (strm->length == 0) {
                    /* adc_dbgmsg("adc_decompress: RAWDATADONE buffered %u avail_in %u avail_out %u \n",
                        strm->buffered, strm->avail_in, strm->avail_out); */
                    strm->state = ADC_STATE_GETTYPE;
                }
                break;
           }

           case ADC_STATE_SHORTLOOK:
           case ADC_STATE_LONGLOOK: {
                /* Copy data */
                adc_dbgmsg("adc_decompress: LOOKBACK offset %u length %u avail_in %u avail_out %u\n",
                    strm->offset, strm->length, strm->avail_in, strm->avail_out);
                while ((strm->avail_out > 0) && (strm->length > 0)) {
                    /* state validation first */
                    if (strm->offset > 0x10000) {
                        cli_dbgmsg("adc_decompress: bad LOOKBACK offset %u\n", strm->offset);
                        return ADC_DATA_ERROR;
                    }
                    else if ((strm->state == ADC_STATE_SHORTLOOK) && (strm->offset > 0x400)) {
                        cli_dbgmsg("adc_decompress: bad LOOKBACK offset %u\n", strm->offset);
                        return ADC_DATA_ERROR;
                    }
                    if (strm->offset > strm->buffered) {
                        cli_dbgmsg("adc_decompress: too large LOOKBACK offset %u\n", strm->offset);
                        return ADC_DATA_ERROR;
                    }
                    /* retrieve byte */
                    if (strm->curr >= (strm->buffer + ADC_BUFF_SIZE)) {
                        strm->curr = strm->buffer;
                    }
                    if (strm->curr >= (strm->buffer + strm->offset)) {
                        bData = *(uint8_t *)(strm->curr - strm->offset);
                    }
                    else {
                        bData = *(uint8_t *)(strm->curr + ADC_BUFF_SIZE - strm->offset);
                    }
                    /* store to output */
                    *(strm->next_out) = bData;
                    strm->next_out++;
                    strm->avail_out--;
                    /* store to buffer */
                    *(strm->curr) = bData;
                    strm->curr++;
                    if (strm->buffered < ADC_BUFF_SIZE) {
                        strm->buffered++;
                    }
                    strm->length--;
                }
                if (strm->length == 0) {
                    strm->state = ADC_STATE_GETTYPE;
                    /* adc_dbgmsg("adc_decompress: LOOKBACKDONE buffered %u avail_in %u avail_out %u \n",
                        strm->buffered, strm->avail_in, strm->avail_out); */
                }
                break;
            }

            default: {
                /* bad state */
                cli_errmsg("adc_decompress: invalid state %u\n", strm->state);
                return ADC_DATA_ERROR;
            }
        } /* end switch */
    } /* end while */

    /* There really isn't a terminator, just end of data */
    if (didNothing && strm->avail_out) {
        if (strm->state == ADC_STATE_GETTYPE) {
            /* Nothing left to do */
            return ADC_STREAM_END;
        }
        else {
            /* Ended mid phrase */
            cli_dbgmsg("adc_decompress: stream ended mid-phrase, state %u\n", strm->state);
            return ADC_DATA_ERROR;
        }
    }
    return ADC_OK;
}

/* Cleanup routine, frees buffer */
int adc_decompressEnd(adc_stream *strm)
{
    if (strm == NULL) {
        return ADC_IO_ERROR;
    }
    if (strm->state == ADC_STATE_UNINIT) {
        return ADC_DATA_ERROR;
    }

    if (strm->buffer != NULL) {
        free(strm->buffer);
    }
    strm->buffered = 0;
    strm->state = ADC_STATE_UNINIT;
    strm->length = 0;
    strm->offset = 0;

    return ADC_OK;
}

