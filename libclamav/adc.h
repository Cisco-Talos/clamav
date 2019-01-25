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

#ifndef CLAM_ADC_H
#define CLAM_ADC_H

struct adc_stream {
    uint8_t *next_in;
    size_t avail_in;
    size_t total_in;

    uint8_t *next_out;
    size_t avail_out;
    size_t total_out;

    /* internals */
    uint8_t *buffer;
    uint8_t *curr;

    uint32_t buffered;
    uint16_t state;
    uint16_t length;
    uint32_t offset;
};
typedef struct adc_stream adc_stream;

#define ADC_BUFF_SIZE 65536

#define    ADC_MEM_ERROR -1
#define    ADC_DATA_ERROR -2
#define    ADC_IO_ERROR -3
#define    ADC_OK 0
#define    ADC_STREAM_END 1

enum adc_state {
    ADC_STATE_UNINIT = 0,
    ADC_STATE_GETTYPE = 1,
    ADC_STATE_RAWDATA = 2,
    ADC_STATE_SHORTOP = 3,
    ADC_STATE_LONGOP2 = 4,
    ADC_STATE_LONGOP1 = 5,
    ADC_STATE_SHORTLOOK = 6,
    ADC_STATE_LONGLOOK = 7
};

/* Compression phrases
 * store phrase - 1 byte header + data, first byte 0x80-0xFF, max length 0x80 (7 bits + 1), no offset
 * short phrase - 2 byte header + data, first byte 0x00-0x3F, max length 0x12 (4 bits + 3), max offset 0x3FF (10 bits)
 * long phrase  - 3 byte header + data, first byte 0x40-0x7F, max length 0x43 (6 bits + 4), max offset 0xFFFF (16 bits)
 */

int adc_decompressInit(adc_stream *strm);
int adc_decompress(adc_stream *strm);
int adc_decompressEnd(adc_stream *strm);

#endif
