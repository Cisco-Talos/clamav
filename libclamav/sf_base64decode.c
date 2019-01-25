/*
 ** Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 ** Copyright (C) 1998-2013 Sourcefire, Inc.
 **
 ** Written by Patrick Mullen <pmullen@sourcefire.com>
 ** 9/11/2013 - Changed uint32_t to size_t
 **
 ** This program is free software; you can redistribute it and/or modify
 ** it under the terms of the GNU General Public License Version 2 as
 ** published by the Free Software Foundation.  You may not use, modify or
 ** distribute this program under any other version of the GNU General
 ** Public License.
 **
 ** This program is distributed in the hope that it will be useful,
 ** but WITHOUT ANY WARRANTY; without even the implied warranty of
 ** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 ** GNU General Public License for more details.
 **
 ** You should have received a copy of the GNU General Public License
 ** along with this program; if not, write to the Free Software
 ** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifdef HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include "sf_base64decode.h"

uint8_t sf_decode64tab[256] = {
        100,100,100,100,100,100,100,100,100,100,100,100,100,100,100,100,
        100,100,100,100,100,100,100,100,100,100,100,100,100,100,100,100,
        100,100,100,100,100,100,100,100,100,100,100,62 ,100,100,100, 63,
         52, 53, 54, 55, 56, 57, 58, 59, 60, 61,100,100,100, 99,100,100,
        100,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
         15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,100,100,100,100,100,
        100, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
         41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,100,100,100,100,100,
        100,100,100,100,100,100,100,100,100,100,100,100,100,100,100,100,
        100,100,100,100,100,100,100,100,100,100,100,100,100,100,100,100,
        100,100,100,100,100,100,100,100,100,100,100,100,100,100,100,100,
        100,100,100,100,100,100,100,100,100,100,100,100,100,100,100,100,
        100,100,100,100,100,100,100,100,100,100,100,100,100,100,100,100,
        100,100,100,100,100,100,100,100,100,100,100,100,100,100,100,100,
        100,100,100,100,100,100,100,100,100,100,100,100,100,100,100,100,
        100,100,100,100,100,100,100,100,100,100,100,100,100,100,100,100};

/* base64decode assumes the input data terminates with '=' and/or at the end of the input buffer
 * at inbuf_size.  If extra characters exist within inbuf before inbuf_size is reached, it will
 * happily decode what it can and skip over what it can't.  This is consistent with other decoders
 * out there.  So, either terminate the string, set inbuf_size correctly, or at least be sure the
 * data is valid up until the point you care about.  Note base64 data does NOT have to end with
 * '=' and won't if the number of bytes of input data is evenly divisible by 3.
*/
int sf_base64decode(uint8_t *inbuf, size_t inbuf_size, uint8_t *outbuf, size_t outbuf_size, size_t *bytes_written)
{
   uint8_t *cursor, *endofinbuf;
   uint8_t *outbuf_ptr;
   uint8_t base64data[4], *base64data_ptr; /* temporary holder for current base64 chunk */
   uint8_t tableval_a, tableval_b, tableval_c, tableval_d;

   size_t n;
   size_t max_base64_chars;  /* The max number of decoded base64 chars that fit into outbuf */

   int error = 0;

   /* This algorithm will waste up to 4 bytes but we really don't care.
      At the end we're going to copy the exact number of bytes requested. */
   max_base64_chars = (outbuf_size / 3) * 4 + 4; /* 4 base64 bytes gives 3 data bytes, plus
                                                    an extra 4 to take care of any rounding */

   base64data_ptr = base64data;
   endofinbuf = inbuf + inbuf_size;

   /* Strip non-base64 chars from inbuf and decode */
   n = 0;
   *bytes_written = 0;
   cursor = inbuf;
   outbuf_ptr = outbuf;
   while((cursor < endofinbuf) && (n < max_base64_chars)) {
      if(sf_decode64tab[*cursor] != 100) {
         *base64data_ptr++ = *cursor;
         n++;  /* Number of base64 bytes we've stored */
         if(!(n % 4)) {
            /* We have four databytes upon which to operate */

            if((base64data[0] == '=') || (base64data[1] == '=')) {
               /* Error in input data */
               error = 1;
               break;
            }

            /* retrieve values from lookup table */
            tableval_a = sf_decode64tab[base64data[0]];
            tableval_b = sf_decode64tab[base64data[1]];
            tableval_c = sf_decode64tab[base64data[2]];
            tableval_d = sf_decode64tab[base64data[3]];

            if(*bytes_written < outbuf_size) {
               *outbuf_ptr++ = (tableval_a << 2) | (tableval_b >> 4);
               (*bytes_written)++;
            }

            if((base64data[2] != '=') && (*bytes_written < outbuf_size)) {
               *outbuf_ptr++ = (tableval_b << 4) | (tableval_c >> 2);
               (*bytes_written)++;
            }  else {
               break;
            }

            if((base64data[3] != '=') && (*bytes_written < outbuf_size)) {
               *outbuf_ptr++ = (tableval_c << 6) | tableval_d;
               (*bytes_written)++;
            }  else {
               break;
            }

            /* Reset our decode pointer for the next group of four */
            base64data_ptr = base64data;
         }
      }
      cursor++;
   }

   if(error)
      return(-1);
   else
      return(0);
}
