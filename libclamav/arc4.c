/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2011-2013 Sourcefire, Inc.
 *
 *  Author: Török Edvin
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

#include "clamav-types.h"
#include "arc4.h"
#include <string.h>

void arc4_init(struct arc4_state *a, const uint8_t *key, unsigned keylength)
{
    unsigned i;
    uint8_t j;
    uint32_t *S = &a->S[0];

    for (i=0; i < 256;i ++)
	S[i] = i;
    for (i=0,j=0; i < 256; i++) {
	uint8_t tmp = S[i];
	j = j + S[i] + key[i % keylength];
	S[i] = S[j];
	S[j] = tmp;
    }
    a->i = a->j = 0;
}

void arc4_apply(struct arc4_state *s, uint8_t *data, unsigned len)
{
    uint8_t i = s->i, j = s->j;
    uint32_t *S = &s->S[0];

    while (len-- > 0) {
	uint32_t a, b;
	i++;
	a = S[i];
	j += a;
	b = S[i] = S[j];
	b += a;
	S[j] = a;
	*data++ ^= S[b & 0xff];
    }

    s->i = i;
    s->j = j;
}

#if 0
#include <sys/time.h>
static struct {
    const char *key;
    const char *plaintext;
    const char *result;
} testdata[] = {
    {"Key", "Plaintext", "\xBB\xF3\x16\xE8\xD9\x40\xAF\x0A\xD3"},
    {"Wiki", "pedia", "\x10\x21\xBF\x04\x20"},
    {"Secret", "Attack at dawn", "\x45\xA0\x1F\x64\x5F\xC3\x5B\x38\x35\x52\x54\x4B\x9B\xF5"}
};

static int data[10*1024*1024];
int main(void)
{
    struct arc4_state a;
    uint8_t data[32];
    size_t i;
    struct timeval tv0, tv1;

    for (i=0;i<sizeof(testdata)/sizeof(testdata[0]);i++) {
	unsigned len;
	arc4_init(&a, (const uint8_t*)testdata[i].key, strlen(testdata[i].key));
	len = strlen(testdata[i].plaintext);
	memcpy(data, testdata[i].plaintext, len);
	arc4_apply(&a, data, len);
	if (memcmp(data, testdata[i].result, len)) {
	    printf("Bad result at %zu\n", i);
	}
    }
    gettimeofday(&tv0, NULL);
    for (i=0;i<1000000;i++)
	arc4_apply(&a, data, sizeof(data));
    gettimeofday(&tv1, NULL);
    tv1.tv_sec -= tv0.tv_sec;
    tv1.tv_usec -= tv0.tv_usec;
    printf("Time: %f us\n", tv1.tv_sec*1000000.0 + tv1.tv_usec);
}
#endif
