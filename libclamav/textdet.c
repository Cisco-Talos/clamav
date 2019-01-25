/*
 * Text detection based on ascmagic.c from the file(1) utility.
 *
 * Portions Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 * Portions Copyright (C) 2008-2013 Sourcefire, Inc.
 *
 * Copyright (c) Ian F. Darwin 1986-1995.
 * Software written by Ian F. Darwin and others;
 * maintained 1995-present by Christos Zoulas and others.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice immediately at the beginning of the file, without modification,
 *    this list of conditions, and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *  
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <memory.h>
#include <ctype.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "clamav.h"
#include "filetypes.h"
#include "textdet.h"
#include "others.h"

#define F 0   /* character never appears in text */
#define T 1   /* character appears in plain ASCII text */
#define I 2   /* character appears in ISO-8859 text */
#define X 3   /* character appears in non-ISO extended ASCII (Mac, IBM PC) */

static char text_chars[256] = {
	/*                  BEL BS HT LF    FF CR    */
	F, F, F, F, F, F, F, T, T, T, T, F, T, T, F, F,  /* 0x0X */
        /*                              ESC          */
	F, F, F, F, F, F, F, F, F, F, F, T, F, F, F, F,  /* 0x1X */
	T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T,  /* 0x2X */
	T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T,  /* 0x3X */
	T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T,  /* 0x4X */
	T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T,  /* 0x5X */
	T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T,  /* 0x6X */
	T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, F,  /* 0x7X */
	/*            NEL                            */
	X, X, X, X, X, T, X, X, X, X, X, X, X, X, X, X,  /* 0x8X */
	X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X,  /* 0x9X */
	I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I,  /* 0xaX */
	I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I,  /* 0xbX */
	I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I,  /* 0xcX */
	I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I,  /* 0xdX */
	I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I,  /* 0xeX */
	I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I   /* 0xfX */
};

static int td_isascii(const unsigned char *buf, unsigned int len)
{
	unsigned int i;

	// @TODO:  UTF8 BOM Detection. 
	//    The following BOM detection results in False Negatives in regression testing
	//    which can be eliminated by adding a condition to call cli_scanhtml for CL_TYPE_TEXT_UTF8
	//    in scanners.c:cli_scanraw().  However, cli_scanhtml was written for ASCII and has 
	//    not been validated to correctly handle multibyte UTF8. 
	// /* Check for the Byte-Order-Mark for UTF-8 */
	// if ((len >= 3) &&
	// 	(buf[0] == 0xEF) &&
	// 	(buf[1] == 0xBB) &&
	// 	(buf[2] == 0xBF))
	// {
	// 	return 0;
	// }

	/* Validate that the data all falls within the bounds of 
	 * plain ASCII, ISO-8859 text, and non-ISO extended ASCII (Mac, IBM PC)
	 */
	for(i = 0; i < len; i++)
		if(text_chars[buf[i]] == F)
			return 0;

    return 1;
}

static int td_isutf8(const unsigned char *buf, unsigned int len)
{
	unsigned int i, j, gotone = 0;


    for(i = 0; i < len; i++) {
	if((buf[i] & 0x80) == 0) {  /* 0xxxxxxx is plain ASCII */
	    /*
	     * Even if the whole file is valid UTF-8 sequences,
	     * still reject it if it uses weird control characters.
	     */
	    if(text_chars[buf[i]] != T)
		return 0;

	} else if((buf[i] & 0x40) == 0) { /* 10xxxxxx never 1st byte */
	    return 0;
	} else {			   /* 11xxxxxx begins UTF-8 */
		unsigned int following;

	    if((buf[i] & 0x20) == 0) {		/* 110xxxxx */
		/* c = buf[i] & 0x1f; */
		following = 1;
	    } else if((buf[i] & 0x10) == 0) {	/* 1110xxxx */
		/* c = buf[i] & 0x0f; */
		following = 2;
	    } else if((buf[i] & 0x08) == 0) {	/* 11110xxx */
		/* c = buf[i] & 0x07; */
		following = 3;
	    } else if((buf[i] & 0x04) == 0) {	/* 111110xx */
		/* c = buf[i] & 0x03; */
		following = 4;
	    } else if((buf[i] & 0x02) == 0) {	/* 1111110x */
		/* c = buf[i] & 0x01; */
		following = 5;
	    } else {
		return 0;
	    }

	    for(j = 0; j < following; j++) {
		if(++i >= len)
		    return gotone;

		if((buf[i] & 0x80) == 0 || (buf[i] & 0x40))
		    return 0;

		/* c = (c << 6) + (buf[i] & 0x3f); */
	    }

	    gotone = 1;
	}
    }

    return gotone;
}

static int td_isutf16(const unsigned char *buf, unsigned int len)
{
	unsigned int be = 1, nobom = 0, i, c, bad = 0, high = 0;


    if(len < 2)
	return 0;

    if(buf[0] == 0xff && buf[1] == 0xfe)
	be = 0;
    else if(buf[0] == 0xfe && buf[1] == 0xff)
	be = 1;
    else
	nobom = 1;

    for(i = 2; i + 1 < len; i += 2) {
	if(be)
	    c = buf[i + 1] + 256 * buf[i];
	else
	    c = buf[i] + 256 * buf[i + 1];

	if(c == 0xfffe)
	    return 0;

	if(c < 128 && text_chars[c] != T) {
	    if(nobom)
		return 0;
	    else
		bad++;
	} else if (c >= 128) {
        high++;
    }
    }

    //   if (nobom && high >= len / 4)
    //        return 0;

    if(!nobom && bad >= len / 2)
	return 0;

    return 1 + be;
}

cli_file_t cli_texttype(const unsigned char *buf, unsigned int len)
{
	int ret;

    if(td_isascii(buf, len)) {
	cli_dbgmsg("Recognized ASCII text\n");
	return CL_TYPE_TEXT_ASCII;
    } else if(td_isutf8(buf, len)) {
	cli_dbgmsg("Recognized UTF-8 character data\n");
	return CL_TYPE_TEXT_UTF8;
    } else if((ret = td_isutf16(buf, len))) {
	cli_dbgmsg("Recognized %s character data\n", (ret == 1) ? "UTF-16LE" : "UTF-16BE");
	return (ret == 1) ? CL_TYPE_TEXT_UTF16LE : CL_TYPE_TEXT_UTF16BE;
    } else {
	cli_dbgmsg("Recognized binary data\n");
	return CL_TYPE_BINARY_DATA;
    }
}
