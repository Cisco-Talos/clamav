/*************************************************
*      Perl-Compatible Regular Expressions       *
*************************************************/

/* PCRE is a library of functions to support regular expressions whose syntax
and semantics are as close as possible to those of the Perl 5 language.

                       Written by Philip Hazel
           Copyright (c) 1997-2006 University of Cambridge

-----------------------------------------------------------------------------
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.

    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.

    * Neither the name of the University of Cambridge nor the names of its
      contributors may be used to endorse or promote products derived from
      this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
-----------------------------------------------------------------------------
*/


/* This module contains an internal function for validating UTF-8 character
strings. */


#include "pcre_internal.h"


/*************************************************
*         Validate a UTF-8 string                *
*************************************************/

/* This function is called (optionally) at the start of compile or match, to
validate that a supposed UTF-8 string is actually valid. The early check means
that subsequent code can assume it is dealing with a valid string. The check
can be turned off for maximum performance, but the consequences of supplying
an invalid string are then undefined.

Arguments:
  string       points to the string
  length       length of string, or -1 if the string is zero-terminated

Returns:       < 0    if the string is a valid UTF-8 string
               >= 0   otherwise; the value is the offset of the bad byte
*/

int
_pcre_valid_utf8(const uschar *string, int length)
{
register const uschar *p;

if (length < 0)
  {
  for (p = string; *p != 0; p++);
  length = p - string;
  }

for (p = string; length-- > 0; p++)
  {
  register int ab;
  register int c = *p;
  if (c < 128) continue;
  if (c < 0xc0) return p - string;
  ab = _pcre_utf8_table4[c & 0x3f];  /* Number of additional bytes */
  if (length < ab) return p - string;
  length -= ab;

  /* Check top bits in the second byte */
  if ((*(++p) & 0xc0) != 0x80) return p - string;

  /* Check for overlong sequences for each different length */
  switch (ab)
    {
    /* Check for xx00 000x */
    case 1:
    if ((c & 0x3e) == 0) return p - string;
    continue;   /* We know there aren't any more bytes to check */

    /* Check for 1110 0000, xx0x xxxx */
    case 2:
    if (c == 0xe0 && (*p & 0x20) == 0) return p - string;
    break;

    /* Check for 1111 0000, xx00 xxxx */
    case 3:
    if (c == 0xf0 && (*p & 0x30) == 0) return p - string;
    break;

    /* Check for 1111 1000, xx00 0xxx */
    case 4:
    if (c == 0xf8 && (*p & 0x38) == 0) return p - string;
    break;

    /* Check for leading 0xfe or 0xff, and then for 1111 1100, xx00 00xx */
    case 5:
    if (c == 0xfe || c == 0xff ||
       (c == 0xfc && (*p & 0x3c) == 0)) return p - string;
    break;
    }

  /* Check for valid bytes after the 2nd, if any; all must start 10 */
  while (--ab > 0)
    {
    if ((*(++p) & 0xc0) != 0x80) return p - string;
    }
  }

return -1;
}

/* End of pcre_valid_utf8.c */
