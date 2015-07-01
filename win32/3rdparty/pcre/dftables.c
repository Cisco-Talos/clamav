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


/* This is a freestanding support program to generate a file containing default
character tables for PCRE. The tables are built according to the default C
locale. Now that pcre_maketables is a function visible to the outside world, we
make use of its code from here in order to be consistent. */

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "pcre_internal.h"

#define DFTABLES          /* pcre_maketables.c notices this */
#include "pcre_maketables.c"


int main(int argc, char **argv)
{
int i;
FILE *f;
const unsigned char *tables = pcre_maketables();
const unsigned char *base_of_tables = tables;

if (argc != 2)
  {
  fprintf(stderr, "dftables: one filename argument is required\n");
  return 1;
  }

f = fopen(argv[1], "wb");
if (f == NULL)
  {
  fprintf(stderr, "dftables: failed to open %s for writing\n", argv[1]);
  return 1;
  }

/* There are two fprintf() calls here, because gcc in pedantic mode complains
about the very long string otherwise. */

fprintf(f,
  "/*************************************************\n"
  "*      Perl-Compatible Regular Expressions       *\n"
  "*************************************************/\n\n"
  "/* This file is automatically written by the dftables auxiliary \n"
  "program. If you edit it by hand, you might like to edit the Makefile to \n"
  "prevent its ever being regenerated.\n\n");
fprintf(f,
  "This file contains the default tables for characters with codes less than\n"
  "128 (ASCII characters). These tables are used when no external tables are\n"
  "passed to PCRE.\n\n");
fprintf(f,
  "The following #include is present because without it gcc 4.x may remove\n"
  "the array definition from the final binary if PCRE is built into a static\n"
  "library and dead code stripping is activated. This leads to link errors.\n"
  "Pulling in the header ensures that the array gets flagged as \"someone\n"
  "outside this compilation unit might reference this\" and so it will always\n"
  "be supplied to the linker. */\n\n"
  "#include \"pcre_internal.h\"\n\n");
fprintf(f,
  "const unsigned char _pcre_default_tables[] = {\n\n"
  "/* This table is a lower casing table. */\n\n");

fprintf(f, "  ");
for (i = 0; i < 256; i++)
  {
  if ((i & 7) == 0 && i != 0) fprintf(f, "\n  ");
  fprintf(f, "%3d", *tables++);
  if (i != 255) fprintf(f, ",");
  }
fprintf(f, ",\n\n");

fprintf(f, "/* This table is a case flipping table. */\n\n");

fprintf(f, "  ");
for (i = 0; i < 256; i++)
  {
  if ((i & 7) == 0 && i != 0) fprintf(f, "\n  ");
  fprintf(f, "%3d", *tables++);
  if (i != 255) fprintf(f, ",");
  }
fprintf(f, ",\n\n");

fprintf(f,
  "/* This table contains bit maps for various character classes.\n"
  "Each map is 32 bytes long and the bits run from the least\n"
  "significant end of each byte. The classes that have their own\n"
  "maps are: space, xdigit, digit, upper, lower, word, graph\n"
  "print, punct, and cntrl. Other classes are built from combinations. */\n\n");

fprintf(f, "  ");
for (i = 0; i < cbit_length; i++)
  {
  if ((i & 7) == 0 && i != 0)
    {
    if ((i & 31) == 0) fprintf(f, "\n");
    fprintf(f, "\n  ");
    }
  fprintf(f, "0x%02x", *tables++);
  if (i != cbit_length - 1) fprintf(f, ",");
  }
fprintf(f, ",\n\n");

fprintf(f,
  "/* This table identifies various classes of character by individual bits:\n"
  "  0x%02x   white space character\n"
  "  0x%02x   letter\n"
  "  0x%02x   decimal digit\n"
  "  0x%02x   hexadecimal digit\n"
  "  0x%02x   alphanumeric or '_'\n"
  "  0x%02x   regular expression metacharacter or binary zero\n*/\n\n",
  ctype_space, ctype_letter, ctype_digit, ctype_xdigit, ctype_word,
  ctype_meta);

fprintf(f, "  ");
for (i = 0; i < 256; i++)
  {
  if ((i & 7) == 0 && i != 0)
    {
    fprintf(f, " /* ");
    if (isprint(i-8)) fprintf(f, " %c -", i-8);
      else fprintf(f, "%3d-", i-8);
    if (isprint(i-1)) fprintf(f, " %c ", i-1);
      else fprintf(f, "%3d", i-1);
    fprintf(f, " */\n  ");
    }
  fprintf(f, "0x%02x", *tables++);
  if (i != 255) fprintf(f, ",");
  }

fprintf(f, "};/* ");
if (isprint(i-8)) fprintf(f, " %c -", i-8);
  else fprintf(f, "%3d-", i-8);
if (isprint(i-1)) fprintf(f, " %c ", i-1);
  else fprintf(f, "%3d", i-1);
fprintf(f, " */\n\n/* End of chartables.c */\n");

fclose(f);
free((void *)base_of_tables);
return 0;
}

/* End of dftables.c */
