/*
 *  Copyright (C) 2002 - 2005 Tomasz Kojm <tkojm@clamav.net>
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

#ifndef __STR_H
#define __STR_H

#include <sys/types.h>

#include "cltypes.h"

int cli_strbcasestr(const char *haystack, const char *needle);
int cli_chomp(char *string);
char *cli_strtok(const char *line, int field, const char *delim);
uint16_t *cli_hex2ui(const char *hex);
char *cli_hex2str(const char *hex);
int cli_hex2num(const char *hex);
char *cli_str2hex(const char *string, unsigned int len);
char *cli_utf16toascii(const char *str, unsigned int length);
char *cli_strtokbuf(const char *input, int fieldno, const char *delim, char *output);
const char *cli_memstr(const char *haystack, int hs, const char *needle, int ns);
char *cli_strrcpy(char *dest, const char *source);
void cli_strtokenize(char *buffer, const char delim, const size_t token_count, const char **tokens);
#endif
