/*
 *  Copyright (C) 2004 Trog <trog@clamav.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef __HTMLNORM_H
#define __HTMLNORM_H

#include <sys/types.h>

unsigned char *html_normalize(unsigned char *in_buff, off_t in_size);
unsigned char *remove_html_comments(unsigned char *line);
unsigned char *remove_html_char_ref(unsigned char *line);
char *quoted_decode(unsigned char *line, off_t in_size);

#endif
