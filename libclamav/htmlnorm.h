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

typedef struct tag_arguments_tag
{
        int count;
        unsigned char **tag;
        unsigned char **value;
} tag_arguments_t;

int html_normalise_mem(unsigned char *in_buff, off_t in_size, const char *dirname, tag_arguments_t *hrefs);
int html_normalise_fd(int fd, const char *dirname, tag_arguments_t *hrefs);
void html_tag_arg_free(tag_arguments_t *tags);
int html_screnc_decode(int fd, const char *dirname);
 
#endif

