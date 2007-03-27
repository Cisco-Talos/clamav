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
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */
 
#ifndef __HTMLNORM_H
#define __HTMLNORM_H

typedef struct tag_arguments_tag
{
        int count;
	int scanContents;
        unsigned char **tag;
        unsigned char **value;
	struct blob   **contents; 
} tag_arguments_t;

typedef struct m_area_tag {
	unsigned char *buffer;
	off_t length;
	off_t offset;
} m_area_t;


unsigned char *cli_readline(FILE *stream, m_area_t *m_area, unsigned int max_len);
int html_normalise_mem(unsigned char *in_buff, off_t in_size, const char *dirname, tag_arguments_t *hrefs,const struct cli_dconf* dconf);
int html_normalise_fd(int fd, const char *dirname, tag_arguments_t *hrefs,const struct cli_dconf* dconf);
void html_tag_arg_free(tag_arguments_t *tags);
int html_screnc_decode(int fd, const char *dirname);
 
#endif

