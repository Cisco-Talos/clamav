/*
 *  Copyright (C) 2004 Nigel Horne <njh@bandsman.co.uk>
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
 *
 * $Log: line.h,v $
 * Revision 1.2  2004/08/20 19:06:45  kojm
 * add line.[ch]
 *
 * Revision 1.1  2004/08/20 11:58:20  nigelhorne
 * First draft
 *
 */

#ifndef __LINE_H
#define __LINE_H

typedef struct line {
	char	*l_data;	/* the line's contents */
	unsigned int	l_refs;	/* the number of references to the data */
} line_t;

line_t	*lineCreate(const char *data);
line_t	*lineLink(line_t *line);
line_t	*lineUnlink(line_t *line);
const	char	*lineGetData(const line_t *line);

#endif
