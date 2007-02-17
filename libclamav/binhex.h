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
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 *
 * Change History:
 * $Log: binhex.h,v $
 * Revision 1.4  2006/04/09 19:59:27  kojm
 * update GPL headers with new address for FSF
 *
 * Revision 1.3  2004/11/18 19:30:29  kojm
 * add support for Mac's HQX file format
 *
 * Revision 1.2  2004/11/18 18:24:45  nigelhorne
 * Added binhex.h
 *
 */

#ifndef __BINHEX_H
#define __BINHEX_H

int	cli_binhex(const char *dir, int desc);

#endif
