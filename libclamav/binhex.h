/*
 *  Copyright (C) 2007-2008 Sourcefire, Inc.
 *
 *  Authors: Nigel Horne
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

#include "others.h"
int cli_binhex(cli_ctx *ctx);

#endif
