/*
 *  Copyright (C) 2002 Tomasz Kojm <zolw@konarski.edu.pl>
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

#ifndef DATADIR
# define DATADIR "/usr/local/share/clamav"
#endif

#define VIRUSDBDIR DATADIR

/* default names */

#ifdef CLAMAVUSER
#define UNPUSER CLAMAVUSER
#else
#define UNPUSER "clamav"
#endif

#ifdef CLAMAVGROUP
#define UNPGROUP CLAMAVGROUP
#else
#define UNPGROUP "clamav"
#endif

#define CL_DEFAULT_CHECKS 12
#define CL_DEFAULT_MAXATTEMPTS 3
#define CL_MAX_CHILDREN 5
