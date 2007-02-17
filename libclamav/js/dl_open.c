/*
 * Dynamic loading with dl{open,close,sym}() functions.
 * Copyright (c) 1998 New Generation Software (NGS) Oy
 *
 * Author: Markku Rossi <mtr@ngs.fi>
 */

/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA
 */

/*
 * $Source: /tmp/cvsroot-15-2-2007/clamav-devel/libclamav/js/dl_open.c,v $
 * $Id: dl_open.c,v 1.2 2006/10/28 11:27:44 njh Exp $
 */
#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#ifdef	CL_EXPERIMENTAL

#include "jsint.h"
#include <dlfcn.h>

/*
 * Global functions.
 */

void *
js_dl_open (const char *filename, char *error_return,
	    unsigned int error_return_len)
{
  void *lib = dlopen (filename, RTLD_NOW);

  if (lib == NULL)
    {
      const char *msg = dlerror ();
      unsigned int msg_len;

      msg_len = strlen (msg);
      if (msg_len > error_return_len - 1)
	msg_len = error_return_len - 1;

      memcpy (error_return, msg, msg_len);
      error_return[msg_len] = '\0';
    }

  return lib;
}


void *
js_dl_sym (void *library, char *symbol, char *error_return,
	   unsigned int error_return_len)
{
  void *sym = dlsym (library, symbol);

  if (sym == NULL)
    {
      const char *msg = dlerror ();
      unsigned int msg_len;

      msg_len = strlen (msg);
      if (msg_len > error_return_len - 1)
	msg_len = error_return_len - 1;

      memcpy (error_return, msg, msg_len);
      error_return[msg_len] = '\0';
    }

  return sym;
}
#endif	/*CL_EXPERIMENTAL*/
