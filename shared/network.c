/*
 *  Copyright (C) 2005 Nigel Horne <njh@bandsman.co.uk>
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
 */

#ifdef	_MSC_VER
#include <windows.h>
#include <winsock.h>
#endif

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>

#ifdef	HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifndef C_WINDOWS
#include <netdb.h>
#endif

#ifdef CL_NOTHREADS
#undef CL_THREAD_SAFE
#endif

#ifdef  CL_THREAD_SAFE
#include <pthread.h>
#endif

#include "network.h"

/*
 * TODO: gethostbyname_r is non-standard so different operating
 * systems do it in different ways. Need more examples
 * Perhaps we could use res_search()?
 *
 * Returns 0 for success
 */
int r_gethostbyname(const char *hostname, struct hostent *hp, char *buf, size_t len)
{
#if	defined(HAVE_GETHOSTBYNAME_R_6)
	/* e.g. Linux */
	struct hostent *hp2;
	int ret = -1;

	if((hostname == NULL) || (hp == NULL))
		return -1;
	if(gethostbyname_r(hostname, hp, buf, len, &hp2, &ret) < 0)
		return ret;
#elif	defined(HAVE_GETHOSTBYNAME_R_5)
	/* e.g. BSD, Solaris, Cygwin */
	int ret = -1;

	if((hostname == NULL) || (hp == NULL))
		return -1;
	if(gethostbyname_r(hostname, hp, buf, len, &ret) == NULL)
		return ret;
#elif	defined(HAVE_GETHOSTBYNAME_R_3)
	/* e.g. HP/UX, AIX */
	if((hostname == NULL) || (hp == NULL))
		return -1;
	if(gethostbyname_r(hostname, &hp, (struct hostent_data *)buf) < 0)
		return h_errno;
#else
	/* Single thread the code e.g. VS2005 */
	struct hostent *hp2;
#ifdef  CL_THREAD_SAFE
	static pthread_mutex_t hostent_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

	if((hostname == NULL) || (hp == NULL))
		return -1;
#ifdef  CL_THREAD_SAFE
	pthread_mutex_lock(&hostent_mutex);
#endif
	if((hp2 = gethostbyname(hostname)) == NULL) {
#ifdef  CL_THREAD_SAFE
		pthread_mutex_unlock(&hostent_mutex);
#endif
		return h_errno;
	}
	memcpy(hp, hp2, sizeof(struct hostent));
#ifdef  CL_THREAD_SAFE
	pthread_mutex_unlock(&hostent_mutex);
#endif

#endif
	return 0;
}
