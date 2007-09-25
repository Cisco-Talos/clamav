/*
 *  Copyright (C) 2008 Nigel Horne <njh@bandsman.co.uk>
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
 * Syslog compatibility for Windows
 * Tested under Microsoft Visual Studio 2005
 */
#define	LOG_ERR		EVENTLOG_ERROR_TYPE	/* or EVENTLOG_AUDIT_FAILURE? */
#define	LOG_WARNING	EVENTLOG_WARNING_TYPE
#define	LOG_INFO	EVENTLOG_INFORMATION_TYPE
#define	LOG_DEBUG	EVENTLOG_INFORMATION_TYPE

/* Only support LOG_MAIL and LOG_LOCAL facilities for now */
#define LOG_MAIL        (2<<3)
#define	LOG_LOCAL6	(22<<3)

#define	LOG_PID		0x01

void	openlog(const char *name, int options , int facility);
void	closelog(void);
void	syslog(int level, const char *format, ...);
