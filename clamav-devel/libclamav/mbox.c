/*
 *  Copyright (C) 2002 Nigel Horne <njh@bandsman.co.uk>
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
 * Change History:
 * $Log: mbox.c,v $
 * Revision 1.176  2004/11/12 09:41:45  nigelhorne
 * Parial mode now on by default
 *
 * Revision 1.175  2004/11/11 22:15:46  nigelhorne
 * Rewrite handling of folded headers
 *
 * Revision 1.174  2004/11/10 10:08:45  nigelhorne
 * Fix escaped parenthesis in rfc822 comments
 *
 * Revision 1.173  2004/11/09 19:40:06  nigelhorne
 * Find uuencoded files in preambles to multipart messages
 *
 * Revision 1.172  2004/11/09 13:33:38  nigelhorne
 * Tidy
 *
 * Revision 1.171  2004/11/09 12:24:32  nigelhorne
 * Better handling of mail-follow-urls when CURL is not installed
 *
 * Revision 1.170  2004/11/09 10:08:02  nigelhorne
 * Added basic handling of folded headers in the main message
 *
 * Revision 1.169  2004/11/08 16:27:09  nigelhorne
 * Fix crash with correctly encoded uuencode files
 *
 * Revision 1.168  2004/11/08 10:26:22  nigelhorne
 * Fix crash if x-yencode is mistakenly guessed
 *
 * Revision 1.167  2004/11/07 16:59:42  nigelhorne
 * Tidy
 *
 * Revision 1.166  2004/11/07 16:39:00  nigelhorne
 * Handle para 4 of RFC2231
 *
 * Revision 1.165  2004/11/06 21:43:23  nigelhorne
 * Fix possible segfault in handling broken RFC2047 headers
 *
 * Revision 1.164  2004/11/04 10:13:41  nigelhorne
 * Rehashed readdir_r patch
 *
 * Revision 1.163  2004/10/31 09:28:56  nigelhorne
 * Handle unbalanced quotes in multipart headers
 *
 * Revision 1.162  2004/10/24 04:35:15  nigelhorne
 * Handle multipart/knowbot as multipart/mixed
 *
 * Revision 1.161  2004/10/21 10:18:40  nigelhorne
 * PARTIAL: readdir_r even more options :-(
 *
 * Revision 1.160  2004/10/21 09:41:07  nigelhorne
 * PARTIAL: add readdir_r fix to BeOS
 *
 * Revision 1.159  2004/10/20 10:35:41  nigelhorne
 * Partial mode: fix possible stack corruption with Solaris
 *
 * Revision 1.158  2004/10/17 09:29:21  nigelhorne
 * Advise to report broken emails
 *
 * Revision 1.157  2004/10/16 20:53:28  nigelhorne
 * Tidy up
 *
 * Revision 1.156  2004/10/16 19:09:39  nigelhorne
 * Handle BeMail (BeOS) files
 *
 * Revision 1.155  2004/10/16 17:23:04  nigelhorne
 * Handle colons in quotes in headers
 *
 * Revision 1.154  2004/10/16 09:01:05  nigelhorne
 * Improved handling of wraparound headers
 *
 * Revision 1.153  2004/10/14 21:18:49  nigelhorne
 * Harden the test for RFC2047 encoded headers
 *
 * Revision 1.152  2004/10/14 17:45:13  nigelhorne
 * RFC2047 on long lines produced by continuation headers
 *
 * Revision 1.151  2004/10/10 11:10:20  nigelhorne
 * Remove perror - replace with cli_errmsg
 *
 * Revision 1.150  2004/10/09 08:01:37  nigelhorne
 * Needs libcurl >= 7.11
 *
 * Revision 1.149  2004/10/06 17:21:30  nigelhorne
 * Fix RFC2298 handling broken by RFC1341 code
 *
 * Revision 1.148  2004/10/05 15:41:53  nigelhorne
 * First draft of code to handle RFC1341
 *
 * Revision 1.147  2004/10/04 12:18:09  nigelhorne
 * Better warning message about PGP attachments not being scanned
 *
 * Revision 1.146  2004/10/04 10:52:39  nigelhorne
 * Better error message on RFC2047 decode error
 *
 * Revision 1.145  2004/10/01 13:49:22  nigelhorne
 * Minor code tidy
 *
 * Revision 1.144  2004/10/01 07:55:36  nigelhorne
 * Better error message on message/partial
 *
 * Revision 1.143  2004/09/30 21:47:35  nigelhorne
 * Removed unneeded strdups
 *
 * Revision 1.142  2004/09/28 18:40:12  nigelhorne
 * Use stack rather than heap where possible
 *
 * Revision 1.141  2004/09/23 08:43:25  nigelhorne
 * Scan multipart/digest messages
 *
 * Revision 1.140  2004/09/22 16:09:51  nigelhorne
 * Build if CURLOPT_DNS_USE_GLOBAL_CACHE isn't supported
 *
 * Revision 1.139  2004/09/22 15:49:13  nigelhorne
 * Handle RFC2298 messages
 *
 * Revision 1.138  2004/09/22 15:21:50  nigelhorne
 * Fix typo
 *
 * Revision 1.137  2004/09/21 20:47:38  nigelhorne
 * FOLLOWURL: Set a default username and password for password protected pages
 *
 * Revision 1.136  2004/09/21 12:18:52  nigelhorne
 * Fallback to CURLOPT_FILE if CURLOPT_WRITEDATA isn't defined
 *
 * Revision 1.135  2004/09/21 08:14:00  nigelhorne
 * Now compiles in machines with libcurl but without threads
 *
 * Revision 1.134  2004/09/20 17:08:43  nigelhorne
 * Some performance enhancements
 *
 * Revision 1.133  2004/09/20 12:44:03  nigelhorne
 * Fix parsing error on mime arguments
 *
 * Revision 1.132  2004/09/20 08:31:56  nigelhorne
 * FOLLOWURLS now compiled if libcurl is found
 *
 * Revision 1.131  2004/09/18 14:59:25  nigelhorne
 * Code tidy
 *
 * Revision 1.130  2004/09/17 10:56:29  nigelhorne
 * Handle multiple content-type headers and use the most likely
 *
 * Revision 1.129  2004/09/17 09:48:53  nigelhorne
 * Handle attempts to hide mime type
 *
 * Revision 1.128  2004/09/17 09:09:44  nigelhorne
 * Better handling of RFC822 comments
 *
 * Revision 1.127  2004/09/16 18:00:43  nigelhorne
 * Handle RFC2047
 *
 * Revision 1.126  2004/09/16 14:23:57  nigelhorne
 * Handle quotes around mime type
 *
 * Revision 1.125  2004/09/16 12:59:36  nigelhorne
 * Handle = and space as header separaters
 *
 * Revision 1.124  2004/09/16 11:20:33  nigelhorne
 * Better handling of folded headers in multipart messages
 *
 * Revision 1.123  2004/09/16 08:56:19  nigelhorne
 * Handle RFC822 Comments
 *
 * Revision 1.122  2004/09/15 22:09:26  nigelhorne
 * Handle spaces before colons
 *
 * Revision 1.121  2004/09/15 18:08:23  nigelhorne
 * Handle multiple encoding types
 *
 * Revision 1.120  2004/09/15 08:47:07  nigelhorne
 * Cleaner way to initialise hrefs
 *
 * Revision 1.119  2004/09/14 20:47:28  nigelhorne
 * Use new normalise code
 *
 * Revision 1.118  2004/09/14 12:09:37  nigelhorne
 * Include old normalise code
 *
 * Revision 1.117  2004/09/13 16:44:01  kojm
 * minor cleanup
 *
 * Revision 1.116  2004/09/13 13:16:28  nigelhorne
 * Return CL_EFORMAT on bad format
 *
 * Revision 1.115  2004/09/06 11:02:08  nigelhorne
 * Normalise HTML before scanning for URLs to download
 *
 * Revision 1.114  2004/09/03 15:59:00  nigelhorne
 * Handle boundary= "foo"
 *
 * Revision 1.113  2004/08/26 09:33:20  nigelhorne
 * Scan Communigate Pro files
 *
 * Revision 1.112  2004/08/23 13:15:16  nigelhorne
 * messageClearMarkers
 *
 * Revision 1.111  2004/08/22 20:20:14  nigelhorne
 * Tidy
 *
 * Revision 1.110  2004/08/22 15:08:59  nigelhorne
 * messageExport
 *
 * Revision 1.109  2004/08/22 10:34:24  nigelhorne
 * Use fileblob
 *
 * Revision 1.108  2004/08/21 11:57:57  nigelhorne
 * Use line.[ch]
 *
 * Revision 1.107  2004/08/20 04:55:07  nigelhorne
 * FOLLOWURL
 *
 * Revision 1.106  2004/08/20 04:53:18  nigelhorne
 * Tidy up
 *
 * Revision 1.105  2004/08/18 21:35:08  nigelhorne
 * Multithread the FollowURL calls
 *
 * Revision 1.104  2004/08/18 15:53:43  nigelhorne
 * Honour CL_MAILURL
 *
 * Revision 1.103  2004/08/18 10:49:45  nigelhorne
 * CHECKURLs was mistakenly turned on
 *
 * Revision 1.102  2004/08/18 07:45:20  nigelhorne
 * Use configure WITH_CURL value
 *
 * Revision 1.101  2004/08/17 08:28:32  nigelhorne
 * Support multitype/fax-message
 *
 * Revision 1.100  2004/08/12 10:36:09  nigelhorne
 * LIBCURL completed
 *
 * Revision 1.99  2004/08/11 15:28:39  nigelhorne
 * No longer needs curl.h
 *
 * Revision 1.98  2004/08/11 14:46:22  nigelhorne
 * Better handling of false positive emails
 *
 * Revision 1.97  2004/08/10 14:02:22  nigelhorne
 * *** empty log message ***
 *
 * Revision 1.96  2004/08/10 08:14:00  nigelhorne
 * Enable CHECKURL
 *
 * Revision 1.95  2004/08/09 21:37:21  kojm
 * libclamav: add new option CL_MAILURL
 *
 * Revision 1.94  2004/08/09 08:26:36  nigelhorne
 * Thread safe checkURL
 *
 * Revision 1.93  2004/08/08 21:30:47  nigelhorne
 * First draft of CheckURL
 *
 * Revision 1.92  2004/08/08 19:13:14  nigelhorne
 * Better handling of bounces
 *
 * Revision 1.91  2004/08/04 18:59:19  nigelhorne
 * Tidy up multipart handling
 *
 * Revision 1.90  2004/07/26 17:02:56  nigelhorne
 * Fix crash when debugging on SPARC
 *
 * Revision 1.89  2004/07/26 09:12:12  nigelhorne
 * Fix crash when debugging on Solaris
 *
 * Revision 1.88  2004/07/20 14:35:29  nigelhorne
 * Some MYDOOM.I were getting through
 *
 * Revision 1.87  2004/07/19 17:54:40  kojm
 * Use new patter matching algorithm. Cleanup.
 *
 * Revision 1.86  2004/07/06 09:32:45  nigelhorne
 * Better handling of Gibe.3 boundary exploit
 *
 * Revision 1.85  2004/06/30 19:48:58  nigelhorne
 * Some TR.Happy99.SKA were getting through
 *
 * Revision 1.84  2004/06/30 14:30:40  nigelhorne
 * Fix compilation error on Solaris
 *
 * Revision 1.83  2004/06/28 11:44:45  nigelhorne
 * Remove empty parts
 *
 * Revision 1.82  2004/06/25 13:56:38  nigelhorne
 * Optimise messages without other messages encapsulated within them
 *
 * Revision 1.81  2004/06/24 21:36:38  nigelhorne
 * Plug memory leak with large number of attachments
 *
 * Revision 1.80  2004/06/23 16:23:25  nigelhorne
 * Further empty line optimisation
 *
 * Revision 1.79  2004/06/22 04:08:01  nigelhorne
 * Optimise empty lines
 *
 * Revision 1.78  2004/06/21 10:21:19  nigelhorne
 * Fix crash when a multipart/mixed message contains many parts that need to be scanned as attachments
 *
 * Revision 1.77  2004/06/18 10:07:12  nigelhorne
 * Allow any number of alternatives in multipart messages
 *
 * Revision 1.76  2004/06/16 08:07:39  nigelhorne
 * Added thread safety
 *
 * Revision 1.75  2004/06/14 09:07:10  nigelhorne
 * Handle spam using broken e-mail generators for multipart/alternative
 *
 * Revision 1.74  2004/06/09 18:18:59  nigelhorne
 * Find uuencoded viruses in multipart/mixed that have no start of message boundaries
 *
 * Revision 1.73  2004/05/14 08:15:55  nigelhorne
 * Use mkstemp on cygwin
 *
 * Revision 1.72  2004/05/12 11:20:37  nigelhorne
 * More bounce message false positives handled
 *
 * Revision 1.71  2004/05/10 11:35:11  nigelhorne
 * No need to update mbox.c for cli_filetype problem
 *
 * Revision 1.69  2004/05/06 11:26:49  nigelhorne
 * Force attachments marked as RFC822 messages to be scanned
 *
 * Revision 1.68  2004/04/29 08:59:24  nigelhorne
 * Tidied up SetDispositionType
 *
 * Revision 1.67  2004/04/23 10:47:41  nigelhorne
 * If an inline text portion has a filename treat is as an attachment
 *
 * Revision 1.66  2004/04/14 08:32:21  nigelhorne
 * When debugging print the email number in mailboxes
 *
 * Revision 1.65  2004/04/07 18:18:07  nigelhorne
 * Some occurances of W97M.Lexar were let through
 *
 * Revision 1.64  2004/04/05 09:32:20  nigelhorne
 * Added SCAN_TO_DISC define
 *
 * Revision 1.63  2004/04/01 15:32:34  nigelhorne
 * Graceful exit if messageAddLine fails in strdup
 *
 * Revision 1.62  2004/03/31 17:00:20  nigelhorne
 * Code tidy up free memory earlier
 *
 * Revision 1.61  2004/03/30 22:45:13  nigelhorne
 * Better handling of multipart/multipart messages
 *
 * Revision 1.60  2004/03/29 09:22:03  nigelhorne
 * Tidy up code and reduce shuffling of data
 *
 * Revision 1.59  2004/03/26 11:08:36  nigelhorne
 * Use cli_writen
 *
 * Revision 1.58  2004/03/25 22:40:46  nigelhorne
 * Removed even more calls to realloc and some duplicated code
 *
 * Revision 1.57  2004/03/21 17:19:49  nigelhorne
 * Handle bounce messages with no headers
 *
 * Revision 1.56  2004/03/21 09:41:26  nigelhorne
 * Faster scanning for non MIME messages
 *
 * Revision 1.55  2004/03/20 17:39:23  nigelhorne
 * First attempt to handle all bounces
 *
 * Revision 1.54  2004/03/19 15:40:45  nigelhorne
 * Handle empty content-disposition types
 *
 * Revision 1.53  2004/03/19 08:08:02  nigelhorne
 * If a message part of a multipart contains an RFC822 message that has no encoding don't scan it
 *
 * Revision 1.52  2004/03/18 21:51:41  nigelhorne
 * If a message only contains a single RFC822 message that has no encoding don't save for scanning
 *
 * Revision 1.51  2004/03/17 19:48:12  nigelhorne
 * Improved embedded RFC822 message handling
 *
 * Revision 1.50  2004/03/10 22:05:39  nigelhorne
 * Fix seg fault when a message in a multimessage mailbox fails to scan
 *
 * Revision 1.49  2004/03/04 13:01:58  nigelhorne
 * Ensure all bounces are rescanned by cl_mbox
 *
 * Revision 1.48  2004/02/27 12:16:26  nigelhorne
 * Catch lines just containing ':'
 *
 * Revision 1.47  2004/02/23 10:13:08  nigelhorne
 * Handle spaces before : in headers
 *
 * Revision 1.46  2004/02/18 13:29:19  nigelhorne
 * Stop buffer overflows for files with very long suffixes
 *
 * Revision 1.45  2004/02/18 10:07:40  nigelhorne
 * Find some Yaha
 *
 * Revision 1.44  2004/02/15 08:45:54  nigelhorne
 * Avoid scanning the same file twice
 *
 * Revision 1.43  2004/02/14 19:04:05  nigelhorne
 * Handle spaces in boundaries
 *
 * Revision 1.42  2004/02/14 17:23:45  nigelhorne
 * Had deleted O_BINARY by mistake
 *
 * Revision 1.41  2004/02/12 18:43:58  nigelhorne
 * Use mkstemp on Solaris
 *
 * Revision 1.40  2004/02/11 08:15:59  nigelhorne
 * Use O_BINARY for cygwin
 *
 * Revision 1.39  2004/02/06 13:46:08  kojm
 * Support for clamav-config.h
 *
 * Revision 1.38  2004/02/04 13:29:48  nigelhorne
 * Handle partial writes - and print when write fails
 *
 * Revision 1.37  2004/02/03 22:54:59  nigelhorne
 * Catch another example of Worm.Dumaru.Y
 *
 * Revision 1.36  2004/02/02 09:52:57  nigelhorne
 * Some instances of Worm.Dumaru.Y got through the net
 *
 * Revision 1.35  2004/01/28 10:15:24  nigelhorne
 * Added support to scan some bounce messages
 *
 * Revision 1.34  2004/01/24 17:43:37  nigelhorne
 * Removed (incorrect) warning about uninitialised variable
 *
 * Revision 1.33  2004/01/23 10:38:22  nigelhorne
 * Fixed memory leak in handling some multipart messages
 *
 * Revision 1.32  2004/01/23 08:51:19  nigelhorne
 * Add detection of uuencoded viruses in single part multipart/mixed files
 *
 * Revision 1.31  2004/01/22 22:13:06  nigelhorne
 * Prevent infinite recursion on broken uuencoded files
 *
 * Revision 1.30  2004/01/13 10:12:05  nigelhorne
 * Remove duplicate code when handling multipart messages
 *
 * Revision 1.29  2004/01/09 18:27:11  nigelhorne
 * ParseMimeHeader could corrupt arg
 *
 * Revision 1.28  2004/01/09 15:07:42  nigelhorne
 * Re-engineered update 1.11 lost in recent changes
 *
 * Revision 1.27  2004/01/09 14:45:59  nigelhorne
 * Removed duplicated code in multipart handler
 *
 * Revision 1.26  2004/01/09 10:20:54  nigelhorne
 * Locate uuencoded viruses hidden in text poritions of multipart/mixed mime messages
 *
 * Revision 1.25  2004/01/06 14:41:18  nigelhorne
 * Handle headers which do not not have a space after the ':'
 *
 * Revision 1.24  2003/12/20 13:55:36  nigelhorne
 * Ensure multipart just save the bodies of attachments
 *
 * Revision 1.23  2003/12/14 18:07:01  nigelhorne
 * Some viruses in embedded messages were not being found
 *
 * Revision 1.22  2003/12/13 16:42:23  nigelhorne
 * call new cli_chomp
 *
 * Revision 1.21  2003/12/11 14:35:48  nigelhorne
 * Better handling of encapsulated messages
 *
 * Revision 1.20  2003/12/06 04:03:26  nigelhorne
 * Handle hand crafted emails that incorrectly set multipart headers
 *
 * Revision 1.19  2003/11/21 07:26:31  nigelhorne
 * Scan multipart alternatives that have no boundaries, finds some uuencoded happy99
 *
 * Revision 1.18  2003/11/17 08:13:21  nigelhorne
 * Handle spaces at the end of lines of MIME headers
 *
 * Revision 1.17  2003/11/06 05:06:42  nigelhorne
 * Some applications weren't being scanned
 *
 * Revision 1.16  2003/11/04 08:24:00  nigelhorne
 * Handle multipart messages that have no text portion
 *
 * Revision 1.15  2003/10/12 20:13:49  nigelhorne
 * Use NO_STRTOK_R consistent with message.c
 *
 * Revision 1.14  2003/10/12 12:37:11  nigelhorne
 * Appledouble encoded EICAR now found
 *
 * Revision 1.13  2003/10/01 09:27:42  nigelhorne
 * Handle content-type header going over to a new line
 *
 * Revision 1.12  2003/09/29 17:10:19  nigelhorne
 * Moved stub from heap to stack since its maximum size is known
 *
 * Revision 1.11  2003/09/29 12:58:32  nigelhorne
 * Handle Content-Type: /; name="eicar.com"
 *
 * Revision 1.10  2003/09/28 10:06:34  nigelhorne
 * Compilable under SCO; removed duplicate code with message.c
 *
 */
static	char	const	rcsid[] = "$Id: mbox.c,v 1.176 2004/11/12 09:41:45 nigelhorne Exp $";

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#ifndef	CL_DEBUG
#define	NDEBUG	/* map CLAMAV debug onto standard */
#endif

#ifdef CL_THREAD_SAFE
#ifndef	_REENTRANT
#define	_REENTRANT	/* for Solaris 2.8 */
#endif
#endif

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/param.h>
#include <clamav.h>
#include <dirent.h>
#include <limits.h>

#if defined(HAVE_READDIR_R_3) || defined(HAVE_READDIR_R_2)
#include <stddef.h>
#endif

#ifdef	CL_THREAD_SAFE
#include <pthread.h>
#endif

#include "table.h"
#include "mbox.h"
#include "blob.h"
#include "line.h"
#include "text.h"
#include "message.h"
#include "others.h"
#include "defaults.h"
#include "str.h"

#ifdef	CL_DEBUG
#if __GLIBC__ == 2 && __GLIBC_MINOR__ >= 1
#define HAVE_BACKTRACE
#endif
#endif

#ifdef HAVE_BACKTRACE
#include <execinfo.h>
#include <signal.h>
#include <syslog.h>

static	void	sigsegv(int sig);
static	void	print_trace(int use_syslog);
#endif

#if	defined(NO_STRTOK_R) || !defined(CL_THREAD_SAFE)
#undef strtok_r
#undef __strtok_r
#define strtok_r(a,b,c)	strtok(a,b)
#endif

/* required for AIX and Tru64 */
#ifdef TRUE
#undef TRUE
#endif
#ifdef FALSE
#undef FALSE
#endif

typedef enum	{ FALSE = 0, TRUE = 1 } bool;

#define	SAVE_TO_DISC	/* multipart/message are saved in a temporary file */

/*
 * Code does exist to run FOLLORURLS on systems without libcurl, however that
 * is not recommended so it is not compiled by default
 */
#ifdef	WITH_CURL
#define	FOLLOWURLS	/*
			 * If an email contains URLs, check them - helps to
			 * find Dialer.gen-45
			 */
#endif

#ifdef	FOLLOWURLS

#include "htmlnorm.h"

#define	MAX_URLS	5	/*
				 * Maximum number of URLs scanned in a message
				 * part
				 */
#ifdef	WITH_CURL	/* Set in configure */
/*
 * To build with WITH_CURL:
 * LDFLAGS=`curl-config --libs` ./configure ...
 */
#include <curl/curl.h>

/*
 * Needs curl >= 7.11 (I've heard that 7.9 can cause crashes and 7.10 is
 * untested)
 */
#if	(LIBCURL_VERSION_MAJOR < 7)
#undef	WITH_CURL	/* also undef FOLLOWURLS? */
#endif

#if	(LIBCURL_VERSION_MAJOR == 7) && (LIBCURL_VERSION_MINOR < 10)
#undef	WITH_CURL	/* also undef FOLLOWURLS? */
#endif

#endif	/*WITH_CURL*/

#else	/*!FOLLOWURLS*/
#undef	WITH_CURL
#endif	/*FOLLOWURLS*/

/*
 * Define this to handle RFC1341 messages.
 *	This is experimental code so it is up to YOU to (1) ensure it's secure
 * (2) periodically trim the directory of old files
 *
 * If you use the load balancing feature of clamav-milter to run clamd on
 * more than one machine you must make sure that .../partial is on a shared
 * network filesystem
 */
#define	PARTIAL_DIR

static	message	*parseEmailHeaders(const message *m, const table_t *rfc821Table);
static	int	parseEmailHeader(message *m, const char *line, const table_t *rfc821Table);
static	int	parseEmailBody(message *messageIn, text *textIn, const char *dir, const table_t *rfc821Table, const table_t *subtypeTable, unsigned int options);
static	int	boundaryStart(const char *line, const char *boundary);
static	int	endOfMessage(const char *line, const char *boundary);
static	int	initialiseTables(table_t **rfc821Table, table_t **subtypeTable);
static	int	getTextPart(message *const messages[], size_t size);
static	size_t	strip(char *buf, int len);
static	bool	continuationMarker(const char *line);
static	int	parseMimeHeader(message *m, const char *cmd, const table_t *rfc821Table, const char *arg);
static	void	saveTextPart(message *m, const char *dir);
static	char	*rfc2047(const char *in);
static	char	*rfc822comments(const char *in);
#ifdef	PARTIAL_DIR
static	int	rfc1341(message *m, const char *dir);
#endif

static	void	checkURLs(message *m, const char *dir);
#ifdef	WITH_CURL
struct arg {
	const char *url;
	const char *dir;
	char *filename;
};
#ifdef	CL_THREAD_SAFE
static	void	*getURL(void *a);
#else
static	void	*getURL(struct arg *arg);
#endif
#endif

/* Maximum line length according to RFC821 */
#define	LINE_LENGTH	1000

/* Hashcodes for our hash tables */
#define	CONTENT_TYPE			1
#define	CONTENT_TRANSFER_ENCODING	2
#define	CONTENT_DISPOSITION		3

/* Mime sub types */
#define	PLAIN		1
#define	ENRICHED	2
#define	HTML		3
#define	RICHTEXT	4
#define	MIXED		5
#define	ALTERNATIVE	6
#define	DIGEST		7
#define	SIGNED		8
#define	PARALLEL	9
#define	RELATED		10	/* RFC2387 */
#define	REPORT		11	/* RFC1892 */
#define	APPLEDOUBLE	12	/* Handling of this in only noddy for now */
#define	FAX		MIXED	/*
				 * RFC3458
				 * Drafts stated to treat is as mixed if it is
				 * not known.  This disappeared in the final
				 * version (except when talking about
				 * voice-message), but it is good enough for us
				 * since we do no validation of coversheet
				 * presence etc. (which also has disappeared
				 * in the final version)
				 */
#define	ENCRYPTED	13	/*
				 * e.g. RFC2015
				 * Content-Type: multipart/encrypted;
				 * boundary="nextPart1383049.XCRrrar2yq";
				 * protocol="application/pgp-encrypted"
				 */
#define	X_BFILE		RELATED	/*
				 * BeOS, expert two parts: the file and it's
				 * attributes. The attributes part comes as
				 *	Content-Type: application/x-be_attribute
				 *		name="foo"
				 * I can't find where it is defined, any
				 * pointers would be appreciated. For now
				 * we treat it as multipart/related
				 */
#define	KNOWBOT		14	/* Unknown and undocumented format? */

static	const	struct tableinit {
	const	char	*key;
	int	value;
} rfc821headers[] = {
	/* TODO: make these regular expressions */
	{	"Content-Type",			CONTENT_TYPE		},
	{	"Content-Transfer-Encoding",	CONTENT_TRANSFER_ENCODING	},
	{	"Content-Disposition",		CONTENT_DISPOSITION	},
	{	NULL,				0			}
}, mimeSubtypes[] = {	/* see RFC2045 */
		/* subtypes of Text */
	{	"plain",	PLAIN		},
	{	"enriched",	ENRICHED	},
	{	"html",		HTML		},
	{	"richtext",	RICHTEXT	},
		/* subtypes of Multipart */
	{	"mixed",	MIXED		},
	{	"alternative",	ALTERNATIVE	},
	{	"digest",	DIGEST		},
	{	"signed",	SIGNED		},
	{	"parallel",	PARALLEL	},
	{	"related",	RELATED		},
	{	"report",	REPORT		},
	{	"appledouble",	APPLEDOUBLE	},
	{	"fax-message",	FAX		},
	{	"encrypted",	ENCRYPTED	},
	{	"x-bfile",	X_BFILE		},	/* BeOS */
	{	"knowbot",		KNOWBOT		},	/* ??? */
	{	"knowbot-metadata",	KNOWBOT		},	/* ??? */
	{	"knowbot-code",		KNOWBOT		},	/* ??? */
	{	"knowbot-state",	KNOWBOT		},	/* ??? */
	{	NULL,		0		}
};

#ifdef	CL_THREAD_SAFE
static	pthread_mutex_t	tables_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

/* Maximum filenames under various systems */
#ifndef	NAME_MAX	/* e.g. Linux */

#ifdef	MAXNAMELEN	/* e.g. Solaris */
#define	NAME_MAX	MAXNAMELEN
#else

#ifdef	FILENAME_MAX	/* e.g. SCO */
#define	NAME_MAX	FILENAME_MAX
#endif

#endif

#endif

#ifndef	O_BINARY
#define	O_BINARY	0
#endif

/*
 * TODO: when signal handling is added, need to remove temp files when a
 *	signal is received
 * TODO: add option to scan in memory not via temp files, perhaps with a
 * named pipe or memory mapped file, though this won't work on big e-mails
 * containing many levels of encapsulated messages - it'd just take too much
 * RAM
 * TODO: parse .msg format files
 * TODO: fully handle AppleDouble format, see
 *	http://www.lazerware.com/formats/Specs/AppleSingle_AppleDouble.pdf
 * TODO: ensure parseEmailHeaders is always called before parseEmailBody
 * TODO: create parseEmail which calls parseEmailHeaders then parseEmailBody
 * TODO: Look into TNEF. Is there anything that needs to be done here?
 */
int
cli_mbox(const char *dir, int desc, unsigned int options)
{
	int retcode, i;
	message *m, *body;
	FILE *fd;
	char buffer[LINE_LENGTH + 1];
#ifdef HAVE_BACKTRACE
	void (*segv)(int);
#endif
	static table_t *rfc821, *subtype;

	cli_dbgmsg("in mbox()\n");

	i = dup(desc);
	if((fd = fdopen(i, "rb")) == NULL) {
		cli_errmsg("Can't open descriptor %d\n", desc);
		close(i);
		return CL_EOPEN;
	}
	if(fgets(buffer, sizeof(buffer) - 1, fd) == NULL) {
		/* empty message */
		fclose(fd);
		return CL_CLEAN;
	}
	m = messageCreate();
	if(m == NULL) {
		fclose(fd);
		return CL_EMEM;
	}

#ifdef	CL_THREAD_SAFE
	pthread_mutex_lock(&tables_mutex);
#endif
	if(rfc821 == NULL) {
		assert(subtype == NULL);

		if(initialiseTables(&rfc821, &subtype) < 0) {
			rfc821 = NULL;
			subtype = NULL;
#ifdef	CL_THREAD_SAFE
			pthread_mutex_unlock(&tables_mutex);
#endif
			messageDestroy(m);
			fclose(fd);
			return CL_EMEM;
		}
	}
#ifdef	CL_THREAD_SAFE
	pthread_mutex_unlock(&tables_mutex);
#endif

#ifdef HAVE_BACKTRACE
	segv = signal(SIGSEGV, sigsegv);
#endif

	/*
	 * is it a UNIX style mbox with more than one
	 * mail message, or just a single mail message?
	 */
	if(strncmp(buffer, "From ", 5) == 0) {
		/*
		 * Have been asked to check a UNIX style mbox file, which
		 * may contain more than one e-mail message to decode
		 */
		bool lastLineWasEmpty = FALSE;
		int messagenumber = 1;

		do {
			/*cli_dbgmsg("read: %s", buffer);*/

			cli_chomp(buffer);
			if(lastLineWasEmpty && (strncmp(buffer, "From ", 5) == 0)) {
				cli_dbgmsg("Deal with email number %d\n", messagenumber++);
				/*
				 * End of a message in the mail box
				 */
				body = parseEmailHeaders(m, rfc821);
				if(body == NULL) {
					messageReset(m);
					continue;
				}
				messageDestroy(m);
				if(messageGetBody(body))
					if(!parseEmailBody(body, NULL, dir, rfc821, subtype, options)) {
						messageReset(body);
						m = body;
						continue;
					}
				/*
				 * Starting a new message, throw away all the
				 * information about the old one
				 */
				m = body;
				messageReset(body);

				cli_dbgmsg("Finished processing message\n");
			} else
				lastLineWasEmpty = (bool)(buffer[0] == '\0');
			if(messageAddStr(m, buffer) < 0)
				break;
		} while(fgets(buffer, sizeof(buffer) - 1, fd) != NULL);

		cli_dbgmsg("Deal with email number %d\n", messagenumber);
	} else {
		/*
		 * It's a single message, parse the headers then the body
		 * Ignore blank lines at the start of the message
		 */
		if(strncmp(buffer, "P I ", 4) == 0)
			/*
			 * CommuniGate Pro format: ignore headers until
			 * blank line
			 */
			while((fgets(buffer, sizeof(buffer) - 1, fd) != NULL) &&
				(strchr("\r\n", buffer[0]) == NULL))
					;
		/*
		 * Ignore any blank lines at the top of the message
		 */
		while(strchr("\r\n", buffer[0]) &&
		     (fgets(buffer, sizeof(buffer) - 1, fd) != NULL))
			;

		buffer[LINE_LENGTH] = '\0';

		/*
		 * FIXME: files full of new lines and nothing else are
		 * handled ungracefully...
		 */
		do {
			/*
			 * TODO: this needlessly creates a message object,
			 * it'd be better if parseEmailHeaders could also
			 * read in from a file. I do not want to lump the
			 * parseEmailHeaders code here, that'd be a duplication
			 * of code I want to avoid
			 */
			(void)cli_chomp(buffer);
			if(messageAddStr(m, buffer) < 0)
				break;
		} while(fgets(buffer, sizeof(buffer) - 1, fd) != NULL);
	}

	fclose(fd);

	/*
	 * This is not necessarily true, but since the only options are
	 * CL_CLEAN and CL_VIRUS this is the better choice. It would be
	 * nice to have CL_CONTINUESCANNING or something like that
	 */
	retcode = CL_CLEAN;

	body = parseEmailHeaders(m, rfc821);
	messageDestroy(m);
	if(body) {
		/*
		 * Write out the last entry in the mailbox
		 */
		if(messageGetBody(body))
			if(!parseEmailBody(body, NULL, dir, rfc821, subtype, options))
				retcode = CL_EFORMAT;

		/*
		 * Tidy up and quit
		 */
		messageDestroy(body);
	}

	cli_dbgmsg("cli_mbox returning %d\n", retcode);

#ifdef HAVE_BACKTRACE
	signal(SIGSEGV, segv);
#endif

	return retcode;
}

/*
 * The given message contains a raw e-mail.
 *
 * This function parses the headers of m and sets the message's arguments
 *
 * Returns the message's body with the correct arguments set
 *
 * The downside of this approach is that for a short time we have two copies
 * of the message in memory, the upside is that it makes for easier parsing
 * of encapsulated messages, and in the long run uses less memory in those
 * scenarios
 */
static message *
parseEmailHeaders(const message *m, const table_t *rfc821)
{
	bool inHeader = TRUE;
	bool contMarker = FALSE;
	const text *t;
	message *ret;
	bool anyHeadersFound = FALSE;
	int commandNumber = -1;
	char *fullline = NULL;
	size_t fulllinelength = 0;

	cli_dbgmsg("parseEmailHeaders\n");

	if(m == NULL)
		return NULL;

	ret = messageCreate();

	for(t = messageGetBody(m); t; t = t->t_next) {
		const char *buffer;

		if(t->t_line)
			buffer = lineGetData(t->t_line);
		else
			buffer = NULL;

		if(inHeader) {
			if(buffer == NULL) {
				/*
				 * A blank line signifies the end of the header
				 * and the start of the text
				 */
				cli_dbgmsg("End of header information\n");
				inHeader = FALSE;
			} else {
				char *ptr;
				bool inquotes = FALSE;
				bool arequotes = FALSE;
				const char *qptr;
				int quotes;
#ifdef CL_THREAD_SAFE
				char *strptr;
#endif
				char cmd[LINE_LENGTH + 1];

				if(fullline == NULL) {
					commandNumber = tableFind(rfc821, buffer);
					fullline = strdup("");
					fulllinelength = 1;
				}
				fulllinelength += strlen(buffer);
				fullline = cli_realloc(fullline, fulllinelength);
				strcat(fullline, buffer);

				contMarker = continuationMarker(buffer);
				if(contMarker)
					continue;

				if(t->t_next && (t->t_next->t_line != NULL)) {
					const char *next = lineGetData(t->t_next->t_line);

					/*
					 * Section B.2 of RFC822 says TAB or SPACE means
					 * a continuation of the previous entry.
					 *
					 * Add all the arguments on the line
					 */
					if((next[0] == '\t') || (next[0] == ' '))
						continue;
				}

				quotes = 0;
				for(qptr = buffer; *qptr; qptr++)
					if(*qptr == '\"')
						quotes++;

				if(quotes & 1) {
					contMarker = TRUE;
					continue;
				}

				ptr = rfc822comments(fullline);
				if(ptr) {
					free(fullline);
					fullline = ptr;
				}
				if(cli_strtokbuf(fullline, 0, ":", cmd) != NULL) {
					anyHeadersFound = TRUE;
					commandNumber = tableFind(rfc821, cmd);
				}

				switch(commandNumber) {
					case CONTENT_TRANSFER_ENCODING:
					case CONTENT_DISPOSITION:
					case CONTENT_TYPE:
						break;
					default:
						free(fullline);
						fullline = NULL;
						continue;
				}

				if(parseEmailHeader(ret, fullline, rfc821) < 0)
					continue;

				/*
				 * Ensure that the colon in headers such as
				 * this doesn't get mistaken for a token
				 * separator
				 *	boundary="=.J:gysAG)N(3_zv"
				 */
				for(ptr = fullline; *ptr; ptr++)
					if(*ptr == '\"')
						inquotes = !inquotes;
					else if(inquotes) {
						*ptr |= '\200';
						arequotes = TRUE;
					}

#ifdef	CL_THREAD_SAFE
				for(ptr = strtok_r(fullline, ";", &strptr); ptr; ptr = strtok_r(NULL, ":", &strptr))
					if(strchr(ptr, '=')) {
						if(arequotes) {
							char *p2;
							for(p2 = ptr; *p2; p2++)
								*p2 &= '\177';
						}
						messageAddArguments(ret, ptr);
					}
#else
				for(ptr = strtok(fullline, ";"); ptr; ptr = strtok(NULL, ":"))
					if(strchr(ptr, '=')) {
						if(arequotes) {
							char *p2;
							for(p2 = ptr; *p2; p2++)
								*p2 &= '\177';
						}
						messageAddArguments(ret, ptr);
					}
#endif
				free(fullline);
				fullline = NULL;
			}
		} else {
			/*cli_dbgmsg("Add line to body '%s'\n", buffer);*/
			if(messageAddLine(ret, t->t_line) < 0)
				break;
		}
	}

	if(fullline) {
		if(*fullline) switch(commandNumber) {
			case CONTENT_TRANSFER_ENCODING:
			case CONTENT_DISPOSITION:
			case CONTENT_TYPE:
				cli_warnmsg("parseEmailHeaders: Fullline set '%s' - report to bugs@clamav.net\n", fullline);
		}
		free(fullline);
	}

	if(!anyHeadersFound) {
		/*
		 * False positive in believing we have an e-mail when we don't
		 */
		messageDestroy(ret);
		cli_dbgmsg("parseEmailHeaders: no headers found, assuming it isn't an email\n");
		return NULL;
	}

	messageClean(ret);

	cli_dbgmsg("parseEmailHeaders: return\n");

	return ret;
}

/*
 * Handle a header line of an email message
 */
static int
parseEmailHeader(message *m, const char *line, const table_t *rfc821)
{
	char *cmd;
	int ret = -1;
#ifdef CL_THREAD_SAFE
	char *strptr;
#endif
	const char *separater;
	char *copy, tokenseparater[2];

	cli_dbgmsg("parseEmailHeader '%s'\n", line);

	/*
	 * In RFC822 the separater between the key a value is a colon,
	 * e.g.	Content-Transfer-Encoding: base64
	 * However some MUA's are lapse about this and virus writers exploit
	 * this hole, so we need to check all known possiblities
	 */
	for(separater = ":= "; *separater; separater++)
		if(strchr(line, *separater) != NULL)
			break;

	if(*separater == '\0')
		return -1;

	copy = rfc2047(line);
	if(copy == NULL)
		return -1;

	tokenseparater[0] = *separater;
	tokenseparater[1] = '\0';

#ifdef	CL_THREAD_SAFE
	cmd = strtok_r(copy, tokenseparater, &strptr);
#else
	cmd = strtok(copy, tokenseparater);
#endif

	if(cmd && (strstrip(cmd) > 0)) {
#ifdef	CL_THREAD_SAFE
		char *arg = strtok_r(NULL, "", &strptr);
#else
		char *arg = strtok(NULL, "");
#endif

		if(arg)
			/*
			 * Found a header such as
			 * Content-Type: multipart/mixed;
			 * set arg to be
			 * "multipart/mixed" and cmd to
			 * be "Content-Type"
			 */
			ret = parseMimeHeader(m, cmd, rfc821, arg);
	}
	free(copy);
	return ret;
}

/*
 * This is a recursive routine.
 *
 * This function parses the body of mainMessage and saves its attachments in dir
 *
 * mainMessage is the buffer to be parsed, it contains an e-mail's body, without
 * any headers. First time of calling it'll be
 * the whole message. Later it'll be parts of a multipart message
 * textIn is the plain text message being built up so far
 *
 * Returns:
 *	0 for fail
 *	1 for success, attachments saved
 *	2 for success, attachments not saved
 */
static int	/* success or fail */
parseEmailBody(message *messageIn, text *textIn, const char *dir, const table_t *rfc821Table, const table_t *subtypeTable, unsigned int options)
{
	message **messages;	/* parts of a multipart message */
	int inhead, inMimeHead, i, rc = 1, htmltextPart, multiparts = 0;
	text *aText;
	const char *cptr;
	message *mainMessage;
	fileblob *fb;

	cli_dbgmsg("in parseEmailBody\n");

	aText = textIn;
	messages = NULL;
	mainMessage = messageIn;

	/* Anything left to be parsed? */
	if(mainMessage && (messageGetBody(mainMessage) != NULL)) {
		mime_type mimeType;
		int subtype;
		const char *mimeSubtype, *boundary;
		char *protocol;
		const text *t_line;
		/*bool isAlternative;*/
		message *aMessage;

		cli_dbgmsg("Parsing mail file\n");

		mimeType = messageGetMimeType(mainMessage);
		mimeSubtype = messageGetMimeSubtype(mainMessage);

		subtype = tableFind(subtypeTable, mimeSubtype);
		if((mimeType == TEXT) && (subtype == PLAIN)) {
			/*
			 * This is effectively no encoding, notice that we
			 * don't check that charset is us-ascii
			 */
			cli_dbgmsg("assume no encoding\n");
			mimeType = NOMIME;
			messageSetMimeSubtype(mainMessage, NULL);
		}

		cli_dbgmsg("mimeType = %d\n", mimeType);

		switch(mimeType) {
		case NOMIME:
			aText = textAddMessage(aText, mainMessage);
			break;
		case TEXT:
			if(subtype == PLAIN)
				/*
				 * Consider what to do if this fails
				 * (i.e. aText == NULL):
				 * We mustn't just return since that could
				 * cause a virus to be missed that we
				 * could be capable of scanning. Ignoring
				 * the error is probably the safest, we may be
				 * able to scan anyway and we lose nothing
				 */
				aText = textCopy(messageGetBody(mainMessage));
			else if((options&CL_SCAN_MAILURL) && (subtype == HTML))
				checkURLs(mainMessage, dir);
			break;
		case MULTIPART:
			boundary = messageFindArgument(mainMessage, "boundary");

			if(boundary == NULL) {
				cli_warnmsg("Multipart MIME message contains no boundaries\n");
				/* Broken e-mail message */
				mimeType = NOMIME;
				/*
				 * The break means that we will still
				 * check if the file contains a uuencoded file
				 */
				break;
			}

			/* Perhaps it should assume mixed? */
			if(mimeSubtype[0] == '\0') {
				cli_warnmsg("Multipart has no subtype assuming alternative\n");
				mimeSubtype = "alternative";
				messageSetMimeSubtype(mainMessage, "alternative");
			}

			/*
			 * Get to the start of the first message
			 */
			t_line = messageGetBody(mainMessage);

			if(t_line == NULL) {
				cli_warnmsg("Multipart MIME message has no body\n");
				free((char *)boundary);
				mimeType = NOMIME;
				break;
			}

			do
				if(t_line->t_line) {
					if(boundaryStart(lineGetData(t_line->t_line), boundary))
						break;
					/*
					 * Found a uuencoded file before the first multipart
					 * TODO: check yEnc and binhex here
					 */
					if(uuencodeBegin(mainMessage) == t_line)
						if(messageGetEncoding(mainMessage) == NOENCODING) {
							messageSetEncoding(mainMessage, "x-uuencode");
							fb = messageToFileblob(mainMessage, dir);

							if(fb)
								fileblobDestroy(fb);
						}
				}
			while((t_line = t_line->t_next) != NULL);

			if(t_line == NULL) {
				cli_dbgmsg("Multipart MIME message contains no boundary lines\n");
				/*
				 * Free added by Thomas Lamy
				 * <Thomas.Lamy@in-online.net>
				 */
				free((char *)boundary);
				mimeType = NOMIME;
				/*
				 * The break means that we will still
				 * check if the file contains a uuencoded file
				 */
				break;
			}
			/*
			 * Build up a table of all of the parts of this
			 * multipart message. Remember, each part may itself
			 * be a multipart message.
			 */
			inhead = 1;
			inMimeHead = 0;

			/*
			 * Parse the mainMessage object and create an array
			 * of objects called messages, one for each of the
			 * multiparts that mainMessage contains
			 *
			 * This looks like parseEmailHeaders() - maybe there's
			 * some duplication of code to be cleaned up
			 */
			for(multiparts = 0; t_line; multiparts++) {
				int lines = 0;
				message **m;

				m = cli_realloc(messages, ((multiparts + 1) * sizeof(message *)));
				if(m == NULL)
					break;
				messages = m;

				aMessage = messages[multiparts] = messageCreate();
				if(aMessage == NULL) {
					multiparts--;
					continue;
				}

				cli_dbgmsg("Now read in part %d\n", multiparts);

				/*
				 * Ignore blank lines. There shouldn't be ANY
				 * but some viruses insert them
				 */
				while((t_line = t_line->t_next) != NULL)
					if(t_line->t_line &&
					   /*(cli_chomp(t_line->t_text) > 0))*/
					   (strlen(lineGetData(t_line->t_line)) > 0))
						break;

				if(t_line == NULL) {
					cli_dbgmsg("Empty part\n");
					/*
					 * Remove this part unless there's
					 * a uuencoded portion somewhere in
					 * the complete message that we may
					 * throw away by mistake if the MIME
					 * encoding information is incorrect
					 */
					if(uuencodeBegin(mainMessage) == NULL) {
						messageDestroy(aMessage);
						--multiparts;
					}
					continue;
				}

				do {
					const char *line = lineGetData(t_line->t_line);

					/*cli_dbgmsg("inMimeHead %d inhead %d boundary %s line '%s' next '%s'\n",
						inMimeHead, inhead, boundary, line, t_line->t_next ? t_line->t_next->t_text : "(null)");*/

					if(inMimeHead) {	/* continuation line */
						if(line == NULL) {
							inhead = inMimeHead = 0;
							continue;
						}
						/*
						 * Handle continuation lines
						 * because the previous line
						 * ended with a ; or this line
						 * starts with a white space
						 */
						cli_dbgmsg("Multipart %d: About to add mime Argument '%s'\n",
							multiparts, line);
						/*
						 * Handle the case when it
						 * isn't really a continuation
						 * line:
						 * Content-Type: application/octet-stream;
						 * Content-Transfer-Encoding: base64
						 */
						parseEmailHeader(aMessage, line, rfc821Table);

						while(isspace((int)*line))
							line++;

						if(*line == '\0') {
							inhead = inMimeHead = 0;
							continue;
						}
						/*
						 * This may cause a trailing ';'
						 * to be added if this test
						 * fails - TODO: verify this
						 */
						inMimeHead = continuationMarker(line);
						messageAddArgument(aMessage, line);
					} else if(inhead) {	/* handling normal headers */
						char *ptr;

						if(line == NULL) {
							/* empty line */
							inhead = 0;
							continue;
						}
						if(isspace((int)*line)) {
							/*
							 * The first line is
							 * continuation line.
							 * This is tricky
							 * to handle, but
							 * all we can do is our
							 * best
							 */
							cli_dbgmsg("Part %d starts with a continuation line\n",
								multiparts);
							messageAddArgument(aMessage, line);
							/*
							 * Give it a default
							 * MIME type since
							 * that may be the
							 * missing line
							 *
							 * Choose application to
							 * force a save
							 */
							if(messageGetMimeType(aMessage) == NOMIME)
								messageSetMimeType(aMessage, "application");
							continue;
						}

						/*
						 * Some clients are broken and
						 * put white space after the ;
						 */
						inMimeHead = continuationMarker(line);
						if(!inMimeHead) {
							const text *next = t_line->t_next;
							char *fullline;
							int quotes = 0;
							const char *qptr;

							assert(strlen(line) <= LINE_LENGTH);

							fullline = rfc822comments(line);
							if(fullline == NULL)
								fullline = strdup(line);

							for(qptr = fullline; *qptr; qptr++)
								if(*qptr == '\"')
									quotes++;

							/*
							 * Fold next lines to the end of this
							 * if they start with a white space
							 * or if this line has an odd number of quotes:
							 * Content-Type: application/octet-stream; name="foo
							 * "
							 */
							while(next && next->t_line) {
								const char *data = lineGetData(next->t_line);

								if((!isspace(data[0])) &&
								   ((quotes & 1) == 0))
									break;

								ptr = cli_realloc(fullline,
									strlen(fullline) + strlen(data) + 1);

								if(ptr == NULL)
									break;

								fullline = ptr;
								strcat(fullline, data);

								for(qptr = data; *qptr; qptr++)
									if(*qptr == '\"')
										quotes++;

								t_line = next;
								next = next->t_next;
							}
							cli_dbgmsg("Multipart %d: About to parse folded header '%s'\n",
								multiparts, fullline);

							parseEmailHeader(aMessage, fullline, rfc821Table);
							free(fullline);
						} else {
							cli_dbgmsg("Multipart %d: About to parse header '%s'\n",
								multiparts, line);

							ptr = rfc822comments(line);

							parseEmailHeader(aMessage, (ptr) ? ptr : line, rfc821Table);

							if(ptr)
								free(ptr);
						}
					} else if(boundaryStart(line, boundary)) {
						inhead = 1;
						break;
					} else if(endOfMessage(line, boundary)) {
						/*
						 * Some viruses put information
						 * *after* the end of message,
						 * which presumably some broken
						 * mail clients find, so we
						 * can't assume that this
						 * is the end of the message
						 */
						/* t_line = NULL;*/
						break;
					} else {
						if(messageAddLine(aMessage, t_line->t_line) < 0)
							break;
						lines++;
					}
				} while((t_line = t_line->t_next) != NULL);

				messageClean(aMessage);

				cli_dbgmsg("Part %d has %d lines\n",
					multiparts, lines);
			}

			free((char *)boundary);

			/*
			 * Preprocess. Anything special to be done before
			 * we handle the multiparts?
			 */
			switch(tableFind(subtypeTable, mimeSubtype)) {
				case KNOWBOT:
					/* TODO */
					cli_dbgmsg("multipart/knowbot parsed as multipart/mixed for now\n");
					mimeSubtype = "mixed";
					break;
			}

			/*
			 * We've finished message we're parsing
			 */
			if(mainMessage && (mainMessage != messageIn)) {
				messageDestroy(mainMessage);
				mainMessage = NULL;
			}

			if(multiparts == 0) {
				if(messages)
					free(messages);
				return 2;	/* Nothing to do */
			}

			cli_dbgmsg("The message has %d parts\n", multiparts);
			cli_dbgmsg("Find out the multipart type (%s)\n", mimeSubtype);

			/*
			 * We now have all the parts of the multipart message
			 * in the messages array:
			 *	message *messages[multiparts]
			 * Let's decide what to do with them all
			 */
			switch(tableFind(subtypeTable, mimeSubtype)) {
			case RELATED:
				cli_dbgmsg("Multipart related handler\n");
				/*
				 * Have a look to see if there's HTML code
				 * which will need scanning
				 */
				aMessage = NULL;
				assert(multiparts > 0);

				htmltextPart = getTextPart(messages, multiparts);

				if(htmltextPart >= 0)
					aText = textAddMessage(aText, messages[htmltextPart]);
				else
					/*
					 * There isn't an HTML bit. If there's a
					 * multipart bit, it'll may be in there
					 * somewhere
					 */
					for(i = 0; i < multiparts; i++)
						if(messageGetMimeType(messages[i]) == MULTIPART) {
							aMessage = messages[i];
							htmltextPart = i;
							break;
						}

				if(htmltextPart == -1)
					cli_dbgmsg("No HTML code found to be scanned");
				else {
					rc = parseEmailBody(aMessage, aText, dir, rfc821Table, subtypeTable, options);
					if(rc == 1) {
						assert(aMessage == messages[htmltextPart]);
						messageDestroy(aMessage);
						messages[htmltextPart] = NULL;
					}
				}

				/*
				 * Fixed based on an idea from Stephen White <stephen@earth.li>
				 * The message is confused about the difference
				 * between alternative and related. Badtrans.B
				 * suffers from this problem.
				 *
				 * Fall through in this case:
				 * Content-Type: multipart/related;
				 *	type="multipart/alternative"
				 */
				/*
				 * Changed to always fall through based on
				 * an idea from Michael Dankov <misha@btrc.ru>
				 * that some viruses are completely confused
				 * about the difference between related
				 * and mixed
				 */
				/*cptr = messageFindArgument(mainMessage, "type");
				if(cptr == NULL)
					break;
				isAlternative = (bool)(strcasecmp(cptr, "multipart/alternative") == 0);
				free((char *)cptr);
				if(!isAlternative)
					break;*/
			case DIGEST:
				/*
				 * According to section 5.1.5 RFC2046, the
				 * default mime type of multipart/digest parts
				 * is message/rfc822
				 *
				 * We consider them as alternative, wrong in
				 * the strictest sense since they aren't
				 * alternatives - all parts a valid - but it's
				 * OK for our needs since it means each part
				 * will be scanned
				 */
			case ALTERNATIVE:
				cli_dbgmsg("Multipart alternative handler\n");

#if	0
				htmltextPart = getTextPart(messages, multiparts);

				if(htmltextPart == -1)
					htmltextPart = 0;

				aMessage = messages[htmltextPart];
				aText = textAddMessage(aText, aMessage);

				rc = parseEmailBody(NULL, aText, dir, rfc821Table, subtypeTable, options);

				if(rc == 1)
					/*
					 * Alternative message has saved its
					 * attachments, ensure we don't do
					 * the same thing
					 */
					rc = 2;
#endif

				/*
				 * Fall through - some clients are broken and
				 * say alternative instead of mixed. The Klez
				 * virus is broken that way
				 */
			case REPORT:
				/*
				 * According to section 1 of RFC1892, the
				 * syntax of multipart/report is the same
				 * as multipart/mixed. There are some required
				 * parameters, but there's no need for us to
				 * verify that they exist
				 */
			case MIXED:
			case APPLEDOUBLE:	/* not really supported */
				/*
				 * Look for attachments
				 *
				 * Not all formats are supported. If an
				 * unsupported format turns out to be
				 * common enough to implement, it is a simple
				 * matter to add it
				 */
				if(aText) {
					if(mainMessage && (mainMessage != messageIn))
						messageDestroy(mainMessage);
					mainMessage = NULL;
				}

				cli_dbgmsg("Mixed message with %d parts\n", multiparts);
				for(i = 0; i < multiparts; i++) {
					bool addAttachment = FALSE;
					bool addToText = FALSE;
					const char *dtype;
#ifndef	SAVE_TO_DISC
					message *body;
#endif

					aMessage = messages[i];

					if(aMessage == NULL)
						continue;

					dtype = messageGetDispositionType(aMessage);
					cptr = messageGetMimeSubtype(aMessage);

					cli_dbgmsg("Mixed message part %d is of type %d\n",
						i, messageGetMimeType(aMessage));

					switch(messageGetMimeType(aMessage)) {
					case APPLICATION:
#if	0
						/* strict checking... */
						if((strcasecmp(dtype, "attachment") == 0) ||
						   (strcasecmp(cptr, "x-msdownload") == 0) ||
						   (strcasecmp(cptr, "octet-stream") == 0) ||
						   (strcasecmp(dtype, "octet-stream") == 0))
							addAttachment = TRUE;
						else {
							cli_dbgmsg("Discarded mixed/application not sent as attachment\n");
							continue;
						}
#endif
						addAttachment = TRUE;

						break;
					case NOMIME:
						if(mainMessage) {
							const text *u_line = uuencodeBegin(mainMessage);
							if(u_line) {
								cli_dbgmsg("Found uuencoded message in multipart/mixed mainMessage\n");
								messageSetEncoding(mainMessage, "x-uuencode");
								fb = messageToFileblob(mainMessage, dir);

								if(fb)
									fileblobDestroy(fb);
							}
							if(mainMessage != messageIn)
								messageDestroy(mainMessage);
							mainMessage = NULL;
						}
						addToText = TRUE;
						if(messageGetBody(aMessage) == NULL)
							/*
							 * No plain text version
							 */
							messageAddStr(aMessage, "No plain text alternative");
						assert(messageGetBody(aMessage) != NULL);
						break;
					case TEXT:
						cli_dbgmsg("Mixed message text part disposition \"%s\"\n",
							dtype);
						if(strcasecmp(dtype, "attachment") == 0)
							addAttachment = TRUE;
						else if((*dtype == '\0') || (strcasecmp(dtype, "inline") == 0)) {
							const text *u_line = uuencodeBegin(aMessage);

							if(mainMessage && (mainMessage != messageIn))
								messageDestroy(mainMessage);
							mainMessage = NULL;
							cli_dbgmsg("Mime subtype \"%s\"\n", cptr);
							if(u_line) {
								cli_dbgmsg("Found uuencoded message in multipart/mixed text portion\n");
								messageSetEncoding(aMessage, "x-uuencode");
								addAttachment = TRUE;
							} else if(tableFind(subtypeTable, cptr) == PLAIN) {
								char *filename;
								/*
								 * Strictly speaking
								 * a text/plain part is
								 * not an attachment. We
								 * pretend it is so that
								 * we can decode and
								 * scan it
								 */
								filename = (char *)messageFindArgument(aMessage, "filename");
								if(filename == NULL)
									filename = (char *)messageFindArgument(aMessage, "name");

								if(filename == NULL) {
									cli_dbgmsg("Adding part to main message\n");
									addToText = TRUE;
								} else {
									cli_dbgmsg("Treating %s as attachment\n",
										filename);
									free(filename);
									addAttachment = TRUE;
								}
							} else {
								if(options&CL_SCAN_MAILURL)
									if(tableFind(subtypeTable, cptr) == HTML)
										checkURLs(aMessage, dir);
								messageAddArgument(aMessage, "filename=textportion");
								addAttachment = TRUE;
							}
						} else {
							cli_dbgmsg("Text type %s is not supported\n", dtype);
							continue;
						}
						break;
					case MESSAGE:
						/* Content-Type: message/rfc822 */
						cli_dbgmsg("Found message inside multipart\n");
						if(encodingLine(aMessage) == NULL) {
							assert(aMessage == messages[i]);
							messageDestroy(messages[i]);
							messages[i] = NULL;
							continue;
						}
						messageAddStrAtTop(aMessage,
							"Received: by clamd");
#ifdef	SAVE_TO_DISC
						/*
						 * Save this embedded message
						 * to a temporary file
						 */
						saveTextPart(aMessage, dir);
						assert(aMessage == messages[i]);
						messageDestroy(messages[i]);
						messages[i] = NULL;
#else
						/*
						 * Scan in memory, faster but
						 * is open to DoS attacks when
						 * many nested levels are
						 * involved.
						 */
						body = parseEmailHeaders(aMessage, rfc821Table, TRUE);
						/*
						 * We've fininished with the
						 * original copy of the message,
						 * so throw that away and
						 * deal with the encapsulated
						 * message as a message.
						 * This can save a lot of memory
						 */
						assert(aMessage == messages[i]);
						messageDestroy(messages[i]);
						messages[i] = NULL;
						if(body) {
							rc = parseEmailBody(body, NULL, dir, rfc821Table, subtypeTable, options);
							messageDestroy(body);
						}
#endif
						continue;
					case MULTIPART:
						/*
						 * It's a multi part within a multi part
						 * Run the message parser on this bit, it won't
						 * be an attachment
						 */
						cli_dbgmsg("Found multipart inside multipart\n");
						if(aMessage) {
							/*
							 * The headers were parsed when reading in the
							 * whole multipart section
							 */
							rc = parseEmailBody(aMessage, aText, dir, rfc821Table, subtypeTable, options);
							cli_dbgmsg("Finished recursion\n");
							assert(aMessage == messages[i]);
							messageDestroy(messages[i]);
							messages[i] = NULL;
						} else {
							rc = parseEmailBody(NULL, NULL, dir, rfc821Table, subtypeTable, options);
							if(mainMessage && (mainMessage != messageIn))
								messageDestroy(mainMessage);
							mainMessage = NULL;
						}
						continue;
					case AUDIO:
					case IMAGE:
					case VIDEO:
						addAttachment = TRUE;
						break;
					default:
						cli_warnmsg("Only text and application attachments are supported, type = %d\n",
							messageGetMimeType(aMessage));
						continue;
					}

					/*
					 * It must be either text or
					 * an attachment. It can't be both
					 */
					assert(addToText || addAttachment);
					assert(!(addToText && addAttachment));

					if(addToText)
						aText = textAdd(aText, messageGetBody(aMessage));
					else {
						fb = messageToFileblob(aMessage, dir);

						if(fb)
							fileblobDestroy(fb);
					}
					assert(aMessage == messages[i]);
					messageDestroy(messages[i]);
					messages[i] = NULL;
				}

				/* rc = parseEmailBody(NULL, NULL, dir, rfc821Table, subtypeTable, options); */
				break;
			case SIGNED:
			case PARALLEL:
				/*
				 * If we're here it could be because we have a
				 * multipart/mixed message, consisting of a
				 * message followed by an attachment. That
				 * message itself is a multipart/alternative
				 * message and we need to dig out the plain
				 * text part of that alternative
				 */
				htmltextPart = getTextPart(messages, multiparts);
				if(htmltextPart == -1)
					htmltextPart = 0;

				rc = parseEmailBody(messages[htmltextPart], aText, dir, rfc821Table, subtypeTable, options);
				break;
			case ENCRYPTED:
				rc = 0;
				protocol = (char *)messageFindArgument(mainMessage, "protocol");
				if(protocol) {
					if(strcasecmp(protocol, "application/pgp-encrypted") == 0) {
						/* RFC2015 */
						cli_warnmsg("PGP encoded attachment not scanned\n");
						rc = 2;
					} else
						cli_warnmsg("Unknown encryption protocol '%s' - report to bugs@clamav.net\n");
					free(protocol);
				} else
					cli_warnmsg("Encryption method missing protocol name - report to bugs@clamav.net\n");

				break;
			default:
				/*
				 * According to section 7.2.6 of RFC1521,
				 * unrecognised multiparts should be treated as
				 * multipart/mixed. I don't do this yet so
				 * that I can see what comes along...
				 */
				cli_warnmsg("Unsupported multipart format `%s' - report to bugs@clamav.net\n", mimeSubtype);
				rc = 0;
			}

			for(i = 0; i < multiparts; i++)
				if(messages[i])
					messageDestroy(messages[i]);

			if(mainMessage && (mainMessage != messageIn))
				messageDestroy(mainMessage);

			if(aText && (textIn == NULL))
				textDestroy(aText);

			if(messages)
				free(messages);

			return rc;

		case MESSAGE:
			/*
			 * Check for forbidden encodings
			 */
			switch(messageGetEncoding(mainMessage)) {
				case NOENCODING:
				case EIGHTBIT:
				case BINARY:
					break;
				default:
					cli_warnmsg("MIME type 'message' cannot be decoded\n");
					break;
			}
			rc = 0;
			if((strcasecmp(mimeSubtype, "rfc822") == 0) ||
			   (strcasecmp(mimeSubtype, "delivery-status") == 0)) {
				message *m = parseEmailHeaders(mainMessage, rfc821Table);
				if(m) {
					cli_dbgmsg("Decode rfc822");

					if(mainMessage && (mainMessage != messageIn)) {
						messageDestroy(mainMessage);
						mainMessage = NULL;
					} else
						messageReset(mainMessage);
					if(messageGetBody(m))
						rc = parseEmailBody(m, NULL, dir, rfc821Table, subtypeTable, options);

					messageDestroy(m);
				}
				break;
			} else if(strcasecmp(mimeSubtype, "disposition-notification") == 0) {
				/* RFC 2298 - handle like a normal email */
				rc = 1;
				break;
			} else if(strcasecmp(mimeSubtype, "partial") == 0) {
#ifdef	PARTIAL_DIR
				/* RFC1341 message split over many emails */
				if(rfc1341(mainMessage, dir) >= 0)
					rc = 1;
#else
				cli_warnmsg("Partial message received from MUA/MTA - message cannot be scanned\n");
				rc = 0;
#endif
			} else if(strcasecmp(mimeSubtype, "external-body") == 0)
				/* TODO */
				cli_warnmsg("Attempt to send Content-type message/external-body trapped");
			else
				cli_warnmsg("Unsupported message format `%s' - please report to bugs@clamav.net\n", mimeSubtype);


			if(mainMessage && (mainMessage != messageIn))
				messageDestroy(mainMessage);
			if(messages)
				free(messages);
			return rc;

		case APPLICATION:
			cptr = messageGetMimeSubtype(mainMessage);

			/*if((strcasecmp(cptr, "octet-stream") == 0) ||
			   (strcasecmp(cptr, "x-msdownload") == 0)) {*/
			{
				fb = messageToFileblob(mainMessage, dir);

				if(fb) {
					cli_dbgmsg("Saving main message as attachment\n");
					fileblobDestroy(fb);
					messageClearMarkers(mainMessage);
				}
			} /*else
				cli_warnmsg("Discarded application not sent as attachment\n");*/
			break;

		case AUDIO:
		case VIDEO:
		case IMAGE:
			break;

		default:
			cli_warnmsg("Message received with unknown mime encoding");
			break;
		}
	}

	if(aText && (textIn == NULL)) {
		textDestroy(aText);
		aText = NULL;
	}

	/*
	 * No attachments - scan the text portions, often files
	 * are hidden in HTML code
	 */
	cli_dbgmsg("%d multiparts found\n", multiparts);
	for(i = 0; i < multiparts; i++) {
		fb = messageToFileblob(messages[i], dir);

		if(fb) {
			cli_dbgmsg("Saving multipart %d\n", i);

			fileblobDestroy(fb);
		}
	}

	if(mainMessage) {
		/*
		 * Look for uu-encoded main file
		 */
		const text *t_line;

		if((t_line = uuencodeBegin(mainMessage)) != NULL) {
			cli_dbgmsg("Found uuencoded file\n");

			/*
			 * Main part contains uuencoded section
			 */
			messageSetEncoding(mainMessage, "x-uuencode");

			if((fb = messageToFileblob(mainMessage, dir)) != NULL) {
				if((cptr = fileblobGetFilename(fb)) != NULL)
					cli_dbgmsg("Found uuencoded message %s\n", cptr);
				fileblobDestroy(fb);
			}
		} else if((encodingLine(mainMessage) != NULL) &&
			  ((t_line = bounceBegin(mainMessage)) != NULL)) {
			const text *t;
			static const char encoding[] = "Content-Transfer-Encoding";
			/*
			 * Attempt to save the original (unbounced)
			 * message - clamscan will find that in the
			 * directory and call us again (with any luck)
			 * having found an e-mail message to handle
			 *
			 * This finds a lot of false positives, the
			 * search that an encoding line is in the
			 * bounce (i.e. it's after the bounce header)
			 * helps a bit, but at the expense of scanning
			 * the entire message. messageAddLine
			 * optimisation could help here, but needs
			 * careful thought, do it with line numbers
			 * would be best, since the current method in
			 * messageAddLine of checking encoding first
			 * must remain otherwise non bounce messages
			 * won't be scanned
			 */
			for(t = t_line; t; t = t->t_next) {
				const char *txt = lineGetData(t->t_line);

				if(txt &&
				   (strncasecmp(txt, encoding, sizeof(encoding) - 1) == 0) &&
				   (strstr(txt, "7bit") == NULL) &&
				   (strstr(txt, "8bit") == NULL))
					break;
			}
			if(t && ((fb = fileblobCreate()) != NULL)) {
				cli_dbgmsg("Found a bounce message\n");
				fileblobSetFilename(fb, dir, "bounce");
				fb = textToFileblob(t_line, fb);
				fileblobDestroy(fb);
			} else
				cli_dbgmsg("Not found a bounce message\n");
		} else {
			bool saveIt;

			cli_dbgmsg("Not found uuencoded file\n");

			if(messageGetMimeType(mainMessage) == MESSAGE)
				/*
				 * Quick peek, if the encapsulated
				 * message has no
				 * content encoding statement don't
				 * bother saving to scan, it's safe
				 */
				saveIt = (encodingLine(mainMessage) != NULL);
			else if((t_line = encodingLine(mainMessage)) != NULL) {
				/*
				 * Some bounces include the message
				 * body without the headers.
				 * Unfortunately this generates a
				 * lot of false positives that a bounce
				 * has been found when it hasn't.
				 */
				if((fb = fileblobCreate()) != NULL) {
					cli_dbgmsg("Found a bounce message with no header\n");
					fileblobSetFilename(fb, dir, "bounce");
					fileblobAddData(fb, "Received: by clamd\n", 19);

					fb = textToFileblob(t_line, fb);

					fileblobDestroy(fb);
				}
				saveIt = FALSE;
			} else if(multiparts == 0)
				/*
				 * Save the entire text portion,
				 * since it it may be an HTML file with
				 * a JavaScript virus
				 */
				saveIt = TRUE;
			else
				saveIt = FALSE;

			if(saveIt) {
				cli_dbgmsg("Saving text part to scan\n");
				/*
				 * TODO: May be better to save aText
				 */
				saveTextPart(mainMessage, dir);
				if(mainMessage != messageIn) {
					messageDestroy(mainMessage);
					mainMessage = NULL;
				} else
					messageReset(mainMessage);
				rc = 1;
			}
		}
	} else
		rc = (multiparts) ? 1 : 2;	/* anything saved? */

	if(mainMessage && (mainMessage != messageIn))
		messageDestroy(mainMessage);

	if(messages)
		free(messages);

	cli_dbgmsg("parseEmailBody() returning %d\n", rc);

	return rc;
}

/*
 * Is the current line the start of a new section?
 *
 * New sections start with --boundary
 */
static int
boundaryStart(const char *line, const char *boundary)
{
	char *ptr, *p;

	if(line == NULL)
		return 0;	/* empty line */

	cli_dbgmsg("boundaryStart: line = '%s' boundary = '%s'\n", line, boundary);

	p = ptr = rfc822comments(line);
	if(ptr == NULL)
		ptr = line;

	if(*ptr++ != '-') {
		if(p)
			free(p);
		return 0;
	}

	/*
	 * Gibe.B3 is broken, it has:
	 *	boundary="---- =_NextPart_000_01C31177.9DC7C000"
	 * but it's boundaries look like
	 *	------ =_NextPart_000_01C31177.9DC7C000
	 * notice the one too few '-'.
	 * Presumably this is a deliberate exploitation of a bug in some mail
	 * clients.
	 *
	 * The trouble is that this creates a lot of false positives for
	 * boundary conditions, if we're too lax about matches. We do our level
	 * best to avoid these false positives. For example if we have
	 * boundary="1" we want to ensure that we don't break out of every line
	 * that has -1 in it instead of starting --1. This needs some more work.
	 */
	if(strstr(ptr, boundary) != NULL) {
		cli_dbgmsg("boundaryStart: found %s in %s\n", boundary, line);
		if(p)
			free(p);
		return 1;
	}
	if(*ptr++ != '-')
		return 0;
	if(p)
		free(p);
	return strcasecmp(line, boundary) == 0;
}

/*
 * Is the current line the end?
 *
 * The message ends with with --boundary--
 */
static int
endOfMessage(const char *line, const char *boundary)
{
	size_t len;

	if(line == NULL)
		return 0;
	cli_dbgmsg("endOfMessage: line = '%s' boundary = '%s'\n", line, boundary);
	if(*line++ != '-')
		return 0;
	if(*line++ != '-')
		return 0;
	len = strlen(boundary);
	if(strncasecmp(line, boundary, len) != 0)
		return 0;
	if(strlen(line) != (len + 2))
		return 0;
	line = &line[len];
	if(*line++ != '-')
		return 0;
	return *line == '-';
}

/*
 * Initialise the various lookup tables
 */
static int
initialiseTables(table_t **rfc821Table, table_t **subtypeTable)
{
	const struct tableinit *tableinit;

	/*
	 * Initialise the various look up tables
	 */
	*rfc821Table = tableCreate();
	assert(*rfc821Table != NULL);

	for(tableinit = rfc821headers; tableinit->key; tableinit++)
		if(tableInsert(*rfc821Table, tableinit->key, tableinit->value) < 0) {
			tableDestroy(*rfc821Table);
			*rfc821Table = NULL;
			return -1;
		}

	*subtypeTable = tableCreate();
	assert(*subtypeTable != NULL);

	for(tableinit = mimeSubtypes; tableinit->key; tableinit++)
		if(tableInsert(*subtypeTable, tableinit->key, tableinit->value) < 0) {
			tableDestroy(*rfc821Table);
			tableDestroy(*subtypeTable);
			*rfc821Table = NULL;
			*subtypeTable = NULL;
			return -1;
		}

	return 0;
}

/*
 * If there's a HTML text version use that, otherwise
 * use the first text part, otherwise just use the
 * first one around. HTML text is most likely to include
 * a scripting worm
 *
 * If we can't find one, return -1
 */
static int
getTextPart(message *const messages[], size_t size)
{
	size_t i;
	int textpart = -1;

	for(i = 0; i < size; i++) {
		assert(messages[i] != NULL);
		if(messageGetMimeType(messages[i]) == TEXT) {
			if(strcasecmp(messageGetMimeSubtype(messages[i]), "html") == 0)
				return (int)i;
			textpart = (int)i;
		}
	}
	return textpart;
}

/*
 * strip -
 *	Remove the trailing spaces from a buffer. Don't call this directly,
 * always call strstrip() which is a wrapper to this routine to be used with
 * NUL terminated strings. This code looks a bit strange because of it's
 * heritage from code that worked on strings that weren't necessarily NUL
 * terminated.
 * TODO: rewrite for clamAV
 *
 * Returns it's new length (a la strlen)
 *
 * len must be int not size_t because of the >= 0 test, it is sizeof(buf)
 *	not strlen(buf)
 */
static size_t
strip(char *buf, int len)
{
	register char *ptr;
	register size_t i;

	if((buf == NULL) || (len <= 0))
		return 0;

	i = strlen(buf);
	if(len > (int)(i + 1))
		return i;
	ptr = &buf[--len];

#if	defined(UNIX) || defined(C_LINUX) || defined(C_DARWIN)	/* watch - it may be in shared text area */
	do
		if(*ptr)
			*ptr = '\0';
	while((--len >= 0) && (!isgraph(*--ptr)) && (*ptr != '\n') && (*ptr != '\r'));
#else	/* more characters can be displayed on DOS */
	do
#ifndef	REAL_MODE_DOS
		if(*ptr)	/* C8.0 puts into a text area */
#endif
			*ptr = '\0';
	while((--len >= 0) && ((*--ptr == '\0') || (isspace((int)*ptr))));
#endif
	return((size_t)(len + 1));
}

/*
 * strstrip:
 *	Strip a given string
 */
size_t
strstrip(char *s)
{
	if(s == (char *)NULL)
		return(0);

	return(strip(s, strlen(s) + 1));
}

/*
 * When parsing a MIME header see if this spans more than one line. A
 * semi-colon at the end of the line indicates that the MIME information
 * is continued on the next line.
 *
 * Some clients are broken and put white space after the ;
 */
static bool
continuationMarker(const char *line)
{
	const char *ptr;

	if(line == NULL)
		return FALSE;

#ifdef	CL_DEBUG
	cli_dbgmsg("continuationMarker(%s)\n", line);
#endif

	if(strlen(line) == 0)
		return FALSE;

	ptr = strchr(line, '\0');

	assert(ptr != NULL);

	while(ptr > line)
		switch(*--ptr) {
			case '\n':
			case '\r':
			case ' ':
			case '\t':
				continue;
			case ';':
				return TRUE;
			default:
				return FALSE;
		}

	return FALSE;
}

static int
parseMimeHeader(message *m, const char *cmd, const table_t *rfc821Table, const char *arg)
{
#ifdef CL_THREAD_SAFE
	char *strptr;
#endif
	char *copy, *ptr;
	int commandNumber;

	cli_dbgmsg("parseMimeHeader: cmd='%s', arg='%s'\n", cmd, arg);

	ptr = rfc822comments(cmd);
	if(ptr) {
		commandNumber = tableFind(rfc821Table, ptr);
		free(ptr);
	} else
		commandNumber = tableFind(rfc821Table, cmd);

	copy = rfc822comments(arg);
	if(copy == NULL)
		copy = strdup(arg);
	if(copy == NULL)
		return -1;

	ptr = copy;

	switch(commandNumber) {
		case CONTENT_TYPE:
			/*
			 * Fix for non RFC1521 compliant mailers
			 * that send content-type: Text instead
			 * of content-type: Text/Plain, or
			 * just simply "Content-Type:"
			 */
			if(arg == NULL)
				/*
				 * According to section 4 of RFC1521:
				 * "Note also that a subtype specification is
				 * MANDATORY. There are no default subtypes"
				 *
				 * We have to break this and make an assumption
				 * for the subtype because virus writers and
				 * email client writers don't get it right
				 */
				 cli_warnmsg("Empty content-type received, no subtype specified, assuming text/plain; charset=us-ascii\n");
			else if(strchr(copy, '/') == NULL)
				/*
				 * Empty field, such as
				 *	Content-Type:
				 * which I believe is illegal according to
				 * RFC1521
				 */
				cli_dbgmsg("Invalid content-type '%s' received, no subtype specified, assuming text/plain; charset=us-ascii\n", copy);
			else {
				int i;
				char *mimeArgs;	/* RHS of the ; */

				/*
				 * Some clients are broken and
				 * put white space after the ;
				 */
				if(*arg == '/') {
					cli_warnmsg("Content-type '/' received, assuming application/octet-stream\n");
					messageSetMimeType(m, "application");
					messageSetMimeSubtype(m, "octet-stream");
				} else {
					/*
					 * The content type could be in quotes:
					 *	Content-Type: "multipart/mixed"
					 * FIXME: this is a hack in that ignores
					 *	the quotes, it doesn't handle
					 *	them properly
					 */
					while(isspace(*copy))
						copy++;
					if(copy[0] == '\"')
						copy++;

					if(copy[0] != '/') {
						char *s;
						char *mimeType;	/* LHS of the ; */

						s = mimeType = cli_strtok(copy, 0, ";");
						/*
						 * Handle
						 * Content-Type: foo/bar multipart/mixed
						 * and
						 * Content-Type: multipart/mixed foo/bar
						 */
						for(;;) {
#ifdef	CL_THREAD_SAFE
							int set = messageSetMimeType(m, strtok_r(s, "/", &strptr));
#else
							int set = messageSetMimeType(m, strtok(s, "/"));
#endif

							/*
							 * Stephen White <stephen@earth.li>
							 * Some clients put space after
							 * the mime type but before
							 * the ;
							 */
#ifdef	CL_THREAD_SAFE
							s = strtok_r(NULL, ";", &strptr);
#else
							s = strtok(NULL, ";");
#endif
							if(s == NULL)
								break;
							if(set) {
								size_t len = strstrip(s) - 1;
								if(s[len] == '\"') {
									s[len] = '\0';
									len = strstrip(s);
								}
								if(len) {
									if(strchr(s, ' ')) {
										char *t = cli_strtok(s, 0, " ");

										messageSetMimeSubtype(m, t);
										free(t);
									} else
										messageSetMimeSubtype(m, s);
								}
							}

							while(*s && !isspace(*s))
								s++;
							if(*s++ == '\0')
								break;
							if(*s == '\0')
								break;
						}
						free(mimeType);
					}
				}

				/*
				 * Add in all rest of the the arguments.
				 * e.g. if the header is this:
				 * Content-Type:', arg='multipart/mixed; boundary=foo
				 * we find the boundary argument set it
				 */
				i = 1;
				while((mimeArgs = cli_strtok(copy, i++, ";")) != NULL) {
					cli_dbgmsg("mimeArgs = '%s'\n", mimeArgs);

					messageAddArguments(m, mimeArgs);
					free(mimeArgs);
				}
			}
			break;
		case CONTENT_TRANSFER_ENCODING:
			messageSetEncoding(m, copy);
			break;
		case CONTENT_DISPOSITION:
#ifdef	CL_THREAD_SAFE
			arg = strtok_r(copy, ";", &strptr);
			if(arg && *arg) {
				messageSetDispositionType(m, arg);
				messageAddArgument(m, strtok_r(NULL, "\r\n", &strptr));
			}
#else
			arg = strtok(copy, ";");
			if(arg && *arg) {
				messageSetDispositionType(m, arg);
				messageAddArgument(m, strtok(NULL, "\r\n"));
			}
#endif
	}
	free(ptr);

	return 0;
}

/*
 * Save the text portion of the message
 */
static void
saveTextPart(message *m, const char *dir)
{
	fileblob *fb;

	messageAddArgument(m, "filename=textportion");
	if((fb = messageToFileblob(m, dir)) != NULL) {
		/*
		 * Save main part to scan that
		 */
		cli_dbgmsg("Saving main message\n");

		fileblobDestroy(fb);
	}
}

/*
 * Handle RFC822 comments in headers.
 * Returns a buffer without the comments or NULL on error or if the input
 * has no comments. The caller must free the returned buffer
 * See secion 3.4.3 of RFC822
 * TODO: handle comments that go on to more than one line
 */
static char *
rfc822comments(const char *in)
{
	const char *iptr;
	char *out, *optr;
	int backslash, inquote, commentlevel;

	if(in == NULL)
		return NULL;

	if(strchr(in, '(') == NULL)
		return NULL;

	out = cli_malloc(strlen(in) + 1);
	if(out == NULL)
		return NULL;

	backslash = commentlevel = inquote = 0;
	optr = out;

	cli_dbgmsg("rfc822comments: contains a comment\n");

	for(iptr = in; *iptr; iptr++)
		if(backslash) {
			if(commentlevel == 0)
				*optr++ = *iptr;
			backslash = 0;
		} else switch(*iptr) {
			case '\\':
				backslash = 1;
				break;
			case '\"':
				inquote = !inquote;
				break;
			case '(':
				commentlevel++;
				break;
			case ')':
				if(commentlevel > 0)
					commentlevel--;
				break;
			default:
				if(commentlevel == 0)
					*optr++ = *iptr;
		}

	if(backslash)	/* last character was a single backslash */
		*optr++ = '\\';
	*optr = '\0';

	strstrip(out);

	cli_dbgmsg("rfc822comments '%s'=>'%s'\n", in, out);

	return out;
}

/*
 * Handle RFC2047 encoding. Returns a malloc'd buffer that the caller must
 * free, or NULL on error
 */
static char *
rfc2047(const char *in)
{
	char *out, *pout;
	size_t len;

	if((strstr(in, "=?") == NULL) || (strstr(in, "?=") == NULL))
		return strdup(in);

	cli_dbgmsg("rfc2047 '%s'\n", in);
	out = cli_malloc(strlen(in) + 1);

	if(out == NULL)
		return NULL;

	pout = out;

	/* For each RFC2047 string */
	while(*in) {
		char encoding, *ptr, *enctext;
		message *m;
		blob *b;

		/* Find next RFC2047 string */
		while(*in) {
			if((*in == '=') && (in[1] == '?')) {
				in += 2;
				break;
			}
			*pout++ = *in++;
		}
		/* Skip over charset, find encoding */
		while((*in != '?') && *in)
			in++;
		if(*in == '\0')
			break;
		encoding = *++in;
		encoding = tolower(encoding);

		if((encoding != 'q') && (encoding != 'b')) {
			cli_warnmsg("Unsupported RFC2047 encoding type '%c' - report to bugs@clamav.net\n", encoding);
			free(out);
			out = NULL;
			break;
		}
		/* Skip to encoded text */
		if(*++in != '?')
			break;
		if(*++in == '\0')
			break;

		enctext = strdup(in);
		if(enctext == NULL) {
			free(out);
			out = NULL;
			break;
		}
		in = strstr(in, "?=");
		if(in == NULL) {
			free(enctext);
			break;
		}
		in += 2;
		ptr = strstr(enctext, "?=");
		assert(ptr != NULL);
		*ptr = '\0';
		/*cli_dbgmsg("Need to decode '%s' with method '%c'\n", enctext, encoding);*/

		m = messageCreate();
		if(m == NULL)
			break;
		messageAddStr(m, enctext);
		free(enctext);
		switch(encoding) {
			case 'q':
				messageSetEncoding(m, "quoted-printable");
				break;
			case 'b':
				messageSetEncoding(m, "base64");
				break;
		}
		b = messageToBlob(m);
		len = blobGetDataSize(b);
		cli_dbgmsg("Decoded as '%*.*s'\n", len, len, blobGetData(b));
		memcpy(pout, blobGetData(b), len);
		blobDestroy(b);
		messageDestroy(m);
		if(pout[len - 1] == '\n')
			pout += len - 1;
		else
			pout += len;

	}
	if(out == NULL)
		return NULL;

	*pout = '\0';

	cli_dbgmsg("rfc2047 returns '%s'\n", out);
	return out;
}

#ifdef	PARTIAL_DIR
/*
 * Handle partial messages
 */
static int
rfc1341(message *m, const char *dir)
{
	fileblob *fb;
	char *arg, *id, *number, *total, *oldfilename;
	const char *tmpdir;
	char *pdir;

#ifdef  CYGWIN
        if((tmpdir = getenv("TEMP")) == (char *)NULL)
                if((tmpdir = getenv("TMP")) == (char *)NULL)
                        if((tmpdir = getenv("TMPDIR")) == (char *)NULL)
                                tmpdir = "C:\\";
#else
        if((tmpdir = getenv("TMPDIR")) == (char *)NULL)
                if((tmpdir = getenv("TMP")) == (char *)NULL)
                        if((tmpdir = getenv("TEMP")) == (char *)NULL)
#ifdef	P_tmpdir
                                tmpdir = P_tmpdir;
#else
                                tmpdir = "/tmp";
#endif
#endif

    	pdir = cli_malloc(strlen(tmpdir) + 16);
	if(pdir == NULL)
		return -1;
                                                                                	sprintf(pdir, "%s/clamav-partial", tmpdir);

	if((mkdir(pdir, 0700) < 0) && (errno != EEXIST)) {
		cli_errmsg("Can't create the directory '%s'\n", pdir);
		free(pdir);
		return -1;
	} else {
		struct stat statb;

		if(stat(pdir, &statb) < 0) {
			cli_errmsg("Can't stat the directory '%s'\n", pdir);
			free(pdir);
			return -1;
		}
		if(statb.st_mode & 077)
			cli_warnmsg("Insecure partial directory %s (mode 0%o)\n",
				pdir, statb.st_mode & 0777);
	}

	id = (char *)messageFindArgument(m, "id");
	if(id == NULL) {
		free(pdir);
		return -1;
	}
	number = (char *)messageFindArgument(m, "number");
	if(number == NULL) {
		free(id);
		free(pdir);
		return -1;
	}

	oldfilename = (char *)messageFindArgument(m, "filename");
	if(oldfilename == NULL)
		oldfilename = (char *)messageFindArgument(m, "name");

	arg = cli_malloc(10 + strlen(id) + strlen(number));
	sprintf(arg, "filename=%s%s", id, number);
	messageAddArgument(m, arg);
	free(arg);

	if(oldfilename) {
		cli_warnmsg("Must reset to %s\n", oldfilename);
		free(oldfilename);
	}

	if((fb = messageToFileblob(m, pdir)) == NULL) {
		free(id);
		free(number);
		free(pdir);
		return -1;
	}

	fileblobDestroy(fb);

	total = (char *)messageFindArgument(m, "total");
	cli_dbgmsg("rfc1341: %s, %s of %s\n", id, number, (total) ? total : "?");
	if(total) {
		int n = atoi(number);
		int t = atoi(total);
		DIR *dd = NULL;

		/*
		 * If it's the last one - reassemble it
		 * FIXME: this assumes that we receive the parts in order
		 */
		if((n == t) && ((dd = opendir(pdir)) != NULL)) {
			FILE *fout;
			char outname[NAME_MAX + 1];

			snprintf(outname, sizeof(outname) - 1, "%s/%s", dir, id);

			cli_dbgmsg("outname: %s\n", outname);

			fout = fopen(outname, "wb");
			if(fout == NULL) {
				cli_errmsg("Can't open '%s' for writing", outname);
				free(id);
				free(total);
				free(number);
				closedir(dd);
				free(pdir);
				return -1;
			}

			for(n = 1; n <= t; n++) {
				char filename[NAME_MAX + 1];
				const struct dirent *dent;
#if defined(HAVE_READDIR_R_3) || defined(HAVE_READDIR_R_2)
				union {
					struct dirent d;
					char b[offsetof(struct dirent, d_name) + NAME_MAX + 1];
				} result;
#endif

				snprintf(filename, sizeof(filename), "%s%d", id, n);

#ifdef HAVE_READDIR_R_3
				while((readdir_r(dd, &result.d, &dent) == 0) && dent) {
#elif defined(HAVE_READDIR_R_2)
				while((dent = (struct dirent *)readdir_r(dd, &result.d))) {
#else	/*!HAVE_READDIR_R*/
				while((dent = readdir(dd))) {
#endif
					char fullname[NAME_MAX + 1];
					FILE *fin;
					char buffer[BUFSIZ];
					int nblanks;
					extern short cli_leavetemps_flag;

					if(dent->d_ino == 0)
						continue;

					if(strncmp(filename, dent->d_name, strlen(filename)) != 0)
						continue;

					sprintf(fullname, "%s/%s", pdir, dent->d_name);
					fin = fopen(fullname, "rb");
					if(fin == NULL) {
						cli_errmsg("Can't open '%s' for reading", fullname);
						fclose(fout);
						unlink(outname);
						free(id);
						free(total);
						free(number);
						closedir(dd);
						free(pdir);
						return -1;
					}
					nblanks = 0;
					while(fgets(buffer, sizeof(buffer), fin) != NULL)
						/*
						 * Ensure that trailing newlines
						 * aren't copied
						 */
						if(buffer[0] == '\n') {
							nblanks++;
						} else {
							if(nblanks)
								do
									putc('\n', fout);
								while(--nblanks > 0);
							fputs(buffer, fout);
						}
					fclose(fin);

					/* don't unlink if leave temps */
					if(!cli_leavetemps_flag)
						unlink(fullname);
					break;
				}
				rewinddir(dd);
			}
			closedir(dd);
			fclose(fout);
		}
		free(number);
	}
	free(id);
	free(total);
	free(pdir);

	return 0;
}
#endif

#ifdef	FOLLOWURLS
static void
checkURLs(message *m, const char *dir)
{
	blob *b = messageToBlob(m);
	size_t len;
	table_t *t;
	int i, n;
#if	defined(WITH_CURL) && defined(CL_THREAD_SAFE)
	pthread_t tid[MAX_URLS];
	struct arg args[MAX_URLS];
#endif
	tag_arguments_t hrefs;

	if(b == NULL)
		return;

	len = blobGetDataSize(b);

	if(len == 0) {
		blobDestroy(b);
		return;
	}

	/* TODO: make this size customisable */
	if(len > 100*1024) {
		cli_warnmsg("Viruses pointed to by URL not scanned in large message\n");
		blobDestroy(b);
		return;
	}

	blobClose(b);
	t = tableCreate();
	if(t == NULL) {
		blobDestroy(b);
		return;
	}

	hrefs.count = 0;
	hrefs.tag = hrefs.value = NULL;

	cli_dbgmsg("checkURLs: calling html_normalise_mem\n");
	if(!html_normalise_mem(blobGetData(b), len, NULL, &hrefs)) {
		blobDestroy(b);
		tableDestroy(t);
		return;
	}
	cli_dbgmsg("checkURLs: html_normalise_mem returned\n");

	/* TODO: Do we need to call remove_html_comments? */

	n = 0;

	for(i = 0; i < hrefs.count; i++) {
		const char *url = (const char *)hrefs.value[i];

		if(strncasecmp("http://", url, 7) == 0) {
			char *ptr;
#ifdef	WITH_CURL
#ifndef	CL_THREAD_SAFE
			struct arg arg;
#endif

#else	/*!WITH_CURL*/
#ifdef	CL_THREAD_SAFE
			static pthread_mutex_t system_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif
			struct stat statb;
			char cmd[512];
#endif	/*WITH_CURL*/
			char name[NAME_MAX + 1];

			if(tableFind(t, url) == 1) {
				cli_dbgmsg("URL %s already downloaded\n", url);
				continue;
			}
			if(n == MAX_URLS) {
				cli_warnmsg("Not all URLs will be scanned\n");
				break;
			}
			(void)tableInsert(t, url, 1);
			cli_dbgmsg("Downloading URL %s to be scanned\n", url);
			strncpy(name, url, sizeof(name) - 1);
			name[sizeof(name) - 1] = '\0';
			for(ptr = name; *ptr; ptr++)
				if(*ptr == '/')
					*ptr = '_';

#ifdef	WITH_CURL
#ifdef	CL_THREAD_SAFE
			args[n].dir = dir;
			args[n].url = url;
			args[n].filename = strdup(name);
			pthread_create(&tid[n], NULL, getURL, &args[n]);
#else
			arg.url = url;
			arg.dir = dir;
			arg.filename = name;
			getURL(&arg);
#endif

#else
			/*
			 * TODO: maximum size and timeouts
			 */
			len = sizeof(cmd) - 26 - strlen(dir) - strlen(name);
#ifdef	CL_DEBUG
			snprintf(cmd, sizeof(cmd) - 1, "GET -t10 %.*s >%s/%s", len, url, dir, name);
#else
			snprintf(cmd, sizeof(cmd) - 1, "GET -t10 %.*s >%s/%s 2>/dev/null", len, url, dir, name);
#endif
			cmd[sizeof(cmd) - 1] = '\0';

#ifndef	WITH_CURL
			for(ptr = cmd; *ptr; ptr++)
				if(strchr(";&", *ptr))
					*ptr = '_';
#endif

			cli_dbgmsg("%s\n", cmd);
#ifdef	CL_THREAD_SAFE
			pthread_mutex_lock(&system_mutex);
#endif
			system(cmd);
#ifdef	CL_THREAD_SAFE
			pthread_mutex_unlock(&system_mutex);
#endif
			snprintf(cmd, sizeof(cmd), "%s/%s", dir, name);
			if(stat(cmd, &statb) >= 0)
				if(statb.st_size == 0) {
					cli_warnmsg("URL %s failed to download\n", url);
					/*
					 * Don't bother scanning an empty file
					 */
					(void)unlink(cmd);
				}
#endif
			++n;
		}
	}
	blobDestroy(b);
	tableDestroy(t);

#if	defined(WITH_CURL) && defined(CL_THREAD_SAFE)
	assert(n <= MAX_URLS);
	cli_dbgmsg("checkURLs: waiting for %d thread(s) to finish\n", n);
	while(--n >= 0) {
		pthread_join(tid[n], NULL);
		free(args[n].filename);
	}
#endif
	html_tag_arg_free(&hrefs);
}

#ifdef	WITH_CURL
static void *
#ifdef	CL_THREAD_SAFE
getURL(void *a)
#else
getURL(struct arg *arg)
#endif
{
	char *fout;
	CURL *curl;
	FILE *fp;
	struct curl_slist *headers;
	static int initialised = 0;
#ifdef	CL_THREAD_SAFE
	static pthread_mutex_t init_mutex = PTHREAD_MUTEX_INITIALIZER;
	struct arg *arg = (struct arg *)a;
#endif
	const char *url = arg->url;
	const char *dir = arg->dir;
	const char *filename = arg->filename;

#ifdef	CL_THREAD_SAFE
	pthread_mutex_lock(&init_mutex);
#endif
	if(!initialised) {
		if(curl_global_init(CURL_GLOBAL_NOTHING) != 0) {
#ifdef	CL_THREAD_SAFE
			pthread_mutex_unlock(&init_mutex);
#endif
			return NULL;
		}
		initialised = 1;
	}
#ifdef	CL_THREAD_SAFE
	pthread_mutex_unlock(&init_mutex);
#endif

	/* easy isn't the word I'd use... */
	curl = curl_easy_init();
	if(curl == NULL)
		return NULL;

	(void)curl_easy_setopt(curl, CURLOPT_USERAGENT, "www.clamav.net");

	if(curl_easy_setopt(curl, CURLOPT_URL, url) != 0)
		return NULL;

	fout = cli_malloc(strlen(dir) + strlen(filename) + 2);

	if(fout == NULL) {
		curl_easy_cleanup(curl);
		return NULL;
	}

	snprintf(fout, NAME_MAX, "%s/%s", dir, filename);

	fp = fopen(fout, "w");

	if(fp == NULL) {
		cli_errmsg("Can't open '%s' for writing", fout);
		free(fout);
		curl_easy_cleanup(curl);
		return NULL;
	}
#ifdef	CURLOPT_WRITEDATA
	if(curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp) != 0) {
		fclose(fp);
		free(fout);
		curl_easy_cleanup(curl);
		return NULL;
	}
#else
	if(curl_easy_setopt(curl, CURLOPT_FILE, fp) != 0) {
		fclose(fp);
		free(fout);
		curl_easy_cleanup(curl);
		return NULL;
	}
#endif

	/*
	 * If an item is in squid's cache get it from there (TCP_HIT/200)
	 * by default curl doesn't (TCP_CLIENT_REFRESH_MISS/200)
	 */
	headers = curl_slist_append(NULL, "Pragma:");
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

	/* These should be customisable */
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10);
#ifdef	CURLOPT_MAXFILESIZE
	curl_easy_setopt(curl, CURLOPT_MAXFILESIZE, 50*1024);
#endif

#ifdef  CL_THREAD_SAFE
#ifdef	CURLOPT_DNS_USE_GLOBAL_CACHE
	curl_easy_setopt(curl, CURLOPT_DNS_USE_GLOBAL_CACHE, 0);
#endif
#endif

	/*
	 * Prevent password: prompting with older versions
	 * FIXME: a better username?
	 */
	curl_easy_setopt(curl, CURLOPT_USERPWD, "username:password");

	/*
	 * FIXME: valgrind reports "pthread_mutex_unlock: mutex is not locked"
	 * from gethostbyaddr_r within this. It may be a bug in libcurl
	 * rather than this code, but I need to check, see Curl_resolv()
	 * If pushed really hard it will sometimes say
	 * Conditional jump or move depends on uninitialised value(s) and
	 * quit. But the program seems to work OK without valgrind...
	 * Perhaps Curl_resolv() isn't thread safe?
	 */
	if(curl_easy_perform(curl) != CURLE_OK) {
		cli_warnmsg("URL %s failed to download\n", url);
		unlink(fout);
	}

	fclose(fp);
	curl_slist_free_all(headers);
	curl_easy_cleanup(curl);
	free(fout);

	return NULL;
}
#endif

#else
static void
checkURLs(message *m, const char *dir)
{
}
#endif

#ifdef HAVE_BACKTRACE
static void
sigsegv(int sig)
{
	signal(SIGSEGV, SIG_DFL);
	print_trace(1);
	exit(SIGSEGV);
}

static void
print_trace(int use_syslog)
{
	void *array[10];
	size_t size;
	char **strings;
	size_t i;
	pid_t pid = getpid();

	size = backtrace(array, 10);
	strings = backtrace_symbols(array, size);

	if(use_syslog == 0)
		cli_dbgmsg("Backtrace of pid %d:\n", pid);
	else
		syslog(LOG_ERR, "Backtrace of pid %d:", pid);

	for(i = 0; i < size; i++)
		if(use_syslog)
			syslog(LOG_ERR, "bt[%d]: %s", (int)i, strings[i]);
		else
			cli_dbgmsg("%s\n", strings[i]);

	/* TODO: dump the current email */

	free(strings);
}
#endif
