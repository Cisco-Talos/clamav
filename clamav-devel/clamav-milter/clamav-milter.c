/*
 * clamav-milter.c
 *	.../clamav-milter/clamav-milter.c
 *
 *  Copyright (C) 2003 Nigel Horne <njh@bandsman.co.uk>
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
 * Install into /usr/local/sbin/clamav-milter, mode 744
 *
 * See http://www.nmt.edu/~wcolburn/sendmail-8.12.5/libmilter/docs/sample.html
 *
 * Installations for RedHat Linux and it's derivatives such as YellowDog:
 * 1) Ensure that you have the sendmail-devel RPM installed
 * 2) Add to /etc/mail/sendmail.mc:
 *	INPUT_MAIL_FILTER(`clamav', `S=local:/var/run/clamav.sock, F=, T=S:4m;R:4m')dnl
 *	define(`confINPUT_MAIL_FILTERS', `clamav')
 * 3) Check entry in /usr/local/etc/clamav.conf of the form:
 *	LocalSocket /var/run/clamd.sock
 *	StreamSaveToDisk
 * 4) If you already have a filter (such as spamassassin-milter from
 * http://savannah.nongnu.org/projects/spamass-milt) add it thus:
 *	INPUT_MAIL_FILTER(`clamav', `S=local:/var/run/clamav.sock, F=, T=S:4m;R:4m')dnl
 *	INPUT_MAIL_FILTER(`spamassassin', `S=local:/var/run/spamass.sock, F=, T=C:15m;S:4m;R:4m;E:10m')
 *	define(`confINPUT_MAIL_FILTERS', `spamassassin,clamav')dnl
 * 5) You may find INPUT_MAIL_FILTERS is not needed on your machine, however it
 * is recommended by the Sendmail documentation and I suggest going along
 * with that.
 * 6) I suggest putting SpamAssassin first since you're more likely to get spam
 * than a virus/worm sent to you.
 * 7) Add to /etc/sysconfig/clamav-milter
 *	CLAMAV_FLAGS="--max-children=2 local:/var/run/clamav.sock"
 * or if clamd is on a different machine
 *	CLAMAV_FLAGS="--max-children=2 --server=192.168.1.9 local:/var/run/clamav.sock"
 * 8) You should have received a script to put into /etc/init.d with this
 * software.
 * 9) run 'chown clamav /usr/local/sbin/clamav-milter; chmod 4700 /usr/local/sbin/clamav-milter
 *
 * Tested OK on Linux/x86 (RH8.0) with gcc3.2.
 *	cc -O3 -pedantic -Wuninitialized -Wall -pipe -mcpu=pentium -march=pentium -fomit-frame-pointer -ffast-math -finline-functions -funroll-loops clamav-milter.c -pthread -lmilter ../libclamav/.libs/libclamav.a ../clamd/cfgfile.o ../clamd/others.o
 * Compiles OK on Linux/x86 with tcc 0.9.16, but fails to link errors with 'atexit'
 *	tcc -g -b -lmilter -lpthread clamav-milter.c...
 * Fails to compile on Linux/x86 with icc6.0 (complains about stdio.h...)
 *	icc -O3 -tpp7 -xiMKW -ipo -parallel -i_dynamic -w2 clamav-milter.c...
 * Fails to build on Linux/x86 with icc7.1 with -ipo (fails on libclamav.a - keeps saying run ranlib). Otherwise it builds and runs OK.
 *	icc -O2 -tpp7 -xiMKW -parallel -i_dynamic -w2 -march=pentium4 -mcpu=pentium4 clamav-milter.c...
 * Tested with Electric Fence 2.2.2
 *
 * Compiles OK on Linux/ppc (YDL2.3) with gcc2.95.4. Needs -lsmutil to link.
 *	cc -O3 -pedantic -Wuninitialized -Wall -pipe -fomit-frame-pointer -ffast-math -finline-functions -funroll-loop -pthread -lmilter ../libclamav/.libs/libclamav.a ../clamd/cfgfile.o ../clamd/others.o -lsmutil
 * I haven't tested it further on this platform yet.
 * YDL3.0 should compile out of the box
	cc -O3 -pedantic -Wuninitialized -Wall -pipe -fomit-frame-pointer -ffast-math -finline-functions -funroll-loop -pthread -lmilter ../libclamav/.libs/libclamav.a ../clamd/cfgfile.o ../clamd/others.o -lsmutil
 *
 * Sendmail on MacOS/X (10.1) is provided without a development package so this
 * can't be run "out of the box"
 *
 * Solaris 8 doesn't have milter support so clamav-milter won't work unless
 * you rebuild sendmail from source.
 *
 * FreeBSD4.7 use /usr/local/bin/gcc30. GCC3.0 is an optional extra on
 * FreeBSD. It comes with getopt.h which is handy. To link you need
 * -lgnugetopt
 *	gcc30 -O3 -DCONFDIR=\"/usr/local/etc\" -I. -I.. -I../clamd -I../libclamav -pedantic -Wuninitialized -Wall -pipe -mcpu=pentium -march=pentium -fomit-frame-pointer -ffast-math -finline-functions -funroll-loops clamav-milter.c -pthread -lmilter ../libclamav/.libs/libclamav.a ../clamd/cfgfile.o ../clamd/others.o -lgnugetopt
 *
 * FreeBSD4.8: compiles out of the box with either gcc2.95 or gcc3
 *
 * OpenBSD3.4: the supplied sendmail does not come with Milter support.
 * Do this *before* running configure (thanks for Per-Olov Sjöhol
 * <peo_s@incedo.org>for these instructions).
 *
 *	echo WANT_LIBMILTER=1 > /etc/mk.conf
 *	cd /usr/src/gnu/usr.sbin/sendmail
 *	make depend
 *	make
 *	make install
 *	kill -HUP `sed q /var/run/sendmail.pid`
 *
 * Then do this to make the milter headers available to clamav...
 * (the libmilter.a file is already in the right place after the sendmail
 * recompiles above)
 *
 *	cd /usr/include
 *	ln -s ../src/gnu/usr.sbin/sendmail/include/libmilter libmilter
 *
 * Solaris 9 and FreeBSD5 have milter support in the supplied sendmail, but
 * doesn't include libmilter so you can't develop milter applications on it.
 * Go to sendmail.org, download the lastest sendmail, cd to libmilter and
 * "make install" there.
 *
 * Needs -lresolv on Solaris
 *
 * Changes
 *	0.2:	4/3/03	clamfi_abort() now always calls pthread_mutex_unlock
 *		5/3/03	Only send a bounce if -b is set
 *			Version now uses -v not -V
 *			--config-file couldn't be set by -c
 *	0.3	7/3/03	Enhanced the Solaris compile time comment
 *			No need to save the return result of LogSyslog
 *			Use LogVerbose
 *	0.4	9/3/03	Initialise dataSocket/cmdSocket correctly
 *		10/3/03	Say why we don't connect() to clamd
 *			Enhanced '-l' usage message
 *	0.5	18/3/03	Ported to FreeBSD 4.7
 *			Source no longer in support, so remove one .. from
 *			the build instructions
 *			Corrected the use of strerror_r
 *	0.51	20/3/03	Mention StreamSaveToDisk in the installation
 *			Added -s option which allows clamd to run on a
 *			different machine from the milter
 *	0.52	20/3/03	-b flag now only stops the bounce, sends warning
 *			to recipient and postmaster
 *	0.53	24/3/03	%d->%u in syslog call
 *		27/3/03	tcpSocket is now of type in_port_t
 *		27/3/03	Use PING/PONG
 *	0.54	23/5/03	Allow a range of IP addresses as outgoing ones
 *			that need not be checked
 *	0.55	24/5/03	Use inet_ntop() instead of inet_ntoa()
 *			Thanks to Krzysztof Olędzki <ole@ans.pl>
 *	0.60	11/7/03	Added suggestions by Nigel Kukard <nkukard@lbsd.net>
 *			Should stop a couple of remote chances of crashes
 *	0.60a	22/7/03	Tidied up message when sender is unknown
 *	0.60b	17/8/03	Optionally set postmaster address. Usually one uses
 *			/etc/aliases, but not everyone want's to...
 *	0.60c	22/8/03	Another go at Solaris support
 *	0.60d	26/8/03	Removed superflous buffer and unneeded strerror call
 *			ETIMEDOUT isn't an error, but should give a warning
 *	0.60e	09/9/03	Added -P and -q flags by "Nicholas M. Kirsch"
 *			<nick@kirsch.org>
 *	0.60f	24/9/03	Changed fprintf to fputs where possible
 *			Redirect stdin from /dev/null, stdout&stderr to
 *			/dev/console
 *	0.60g	26/9/03	Handle sendmail calling abort after calling cleanup
 *			(Should never happen - but it does)
 *			Added -noxheader patch from dirk.meyer@dinoex.sub.org
 *	0.60h	28/9/03	Support MaxThreads option in config file,
 *			overriden by --max-children.
 *			Patch from "Richard G. Roberto" <rgr@dedlegend.com>
 *	0.60i	30/9/03	clamfi_envfrom() now correctly returns SMFIS_TEMPFAIL,
 *			in a few circumstances it used to return EX_TEMPFAIL
 *			Patch from Matt Sullivan <matt@sullivan.gen.nz>
 *	0.60j	1/10/03	strerror_r doesn't work on Linux, attempting workaround
 *			Added support for hard-coded list of email addresses
 *			who's e-mail is not scanned
 *	0.60k	5/10/03	Only remove old UNIX domain socket if FixStaleSocket
 *			is set
 *	0.60l	11/10/03 port is now unsigned
 *			Removed remote possibility of crash if the target
 *			e-mail address is very long
 *			No longer calls clamdscan to get the version
 *	0.60m	12/10/03 Now does sanity check if using localSocket
 *			Gets version info from clamd
 *			Only reset fd's 0/1/2 if !ForeGround
 *	0.60n	22/10/03 Call pthread_cont_broadcast more often
 *	0.60o	31/10/03 Optionally accept all mails if scanning procedure
 *			fails (Joe Talbott <josepht@cstone.net>)
 *	0.60p	5/11/03	Only call mutex_unlock when max_children is set
 *			Tidy up the call to pthread_cond_timedwait
 *	0.60q	11/11/03 Fixed handling of % characters in e-mail addresses
 *			pointed out by dotslash@snosoft.com
 *	0.65	15/11/03 Upissue of clamav
 *	0.65a	19/11/03 Close cmdSocket earlier
 *			Added setpgrp()
 *	0.65b	22/11/03 Ensure milter is not run as root if requested
 *			Added quarantine support
 *	0.65c	24/11/03 Support AllowSupplementaryGroups
 *			Fix warning about root usage
 *	0.65d	25/11/03 Handle empty hostname or hostaddr
 *			Fix based on a submission by Michael Dankov <misha@btrc.ru>
 *	0.65e	29/11/03 Fix problem of possible confused pointers if large
 *			number of recipients given.
 *			Fix by Michael Dankov <misha@btrc.ru>.
 *	0.65f	29/11/03 Added --quarantine-dir
 *			Thanks to Michael Dankov <misha@btrc.ru>.
 *	0.65g	2/12/03	Use setsid if setpgrp is not present.
 *			Thanks to Eugene Crosser <crosser@rol.ru>
 *	0.65h	4/12/03	Added call to umask to ensure that the local socket
 *			is not publically writeable. If it is sendmail
 *			will (correctly!) refuse to start this program
 *			Thanks for Nicklaus Wicker <n.wicker@cnk-networks.de>
 *			Don't sent From as the first line since that means
 *			clamd will think it is an mbox and not handle
 *			unescaped From at the start of lines properly
 *			Thanks to Michael Dankov <misha@btrc.ru>
 *	0.65i	9/12/03	Use the location of sendmail discovered by configure
 *	0.65j	10/12/03 Timeout on waiting for data from clamd
 *	0.65k	12/12/03 A couple of calls to clamfi_cleanup were missing
 *			before return cl_error
 *	0.66	13/12/03 Upissue
 *	0.66a	22/12/03 Added --sign
 *	0.66b	27/12/03 --sign moved to privdata
 *	0.66c	31/12/03 Included the sendmail queue ID in the log, from an
 *			idea by Andy Fiddaman <af@jeamland.org>
 *	0.66d	10/1/04	Added OpenBSD instructions
 *			Added --signature-file option
 *	0.66e	12/1/04	FixStaleSocket: no longer complain if asked to remove
 *			an old socket when there was none to remove
 *	0.66f	24/1/04	-s: Allow clamd server name as well as IPaddress
 *
 * Change History:
 * $Log: clamav-milter.c,v $
 * Revision 1.37  2004/01/24 18:09:39  nigelhorne
 * Allow clamd server name as well as IPaddress in -s option
 *
 * Revision 1.36  2004/01/12 15:30:53  nigelhorne
 * FixStaleSocket no longer complains on ENOENT
 *
 * Revision 1.35  2004/01/10 16:22:14  nigelhorne
 * Added OpenBSD instructions and --signature-file
 *
 * Revision 1.34  2003/12/31 14:46:35  nigelhorne
 * Include the sendmail queue ID in the log
 *
 * Revision 1.33  2003/12/27 17:28:56  nigelhorne
 * Moved --sign data to private area
 *
 * Revision 1.32  2003/12/22 14:05:31  nigelhorne
 * Added --sign option
 *
 * Revision 1.31  2003/12/13 16:43:21  nigelhorne
 * Upissue
 *
 * Revision 1.30  2003/12/12 13:42:47  nigelhorne
 * alls to clamfi_cleanup were missing
 *
 * Revision 1.29  2003/12/10 12:00:39  nigelhorne
 * Timeout on waiting for data from clamd
 *
 * Revision 1.28  2003/12/09 09:22:14  nigelhorne
 * Use the location of sendmail discovered by configure
 *
 * Revision 1.27  2003/12/05 19:14:07  nigelhorne
 * Set umask; handle unescaped From in mailboxes
 *
 * Revision 1.26  2003/12/02 06:37:26  nigelhorne
 * Use setsid if setpgrp not present
 *
 * Revision 1.25  2003/11/30 06:12:06  nigelhorne
 * Added --quarantine-dir option
 *
 * Revision 1.24  2003/11/29 11:51:19  nigelhorne
 * Fix problem of possible confused pointers if large number of recipients given
 *
 * Revision 1.23  2003/11/25 05:56:43  nigelhorne
 * Handle empty hostname or hostaddr
 *
 * Revision 1.22  2003/11/24 04:48:44  nigelhorne
 * Support AllowSupplementaryGroups
 *
 * Revision 1.21  2003/11/22 11:47:45  nigelhorne
 * Drop root priviliges and support quanrantine
 *
 * Revision 1.20  2003/11/19 16:32:22  nigelhorne
 * Close cmdSocket earlier
 *
 * Revision 1.19  2003/11/17 04:48:30  nigelhorne
 * Up issue to version 0.65
 *
 * Revision 1.18  2003/11/11 08:19:20  nigelhorne
 * Handle % characters in e-mail addresses
 *
 * Revision 1.17  2003/11/05 15:41:11  nigelhorne
 * Tidyup pthread_cond_timewait call
 *
 * Revision 1.16  2003/10/31 13:33:40  nigelhorne
 * Added dont scan on error flag
 *
 * Revision 1.15  2003/10/22 19:44:01  nigelhorne
 * more calls to pthread_cond_broadcast
 *
 * Revision 1.14  2003/10/12 08:37:21  nigelhorne
 * Uses VERSION command to get version information
 *
 * Revision 1.13  2003/10/11 15:42:15  nigelhorne
 * Don't call clamdscan
 *
 * Revision 1.12  2003/10/05 17:30:04  nigelhorne
 * Only fix old socket when FixStaleSocket is set
 *
 * Revision 1.11  2003/10/05 13:57:47  nigelhorne
 * Fixed handling of MaxThreads
 *
 * Revision 1.10  2003/10/03 11:54:53  nigelhorne
 * Added white list of recipients
 *
 * Revision 1.9  2003/09/30 11:53:55  nigelhorne
 * clamfi_envfrom was returning EX_TEMPFAIL in some places rather than SMFIS_TEMPFAIL
 *
 * Revision 1.8  2003/09/29 06:20:17  nigelhorne
 * max_children now overrides MaxThreads
 *
 * Revision 1.7  2003/09/29 06:07:49  nigelhorne
 * Ensure remoteIP is set before usage
 *
 * Revision 1.6  2003/09/28 16:37:23  nigelhorne
 * Added -f flag use MaxThreads if --max-children not set
 */
static	char	const	rcsid[] = "$Id: clamav-milter.c,v 1.37 2004/01/24 18:09:39 nigelhorne Exp $";

#define	CM_VERSION	"0.66f"

/*#define	CONFDIR	"/usr/local/etc"*/

#include "defaults.h"
#include "cfgfile.h"
#include "../target.h"

#ifndef	CL_DEBUG
#define	NDEBUG
#endif

#include <stdio.h>
#include <sysexits.h>
#ifndef HAVE_MALLOC_H
#include <malloc.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <assert.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdarg.h>
#include <errno.h>
#include <libmilter/mfapi.h>
#include <pthread.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <signal.h>
#include <regex.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include <netdb.h>

#define _GNU_SOURCE
#include "getopt.h"

#ifndef	SENDMAIL_BIN
#define	SENDMAIL_BIN	"/usr/lib/sendmail"
#endif

/*
 * TODO: optional: xmessage on console when virus stopped (SNMP would be real nice!)
 *	Having said that, with LogSysLog you can (on Linux) configure the system
 *	to get messages on the system console, see syslog.conf(5), also you
 *	can use wall(1) in the VirusEvent entry in clamav.conf
 * TODO: build with libclamav.so rather than libclamav.a
 * TODO: bounce message should optionally be read from a file
 * TODO: Support ThreadTimeout, LogTime and Logfile from the conf
 *	 file
 * TODO: Allow more than one clamdscan server to be given
 */

/*
 * Each thread has one of these
 */
struct	privdata {
	char	*from;	/* Who sent the message */
	char	**to;	/* Who is the message going to */
	int	numTo;	/* Number of people the message is going to */
	int	cmdSocket;	/*
				 * Socket to send/get commands e.g. PORT for
				 * dataSocket
				 */
	int	dataSocket;	/* Socket to send data to clamd */
	char	*filename;	/* Where to store the message in quarantine */
	u_char	*body;		/* body of the message if Sflag is set */
	size_t	bodyLen;	/* number of bytes in body */
};

static	int		pingServer(void);
static	sfsistat	clamfi_connect(SMFICTX *ctx, char *hostname, _SOCK_ADDR *hostaddr);
static	sfsistat	clamfi_envfrom(SMFICTX *ctx, char **argv);
static	sfsistat	clamfi_envrcpt(SMFICTX *ctx, char **argv);
static	sfsistat	clamfi_header(SMFICTX *ctx, char *headerf, char *headerv);
static	sfsistat	clamfi_eoh(SMFICTX *ctx);
static	sfsistat	clamfi_body(SMFICTX *ctx, u_char *bodyp, size_t len);
static	sfsistat	clamfi_eom(SMFICTX *ctx);
static	sfsistat	clamfi_abort(SMFICTX *ctx);
static	sfsistat	clamfi_close(SMFICTX *ctx);
static	void		clamfi_cleanup(SMFICTX *ctx);
static	int		clamfi_send(const struct privdata *privdata, size_t len, const char *format, ...);
static	char		*strrcpy(char *dest, const char *source);
static	int		clamd_recv(int sock, char *buf, size_t len);
static	off_t		updateSigFile(void);

static	char	clamav_version[128];
static	int	fflag = 0;	/* force a scan, whatever */
static	int	oflag = 0;	/* scan messages from our machine? */
static	int	lflag = 0;	/* scan messages from our site? */
static	int	bflag = 0;	/*
				 * send a failure (bounce) message to the
				 * sender. This probably isn't a good idea
				 * since most reply addresses will be fake
				 */
static	int	pflag = 0;	/*
				 * Send a warning to the postmaster only,
				 * this means user's won't be told when someone
				 * sent them a virus
				 */
static	int	qflag = 0;	/*
				 * Send no warnings when a virus is found,
				 * this means that the only log of viruses
				 * found is the syslog, so it's best to
				 * enable LogSyslog in clamav.conf
				 */
static	int	Sflag = 0;	/*
				 * Add a signature to each message that
				 * has been scanned
				 */
static	const	char	*sigFilename;	/*
				 * File where the scanned message signature
				 * can be found
				 */
static	char	*quarantine;	/*
				 * If a virus is found in an email redirect
				 * it to this account
				 */
static	char	*quarantine_dir; /*
				 * Path to store messages before scanning.
				 * Infected ones will be left there.
				 */
static	int	nflag = 0;	/*
				 * Don't add X-Virus-Scanned to header. Patch
				 * from Dirk Meyer <dirk.meyer@dinoex.sub.org>
				 */
static	int	cl_error = SMFIS_TEMPFAIL; /*
				 * If an error occurs, return
				 * this status. Allows messages
				 * to be passed through
				 * unscanned in the event of
				 * an error. Patch from
				 * Joe Talbott <josepht@cstone.net>
				 */
static	int	threadtimeout = CL_DEFAULT_SCANTIMEOUT; /*
				 * number of seconds to wait for clamd to
				 * respond
				 */
static	char	*signature = "-- \nScanned by ClamAv - http://www.clamav.net\n";
static	time_t	signatureStamp;

#ifdef	CL_DEBUG
static	int	debug_level = 0;
#endif

static	pthread_mutex_t	n_children_mutex = PTHREAD_MUTEX_INITIALIZER;
static	pthread_cond_t	n_children_cond = PTHREAD_COND_INITIALIZER;
static	unsigned	int	n_children = 0;
static	unsigned	int	max_children = 0;
static	int	use_syslog = 0;
static	int	logVerbose = 0;
static	struct	cfgstruct	*copt;
static	const	char	*localSocket;
static	in_port_t	tcpSocket;
static	const	char	*serverHostName = "127.0.0.1";
static	long	serverIP = -1L;	/* IPv4 only */
static	const	char	*postmaster = "postmaster";

/*
 * Whitelist of source e-mail addresses that we do NOT scan
 * TODO: read in from a file
 */
static	const	char	*ignoredEmailAddresses[] = {
	/*"Mailer-Daemon@bandsman.co.uk",
	"postmaster@bandsman.co.uk",*/
	NULL
};

static void
help(void)
{
	printf("\n\tclamav-milter version %s\n", CM_VERSION);
	puts("\tCopyright (C) 2003 Nigel Horne <njh@despammed.com>\n");

	puts("\t--bounce\t\t-b\tSend a failure message to the sender.");
	puts("\t--config-file=FILE\t-c FILE\tRead configuration from FILE.");
	puts("\t--dont-scan-on-error\t-d\tPass e-mails through unscanned if a system error occurs.");
	puts("\t--force-scan\t\t-f\tForce scan all messages (overrides (-o and -l).");
	puts("\t--help\t\t\t-h\tThis message.");
	puts("\t--local\t\t\t-l\tScan messages sent from machines on our LAN.");
	puts("\t--outgoing\t\t-o\tScan outgoing messages from this machine.");
	puts("\t--noxheader\t\t-n\tSuppress X-Virus-Scanned header.");
	puts("\t--postmaster\t\t-p EMAIL\tPostmaster address [default=postmaster].");
	puts("\t--postmaster-only\t-P\tSend warnings only to the postmaster.");
	puts("\t--quiet\t\t\t-q\tDon't send e-mail notifications of interceptions.");
	puts("\t--quarantine=USER\t-Q EMAIL\tQuanrantine e-mail account.");
	puts("\t--quarantine-dir=DIR\t-U DIR\tDirectory to store infected emails.");
	puts("\t--server=ADDRESS\t-s ADDR\tHostname/IP address of server running clamd (when using TCPsocket).");
	puts("\t--sign\t\t\t-S\tAdd a hard-coded signature to each scanned message.");
	puts("\t--signature-file\t-F\tLocation of signature file.");
	puts("\t--version\t\t-V\tPrint the version number of this software.");
#ifdef	CL_DEBUG
	puts("\t--debug-level=n\t\t-x n\tSets the debug level to 'n'.");
#endif
}

int
main(int argc, char **argv)
{
	extern char *optarg;
	char *port = NULL;
	const char *cfgfile = CL_DEFAULT_CFG;
	struct cfgstruct *cpt;
	struct passwd *user;
	struct smfiDesc smfilter = {
		"ClamAv", /* filter name */
		SMFI_VERSION,	/* version code -- leave untouched */
		SMFIF_ADDHDRS,	/* flags - we add headers */
		clamfi_connect, /* connection callback */
		NULL, /* HELO filter callback */
		clamfi_envfrom, /* envelope sender filter callback */
		clamfi_envrcpt, /* envelope recipient filter callback */
		clamfi_header, /* header filter callback */
		clamfi_eoh, /* end of header callback */
		clamfi_body, /* body filter callback */
		clamfi_eom, /* end of message callback */
		clamfi_abort, /* message aborted callback */
		clamfi_close, /* connection cleanup callback */
	};

	/*
	 * Temporarily enter guessed value into clamav_version, will
	 * be overwritten later by the value returned by clamd
	 */
	snprintf(clamav_version, sizeof(clamav_version),
		"ClamAV version %s, clamav-milter version %s",
		VERSION, CM_VERSION);

	for(;;) {
		int opt_index = 0;
#ifdef	CL_DEBUG
		const char *args = "bc:fF:lm:nop:PqQ:dhs:SU:Vx:";
#else
		const char *args = "bc:fF:lm:nop:PqQ:dhs:SU:V";
#endif

		static struct option long_options[] = {
			{
				"bounce", 0, NULL, 'b'
			},
			{
				"config-file", 1, NULL, 'c'
			},
			{
				"dont-scan-on-error", 0, NULL, 'd'
			},
			{
				"force-scan", 0, NULL, 'f'
			},
			{
				"help", 0, NULL, 'h'
			},
			{
				"local", 0, NULL, 'l'
			},
			{
				"noxheader", 0, NULL, 'n'
			},
			{
				"outgoing", 0, NULL, 'o'
			},
			{
				"postmaster", 1, NULL, 'p'
			},
			{
				"postmaster-only", 0, NULL, 'P',
			},
			{
				"quiet", 0, NULL, 'q'
			},
			{
				"quarantine", 1, NULL, 'Q',
			},
			{
				"quarantine-dir", 1, NULL, 'U',
			},
			{
				"max-children", 1, NULL, 'm'
			},
			{
				"server", 1, NULL, 's'
			},
			{
				"sign", 0, NULL, 'S'
			},
			{
				"signature-file", 1, NULL, 'F'
			},
			{
				"version", 0, NULL, 'V'
			},
#ifdef	CL_DEBUG
			{
				"debug-level", 1, NULL, 'x'
			},
#endif
			{
				NULL, 0, NULL, '\0'
			}
		};

		int ret = getopt_long(argc, argv, args, long_options, &opt_index);

		if(ret == -1)
			break;
		else if(ret == 0)
			ret = long_options[opt_index].val;

		switch(ret) {
			case 'b':	/* bounce worms/viruses */
				bflag++;
				break;
			case 'c':	/* where is clamav.conf? */
				cfgfile = optarg;
				break;
			case 'd':	/* don't scan on error */
				cl_error = SMFIS_ACCEPT;
				break;
			case 'f':	/* force the scan */
				fflag++;
				break;
			case 'h':
				help();
				return EX_OK;
			case 'l':	/* scan mail from the lan */
				lflag++;
				break;
			case 'm':	/* maximum number of children */
				max_children = atoi(optarg);
				break;
			case 'n':	/* don't add X-Virus-Scanned */
				nflag++;
				smfilter.xxfi_flags &= ~SMFIF_ADDHDRS;
				break;
			case 'o':	/* scan outgoing mail */
				oflag++;
				break;
			case 'p':	/* postmaster e-mail address */
				postmaster = optarg;
				break;
			case 'P':	/* postmaster only */
				pflag++;
				break;
			case 'q':	/* send NO notification email */
				qflag++;
				break;
			case 'Q':	/* quarantine e-mail address */
				quarantine = optarg;
				smfilter.xxfi_flags |= SMFIF_CHGHDRS|SMFIF_ADDRCPT|SMFIF_DELRCPT;
				break;
			case 's':	/* server running clamd */
				serverHostName = optarg;
				break;
			case 'F':	/* signature file */
				sigFilename = optarg;
				signature = NULL;
				/* fall through */
			case 'S':	/* sign */
				smfilter.xxfi_flags |= SMFIF_CHGBODY;
				Sflag++;
				break;
			case 'U':	/* quarantine path */
				quarantine_dir = optarg;
				break;
			case 'V':
				puts(clamav_version);
				return EX_OK;
#ifdef	CL_DEBUG
			case 'x':
				debug_level = atoi(optarg);
				break;
#endif
			default:
#ifdef	CL_DEBUG
				fprintf(stderr, "Usage: %s [-b] [-c FILE] [-F FILE] [--max-children=num] [-l] [-o] [-p address] [-P] [-q] [-Q USER] [-S] [-x#] [-U PATH] socket-addr\n", argv[0]);
#else
				fprintf(stderr, "Usage: %s [-b] [-c FILE] [-F FILE] [--max-children=num] [-l] [-o] [-p address] [-P] [-q] [-Q USER] [-S] [-U PATH] socket-addr\n", argv[0]);
#endif
				return EX_USAGE;
		}
	}

	if (optind == argc) {
		fprintf(stderr, "%s: No socket-addr given\n", argv[0]);
		return EX_USAGE;
	}
	port = argv[optind];

	/*
	 * Sanity checks on the clamav configuration file
	 */
	if((copt = parsecfg(cfgfile)) == NULL) {
		fprintf(stderr, "%s: Can't parse the config file %s\n",
			argv[0], cfgfile);
		return EX_CONFIG;
	}

	/*
	 * Drop privileges
	 */
	if(getuid() == 0) {
		if((cpt = cfgopt(copt, "User")) != NULL) {
			if((user = getpwnam(cpt->strarg)) == NULL) {
				fprintf(stderr, "%s: Can't get information about user %s\n", argv[0], cpt->strarg);
				return EX_CONFIG;
			}

			if(cfgopt(copt, "AllowSupplementaryGroups"))
				initgroups(cpt->strarg, user->pw_gid);
			else
				setgroups(1, &user->pw_gid);

			setgid(user->pw_gid);
			setuid(user->pw_uid);
		} else
			fprintf(stderr, "%s: running as root is not recommended\n", argv[0]);
	}
	if(quarantine_dir && (access(quarantine_dir, W_OK) < 0)) {
		perror(quarantine_dir);
		return EX_CONFIG;
	}

	if(sigFilename && !updateSigFile())
		return EX_USAGE;

	if(!cfgopt(copt, "StreamSaveToDisk")) {
		fprintf(stderr, "%s: StreamSavetoDisk not enabled in %s\n",
			argv[0], cfgfile);
		return EX_CONFIG;
	}

	if(!cfgopt(copt, "ScanMail")) {
		fprintf(stderr, "%s: ScanMail not enabled in %s\n",
			argv[0], cfgfile);
		return EX_CONFIG;
	}

	/*
	 * patch from "Richard G. Roberto" <rgr@dedlegend.com>
	 * If the --max-children flag isn't set, see if MaxThreads
	 * is set in the config file
	 */
	if((max_children == 0) && ((cpt = cfgopt(copt, "MaxThreads")) != NULL))
		max_children = cpt->numarg;

	if((cpt = cfgopt(copt, "ThreadTimeout")) != NULL) {
		threadtimeout = cpt->numarg;

		if(threadtimeout < 0) {
			fprintf(stderr, "%s: ThreadTimeout must not be negative in %s\n",
				argv[0], cfgfile);
		}
	}

	/*
	 * Get the outgoing socket details - the way to talk to clamd
	 */
	if((cpt = cfgopt(copt, "LocalSocket")) != NULL) {
		if(cfgopt(copt, "TCPSocket") != NULL) {
			fprintf(stderr, "%s: You can select one server type only (local/TCP) in %s\n",
				argv[0], cfgfile);
			return EX_CONFIG;
		}
		/*
		 * TODO: check --server hasn't been set
		 */
		localSocket = cpt->strarg;
		if(!pingServer()) {
			fprintf(stderr, "Can't talk to clamd server via %s\n",
				localSocket);
			fprintf(stderr, "Check your entry for LocalSocket in %s\n",
				cfgfile);
			return EX_CONFIG;
		}
		umask(022);
	} else if((cpt = cfgopt(copt, "TCPSocket")) != NULL) {
		/*
		 * TCPSocket is in fact a port number not a full socket
		 */
		if(quarantine_dir) {
			fprintf(stderr, "%s: --quarantine-dir not supported for remote scanning - use --quarantine\n", argv[0]);
			return EX_CONFIG;
		}

		/*
		 * Translate server's name to IP address
		 */
		serverIP = inet_addr(serverHostName);
		if(serverIP == -1L) {
			const struct hostent *h = gethostbyname(serverHostName);

			if(h == NULL) {
				fprintf(stderr, "%s: Unknown host %s\n",
					argv[0], serverHostName);
				return EX_USAGE;
			}

			memcpy((char *)&serverIP, h->h_addr, sizeof(serverIP));
		}

		tcpSocket = cpt->numarg;

		if(!pingServer()) {
			fprintf(stderr, "Can't talk to clamd server at %s on port %d\n",
				serverHostName, tcpSocket);
			fprintf(stderr, "Check your entry for TCPSocket in %s\n",
				cfgfile);
			return EX_CONFIG;
		}
	} else {
		fprintf(stderr, "%s: You must select server type (local/TCP) in %s\n",
			argv[0], cfgfile);
		return EX_CONFIG;
	}

	if(!cfgopt(copt, "Foreground")) {

#ifdef	CL_DEBUG
		printf("When debugging it is recommended that you use Foreground mode in %s\n", cfgfile);
		puts("So that you can see all of the messages");
#endif

		switch(fork()) {
			case -1:
				perror("fork");
				return EX_TEMPFAIL;
			case 0:	/* child */
				break;
			default:	/* parent */
				return EX_OK;
		}
		close(0);
		close(1);
		close(2);
		open("/dev/null", O_RDONLY);
		if(open("/dev/console", O_WRONLY) == 1)
			dup(1);
#ifdef HAVE_SETPGRP
#ifdef SETPGRP_VOID
		setpgrp();
#else
		setpgrp(0,0);
#endif
#else
#ifdef HAVE_SETSID
		 setsid();
#endif
#endif
	}

	if(smfi_setconn(port) == MI_FAILURE) {
		fprintf(stderr, "%s: smfi_setconn failed\n",
			argv[0]);
		return EX_SOFTWARE;
	}

	if(cfgopt(copt, "LogSyslog")) {
		openlog("clamav-milter", LOG_CONS|LOG_PID, LOG_MAIL);
		syslog(LOG_INFO, clamav_version);
#ifdef	CL_DEBUG
		if(debug_level > 0)
			syslog(LOG_DEBUG, "Debugging is on");
#endif
		use_syslog = 1;

		if(cfgopt(copt, "LogVerbose"))
			logVerbose = 1;
	} else {
		if(qflag)
			fprintf(stderr, "%s: (-q && !LogSysLog): warning - all interception message methods are off\n",
				argv[0]);
		use_syslog = 0;
	}

	if(cfgopt(copt, "FixStaleSocket")) {
		/*
		 * Get the incoming socket details - the way sendmail talks to
		 * us
		 *
		 * TODO: There's a security problem here that'll need fixing if
		 * the User entry of clamav.conf is not used
		 */
		if(strncasecmp(port, "unix:", 5) == 0) {
			if(unlink(&port[5]) < 0)
				if(errno != ENOENT)
					perror(&port[5]);
		} else if(strncasecmp(port, "local:", 6) == 0) {
			if(unlink(&port[6]) < 0)
				if(errno != ENOENT)
					perror(&port[6]);
		}
	}

	if(smfi_register(smfilter) == MI_FAILURE) {
		fputs("smfi_register failure\n", stderr);
		return EX_UNAVAILABLE;
	}

	signal(SIGPIPE, SIG_IGN);

	return smfi_main();
}

/*
 * Verify that the server is where we think it is
 * Returns true or false
 */
static int
pingServer(void)
{
	char *ptr;
	int sock, nbytes;
	char buf[128];

	if(localSocket) {
		struct sockaddr_un server;

		memset((char *)&server, 0, sizeof(struct sockaddr_un));
		server.sun_family = AF_UNIX;
		strncpy(server.sun_path, localSocket, sizeof(server.sun_path));

		if((sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
			perror("socket");
			return 0;
		}
		if(connect(sock, (struct sockaddr *)&server, sizeof(struct sockaddr_un)) < 0) {
			perror(localSocket);
			return 0;
		}
	} else {
		struct sockaddr_in server;

		memset((char *)&server, 0, sizeof(struct sockaddr_in));
		server.sin_family = AF_INET;
		server.sin_port = htons(tcpSocket);
		
		assert(serverIP != -1L);

		server.sin_addr.s_addr = serverIP;

		if((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
			perror("socket");
			return 0;
		}
		if(connect(sock, (struct sockaddr *)&server, sizeof(struct sockaddr_in)) < 0) {
			perror("connect");
			return 0;
		}
	}

	/*
	 * It would be better to use PING, check for PONG then issue the
	 * VERSION command, since that would better validate that we're
	 * talking to clamd, however clamd closes the session after
	 * sending PONG :-(
	 * So this code does not really validate that we're talking to clamd
	 * Needs a fix to clamd
	 * Also version command is verbose: says "clamd / ClamAV version"
	 * instead of "clamAV version"
	 */
	if(send(sock, "VERSION\n", 8, 0) < 8) {
		perror("send");
		close(sock);
		return 0;
	}

	shutdown(sock, SHUT_WR);

	nbytes = clamd_recv(sock, buf, sizeof(buf));

	close(sock);

	if(nbytes < 0) {
		perror("recv");
		return 0;
	}
	if(nbytes == 0)
		return 0;

	buf[nbytes] = '\0';

	/* Remove the trailing new line from the reply */
	if((ptr = strchr(buf, '\n')) != NULL)
		*ptr = '\0';

	/*
	 * No real validation is done here
	 */
	snprintf(clamav_version, sizeof(clamav_version),
		"ClamAV version '%s', clamav-milter version '%s'",
		buf, CM_VERSION);

	return 1;
}

static sfsistat
clamfi_connect(SMFICTX *ctx, char *hostname, _SOCK_ADDR *hostaddr)
{
	char buf[INET_ADDRSTRLEN];	/* IPv4 only */
	const char *remoteIP;

	if(hostname == NULL) {
		if(use_syslog)
			syslog(LOG_ERR, "clamfi_connect: hostname is null");
		return cl_error;
	}
	if(hostaddr == NULL) {
		if(use_syslog)
			syslog(LOG_ERR, "clamfi_connect: hostaddr is null");
		return cl_error;
	}

	remoteIP = inet_ntop(AF_INET, &((struct sockaddr_in *)(hostaddr))->sin_addr, buf, sizeof(buf));

	if(remoteIP == NULL) {
		if(use_syslog)
			syslog(LOG_ERR, "clamfi_connect: remoteIP is null");
		return cl_error;
	}

#ifdef	CL_DEBUG
	if(debug_level >= 4) {
		if(use_syslog)
			syslog(LOG_NOTICE, "clamfi_connect: connection from %s [%s]", hostname, remoteIP);
		printf("clamfi_connect: connection from %s [%s]\n", hostname, remoteIP);
	}
#endif

	if(fflag)
		/*
		 * Patch from "Richard G. Roberto" <rgr@dedlegend.com>
		 * Always scan whereever the message is from
		 */
		return SMFIS_CONTINUE;

	if(!oflag)
		if(strcmp(remoteIP, "127.0.0.1") == 0) {
#ifdef	CL_DEBUG
			if(use_syslog)
				syslog(LOG_DEBUG, "clamfi_connect: not scanning outgoing messages");
			puts("clamfi_connect: not scanning outgoing messages");
#endif
			return SMFIS_ACCEPT;
		}
	if(!lflag) {
		/*
		 * Decide what constitutes a local IP address. Emails from
		 * local machines are not scanned.
		 *
		 * TODO: read these from clamav.conf
		 */
		static const char *localAddresses[] = {
			/*"^192\\.168\\.[0-9]+\\.[0-9]+$",*/
			"^192\\.168\\.[0-9]*\\.[0-9]*$",
			"^10\\.0\\.0\\.[0-9]*$",
			"127.0.0.1",
			NULL
		};
		const char **possible;

		for(possible = localAddresses; *possible; possible++) {
			int rc;
			regex_t reg;

			if(regcomp(&reg, *possible, 0) != 0) {
				if(use_syslog)
					syslog(LOG_ERR, "Couldn't parse local regexp");
				return cl_error;
			}

			rc = (regexec(&reg, remoteIP, 0, NULL, 0) == REG_NOMATCH) ? 0 : 1;

			regfree(&reg);

			if(rc) {
#ifdef	CL_DEBUG
				if(use_syslog)
					syslog(LOG_DEBUG, "clamfi_connect: not scanning local messages");
				puts("clamfi_connect: not scanning outgoing messages");
#endif
				return SMFIS_ACCEPT;
			}
		}
	}
	return SMFIS_CONTINUE;
}

static sfsistat
clamfi_envfrom(SMFICTX *ctx, char **argv)
{
	struct privdata *privdata;
	struct sockaddr_in reply;
	unsigned short port;
	int nbytes, rc;
	char buf[64];

	if(logVerbose)
		syslog(LOG_DEBUG, "clamfi_envfrom: %s", argv[0]);

#ifdef	CL_DEBUG
	printf("clamfi_envfrom: %s\n", argv[0]);
#endif

	if(max_children > 0) {
		rc = 0;

		pthread_mutex_lock(&n_children_mutex);

		/*
		 * Not a while since sendmail doesn't like it if we
		 * take too long replying. Effectively this means that
		 * max_children is more of a hint than a rule
		 */
		if(n_children >= max_children) {
			struct timeval now;
			struct timespec timeout;
			struct timezone tz;

			/*
			 * Use pthread_cond_timedwait rather than
			 * pthread_cond_wait since the sendmail which calls
			 * us will have a timeout that we don't want to exceed
			 *
			 * Wait for a maximum of 1 minute.
			 *
			 * TODO: this timeout should be configurable
			 * It stops sendmail getting fidgety.
			 */
			gettimeofday(&now, &tz);
			timeout.tv_sec = now.tv_sec + 60;
			timeout.tv_nsec = 0;

			if(use_syslog)
				syslog(LOG_NOTICE,
					"hit max-children limit (%u >= %u): waiting for some to exit",
					n_children, max_children);
			do
				rc = pthread_cond_timedwait(&n_children_cond, &n_children_mutex, &timeout);
			while(rc != ETIMEDOUT);
		}
		n_children++;

#ifdef	CL_DEBUG
		printf(">n_children = %d\n", n_children);
#endif
		pthread_mutex_unlock(&n_children_mutex);

		if(rc == ETIMEDOUT) {
#ifdef	CL_DEBUG
			if(use_syslog)
				syslog(LOG_NOTICE, "Timeout waiting for a child to die");
			puts("Timeout waiting for a child to die");
#endif
		}
	}

	privdata = (struct privdata *)calloc(1, sizeof(struct privdata));
	privdata->dataSocket = -1;	/* 0.4 */
	privdata->cmdSocket = -1;	/* 0.4 */

	if(quarantine_dir) {
		/*
		 * quarantine_dir is specified
		 * store message in a temporary file
		 */
		int ntries = 5;

		privdata->filename = malloc(strlen(quarantine_dir) + 12);

		do {
			sprintf(privdata->filename, "%s/msg.XXXXXX", quarantine_dir);
#if	defined(C_LINUX) || defined(C_BSD)
			privdata->dataSocket = mkstemp(privdata->filename);
#else
			if(mktemp(privdata->filename) == NULL) {
				if(use_syslog)
					syslog(LOG_ERR, "mktemp %s failed", privdata->filename);
				free(privdata->filename);
				privdata->filename = NULL;
				return cl_error;
			}
			privdata->dataSocket = open(privdata->filename, O_CREAT|O_EXCL|O_WRONLY|O_TRUNC, 0600);
#endif
		} while((--ntries > 0) && (privdata->dataSocket < 0));

		if(privdata->dataSocket < 0) {
			if(use_syslog)
				syslog(LOG_ERR, "tempfile %s creation failed", privdata->filename);
			free(privdata->filename);
			privdata->filename = NULL;
			return cl_error;
		}
	} else {
		/*
		 * Create socket to talk to clamd. It will tell us the port to use
		 * to send the data. That will require another socket.
		 */
		if(localSocket) {
			struct sockaddr_un server;

			memset((char *)&server, 0, sizeof(struct sockaddr_un));
			server.sun_family = AF_UNIX;
			strncpy(server.sun_path, localSocket, sizeof(server.sun_path));

			if((privdata->cmdSocket = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
				perror("socket");
				return cl_error;
			}
			if(connect(privdata->cmdSocket, (struct sockaddr *)&server, sizeof(struct sockaddr_un)) < 0) {
				perror(localSocket);
				return cl_error;
			}
		} else {
			struct sockaddr_in server;

			memset((char *)&server, 0, sizeof(struct sockaddr_in));
			server.sin_family = AF_INET;
			server.sin_port = htons(tcpSocket);

			assert(serverIP != -1L);

			server.sin_addr.s_addr = serverIP;

			if((privdata->cmdSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
				perror("socket");
				return cl_error;
			}
			if(connect(privdata->cmdSocket, (struct sockaddr *)&server, sizeof(struct sockaddr_in)) < 0) {
				perror("connect");
				return cl_error;
			}
		}

		/*
		 * Create socket that we'll use to send the data to clamd
		 */
		if((privdata->dataSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
			perror("socket");
			close(privdata->cmdSocket);
			free(privdata);
			if(use_syslog)
				syslog(LOG_ERR, "failed to create socket");
			return cl_error;
		}

		shutdown(privdata->dataSocket, SHUT_RD);

		if(send(privdata->cmdSocket, "STREAM\n", 7, 0) < 7) {
			perror("send");
			close(privdata->dataSocket);
			close(privdata->cmdSocket);
			free(privdata);
			if(use_syslog)
				syslog(LOG_ERR, "send failed to clamd");
			return cl_error;
		}

		shutdown(privdata->cmdSocket, SHUT_WR);

		nbytes = clamd_recv(privdata->cmdSocket, buf, sizeof(buf));
		if(nbytes < 0) {
			perror("recv");
			close(privdata->dataSocket);
			close(privdata->cmdSocket);
			free(privdata);
			if(use_syslog)
				syslog(LOG_ERR, "recv failed from clamd getting PORT");
			return cl_error;
		}
		buf[nbytes] = '\0';
#ifdef	CL_DEBUG
		if(debug_level >= 4)
			printf("Received: %s", buf);
#endif
		if(sscanf(buf, "PORT %hu\n", &port) != 1) {
			close(privdata->dataSocket);
			close(privdata->cmdSocket);
			free(privdata);
			if(use_syslog)
				syslog(LOG_ERR, "Expected port information from clamd, got '%s'",
					buf);
			else
				fprintf(stderr, "Expected port information from clamd, got '%s'\n",
					buf);
			return cl_error;
		}

		memset((char *)&reply, 0, sizeof(struct sockaddr_in));
		reply.sin_family = AF_INET;
		reply.sin_port = ntohs(port);

		assert(serverIP != -1L);

		reply.sin_addr.s_addr = serverIP;

#ifdef	CL_DEBUG
		if(debug_level >= 4)
			printf("Connecting to local port %d\n", port);
#endif

		rc = connect(privdata->dataSocket, (struct sockaddr *)&reply, sizeof(struct sockaddr_in));

		if(rc < 0) {
			perror("connect");

			close(privdata->dataSocket);
			close(privdata->cmdSocket);
			free(privdata);

			/* 0.4 - use better error message */
			if(use_syslog) {
#ifdef TARGET_OS_SOLARIS	/* no strerror_r */
				syslog(LOG_ERR, "Failed to connect to port %d given by clamd: %s", port, strerror(rc));
#else
				strerror_r(rc, buf, sizeof(buf));
				syslog(LOG_ERR, "Failed to connect to port %d given by clamd: %s", port, buf);
#endif
			}

			return cl_error;
		}
	}

	clamfi_send(privdata, 0, "Received: by clamav-milter\nFrom: %s\n", argv[0]);

	privdata->from = strdup(argv[0]);
	privdata->to = NULL;

	return (smfi_setpriv(ctx, privdata) == MI_SUCCESS) ? SMFIS_CONTINUE : cl_error;
}

static sfsistat
clamfi_envrcpt(SMFICTX *ctx, char **argv)
{
	struct privdata *privdata = (struct privdata *)smfi_getpriv(ctx);

	if(logVerbose)
		syslog(LOG_DEBUG, "clamfi_envrcpt: %s", argv[0]);

#ifdef	CL_DEBUG
	printf("clamfi_envrcpt: %s \n", argv[0]);
#endif

	clamfi_send(privdata, 0, "To: %s\n", argv[0]);

	if(privdata->to == NULL) {
		privdata->to = malloc(sizeof(char *) * 2);

		assert(privdata->numTo == 0);
	} else
		privdata->to = realloc(privdata->to, sizeof(char *) * (privdata->numTo + 2));

	privdata->to[privdata->numTo] = strdup(argv[0]);
	privdata->to[++privdata->numTo] = NULL;

	return SMFIS_CONTINUE;
}

static sfsistat
clamfi_header(SMFICTX *ctx, char *headerf, char *headerv)
{
	struct privdata *privdata = (struct privdata *)smfi_getpriv(ctx);

	if(logVerbose)
		syslog(LOG_DEBUG, "clamfi_header: %s: %s", headerf, headerv);
#ifdef	CL_DEBUG
	if(debug_level >= 9)
		printf("clamfi_header: %s: %s\n", headerf, headerv);
	else
		puts("clamfi_header");
#endif

	if(clamfi_send(privdata, 0, "%s: %s\n", headerf, headerv) < 0) {
		clamfi_cleanup(ctx);
		return cl_error;
	}
	return SMFIS_CONTINUE;
}

static sfsistat
clamfi_eoh(SMFICTX *ctx)
{
	struct privdata *privdata = (struct privdata *)smfi_getpriv(ctx);
	char **to;

	if(logVerbose)
		syslog(LOG_DEBUG, "clamfi_eoh");
#ifdef	CL_DEBUG
	puts("clamfi_eoh");
#endif

	if(clamfi_send(privdata, 1, "\n") < 0) {
		clamfi_cleanup(ctx);
		return cl_error;
	}

	/*
	 * See if the e-mail is only going to members of the list
	 * of users we don't scan for. If it is, don't scan, otherwise
	 * scan
	 *
	 * scan = false
	 * FORALL recipients
	 *	IF receipient NOT MEMBER OF white address list
	 *	THEN
	 *		scan = true
	 *	FI
	 * ENDFOR
	 */
	for(to = privdata->to; *to; to++) {
		const char **s;

		for(s = ignoredEmailAddresses; *s; s++)
			if(strcasecmp(*s, *to) == 0)
				/*
				 * This recipient is on the whitelist
				 */
				break;

		if(*s == NULL)
			/*
			 * This recipient is not on the whitelist,
			 * no need to check any further
			 */
			return SMFIS_CONTINUE;
	}
	/*
	 * Didn't find a recipient who is not on the white list, so all
	 * must be on the white list, so just accept the e-mail
	 */
	if(use_syslog)
		syslog(LOG_NOTICE, "clamfi_connect: ignoring whitelisted message");
#ifdef	CL_DEBUG
	puts("clamfi_connect: not scanning outgoing messages");
#endif
	clamfi_cleanup(ctx);

	return SMFIS_ACCEPT;
}

static sfsistat
clamfi_body(SMFICTX *ctx, u_char *bodyp, size_t len)
{
	struct privdata *privdata = (struct privdata *)smfi_getpriv(ctx);

	if(logVerbose)
		syslog(LOG_DEBUG, "clamfi_envbody: %u bytes", len);
#ifdef	CL_DEBUG
	printf("clamfi_envbody: %u bytes\n", len);
#endif

	if(clamfi_send(privdata, len, (char *)bodyp) < 0) {
		clamfi_cleanup(ctx);
		return cl_error;
	}
	if(Sflag) {
		if(privdata->body) {
			assert(privdata->bodyLen > 0);
			privdata->body = realloc(privdata->body, privdata->bodyLen + len);
			memcpy(&privdata->body[privdata->bodyLen], bodyp, len);
			privdata->bodyLen += len;
		} else {
			assert(privdata->bodyLen == 0);
			privdata->body = malloc(len);
			memcpy(privdata->body, bodyp, len);
			privdata->bodyLen = len;
		}
	}
	return SMFIS_CONTINUE;
}

static sfsistat
clamfi_eom(SMFICTX *ctx)
{
	int rc = SMFIS_CONTINUE;
	char *ptr;
	struct privdata *privdata = (struct privdata *)smfi_getpriv(ctx);
	char mess[128];

	if(logVerbose)
		syslog(LOG_DEBUG, "clamfi_eom");
#ifdef	CL_DEBUG
	puts("clamfi_eom");
	assert(privdata != NULL);
	assert((privdata->cmdSocket >= 0) || (privdata->filename != NULL));
	assert(!((privdata->cmdSocket >= 0) && (privdata->filename != NULL)));
	assert(privdata->dataSocket >= 0);
#endif

	close(privdata->dataSocket);
	privdata->dataSocket = -1;

	if(quarantine_dir != NULL) {
		char cmdbuf[1024];
		/*
		 * Create socket to talk to clamd.
		 */
		struct sockaddr_un server;
		int nbytes;

		assert(localSocket != NULL);

		memset((char *)&server, 0, sizeof(struct sockaddr_un));
		server.sun_family = AF_UNIX;
		strncpy(server.sun_path, localSocket, sizeof(server.sun_path));

		if((privdata->cmdSocket = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
			perror("socket");
			clamfi_cleanup(ctx);
			return cl_error;
		}
		if(connect(privdata->cmdSocket, (struct sockaddr *)&server, sizeof(struct sockaddr_un)) < 0) {
			perror(localSocket);
			clamfi_cleanup(ctx);
			return cl_error;
		}

		snprintf(cmdbuf, sizeof(cmdbuf) - 1, "SCAN %s", privdata->filename);

		nbytes = (int)strlen(cmdbuf);

		if(send(privdata->cmdSocket, cmdbuf, nbytes, 0) < nbytes) {
			perror("send");
			clamfi_cleanup(ctx);
			if(use_syslog)
				syslog(LOG_ERR, "send failed to clamd");
			return cl_error;
		}

		shutdown(privdata->cmdSocket, SHUT_WR);
	}

	if(clamd_recv(privdata->cmdSocket, mess, sizeof(mess)) > 0) {
		if((ptr = strchr(mess, '\n')) != NULL)
			*ptr = '\0';

		if(logVerbose)
			syslog(LOG_DEBUG, "clamfi_eom: read %s", mess);
#ifdef	CL_DEBUG
		printf("clamfi_eom: read %s\n", mess);
#endif
	} else {
		clamfi_cleanup(ctx);
		syslog(LOG_NOTICE, "clamfi_eom: read nothing from clamd");
#ifdef	CL_DEBUG
		puts("clamfi_eom: read nothing from clamd");
#endif
		return cl_error;
	}

	close(privdata->cmdSocket);
	privdata->cmdSocket = -1;

	if(strstr(mess, "FOUND") == NULL) {
		if(!nflag)
			smfi_addheader(ctx, "X-Virus-Scanned", clamav_version);

		/*
		 * TODO: if privdata->from is NULL it's probably SPAM, and
		 * me might consider bouncing it...
		 */
		if(use_syslog)
			/* Include the sendmail queue ID in the log */
			syslog(LOG_NOTICE, "%s: clean message from %s",
				smfi_getsymval(ctx, "i"),
				(privdata->from) ? privdata->from : "an unknown sender");

		if(privdata->body) {
			/*
			 * Add a signature that all has been scanned OK
			 */
			off_t len = updateSigFile();

			if(len) {
				assert(Sflag != 0);

				privdata->body = realloc(privdata->body, privdata->bodyLen + len);
				memcpy(&privdata->body[privdata->bodyLen], signature, len);

				smfi_replacebody(ctx, privdata->body, privdata->bodyLen + len);
			}
		}
	} else {
		int i;
		char **to, *err;
		FILE *sendmail;

		if(use_syslog)
			syslog(LOG_NOTICE, mess);

		/*
		 * Setup err as a list of recipients
		 */
		err = (char *)malloc(1024);

		/*
		 * Use snprintf rather than printf since we don't know the
		 * length of privdata->from and may get a buffre overrun
		 * causing a crash
		 */
		snprintf(err, 1024, "Intercepted virus from %s to", privdata->from);

		ptr = strchr(err, '\0');

		i = 1024;

		for(to = privdata->to; *to; to++) {
			/*
			 * Re-alloc if we are about run out of buffer space
			 */
			if(&ptr[strlen(*to) + 2] >= &err[i]) {
				i += 1024;
				err = realloc(err, i);
				ptr = strchr(err, '\0');
			}
			ptr = strrcpy(ptr, " ");
			ptr = strrcpy(ptr, *to);
		}
		(void)strcpy(ptr, "\n");

		if(use_syslog)
			/* Include the sendmail queue ID in the log */
			syslog(LOG_NOTICE, "%s: %s",
				smfi_getsymval(ctx, "i"),
				err);
#ifdef	CL_DEBUG
		puts(err);
#endif
		free(err);

		if(!qflag) {
			char cmd[128];

			snprintf(cmd, sizeof(cmd), "%s -t", SENDMAIL_BIN);

			sendmail = popen(cmd, "w");

			if(sendmail) {
				/*
				 * TODO: Make this e-mail message customisable
				 * perhaps by means of a template
				 */
				fputs("From: MAILER-DAEMON\n", sendmail);
				if(bflag) {
					fprintf(sendmail, "To: %s\n", privdata->from);
					fprintf(sendmail, "Cc: %s\n", postmaster);
				} else
					fprintf(sendmail, "To: %s\n", postmaster);

				if(!pflag)
					for(to = privdata->to; *to; to++)
						fprintf(sendmail, "Cc: %s\n", *to);
				fputs("Subject: Virus intercepted\n\n", sendmail);

				if(bflag)
					fputs("A message you sent to\n\t", sendmail);
				else
					fprintf(sendmail, "A message sent from %s to\n\t", privdata->from);

				for(to = privdata->to; *to; to++)
					fprintf(sendmail, "%s\n", *to);
				fputs("contained a virus and has not been delivered.\n\t", sendmail);
				fputs(mess, sendmail);

				if(privdata->filename != NULL)
					fprintf(sendmail, "\nThe message in question is quarantined as %s\n", privdata->filename);

				pclose(sendmail);
			}
		}

		if(privdata->filename) {
			assert(quarantine_dir != NULL);

			if(use_syslog)
				syslog(LOG_NOTICE, "Quarantined infected mail as %s", privdata->filename);
			/*
			 * Cleanup filename here! Default procedure would delete quarantine file
			 */
			free(privdata->filename);
			privdata->filename = NULL;
		}

		if(quarantine) {
			for(to = privdata->to; *to; to++) {
				smfi_delrcpt(ctx, *to);
				smfi_addheader(ctx, "X-Original-To", *to);
				free(*to);
			}
			free(privdata->to);
			privdata->to = NULL;
			if(smfi_addrcpt(ctx, quarantine) == MI_FAILURE) {
				if(use_syslog)
					syslog(LOG_DEBUG, "Can't set quarantine user %s", quarantine);
				else
					fprintf(stderr, "Can't set quarantine user %s\n", quarantine);
			} else
				/*
				 * FIXME: doesn't work if there's no subject
				 */
				smfi_chgheader(ctx, "Subject", 1, mess);
		} else
			rc = SMFIS_REJECT;	/* Delete the e-mail */

		smfi_setreply(ctx, "550", "5.7.1", "Virus detected by ClamAV - http://clamav.elektrapro.com");
	}
	clamfi_cleanup(ctx);

	return rc;
}

static sfsistat
clamfi_abort(SMFICTX *ctx)
{
#ifdef	CL_DEBUG
	if(use_syslog)
		syslog(LOG_DEBUG, "clamfi_abort");
	puts("clamfi_abort");
#endif

	/*
	 * Unlock incase we're called during a cond_timedwait in envfrom
	 *
	 * TODO: There *must* be a tidier way of doing this!
	 */
	if(max_children > 0)
		(void)pthread_mutex_unlock(&n_children_mutex);

	clamfi_cleanup(ctx);

	return cl_error;
}

static sfsistat
clamfi_close(SMFICTX *ctx)
{
#ifdef	CL_DEBUG
	struct privdata *privdata = (struct privdata *)smfi_getpriv(ctx);

	puts("clamfi_close");
	assert(privdata == NULL);
#endif

	if(logVerbose)
		syslog(LOG_DEBUG, "clamfi_close");

	return SMFIS_CONTINUE;
}

static void
clamfi_cleanup(SMFICTX *ctx)
{
	struct privdata *privdata = (struct privdata *)smfi_getpriv(ctx);

	if(privdata) {
		if(privdata->body)
			free(privdata->body);

		if(privdata->dataSocket >= 0) {
			close(privdata->dataSocket);
			privdata->dataSocket = -1;
		}

		if(privdata->filename != NULL) {
			if(unlink(privdata->filename) < 0)
				perror(privdata->filename);
			free(privdata->filename);
			privdata->filename = NULL;
		}

		if(privdata->from) {
#ifdef	CL_DEBUG
			if(debug_level >= 9)
				puts("Free privdata->from");
#endif
			free(privdata->from);
			privdata->from = NULL;
		}

		if(privdata->to) {
			char **to;

			for(to = privdata->to; *to; to++) {
#ifdef	CL_DEBUG
				if(debug_level >= 9)
					puts("Free *privdata->to");
#endif
				free(*to);
			}
#ifdef	CL_DEBUG
			if(debug_level >= 9)
				puts("Free privdata->to");
#endif
			free(privdata->to);
			privdata->to = NULL;
		}

		if(privdata->cmdSocket >= 0) {
			char buf[64];

			/*
			 * Flush the remote end so that clamd doesn't get a SIGPIPE
			 */
			while(clamd_recv(privdata->cmdSocket, buf, sizeof(buf)) > 0)
				;
			close(privdata->cmdSocket);
			privdata->cmdSocket = -1;
		}

#ifdef	CL_DEBUG
		if(debug_level >= 9)
			puts("Free privdata");
#endif
		free(privdata);
		smfi_setpriv(ctx, NULL);
	}

	if(max_children > 0) {
		pthread_mutex_lock(&n_children_mutex);
		/*
		 * Deliberately errs on the side of broadcasting too many times
		 */
		if(n_children > 0)
			--n_children;
#ifdef	CL_DEBUG
		puts("pthread_cond_broadcast");
#endif
		pthread_cond_broadcast(&n_children_cond);
#ifdef	CL_DEBUG
		printf("<n_children = %d\n", n_children);
#endif
		pthread_mutex_unlock(&n_children_mutex);
	}
}

static int
clamfi_send(const struct privdata *privdata, size_t len, const char *format, ...)
{
	char output[BUFSIZ];
	const char *ptr;

	assert(format != NULL);

	if(len > 0)
		/*
		 * It isn't a NUL terminated string. We have a set number of
		 * bytes to output.
		 */
		ptr = format;
	else {
		va_list argp;

		va_start(argp, format);
		vsnprintf(output, sizeof(output), format, argp);
		va_end(argp);

		len = strlen(output);
		ptr = output;
	}
#ifdef	CL_DEBUG
	if(debug_level >= 9)
		printf("clamfi_send: len=%u bufsiz=%u\n", len, sizeof(output));
#endif

	while(len > 0) {
		const int nbytes = (quarantine_dir) ?
			write(privdata->dataSocket, ptr, len) :
			send(privdata->dataSocket, ptr, len, 0);

		if(nbytes == -1) {
			if(errno == EINTR)
				continue;
			perror("send");
			if(use_syslog)
				syslog(LOG_ERR, "write failure to clamd");

			return -1;
		}
		len -= nbytes;
		ptr = &ptr[nbytes];
	}
	return 0;
}

/*
 * Like strcpy, but return the END of the destination, allowing a quicker
 * means of adding to the end of a string than strcat
 */
static char *
strrcpy(char *dest, const char *source)
{
	/* Pre assertions */
	assert(dest != NULL);
	assert(source != NULL);
	assert(dest != source);

	while((*dest++ = *source++) != '\0')
		;
	return(--dest);
}

/*
 * Read from clamav - timeout if necessary
 */
static int
clamd_recv(int sock, char *buf, size_t len)
{
	fd_set rfds;
	struct timeval tv;

	if(threadtimeout == 0)
		return recv(sock, buf, len, 0);

	FD_ZERO(&rfds);
	FD_SET(sock, &rfds);

	tv.tv_sec = threadtimeout;
	tv.tv_usec = 0;

	switch(select(sock + 1, &rfds, NULL, NULL, &tv)) {
		case -1:
			perror("select");
			return -1;
		case 0:
			if(use_syslog)
				syslog(LOG_ERR, "No data received from clamd in %d seconds\n", threadtimeout);
			return 0;
	}
	return recv(sock, buf, len, 0);
}

/*
 * Read in the signature file
 */
static off_t
updateSigFile(void)
{
	struct stat statb;
	int fd;

	if(sigFilename == NULL)
		/* nothing to read */
		return signature ? strlen(signature) : 0;

	if(stat(sigFilename, &statb) < 0) {
		perror(sigFilename);
		if(use_syslog)
			syslog(LOG_ERR, "Can't stat %s\n", sigFilename);
		return 0;
	}

	if(statb.st_mtime <= signatureStamp)
		return statb.st_size;	/* not changed */

	fd = open(sigFilename, O_RDONLY);
	if(fd < 0) {
		perror(sigFilename);
		if(use_syslog)
			syslog(LOG_ERR, "Can't open %s\n", sigFilename);
		return 0;
	}

	signatureStamp = statb.st_mtime;

	signature = realloc(signature, statb.st_size);
	read(fd, signature, statb.st_size);
	close(fd);

	return statb.st_size;
}
