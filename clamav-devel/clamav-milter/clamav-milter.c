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
 * Install into /usr/local/sbin/clamav-milter
 *
 * See http://www.nmt.edu/~wcolburn/sendmail-8.12.5/libmilter/docs/sample.html
 *
 * Installations for RedHat Linux and it's derivatives such as YellowDog:
 * 1) Ensure that you have the sendmail-devel RPM installed
 * 2) Add to /etc/mail/sendmail.mc:
 *	INPUT_MAIL_FILTER(`clamav', `S=local:/var/run/clamav/clmilter.sock, F=, T=S:4m;R:4m')dnl
 *	define(`confINPUT_MAIL_FILTERS', `clamav')
 * 3) Check entry in /usr/local/etc/clamav.conf of the form:
 *	LocalSocket /var/run/clamav/clamd.sock
 *	StreamSaveToDisk
 * 4) If you already have a filter (such as spamassassin-milter from
 * http://savannah.nongnu.org/projects/spamass-milt) add it thus:
 *	INPUT_MAIL_FILTER(`clamav', `S=local:/var/run/clamav/clmilter.sock, F=, T=S:4m;R:4m')dnl
 *	INPUT_MAIL_FILTER(`spamassassin', `S=local:/var/run/spamass.sock, F=, T=C:15m;S:4m;R:4m;E:10m')
 *	define(`confINPUT_MAIL_FILTERS', `spamassassin,clamav')dnl
 *	mkdir /var/run/clamav
 *	chown clamav /var/run/clamav	(if you use User clamav in clamav.conf)
 *	chmod 700 /var/run/clamav
 *
 * The above example shows clamav-milter, clamd and sendmail all on the
 * same machine, however using TCP they may reside on different machines,
 * indeed clamav-milter is capable of talking to multiple clamds for redundancy
 * and load balancing.
 * 5) You may find INPUT_MAIL_FILTERS is not needed on your machine, however it
 * is recommended by the Sendmail documentation and I suggest going along
 * with that.
 * 6) I suggest putting SpamAssassin first since you're more likely to get spam
 * than a virus/worm sent to you.
 * 7) Add to /etc/sysconfig/clamav-milter
 *	CLAMAV_FLAGS="--max-children=2 local:/var/run/clamav/clmilter.sock"
 * or if clamd is on a different machine
 *	CLAMAV_FLAGS="--max-children=2 --server=192.168.1.9 local:/var/run/clamav/clmilter.sock"
 *
 * If you want clamav-milter to listen on TCP for communication with sendmail,
 * for example if they are on different machines use inet:<port>.
 * On machine A (running sendmail) you would have in sendmail.mc:
 *	INPUT_MAIL_FILTER(`clamav', `S=inet:3311@machineb, F=, T=S:4m;R:4m')dnl
 * On machine B (running clamav-milter) you would start up clamav-milter thus:
 *	clamav-milter inet:3311
 *
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
 *	0.60d	26/8/03	Removed superfluous buffer and unneeded strerror call
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
 *	0.66g	25/1/04 Corrected usage message
 *			Started to honour --debug
 *			Dump core on LINUX if CL_DEBUG set
 *			Support multiple servers separated by colons
 *	0.66h	26/1/04	Corrected endian problem (ntohs instead of htons)
 *	0.66i	28/1/04	Fixed compilation error with --enable-debug
 *	0.66j	29/1/03	Added --noreject flag, based on a patch by
 *			"Vijay Sarvepalli" <vssarvep@office.uncg.edu>
 *	0.66k	2/2/04	When --postmaster-only is given, include the system
 *			ID of the message in the warning e-mail, since that
 *			will help the administrator when sifting through the
 *			mail logs. Based on an idea by Jim Allen,
 *			<Jim.Allen@Heartsine.co.uk>
 *	0.66l	7/2/04	Updated URL reference
 *			Added new config.h mechanism
 *	0.66m	9/2/04	Added Hflag from "Leonid Zeitlin" <lz@europe.com>
 *	0.66n	13/2/04	Added TCPwrappers support
 *			Removed duplication in version string
 *			Handle machines that don't have in_port_t
 *	0.67	16/2/04	Upissued to 0.67
 *	0.67a	16/2/04	Added clamfi_free
 *	0.67b	17/2/04	Removed compilation warning - now compiles on FreeBSD5.2
 *			Don't allow --force to overwride TCPwrappers
 *	0.67c	18/2/04	Added dont-log-clean flag
 *	0.67d	19/2/04	Reworked TCPwrappers code
 *			Thanks to "Hector M. Rulot Segovia" <Hector.Rulot@uv.es>
 *			Changed some printf/puts to cli_dbgmsg
 *	0.67e	20/2/04	Moved the definition of the sendmail pipe
 *			The recent changes to the configure script changed
 *			the order of includes so some prototypes weren't
 *			getting in
 *	0.67f	20/2/04	Added checkClamd() - if possible attempts to see
 *			if clamd has died
 *	0.67g	21/2/04	Don't run if the quarantine-dir is publically accessable
 *	0.67h	22/2/04	Change the log level TCPwrapper denying
 *			Handle ERROR message from clamd
 *			Moved smfi_setconn to avoid race condictions when
 *			an e-mail is received just as the milter is starting
 *			but isn't ready to handle it causing the milter to
 *			go to an error state
 *			Hardend umask
 *	0.67i	27/2/04	Dropping priv message now same as clamd
 *			Only use TCPwrappers when using TCP/IP to establish
 *			communications with the milter
 *	0.67j	27/2/04	Call checkClamd() before attempting to connect, it's
 *			a way of warning the user if they've started the
 *			milter before clamd
 *			checkClamd() now stashes pid in syslog
 *			Ensure installation instructions tally with man page
 *			and put sockets into subdirectory for security
 *			clamfi_close debug, change assert to debug message
 *			Better way to force TCPwrappers only with TCP/IP
 *	0.67k	7/3/04	Ensure cli_dbgmsg's end with \n
 *			Fixed some warning messages with icc
 *			Use cli_[cm]alloc
 *			Included extra information if --headers is given (based
 *			on an idea from "Leonid Zeitlin" <lz@europe.com>
 *	0.67l	10/3/04	Use new HAVE_STRERROR_R rather than TARGET_OS_SOLARIS
 *			to determine if strerror_r exists
 *	0.70	17/3/04	Up-issued to 0.70
 *	0.70a	20/3/04	strerror_r is a bit confused on Fedora Linux. The
 *			man page says it returns an int, but the prototype
 *			in string.h says it returns a char *
 *			Say how many bytes can't be written to clamd - it may
 *			give a clue what's wrong
 *	0.70b	26/3/04	Display errno information on write failure to clamd
 *			Ensure errno is passed to strerror
 *			Print fd in clamfi_send debug
 *	0.70c	27/3/04	Timestamp clamfi_send messages
 *			Call cli_warnmsg if ERROR received
 *			Minor code tidy
 *			Delay connection to clamd to handle clamd's appetite
 *			for timing out when the remote end (the end talking to
 *			sendmail) is slow
 *			Prefer cli_dbgmsg/cli_warnmsg over printf
 *	0.70d	29/3/04	Print the sendmail ID with the virus note in syslog
 *			config file location has changed
 *	0.70e	1/4/04	Fix a remote possibility of a file descriptor leak
 *			in PingServer() if clamd has died
 *			Fix by Andrey J. Melnikoff (TEMHOTA) <temnota@kmv.ru>
 *			Corrected some debug messages reported by
 *			Sergey Y. Afonin <asy@kraft-s.ru>
 *	0.70f	1/4/04	Added auto-submitted header to messages generated here
 *			Suggested by "Andrey J. Melnikoff (TEMHOTA)"
 *			<temnota@kmv.ru>
 *			Add advice that --quarantine-dir may improve
 *			performance when LocalSocket is used
 *			ThreadTimeout seems to have been changed to ReadTimeout
 *	0.70g	3/4/04	Error if ReadTimeout is -ve
 *			Honour StreamMaxLength
 *	0.70h	8/4/04	Cleanup StreamMaxLength code
 *	0.70i	9/4/04	Handle clamd giving up on StreamMaxLength before
 *			clamav-milter
 *	0.70j	15/4/04	Handle systems without inet_ntop
 *
 * Change History:
 * $Log: clamav-milter.c,v $
 * Revision 1.73  2004/04/15 09:53:25  nigelhorne
 * Handle systems without inet_ntop
 *
 * Revision 1.72  2004/04/09 08:36:53  nigelhorne
 * Handle clamd giving up on StreamMaxLength before clamav-milter
 *
 * Revision 1.71  2004/04/08 13:14:07  nigelhorne
 * Code tidy up
 *
 * Revision 1.70  2004/04/06 22:43:43  kojm
 * reverse strlcpy/strlcat patch
 *
 * Revision 1.69  2004/04/06 12:14:52  kojm
 * use strlcpy/strlcat
 *
 * Revision 1.68  2004/04/03 04:47:22  nigelhorne
 * Honour StreamMaxLength
 *
 * Revision 1.67  2004/04/01 15:34:00  nigelhorne
 * ThreadTimeout has been renamed ReadTimeout
 *
 * Revision 1.66  2004/03/31 20:48:03  nigelhorne
 * Config file has changed
 *
 * Revision 1.65  2004/03/27 21:44:21  nigelhorne
 * Attempt to handle clamd quick timeout for slow remote sites
 *
 * Revision 1.64  2004/03/26 11:10:27  nigelhorne
 * Added debug information
 *
 * Revision 1.63  2004/03/20 12:30:00  nigelhorne
 * strerror_r is confused on Linux
 *
 * Revision 1.62  2004/03/17 19:46:49  nigelhorne
 * Upissue to 0.70@
 *
 * Revision 1.61  2004/03/15 19:54:12  kojm
 * 0.70-rc
 *
 * Revision 1.60  2004/03/10 11:31:03  nigelhorne
 * Use HAVE_STRERROR_R
 *
 * Revision 1.59  2004/03/07 15:11:15  nigelhorne
 * Added more information to headers flag
 *
 * Revision 1.58  2004/03/03 09:14:55  nigelhorne
 * Change way check for TCPwrappers on TCP/IP
 *
 * Revision 1.57  2004/02/27 15:27:11  nigelhorne
 * call checkClamd on start
 *
 * Revision 1.56  2004/02/27 09:23:56  nigelhorne
 * Don't use TCP wrappers when UNIX domain sockets are used
 *
 * Revision 1.55  2004/02/22 22:53:50  nigelhorne
 * Handle ERROR message from clamd
 *
 * Revision 1.54  2004/02/22 17:27:40  nigelhorne
 * Updated installation instructions now that privileges are dropped
 *
 * Revision 1.53  2004/02/21 11:03:23  nigelhorne
 * Error if quarantine-dir is publically accessable
 *
 * Revision 1.52  2004/02/20 17:07:24  nigelhorne
 * Added checkClamd
 *
 * Revision 1.51  2004/02/20 09:50:42  nigelhorne
 * Removed warnings added by new configuration script
 *
 * Revision 1.50  2004/02/19 10:00:26  nigelhorne
 * Rework TCPWrappers support
 *
 * Revision 1.49  2004/02/18 13:30:34  nigelhorne
 * Added dont-long-clean argument
 *
 * Revision 1.48  2004/02/18 10:06:51  nigelhorne
 * Fix FreeBSD
 *
 * Revision 1.47  2004/02/16 11:55:24  nigelhorne
 * Added clamfi_free which helps with the tidying up
 *
 * Revision 1.46  2004/02/16 09:39:22  nigelhorne
 * Upissued to 0.67
 *
 * Revision 1.45  2004/02/14 17:20:38  nigelhorne
 * Add TCPwrappers support
 *
 * Revision 1.44  2004/02/09 11:05:33  nigelhorne
 * Added Hflag
 *
 * Revision 1.43  2004/02/07 12:16:20  nigelhorne
 * Added config.h
 *
 * Revision 1.42  2004/02/02 13:44:31  nigelhorne
 * Include the ID of the message when warnings are sent to the postmaster-only
 *
 * Revision 1.41  2004/01/29 12:52:35  nigelhorne
 * Added --noreject flag
 *
 * Revision 1.40  2004/01/28 15:55:59  nigelhorne
 * Fixed compilation error with --enable-debug
 *
 * Revision 1.39  2004/01/26 14:12:42  nigelhorne
 * Corrected endian problem (ntohs instead of htons)
 *
 * Revision 1.38  2004/01/25 14:23:51  nigelhorne
 * Support multiple clamd servers
 *
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
 * Drop root priviliges and support quarantine
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
static	char	const	rcsid[] = "$Id: clamav-milter.c,v 1.73 2004/04/15 09:53:25 nigelhorne Exp $";

#define	CM_VERSION	"0.70j"

/*#define	CONFDIR	"/usr/local/etc"*/

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include "defaults.h"
#include "cfgparser.h"
#include "../target.h"
#include "str.h"
#include "../libclamav/others.h"
#include "clamav.h"

#ifndef	CL_DEBUG
#define	NDEBUG
#endif

#include <stdio.h>
#include <sysexits.h>
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

#ifdef	WITH_TCPWRAP
#include <tcpd.h>

int	allow_severity = LOG_DEBUG;
int	deny_severity = LOG_NOTICE;

#endif

#if defined(CL_DEBUG) && defined(C_LINUX)
#include <sys/resource.h>
#endif

#define _GNU_SOURCE
#include "getopt.h"

#ifndef	SENDMAIL_BIN
#define	SENDMAIL_BIN	"/usr/lib/sendmail"
#endif

#ifndef HAVE_IN_PORT_T
typedef	unsigned short	in_port_t;
#endif

/*
 * TODO: optional: xmessage on console when virus stopped (SNMP would be real nice!)
 *	Having said that, with LogSysLog you can (on Linux) configure the system
 *	to get messages on the system console, see syslog.conf(5), also you
 *	can use wall(1) in the VirusEvent entry in clamav.conf
 * TODO: build with libclamav.so rather than libclamav.a
 * TODO: bounce message should optionally be read from a file
 * TODO: Support LogTime and Logfile from the conf file
 * TODO: Warn if TCPAddr doesn't allow connection from us
 * TODO: Decide action (bounce, discard, reject etc.) based on the virus
 *	found. Those with faked addresses, such as SCO.A want discarding,
 *	others could be bounced properly.
 */

struct header_node_t {
	char *header;
	struct header_node_t *next;
};

struct header_list_struct {
	struct header_node_t *first;
	struct header_node_t *last;
};

typedef struct header_list_struct *header_list_t;

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
	header_list_t headers;	/* Message headers */
	long	numBytes;	/* Number of bytes sent so far */
};

static	int		pingServer(int serverNumber);
static	int		findServer(void);
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
static	void		clamfi_free(struct privdata *privdata);
static	int		clamfi_send(const struct privdata *privdata, size_t len, const char *format, ...);
static	char		*strrcpy(char *dest, const char *source);
static	int		clamd_recv(int sock, char *buf, size_t len);
static	off_t		updateSigFile(void);
static	header_list_t	header_list_new(void);
static	void	header_list_free(header_list_t list);
static	void	header_list_add(header_list_t list, const char *headerf, const char *headerv);
static	void	header_list_print(header_list_t list, FILE *fp);
static	int	connect2clamd(struct privdata *privdata);
static	void	checkClamd(void);

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
static	int	rejectmail = 1;	/*
				 * Send a 550 rejection when a virus is
				 * found
				 */
static	int	hflag = 0;	/*
				 * Include original message headers in
				 * report
				 */
static	int	cl_error = SMFIS_TEMPFAIL; /*
				 * If an error occurs, return
				 * this status. Allows messages
				 * to be passed through
				 * unscanned in the event of
				 * an error. Patch from
				 * Joe Talbott <josepht@cstone.net>
				 */
static	int	readTimeout = CL_DEFAULT_SCANTIMEOUT; /*
				 * number of seconds to wait for clamd to
				 * respond, see ReadTimeout in clamav.conf
				 */
static	long	streamMaxLength = -1;	/* StreamMaxLength from clamav.conf */
static	int	logClean = 1;	/*
				 * Add clean items to the log file
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
short	use_syslog = 0;
static	const	char	*pidFile;
static	int	logVerbose = 0;
static	struct	cfgstruct	*copt;
static	const	char	*localSocket;	/* milter->clamd comms */
static	in_port_t	tcpSocket;	/* milter->clamd comms */
static	char	*port = NULL;	/* sendmail->milter comms */
static	const	char	*serverHostNames = "127.0.0.1";
static	long	*serverIPs;	/* IPv4 only */
static	int	numServers;	/* numer of elements in serverIPs */
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
	puts("\t--debug\t\t\t-D\tPrint debug messages.");
	puts("\t--dont-log-clean\t-C\tDon't add an entry to syslog that a mail is clean.");
	puts("\t--dont-scan-on-error\t-d\tPass e-mails through unscanned if a system error occurs.");
	puts("\t--force-scan\t\t-f\tForce scan all messages (overrides (-o and -l).");
	puts("\t--help\t\t\t-h\tThis message.");
	puts("\t--headers\t\t-H\tInclude original message headers in the report.");
	puts("\t--local\t\t\t-l\tScan messages sent from machines on our LAN.");
	puts("\t--outgoing\t\t-o\tScan outgoing messages from this machine.");
	puts("\t--noreject\t\t-N\tDon't reject viruses, silently throw them away.");
	puts("\t--noxheader\t\t-n\tSuppress X-Virus-Scanned header.");
	puts("\t--postmaster\t\t-p EMAIL\tPostmaster address [default=postmaster].");
	puts("\t--postmaster-only\t-P\tSend warnings only to the postmaster.");
	puts("\t--quiet\t\t\t-q\tDon't send e-mail notifications of interceptions.");
	puts("\t--quarantine=USER\t-Q EMAIL\tQuanrantine e-mail account.");
	puts("\t--quarantine-dir=DIR\t-U DIR\tDirectory to store infected emails.");
	puts("\t--server=SERVER\t\t-s SERVER\tHostname/IP address of server(s) running clamd (when using TCPsocket).");
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

#if defined(CL_DEBUG) && defined(C_LINUX)
	struct rlimit rlim;

	rlim.rlim_cur = rlim.rlim_max = RLIM_INFINITY;
	if(setrlimit(RLIMIT_CORE, &rlim) < 0)
		perror("setrlimit");
#endif
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
		const char *args = "bc:CDfF:lm:nNop:PqQ:dhHs:SU:Vx:";
#else
		const char *args = "bc:CDfF:lm:nNop:PqQ:dhHs:SU:V";
#endif

		static struct option long_options[] = {
			{
				"bounce", 0, NULL, 'b'
			},
			{
				"config-file", 1, NULL, 'c'
			},
			{
				"dont-log-clean", 0, NULL, 'C'
			},
			{
				"dont-scan-on-error", 0, NULL, 'd'
			},
			{
				"debug", 0, NULL, 'D'
			},
			{
				"force-scan", 0, NULL, 'f'
			},
			{
				"headers", 0, NULL, 'H'
			},
			{
				"help", 0, NULL, 'h'
			},
			{
				"local", 0, NULL, 'l'
			},
			{
				"noreject", 0, NULL, 'N'
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
			case 'C':	/* dont log clean */
				logClean = 0;
				break;
			case 'd':	/* don't scan on error */
				cl_error = SMFIS_ACCEPT;
				break;
			case 'D':	/* enable debug messages */
				cl_debug();
				break;
			case 'f':	/* force the scan */
				fflag++;
				break;
			case 'h':
				help();
				return EX_OK;
			case 'H':
				hflag++;
				break;
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
			case 'N':	/* Do we reject mail or silently drop it */
				rejectmail = 0;
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
				serverHostNames = optarg;
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
				fprintf(stderr, "Usage: %s [-b] [-c FILE] [-F FILE] [--max-children=num] [-l] [-o] [-p address] [-P] [-q] [-Q USER] [-s SERVER] [-S] [-x#] [-U PATH] socket-addr\n", argv[0]);
#else
				fprintf(stderr, "Usage: %s [-b] [-c FILE] [-F FILE] [--max-children=num] [-l] [-o] [-p address] [-P] [-q] [-Q USER] [-s SERVER] [-S] [-U PATH] socket-addr\n", argv[0]);
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

			cli_dbgmsg("Running as user %s (UID %d, GID %d)\n",
				cpt->strarg, user->pw_uid, user->pw_gid);
		} else
			fprintf(stderr, "%s: running as root is not recommended\n", argv[0]);
	}
	if(quarantine_dir) {
		struct stat statb;

		if(access(quarantine_dir, W_OK) < 0) {
			perror(quarantine_dir);
			return EX_CONFIG;
		}
		if(stat(quarantine_dir, &statb) < 0) {
			perror(quarantine_dir);
			return EX_CONFIG;
		}
		/*
		 * Quit if the quarantine directory is publically readable
		 * or writeable
		 */
		if(statb.st_mode & 077) {
			fprintf(stderr, "%s: unsafe quarantine directory %s\n",
				argv[0], quarantine_dir);
			return EX_CONFIG;
		}
	}

	if(sigFilename && !updateSigFile())
		return EX_USAGE;

	if(!cfgopt(copt, "StreamSaveToDisk")) {
		fprintf(stderr, "%s: StreamSavetoDisk not enabled in %s\n",
			argv[0], cfgfile);
		return EX_CONFIG;
	}

	if(!cfgopt(copt, "ScanMail")) {
		/*
		 * In fact ScanMail isn't needed if this machine doesn't run
		 * clamd.
		 */
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

	if((cpt = cfgopt(copt, "ReadTimeout")) != NULL) {
		readTimeout = cpt->numarg;

		if(readTimeout < 0) {
			fprintf(stderr, "%s: ReadTimeout must not be negative in %s\n",
				argv[0], cfgfile);
			return EX_CONFIG;
		}
	}
	if((cpt = cfgopt(copt, "StreamMaxLength")) != NULL) {
		if(cpt->numarg < 0) {
			fprintf(stderr, "%s: StreamMaxLength must not be negative in %s\n",
				argv[0], cfgfile);
			return EX_CONFIG;
		}
		streamMaxLength = (long)cpt->numarg;
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
		if(!pingServer(-1)) {
			fprintf(stderr, "Can't talk to clamd server via %s\n",
				localSocket);
			fprintf(stderr, "Check your entry for LocalSocket in %s\n",
				cfgfile);
			return EX_CONFIG;
		}
		if(quarantine_dir == NULL)
			fprintf(stderr, "When using Localsocket in %s\nyou may improve performance if you use the --quarantine_dir option\n", cfgfile);

		umask(077);

		serverIPs = (long *)cli_malloc(sizeof(long));
		serverIPs[0] = inet_addr("127.0.0.1");
	} else if((cpt = cfgopt(copt, "TCPSocket")) != NULL) {
		int i;

		/*
		 * TCPSocket is in fact a port number not a full socket
		 */
		if(quarantine_dir) {
			fprintf(stderr, "%s: --quarantine-dir not supported for remote scanning - use --quarantine\n", argv[0]);
			return EX_CONFIG;
		}

		tcpSocket = (in_port_t)cpt->numarg;

		/*
		 * cli_strtok's fieldno counts from 0
		 */
		for(;;) {
			char *hostname;

			hostname = cli_strtok(serverHostNames, numServers, ":");
			if(hostname == NULL)
				break;
			numServers++;
			free(hostname);
		}

		cli_dbgmsg("numServers: %d\n", numServers);

		serverIPs = (long *)cli_malloc(numServers * sizeof(long));

		for(i = 0; i < numServers; i++) {
			char *hostname;

			/*
			 * Translate server's name to IP address
			 */
			hostname = cli_strtok(serverHostNames, i, ":");
			serverIPs[i] = inet_addr(hostname);
			if(serverIPs[i] == -1L) {
				const struct hostent *h = gethostbyname(hostname);

				if(h == NULL) {
					fprintf(stderr, "%s: Unknown host %s\n",
						argv[0], hostname);
					return EX_USAGE;
				}

				memcpy((char *)&serverIPs[i], h->h_addr, sizeof(serverIPs[i]));
			}

			if(!pingServer(i)) {
				fprintf(stderr, "Can't talk to clamd server %s on port %d\n",
					hostname, tcpSocket);
				fprintf(stderr, "Check your entry for TCPSocket in %s\n",
					cfgfile);
				return EX_CONFIG;
			}
			free(hostname);
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

	if((cpt = cfgopt(copt, "PidFile")) != NULL)
		pidFile = cpt->strarg;

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

	if(smfi_setconn(port) == MI_FAILURE) {
		fprintf(stderr, "%s: smfi_setconn failed\n",
			argv[0]);
		return EX_SOFTWARE;
	}

	if(smfi_register(smfilter) == MI_FAILURE) {
		cli_errmsg("smfi_register failure\n");
		return EX_UNAVAILABLE;
	}

	signal(SIGPIPE, SIG_IGN);

	return smfi_main();
}

/*
 * Verify that the server is where we think it is
 * Returns true or false
 *
 * serverNumber counts from 0
 */
static int
pingServer(int serverNumber)
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
		checkClamd();
		if(connect(sock, (struct sockaddr *)&server, sizeof(struct sockaddr_un)) < 0) {
			perror(localSocket);
			close(sock);
			return 0;
		}
	} else {
		struct sockaddr_in server;

		memset((char *)&server, 0, sizeof(struct sockaddr_in));
		server.sin_family = AF_INET;
		server.sin_port = (in_port_t)htons(tcpSocket);

		assert(serverIPs != NULL);
		assert(serverIPs[0] != -1L);

		server.sin_addr.s_addr = serverIPs[serverNumber];

		if((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
			perror("socket");
			return 0;
		}
		if(connect(sock, (struct sockaddr *)&server, sizeof(struct sockaddr_in)) < 0) {
			perror("connect");
			close(sock);
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
	 *
	 * TODO: When connecting to more than one server, give a warning
	 *	if they're running different versions, or if the virus DBs
	 *	are out of date
	 */
	snprintf(clamav_version, sizeof(clamav_version),
		"%s, clamav-milter version %s",
		buf, CM_VERSION);

	return 1;
}

/*
 * Find the best server to connect to. No intelligence to this, if one
 * of the servers goes down it'll be silently ignored, which is probably
 * ok. It is best to weight the order of the servers from most wanted to
 * least wanted
 *
 * Return value is from 0 - index into serverIPs
 */
static int
findServer(void)
{
	struct sockaddr_in *servers, *server;
	int *socks, maxsock = 0, i;
	fd_set rfds;
	struct timeval tv;
	int retval;

	assert(tcpSocket != 0);
	assert(numServers > 0);

	if(numServers == 1)
		return 0;

	servers = (struct sockaddr_in *)cli_calloc(numServers, sizeof(struct sockaddr_in));
	socks = (int *)cli_malloc(numServers * sizeof(int));

	FD_ZERO(&rfds);

	for(i = 0, server = servers; i < numServers; i++, server++) {
		int sock;

		server->sin_family = AF_INET;
		server->sin_port = (in_port_t)htons(tcpSocket);
		server->sin_addr.s_addr = serverIPs[i];

		sock = socks[i] = socket(AF_INET, SOCK_STREAM, 0);
		if(sock < 0) {
			perror("socket");
			do
				if(socks[i] >= 0)
					close(socks[i]);
			while(--i >= 0);
			free(socks);
			free(servers);
			return 0;	/* Use the first server on failure */
		}

		if((connect(sock, (struct sockaddr *)server, sizeof(struct sockaddr)) < 0) ||
		   (send(sock, "PING\n", 5, 0) < 5)) {
			cli_errmsg("findServer: Check server %d - it may be down\n", i);
			if(use_syslog)
				syslog(LOG_WARNING, "findServer: Check server %d - it may be down", i);
			socks[i] = -1;
			close(sock);
			continue;
		}

		shutdown(sock, SHUT_WR);

		FD_SET(sock, &rfds);
		if(sock > maxsock)
			maxsock = sock;
	}

	free(servers);

	tv.tv_sec = readTimeout;
	tv.tv_usec = 0;

	retval = select(maxsock, &rfds, NULL, NULL, &tv);
	if(retval < 0)
		perror("select");

	for(i = 0; i < numServers; i++)
		if(socks[i] >= 0)
			close(socks[i]);

	if(retval == 0) {
		free(socks);
		cli_dbgmsg("findServer: No response from any server\n");
		if(use_syslog)
			syslog(LOG_WARNING, "findServer: No response from any server");
		return 0;
	} else if(retval < 0) {
		free(socks);
		if(use_syslog)
			syslog(LOG_ERR, "findServer: select failed\n");
		return 0;
	}

	for(i = 0; i < numServers; i++)
		if(FD_ISSET(socks[i], &rfds)) {
			free(socks);
			cli_dbgmsg("findServer: using server %d\n", i);
			return i;
		}

	free(socks);
	cli_dbgmsg("findServer: No response from any server\n");
	if(use_syslog)
		syslog(LOG_WARNING, "findServer: No response from any server");
	return 0;
}

/*
 * Sendmail wants to establish a connection to us
 */
static sfsistat
clamfi_connect(SMFICTX *ctx, char *hostname, _SOCK_ADDR *hostaddr)
{
#if	defined(HAVE_INET_NTOP) || defined(WITH_TCPWRAP)
	char ip[INET_ADDRSTRLEN];	/* IPv4 only */
#endif
	char *remoteIP;

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

#ifdef HAVE_INET_NTOP
	remoteIP = (char *)inet_ntop(AF_INET, &((struct sockaddr_in *)(hostaddr))->sin_addr, ip, sizeof(ip));
#else
	remoteIP = inet_ntoa(((struct sockaddr_in *)(hostaddr))->sin_addr);
#endif

	if(remoteIP == NULL) {
		if(use_syslog)
			syslog(LOG_ERR, "clamfi_connect: remoteIP is null");
		return cl_error;
	}

#ifdef	CL_DEBUG
	if(debug_level >= 4) {
		if(use_syslog)
			syslog(LOG_NOTICE, "clamfi_connect: connection from %s [%s]", hostname, remoteIP);
		cli_dbgmsg("clamfi_connect: connection from %s [%s]\n", hostname, remoteIP);
	}
#endif

#ifdef	WITH_TCPWRAP
	/*
	 * Support /etc/hosts.allow and /etc/hosts.deny
	 */
	if(strncasecmp(port, "inet:", 5) == 0) {
		const char *hostmail;
		const struct hostent *hp = NULL;

		/*
		 * Using TCP/IP for the sendmail->clamav-milter connection
		 */
		if((hostmail = smfi_getsymval(ctx, "{if_name}")) == NULL) {
			if(use_syslog)
				syslog(LOG_WARNING, "Can't get sendmail hostname");
			hostmail = "unknown";
		}

		if((hp = gethostbyname(hostmail)) == NULL) {
			if(use_syslog)
				syslog(LOG_WARNING, "Access Denied: Host Unknown (%s)", hostname);
			return SMFIS_TEMPFAIL;
		}

		/* inet_ntop? */
		strcpy(ip, (char *)inet_ntoa(*(struct in_addr *)hp->h_addr));

		/*
		 * Ask is this is a allowed name or IP number
		 */
		if(!hosts_ctl("clamav-milter", hp->h_name, ip, STRING_UNKNOWN)) {
			if(use_syslog)
				syslog(LOG_WARNING, "Access Denied for %s[%s]", hp->h_name, ip);
			return SMFIS_TEMPFAIL;
		}
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
			cli_dbgmsg("clamfi_connect: not scanning outgoing messages\n");
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
				cli_dbgmsg("clamfi_connect: not scanning outgoing messages\n");
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

	if(logVerbose)
		syslog(LOG_DEBUG, "clamfi_envfrom: %s", argv[0]);

	cli_dbgmsg("clamfi_envfrom: %s\n", argv[0]);

	if(max_children > 0) {
		int rc = 0;

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

		cli_dbgmsg(">n_children = %d\n", n_children);
		pthread_mutex_unlock(&n_children_mutex);

		if(rc == ETIMEDOUT) {
#ifdef	CL_DEBUG
			if(use_syslog)
				syslog(LOG_NOTICE, "Timeout waiting for a child to die");
#endif
			cli_dbgmsg("Timeout waiting for a child to die\n");
		}
	}

	privdata = (struct privdata *)cli_calloc(1, sizeof(struct privdata));
	privdata->dataSocket = -1;	/* 0.4 */
	privdata->cmdSocket = -1;	/* 0.4 */

	privdata->from = strdup(argv[0]);

	if(streamMaxLength > 0L)
		privdata->numBytes = (long)(strlen(argv[0]) + 6);

	if(hflag)
		privdata->headers = header_list_new();

	if(smfi_setpriv(ctx, privdata) == MI_SUCCESS)
		return SMFIS_CONTINUE;

	clamfi_free(privdata);

	return cl_error;
}

static sfsistat
clamfi_envrcpt(SMFICTX *ctx, char **argv)
{
	struct privdata *privdata = (struct privdata *)smfi_getpriv(ctx);

	if(logVerbose)
		syslog(LOG_DEBUG, "clamfi_envrcpt: %s", argv[0]);

	cli_dbgmsg("clamfi_envrcpt: %s\n", argv[0]);

	if(privdata->to == NULL) {
		privdata->to = cli_malloc(sizeof(char *) * 2);

		assert(privdata->numTo == 0);
	} else
		privdata->to = cli_realloc(privdata->to, sizeof(char *) * (privdata->numTo + 2));

	privdata->to[privdata->numTo] = strdup(argv[0]);
	privdata->to[++privdata->numTo] = NULL;

	if(streamMaxLength > 0L)
		privdata->numBytes += (long)(strlen(argv[0]) + 4);

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
		cli_dbgmsg("clamfi_header: %s: %s\n", headerf, headerv);
	else
		cli_dbgmsg("clamfi_header\n");
#endif

	if(privdata->dataSocket == -1)
		/*
		 * First header - make connection with clamd
		 */
		if(!connect2clamd(privdata)) {
			clamfi_cleanup(ctx);
			return cl_error;
		}

	if(clamfi_send(privdata, 0, "%s: %s\n", headerf, headerv) < 0) {
		clamfi_cleanup(ctx);
		return cl_error;
	}

	if(streamMaxLength > 0L)
		privdata->numBytes += (long)(strlen(headerf) + strlen(headerv) + 3);

	if(hflag)
		header_list_add(privdata->headers, headerf, headerv);

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
	if(debug_level >= 4)
		cli_dbgmsg("clamfi_eoh\n");
#endif

	if(privdata->dataSocket == -1)
		/*
		 * No headers - make connection with clamd
		 */
		if(!connect2clamd(privdata)) {
			clamfi_cleanup(ctx);
			return cl_error;
		}

	if(clamfi_send(privdata, 1, "\n") < 0) {
		clamfi_cleanup(ctx);
		return cl_error;
	}
	if(streamMaxLength > 0L)
		privdata->numBytes++;

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
		syslog(LOG_NOTICE, "clamfi_eoh: ignoring whitelisted message");
#ifdef	CL_DEBUG
	cli_dbgmsg("clamfi_eoh: not scanning outgoing messages\n");
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
	cli_dbgmsg("clamfi_envbody: %u bytes\n", len);
#endif

	if(streamMaxLength > 0L) {
		privdata->numBytes += (long)len;
		if(privdata->numBytes > streamMaxLength) {
			if(use_syslog)
				syslog(LOG_NOTICE, "%s: Message more than StreamMaxLength (%ld) bytes - not scanned\n",
					smfi_getsymval(ctx, "i"),
					streamMaxLength);
			clamfi_cleanup(ctx);	/* not needed, but just to be safe */
			return SMFIS_ACCEPT;
		}
	}
	if(clamfi_send(privdata, len, (char *)bodyp) < 0) {
		clamfi_cleanup(ctx);	/* not needed, but just to be safe */
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
			privdata->body = cli_malloc(len);
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
	const char *sendmailId;
	struct privdata *privdata = (struct privdata *)smfi_getpriv(ctx);
	char mess[128];

	if(logVerbose)
		syslog(LOG_DEBUG, "clamfi_eom");
#ifdef	CL_DEBUG
	cli_dbgmsg("clamfi_eom\n");
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
		cli_dbgmsg("clamfi_eom: read %s\n", mess);
	} else {
		clamfi_cleanup(ctx);
		syslog(LOG_NOTICE, "clamfi_eom: read nothing from clamd");
#ifdef	CL_DEBUG
		cli_dbgmsg("clamfi_eom: read nothing from clamd\n");
#endif
		return cl_error;
	}

	close(privdata->cmdSocket);
	privdata->cmdSocket = -1;

	sendmailId = smfi_getsymval(ctx, "i");

	if(strstr(mess, "ERROR") != NULL) {
		if(strstr(mess, "Size exceeded") != NULL) {
			/*
			 * Clamd has stopped on StreamMaxLength before us
			 */
			if(use_syslog)
				syslog(LOG_NOTICE, "%s: Message more than StreamMaxLength (%ld) bytes - not scanned\n",
					sendmailId, streamMaxLength);
			clamfi_cleanup(ctx);	/* not needed, but just to be safe */
			return SMFIS_ACCEPT;
		}

		cli_warnmsg("%s: %s\n", sendmailId, mess);
		if(use_syslog)
			syslog(LOG_ERR, "%s: %s\n", sendmailId, mess);
		clamfi_cleanup(ctx);
		return cl_error;
	}

	if(strstr(mess, "FOUND") == NULL) {
		if(!nflag)
			smfi_addheader(ctx, "X-Virus-Scanned", clamav_version);

		/*
		 * TODO: if privdata->from is NULL it's probably SPAM, and
		 * me might consider bouncing it...
		 */
		if(use_syslog && logClean)
			/* Include the sendmail queue ID in the log */
			syslog(LOG_NOTICE, "%s: clean message from %s",
				sendmailId,
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

		/*
		 * Setup err as a list of recipients
		 */
		err = (char *)cli_malloc(1024);

		/*
		 * Use snprintf rather than printf since we don't know the
		 * length of privdata->from and may get a buffer overrun
		 */
		snprintf(err, 1023, "Intercepted virus from %s to",
			privdata->from);

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
			syslog(LOG_NOTICE, "%s: %s %s", sendmailId, mess, err);
#ifdef	CL_DEBUG
		cli_dbgmsg("%s\n", err);
#endif
		free(err);

		if(!qflag) {
			char cmd[128];
			FILE *sendmail;

			snprintf(cmd, sizeof(cmd), "%s -t", SENDMAIL_BIN);

			sendmail = popen(cmd, "w");

			if(sendmail) {
				const char *from;

				/*
				 * Try to determine who sent the message.
				 * In the days of faked from addresses this is
				 * not easy!
				 */
				if(privdata->from)
					from = (strcmp(privdata->from, "<>") == 0) ?
						smfi_getsymval(ctx, "_") :
						privdata->from;
				else
					from = smfi_getsymval(ctx, "_");

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
				/*
				 * Auto-submittied is still a draft, keep an
				 * eye on its format
				 */
				fputs("Auto-Submitted: auto-submitted (antivirus notify)\n", sendmail);
				fputs("Subject: Virus intercepted\n\n", sendmail);

				if(bflag)
					fputs("A message you sent to\n\t", sendmail);
				else if(pflag)
					/*
					 * The message is only going to the
					 * postmaster, so include some useful
					 * information
					 */
					fprintf(sendmail, "The message %s sent from %s to\n\t",
						sendmailId, from);
				else
					fprintf(sendmail, "A message sent from %s to\n\t",
						from);

				for(to = privdata->to; *to; to++)
					fprintf(sendmail, "%s\n", *to);
				fputs("contained a virus and has not been delivered.\n\t", sendmail);
				fputs(mess, sendmail);

				if(privdata->filename != NULL)
					fprintf(sendmail, "\nThe message in question has been quarantined as %s\n", privdata->filename);

				if(hflag) {
					fprintf(sendmail, "\nThe message was received by %s from %s via %s\n\n",
						smfi_getsymval(ctx, "j"), from,
						smfi_getsymval(ctx, "_"));
					fputs("For your information, the original message headers were:\n\n", sendmail);
					header_list_print(privdata->headers, sendmail);
				}

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
					cli_warnmsg("Can't set quarantine user %s\n", quarantine);
			} else
				/*
				 * FIXME: doesn't work if there's no subject
				 */
				smfi_chgheader(ctx, "Subject", 1, mess);
		} else if(rejectmail)
			rc = SMFIS_REJECT;	/* Delete the e-mail */
		else
			rc = SMFIS_DISCARD;

		smfi_setreply(ctx, "550", "5.7.1", "Virus detected by ClamAV - http://www.clamav.net");
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
	cli_dbgmsg("clamfi_abort\n");
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

	cli_dbgmsg("clamfi_close\n");
	if(privdata != NULL) {
		if(use_syslog)
			syslog(LOG_DEBUG, "clamfi_close, privdata != NULL");
		else
			cli_warnmsg("clamfi_close, privdata != NULL");
	}
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
		clamfi_free(privdata);
		smfi_setpriv(ctx, NULL);
	}
}

static void
clamfi_free(struct privdata *privdata)
{
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
				cli_dbgmsg("Free privdata->from\n");
#endif
			free(privdata->from);
			privdata->from = NULL;
		}

		if(privdata->to) {
			char **to;

			for(to = privdata->to; *to; to++) {
#ifdef	CL_DEBUG
				if(debug_level >= 9)
					cli_dbgmsg("Free *privdata->to\n");
#endif
				free(*to);
			}
#ifdef	CL_DEBUG
			if(debug_level >= 9)
				cli_dbgmsg("Free privdata->to\n");
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
		if(privdata->headers)
			header_list_free(privdata->headers);

#ifdef	CL_DEBUG
		if(debug_level >= 9)
			cli_dbgmsg("Free privdata\n");
#endif
		free(privdata);
	}

	if(max_children > 0) {
		pthread_mutex_lock(&n_children_mutex);
		/*
		 * Deliberately errs on the side of broadcasting too many times
		 */
		if(n_children > 0)
			--n_children;
#ifdef	CL_DEBUG
		cli_dbgmsg("pthread_cond_broadcast\n");
#endif
		pthread_cond_broadcast(&n_children_cond);
#ifdef	CL_DEBUG
		cli_dbgmsg("<n_children = %d\n", n_children);
#endif
		pthread_mutex_unlock(&n_children_mutex);
	}
}

/*
 * Returns < 0 for failure
 */
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
	if(debug_level >= 9) {
		time_t t;
		const struct tm *tm;

		time(&t);
		tm = localtime(&t);

		cli_dbgmsg("%d:%d:%d clamfi_send: len=%u bufsiz=%u, fd=%d\n",
			tm->tm_hour, tm->tm_min, tm->tm_sec, len,
			sizeof(output), privdata->dataSocket);
	}
#endif

	while(len > 0) {
		const int nbytes = (quarantine_dir) ?
			write(privdata->dataSocket, ptr, len) :
			send(privdata->dataSocket, ptr, len, 0);

		assert(privdata->dataSocket >= 0);

		if(nbytes == -1) {
			if(errno == EINTR)
				continue;
			perror("send");
			if(use_syslog) {
#ifdef HAVE_STRERROR_R
				char buf[32];
				strerror_r(errno, buf, sizeof(buf));
				syslog(LOG_ERR,
					"write failure (%u bytes) to clamd: %s",
					len, buf);
#else
				syslog(LOG_ERR, "write failure (%u bytes) to clamd: %s", len, strerror(errno));
#endif
			}
			checkClamd();

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

	if(readTimeout == 0)
		return recv(sock, buf, len, 0);

	FD_ZERO(&rfds);
	FD_SET(sock, &rfds);

	tv.tv_sec = readTimeout;
	tv.tv_usec = 0;

	switch(select(sock + 1, &rfds, NULL, NULL, &tv)) {
		case -1:
			perror("select");
			return -1;
		case 0:
			if(use_syslog)
				syslog(LOG_ERR, "No data received from clamd in %d seconds\n", readTimeout);
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

static header_list_t
header_list_new(void)
{
	header_list_t ret;

	ret = (header_list_t)cli_malloc(sizeof(struct header_list_struct));
	ret->first = NULL;
	ret->last = NULL;
	return ret;
}

static void
header_list_free(header_list_t list)
{
	struct header_node_t *iter;

	iter = list->first;
	while (iter) {
		struct header_node_t *iter2 = iter->next;
		free(iter->header);
		free(iter);
		iter = iter2;
	}
	free(list);
}

static void
header_list_add(header_list_t list, const char *headerf, const char *headerv)
{
	char *header;
	size_t len;
	struct header_node_t *new_node;

	len = strlen(headerf) + strlen(headerv) + 3;

	header = (char *)cli_malloc(len);
	sprintf(header, "%s: %s", headerf, headerv);
	new_node = (struct header_node_t *)cli_malloc(sizeof(struct header_node_t));
	new_node->header = header;
	new_node->next = NULL;
	if(!list->first)
		list->first = new_node;
	if(list->last)
		list->last->next = new_node;

	list->last = new_node;
}

static void
header_list_print(header_list_t list, FILE *fp)
{
	const struct header_node_t *iter;

	for(iter = list->first; iter; iter = iter->next)
		fprintf(fp, "%s\n", iter->header);
}
 
/*
 * Establish a connection to clamd
 *	Returns success (1) or failure (0)
 */
static int
connect2clamd(struct privdata *privdata)
{
	char **to;

	assert(privdata->dataSocket == -1);
	assert(privdata->from != NULL);
	assert(privdata->to != NULL);

#ifdef	CL_DEBUG
	if((debug_level > 0) && use_syslog)
		syslog(LOG_DEBUG, "connect2clamd");
	if(debug_level >= 4)
		cli_dbgmsg("connect2clamd\n");
#endif

	if(quarantine_dir) {
		/*
		 * quarantine_dir is specified
		 * store message in a temporary file
		 */
		int ntries = 5;

		privdata->filename = (char *)cli_malloc(strlen(quarantine_dir) + 12);

		do {
			sprintf(privdata->filename, "%s/msg.XXXXXX", quarantine_dir);
#if	defined(C_LINUX) || defined(C_BSD) || defined(HAVE_MKSTEMP) || defined(C_SOLARIS)
			privdata->dataSocket = mkstemp(privdata->filename);
#else
			if(mktemp(privdata->filename) == NULL) {
				if(use_syslog)
					syslog(LOG_ERR, "mktemp %s failed", privdata->filename);
				return 0;
			}
			privdata->dataSocket = open(privdata->filename, O_CREAT|O_EXCL|O_WRONLY|O_TRUNC, 0600);
#endif
		} while((--ntries > 0) && (privdata->dataSocket < 0));

		if(privdata->dataSocket < 0) {
			if(use_syslog)
				syslog(LOG_ERR, "tempfile %s creation failed", privdata->filename);
			return 0;
		}
	} else {
		int freeServer, nbytes;
		struct sockaddr_in reply;
		unsigned short port;
		char buf[64];

		assert(privdata->cmdSocket == -1);

		/*
		 * Create socket to talk to clamd. It will tell us the port to
		 * use to send the data. That will require another socket.
		 */
		if(localSocket) {
			struct sockaddr_un server;

			memset((char *)&server, 0, sizeof(struct sockaddr_un));
			server.sun_family = AF_UNIX;
			strncpy(server.sun_path, localSocket, sizeof(server.sun_path));

			if((privdata->cmdSocket = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
				perror("socket");
				return 0;
			}
			if(connect(privdata->cmdSocket, (struct sockaddr *)&server, sizeof(struct sockaddr_un)) < 0) {
				perror(localSocket);
				return 0;
			}
			freeServer = 0;
		} else {
			struct sockaddr_in server;

			memset((char *)&server, 0, sizeof(struct sockaddr_in));
			server.sin_family = AF_INET;
			server.sin_port = (in_port_t)htons(tcpSocket);

			assert(serverIPs != NULL);

			freeServer = findServer();
			if(freeServer < 0)
				return 0;

			server.sin_addr.s_addr = serverIPs[freeServer];

			if((privdata->cmdSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
				perror("socket");
				return 0;
			}
			if(connect(privdata->cmdSocket, (struct sockaddr *)&server, sizeof(struct sockaddr_in)) < 0) {
				perror("connect");
				return 0;
			}
		}

		/*
		 * Create socket that we'll use to send the data to clamd
		 */
		if((privdata->dataSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
			perror("socket");
			if(use_syslog)
				syslog(LOG_ERR, "failed to create socket");
			return 0;
		}

		shutdown(privdata->dataSocket, SHUT_RD);

		if(send(privdata->cmdSocket, "STREAM\n", 7, 0) < 7) {
			perror("send");
			if(use_syslog)
				syslog(LOG_ERR, "send failed to clamd");
			return 0;
		}

		shutdown(privdata->cmdSocket, SHUT_WR);

		nbytes = clamd_recv(privdata->cmdSocket, buf, sizeof(buf));
		if(nbytes < 0) {
			perror("recv");
			if(use_syslog)
				syslog(LOG_ERR, "recv failed from clamd getting PORT");
			return 0;
		}
		buf[nbytes] = '\0';
#ifdef	CL_DEBUG
		if(debug_level >= 4)
			cli_dbgmsg("Received: %s", buf);
#endif
		if(sscanf(buf, "PORT %hu\n", &port) != 1) {
			if(use_syslog)
				syslog(LOG_ERR, "Expected port information from clamd, got '%s'",
					buf);
			else
				cli_warnmsg("Expected port information from clamd, got '%s'\n",
					buf);
			return 0;
		}

		memset((char *)&reply, 0, sizeof(struct sockaddr_in));
		reply.sin_family = AF_INET;
		reply.sin_port = (in_port_t)htons(port);

		assert(serverIPs != NULL);

		reply.sin_addr.s_addr = serverIPs[freeServer];

#ifdef	CL_DEBUG
		if(debug_level >= 4)
			cli_dbgmsg("Connecting to local port %d\n", port);
#endif

		if(connect(privdata->dataSocket, (struct sockaddr *)&reply, sizeof(struct sockaddr_in)) < 0) {
			perror("connect");

			/* 0.4 - use better error message */
			if(use_syslog) {
#ifdef HAVE_STRERROR_R
				strerror_r(errno, buf, sizeof(buf));
				syslog(LOG_ERR,
					"Failed to connect to port %d given by clamd: %s",
					port, buf);
#else
				syslog(LOG_ERR, "Failed to connect to port %d given by clamd: %s", port, strerror(errno));
#endif
			}
			return 0;
		}
	}

	/*
	 * TODO:
	 *	Put from and to data into a buffer and call clamfi_send once
	 * to save bandwidth when using TCP/IP to connect with a remote clamd
	 */
	clamfi_send(privdata, 0,
		"Received: by clamav-milter\nFrom: %s\n",
		privdata->from);

	for(to = privdata->to; *to; to++)
		if(clamfi_send(privdata, 0, "To: %s\n", *to) < 0)
			return 0;

	cli_dbgmsg("connect2clamd OK\n");

	return 1;
}

/*
 * If possible, check if clamd has died, and report if it has
 */
static void
checkClamd(void)
{
	pid_t pid;
	int fd, nbytes;
	char buf[9];

	if(!localSocket)
		return;	/* communicating via TCP */

	if(pidFile == NULL)
		return;	/* PidFile directive missing from clamav.conf */

	fd = open(pidFile, O_RDONLY);
	if(fd < 0) {
		perror(pidFile);
		if(use_syslog)
			syslog(LOG_ERR, "Can't open %s\n", pidFile);
		return;
	}
	nbytes = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	buf[nbytes] = '\0';
	pid = atoi(buf);
	if((kill(pid, 0) < 0) && (errno == ESRCH)) {
		if(use_syslog)
			syslog(LOG_ERR, "Clamd (pid %d) seems to have died\n",
				pid);
		perror("clamd");
	}
}
