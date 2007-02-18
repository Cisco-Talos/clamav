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
 * For installation instructions see the file INSTALL that came with this file
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#define	CM_VERSION	VERSION

#include "defaults.h"
#include "cfgparser.h"
#include "target.h"
#include "str.h"
#include "../libclamav/others.h"
#include "strrcpy.h"
#include "clamav.h"
#include "../libclamav/table.h"

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
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <stdarg.h>
#include <errno.h>
#include <libmilter/mfapi.h>
#include <pthread.h>
#include <sys/time.h>
#include <signal.h>
#include <regex.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include <netdb.h>
#include <sys/param.h>

#if HAVE_MMAP
#if HAVE_SYS_MMAN_H
#include <sys/mman.h>
#else /* HAVE_SYS_MMAN_H */
#undef HAVE_MMAP
#endif
#endif

#ifdef	C_LINUX
#include <sys/sendfile.h>
#include <libintl.h>
#include <locale.h>

#define	gettext_noop(s)	s
#define	_(s)	gettext(s)
#define	N_(s)	gettext_noop(s)

#else

#define	_(s)	s
#define	N_(s)	s

#endif

#ifdef	WITH_TCPWRAP
#include <tcpd.h>

int	allow_severity = LOG_DEBUG;
int	deny_severity = LOG_NOTICE;

#endif

#ifndef	CL_DEBUG
static	const	char	*logFile;
static	char	console[] = "/dev/console";
#endif

#if defined(CL_DEBUG) && defined(C_LINUX)
#include <sys/resource.h>
#endif

#define _GNU_SOURCE
#include <getopt.h>

#ifndef	SENDMAIL_BIN
#define	SENDMAIL_BIN	"/usr/lib/sendmail"
#endif

#ifndef HAVE_IN_PORT_T
typedef	unsigned short	in_port_t;
#endif

#ifndef	HAVE_IN_ADDR_T
typedef	unsigned int	in_addr_t;
#endif

#define	VERSION_LENGTH	128

/*#define	SESSION	/*
		 * Keep one command connection open to clamd, otherwise a new
		 * command connection is created for each new email
		 *
		 * FIXME: When SESSIONS are open, freshclam can hang when
		 *	notfying clamd of an update. This is most likely to be a
		 *	problem with the implementation of SESSIONS on clamd.
		 *	The problem seems worst on BSD.
		 *
		 * Note that clamd is buggy and can hang or even crash if you
		 *	send SESSION command so be aware
		 */

/*
 * TODO: optional: xmessage on console when virus stopped (SNMP would be real nice!)
 *	Having said that, with LogSysLog you can (on Linux) configure the system
 *	to get messages on the system console, see syslog.conf(5), also you
 *	can use wall(1) in the VirusEvent entry in clamd.conf
 * TODO: build with libclamav.so rather than libclamav.a
 * TODO: Decide action (bounce, discard, reject etc.) based on the virus
 *	found. Those with faked addresses, such as SCO.A want discarding,
 *	others could be bounced properly.
 * TODO: Encrypt mails sent to clamd to stop sniffers
 * TODO: Test with IPv6
 * TODO: Files can be scanned with "SCAN" not "STREAM" if clamd is on the same
 *	machine when talking via INET domain socket.
 * TODO: Load balancing, allow local machine to talk via UNIX domain socket.
 * TODO: allow each line in the whitelist file to specify a quarantine email
 *	address
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
 * Local addresses are those not scanned if --local is not set
 * 127.0.0.0 is not in this table since that's goverend by --outgoing
 * Andy Fiddaman <clam@fiddaman.net> added 69.254.0.0/16
 *	(Microsoft default DHCP)
 *
 * TODO: read this table in from a file (clamd.conf?)
 */
#define PACKADDR(a, b, c, d) (((uint32_t)(a) << 24) | ((b) << 16) | ((c) << 8) | (d))
#define MAKEMASK(bits)	((uint32_t)(0xffffffff << (bits)))

static const struct cidr_net {
	uint32_t	base;
	uint32_t	mask;
} localNets[] = {
	/*{ PACKADDR(127,   0,   0,   0), MAKEMASK(24) },	/*   127.0.0.0/24 */
	{ PACKADDR(192, 168,   0,   0), MAKEMASK(16) },	/* 192.168.0.0/16 */
	{ PACKADDR( 10,   0,   0,   0), MAKEMASK(24) },	/*    10.0.0.0/24 */
	{ PACKADDR(172,  16,   0,   0), MAKEMASK(20) },	/*  172.16.0.0/20 */
	{ PACKADDR(169,  254,  0,   0), MAKEMASK(16) },	/* 169.254.0.0/16 */
	{ 0, 0 }
};

/*
 * Each libmilter thread has one of these
 */
struct	privdata {
	char	*from;	/* Who sent the message */
	char	*subject;	/* Original subject */
	char	*sender;	/* Secretary - often used in mailing lists */
	char	*helo;		/* The HELO string */
	char	**to;	/* Who is the message going to */
	int	numTo;	/* Number of people the message is going to */
#ifndef	SESSION
	int	cmdSocket;	/*
				 * Socket to send/get commands e.g. PORT for
				 * dataSocket
				 */
#endif
	int	dataSocket;	/* Socket to send data to clamd */
	char	*filename;	/* Where to store the message in quarantine */
	u_char	*body;		/* body of the message if Sflag is set */
	size_t	bodyLen;	/* number of bytes in body */
	header_list_t headers;	/* Message headers */
	long	numBytes;	/* Number of bytes sent so far */
	char	*received;	/* keep track of received from */
	const	char	*rejectCode;	/* 550 or 554? */
	char	*messageID;	/* sendmailID */
	int	discard;	/*
				 * looks like the remote end is playing ping
				 * pong with us
				 */
	int	statusCount;	/* number of X-Virus-Status headers */
	int	serverNumber;	/* Index into serverIPs */
	struct  cl_node *root; /* database of viruses used to scan this one */
};

#ifdef	SESSION
static	int		createSession(unsigned int s);
#else
static	int		pingServer(int serverNumber);
#endif
static	int		findServer(void);
static	sfsistat	clamfi_connect(SMFICTX *ctx, char *hostname, _SOCK_ADDR *hostaddr);
#ifdef	CL_DEBUG
static	sfsistat	clamfi_helo(SMFICTX *ctx, char *helostring);
#endif
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
static	int		clamfi_send(struct privdata *privdata, size_t len, const char *format, ...);
static	int		clamd_recv(int sock, char *buf, size_t len);
static	off_t		updateSigFile(void);
static	header_list_t	header_list_new(void);
static	void	header_list_free(header_list_t list);
static	void	header_list_add(header_list_t list, const char *headerf, const char *headerv);
static	void	header_list_print(header_list_t list, FILE *fp);
static	int	connect2clamd(struct privdata *privdata);
static	int	sendToFrom(struct privdata *privdata);
static	void	checkClamd(void);
static	int	sendtemplate(SMFICTX *ctx, const char *filename, FILE *sendmail, const char *virusname);
static	int	qfile(struct privdata *privdata, const char *sendmailId, const char *virusname);
static	int	move(const char *oldfile, const char *newfile);
static	void	setsubject(SMFICTX *ctx, const char *virusname);
static	int	clamfi_gethostbyname(const char *hostname, struct hostent *hp, char *buf, size_t len);
static	int	isLocalAddr(in_addr_t addr);
static	void	clamdIsDown(void);
static	void	*watchdog(void *a);
static	int	logg_facility(const char *name);
static	void	quit(void);
static	void	broadcast(const char *mess);
static	int	loadDatabase(void);

#ifdef	SESSION
static	pthread_mutex_t	version_mutex = PTHREAD_MUTEX_INITIALIZER;
static	char	**clamav_versions;	/* max_children elements in the array */
#define	clamav_version	(clamav_versions[0])
#else
static	char	clamav_version[VERSION_LENGTH + 1];
#endif
static	int	fflag = 0;	/* force a scan, whatever */
static	int	oflag = 0;	/* scan messages from our machine? */
static	int	lflag = 0;	/* scan messages from our site? */
static	const	char	*progname;	/* our name - usually clamav-milter */

/* Variables for --external */
static	int	external = 0;	/* scan messages ourself or use clamd? */
static	pthread_mutex_t	root_mutex = PTHREAD_MUTEX_INITIALIZER;
static	struct	cl_node	*root = NULL;
static	struct	cl_limits	limits;
static	struct	cl_stat	dbstat;
static	int	options = CL_SCAN_STDOPT;

static	int	bflag = 0;	/*
				 * send a failure (bounce) message to the
				 * sender. This probably isn't a good idea
				 * since most reply addresses will be fake
				 *
				 * TODO: Perhaps we can have an option to
				 * bounce outgoing mail, but not incoming?
				 */
static	const	char	*iface;	/*
				 * Broadcast a message when a virus is found,
				 * this allows remote network management
				 */
static	int	broadcastSock = -1;
static	int	pflag = 0;	/*
				 * Send a warning to the postmaster only,
				 * this means user's won't be told when someone
				 * sent them a virus
				 */
static	int	qflag = 0;	/*
				 * Send no warnings when a virus is found,
				 * this means that the only log of viruses
				 * found is the syslog, so it's best to
				 * enable LogSyslog in clamd.conf
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
				 * respond, see ReadTimeout in clamd.conf
				 */
static	long	streamMaxLength = -1;	/* StreamMaxLength from clamd.conf */
static	int	logClean = 1;	/*
				 * Add clean items to the log file
				 */
static	char	*signature = N_("-- \nScanned by ClamAv - http://www.clamav.net\n");
static	time_t	signatureStamp;
static	char	*templatefile;	/* e-mail to be sent when virus detected */
static	const char	*tmpdir;

#ifdef	CL_DEBUG
static	int	debug_level = 0;
#endif

static	pthread_mutex_t	n_children_mutex = PTHREAD_MUTEX_INITIALIZER;
static	pthread_cond_t	n_children_cond = PTHREAD_COND_INITIALIZER;
static	volatile	unsigned	int	n_children = 0;
static	unsigned	int	max_children = 0;
static	int	child_timeout = 300;	/* number of seconds to wait for
					 * a child to die. Set to 0 to
					 * wait forever
					 */
static	int	dont_wait = 0;	/*
				 * If 1 send retry later to the remote end
				 * if max_chilren is exceeded, otherwise we
				 * wait for the number to go down
				 */
static	int	advisory = 0;	/*
				 * Run clamav-milter in advisory mode - viruses
				 * are flagged rather than deleted. Incompatible
				 * with quarantine options
				 */
static	int	detect_forged_local_address;	/*
				 * for incoming only mail servers, drop emails
				 * claiming to be from us that must be false
				 * Requires that -o, -l or -f are NOT given
				 */
static	short	use_syslog = 0;
static	const	char	*pidFile;
static	int	logVerbose = 0;
static	struct	cfgstruct	*copt;
static	const	char	*localSocket;	/* milter->clamd comms */
static	in_port_t	tcpSocket;	/* milter->clamd comms */
static	char	*port = NULL;	/* sendmail->milter comms */

static	const	char	*serverHostNames = "127.0.0.1";
static	long	*serverIPs;	/* IPv4 only */
static	int	numServers;	/* number of elements in serverIPs array */

#ifdef	SESSION
static	struct	session {
	int	sock;	/* fd */
	enum	{ CMDSOCKET_FREE, CMDSOCKET_INUSE, CMDSOCKET_DOWN }	status;
} *sessions;	/* max_children elements in the array */
static	pthread_mutex_t sstatus_mutex = PTHREAD_MUTEX_INITIALIZER;

#endif	/*SESSION*/

static	pthread_cond_t	watchdog_cond = PTHREAD_COND_INITIALIZER;

#ifndef	SHUT_RD
#define	SHUT_RD		0
#endif
#ifndef	SHUT_WR
#define	SHUT_WR		1
#endif
#ifndef	INET_ADDRSTRLEN
#define	INET_ADDRSTRLEN	16
#endif

static	const	char	*postmaster = "postmaster";
static	const	char	*from = "MAILER-DAEMON";
static	int	quitting;

static	const	char	*whitelistFile;	/*
					 * file containing destination email
					 * addresses that we don't scan
					 */
static	const	char	*sendmailCF;	/* location of sendmail.cf to verify */
static	const	char	*pidfile;

#ifdef	CL_DEBUG
#if __GLIBC__ == 2 && __GLIBC_MINOR__ >= 1
#define HAVE_BACKTRACE
#endif
#endif

static	void	sigsegv(int sig);

#ifdef HAVE_BACKTRACE
#include <execinfo.h>

static	void	print_trace(void);

#define	BACKTRACE_SIZE	200

#endif

static	int	verifyIncomingSocketName(const char *sockName);
static	int	isWhitelisted(const char *emailaddress);
static	void	logger(const char *mess);

short	logg_time, logg_lock, logok;
int	logg_size;

static void
help(void)
{
	printf("\n\tclamav-milter version %s\n", CM_VERSION);
	puts("\tCopyright (C) 2004 Nigel Horne <njh@despammed.com>\n");

	puts(_("\t--advisory\t\t-A\tFlag viruses rather than deleting them."));
	puts(_("\t--bounce\t\t-b\tSend a failure message to the sender."));
	puts(_("\t--broadcast\t\t-B [IFACE]\tBroadcast to a network manager when a virus is found."));
	puts(_("\t--config-file=FILE\t-c FILE\tRead configuration from FILE."));
	puts(_("\t--debug\t\t\t-D\tPrint debug messages."));
	puts(_("\t--detect-forged-local-address\t-L\tReject mails that claim to be from us."));
	puts(_("\t--dont-log-clean\t-C\tDon't add an entry to syslog that a mail is clean."));
	puts(_("\t--dont-scan-on-error\t-d\tPass e-mails through unscanned if a system error occurs."));
	puts(_("\t--dont-wait\t\t\tAsk remote end to resend if max-children exceeded."));
	puts(_("\t--external\t\t-e\tUse an external scanner (usually clamd)."));
	puts(_("\t--from=EMAIL\t\t-a EMAIL\tError messages come from here."));
	puts(_("\t--force-scan\t\t-f\tForce scan all messages (overrides (-o and -l)."));
	puts(_("\t--help\t\t\t-h\tThis message."));
	puts(_("\t--headers\t\t-H\tInclude original message headers in the report."));
	puts(_("\t--local\t\t\t-l\tScan messages sent from machines on our LAN."));
	puts(_("\t--max-childen\t\t-m\tMaximum number of concurrent scans."));
	puts(_("\t--outgoing\t\t-o\tScan outgoing messages from this machine."));
	puts(_("\t--noreject\t\t-N\tDon't reject viruses, silently throw them away."));
	puts(_("\t--noxheader\t\t-n\tSuppress X-Virus-Scanned/X-Virus-Status headers."));
	puts(_("\t--pidfile=FILE\t\t-i FILE\tLocation of pidfile."));
	puts(_("\t--postmaster\t\t-p EMAIL\tPostmaster address [default=postmaster]."));
	puts(_("\t--postmaster-only\t-P\tSend warnings only to the postmaster."));
	puts(_("\t--quiet\t\t\t-q\tDon't send e-mail notifications of interceptions."));
	puts(_("\t--quarantine=USER\t-Q EMAIL\tQuanrantine e-mail account."));
	puts(_("\t--quarantine-dir=DIR\t-U DIR\tDirectory to store infected emails."));
	puts(_("\t--server=SERVER\t\t-s SERVER\tHostname/IP address of server(s) running clamd (when using TCPsocket)."));
	puts(_("\t--sendmail-cf=FILE\t\tLocation of the sendmail.cf file to verify"));
	puts(_("\t--sign\t\t\t-S\tAdd a hard-coded signature to each scanned message."));
	puts(_("\t--signature-file=FILE\t-F FILE\tLocation of signature file."));
	puts(_("\t--template-file=FILE\t-t FILE\tLocation of e-mail template file."));
	puts(_("\t--timeout=SECS\t\t-T SECS\tTimeout waiting to childen to die."));
	puts(_("\t--whitelist-file=FILE\t-W FILE\tLocation of the file of whitelisted addresses"));
	puts(_("\t--version\t\t-V\tPrint the version number of this software."));
#ifdef	CL_DEBUG
	puts(_("\t--debug-level=n\t\t-x n\tSets the debug level to 'n'."));
#endif
	puts(_("\nFor more information type \"man clamav-milter\"."));
	puts(_("Report bugs to bugs@clamav.net."));
}

int
main(int argc, char **argv)
{
	extern char *optarg;
	int i, Bflag = 0;
	const char *cfgfile = CL_DEFAULT_CFG;
	const struct cfgstruct *cpt;
	char version[VERSION_LENGTH + 1];
	pthread_t tid;
#ifndef	CL_DEBUG
	int consolefd;
#endif
	struct smfiDesc smfilter = {
		"ClamAv", /* filter name */
		SMFI_VERSION,	/* version code -- leave untouched */
		SMFIF_ADDHDRS|SMFIF_CHGHDRS,	/* flags - we add and deleted headers */
		clamfi_connect, /* connection callback */
#ifdef	CL_DEBUG
		clamfi_helo,	/* HELO filter callback */
#else
		NULL,
#endif
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
	 * Temporarily enter guessed value into version, will
	 * be overwritten later by the value returned by clamd
	 */
	snprintf(version, sizeof(version) - 1,
		"ClamAV version %s, clamav-milter version %s",
		VERSION, CM_VERSION);

	progname = strrchr(argv[0], '/');
	if(progname)
		progname++;
	else
		progname = "clamav-milter";

#ifdef	C_LINUX
	setlocale(LC_ALL, "");
	bindtextdomain(progname, DATADIR"/clamav-milter/locale");
	textdomain(progname);
#endif

	for(;;) {
		int opt_index = 0;
#ifdef	CL_DEBUG
		const char *args = "a:AbB:c:CdDefF:lLm:nNop:PqQ:hHs:St:T:U:VwW:x:0:";
#else
		const char *args = "a:AbB:c:CdDefF:lLm:nNop:PqQ:hHs:St:T:U:VwW:0:";
#endif

		static struct option long_options[] = {
			{
				"from", 2, NULL, 'a'
			},
			{
				"advisory", 0, NULL, 'A'
			},
			{
				"bounce", 0, NULL, 'b'
			},
			{
				"broadcast", 2, NULL, 'B'
			},
			{
				"config-file", 1, NULL, 'c'
			},
			{
				"detect-forged-local-address", 0, NULL, 'L'
			},
			{
				"dont-log-clean", 0, NULL, 'C'
			},
			{
				"dont-scan-on-error", 0, NULL, 'd'
			},
			{
				"dont-wait", 0, NULL, 'w'
			},
			{
				"debug", 0, NULL, 'D'
			},
			{
				"external", 0, NULL, 'e'
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
				"pidfile", 1, NULL, 'i'
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
				"template-file", 1, NULL, 't'
			},
			{
				"timeout", 1, NULL, 'T'
			},
			{
				"whitelist-file", 1, NULL, 'W'
			},
			{
				"version", 0, NULL, 'V'
			},
			{
				"sendmail-cf", 1, NULL, '0'
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
			case 'a':	/* e-mail errors from here */
				/*
				 * optarg is optional - if you give --from
				 * then the --from is set to the orginal,
				 * probably forged, email address
				 */
				from = optarg;
				break;
			case 'A':
				advisory++;
				break;
			case 'b':	/* bounce worms/viruses */
				bflag++;
				break;
			case 'B':	/* broadcast */
				Bflag++;
				if(optarg)
					iface = optarg;
				break;
			case 'c':	/* where is clamd.conf? */
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
			case 'e':	/* use clamd */
				external++;
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
			case 'i':	/* pidfile */
				pidfile = optarg;
				break;
			case 'l':	/* scan mail from the lan */
				lflag++;
				break;
			case 'L':	/* detect forged local addresses */
				detect_forged_local_address++;
				break;
			case 'm':	/* maximum number of children */
				max_children = atoi(optarg);
				break;
			case 'n':	/* don't add X-Virus-Scanned */
				nflag++;
				smfilter.xxfi_flags &= ~(SMFIF_ADDHDRS|SMFIF_CHGHDRS);
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
#ifdef	notdef	/* don't define - forces --external to be listed first :-( */
				if(!external) {
					fputs("--server can only be used with --external\n", stderr);
					return EX_USAGE;
				}
#endif
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
			case 't':	/* e-mail template file */
				templatefile = optarg;
				break;
			case 'T':	/* time to wait for child to die */
				child_timeout = atoi(optarg);
				break;
			case 'U':	/* quarantine path */
				quarantine_dir = optarg;
				break;
			case 'V':
				puts(version);
				return EX_OK;
			case 'w':
				dont_wait++;
				break;
			case 'W':
				whitelistFile = optarg;
				break;
			case '0':
				sendmailCF = optarg;
				break;
#ifdef	CL_DEBUG
			case 'x':
				debug_level = atoi(optarg);
				break;
#endif
			default:
#ifdef	CL_DEBUG
				fprintf(stderr, "Usage: %s [-b] [-c FILE] [-F FILE] [--max-children=num] [-e] [-l] [-o] [-p address] [-P] [-q] [-Q USER] [-s SERVER] [-S] [-x#] [-U PATH] socket-addr\n", argv[0]);
#else
				fprintf(stderr, "Usage: %s [-b] [-c FILE] [-F FILE] [--max-children=num] [-e] [-l] [-o] [-p address] [-P] [-q] [-Q USER] [-s SERVER] [-S] [-U PATH] socket-addr\n", argv[0]);
#endif
				return EX_USAGE;
		}
	}

	/* FIXME: error if --servers and --external is not given */
	/* TODO: support freshclam's daemon notify if --external is not given */

	if(optind == argc) {
		fprintf(stderr, _("%s: No socket-addr given\n"), argv[0]);
		return EX_USAGE;
	}
	port = argv[optind];

	if(verifyIncomingSocketName(port) < 0) {
		fprintf(stderr, _("%s: socket-addr (%s) doesn't agree with sendmail.cf\n"), argv[0], port);
		return EX_CONFIG;
	}
	if(strncasecmp(port, "inet:", 5) == 0)
		if(!lflag) {
			/*
			 * Barmy but true. It seems that clamfi_connect will,
			 * in this case, get the IP address of the machine
			 * running sendmail, not of the machine sending the
			 * mail, so the remote end will be a local address so
			 * we must scan by enabling --local
			 *
			 * TODO: this is probably not needed if the remote
			 * machine is localhost, need to check though
			 */
			fprintf(stderr, _("%s: when using inet: connection to sendmail you must enable --local\n"), argv[0]);
			return EX_USAGE;
		}

	/*
	 * Sanity checks on the clamav configuration file
	 */
	if((copt = parsecfg(cfgfile, 1)) == NULL) {
		fprintf(stderr, _("%s: Can't parse the config file %s\n"),
			argv[0], cfgfile);
		return EX_CONFIG;
	}

	if(detect_forged_local_address) {
		if(oflag) {
			fprintf(stderr, _("%s: --detect-forged-local-addresses is not compatible with --outgoing\n"), argv[0]);
			return EX_CONFIG;
		}
		if(lflag) {
			fprintf(stderr, _("%s: --detect-forged-local-addresses is not compatible with --local\n"), argv[0]);
			return EX_CONFIG;
		}
		if(fflag) {
			fprintf(stderr, _("%s: --detect-forged-local-addresses is not compatible with --force\n"), argv[0]);
			return EX_CONFIG;
		}
	}

	if(Bflag) {
		int on;

		broadcastSock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
		/*
		 * SO_BROADCAST doesn't sent to all NICs on Linux, it only
		 * broadcasts on eth0, which is why there's an optional argument
		 * to --broadcast to say which NIC to broadcast on. You can use
		 * SO_BINDTODEVICE to get around that, but you need to have
		 * uid == 0 for that
		 */
		on = 1;
		if(setsockopt(broadcastSock, SOL_SOCKET, SO_BROADCAST, (int *)&on, sizeof(on)) < 0) {
			perror("setsockopt");
			return EX_UNAVAILABLE;
		}
		shutdown(broadcastSock, SHUT_RD);
	}

	/*
	 * Drop privileges
	 */
#ifndef	CL_DEBUG
	/* Save the fd for later, open while we can */
	consolefd = open(console, O_WRONLY);
#endif

	if(getuid() == 0) {
		if(iface) {
#ifdef	SO_BINDTODEVICE
			struct ifreq ifr;

			memset(&ifr, '\0', sizeof(struct ifreq));
			strncpy(ifr.ifr_name, iface, sizeof(ifr.ifr_name) - 1);
			if(setsockopt(broadcastSock, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0) {
				perror(iface);
				return EX_CONFIG;
			}
#else
			fprintf(stderr, _("%s: The iface option to --broadcast is not supported on your operating system\n"), argv[0]);
			return EX_CONFIG;
#endif
		}

		if((cpt = cfgopt(copt, "User")) != NULL) {
			const struct passwd *user;

			if((user = getpwnam(cpt->strarg)) == NULL) {
				fprintf(stderr, _("%s: Can't get information about user %s\n"), argv[0], cpt->strarg);
				return EX_CONFIG;
			}

			if(cfgopt(copt, "AllowSupplementaryGroups")) {
#ifdef HAVE_INITGROUPS
				if(initgroups(cpt->strarg, user->pw_gid) < 0) {
					perror(cpt->strarg);
					return EX_CONFIG;
				}
#else
				fprintf(stderr, _("%s: AllowSupplementaryGroups: initgroups not supported.\n"),
					argv[0]);
				return EX_CONFIG;
#endif
			} else {
#ifdef	HAVE_SETGROUPS
				if(setgroups(1, &user->pw_gid) < 0) {
					perror(cpt->strarg);
					return EX_CONFIG;
				}
#endif
			}

			setgid(user->pw_gid);
			if(setuid(user->pw_uid) < 0)
				perror(cpt->strarg);
			else
				cli_dbgmsg(_("Running as user %s (UID %d, GID %d)\n"),
					cpt->strarg, user->pw_uid, user->pw_gid);
		} else
			fprintf(stderr, _("%s: running as root is not recommended (check \"User\" in %s)\n"), argv[0], cfgfile);
	} else if(iface) {
		fprintf(stderr, _("%s: Only root can set an interface for --broadcast\n"), argv[0]);
		return EX_USAGE;
	}

	if(advisory && quarantine) {
		fprintf(stderr, _("%s: Advisory mode doesn't work with quarantine mode\n"), argv[0]);
		return EX_USAGE;
	}
	if(quarantine_dir) {
		struct stat statb;

		if(advisory) {
			fprintf(stderr,
				_("%s: Advisory mode doesn't work with quarantine directories\n"),
				argv[0]);
			return EX_USAGE;
		}
		if(strstr(quarantine_dir, "ERROR") != NULL) {
			fprintf(stderr,
				_("%s: the quarantine directory must not contain the string 'ERROR'\n"),
				argv[0]);
			return EX_USAGE;
		}
		if(strstr(quarantine_dir, "FOUND") != NULL) {
			fprintf(stderr,
				_("%s: the quarantine directory must not contain the string 'FOUND'\n"),
				argv[0]);
			return EX_USAGE;
		}
		if(strstr(quarantine_dir, "OK") != NULL) {
			fprintf(stderr,
				_("%s: the quarantine directory must not contain the string 'OK'\n"),
				argv[0]);
			return EX_USAGE;
		}
		if(access(quarantine_dir, W_OK) < 0) {
			perror(quarantine_dir);
			return EX_USAGE;
		}
		if(stat(quarantine_dir, &statb) < 0) {
			perror(quarantine_dir);
			return EX_USAGE;
		}
		/*
		 * Quit if the quarantine directory is publically readable
		 * or writeable
		 */
		if(statb.st_mode & 077) {
			fprintf(stderr, _("%s: insecure quarantine directory %s (mode 0%o)\n"),
				argv[0], quarantine_dir, statb.st_mode & 0777);
			return EX_CONFIG;
		}
	}

	if(sigFilename && !updateSigFile())
		return EX_USAGE;

	if(templatefile && (access(templatefile, R_OK) < 0)) {
		perror(templatefile);
		return EX_CONFIG;
	}

	if(whitelistFile && (access(whitelistFile, R_OK) < 0)) {  
	    perror(templatefile);	
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
			fprintf(stderr, _("%s: ReadTimeout must not be negative in %s\n"),
				argv[0], cfgfile);
			return EX_CONFIG;
		}
	}

	if((cpt = cfgopt(copt, "StreamMaxLength")) != NULL) {
		if(cpt->numarg < 0) {
			fprintf(stderr, _("%s: StreamMaxLength must not be negative in %s\n"),
				argv[0], cfgfile);
			return EX_CONFIG;
		}
		streamMaxLength = (long)cpt->numarg;
	}

	if(cfgopt(copt, "LogSyslog")) {
		int fac = LOG_LOCAL6;

		if(cfgopt(copt, "LogVerbose")) {
			logVerbose = 1;
#if	((SENDMAIL_VERSION_A > 8) || ((SENDMAIL_VERSION_A == 8) && (SENDMAIL_VERSION_B >= 13)))
			smfi_setdbg(6);
#endif
		}
		use_syslog = 1;

		if((cpt = cfgopt(copt, "LogFacility")) != NULL)
			if((fac = logg_facility(cpt->strarg)) == -1) {
				fprintf(stderr, "%s: LogFacility: %s: No such facility\n",
					argv[0], cpt->strarg);
				return EX_CONFIG;
			}
		openlog(progname, LOG_CONS|LOG_PID, fac);
	} else {
		if(qflag)
			fprintf(stderr, _("%s: (-q && !LogSyslog): warning - all interception message methods are off\n"),
				argv[0]);
		use_syslog = 0;
	}
	/*
	 * Get the outgoing socket details - the way to talk to clamd, unless
	 * we're doing the scanning internally
	 */
	if(!external) {
		if(max_children == 0) {
			fprintf(stderr, _("%s: --max-children must be given if --external is not given\n"), argv[0]);
			return EX_CONFIG;
		}
#if     0
		if(child_timeout) {
			fprintf(stderr, _("%s: --timeout must not be given if --external is not given\n"), argv[0]);
			return EX_CONFIG;
		}
#endif
		if(loadDatabase() != 0)
			return EX_CONFIG;
		numServers = 1;
	} else if((cpt = cfgopt(copt, "LocalSocket")) != NULL) {
#ifdef	SESSION
		struct sockaddr_un server;
#endif
		char *sockname = NULL;

		if(cfgopt(copt, "TCPSocket") != NULL) {
			fprintf(stderr, _("%s: You can select one server type only (local/TCP) in %s\n"),
				argv[0], cfgfile);
			return EX_CONFIG;
		}
		if(strncasecmp(port, "unix:", 5) == 0)
			sockname = &port[5];
		else if(strncasecmp(port, "local:", 6) == 0)
			sockname = &port[6];

		if(sockname && (strcmp(sockname, cpt->strarg) == 0)) {
			fprintf(stderr, _("The connection from sendmail to %s (%s) must not\n"),
				argv[0], sockname);
			fprintf(stderr, _("be the same as the connection to clamd (%s) in %s\n"),
				cpt->strarg, cfgfile);
			return EX_CONFIG;
		}
		/*
		 * TODO: check --server hasn't been set
		 */
		localSocket = cpt->strarg;
#ifndef	SESSION
		if(!pingServer(-1)) {
			fprintf(stderr, _("Can't talk to clamd server via %s\n"),
				localSocket);
			fprintf(stderr, _("Check your entry for LocalSocket in %s\n"),
				cfgfile);
			return EX_CONFIG;
		}
#endif
		/*if(quarantine_dir == NULL)
			fprintf(stderr, _("When using Localsocket in %s\nyou may improve performance if you use the --quarantine-dir option\n"), cfgfile);*/

		umask(077);

		serverIPs = (long *)cli_malloc(sizeof(long));
		serverIPs[0] = inet_addr("127.0.0.1");

#ifdef	SESSION
		memset((char *)&server, 0, sizeof(struct sockaddr_un));
		server.sun_family = AF_UNIX;
		strncpy(server.sun_path, localSocket, sizeof(server.sun_path));

		sessions = (struct session *)cli_malloc(sizeof(struct session));
		if((sessions[0].sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
			perror(localSocket);
			fprintf(stderr, _("Can't talk to clamd server via %s\n"),
				localSocket);
			fprintf(stderr, _("Check your entry for LocalSocket in %s\n"),
				cfgfile);
			return EX_CONFIG;
		}
		if(connect(sessions[0].sock, (struct sockaddr *)&server, sizeof(struct sockaddr_un)) < 0) {
			perror(localSocket);
			return EX_UNAVAILABLE;
		}
		if(send(sessions[0].sock, "SESSION\n", 7, 0) < 7) {
			perror("send");
			if(use_syslog)
				syslog(LOG_ERR, _("Can't create a clamd session"));
			return EX_UNAVAILABLE;
		}
		sessions[0].status = CMDSOCKET_FREE;
#endif
		/*
		 * FIXME: Allow connection to remote servers by TCP/IP whilst
		 * connecting to the localserver via a UNIX domain socket
		 */
		numServers = 1;
	} else if((cpt = cfgopt(copt, "TCPSocket")) != NULL) {
		int activeServers;

		/*
		 * TCPSocket is in fact a port number not a full socket
		 */
		if(quarantine_dir) {
			fprintf(stderr, _("%s: --quarantine-dir not supported for TCPSocket - use --quarantine\n"), argv[0]);
			return EX_CONFIG;
		}

		tcpSocket = (in_port_t)cpt->numarg;

		/*
		 * cli_strtok's fieldno counts from 0
		 */
		for(;;) {
			char *hostname = cli_strtok(serverHostNames, numServers, ":");
			if(hostname == NULL)
				break;
#ifdef	MAXHOSTNAMELEN
			if(strlen(hostname) > MAXHOSTNAMELEN) {
				fprintf(stderr, _("%s: hostname %s is longer than %d characters\n"),
					argv[0], hostname, MAXHOSTNAMELEN);
				return EX_CONFIG;
			}
#endif
			numServers++;
			free(hostname);
		}

		cli_dbgmsg("numServers: %d\n", numServers);

		serverIPs = (long *)cli_malloc(numServers * sizeof(long));
		activeServers = 0;

#ifdef	SESSION
		/*
		 * We need to know how many connections to establish to clamd
		 */
		if(max_children == 0) {
			fprintf(stderr, _("%s: --max-children must be given in sessions mode\n"), argv[0]);
			return EX_CONFIG;
		}
#endif

		for(i = 0; i < numServers; i++) {
#ifdef	MAXHOSTNAMELEN
			char hostname[MAXHOSTNAMELEN + 1];

			if(cli_strtokbuf(serverHostNames, i, ":", hostname) == NULL)
				break;
#else
			char *hostname = cli_strtok(serverHostNames, i, ":");
#endif

			/*
			 * Translate server's name to IP address
			 */
			serverIPs[i] = inet_addr(hostname);
			if(serverIPs[i] == -1L) {
				const struct hostent *h = gethostbyname(hostname);

				if(h == NULL) {
					fprintf(stderr, _("%s: Unknown host %s\n"),
						argv[0], hostname);
					return EX_USAGE;
				}

				memcpy((char *)&serverIPs[i], h->h_addr, sizeof(serverIPs[i]));
			}

#ifndef	SESSION
			if(pingServer(i))
				activeServers++;
			else {
				cli_warnmsg(_("Can't talk to clamd server %s on port %d\n"),
					hostname, tcpSocket);
				if(serverIPs[i] == (int)inet_addr("127.0.0.1")) {
					if(cfgopt(copt, "TCPAddr") != NULL)
						cli_warnmsg(_("Check the value for TCPAddr in %s\n"), cfgfile);
				} else
					cli_warnmsg(_("Check the value for TCPAddr in clamd.conf on %s\n"), hostname);
			}
#endif

#ifndef	MAXHOSTNAMELEN
			free(hostname);
#endif
		}
#ifdef	SESSION
		activeServers = numServers;

		sessions = (struct session *)cli_calloc(max_children, sizeof(struct session));
		for(i = 0; i < (int)max_children; i++)
			if(createSession(i) < 0)
				return EX_UNAVAILABLE;
		if(activeServers == 0) {
			cli_warnmsg(_("Can't find any active clamd servers\n"));
			cli_warnmsg(_("Check your entry for TCPSocket in %s\n"),
				cfgfile);
		}
#else
		if(activeServers == 0) {
			cli_errmsg(_("Can't find any clamd servers\n"));
			cli_errmsg(_("Check your entry for TCPSocket in %s\n"),
				cfgfile);
			return EX_CONFIG;
		}
#endif
	} else {
		fprintf(stderr, _("%s: You must select server type (local/TCP) in %s\n"),
			argv[0], cfgfile);
		return EX_CONFIG;
	}

#ifdef	SESSION
	if(!external) {
		if(clamav_versions == NULL) {
			clamav_versions = (char **)cli_malloc(sizeof(char *));
			if(clamav_versions == NULL)
				return EX_TEMPFAIL;
			clamav_version = strdup(version);
		}
	} else {
		unsigned int session;

		/*
		 * We need to know how many connections to establish to clamd
		 */
		if(max_children == 0) {
			fprintf(stderr, _("%s: --max-children must be given in sessions mode\n"), argv[0]);
			return EX_CONFIG;
		}

		clamav_versions = (char **)cli_malloc(max_children * sizeof(char *));
		if(clamav_versions == NULL)
			return EX_TEMPFAIL;

		for(session = 0; session < max_children; session++) {
			clamav_versions[session] = strdup(version);
			if(clamav_versions[session] == NULL)
				return EX_TEMPFAIL;
		}
	}
#else
	strcpy(clamav_version, version);
#endif

	if(((quarantine_dir == NULL) && localSocket) || !external) {
		/* set the temporary dir */
		if((cpt = cfgopt(copt, "TemporaryDirectory"))) {
			tmpdir = cpt->strarg;
			cl_settempdir(tmpdir, (short)(cfgopt(copt, "LeaveTemporaryFiles") != NULL));
		} else if((tmpdir = getenv("TMPDIR")) == (char *)NULL)
			if((tmpdir = getenv("TMP")) == (char *)NULL)
				if((tmpdir = getenv("TEMP")) == (char *)NULL)
#ifdef	P_tmpdir
					tmpdir = P_tmpdir;
#else
					tmpdir = "/tmp";
#endif

		/*
		 * TODO: investigate mkdtemp on LINUX and possibly others
		 */
		tmpdir = cli_gentemp(NULL);

		cli_dbgmsg("Making %s\n", tmpdir);

		if(mkdir(tmpdir, 0700)) {
			perror(tmpdir);
			return EX_CANTCREAT;
		}
	} else
		tmpdir = NULL;

	if(!cfgopt(copt, "Foreground")) {
#ifdef	CL_DEBUG
		printf(_("When debugging it is recommended that you use Foreground mode in %s\n"), cfgfile);
		puts(_("\tso that you can see all of the messages"));
#endif

		switch(fork()) {
			case -1:
				perror("fork");
				return EX_OSERR;
			case 0:	/* child */
				break;
			default:	/* parent */
				return EX_OK;
		}
		close(0);
		open("/dev/null", O_RDONLY);

#ifndef	CL_DEBUG
		close(1);

		if((cpt = cfgopt(copt, "LogFile"))) {
			logFile = cpt->strarg;

#if	defined(MSDOS) || defined(C_CYGWIN) || defined(WIN32)
			if((strlen(logFile) < 2) || ((logFile[0] != '/') && (logFile[0] != '\\') && (logFile[1] != ':'))) {
#else
			if((strlen(logFile) < 2) || (logFile[0] != '/')) {
#endif
				fprintf(stderr, "%s: LogFile requires full path\n", argv[0]);
				return EX_CONFIG;
			}
			if(open(logFile, O_WRONLY|O_APPEND) < 0) {
				if(errno == ENOENT) {
					/*
					 * There is low risk race condition here
					 */
					if(open(logFile, O_WRONLY|O_CREAT, 0644) < 0) {
						perror(logFile);
						return EX_CANTCREAT;
					}
				} else {
					perror(logFile);
					return EX_CANTCREAT;
				}
			}
		} else {
			logFile = console;
			if(consolefd < 0) {
				perror(console);
				return EX_OSFILE;
			}
			dup(consolefd);
		}
		close(2);
		dup(1);
		if(consolefd >= 0)
			close(consolefd);

#endif	/*!CL_DEBUG*/

		if(cfgopt(copt, "LogTime"))
			logg_time = 1;
		if(cfgopt(copt, "LogFileUnlock"))
			logg_lock = 0;
		if(cfgopt(copt, "LogClean"))
			logok = 1;
		if((cpt = cfgopt(copt, "LogFileMaxSize")))
			logg_size = cpt->numarg;
		else
			logg_size = CL_DEFAULT_LOGSIZE;


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

	atexit(quit);

	if(!external) {
		/* TODO: read the limits from clamd.conf */

		if(cfgopt(copt, "DisableDefaultScanOptions")) {
			options &= ~CL_SCAN_STDOPT;
			if(!cfgopt(copt, "ScanMail"))
				printf(_("%s: ScanMail not defined in %s (needed without --external), enabling\n"),
					argv[0], cfgfile);
		}
		options |= CL_SCAN_MAIL;	/* no choice */
		if(!cfgopt(copt, "ScanRAR"))
			options |= CL_SCAN_DISABLERAR;
		if(cfgopt(copt, "ArchiveBlockEncrypted"))
			options |= CL_SCAN_BLOCKENCRYPTED;
		if(cfgopt(copt, "ArchiveBlockMax"))
			options |= CL_SCAN_BLOCKMAX;
		if(cfgopt(copt, "ScanPE"))
			options |= CL_SCAN_PE;
		if(cfgopt(copt, "DetectBrokenExecutables"))
			options |= CL_SCAN_BLOCKBROKEN;
		if(cfgopt(copt, "MailFollowURLs"))
			options |= CL_SCAN_MAILURL;
		if(cfgopt(copt, "ScanOLE2"))
			options |= CL_SCAN_OLE2;
		if(cfgopt(copt, "ScanHTML"))
			options |= CL_SCAN_HTML;

		memset(&limits, '\0', sizeof(struct cl_limits));

		if(cfgopt(copt, "ScanArchive")) {
			options |= CL_SCAN_ARCHIVE;
			if((cpt = cfgopt(copt, "ArchiveMaxFileSize")) != NULL)
				limits.maxfilesize = cpt->numarg;
			else
				limits.maxfilesize = 10485760;

			if((cpt = cfgopt(copt, "ArchiveMaxRecursion")) != NULL)
				limits.maxreclevel = cpt->numarg;
			else
				limits.maxreclevel = 8;

			if((cpt = cfgopt(copt, "ArchiveMaxFiles")) != NULL)
				limits.maxfiles = cpt->numarg;
			else
				limits.maxfiles = 1000;

			if((cpt = cfgopt(copt, "ArchiveMaxCompressionRatio")) != NULL)
				limits.maxratio = cpt->numarg;
			else
				limits.maxratio = 250;

			if(cfgopt(copt, "ArchiveLimitMemoryUsage") != NULL)
				limits.archivememlim = 1;
			else
				limits.archivememlim = 0;
		}
	}

#ifdef	SESSION
	/* FIXME: add localSocket support to watchdog */
	if((localSocket == NULL) || external)
#endif
		pthread_create(&tid, NULL, watchdog, NULL);

	if((cpt = cfgopt(copt, "PidFile")) != NULL)
		pidFile = cpt->strarg;

	broadcast(_("Starting clamav-milter"));

	if(pidfile) {
		/* save the PID */
		char *p, *q;
		FILE *fd;
		const mode_t old_umask = umask(0006);

		if(pidfile[0] != '/') {
			if(use_syslog)
				syslog(LOG_ERR, _("pidfile: '%s' must be a full pathname"),
					pidfile);
			cli_errmsg(_("pidfile '%s' must be a full pathname\n"), pidfile);

			return EX_CONFIG;
		}
		p = strdup(pidfile);
		q = strrchr(p, '/');
		*q = '\0';

		if(chdir(p) < 0)	/* safety */
			perror(p);
		free(p);

		if((fd = fopen(pidfile, "w")) == NULL) {
			if(use_syslog)
				syslog(LOG_ERR, _("Can't save PID in file %s"),
					pidfile);
			cli_errmsg(_("Can't save PID in file %s\n"), pidfile);
			return EX_CONFIG;
		}
#ifdef	C_LINUX
		/* Ensure that all threads are kill()ed */
		fprintf(fd, "-%d\n", (int)getpgrp());
#else
		fprintf(fd, "%d\n", (int)getpid());
#endif
		fclose(fd);
		umask(old_umask);
	} else if(tmpdir)
		chdir(tmpdir);	/* safety */
	else
#ifdef	P_tmpdir
		chdir(P_tmpdir);
#else
		chdir("/tmp");
#endif

	if(cfgopt(copt, "FixStaleSocket")) {
		/*
		 * Get the incoming socket details - the way sendmail talks to
		 * us
		 *
		 * TODO: There's a security problem here that'll need fixing if
		 * the User entry of clamd.conf is not used
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
		cli_errmsg("smfi_setconn failure\n");
		return EX_SOFTWARE;
	}

	if(smfi_register(smfilter) == MI_FAILURE) {
		cli_errmsg("smfi_register failure\n");
		return EX_UNAVAILABLE;
	}

#if	((SENDMAIL_VERSION_A > 8) || ((SENDMAIL_VERSION_A == 8) && (SENDMAIL_VERSION_B >= 13)))
	if(smfi_opensocket(1) == MI_FAILURE) {
		cli_errmsg("Can't open/create %s\n", port);
		return EX_CONFIG;
	}
#endif

	signal(SIGPIPE, SIG_IGN);	/* libmilter probably does this as well */

#ifdef	SESSION
	pthread_mutex_lock(&version_mutex);
#endif
	if(use_syslog) {
		syslog(LOG_INFO, _("Starting %s"), clamav_version);
#ifdef	CL_DEBUG
		if(debug_level > 0)
			syslog(LOG_DEBUG, _("Debugging is on"));
#endif
	}

	cli_dbgmsg("Started: %s\n", clamav_version);
#ifdef	SESSION
	pthread_mutex_unlock(&version_mutex);
#endif

	(void)signal(SIGSEGV, sigsegv);

	return smfi_main();
}

#ifdef	SESSION
/*
 * Use the SESSION command of clamd.
 * Returns -1 for terminal failure, 0 for OK, 1 for nonterminal failure
 * The caller must take care of locking the sessions array
 */
static int
createSession(unsigned int s)
{
	int ret = 0, fd;
	struct sockaddr_in server;
	const int serverNumber = s % numServers;
	struct session *session = &sessions[s];

	cli_dbgmsg("createSession session %d, server %d\n", s, serverNumber);
	assert(s < max_children);

	memset((char *)&server, 0, sizeof(struct sockaddr_in));
	server.sin_family = AF_INET;
	server.sin_port = (in_port_t)htons(tcpSocket);

	server.sin_addr.s_addr = serverIPs[serverNumber];

	session->sock = -1;
	if((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		ret = -1;
	} else if(connect(fd, (struct sockaddr *)&server, sizeof(struct sockaddr_in)) < 0) {
		perror("connect");
		ret = 1;
	} else if(send(fd, "SESSION\n", 7, 0) < 7) {
		perror("send");
		ret = 1;
	}

	if(ret != 0) {
#ifdef	MAXHOSTNAMELEN
		char hostname[MAXHOSTNAMELEN + 1];

		cli_strtokbuf(serverHostNames, serverNumber, ":", hostname);
		if(strcmp(hostname, "127.0.0.1") == 0)
			gethostname(hostname, sizeof(hostname));
#else
		char *hostname = cli_strtok(serverHostNames, serverNumber, ":");
#endif

		session->status = CMDSOCKET_DOWN;

		if(fd >= 0)
			close(fd);

		cli_warnmsg(_("Check clamd server %s - it may be down\n"), hostname);
#ifndef	MAXHOSTNAMELEN
		free(hostname);
#endif

		broadcast(_("Check clamd server - it may be down"));
	} else
		session->sock = fd;

	return ret;
}

#else

/*
 * Verify that the server is where we think it is
 * Returns true or false
 *
 * serverNumber counts from 0, but is only used for TCPSocket
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
			perror(localSocket);
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
	cli_dbgmsg("pingServer%d: sending VERSION\n", serverNumber);
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
	 *	are out of date (say more than a month old)
	 */
	snprintf(clamav_version, sizeof(clamav_version) - 1,
		"%s\n\tclamav-milter version %s",
		buf, CM_VERSION);

	return 1;
}
#endif

/*
 * Find the best server to connect to. No intelligence to this.
 * It is best to weight the order of the servers from most wanted to least
 * wanted
 *
 * Return value is from 0 - index into sessions array
 *
 * If the load balancing fails return the first server in the list, not
 * an error, to be on the safe side
 */
#ifdef	SESSION
static int
findServer(void)
{
	unsigned int i, j;
	struct session *session;

	/*
	 * FIXME: Sessions code isn't flexible at handling servers
	 *	appearing and disappearing, e.g. sessions[n_children].sock == -1
	 */
	i = 0;
	pthread_mutex_lock(&n_children_mutex);
	assert(n_children > 0);
	assert(n_children <= max_children);
	j = n_children - 1;
	pthread_mutex_unlock(&n_children_mutex);

	pthread_mutex_lock(&sstatus_mutex);
	for(; i < max_children; i++) {
		const int sess = (j + i) % max_children;

		session = &sessions[sess];
		cli_dbgmsg("findServer: try server %d\n", sess);
		if(session->status == CMDSOCKET_FREE) {
			session->status = CMDSOCKET_INUSE;
			pthread_mutex_unlock(&sstatus_mutex);
			return sess;
		}
	}
	pthread_mutex_unlock(&sstatus_mutex);

	/*
	 * No session free - wait until one comes available. Only
	 * retries once.
	 */
	if(pthread_cond_broadcast(&watchdog_cond) < 0)
		perror("pthread_cond_broadcast");

	i = 0;
	session = sessions;
	pthread_mutex_lock(&sstatus_mutex);
	for(; i < max_children; i++, session++) {
		cli_dbgmsg("findServer: try server %d\n", i);
		if(session->status == CMDSOCKET_FREE) {
			session->status = CMDSOCKET_INUSE;
			pthread_mutex_unlock(&sstatus_mutex);
			return i;
		}
	}
	pthread_mutex_unlock(&sstatus_mutex);

	cli_warnmsg(_("No free clamd sessions\n"));

	return -1;	/* none available - must fail */
}
#else
/*
 * Return value is from 0 - index into serverIPs
 */
static int
findServer(void)
{
	struct sockaddr_in *servers, *server;
	int *socks, maxsock = 0, i, j;
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

	if(max_children > 0) {
		assert(n_children > 0);
		assert(n_children <= max_children);

		/*
		 * Don't worry about no lock - it's doesn't matter if it's
		 * not really accurate
		 */
		j = n_children - 1;
	} else
		/*
		 * cli_rndnum returns 0..(max-1) - the max argument is not
		 * the maximum number you want it to return, it is in fact
		 * one *more* than the maximum number you want it to return
		 */
		j = cli_rndnum(numServers);

	for(i = 0, server = servers; i < numServers; i++, server++) {
		int sock;

		server->sin_family = AF_INET;
		server->sin_port = (in_port_t)htons(tcpSocket);
		server->sin_addr.s_addr = serverIPs[(i + j) % numServers];

		cli_dbgmsg("findServer: try server %d\n",
			(i + j) % numServers);

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
#ifdef	MAXHOSTNAMELEN
			char hostname[MAXHOSTNAMELEN + 1];

			cli_strtokbuf(serverHostNames, i, ":", hostname);
			if(strcmp(hostname, "127.0.0.1") == 0)
				gethostname(hostname, sizeof(hostname));
#else
			char *hostname = cli_strtok(serverHostNames, i, ":");
#endif
			cli_warnmsg(_("Check clamd server %s - it may be down\n"), hostname);
			if(use_syslog)
				syslog(LOG_WARNING,
					_("Check clamd server %s - it may be down"),
					hostname);
			close(sock);
#ifndef	MAXHOSTNAMELEN
			free(hostname);
#endif
			broadcast(_("Check clamd server - it may be down\n"));
			socks[i] = -1;
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

	if(maxsock == 0)
		retval = 0;
	else
		retval = select(maxsock + 1, &rfds, NULL, NULL, &tv);

	if(retval < 0)
		perror("select");

	for(i = 0; i < numServers; i++)
		if(socks[i] >= 0)
			close(socks[i]);

	if(retval == 0) {
		free(socks);
		clamdIsDown();
		return 0;
	} else if(retval < 0) {
		free(socks);
		if(use_syslog)
			syslog(LOG_ERR, _("findServer: select failed"));
		return 0;
	}

	for(i = 0; i < numServers; i++)
		if((socks[i] >= 0) && (FD_ISSET(socks[i], &rfds))) {
			const int s = (i + j) % numServers;

			free(socks);
			cli_dbgmsg(_("findServer: using server %d\n"), s);
			return s;
		}

	free(socks);
	cli_dbgmsg(_("findServer: No response from any server\n"));
	if(use_syslog)
		syslog(LOG_WARNING, _("findServer: No response from any server"));
	return 0;
}
#endif

/*
 * Sendmail wants to establish a connection to us
 */
static sfsistat
clamfi_connect(SMFICTX *ctx, char *hostname, _SOCK_ADDR *hostaddr)
{
#if	defined(HAVE_INET_NTOP) || defined(WITH_TCPWRAP)
	char ip[INET_ADDRSTRLEN];	/* IPv4 only */
#endif
	const char *remoteIP;

	if(quitting)
		return cl_error;

	if(ctx == NULL) {
		if(use_syslog)
			syslog(LOG_ERR, _("clamfi_connect: ctx is null"));
		return cl_error;
	}
	if(hostname == NULL) {
		if(use_syslog)
			syslog(LOG_ERR, _("clamfi_connect: hostname is null"));
		return cl_error;
	}
	if((hostaddr == NULL) || (&(((struct sockaddr_in *)(hostaddr))->sin_addr) == NULL))
		/*
		 * According to the sendmail API hostaddr is NULL if
		 * "the type is not supported in the current version". What
		 * the documentation doesn't say is the type of what.
		 *
		 * Possibly the input is not a TCP/IP socket e.g. stdin?
		 */
		remoteIP = "127.0.0.1";
	else {
#ifdef HAVE_INET_NTOP
		remoteIP = (char *)inet_ntop(AF_INET, &((struct sockaddr_in *)(hostaddr))->sin_addr, ip, sizeof(ip));
#else
		remoteIP = inet_ntoa(((struct sockaddr_in *)(hostaddr))->sin_addr);
#endif

		if(remoteIP == NULL) {
			if(use_syslog)
				syslog(LOG_ERR, _("clamfi_connect: remoteIP is null"));
			return cl_error;
		}
	}

#ifdef	CL_DEBUG
	if(debug_level >= 4) {
		if(hostname[0] == '[') {
			if(use_syslog)
				syslog(LOG_NOTICE, _("clamfi_connect: connection from %s"), remoteIP);
			cli_dbgmsg(_("clamfi_connect: connection from %s\n"), remoteIP);
		} else {
			if(use_syslog)
				syslog(LOG_NOTICE, _("clamfi_connect: connection from %s [%s]"), hostname, remoteIP);
			cli_dbgmsg(_("clamfi_connect: connection from %s [%s]\n"), hostname, remoteIP);
		}
	}
#endif

#ifdef	WITH_TCPWRAP
	/*
	 * Support /etc/hosts.allow and /etc/hosts.deny
	 */
	if(strncasecmp(port, "inet:", 5) == 0) {
		const char *hostmail;
		struct hostent hostent;
		char buf[BUFSIZ];
		static pthread_mutex_t wrap_mutex = PTHREAD_MUTEX_INITIALIZER;

		/*
		 * Using TCP/IP for the sendmail->clamav-milter connection
		 */
		if((hostmail = smfi_getsymval(ctx, "{if_name}")) == NULL) {
			if(use_syslog)
				syslog(LOG_ERR, _("Can't get sendmail hostname"));
			return cl_error;
		}
		/*
		 * Use hostmail for error statements, not hostname, suggestion
		 * by Yar Tikhiy <yar@comp.chem.msu.su>
		 */
		if(clamfi_gethostbyname(hostmail, &hostent, buf, sizeof(buf)) != 0) {
			if(use_syslog)
				syslog(LOG_WARNING, _("Access Denied: Host Unknown (%s)"), hostmail);
			if(hostmail[0] == '[')
				/*
				 * A case could be made that it's not clamAV's
				 * job to check a system's DNS configuration
				 * and let this message through. However I am
				 * just too worried about any knock on effects
				 * to do that...
				 */
				cli_warnmsg(_("Can't find entry for IP address %s in DNS - check your DNS setting\n"),
					hostmail);
			return cl_error;
		}

#ifdef HAVE_INET_NTOP
		if(hostent.h_addr &&
		   (inet_ntop(AF_INET, (struct in_addr *)hostent.h_addr, ip, sizeof(ip)) == NULL)) {
			perror(hostent.h_name);
			/*strcpy(ip, (char *)inet_ntoa(*(struct in_addr *)hostent.h_addr));*/
			if(use_syslog)
				syslog(LOG_WARNING, _("Access Denied: Can't get IP address for (%s)"), hostent.h_name);
			return cl_error;
		}
#else
		strncpy(ip, (char *)inet_ntoa(*(struct in_addr *)hostent.h_addr), sizeof(ip));
#endif

		/*
		 * Ask is this is a allowed name or IP number
		 *
		 * hosts_ctl uses strtok so it is not thread safe, see
		 * hosts_access(3)
		 */
		pthread_mutex_lock(&wrap_mutex);
		if(!hosts_ctl(progname, hostent.h_name, ip, STRING_UNKNOWN)) {
			pthread_mutex_unlock(&wrap_mutex);
			if(use_syslog)
				syslog(LOG_WARNING, _("Access Denied for %s[%s]"), hostent.h_name, ip);
			return SMFIS_TEMPFAIL;
		}
		pthread_mutex_unlock(&wrap_mutex);
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
				syslog(LOG_DEBUG, _("clamfi_connect: not scanning outgoing messages"));
			cli_dbgmsg(_("clamfi_connect: not scanning outgoing messages\n"));
#endif
			return SMFIS_ACCEPT;
		}

	if((!lflag) && isLocalAddr(inet_addr(remoteIP))) {
#ifdef	CL_DEBUG
		if(use_syslog)
			syslog(LOG_DEBUG, _("clamfi_connect: not scanning local messages"));
		cli_dbgmsg(_("clamfi_connect: not scanning local messages\n"));
#endif
		return SMFIS_ACCEPT;
	}

#if	defined(HAVE_INET_NTOP) || defined(WITH_TCPWRAP)
	if(detect_forged_local_address && !isLocalAddr(inet_addr(ip))) {
#else
	if(detect_forged_local_address && !isLocalAddr(inet_addr(remoteIP))) {
#endif
		char me[MAXHOSTNAMELEN + 1];

		if(gethostname(me, sizeof(me) - 1) < 0) {
			if(use_syslog)
				syslog(LOG_WARNING, _("clamfi_connect: gethostname failed"));
			return SMFIS_CONTINUE;
		}
		if(strcasecmp(hostname, me) == 0) {
			if(use_syslog)
				syslog(LOG_NOTICE, _("Rejected email falsely claiming to be from here"));
			smfi_setreply(ctx, "550", "5.7.1", _("You have claimed to be me, but you are not"));
			broadcast(_("Forged local address detected"));
			return SMFIS_REJECT;
		}
	}
	return SMFIS_CONTINUE;
}

static sfsistat
clamfi_envfrom(SMFICTX *ctx, char **argv)
{
	struct privdata *privdata;
	const char *mailaddr = argv[0];

	if(logVerbose)
		syslog(LOG_DEBUG, "clamfi_envfrom: %s", argv[0]);

	cli_dbgmsg("clamfi_envfrom: %s\n", argv[0]);

	if(strcmp(argv[0], "<>") == 0) {
		mailaddr = smfi_getsymval(ctx, "{mail_addr}");
		if(mailaddr == NULL)
			mailaddr = smfi_getsymval(ctx, "_");

		if(mailaddr && *mailaddr)
			cli_dbgmsg("Message from \"%s\" has no from field\n", mailaddr);
		else {
#if	0
			if(use_syslog)
				syslog(LOG_NOTICE, _("Rejected email with empty from field"));
			smfi_setreply(ctx, "554", "5.7.1", _("You have not said who the email is from"));
			broadcast(_("Reject email with empty from field"));
			clamfi_cleanup(ctx);
			return SMFIS_REJECT;
#endif
			mailaddr = "<>";
		}
	}

	if(max_children > 0) {
		int rc = 0;

		pthread_mutex_lock(&n_children_mutex);

		/*
		 * Wait a while since sendmail doesn't like it if we
		 * take too long replying. Effectively this means that
		 * max_children is more of a hint than a rule
		 */
		if(n_children >= max_children) {
			struct timespec timeout;

			cli_dbgmsg((dont_wait) ?
					_("hit max-children limit (%u >= %u)\n") :
					_("hit max-children limit (%u >= %u): waiting for some to exit\n"),
				n_children, max_children);

			if(use_syslog)
				syslog(LOG_NOTICE,
					(dont_wait) ?
						_("hit max-children limit (%u >= %u)") :
						_("hit max-children limit (%u >= %u): waiting for some to exit"),
					n_children, max_children);

			if(dont_wait) {
				pthread_mutex_unlock(&n_children_mutex);
				smfi_setreply(ctx, "451", "4.3.2", _("AV system temporarily overloaded - please try later"));
				return SMFIS_TEMPFAIL;
			}
			/*
			 * Wait for an amount of time for a child to go
			 *
			 * Use pthread_cond_timedwait rather than
			 * pthread_cond_wait since the sendmail which calls
			 * us will have a timeout that we don't want to exceed,
			 * stops sendmail getting fidgety.
			 *
			 * Patch from Damian Menscher <menscher@uiuc.edu> to
			 * ensure it wakes up when a child goes away
			 */
			do
				if(child_timeout == 0) {
					pthread_cond_wait(&n_children_cond, &n_children_mutex);
					rc = 0;
				} else {
					struct timeval now;
					struct timezone tz;

					gettimeofday(&now, &tz);
					timeout.tv_sec = now.tv_sec + child_timeout;
					timeout.tv_nsec = 0;

					rc = pthread_cond_timedwait(&n_children_cond, &n_children_mutex, &timeout);
				}
			while((n_children >= max_children) && (rc != ETIMEDOUT));
		}
		n_children++;

		cli_dbgmsg(_(">n_children = %d\n"), n_children);
		pthread_mutex_unlock(&n_children_mutex);

		if(child_timeout && (rc == ETIMEDOUT)) {
#ifdef	CL_DEBUG
			if(use_syslog)
				syslog(LOG_NOTICE, _("Timeout waiting for a child to die"));
#endif
			cli_dbgmsg(_("Timeout waiting for a child to die\n"));
		}
	}

	privdata = (struct privdata *)cli_calloc(1, sizeof(struct privdata));
	if(privdata == NULL)
		return cl_error;

	privdata->dataSocket = -1;	/* 0.4 */
#ifndef	SESSION
	privdata->cmdSocket = -1;	/* 0.4 */
#endif

	/*
	 * Rejection is via 550 until DATA is received. We know that
	 * DATA has been sent when either we get a header or the end of
	 * header statement
	 */
	privdata->rejectCode = "550";

	privdata->from = strdup(mailaddr);

	if(hflag)
		privdata->headers = header_list_new();

	if(smfi_setpriv(ctx, privdata) == MI_SUCCESS)
		return SMFIS_CONTINUE;

	clamfi_free(privdata);

	return cl_error;
}

#ifdef	CL_DEBUG
static sfsistat
clamfi_helo(SMFICTX *ctx, char *helostring)
{
	cli_dbgmsg("HELO '%s'\n", helostring);

	return SMFIS_CONTINUE;
}
#endif

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

	if(privdata->to == NULL)
		return cl_error;

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
		cli_dbgmsg("clamfi_header: %s: %s\n", headerf, headerv);
	else
		cli_dbgmsg("clamfi_header\n");
#endif

	/*
	 * The DATA instruction from SMTP (RFC2821) must have been sent
	 */
	privdata->rejectCode = "554";

	if(privdata->dataSocket == -1)
		/*
		 * First header - make connection with clamd
		 */
		if(!connect2clamd(privdata)) {
			clamfi_cleanup(ctx);
			return cl_error;
		}

	if(clamfi_send(privdata, 0, "%s: %s\n", headerf, headerv) <= 0) {
		clamfi_cleanup(ctx);
		return cl_error;
	}

	if(hflag)
		header_list_add(privdata->headers, headerf, headerv);
	else if((strcasecmp(headerf, "Received") == 0) &&
		(strncasecmp(headerv, "from ", 5) == 0) &&
		(strstr(headerv, "localhost") != 0)) {
		if(privdata->received)
			free(privdata->received);
		privdata->received = strdup(headerv);
	}

	if((strcasecmp(headerf, "Message-ID") == 0) &&
	   (strncasecmp(headerv, "<MDAEMON", 8) == 0))
		privdata->discard = 1;
	else if(strcasecmp(headerf, "Subject") == 0) {
		if(privdata->subject)
			free(privdata->subject);
		if(headerv)
			privdata->subject = strdup(headerv);
	} else if(strcasecmp(headerf, "X-Virus-Status") == 0)
		privdata->statusCount++;
	else if(strcasecmp(headerf, "Sender") == 0) {
		if(privdata->sender)
			free(privdata->sender);
		if(headerv)
			privdata->sender = strdup(headerv);
	}

	return SMFIS_CONTINUE;
}

/*
 * At this point DATA will have been received, so we really ought to
 * send 554 back not 550
 */
static sfsistat
clamfi_eoh(SMFICTX *ctx)
{
	struct privdata *privdata = (struct privdata *)smfi_getpriv(ctx);
	char **to;

	if(logVerbose)
		syslog(LOG_DEBUG, _("clamfi_eoh"));
#ifdef	CL_DEBUG
	if(debug_level >= 4)
		cli_dbgmsg(_("clamfi_eoh\n"));
#endif

	/*
	 * The DATA instruction from SMTP (RFC2821) must have been sent
	 */
	privdata->rejectCode = "554";

	if(privdata->dataSocket == -1)
		/*
		 * No headers - make connection with clamd
		 */
		if(!connect2clamd(privdata)) {
			clamfi_cleanup(ctx);
			return cl_error;
		}

	if(detect_forged_local_address && privdata->from &&
	   (!privdata->sender) && !isWhitelisted(privdata->from)) {
		char me[MAXHOSTNAMELEN + 1];
		const char *ptr;

		if(gethostname(me, sizeof(me) - 1) < 0) {
			if(use_syslog)
				syslog(LOG_WARNING, _("clamfi_eoh: gethostname failed"));
			return SMFIS_CONTINUE;
		}
		ptr = strstr(privdata->from, me);
		if(ptr && (ptr != privdata->from) && (*--ptr == '@')) {
			if(use_syslog)
				syslog(LOG_NOTICE, _("Rejected email falsely claiming to be from %s"), privdata->from);
			smfi_setreply(ctx, "554", "5.7.1", _("You have claimed to be from me, but you are not"));
			broadcast(_("Forged local address detected"));
			clamfi_cleanup(ctx);
			return SMFIS_REJECT;
		}
	}

	if(clamfi_send(privdata, 1, "\n") != 1) {
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
	for(to = privdata->to; *to; to++)
		if(!isWhitelisted(*to))
			/*
			 * This recipient is not on the whitelist,
			 * no need to check any further
			 */
			return SMFIS_CONTINUE;
	/*
	 * Didn't find a recipient who is not on the white list, so all
	 * must be on the white list, so just accept the e-mail
	 */
	if(use_syslog)
		syslog(LOG_NOTICE, _("clamfi_eoh: ignoring whitelisted message"));
#ifdef	CL_DEBUG
	cli_dbgmsg(_("clamfi_eoh: ignoring whitelisted message\n"));
#endif
	clamfi_cleanup(ctx);

	return SMFIS_ACCEPT;
}

static sfsistat
clamfi_body(SMFICTX *ctx, u_char *bodyp, size_t len)
{
	struct privdata *privdata = (struct privdata *)smfi_getpriv(ctx);
	int nbytes;

	if(logVerbose)
		syslog(LOG_DEBUG, _("clamfi_envbody: %u bytes"), len);
#ifdef	CL_DEBUG
	cli_dbgmsg(_("clamfi_envbody: %u bytes\n"), len);
#endif

	if(len == 0)	/* unlikely */
		return SMFIS_CONTINUE;

	nbytes = clamfi_send(privdata, len, (char *)bodyp);
	if(streamMaxLength > 0L) {
		if(privdata->numBytes > streamMaxLength) {
			if(use_syslog) {
				const char *sendmailId = smfi_getsymval(ctx, "i");
				if(sendmailId == NULL)
					sendmailId = "Unknown";
				syslog(LOG_NOTICE, _("%s: Message more than StreamMaxLength (%ld) bytes - not scanned"),
					sendmailId, streamMaxLength);
			}
			if(!nflag)
				smfi_addheader(ctx, "X-Virus-Status", _("Not Scanned - StreamMaxLength exceeded"));

			return SMFIS_ACCEPT;	/* clamfi_close will be called */
		}
	}
	if((size_t)nbytes < len) {
		clamfi_cleanup(ctx);	/* not needed, but just to be safe */
		return cl_error;
	}
	if(Sflag) {
		if(privdata->body) {
			assert(privdata->bodyLen > 0);
			privdata->body = cli_realloc(privdata->body, privdata->bodyLen + len);
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
#ifdef	SESSION
	struct session *session;
#endif

	if(logVerbose)
		syslog(LOG_DEBUG, "clamfi_eom");

	cli_dbgmsg("clamfi_eom\n");

	if(!nflag) {
		/*
		 * remove any existing claims that it's virus free so that
		 * downstream checkers aren't fooled by a carefully crafted
		 * virus.
		 */
		int i;

		for(i = privdata->statusCount; i > 0; --i)
			if(smfi_chgheader(ctx, "X-Virus-Status", i, NULL) == MI_FAILURE)
				if(use_syslog)
					syslog(LOG_WARNING, _("Failed to delete X-Virus-Status header %d"), i);
	}

#ifdef	CL_DEBUG
	assert(privdata != NULL);
#ifndef	SESSION
	assert((privdata->cmdSocket >= 0) || (privdata->filename != NULL));
	assert(!((privdata->cmdSocket >= 0) && (privdata->filename != NULL)));
#endif
	assert(privdata->dataSocket >= 0);
#endif

	if(external) {
		close(privdata->dataSocket);
		privdata->dataSocket = -1;
	}

	if(!external) {
		const char *virname;
		unsigned long int scanned = 0L;

		/*
		 * TODO: consider using cl_scandesc and not using a temporary
		 *	file from the mail being read in
		 */
		pthread_mutex_lock(&root_mutex);
		privdata->root = cl_dup(root);
		pthread_mutex_unlock(&root_mutex);
		if(privdata->root == NULL) {
			cli_errmsg("privdata->root == NULL\n");
			clamfi_cleanup(ctx);
			return cl_error;
		}
		switch(cl_scanfile(privdata->filename, &virname, &scanned, privdata->root, &limits, options)) {
			case CL_CLEAN:
				if(logClean) {
					snprintf(mess, sizeof(mess), "%s: OK", privdata->filename);
					logger(mess);
				}
				strcpy(mess, "OK");
				break;
			case CL_VIRUS:
				snprintf(mess, sizeof(mess), "%s: %s FOUND", privdata->filename, virname);
				logger(mess);
				break;
			default:
				snprintf(mess, sizeof(mess), "%s: %s ERROR", privdata->filename, cl_strerror(rc));
				logger(mess);
				break;
		}
		cl_free(privdata->root);
		privdata->root = NULL;

#ifdef	SESSION
		session = NULL;
#endif
	} else if(privdata->filename) {
		char cmdbuf[1024];
		/*
		 * Create socket to talk to clamd.
		 */
#ifndef	SESSION
		struct sockaddr_un server;
#endif
		int nbytes;

		snprintf(cmdbuf, sizeof(cmdbuf) - 1, "SCAN %s", privdata->filename);
		cli_dbgmsg("clamfi_eom: SCAN %s\n", privdata->filename);

		nbytes = (int)strlen(cmdbuf);

#ifdef	SESSION
		session = sessions;
		if(send(session->sock, cmdbuf, nbytes, 0) < nbytes) {
			perror("send");
			clamfi_cleanup(ctx);
			if(use_syslog)
				syslog(LOG_ERR, _("failed to send SCAN %s command to clamd"), privdata->filename);
			return cl_error;
		}
#else
		if((privdata->cmdSocket = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
			perror("socket");
			clamfi_cleanup(ctx);
			return cl_error;
		}
		memset((char *)&server, 0, sizeof(struct sockaddr_un));
		server.sun_family = AF_UNIX;
		strncpy(server.sun_path, localSocket, sizeof(server.sun_path));

		if(connect(privdata->cmdSocket, (struct sockaddr *)&server, sizeof(struct sockaddr_un)) < 0) {
			perror(localSocket);
			clamfi_cleanup(ctx);
			return cl_error;
		}
		if(send(privdata->cmdSocket, cmdbuf, nbytes, 0) < nbytes) {
			perror("send");
			clamfi_cleanup(ctx);
			if(use_syslog)
				syslog(LOG_ERR, _("failed to send SCAN command to clamd"));
			return cl_error;
		}

		shutdown(privdata->cmdSocket, SHUT_WR);
#endif
	}
#ifdef	SESSION
	else
		session = &sessions[privdata->serverNumber];
#endif

	if(external) {
		int nbytes;
#ifdef	SESSION
#ifdef	CL_DEBUG
		if(debug_level >= 4)
			cli_dbgmsg(_("Waiting to read status from fd %d\n"),
				session->sock);
#endif
		nbytes = clamd_recv(session->sock, mess, sizeof(mess) - 1);
#else
		nbytes = clamd_recv(privdata->cmdSocket, mess, sizeof(mess) - 1);
#endif
		if(nbytes > 0) {
			mess[nbytes] = '\0';
			if((ptr = strchr(mess, '\n')) != NULL)
				*ptr = '\0';

			if(logVerbose)
				syslog(LOG_DEBUG, _("clamfi_eom: read %s"), mess);
			cli_dbgmsg(_("clamfi_eom: read %s\n"), mess);
		} else {
#ifdef	MAXHOSTNAMELEN
			char hostname[MAXHOSTNAMELEN + 1];

			cli_strtokbuf(serverHostNames, privdata->serverNumber, ":", hostname);
			if(strcmp(hostname, "127.0.0.1") == 0)
				gethostname(hostname, sizeof(hostname));
#else
			char *hostname = cli_strtok(serverHostNames, privdata->serverNumber, ":");
#endif
			/*
			 * TODO: if more than one host has been specified, try
			 * another one - setting cl_error to SMFIS_TEMPFAIL
			 * helps by forcing a retry
			 */
			clamfi_cleanup(ctx);
			syslog(LOG_NOTICE, _("clamfi_eom: read nothing from clamd on %s"), hostname);
#ifdef	CL_DEBUG
			cli_dbgmsg(_("clamfi_eom: read nothing from clamd on %s\n"), hostname);
#endif
#ifdef	SESSION
			pthread_mutex_lock(&sstatus_mutex);
			session->status = CMDSOCKET_DOWN;
			pthread_mutex_unlock(&sstatus_mutex);
#endif
			return cl_error;
		}

#ifdef	SESSION
		pthread_mutex_lock(&sstatus_mutex);
		if(session->status == CMDSOCKET_INUSE)
			session->status = CMDSOCKET_FREE;
		pthread_mutex_unlock(&sstatus_mutex);
#else
		close(privdata->cmdSocket);
		privdata->cmdSocket = -1;
#endif
	}

	sendmailId = smfi_getsymval(ctx, "i");
	if(sendmailId == NULL)
		sendmailId = "Unknown";

	if(!nflag) {
		char buf[1024];

		/*
		 * Include the hostname where the scan took place
		 */
		if(localSocket || !external) {
#ifdef	MAXHOSTNAMELEN
			char hostname[MAXHOSTNAMELEN + 1];
#else
			char hostname[65];
#endif

			if(gethostname(hostname, sizeof(hostname)) < 0) {
				const char *j = smfi_getsymval(ctx, "{j}");

				if(j)
					strncpy(hostname, j,
						sizeof(hostname) - 1);
				else
					strcpy(hostname, _("Error determining host"));
			} else if(strchr(hostname, '.') == NULL) {
				/*
				 * Determine fully qualified name
				 */
				struct hostent hostent;

				if(clamfi_gethostbyname(hostname, &hostent, buf, sizeof(buf)) == 0)
					strncpy(hostname, hostent.h_name, sizeof(hostname));
			}

#ifdef	SESSION
			pthread_mutex_lock(&version_mutex);
			snprintf(buf, sizeof(buf) - 1, "%s on %s",
				clamav_versions[privdata->serverNumber], hostname);
			pthread_mutex_unlock(&version_mutex);
#else
			snprintf(buf, sizeof(buf) - 1, "%s on %s",
				clamav_version, hostname);
#endif
		} else {
#ifdef	MAXHOSTNAMELEN
			char hostname[MAXHOSTNAMELEN + 1];

			if(cli_strtokbuf(serverHostNames, privdata->serverNumber, ":", hostname)) {
				if(strcmp(hostname, "127.0.0.1") == 0)
					gethostname(hostname, sizeof(hostname));
#else
			char *hostname = cli_strtok(serverHostNames, privdata->serverNumber, ":");
			if(hostname) {
#endif

#ifdef	SESSION
				pthread_mutex_lock(&version_mutex);
				snprintf(buf, sizeof(buf) - 1, "%s on %s",
					clamav_versions[privdata->serverNumber], hostname);
				pthread_mutex_unlock(&version_mutex);
#else
				snprintf(buf, sizeof(buf) - 1, "%s on %s",
					clamav_version, hostname);
#endif
#ifndef	MAXHOSTNAMELEN
				free(hostname);
#endif
			} else
				/* sanity check failed - should issue warning */
				strcpy(buf, _("Error determining host"));
		}
		smfi_addheader(ctx, "X-Virus-Scanned", buf);
	}

	if(strstr(mess, "ERROR") != NULL) {
		if(strstr(mess, "Size limit reached") != NULL) {
			/*
			 * Clamd has stopped on StreamMaxLength before us
			 */
			if(use_syslog)
				syslog(LOG_NOTICE, _("%s: Message more than StreamMaxLength (%ld) bytes - not scanned"),
					sendmailId, streamMaxLength);
			if(!nflag)
				smfi_addheader(ctx, "X-Virus-Status", _("Not Scanned - StreamMaxLength exceeded"));
			clamfi_cleanup(ctx);	/* not needed, but just to be safe */
			return SMFIS_ACCEPT;
		}
		if(!nflag)
			smfi_addheader(ctx, "X-Virus-Status", _("Not Scanned"));

		cli_warnmsg("%s: %s\n", sendmailId, mess);
		if(use_syslog)
			syslog(LOG_ERR, "%s: %s\n", sendmailId, mess);
		rc = cl_error;
	} else if((ptr = strstr(mess, "FOUND")) != NULL) {
		/*
		 * Fixme: This will give false positives if the
		 *	word "FOUND" is in the email, e.g. the
		 *	quarantine directory is /tmp/VIRUSES-FOUND
		 */
		char reject[1024];
		char **to, *virusname;

		/*
		 Remove the "FOUND" word, and the space before it
		 */
		*--ptr = '\0';

		/* skip over 'stream/filename: ' at the start */
		if((virusname = strchr(mess, ':')) != NULL)
			virusname = &virusname[2];
		else
			virusname = mess;

		if(!nflag) {
			char buf[129];

			snprintf(buf, sizeof(buf) - 1, "%s %s", _("Infected with"), virusname);
			smfi_addheader(ctx, "X-Virus-Status", buf);
		}

		if(quarantine_dir)
			qfile(privdata, sendmailId, virusname);

		if(use_syslog) {
			/*
			 * Setup err as a list of recipients
			 */
			char *err = (char *)cli_malloc(1024);
			int i;

			if(err == NULL) {
				clamfi_cleanup(ctx);
				return cl_error;
			}

			/*
			 * Use snprintf rather than printf since we don't know
			 * the length of privdata->from and may get a buffer
			 * overrun
			 */
			snprintf(err, 1023, _("Intercepted virus from %s to"),
				privdata->from);

			ptr = strchr(err, '\0');

			i = 1024;

			for(to = privdata->to; *to; to++) {
				/*
				 * Re-alloc if we are about run out of buffer space
				 */
				if(&ptr[strlen(*to) + 2] >= &err[i]) {
					i += 1024;
					err = cli_realloc(err, i);
					if(err == NULL) {
						clamfi_cleanup(ctx);
						return cl_error;
					}
					ptr = strchr(err, '\0');
				}
				ptr = strrcpy(ptr, " ");
				ptr = strrcpy(ptr, *to);
			}
			(void)strcpy(ptr, "\n");

			/* Include the sendmail queue ID in the log */
			syslog(LOG_NOTICE, "%s: %s %s", sendmailId, mess, err);
#ifdef	CL_DEBUG
			cli_dbgmsg("%s", err);
#endif
			free(err);
		}

		if(!qflag) {
			char cmd[128];
			FILE *sendmail;

			/*
			 * If the oflag is given this sendmail command
			 * will cause the mail being generated here to be
			 * scanned. So if oflag is given we just put the
			 * item in the queue so there's no scanning of two
			 * messages at once. It'll still be scanned, but
			 * not at the same time as the incoming message
			 *
			 * FIXME: there is a race condition here when sendmail
			 * and clamav-milter run on the same machine. If the
			 * system is very overloaded this sendmail can
			 * take a long time to start - and may even fail
			 * is the LA is > REFUSE_LA. In all the time we're
			 * taking to start this sendmail, the sendmail that's
			 * started us may timeout waiting for a response and
			 * let the virus through (albeit tagged with
			 * X-Virus-Status: Infected) because we haven't
			 * sent SMFIS_DISCARD or SMFIS_REJECT
			 *
			 * -i flag, suggested by Michal Jaegermann
			 *	<michal@harddata.com>
			 */
			snprintf(cmd, sizeof(cmd) - 1,
				(oflag || fflag) ? "%s -t -i -odq" : "%s -t -i",
				SENDMAIL_BIN);

			cli_dbgmsg("Calling %s\n", cmd);
			sendmail = popen(cmd, "w");

			if(sendmail) {
				if(from && from[0])
					fprintf(sendmail, "From: %s\n", from);
				else
					fprintf(sendmail, "From: %s\n", privdata->from);
				if(bflag && privdata->from) {
					fprintf(sendmail, "To: %s\n", privdata->from);
					fprintf(sendmail, "Cc: %s\n", postmaster);
				} else
					fprintf(sendmail, "To: %s\n", postmaster);

				if((!pflag) && privdata->to)
					for(to = privdata->to; *to; to++)
						fprintf(sendmail, "Cc: %s\n", *to);
				/*
				 * Auto-submitted is still a draft, keep an
				 * eye on its format
				 */
				fputs("Auto-Submitted: auto-submitted (antivirus notify)\n", sendmail);
				/* "Sergey Y. Afonin" <asy@kraft-s.ru> */
				if((ptr = smfi_getsymval(ctx, "{_}")) != NULL)
					fprintf(sendmail,
						"X-Infected-Received-From: %s\n",
						ptr);
				fputs(_("Subject: Virus intercepted\n\n"), sendmail);

				if((templatefile == NULL) ||
				   (sendtemplate(ctx, templatefile, sendmail, virusname) < 0)) {
					/*
					 * Use our own hardcoded template
					 */
					if(bflag)
						fputs(_("A message you sent to\n"), sendmail);
					else if(pflag)
						/*
						 * The message is only going to
						 * the postmaster, so include
						 * some useful information
						 */
						fprintf(sendmail, _("The message %1$s sent from %2$s to\n"),
							sendmailId, privdata->from);
					else
						fprintf(sendmail, _("A message sent from %s to\n"),
							privdata->from);

					for(to = privdata->to; *to; to++)
						fprintf(sendmail, "\t%s\n", *to);
					fprintf(sendmail, _("contained %s and has not been delivered.\n"), virusname);

					if(quarantine_dir != NULL)
						fprintf(sendmail, _("\nThe message in question has been quarantined as %s\n"), privdata->filename);

					if(hflag) {
						fprintf(sendmail, _("\nThe message was received by %1$s from %2$s via %3$s\n\n"),
							smfi_getsymval(ctx, "j"), privdata->from,
							smfi_getsymval(ctx, "_"));
						fputs(_("For your information, the original message headers were:\n\n"), sendmail);
						header_list_print(privdata->headers, sendmail);
					} else if(privdata->received)
						/*
						 * TODO: parse this to find
						 * real infected machine.
						 * Need to decide how to find
						 * if it's a dynamic IP from a
						 * dial up account in which
						 * case there may not be much
						 * we can do if that DHCP has
						 * set the hostname...
						 */
						fprintf(sendmail, _("\nThe infected machine is likely to be here:\n%s\t\n"),
							privdata->received);

				}

				cli_dbgmsg("Waiting for %s to finish\n", cmd);
				if(pclose(sendmail) != 0)
					if(use_syslog)
						syslog(LOG_ERR, "%s: Failed to notify clamAV interception - see dead.letter", sendmailId);
			} else if(use_syslog)
				syslog(LOG_WARNING, _("Can't execute '%s' to send virus notice"), cmd);
		}

		if(quarantine_dir) {
			/*
			 * Cleanup filename here otherwise clamfi_free() will
			 * delete the file that we wish to keep because it
			 * is infected
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
			/*
			 * NOTE: on a closed relay this will not work
			 * if the recipient is a remote address
			 */
			if(smfi_addrcpt(ctx, quarantine) == MI_FAILURE) {
				if(use_syslog)
					syslog(LOG_ERR, _("Can't set quarantine user %s"), quarantine);
				else
					cli_warnmsg(_("Can't set quarantine user %s\n"), quarantine);
				rc = (privdata->discard) ? SMFIS_DISCARD : SMFIS_REJECT;
			} else {
				if(use_syslog)
					syslog(LOG_DEBUG, "Redirected virus to %s", quarantine);
				cli_dbgmsg("Redirected virus to %s\n", quarantine);
				setsubject(ctx, virusname);
			}
		} else if(advisory)
			setsubject(ctx, virusname);
		else if(rejectmail) {
			if(privdata->discard)
				rc = SMFIS_DISCARD;
			else
				rc = SMFIS_REJECT;	/* Delete the e-mail */
		} else
			rc = SMFIS_DISCARD;

		/*
		 * Don't drop the message if it's been forwarded to a
		 * quarantine email
		 */
		snprintf(reject, sizeof(reject) - 1, _("virus %s detected by ClamAV - http://www.clamav.net"), virusname);
		smfi_setreply(ctx, (char *)privdata->rejectCode, "5.7.1", reject);
		broadcast(mess);
	} else if(strstr(mess, "OK") == NULL) {
		if(!nflag)
			smfi_addheader(ctx, "X-Virus-Status", _("Unknown"));
		if(use_syslog)
			syslog(LOG_ERR, _("%s: incorrect message \"%s\" from clamd"),
				sendmailId,
				mess);
		rc = cl_error;
	} else {
		if(!nflag)
			smfi_addheader(ctx, "X-Virus-Status", _("Clean"));

		if(use_syslog && logClean)
			/* Include the sendmail queue ID in the log */
			syslog(LOG_NOTICE, _("%s: clean message from %s"),
				sendmailId,
				(privdata->from) ? privdata->from : _("an unknown sender"));

		if(privdata->body) {
			/*
			 * Add a signature that all has been scanned OK
			 */
			off_t len = updateSigFile();

			if(len) {
				assert(Sflag != 0);

				privdata->body = cli_realloc(privdata->body, privdata->bodyLen + len);
				if(privdata->body) {
					memcpy(&privdata->body[privdata->bodyLen], signature, len);
					smfi_replacebody(ctx, privdata->body, privdata->bodyLen + len);
				}
			}
		}
	}
	clamfi_cleanup(ctx);

	return rc;
}

static sfsistat
clamfi_abort(SMFICTX *ctx)
{
#ifdef	CL_DEBUG
	if(logVerbose)
		syslog(LOG_DEBUG, "clamfi_abort");
#endif

	cli_dbgmsg("clamfi_abort\n");

	clamfi_cleanup(ctx);

	cli_dbgmsg("clamfi_abort returns\n");

	return cl_error;
}

static sfsistat
clamfi_close(SMFICTX *ctx)
{
	struct privdata *privdata = (struct privdata *)smfi_getpriv(ctx);

	cli_dbgmsg("clamfi_close\n");
	if(privdata != NULL)
		clamfi_cleanup(ctx);

	if(logVerbose)
		syslog(LOG_DEBUG, "clamfi_close");

	return SMFIS_CONTINUE;
}

static void
clamfi_cleanup(SMFICTX *ctx)
{
	struct privdata *privdata = (struct privdata *)smfi_getpriv(ctx);

	cli_dbgmsg("clamfi_cleanup\n");

	if(privdata) {
		clamfi_free(privdata);
		smfi_setpriv(ctx, NULL);
	}
}

static void
clamfi_free(struct privdata *privdata)
{
	cli_dbgmsg("clamfi_free\n");

	if(privdata) {
#ifdef	SESSION
		struct session *session;
#endif
		if(privdata->body)
			free(privdata->body);

		if(privdata->dataSocket >= 0) {
			close(privdata->dataSocket);
			privdata->dataSocket = -1;
		}

		if(privdata->filename != NULL) {
			/*
			 * Don't print an error if the file hasn't been
			 * created yet
			 */
			if((unlink(privdata->filename) < 0) && (errno != ENOENT)) {
				perror(privdata->filename);
				if(use_syslog)
					syslog(LOG_ERR,
						_("Can't remove clean file %s"),
						privdata->filename);
			}
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

		if(privdata->subject) {
			free(privdata->subject);
			privdata->subject = NULL;
		}
		if(privdata->sender) {
			free(privdata->sender);
			privdata->sender = NULL;
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

		if(external) {
#ifdef	SESSION
			session = &sessions[privdata->serverNumber];
			pthread_mutex_lock(&sstatus_mutex);
			if(session->status == CMDSOCKET_INUSE) {
				/*
				 * Probably we've got here because
				 * StreamMaxLength has been reached
				 */
#if	0
				pthread_mutex_unlock(&sstatus_mutex);
				if(readTimeout) {
					char buf[64];
					const int fd = session->sock;

					cli_dbgmsg("clamfi_free: flush server %d fd %d\n",
						privdata->serverNumber, fd);

					/*
					 * FIXME: whenever this code gets
					 *	executed, all of the PINGs fail
					 *	in the next watchdog cycle
					 */
					while(clamd_recv(fd, buf, sizeof(buf)) > 0)
						;
				}
				pthread_mutex_lock(&sstatus_mutex);
#endif
				/* Force a reset */
				session->status = CMDSOCKET_DOWN;
			}
			pthread_mutex_unlock(&sstatus_mutex);
#else
			if(privdata->cmdSocket >= 0) {
				char buf[64];

				/*
				 * Flush the remote end so that clamd doesn't
				 * get a SIGPIPE
				 */
				if(readTimeout)
					while(clamd_recv(privdata->cmdSocket, buf, sizeof(buf)) > 0)
						;
				close(privdata->cmdSocket);
				privdata->cmdSocket = -1;
			}
#endif
		} else if(privdata->root)
			/*
			 * Since only one of clamfi_abort() and clamfi_eom()
			 * can ever be called, and the only cl_dup is in
			 * clamfi_eom() which calls cl_free soon after, this
			 * should be overkill, since this can "never happen"
			 */
			cl_free(privdata->root);

		if(privdata->headers)
			header_list_free(privdata->headers);

#ifdef	CL_DEBUG
		if(debug_level >= 9)
			cli_dbgmsg("Free privdata\n");
#endif
		if(privdata->received)
			free(privdata->received);
		free(privdata);
	}

	if(max_children > 0) {
		pthread_mutex_lock(&n_children_mutex);
		cli_dbgmsg("clamfi_free: n_children = %d\n", n_children);
		/*
		 * Deliberately errs on the side of broadcasting too many times
		 */
		if(n_children > 0)
			if(--n_children == 0) {
				cli_dbgmsg("%s is idle\n", progname);
				if(pthread_cond_broadcast(&watchdog_cond) < 0)
					perror("pthread_cond_broadcast");
			}
#ifdef	CL_DEBUG
		cli_dbgmsg("pthread_cond_broadcast\n");
#endif
		if(pthread_cond_broadcast(&n_children_cond) < 0)
			perror("pthread_cond_broadcast");
		cli_dbgmsg("<n_children = %d\n", n_children);
		pthread_mutex_unlock(&n_children_mutex);
	}
	cli_dbgmsg("clamfi_free returns\n");
}

/*
 * Returns < 0 for failure, otherwise the number of bytes sent
 */
static int
clamfi_send(struct privdata *privdata, size_t len, const char *format, ...)
{
	char output[BUFSIZ];
	const char *ptr;
	int ret = 0;

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
		vsnprintf(output, sizeof(output) - 1, format, argp);
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
		const int nbytes = (privdata->filename) ?
			write(privdata->dataSocket, ptr, len) :
			send(privdata->dataSocket, ptr, len, 0);

		assert(privdata->dataSocket >= 0);

		if(nbytes == -1) {
			if(privdata->filename) {
				perror(privdata->filename);
				if(use_syslog) {
#ifdef HAVE_STRERROR_R
					char buf[32];
					strerror_r(errno, buf, sizeof(buf));
					syslog(LOG_ERR,
						_("write failure (%u bytes) to %s: %s"),
						len, privdata->filename, buf);
#else
					syslog(LOG_ERR, _("write failure (%u bytes) to %s: %s"),
						len, privdata->filename,
						strerror(errno));
#endif
				}
			} else {
				if(errno == EINTR)
					continue;
				perror("send");
				if(use_syslog) {
#ifdef HAVE_STRERROR_R
					char buf[32];
					strerror_r(errno, buf, sizeof(buf));
					syslog(LOG_ERR,
						_("write failure (%u bytes) to clamd: %s"),
						len, buf);
#else
					syslog(LOG_ERR, _("write failure (%u bytes) to clamd: %s"), len, strerror(errno));
#endif
				}
				checkClamd();
			}

			return -1;
		}
		ret += nbytes;
		len -= nbytes;
		ptr = &ptr[nbytes];

		if(streamMaxLength > 0L) {
			privdata->numBytes += nbytes;
			if(privdata->numBytes >= streamMaxLength)
				break;
		}
	}
	return ret;
}

/*
 * Like strcpy, but return the END of the destination, allowing a quicker
 * means of adding to the end of a string than strcat
 */
#if	0
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
#endif

/*
 * Read from clamav - timeout if necessary
 */
static int
clamd_recv(int sock, char *buf, size_t len)
{
	fd_set rfds;
	struct timeval tv;
	int ret;

	assert(sock >= 0);

	if(readTimeout == 0) {
		do
			ret = recv(sock, buf, len, 0);
		while((ret < 0) && (errno == EINTR));

		return ret;
	}

	FD_ZERO(&rfds);
	FD_SET(sock, &rfds);

	tv.tv_sec = readTimeout;
	tv.tv_usec = 0;

	for(;;) {
		switch(select(sock + 1, &rfds, NULL, NULL, &tv)) {
			case -1:
				if(errno == EINTR)
					/* FIXME: work out time left */
					continue;
				perror("select");
				return -1;
			case 0:
				if(use_syslog)
					syslog(LOG_ERR, _("No data received from clamd in %d seconds\n"), readTimeout);
				return 0;
		}
		break;
	}

	do
		ret = recv(sock, buf, len, 0);
	while((ret < 0) && (errno == EINTR));

	return ret;
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
		return 0;

	if(stat(sigFilename, &statb) < 0) {
		perror(sigFilename);
		if(use_syslog)
			syslog(LOG_ERR, _("Can't stat %s"), sigFilename);
		return 0;
	}

	if(statb.st_mtime <= signatureStamp)
		return statb.st_size;	/* not changed */

	fd = open(sigFilename, O_RDONLY);
	if(fd < 0) {
		perror(sigFilename);
		if(use_syslog)
			syslog(LOG_ERR, _("Can't open %s"), sigFilename);
		return 0;
	}

	signatureStamp = statb.st_mtime;

	signature = cli_realloc(signature, statb.st_size);
	if(signature)
		cli_readn(fd, signature, statb.st_size);
	close(fd);

	return statb.st_size;
}

static header_list_t
header_list_new(void)
{
	header_list_t ret;

	ret = (header_list_t)cli_malloc(sizeof(struct header_list_struct));
	if(ret) {
		ret->first = NULL;
		ret->last = NULL;
	}
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

	len = (size_t)(strlen(headerf) + strlen(headerv) + 3);

	header = (char *)cli_malloc(len);
	if(header == NULL)
		return;

	sprintf(header, "%s: %s", headerf, headerv);
	new_node = (struct header_node_t *)cli_malloc(sizeof(struct header_node_t));
	if(new_node == NULL) {
		free(header);
		return;
	}
	new_node->header = header;
	new_node->next = NULL;
	if(list->first == NULL)
		list->first = new_node;
	if(list->last)
		list->last->next = new_node;

	list->last = new_node;
}

static void
header_list_print(const header_list_t list, FILE *fp)
{
	const struct header_node_t *iter;

	if(list == NULL)
		return;

	for(iter = list->first; iter; iter = iter->next) {
		if(strncmp(iter->header, "From ", 5) == 0)
			putc('>', fp);
		fprintf(fp, "%s\n", iter->header);
	}
}

/*
 * Establish a connection to clamd
 *	Returns success (1) or failure (0)
 */
static int
connect2clamd(struct privdata *privdata)
{
	assert(privdata != NULL);
	assert(privdata->dataSocket == -1);
	assert(privdata->from != NULL);
	assert(privdata->to != NULL);

#ifdef	CL_DEBUG
	if((debug_level > 0) && use_syslog)
		syslog(LOG_DEBUG, "connect2clamd");
	if(debug_level >= 4)
		cli_dbgmsg("connect2clamd\n");
#endif

	if(quarantine_dir || tmpdir) {	/* store message in a temporary file */
		int ntries = 5;
		const char *dir = (tmpdir) ? tmpdir : quarantine_dir;

		/*
		 * TODO: investigate mkdtemp on LINUX and possibly others
		 */
#ifdef	C_AIX
		/*
		 * Patch by Andy Feldt <feldt@nhn.ou.edu>, AIX 5.2 sets errno
		 * to ENOENT often and sometimes sets errno to 0 (after a
		 * database reload) for the mkdir call
		 */
		if((mkdir(dir, 0700) < 0) && (errno != EEXIST) && (errno > 0) &&
		    (errno != ENOENT)) {
#else
		if((mkdir(dir, 0700) < 0) && (errno != EEXIST)) {
#endif
			perror(dir);
			if(use_syslog)
				syslog(LOG_ERR, _("mkdir %s failed"), dir);
			return 0;
		}
		privdata->filename = (char *)cli_malloc(strlen(dir) + 12);

		do {
			sprintf(privdata->filename, "%s/msg.XXXXXX", dir);
#if	defined(C_LINUX) || defined(C_BSD) || defined(HAVE_MKSTEMP) || defined(C_SOLARIS)
			privdata->dataSocket = mkstemp(privdata->filename);
#else
			if(mktemp(privdata->filename) == NULL) {
				if(use_syslog)
					syslog(LOG_ERR, _("mktemp %s failed"), privdata->filename);
				return 0;
			}
			privdata->dataSocket = open(privdata->filename, O_CREAT|O_EXCL|O_WRONLY|O_TRUNC, 0600);
#endif
		} while((--ntries > 0) && (privdata->dataSocket < 0));

		if(privdata->dataSocket < 0) {
			perror(privdata->filename);
			if(use_syslog)
				syslog(LOG_ERR, _("Temporary quarantine file %s creation failed"), privdata->filename);
			return 0;
		}
		privdata->serverNumber = 0;
		cli_dbgmsg("Saving message to %s to scan later\n", privdata->filename);
	} else {	/* communicate to clamd */
		int freeServer, nbytes;
		struct sockaddr_in reply;
		unsigned short p;
		char buf[64];

#ifdef	SESSION
		struct session *session;
#else
		assert(privdata->cmdSocket == -1);
#endif

		/*
		 * Create socket to talk to clamd. It will tell us the port to
		 * use to send the data. That will require another socket.
		 */
		if(localSocket) {
#ifndef	SESSION
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
			privdata->serverNumber = 0;
#endif
			freeServer = 0;
		} else {	/* TCP/IP */
#ifdef	SESSION
			freeServer = findServer();
			if(freeServer < 0)
				return 0;
			assert(freeServer < (int)max_children);
#else
			struct sockaddr_in server;

			memset((char *)&server, 0, sizeof(struct sockaddr_in));
			server.sin_family = AF_INET;
			server.sin_port = (in_port_t)htons(tcpSocket);

			assert(serverIPs != NULL);

			freeServer = findServer();
			if(freeServer < 0)
				return 0;
			assert(freeServer < (int)max_children);

			server.sin_addr.s_addr = serverIPs[freeServer];

			if((privdata->cmdSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
				perror("socket");
				return 0;
			}
			if(connect(privdata->cmdSocket, (struct sockaddr *)&server, sizeof(struct sockaddr_in)) < 0) {
				perror("connect");
				return 0;
			}
#endif
			privdata->serverNumber = freeServer;
		}

#ifdef	SESSION
		if(serverIPs[freeServer] == (int)inet_addr("127.0.0.1")) {
			privdata->filename = cli_gentemp(NULL);
			if(privdata->filename) {
				cli_dbgmsg("connect2clamd(%d): creating %s\n", freeServer, privdata->filename);
#ifdef	O_TEXT
				privdata->dataSocket = open(privdata->filename, O_WRONLY|O_CREAT|O_EXCL|O_TRUNC|O_TEXT, 0600);
#else
				privdata->dataSocket = open(privdata->filename, O_WRONLY|O_CREAT|O_EXCL|O_TRUNC, 0600);
#endif
				if(privdata->dataSocket < 0) {
					perror(privdata->filename);
					free(privdata->filename);
					privdata->filename = NULL;
				} else
					return sendToFrom(privdata);
			}
		}
		cli_dbgmsg("connect2clamd(%d): STREAM\n", freeServer);

		session = &sessions[freeServer];
		if((session->sock < 0) || (send(session->sock, "STREAM\n", 7, 0) < 7)) {
			perror("send");
			pthread_mutex_lock(&sstatus_mutex);
			session->status = CMDSOCKET_DOWN;
			pthread_mutex_unlock(&sstatus_mutex);
			cli_warnmsg("Failed sending stream to server %d (fd %d) errno %d\n",
				freeServer, session->sock, errno);
			if(use_syslog)
				syslog(LOG_ERR, _("failed to send STREAM command clamd server %d"),
					freeServer);

			return 0;
		}
#else
		if(send(privdata->cmdSocket, "STREAM\n", 7, 0) < 7) {
			perror("send");
			if(use_syslog)
				syslog(LOG_ERR, _("failed to send STREAM command clamd"));
			return 0;
		}
		shutdown(privdata->cmdSocket, SHUT_WR);
#endif

		/*
		 * Create socket that we'll use to send the data to clamd
		 */
		if((privdata->dataSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
			perror("socket");
			if(use_syslog)
				syslog(LOG_ERR, _("failed to create TCPSocket to talk to clamd"));
			return 0;
		}

		shutdown(privdata->dataSocket, SHUT_RD);

#ifdef	SESSION
		nbytes = clamd_recv(session->sock, buf, sizeof(buf));
		if(nbytes <= 0) {
			if(nbytes < 0) {
				perror("recv");
				if(use_syslog)
					syslog(LOG_ERR, _("recv failed from clamd getting PORT"));
				cli_warnmsg("Failed get PORT from server %d (fd %d) errno %d\n",
					freeServer, session->sock, errno);
			} else if(use_syslog)
				syslog(LOG_ERR, _("EOF from clamd getting PORT"));
			pthread_mutex_lock(&sstatus_mutex);
			session->status = CMDSOCKET_DOWN;
			pthread_mutex_unlock(&sstatus_mutex);
			return 0;
		}
#else
		nbytes = clamd_recv(privdata->cmdSocket, buf, sizeof(buf));
		if(nbytes <= 0) {
			if(nbytes < 0) {
				perror("recv");
				if(use_syslog)
					syslog(LOG_ERR, _("recv failed from clamd getting PORT"));
			} else if(use_syslog)
				syslog(LOG_ERR, _("EOF from clamd getting PORT"));
			return 0;
		}
#endif
		buf[nbytes] = '\0';
#ifdef	CL_DEBUG
		if(debug_level >= 4)
			cli_dbgmsg("Received: %s", buf);
#endif
		if(sscanf(buf, "PORT %hu\n", &p) != 1) {
			if(use_syslog)
				syslog(LOG_ERR, _("Expected port information from clamd, got '%s'"),
					buf);
			else
				cli_warnmsg(_("Expected port information from clamd, got '%s'\n"),
					buf);
#ifdef	SESSION
			session->status = CMDSOCKET_DOWN;
			pthread_mutex_unlock(&sstatus_mutex);
#endif
			return 0;
		}

		memset((char *)&reply, 0, sizeof(struct sockaddr_in));
		reply.sin_family = AF_INET;
		reply.sin_port = (in_port_t)htons(p);

		assert(serverIPs != NULL);

		reply.sin_addr.s_addr = serverIPs[freeServer];

#ifdef	CL_DEBUG
		if(debug_level >= 4)
#ifdef	SESSION
			cli_dbgmsg(_("Connecting to local port %d - data %d cmd %d\n"),
				p, privdata->dataSocket, session->sock);
#else
			cli_dbgmsg(_("Connecting to local port %d - data %d cmd %d\n"),
				p, privdata->dataSocket, privdata->cmdSocket);
#endif
#endif

		if(connect(privdata->dataSocket, (struct sockaddr *)&reply, sizeof(struct sockaddr_in)) < 0) {
			perror("connect");

			cli_dbgmsg("Failed to connect to port %d given by clamd",
				p);
			/* 0.4 - use better error message */
			if(use_syslog) {
#ifdef HAVE_STRERROR_R
				strerror_r(errno, buf, sizeof(buf));
				syslog(LOG_ERR,
					_("Failed to connect to port %d given by clamd: %s"),
					p, buf);
#else
				syslog(LOG_ERR, _("Failed to connect to port %d given by clamd: %s"), p, strerror(errno));
#endif
			}
#ifdef	SESSION
			pthread_mutex_lock(&sstatus_mutex);
			session->status = CMDSOCKET_DOWN;
			pthread_mutex_unlock(&sstatus_mutex);
#endif
			return 0;
		}
	}

	if(!sendToFrom(privdata))
		return 0;

	cli_dbgmsg("connect2clamd: serverNumber = %d\n", privdata->serverNumber);

	return 1;
}

/*
 * Combine the To and From into one clamfi_send to save bandwidth
 * when sending using TCP/IP to connect to a remote clamd, by band
 * width here I mean number of packets
 */
static int
sendToFrom(struct privdata *privdata)
{
	char **to;
	char *msg;
	int length;

	length = strlen(privdata->from) + 34;
	for(to = privdata->to; *to; to++)
		length += strlen(*to) + 5;

	msg = cli_malloc(length + 1);

	if(msg) {
		sprintf(msg, "Received: by clamav-milter\nFrom: %s\n",
			privdata->from);

		for(to = privdata->to; *to; to++) {
			char *eom = strchr(msg, '\0');

			sprintf(eom, "To: %s\n", *to);
		}
		if(clamfi_send(privdata, length, msg) != length) {
			free(msg);
			return 0;
		}
		free(msg);
	} else {
		clamfi_send(privdata, 0,
			"Received: by clamav-milter\nFrom: %s\n",
			privdata->from);

		for(to = privdata->to; *to; to++)
			if(clamfi_send(privdata, 0, "To: %s\n", *to) <= 0)
				return 0;
	}

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
		return;	/* PidFile directive missing from clamd.conf */

	fd = open(pidFile, O_RDONLY);
	if(fd < 0) {
		perror(pidFile);
		if(use_syslog)
			syslog(LOG_ERR, _("Can't open %s"), pidFile);
		return;
	}
	nbytes = read(fd, buf, sizeof(buf) - 1);
	if(nbytes < 0)
		perror(pidFile);
	else
		buf[nbytes] = '\0';
	close(fd);
	pid = atoi(buf);
	if((kill(pid, 0) < 0) && (errno == ESRCH)) {
		if(use_syslog)
			syslog(LOG_ERR, _("Clamd (pid %d) seems to have died"),
				pid);
		perror("clamd");
	}
}

/*
 * Send a templated message about an intercepted message. Very basic for
 * now, just to prove it works, will enhance the flexability later, only
 * supports %v and $sendmail_variables$ at present.
 *
 * TODO: more template features
 * TODO: allow filename to start with a '|' taken to mean the output of
 *	a program
 */
static int
sendtemplate(SMFICTX *ctx, const char *filename, FILE *sendmail, const char *virusname)
{
	FILE *fin = fopen(filename, "r");
	struct stat statb;
	char *buf, *ptr /* , *ptr2 */;
	struct privdata *privdata = (struct privdata *)smfi_getpriv(ctx);

	if(fin == NULL) {
		perror(filename);
		if(use_syslog)
			syslog(LOG_ERR, _("Can't open e-mail template file %s"),
				filename);
		return -1;
	}

	if(fstat(fileno(fin), &statb) < 0) {
		/* File disappeared in race condition? */
		perror(filename);
		if(use_syslog)
			syslog(LOG_ERR, _("Can't stat e-mail template file %s"),
				filename);
		fclose(fin);
		return -1;
	}
	buf = cli_malloc(statb.st_size + 1);
	if(buf == NULL) {
		fclose(fin);
		if(use_syslog)
			syslog(LOG_ERR, _("Out of memory"));
		return -1;
	}
	if(fread(buf, sizeof(char), statb.st_size, fin) != (size_t)statb.st_size) {
		perror(filename);
		if(use_syslog)
			syslog(LOG_ERR, _("Error reading e-mail template file %s"),
				filename);
		fclose(fin);
		return -1;
	}
	fclose(fin);
	buf[statb.st_size] = '\0';

	for(ptr = buf; *ptr; ptr++)
		switch(*ptr) {
			case '%': /* clamAV variable */
				switch(*++ptr) {
					case 'v':	/* virus name */
						fputs(virusname, sendmail);
						break;
					case '%':
						putc('%', sendmail);
						break;
					case 'h':	/* headers */
						if(privdata)
							header_list_print(privdata->headers, sendmail);
						break;
					case '\0':
						putc('%', sendmail);
						--ptr;
						continue;
					default:
						syslog(LOG_ERR,
							_("%s: Unknown clamAV variable \"%c\"\n"),
							filename, *ptr);
						break;
				}
				break;
			case '$': /* sendmail string */ {
				const char *val;
				char *end = strchr(++ptr, '$');

				if(end == NULL) {
					syslog(LOG_ERR,
						_("%s: Unterminated sendmail variable \"%s\"\n"),
							filename, ptr);
					continue;
				}
				*end = '\0';

				val = smfi_getsymval(ctx, ptr);
				if(val == NULL) {
					fputs(ptr, sendmail);
					if(use_syslog)
						syslog(LOG_ERR,
							_("%s: Unknown sendmail variable \"%s\"\n"),
							filename, ptr);
				} else
					fputs(val, sendmail);
				ptr = end;
				break;
			}
			case '\\':
				if(*++ptr == '\0') {
					--ptr;
					continue;
				}
				putc(*ptr, sendmail);
				break;
			default:
				putc(*ptr, sendmail);
		}

	free(buf);

	return 0;
}

/*
 * Keep the infected file in quarantine, return success (0) or failure
 */
static int
qfile(struct privdata *privdata, const char *sendmailId, const char *virusname)
{
	int MM, YY, DD;
	time_t t;
	size_t len;
	char *newname, *ptr;
	const struct tm *tm;

	assert(privdata != NULL);

	if((privdata->filename == NULL) || (virusname == NULL))
		return -1;

	cli_dbgmsg("qfile filename '%s' sendmailId '%s' virusname '%s'\n", privdata->filename, sendmailId, virusname);

	len = strlen(quarantine_dir);

	newname = cli_malloc(len + strlen(sendmailId) + strlen(virusname) + 10);

	if(newname == NULL)
		return -1;

	t = time((time_t *)0);
	tm = localtime(&t);
	MM = tm->tm_mon + 1;
	YY = tm->tm_year - 100;
	DD = tm->tm_mday;

	sprintf(newname, "%s/%02d%02d%02d", quarantine_dir, YY, MM, DD);
#ifdef	C_AIX
	if((mkdir(newname, 0700) < 0) && (errno != EEXIST) && (errno > 0) &&
	    (errno != ENOENT)) {
#else
	if((mkdir(newname, 0700) < 0) && (errno != EEXIST)) {
#endif
		perror(newname);
		if(use_syslog)
			syslog(LOG_ERR, _("mkdir %s failed"), newname);
		return -1;
	}
	sprintf(newname, "%s/%02d%02d%02d/%s.%s",
		quarantine_dir, YY, MM, DD, sendmailId, virusname);

	/*
	 * Strip out funnies that may be in the name of the virus, such as '/'
	 * that would cause the quarantine to fail to save since the name
	 * of the virus is included in the filename
	 */
	for(ptr = &newname[len + 8]; *ptr; ptr++) {
#ifdef	C_DARWIN
		*ptr &= '\177';
#endif
#if	defined(MSDOS) || defined(C_CYGWIN) || defined(WIN32) || defined(C_OS2)
		if(strchr("/*?<>|\\\"+=,;:\t ", *ptr))
#else
		if(*ptr == '/')
#endif
			*ptr = '_';
	}
	cli_dbgmsg("qfile move '%s' to '%s'\n", privdata->filename, newname);

	if(move(privdata->filename, newname) < 0) {
		if(use_syslog)
			syslog(LOG_WARNING, _("Can't rename %1$s to %2$s"),
				privdata->filename, newname);
		free(newname);
		return -1;
	}
	free(privdata->filename);
	privdata->filename = newname;

	if(use_syslog)
		syslog(LOG_INFO, _("Email quarantined as %s"), newname);

	return 0;
}

/*
 * Move oldfile to newfile using the fastest possible method
 */
static int
move(const char *oldfile, const char *newfile)
{
	int ret;
#ifdef	C_LINUX
	struct stat statb;
	int fin, fout, c;
	off_t offset;
	FILE *fsin, *fsout;
#else
	FILE *fin, *fout;
	int c;
#endif

	ret = rename(oldfile, newfile);
	if(ret >= 0)
		return 0;

	if((ret < 0) && (errno != EXDEV)) {
		perror(newfile);
		return -1;
	}

#ifdef	C_LINUX	/* >= 2.2 */
	fin = open(oldfile, O_RDONLY);
	if(fin < 0) {
		perror(oldfile);
		return -1;
	}

	if(fstat(fin, &statb) < 0) {
		perror(oldfile);
		close(fin);
		return -1;
	}
	fout = open(newfile, O_WRONLY|O_CREAT, 0600);
	if(fout < 0) {
		perror(newfile);
		close(fin);
		return -1;
	}
	offset = (off_t)0;
	ret = sendfile(fout, fin, &offset, statb.st_size);
	close(fin);
	if(ret < 0) {
		/* fall back if sendfile fails, which shouldn't happen */
		perror(newfile);
		close(fout);
		unlink(newfile);

		fsin = fopen(oldfile, "r");
		if(fsin == NULL)
			return -1;

		fsout = fopen(newfile, "w");
		if(fsout == NULL) {
			fclose(fsin);
			return -1;
		}
		while((c = getc(fsin)) != EOF)
			putc(c, fsout);

		fclose(fsin);
		fclose(fsout);
	} else
		close(fout);
#else
	fin = fopen(oldfile, "r");
	if(fin == NULL)
		return -1;

	fout = fopen(newfile, "w");
	if(fout == NULL) {
		fclose(fin);
		return -1;
	}
	while((c = getc(fin)) != EOF)
		putc(c, fout);

	fclose(fin);
	fclose(fout);
#endif

	cli_dbgmsg("removing %s\n", oldfile);

	return unlink(oldfile);
}

/*
 * Store the name of the virus in the subject of the e-mail
 */
static void
setsubject(SMFICTX *ctx, const char *virusname)
{
	struct privdata *privdata = (struct privdata *)smfi_getpriv(ctx);
	char subject[128];

	if(privdata->subject)
		smfi_addheader(ctx, "X-Original-Subject", privdata->subject);

	snprintf(subject, sizeof(subject) - 1, _("[Virus] %s"), virusname);
	if(privdata->subject)
		smfi_chgheader(ctx, "Subject", 1, subject);
	else
		smfi_addheader(ctx, "Subject", subject);
}

/*
 * TODO: gethostbyname_r is non-standard so different operating
 * systems do it in different ways. Need more examples
 * Perhaps we could use res_search()?
 *
 * Returns 0 for success
 */
static int
clamfi_gethostbyname(const char *hostname, struct hostent *hp, char *buf, size_t len)
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
	/* Single thread the code */
	struct hostent *hp2;
	static pthread_mutex_t hostent_mutex = PTHREAD_MUTEX_INITIALIZER;

	if((hostname == NULL) || (hp == NULL))
		return -1;

	pthread_mutex_lock(&hostent_mutex);
	if((hp2 = gethostbyname(hostname)) == NULL) {
		pthread_mutex_unlock(&hostent_mutex);
		return h_errno;
	}
	memcpy(hp, hp2, sizeof(struct hostent));
	pthread_mutex_unlock(&hostent_mutex);
#endif

	return 0;
}

/*
 * David Champion <dgc@uchicago.edu>
 *
 * Check whether addr is on network by applying netmasks.
 * addr must be a 32-bit integer-packed IPv4 address in network order.
 * For example:
 *	struct in_addr IPAddress;
 *	isLocal = isLocalAddr(IPAddress.s_addr);
 */
static int
isLocalAddr(in_addr_t addr)
{
	const struct cidr_net *net;

	for(net = localNets; net->base; net++)
		if(htonl(net->base & net->mask) == (addr & htonl(net->mask)))
			return 1;

	return 0;	/* is non-local */
}

/*
 * Can't connect to any clamd server. This is serious, we need to inform
 * someone. In the absence of SNMP the best way is by e-mail. We
 * don't want to flood so there's a need to restrict to
 * no more than say one message every 15 minutes
 */
static void
clamdIsDown(void)
{
	static time_t lasttime;
	time_t thistime, diff;
	static pthread_mutex_t time_mutex = PTHREAD_MUTEX_INITIALIZER;

	cli_errmsg(_("No response from any clamd server - your AV system is not scanning emails\n"));

	if(use_syslog)
		syslog(LOG_ERR, _("No response from any clamd server - your AV system is not scanning emails"));

	time(&thistime);
	pthread_mutex_lock(&time_mutex);
	diff = thistime - lasttime;
	pthread_mutex_unlock(&time_mutex);

	if(diff >= (time_t)(15 * 60)) {
		char cmd[128];
		FILE *sendmail;

		snprintf(cmd, sizeof(cmd) - 1, "%s -t -i", SENDMAIL_BIN);

		sendmail = popen(cmd, "w");

		if(sendmail) {
			fprintf(sendmail, "To: %s\n", postmaster);
			fprintf(sendmail, "From: %s\n", postmaster);
			fputs(_("Subject: ClamAV Down\n"), sendmail);
			fputs("Priority: High\n\n", sendmail);

			fputs(_("This is an automatic message\n\n"), sendmail);

			if(numServers == 1)
				fputs(_("The clamd program cannot be contacted.\n"), sendmail);
			else
				fputs(_("No clamd server can be contacted.\n"), sendmail);

			fputs(_("Emails may not be being scanned, please check your servers.\n"), sendmail);

			if(pclose(sendmail) == 0) {
				pthread_mutex_lock(&time_mutex);
				time(&lasttime);
				pthread_mutex_unlock(&time_mutex);
			}
		}
	}
}

#ifdef	SESSION
/*
 * Thread to monitor the links to clamd sessions. Any marked as being in
 * an error state because of previous I/O errors are restarted, and a heartbeat
 * is sent the others
 *
 * It is woken up when the milter goes idle, when there are no free servers
 * available and once every readTimeout-1 seconds
 *
 * TODO: reload the whiteList file if it's been changed
 *
 * TODO: localSocket support
 */
static void *
watchdog(void *a)
{
	static pthread_mutex_t watchdog_mutex = PTHREAD_MUTEX_INITIALIZER;

	assert((!external) || (sessions != NULL));

	while(!quitting) {
		unsigned int i;
		struct timespec ts;
		struct timeval tp;
		struct session *session;

		gettimeofday(&tp, NULL);

		ts.tv_sec = tp.tv_sec + readTimeout - 1;
		ts.tv_nsec = tp.tv_usec * 1000;
		cli_dbgmsg("watchdog sleeps\n");
		pthread_mutex_lock(&watchdog_mutex);
		/*
		 * Sometimes this returns EPIPE which isn't listed as a
		 * return value in the Linux man page for pthread_cond_timedwait
		 * so I'm not sure why it happens
		 */
		switch(pthread_cond_timedwait(&watchdog_cond, &watchdog_mutex, &ts)) {
			case ETIMEDOUT:
			case 0:
				break;
			default:
				perror("pthread_cond_timedwait");
		}
		cli_dbgmsg("watchdog wakes\n");
		pthread_mutex_unlock(&watchdog_mutex);

		if(!external) {
			/*
			 * Re-load the database if needed
			 */
			switch(cl_statchkdir(&dbstat)) {
				case 1:
					cli_dbgmsg("Database has changed\n");
					cl_statfree(&dbstat);
					if(use_syslog)
						syslog(LOG_WARNING, _("Loading new database"));
					if(loadDatabase() != 0) {
						smfi_stop();
						cli_errmsg("Failed to load updated database\n");
						return NULL;
					}
					break;
				case 0:
					cli_dbgmsg("Database has not changed\n");
					break;
				default:
					smfi_stop();
					cli_errmsg("Database error - %s is stopping\n", progname);
					return NULL;
			}
			continue;
		}
		i = 0;
		session = sessions;
		pthread_mutex_lock(&sstatus_mutex);
		for(; i < max_children; i++, session++) {
			const int sock = session->sock;

			/*
			 * Check all free sessions are still usable
			 * This could take some time with many free
			 * sessions to slow remote servers, so only do this
			 * when the system is quiet (not 100% accurate when
			 * determining this since n_children isn't locked but
			 * that doesn't really matter)
			 */
			cli_dbgmsg("watchdog: check server %d\n", i);
			if((n_children == 0) &&
			   (session->status == CMDSOCKET_FREE) &&
			   (clamav_versions != NULL)) {
				if(send(sock, "VERSION\n", 8, 0) == 8) {
					char buf[81];
					const int nbytes = clamd_recv(sock, buf, sizeof(buf) - 1);

					if(nbytes <= 0)
						session->status = CMDSOCKET_DOWN;
					else {
						buf[nbytes] = '\0';
						if(strncmp(buf, "ClamAV ", 7) == 0) {
							/* Remove the trailing new line from the reply */
							char *ptr;

							if((ptr = strchr(buf, '\n')) != NULL)
								*ptr = '\0';
							pthread_mutex_lock(&version_mutex);
							if(clamav_versions[i] == NULL)
								clamav_versions[i] = strdup(buf);
							else if(strcmp(buf, clamav_versions[i]) != 0) {
								if(use_syslog)
									syslog(LOG_INFO, "New version received for server %d: '%s'\n", i, buf);
								free(clamav_versions[i]);
								clamav_versions[i] = strdup(buf);
							}
							pthread_mutex_unlock(&version_mutex);
						} else {
							cli_warnmsg("watchdog: expected \"ClamAV\", got \"%s\"\n", buf);
							session->status = CMDSOCKET_DOWN;
						}
					}
				} else {
					perror("send");
					session->status = CMDSOCKET_DOWN;
				}

				if(session->status == CMDSOCKET_DOWN)
					cli_warnmsg("Session %d has gone down\n", i);
			}
			/*
			 * Reset all all dead sessions
			 */
			if(session->status == CMDSOCKET_DOWN) {
				/*
				 * The END command probably won't get through,
				 * but let's give it a go anyway
				 */
				if(sock >= 0) {
					send(sock, "END\n", 4, 0);
					close(sock);
				}

				cli_dbgmsg("Trying to restart session %d\n", i);
				if(createSession(i) == 0) {
					session->status = CMDSOCKET_FREE;
					cli_warnmsg("Session %d restarted OK\n", i);
				}
			}
		}
		for(i = 0; i < max_children; i++)
			if(sessions[i].status != CMDSOCKET_DOWN)
				break;

		if(i == max_children)
			clamdIsDown();
		pthread_mutex_unlock(&sstatus_mutex);
	}
	cli_dbgmsg("watchdog quits\n");
	return NULL;
}
#else	/*!SESSION*/
/*
 * Reload the database from time to time, when using the internal scanner
 *
 * TODO: reload the whiteList file if it's been changed
 */
/*ARGSUSED*/
static void *
watchdog(void *a)
{
	static pthread_mutex_t watchdog_mutex = PTHREAD_MUTEX_INITIALIZER;

	if(external)
		return NULL;

	while(!quitting) {
		struct timespec ts;
		struct timeval tp;

		gettimeofday(&tp, NULL);

		ts.tv_sec = tp.tv_sec + readTimeout - 1;
		ts.tv_nsec = tp.tv_usec * 1000;
		cli_dbgmsg("watchdog sleeps\n");
		pthread_mutex_lock(&watchdog_mutex);
		/*
		 * Sometimes this returns EPIPE which isn't listed as a
		 * return value in the Linux man page for pthread_cond_timedwait
		 * so I'm not sure why it happens
		 */
		switch(pthread_cond_timedwait(&watchdog_cond, &watchdog_mutex, &ts)) {
			case ETIMEDOUT:
			case 0:
				break;
			default:
				perror("pthread_cond_timedwait");
		}
		cli_dbgmsg("watchdog wakes\n");
		pthread_mutex_unlock(&watchdog_mutex);

		/*
		 * Re-load the database.
 		 * TODO: sanity check that if n_children == 0, that
 		 * root->refcount == 0. Unfortunatly root->refcount isn't
 		 * thread-safe, since it's governed by a mutex that we can't
 		 * see, and there's no access to it via an approved method
 		 */
		switch(cl_statchkdir(&dbstat)) {
			case 1:
				cli_dbgmsg("Database has changed\n");
				cl_statfree(&dbstat);
				if(use_syslog)
					syslog(LOG_WARNING, _("Loading new database"));
				if(loadDatabase() != 0) {
					smfi_stop();
					cli_errmsg("Failed to load updated database\n");
					return NULL;
				}
				break;
			case 0:
				cli_dbgmsg("Database has not changed\n");
				break;
			default:
				smfi_stop();
				cli_errmsg("Database error - %s is stopping\n", progname);
				return NULL;
		}
	}
	cli_dbgmsg("watchdog quits\n");
	return NULL;
}
#endif

static const struct {
	const char *name;
	int code;
} facilitymap[] = {
#ifdef LOG_AUTH
	{ "LOG_AUTH",	LOG_AUTH },
#endif
#ifdef LOG_AUTHPRIV
	{ "LOG_AUTHPRIV",	LOG_AUTHPRIV },
#endif
#ifdef LOG_CRON
	{ "LOG_CRON",	LOG_CRON },
#endif
#ifdef LOG_DAEMON
	{ "LOG_DAEMON",	LOG_DAEMON },
#endif
#ifdef LOG_FTP
	{ "LOG_FTP",	LOG_FTP },
#endif
#ifdef LOG_KERN
	{ "LOG_KERN",	LOG_KERN },
#endif
#ifdef LOG_LPR
	{ "LOG_LPR",	LOG_LPR },
#endif
#ifdef LOG_MAIL
	{ "LOG_MAIL",	LOG_MAIL },
#endif
#ifdef LOG_NEWS
	{ "LOG_NEWS",	LOG_NEWS },
#endif
#ifdef LOG_AUTH
	{ "LOG_AUTH",	LOG_AUTH },
#endif
#ifdef LOG_SYSLOG
	{ "LOG_SYSLOG",	LOG_SYSLOG },
#endif
#ifdef LOG_USER
	{ "LOG_USER",	LOG_USER },
#endif
#ifdef LOG_UUCP
	{ "LOG_UUCP",	LOG_UUCP },
#endif
#ifdef LOG_LOCAL0
	{ "LOG_LOCAL0",	LOG_LOCAL0 },
#endif
#ifdef LOG_LOCAL1
	{ "LOG_LOCAL1",	LOG_LOCAL1 },
#endif
#ifdef LOG_LOCAL2
	{ "LOG_LOCAL2",	LOG_LOCAL2 },
#endif
#ifdef LOG_LOCAL3
	{ "LOG_LOCAL3",	LOG_LOCAL3 },
#endif
#ifdef LOG_LOCAL4
	{ "LOG_LOCAL4",	LOG_LOCAL4 },
#endif
#ifdef LOG_LOCAL5
	{ "LOG_LOCAL5",	LOG_LOCAL5 },
#endif
#ifdef LOG_LOCAL6
	{ "LOG_LOCAL6",	LOG_LOCAL6 },
#endif
#ifdef LOG_LOCAL7
	{ "LOG_LOCAL7",	LOG_LOCAL7 },
#endif
	{ NULL,		-1 }
};

static int
logg_facility(const char *name)
{
	int i;

	for(i = 0; facilitymap[i].name; i++)
		if(strcasecmp(facilitymap[i].name, name) == 0)
			return facilitymap[i].code;

	return -1;
}

static void
quit(void)
{
	extern short cli_leavetemps_flag;

	quitting++;

#ifdef	SESSION
	pthread_mutex_lock(&version_mutex);
#endif
	if(use_syslog)
		syslog(LOG_INFO, _("Stopping %s"), clamav_version);
#ifdef	SESSION
	pthread_mutex_unlock(&version_mutex);
#endif

	if(!external) {
		pthread_mutex_lock(&root_mutex);
		if(root) {
			cl_free(root);
			root = NULL;
		}
		pthread_mutex_unlock(&root_mutex);
	} else {
#ifdef	SESSION
		int i = 0;
		struct session *session = sessions;

		pthread_mutex_lock(&sstatus_mutex);
		for(; i < ((localSocket != NULL) ? 1 : (int)max_children); i++) {
			/*
			 * Check all free sessions are still usable
			 * This could take some time with many free
			 * sessions to slow remote servers, so only do this
			 * when the system is quiet (not 100% accurate when
			 * determining this since n_children isn't locked but
			 * that doesn't really matter)
			 */
			cli_dbgmsg("quit: close server %d\n", i);
			if(session->status == CMDSOCKET_FREE) {
				const int sock = session->sock;

				send(sock, "END\n", 4, 0);
				shutdown(sock, SHUT_WR);
				session->status = CMDSOCKET_DOWN;
				pthread_mutex_unlock(&sstatus_mutex);
				close(sock);
				pthread_mutex_lock(&sstatus_mutex);
			}
			session++;
		}
		pthread_mutex_unlock(&sstatus_mutex);
#endif
	}

	if(tmpdir && !cli_leavetemps_flag)
		if(rmdir(tmpdir) < 0)
			perror(tmpdir);

	broadcast(_("Stopping clamav-milter"));

	if(pidfile)
		if(unlink(pidfile) < 0)
			perror(pidfile);

	if(use_syslog)
		closelog();
}

static void
broadcast(const char *mess)
{
	struct sockaddr_in s;

	if(broadcastSock < 0)
		return;

	memset(&s, '\0', sizeof(struct sockaddr_in));
	s.sin_family = AF_INET;
	s.sin_port = (in_port_t)htons(tcpSocket ? tcpSocket : 3310);
	s.sin_addr.s_addr = htonl(INADDR_BROADCAST);

	cli_dbgmsg("broadcast %s to %d\n", mess, broadcastSock);
	if(sendto(broadcastSock, mess, strlen(mess), 0, (struct sockaddr *)&s, sizeof(struct sockaddr_in)) < 0)
		perror("sendto");
}

/*
 * Load a new database into the internal scanner
 */
static int
loadDatabase(void)
{
	extern const char *cl_retdbdir(void);	/* FIXME: should be included */
	int ret, v;
	unsigned int signatures;
	time_t t;
	char *daily, *ptr;
	struct cl_cvd *d;
	const struct cfgstruct *cpt;
	struct cl_node *newroot, *oldroot;
	static const char *dbdir;

	assert(!external);

	if(dbdir == NULL) {
		/*
		 * First time through, find out in which directory the signature
		 * databases are
		 */
		if((cpt = cfgopt(copt, "DatabaseDirectory")) || (cpt = cfgopt(copt, "DataDirectory")))
			dbdir = cpt->strarg;
		else
			dbdir = cl_retdbdir();
	}

	daily = cli_malloc(strlen(dbdir) + 11);
	sprintf(daily, "%s/daily.cvd", dbdir);

	cli_dbgmsg("loadDatabase: check %s for updates\n", daily);

	d = cl_cvdhead(daily);

	if(d == NULL) {
		cli_errmsg("Can't find %s\n", daily);
		free(daily);
		return -1;
	}

	t = d->stime;
	v = d->version;

	cl_cvdfree(d);
	free(daily);

#ifdef	SESSION
	pthread_mutex_lock(&version_mutex);
	if(clamav_versions == NULL) {
		clamav_versions = (char **)cli_malloc(sizeof(char *));
		if(clamav_versions == NULL) {
			pthread_mutex_unlock(&version_mutex);
			return -1;
		}
		clamav_version = cli_malloc(VERSION_LENGTH + 1);
		if(clamav_version == NULL) {
			free(clamav_versions);
			clamav_versions = NULL;
			pthread_mutex_unlock(&version_mutex);
			return -1;
		}
	}
	pthread_mutex_unlock(&version_mutex);
#endif
	snprintf(clamav_version, VERSION_LENGTH,
		"ClamAV %s/%d/%s", VERSION, v, ctime(&t));
	/* Remove ctime's trailing \n */
	if((ptr = strchr(clamav_version, '\n')) != NULL)
		*ptr = '\0';

	signatures = 0;
	newroot = NULL;
	ret = cl_loaddbdir(dbdir, &newroot, &signatures);
	if(ret != 0) {
		cli_errmsg("%s\n", cl_strerror(ret));
		return -1;
	}
	if(newroot == NULL) {
		cli_errmsg("Can't initialize the virus database.\n");
		return -1;
	}

	ret = cl_build(newroot);
	if(ret != 0) {
		cli_errmsg("Database initialization error: %s\n", cl_strerror(ret));
		cl_free(newroot);
		return -1;
	}
	pthread_mutex_lock(&root_mutex);
	oldroot = root;
	root = newroot;
	pthread_mutex_unlock(&root_mutex);

	if(use_syslog) {
#ifdef	SESSION
		pthread_mutex_lock(&version_mutex);
#endif
		syslog(LOG_INFO, _("Loaded %s"), clamav_version);
#ifdef	SESSION
		pthread_mutex_unlock(&version_mutex);
#endif
		syslog(LOG_INFO, _("ClamAV: Protecting against %u viruses"), signatures);
	}
	if(oldroot) {
		char mess[128];

		cl_free(oldroot);
		sprintf(mess, "Database correctly reloaded (%u signatures)\n", signatures);
		logger(mess);
		cli_dbgmsg("Database updated\n");
	} else
		cli_dbgmsg("Database loaded\n");

	return cl_statinidir(dbdir, &dbstat);
}

static void
sigsegv(int sig)
{
	signal(SIGSEGV, SIG_DFL);

#ifdef HAVE_BACKTRACE
	print_trace();
#endif

	if(use_syslog)
		syslog(LOG_CRIT, "Segmentation fault :-( Bye..");
	cli_errmsg("Segmentation fault :-( Bye..\n");

	smfi_stop();
}

#ifdef HAVE_BACKTRACE
static void
print_trace(void)
{
	void *array[BACKTRACE_SIZE];
	size_t size, i;
	char **strings;
	pid_t pid = getpid();

	size = backtrace(array, BACKTRACE_SIZE);
	strings = backtrace_symbols(array, size);

	cli_dbgmsg("Backtrace of pid %d:\n", pid);
	if(use_syslog)
		syslog(LOG_ERR, "Backtrace of pid %d:", pid);

	for(i = 0; i < size; i++) {
		if(use_syslog)
			syslog(LOG_ERR, "bt[%u]: %s", i, strings[i]);
		cli_dbgmsg("%s\n", strings[i]);
	}

	/* TODO: dump the current email */

	free(strings);
}
#endif

/*
 * Check that the correct port name has been given, i.e. that the
 * input socket to clamav-milter from sendmail, is the same that
 * sendmail has been configured to use as it's output socket
 * Return:	<0 invalid
 *		=0 valid
 *		>0 unknown
 */
static int
verifyIncomingSocketName(const char *sockName)
{
#if HAVE_MMAP
	int fd, ret;
	char *ptr;
	size_t size;
	struct stat statb;

	if(strncmp(sockName, "inet:", 5) == 0)
		/*
		 * clamav-milter is running on a different machine from sendmail
		 */
		return 1;

	if(sendmailCF)
		fd = open(sendmailCF, O_RDONLY);
	else {
		fd = open("/etc/mail/sendmail.cf", O_RDONLY);
		if(fd < 0)
			fd = open("/etc/sendmail.cf", O_RDONLY);
	}

	if(fd < 0)
		return 1;

	if(fstat(fd, &statb) < 0) {
		close(fd);
		return 1;
	}

	size = statb.st_size;

	if(size == 0) {
		close(fd);
		return -1;
	}

	ptr = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);
	if(ptr == MAP_FAILED) {
		perror("mmap");
		close(fd);
		return -1;
	}

	ret = (cli_memstr(ptr, size, sockName, strlen(sockName)) != NULL) ? 1 : -1;

	munmap(ptr, size);
	close(fd);

	return ret;
#else	/*!HAVE_MMAP*/
	return 1;
#endif
}

/*
 * If the given email address is whitelisted don't scan emails to them
 *
 * TODO: Allow regular expressions in the emails
 * TODO: Syntax check the contents of the files
 * TODO: Allow emails of the form "name <address>"
 */
static int
isWhitelisted(const char *emailaddress)
{
	static table_t *whitelist;


	cli_dbgmsg("isWhitelisted %s\n", emailaddress);   
        /*	
	 * Don't scan messages to the quarantine email address 
	 */
        if(quarantine && (strcasecmp(quarantine, emailaddress) == 0))
		return 1;

	if((whitelist == NULL) && whitelistFile) {
		FILE *fin;
		char buf[BUFSIZ + 1];

		fin = fopen(whitelistFile, "r");

		if(fin == NULL) {
			perror(whitelistFile);
			if(use_syslog)  
			    syslog(LOG_ERR, _("Can't open white-list file %s"),
				    whitelistFile);
			return 0;
		}
		whitelist = tableCreate();

		while(fgets(buf, sizeof(buf), fin) != NULL) {
			/* comment line? */
			switch(buf[0]) {
				case '#':
				case '/':
				case ':':
					continue;
			}
			if(cli_chomp(buf) > 0)
				(void)tableInsert(whitelist, buf, 1);
		}
		fclose(fin);
	}
	if(whitelist && (tableFind(whitelist, emailaddress) == 1))
		/*
		 * This recipient is on the whitelist
		 */
		return 1;

	/*
	 * Don't scan messages to the quarantine email address
	 */
	if(quarantine && (strcasecmp(quarantine, emailaddress) == 0))
		return 1;

	return 0;
}

static void
logger(const char *mess)
{
#ifdef	CL_DEBUG
	puts(mess);
#else
	FILE *fout;
	
	if(cfgopt(copt, "Foreground"))
		fout = stderr;
	else
		fout = fopen(logFile, "a");

	if(fout == NULL)
		return;

	if(logg_time) {
#ifdef HAVE_CTIME_R
		time_t currtime = time((time_t)0);
		char buf[27];

#ifdef HAVE_CTIME_R_3
		ctime_r(&currtime, buf, sizeof(buf));
#else
		ctime_r(&currtime, buf);
#endif
		fprintf(fout, "%.*s -> %s\n", (int)strlen(buf) - 1, buf, mess);
#else	/*!HAVE_CTIME_R*/
		/* TODO */
		fprintf(fout, "%s\n", mess);
#endif
	} else
		fprintf(fout, "%s\n", mess);
	if(fout != stderr)
		fclose(fout);
#endif
}
