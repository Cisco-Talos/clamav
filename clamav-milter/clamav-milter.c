/*
 * clamav-milter.c
 *	.../clamav-milter/clamav-milter.c
 *
 *  Copyright (C) 2003- Nigel Horne <njh@bandsman.co.uk>
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
 * Install into /usr/local/sbin/clamav-milter
 * See http://www.elandsys.com/resources/sendmail/libmilter/overview.html
 *
 * For installation instructions see the file INSTALL that came with this file
 */
static	char	const	rcsid[] = "$Id: clamav-milter.c,v 1.295 2006/10/30 14:20:36 njh Exp $";

#define	CM_VERSION	"devel-301006"

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include "defaults.h"
#include "cfgparser.h"
#include "target.h"
#include "str.h"
#include "../libclamav/others.h"
#include "output.h"
#include "clamav.h"
#include "table.h"
#include "network.h"

#ifndef	CL_DEBUG
#define	NDEBUG
#endif

#include <stdio.h>
#include <sysexits.h>
#include <sys/stat.h>
#include <syslog.h>
#if	HAVE_STDINT_H
#include <stdlib.h>
#endif
#if	HAVE_MEMORY_H
#include <memory.h>
#endif
#if	HAVE_STRING_H
#include <string.h>
#endif
#include <sys/wait.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <stdarg.h>
#include <errno.h>
#if	HAVE_LIBMILTER_MFAPI_H
#include <libmilter/mfapi.h>
#endif
#include <pthread.h>
#include <sys/time.h>
#include <signal.h>
#if	HAVE_REGEX_H
#include <regex.h>
#endif
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#if	HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#if	HAVE_RESOLV_H
#include <arpa/nameser.h>	/* for HEADER */
#include <resolv.h>
#endif
#ifdef	HAVE_UNISTD_H
#include <unistd.h>
#endif

#if HAVE_MMAP
#if HAVE_SYS_MMAN_H
#include <sys/mman.h>
#else /* HAVE_SYS_MMAN_H */
#undef HAVE_MMAP
#endif
#endif

#ifdef	C_LINUX
#include <sys/sendfile.h>	/* FIXME: use sendfile on BSD not Linux */
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
#if	HAVE_TCPD_H
#include <tcpd.h>
#endif

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
#define	DEFAULT_TIMEOUT	120

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
 * TODO: Decide action (bounce, discard, reject etc.) based on the virus
 *	found. Those with faked addresses, such as SCO.A want discarding,
 *	others could be bounced properly.
 * TODO: Encrypt mails sent to clamd to stop sniffers. Sending by UNIX domain
 *	sockets is better
 * TODO: Test with IPv6
 * TODO: Load balancing, allow local machine to talk via UNIX domain socket.
 * TODO: allow each line in the whitelist file to specify a quarantine email
 *	address
 */

struct header_node_t {
	char	*header;
	struct	header_node_t *next;
};

struct header_list_struct {
	struct	header_node_t *first;
	struct	header_node_t *last;
};

typedef struct header_list_struct *header_list_t;

/*
 * Local addresses are those not scanned if --local is not set
 * 127.0.0.0 is not in this table since that's goverend by --outgoing
 * Andy Fiddaman <clam@fiddaman.net> added 69.254.0.0/16
 *	(Microsoft default DHCP)
 * TODO: compare this with RFC1918
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
	{ 0, 0 },	/* space to put one more via -I addr */
	{ 0, 0 }
};

/*
 * Each libmilter thread has one of these
 */
struct	privdata {
	char	*from;	/* Who sent the message */
	char	*subject;	/* Original subject */
	char	*sender;	/* Secretary - often used in mailing lists */
	char	**to;	/* Who is the message going to */
	char	ip[INET_ADDRSTRLEN];	/* IP address of the other end */
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
	struct	cl_node	*root;	/* database of viruses used to scan this one */
};

#ifdef	SESSION
static	int		createSession(unsigned int s);
#else
static	int		pingServer(int serverNumber);
static	void		*try_server(void *var);
struct	try_server_struct {
	int	sock;
	int	rc;
	struct	sockaddr_in *server;
	int	server_index;
};
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
static	void		clamfi_free(struct privdata *privdata, int free);
static	int		clamfi_send(struct privdata *privdata, size_t len, const char *format, ...);
static	long		clamd_recv(int sock, char *buf, size_t len);
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
/*static	int	clamfi_gethostbyname(const char *hostname, struct hostent *hp, char *buf, size_t len);*/
static	int	isLocalAddr(in_addr_t addr);
static	void	clamdIsDown(void);
static	void	*watchdog(void *a);
static	int	check_and_reload_database(void);
static	void	timeoutBlacklist(char *ip_address, int time_of_blacklist);
static	void	quit(void);
static	void	broadcast(const char *mess);
static	int	loadDatabase(void);
static	int	increment_connections(void);
static	void	decrement_connections(void);

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
static	int	Iflag = 0;	/* Added an IP addr to localNets? */
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
static	int	readTimeout = DEFAULT_TIMEOUT; /*
				 * number of seconds to wait for clamd to
				 * respond, see ReadTimeout in clamd.conf
				 */
static	long	streamMaxLength = -1;	/* StreamMaxLength from clamd.conf */
static	int	logClean = 0;	/*
				 * Add clean items to the log file
				 */
static	char	*signature = N_("-- \nScanned by ClamAv - http://www.clamav.net\n");
static	time_t	signatureStamp;
static	char	*templateFile;	/* e-mail to be sent when virus detected */
static	char	*templateHeaders;	/* headers to be added to the above */
static	const char	*tmpdir;

#ifdef	CL_DEBUG
static	int	debug_level = 0;
#endif

static	pthread_mutex_t	n_children_mutex = PTHREAD_MUTEX_INITIALIZER;
static	pthread_cond_t	n_children_cond = PTHREAD_COND_INITIALIZER;
static	int	n_children = 0;
static	int	max_children = 0;
static	unsigned	int	freshclam_monitor = 10;	/*
							 * how often, in
							 * seconds, to scan for
							 * database updates
							 */
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
				/*
				 * NOTE: first character of strings to logg():
				 *	! Error
				 *	^ Warning
				 *	* Verbose
				 *	# Info, but not logged in foreground
				 *	Default Info
				 */
static	const	char	*pidFile;
static	int	logVerbose = 0;
static	struct	cfgstruct	*copt;
static	const	char	*localSocket;	/* milter->clamd comms */
static	in_port_t	tcpSocket;	/* milter->clamd comms */
static	char	*port = NULL;	/* sendmail->milter comms */

static	const	char	*serverHostNames = "127.0.0.1";
#if	HAVE_IN_ADDR_T
static	in_addr_t	*serverIPs;	/* IPv4 only */
#else
static	long	*serverIPs;	/* IPv4 only */
#endif
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
static	const	char	*report;

static	const	char	*whitelistFile;	/*
					 * file containing destination email
					 * addresses that we don't scan
					 */
static	const	char	*sendmailCF;	/* location of sendmail.cf to verify */
static	const	char	*pidfile;
static	int	black_hole_mode; /*
				 * Since sendmail calls its milters before it
				 * looks in /etc/aliases we can spend time
				 * looking for malware that's going to be
				 * thrown away even if the message is clean.
				 * Enable this to not scan these messages.
				 * Sadly, because these days sendmail -bv
				 * only works as root, you can't use this with
				 * the User directive, which some won't like
				 * which also may contain the real target name
				 *
				 * smfi_getsymval(ctx, "{rcpt_addr}") only
				 * handles virtuser, it doesn't also deref
				 * the alias table, so it isn't any help
				 */

static	table_t	*blacklist;	/* never freed */
static	int	blacklist_time;	/* How long to blacklist an IP */
static	pthread_mutex_t	blacklist_mutex = PTHREAD_MUTEX_INITIALIZER;

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
static	int	isBlacklisted(const char *ip_address);
static	void	mx(void);
#ifdef	HAVE_RESOLV_H
static	void	resolve(const char *host);
#endif
static	sfsistat	black_hole(const struct privdata *privdata);
static	int	useful_header(const char *cmd);

extern	short	logg_time, logg_lock, logg_verbose, logg_foreground;
extern	int	logg_size;

static void
help(void)
{
	printf("\n\tclamav-milter version %s\n", CM_VERSION);
	puts("\tCopyright (C) 2006 Nigel Horne <njh@clamav.net>\n");

	puts(_("\t--advisory\t\t-A\tFlag viruses rather than deleting them."));
	puts(_("\t--blacklist=time\t-k\tTime (in seconds) to blacklist an IP."));
	puts(_("\t--black-hole-mode\t\tDon't scan messages aliased to /dev/null."));
	puts(_("\t--bounce\t\t-b\tSend a failure message to the sender."));
	puts(_("\t--broadcast\t\t-B [IFACE]\tBroadcast to a network manager when a virus is found."));
	puts(_("\t--config-file=FILE\t-c FILE\tRead configuration from FILE."));
	puts(_("\t--debug\t\t\t-D\tPrint debug messages."));
	puts(_("\t--detect-forged-local-address\t-L\tReject mails that claim to be from us."));
	puts(_("\t--dont-scan-on-error\t-d\tPass e-mails through unscanned if a system error occurs."));
	puts(_("\t--dont-wait\t\t\tAsk remote end to resend if max-children exceeded."));
	puts(_("\t--external\t\t-e\tUse an external scanner (usually clamd)."));
	puts(_("\t--freshclam-monitor=SECS\t-M SECS\tHow often to check for database update."));
	puts(_("\t--from=EMAIL\t\t-a EMAIL\tError messages come from here."));
	puts(_("\t--force-scan\t\t-f\tForce scan all messages (overrides (-o and -l)."));
	puts(_("\t--help\t\t\t-h\tThis message."));
	puts(_("\t--headers\t\t-H\tInclude original message headers in the report."));
	puts(_("\t--ignore IPaddr\t\t-I IPaddr\tAdd IPaddr to LAN IP list (see --local)."));
	puts(_("\t--local\t\t\t-l\tScan messages sent from machines on our LAN."));
	puts(_("\t--max-childen\t\t-m\tMaximum number of concurrent scans."));
	puts(_("\t--outgoing\t\t-o\tScan outgoing messages from this machine."));
	puts(_("\t--noreject\t\t-N\tDon't reject viruses, silently throw them away."));
	puts(_("\t--noxheader\t\t-n\tSuppress X-Virus-Scanned/X-Virus-Status headers."));
	puts(_("\t--pidfile=FILE\t\t-i FILE\tLocation of pidfile."));
	puts(_("\t--postmaster\t\t-p EMAIL\tPostmaster address [default=postmaster]."));
	puts(_("\t--postmaster-only\t-P\tSend warnings only to the postmaster."));
	puts(_("\t--quiet\t\t\t-q\tDon't send e-mail notifications of interceptions."));
	puts(_("\t--quarantine=USER\t-Q EMAIL\tQuarantine e-mail account."));
	puts(_("\t--report-phish=EMAIL\t-r EMAIL\tReport phish to this email address."));
	puts(_("\t--quarantine-dir=DIR\t-U DIR\tDirectory to store infected emails."));
	puts(_("\t--server=SERVER\t\t-s SERVER\tHostname/IP address of server(s) running clamd (when using TCPsocket)."));
	puts(_("\t--sendmail-cf=FILE\t\tLocation of the sendmail.cf file to verify"));
	puts(_("\t--sign\t\t\t-S\tAdd a hard-coded signature to each scanned message."));
	puts(_("\t--signature-file=FILE\t-F FILE\tLocation of signature file."));
	puts(_("\t--template-file=FILE\t-t FILE\tLocation of e-mail template file."));
	puts(_("\t--template-headers=FILE\t\tLocation of e-mail headers for template file."));
	puts(_("\t--timeout=SECS\t\t-T SECS\tTimeout waiting to childen to die."));
	puts(_("\t--whitelist-file=FILE\t-W FILE\tLocation of the file of whitelisted addresses"));
	puts(_("\t--version\t\t-V\tPrint the version number of this software."));
#ifdef	CL_DEBUG
	puts(_("\t--debug-level=n\t\t-x n\tSets the debug level to 'n'."));
#endif
	puts(_("\nFor more information type \"man clamav-milter\"."));
	puts(_("For bug reports, please refer to http://www.clamav.net/bugs.html#pagestart"));
}

int
main(int argc, char **argv)
{
	extern char *optarg;
	int i, Bflag = 0, server = 0;
	char *cfgfile = NULL;
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
		struct cidr_net *net;
		struct in_addr ignoreIP;
#ifdef	CL_DEBUG
		const char *args = "a:AbB:c:dDefF:I:k:lLm:M:nNop:PqQ:r:hHs:St:T:U:VwW:x:0:1:2";
#else
		const char *args = "a:AbB:c:dDefF:I:k:lLm:M:nNop:PqQ:r:hHs:St:T:U:VwW:0:1:2";
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
				"ignore", 1, NULL, 'I'
			},
			{
				"pidfile", 1, NULL, 'i'
			},
			{
				"blacklist", 1, NULL, 'k'
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
				"report-phishing", 1, NULL, 'r'
			},
			{
				"quarantine-dir", 1, NULL, 'U',
			},
			{
				"max-children", 1, NULL, 'm'
			},
			{
				"freshclam-monitor", 1, NULL, 'M'
			},
			{
				"sendmail-cf", 1, NULL, '0'
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
				"template-headers", 1, NULL, '1'
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
				"black-hole-mode", 0, NULL, '2'
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
			case 'k':	/* blacklist time */
				blacklist_time = atoi(optarg);
				break;
			case 'I':	/* --ignore, -I hostname */
				/*
				 * Based on patch by jpd@louisiana.edu
				 */
				if(Iflag) {
					fprintf(stderr,
						_("%s: %s, -I may only be given once"),
							argv[0], optarg);
					return EX_USAGE;
				}
				if(!inet_aton(optarg, &ignoreIP)) {
					fprintf(stderr,
						_("%s: Cannot convert -I%s to IPaddr"),
							argv[0], optarg);
					return EX_USAGE;
				}
				for(net = (struct cidr_net *)localNets; net->base; net++)
					;
				/* TODO: allow netmasks */
				net->base = ntohl(ignoreIP.s_addr);
				net->mask = ntohl(0xffffffffU);
				Iflag++;
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
			case 'M':	/* how often to monitor for freshclam */
				freshclam_monitor = atoi(optarg);
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
			case 'r':	/* report phishing here */
				/* e.g. reportphishing@antiphishing.org */
				report = optarg;
				break;
			case 's':	/* server running clamd */
				server++;
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
				templateFile = optarg;
				break;
			case '1':	/* headers for the template file */
				templateHeaders = optarg;
				break;
			case '2':
				black_hole_mode++;
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
				fprintf(stderr, "Usage: %s [-b] [-c FILE] [-F FILE] [--max-children=num] [-e] [-l] [-o] [-p address] [-P] [-q] [-Q USER] [-s SERVER] [-S] [-x#] [-U PATH] [-M#] socket-addr\n", argv[0]);
#else
				fprintf(stderr, "Usage: %s [-b] [-c FILE] [-F FILE] [--max-children=num] [-e] [-l] [-o] [-p address] [-P] [-q] [-Q USER] [-s SERVER] [-S] [-U PATH] [-M#] socket-addr\n", argv[0]);
#endif
				return EX_USAGE;
		}
	}

	/*
	 * Check sanity of --external and --server arguments
	 */
	if(server && !external) {
		fprintf(stderr,
			"%s: --server can only be used with --external\n",
			argv[0]);
		return EX_USAGE;
	}

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
	if(cfgfile == NULL) {
		cfgfile = cli_malloc(strlen(CONFDIR) + 12);	/* leak */
		sprintf(cfgfile, "%s/clamd.conf", CONFDIR);
	}
	if((copt = getcfg(cfgfile, 1)) == NULL) {
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

		if(((cpt = cfgopt(copt, "User")) != NULL) && cpt->enabled) {
			const struct passwd *user;

			if((user = getpwnam(cpt->strarg)) == NULL) {
				fprintf(stderr, _("%s: Can't get information about user %s\n"), argv[0], cpt->strarg);
				return EX_CONFIG;
			}

			if(cfgopt(copt, "AllowSupplementaryGroups")->enabled) {
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

			if(black_hole_mode && (user->pw_uid != 0)) {
				fprintf(stderr, _("%s: You cannot use black hole mode unless you are root\n"),
					argv[0]);
				return EX_CONFIG;
			}

			setgid(user->pw_gid);

			if(setuid(user->pw_uid) < 0)
				perror(cpt->strarg);
			else
				cli_dbgmsg(_("Running as user %s (UID %d, GID %d)\n"),
					cpt->strarg, user->pw_uid, user->pw_gid);
		} else if(!black_hole_mode)
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
				argv[0], quarantine_dir, (int)statb.st_mode & 0777);
			return EX_CONFIG;
		}
	}

	if(sigFilename && !updateSigFile())
		return EX_USAGE;

	if(templateFile && (access(templateFile, R_OK) < 0)) {
		perror(templateFile);
		return EX_CONFIG;
	}
	if(templateHeaders) {
		if(templateFile == NULL) {
			fputs(("%s: --template-headers requires --template-file\n"),
				stderr);
			return EX_CONFIG;
		}
		if(access(templateHeaders, R_OK) < 0) {
			perror(templateHeaders);
			return EX_CONFIG;
		}
	}
	if(whitelistFile && (access(whitelistFile, R_OK) < 0)) {
		perror(whitelistFile);
		return EX_CONFIG;
	}

	/*
	 * patch from "Richard G. Roberto" <rgr@dedlegend.com>
	 * If the --max-children flag isn't set, see if MaxThreads
	 * is set in the config file
	 */
	if((max_children == 0) && ((cpt = cfgopt(copt, "MaxThreads")) != NULL) && cpt->enabled)
		max_children = cpt->numarg;

	if(((cpt = cfgopt(copt, "ReadTimeout")) != NULL) && cpt->enabled) {
		readTimeout = cpt->numarg;

		if(readTimeout < 0) {
			fprintf(stderr, _("%s: ReadTimeout must not be negative in %s\n"),
				argv[0], cfgfile);
			return EX_CONFIG;
		}
	} else
		readTimeout = DEFAULT_TIMEOUT;

	if(((cpt = cfgopt(copt, "StreamMaxLength")) != NULL) && cpt->enabled) {
		if(cpt->numarg < 0) {
			fprintf(stderr, _("%s: StreamMaxLength must not be negative in %s\n"),
				argv[0], cfgfile);
			return EX_CONFIG;
		}
		streamMaxLength = (long)cpt->numarg;
	}

	if(cfgopt(copt, "LogSyslog")->enabled) {
		int fac = LOG_LOCAL6;

		if(cfgopt(copt, "LogVerbose")->enabled) {
			logg_verbose = 1;
#ifdef	CL_DEBUG
			if(debug_level >= 15) {
				logVerbose = 1;
#if	((SENDMAIL_VERSION_A > 8) || ((SENDMAIL_VERSION_A == 8) && (SENDMAIL_VERSION_B >= 13)))
				smfi_setdbg(6);
#endif
			}
#endif
		}
		logg_syslog = use_syslog = 1;

		if(((cpt = cfgopt(copt, "LogFacility")) != NULL) && cpt->enabled)
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
		logg_syslog = use_syslog = 0;
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
		if(freshclam_monitor <= 0) {
			fprintf(stderr, _("%s: --freshclam_monitor must be at least one second\n"), argv[0]);
			return EX_CONFIG;
		}
#if	0
		if(child_timeout) {
			fprintf(stderr, _("%s: --timeout must not be given if --external is not given\n"), argv[0]);
			return EX_CONFIG;
		}
#endif
		if(loadDatabase() != 0) {
			/*
			 * Handle the dont-scan-on-error option, which says
			 * that we pass on emails, unscanned, if an error has
			 * occurred
			 */
			if(cl_error != SMFIS_ACCEPT)
				return EX_CONFIG;

			fprintf(stderr, _("%s: No emails will be scanned"),
				argv[0]);
		}
		numServers = 1;
	} else if(((cpt = cfgopt(copt, "LocalSocket")) != NULL) && cpt->enabled) {
#ifdef	SESSION
		struct sockaddr_un server;
#endif
		char *sockname = NULL;

		if(cfgopt(copt, "TCPSocket")->enabled) {
			fprintf(stderr, _("%s: You can select one server type only (local/TCP) in %s\n"),
				argv[0], cfgfile);
			return EX_CONFIG;
		}
		if(server) {
			fprintf(stderr, _("%s: You cannot use the --server option when using LocalSocket in %s\n"),
				argv[0], cfgfile);
			return EX_USAGE;
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

		serverIPs = (in_addr_t *)cli_malloc(sizeof(in_addr_t));
#ifdef	INADDR_LOOPBACK
		serverIPs[0] = INADDR_LOOPBACK;
#else
		serverIPs[0] = inet_addr("127.0.0.1");
#endif

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
	} else if(((cpt = cfgopt(copt, "TCPSocket")) != NULL) && cpt->enabled) {
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

		logg("*numServers: %d\n", numServers);

		serverIPs = (in_addr_t *)cli_malloc(numServers * sizeof(in_addr_t));
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

		if(numServers > max_children) {
			fprintf(stderr, _("%1$s: --max-children (%2$d) is lower than the number of servers you have (%3$d)\n"),
				argv[0], max_children, numServers);
			return EX_CONFIG;
		}

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
#ifdef	INADDR_NONE
			if(serverIPs[i] == INADDR_NONE) {
#else
			if(serverIPs[i] == (in_addr_t)-1) {
#endif
				const struct hostent *h = gethostbyname(hostname);

				if(h == NULL) {
					fprintf(stderr, _("%s: Unknown host %s\n"),
						argv[0], hostname);
					return EX_USAGE;
				}

				memcpy((char *)&serverIPs[i], h->h_addr, sizeof(serverIPs[i]));
			}

#ifndef	SESSION
			if(serverIPs[i] == (int)inet_addr("127.0.0.1")) {
				/*
				 * Fudge to allow clamd to come up on
				 * our local machine
				 */
				sync();
				sleep(2);
			}

			if(pingServer(i))
				activeServers++;
			else {
				cli_warnmsg(_("Can't talk to clamd server %s on port %d\n"),
					hostname, tcpSocket);
				if(serverIPs[i] == INADDR_LOOPBACK) {
					if(cfgopt(copt, "TCPAddr")->enabled)
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
			if(use_syslog) {
				syslog(LOG_ERR, _("Can't find any clamd server"));
				closelog();
			}
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
		if((cpt = cfgopt(copt, "TemporaryDirectory")) && cpt->enabled) {
			tmpdir = cpt->strarg;
			cl_settempdir(tmpdir, (short)(cfgopt(copt, "LeaveTemporaryFiles")->enabled));
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

	if(report) {
		if(!cfgopt(copt, "DetectPhishing")->enabled) {
			fprintf(stderr, "%s: You have chosen --report, but DetectPhishing is off in %s\n",
				argv[0], cfgfile);
			return EX_USAGE;
		}
		if((quarantine_dir == NULL) && (tmpdir == NULL)) {
			/*
			 * Limitation: doesn't store message in a temporary
			 * file, so we won't be able to use mail < file
			 */
			fprintf(stderr, "%s: when using --external, --report-phish cannot be used without either LocalSocket or --quarantine\n",
				argv[0]);
			return EX_USAGE;
		}
		if(lflag) {
			/*
			 * Naturally, if you attempt to scan the phish you've
			 * just reported, it'll be blocked!
			 */
			fprintf(stderr, "%s: --report-phish cannot be used with --local\n",
				argv[0]);
			return EX_USAGE;
		}
	}

	if(cfgopt(copt, "Foreground")->enabled)
		logg_foreground = 1;
	else {
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

		if((cpt = cfgopt(copt, "LogFile")) && cpt->enabled) {
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

	logg_lock = cfgopt(copt, "LogFileUnlock")->enabled;
	logg_time = cfgopt(copt, "LogTime")->enabled;
	logClean = cfgopt(copt, "LogClean")->enabled;
	logg_size = cfgopt(copt, "LogFileMaxSize")->numarg;
	logg_verbose = mprintf_verbose = cfgopt(copt, "LogVerbose")->enabled;

	if(cfgopt(copt, "Debug")->enabled)
		/*
		 * enable debug messages in libclamav, --debug also does this
		 */
		cl_debug();

	atexit(quit);

	if(!external) {
		/* TODO: read the limits from clamd.conf */

		if(!cfgopt(copt, "ScanMail")->enabled)
			printf(_("%s: ScanMail not defined in %s (needed without --external), enabling\n"),
				argv[0], cfgfile);

		options |= CL_SCAN_MAIL;	/* no choice */
		/*if(!cfgopt(copt, "ScanRAR")->enabled)
			options |= CL_SCAN_DISABLERAR;*/
		if(cfgopt(copt, "ArchiveBlockEncrypted")->enabled)
			options |= CL_SCAN_BLOCKENCRYPTED;
		if(cfgopt(copt, "ArchiveBlockMax")->enabled)
			options |= CL_SCAN_BLOCKMAX;
		if(cfgopt(copt, "ScanPE")->enabled)
			options |= CL_SCAN_PE;
		if(cfgopt(copt, "DetectBrokenExecutables")->enabled)
			options |= CL_SCAN_BLOCKBROKEN;
		if(cfgopt(copt, "MailFollowURLs")->enabled)
			options |= CL_SCAN_MAILURL;
		if(cfgopt(copt, "ScanOLE2")->enabled)
			options |= CL_SCAN_OLE2;
		if(cfgopt(copt, "ScanHTML")->enabled)
			options |= CL_SCAN_HTML;

		memset(&limits, '\0', sizeof(struct cl_limits));

		if(cfgopt(copt, "ScanArchive")->enabled) {
			options |= CL_SCAN_ARCHIVE;
			if(((cpt = cfgopt(copt, "ArchiveMaxFileSize")) != NULL) && cpt->enabled)
				limits.maxfilesize = cpt->numarg;
			else
				limits.maxfilesize = 10485760;

			if(((cpt = cfgopt(copt, "ArchiveMaxRecursion")) != NULL) && cpt->enabled)
				limits.maxreclevel = cpt->numarg;
			else
				limits.maxreclevel = 8;

			if(((cpt = cfgopt(copt, "ArchiveMaxFiles")) != NULL) && cpt->enabled)
				limits.maxfiles = cpt->numarg;
			else
				limits.maxfiles = 1000;

			if(((cpt = cfgopt(copt, "ArchiveMaxCompressionRatio")) != NULL) && cpt->enabled)
				limits.maxratio = cpt->numarg;
			else
				limits.maxratio = 250;

			if(cfgopt(copt, "ArchiveLimitMemoryUsage")->enabled)
				limits.archivememlim = 1;
			else
				limits.archivememlim = 0;
		}
	}

	pthread_create(&tid, NULL, watchdog, NULL);

	if(((cpt = cfgopt(copt, "PidFile")) != NULL) && cpt->enabled)
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

	if(cfgopt(copt, "FixStaleSocket")->enabled) {
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

	if(blacklist_time) {
		mx();
		if(blacklist)
			/* We must never blacklist ourself */
			tableInsert(blacklist, "127.0.0.1", 0);
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
	const struct protoent *proto;

	cli_dbgmsg("createSession session %d, server %d\n", s, serverNumber);
	assert(s < max_children);

	memset((char *)&server, 0, sizeof(struct sockaddr_in));
	server.sin_family = AF_INET;
	server.sin_port = (in_port_t)htons(tcpSocket);

	server.sin_addr.s_addr = serverIPs[serverNumber];

	session->sock = -1;
	proto = getprotobyname("tcp");
	if(proto == NULL) {
		fputs("Unknown prototol tcp, check /etc/protocols\n", stderr);
		ret = -1;
	} else if((fd = socket(AF_INET, SOCK_STREAM, proto->p_proto)) < 0) {
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
	int sock;
	long nbytes;
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
#ifdef	INADDR_NONE
		assert(serverIPs[0] != INADDR_NONE);
#else
		assert(serverIPs[0] != (in_addr_t)-1);
#endif

		server.sin_addr.s_addr = serverIPs[serverNumber];

		if((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
			perror("socket");
			return 0;
		}
		if(connect(sock, (struct sockaddr *)&server, sizeof(struct sockaddr_in)) < 0) {
			int is_connected = 0;

			if(errno == ECONNREFUSED) {
				/*
				 * During startup there is a race condition:
				 * clamd can start and fork, then rc will start
				 * clamav-milter before clamd has run accept(2),
				 * so we fail to connect.
				 * In case this is the situation here, we wait
				 * for a couple of seconds and try again. The
				 * sync() is because during startup the machine
				 * won't be doing much for most of the time, so
				 * we may as well do something constructive!
				 */
				sync();
				sleep(2);
				if(connect(sock, (struct sockaddr *)&server, sizeof(struct sockaddr_in)) >= 0)
					is_connected = 1;
			}
			if(!is_connected) {
				char *hostname = cli_strtok(serverHostNames,
					serverNumber, ":");

				perror(hostname ? hostname : "connect");
				close(sock);
				free(hostname);
				return 0;
			}
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
	int maxsock, i, j;
	fd_set rfds;
	int retval;
	pthread_t *tids;
	struct try_server_struct *socks;

	assert(tcpSocket != 0);
	assert(numServers > 0);

	if(numServers == 1)
		return 0;

	servers = (struct sockaddr_in *)cli_calloc(numServers, sizeof(struct sockaddr_in));
	if(servers == NULL)
		return 0;
	socks = (struct try_server_struct *)cli_malloc(numServers * sizeof(struct try_server_struct));

	if(max_children > 0) {
		assert(n_children > 0);
		assert(n_children <= max_children);

		/*
		 * Don't worry about no lock - it's doesn't matter if it's
		 * not really accurate
		 */
		j = n_children - 1;	/* look at the next free one */
		if(j < 0)
			j = 0;
	} else
		/*
		 * cli_rndnum returns 0..(max-1) - the max argument is not
		 * the maximum number you want it to return, it is in fact
		 * one *more* than the maximum number you want it to return
		 */
		j = cli_rndnum(numServers);

	tids = cli_malloc(numServers * sizeof(pthread_t));

	for(i = 0; i < numServers; i++)
		socks[i].sock = -1;

	for(i = 0, server = servers; i < numServers; i++, server++) {
		int sock;
		int server_index = (i + j) % numServers;

		server->sin_family = AF_INET;
		server->sin_port = (in_port_t)htons(tcpSocket);
		server->sin_addr.s_addr = serverIPs[server_index];

		logg("*findServer: try server %d\n", server_index);

		sock = socks[i].sock = socket(AF_INET, SOCK_STREAM, 0);

		if(sock < 0) {
			perror("socket");
			do {
				pthread_join(tids[i], NULL);
				if(socks[i].sock >= 0)
					close(socks[i].sock);
			} while(--i >= 0);
			free(socks);
			free(servers);
			return 0;	/* Use the first server on failure */
		}

		socks[i].server = server;
		socks[i].server_index = server_index;

		if(pthread_create(&tids[i], NULL, try_server, &socks[i]) != 0) {
			perror("pthread_create");
			do {
				pthread_join(tids[i], NULL);
				if(socks[i].sock >= 0)
					close(socks[i].sock);
			} while(--i >= 0);
			free(socks);
			free(servers);
			return 0;	/* Use the first server on failure */
		}
	}

	maxsock = -1;
	FD_ZERO(&rfds);

	for(i = 0; i < numServers; i++) {
		struct try_server_struct *rc;

		pthread_join(tids[i], &rc);
		assert(rc->sock == socks[i].sock);
		if(rc->rc == 0) {
			close(rc->sock);
			socks[i].sock = -1;
		} else {
			shutdown(rc->sock, SHUT_WR);
			FD_SET(rc->sock, &rfds);
			if(rc->sock > maxsock)
				maxsock = rc->sock;
		}
	}

	free(servers);

	if(maxsock == -1) {
		logg(_("^Couldn't establish a connection to any clamd server\n"));
		retval = 0;
	} else {
		struct timeval tv;

		tv.tv_sec = readTimeout ? readTimeout : DEFAULT_TIMEOUT;
		tv.tv_usec = 0;

		retval = select(maxsock + 1, &rfds, NULL, NULL, &tv);
	}

	if(retval < 0)
		perror("select");

	for(i = 0; i < numServers; i++)
		if(socks[i].sock >= 0)
			close(socks[i].sock);

	if(retval == 0) {
		free(socks);
		clamdIsDown();
		return 0;
	} else if(retval < 0) {
		free(socks);
		logg(_("^findServer: select failed (maxsock = %d)\n"), maxsock);
		return 0;
	}

	for(i = 0; i < numServers; i++)
		if((socks[i].sock >= 0) && (FD_ISSET(socks[i].sock, &rfds))) {
			const int s = (i + j) % numServers;

			free(socks);
			logg("*findServer: use server %d\n", s);
			return s;
		}

	free(socks);
	logg(_("^findServer: No response from any server\n"));
	return 0;
}

/*
 * Connecting to remote servers can take some time, so let's connect to
 *	them in parallel. This routine is started as a thread
 */
static void *
try_server(void *var)
{
	struct try_server_struct *s = (struct try_server_struct *)var;
	int sock = s->sock;
	struct sockaddr *server = (struct sockaddr *)s->server;
	int server_index = s->server_index;

	logg("*try_server: sock %d\n", sock);

	if(connect(sock, server, sizeof(struct sockaddr)) < 0) {
		perror("connect");
		s->rc = 0;
	} else if(send(sock, "PING\n", 5, 0) < 5) {
		perror("send");
		s->rc = 0;
	} else
		s->rc = 1;

	if(s->rc == 0) {
#ifdef	MAXHOSTNAMELEN
		char hostname[MAXHOSTNAMELEN + 1];

		cli_strtokbuf(serverHostNames, server_index, ":", hostname);
		if(strcmp(hostname, "127.0.0.1") == 0)
			gethostname(hostname, sizeof(hostname));
#else
		char *hostname = cli_strtok(serverHostNames, server_index, ":");
#endif
		logg(_("^Check clamd server %s - it may be down\n"), hostname);
#ifndef	MAXHOSTNAMELEN
		free(hostname);
#endif
		broadcast(_("Check clamd server - it may be down\n"));
	}

	return var;
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
	int t;
	const char *remoteIP;
	struct privdata *privdata;

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
	if(smfi_getpriv(ctx) != NULL) {
		/* More than one connection command, "can't happen" */
		cli_warnmsg("clamfi_connect: called more than once\n");
		clamfi_cleanup(ctx);
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
		if(r_gethostbyname(hostmail, &hostent, buf, sizeof(buf)) != 0) {
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
#endif	/*WITH_TCPWRAP*/

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
		logg(_("*clamfi_connect: not scanning local messages\n"));
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
			logg(_("^clamfi_connect: gethostname failed"));
			return SMFIS_CONTINUE;
		}
		logg("*me '%s' hostname '%s'\n", me, hostname);
		if(strcasecmp(hostname, me) == 0) {
			logg(_("Rejected connexion falsely claiming to be from here\n"));
			smfi_setreply(ctx, "550", "5.7.1", _("You have claimed to be me, but you are not"));
			broadcast(_("Forged local address detected"));
			return SMFIS_REJECT;
		}
	}
	if(isBlacklisted(remoteIP)) {
		logg("Rejected connexion from blacklisted IP %s\n", remoteIP);

		/*
		 * TODO: Option to greylist rather than blacklist, by sending
		 *	a try again code
		 * TODO: state *which* virus
		 */
		smfi_setreply(ctx, "550", "5.7.1", _("Your IP is blacklisted because your machine is infected with a virus"));
		broadcast(_("Blacklisted IP detected"));

		/*
		 * Keep them blacklisted
		 */
		pthread_mutex_lock(&blacklist_mutex);
		(void)tableUpdate(blacklist, remoteIP, (int)time((time_t *)0));
		pthread_mutex_unlock(&blacklist_mutex);

		return SMFIS_REJECT;
	}

	if(blacklist_time == 0)
		return SMFIS_CONTINUE;	/* allocate privdata per message */

	pthread_mutex_lock(&blacklist_mutex);
	t = tableFind(blacklist, remoteIP);
	pthread_mutex_unlock(&blacklist_mutex);

	if(t == 0)
		return SMFIS_CONTINUE;	/* this IP will never be blacklisted */

	privdata = (struct privdata *)cli_calloc(1, sizeof(struct privdata));
	if(privdata == NULL)
		return cl_error;

#ifdef	SESSION
	privdata->dataSocket = -1;
#else
	privdata->dataSocket = privdata->cmdSocket = -1;
#endif

	if(smfi_setpriv(ctx, privdata) == MI_SUCCESS) {
		strcpy(privdata->ip, remoteIP);
		return SMFIS_CONTINUE;
	}

	free(privdata);

	return cl_error;
}

/*
 * Since sendmail requires that MAIL FROM is called before RCPT TO, it is
 *	safe to assume that this routine is called first, so the n_children
 *	handler is put here
 */
static sfsistat
clamfi_envfrom(SMFICTX *ctx, char **argv)
{
	struct privdata *privdata;
	const char *mailaddr = argv[0];

	logg("*clamfi_envfrom: %s\n", argv[0]);

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
	privdata = smfi_getpriv(ctx);

	if(privdata == NULL) {
		privdata = (struct privdata *)cli_calloc(1, sizeof(struct privdata));
		if(privdata == NULL)
			return cl_error;
		if(smfi_setpriv(ctx, privdata) != MI_SUCCESS) {
			free(privdata);
			return cl_error;
		}
		if(!increment_connections()) {
			smfi_setreply(ctx, "451", "4.3.2", _("AV system temporarily overloaded - please try later"));
			free(privdata);
			smfi_setpriv(ctx, NULL);
			return SMFIS_TEMPFAIL;
		}
	} else {
		/* More than one message on this connection */
		char ip[INET_ADDRSTRLEN];

		strcpy(ip, privdata->ip);
		if(isBlacklisted(ip)) {
			logg("Rejected email from blacklisted IP %s\n", ip);

			/*
			 * TODO: Option to greylist rather than blacklist, by
			 *	sending	a try again code
			 * TODO: state *which* virus
			 */
			smfi_setreply(ctx, "550", "5.7.1", _("Your IP is blacklisted because your machine is infected with a virus"));
			broadcast(_("Blacklisted IP detected"));

			/*
			 * Keep them blacklisted
			 */
			pthread_mutex_lock(&blacklist_mutex);
			(void)tableUpdate(blacklist, ip, (int)time((time_t *)0));
			pthread_mutex_unlock(&blacklist_mutex);

			return SMFIS_REJECT;
		}
		clamfi_free(privdata, 1);
		strcpy(privdata->ip, ip);
	}

#ifdef	SESSION
	privdata->dataSocket = -1;
#else
	privdata->dataSocket = privdata->cmdSocket = -1;
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

	return SMFIS_CONTINUE;
}

#ifdef	CL_DEBUG
static sfsistat
clamfi_helo(SMFICTX *ctx, char *helostring)
{
	logg("HELO '%s'\n", helostring);

	return SMFIS_CONTINUE;
}
#endif

static sfsistat
clamfi_envrcpt(SMFICTX *ctx, char **argv)
{
	struct privdata *privdata = (struct privdata *)smfi_getpriv(ctx);
	const char *to;

	logg("*clamfi_envrcpt: %s\n", argv[0]);

	if(privdata->to == NULL) {
		privdata->to = cli_malloc(sizeof(char *) * 2);

		assert(privdata->numTo == 0);
	} else
		privdata->to = cli_realloc(privdata->to, sizeof(char *) * (privdata->numTo + 2));

	if(privdata->to == NULL)
		return cl_error;

	to = smfi_getsymval(ctx, "{rcpt_addr}");
	if(to == NULL)
		to = argv[0];

	privdata->to[privdata->numTo] = strdup(to);
	privdata->to[++privdata->numTo] = NULL;

	return SMFIS_CONTINUE;
}

static sfsistat
clamfi_header(SMFICTX *ctx, char *headerf, char *headerv)
{
	struct privdata *privdata = (struct privdata *)smfi_getpriv(ctx);

#ifdef	CL_DEBUG
	if(debug_level >= 9)
		logg("*clamfi_header: %s: %s\n", headerf, headerv);
	else
		logg("*clamfi_header: %s\n", headerf);
#else
	logg("*clamfi_header: %s\n", headerf);
#endif

	/*
	 * The DATA instruction from SMTP (RFC2821) must have been sent
	 */
	privdata->rejectCode = "554";

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

	if(!useful_header(headerf)) {
		logg("*Discarded the header\n");
		return SMFIS_CONTINUE;
	}

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

#if	0
	/* Mailing lists often say our own posts are from us */
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
#endif

	if(clamfi_send(privdata, 1, "\n") != 1) {
		clamfi_cleanup(ctx);
		return cl_error;
	}

	if(black_hole_mode) {
		sfsistat rc = black_hole(privdata);

		if(rc != SMFIS_CONTINUE) {
			clamfi_cleanup(ctx);
			return rc;
		}
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

	/*
	 * TODO:
	 *	If not in external mode, call cli_scanbuff here
	 */
	/*
	 * Lines starting with From are changed to >From, to
	 *	avoid FP matches in the scanning code, which will speed it up
	 */
	if((len >= 6) && cli_memstr((char *)bodyp, len, "\nFrom ", 6)) {
		const char *ptr = (const char *)bodyp;
		int left = len;

		nbytes = 0;

		/*
		 * FIXME: sending one byte at a time down a socket is
		 *	inefficient
		 */
		do {
			if(*ptr == '\n') {
				/*
				 * FIXME: doesn't work if the \nFrom straddles
				 * multiple calls to clamfi_body
				 */
				if(strncmp(ptr, "\nFrom ", 6) == 0) {
					nbytes += clamfi_send(privdata, 7, "\n>From ");
					ptr += 6;
					left -= 6;
				} else {
					nbytes += clamfi_send(privdata, 1, "\n");
					ptr++;
					left--;
				}
			} else {
				nbytes += clamfi_send(privdata, 1, ptr++);
				left--;
			}
			if(left < 6) {
				nbytes += clamfi_send(privdata, left, ptr);
				break;
			}
		} while(left > 0);
	} else
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

		pthread_mutex_lock(&root_mutex);
		privdata->root = cl_dup(root);
		pthread_mutex_unlock(&root_mutex);
		if(privdata->root == NULL) {
			logg("!privdata->root == NULL\n");
			clamfi_cleanup(ctx);
			return cl_error;
		}
		switch(cl_scanfile(privdata->filename, &virname, NULL, privdata->root, &limits, options)) {
			case CL_CLEAN:
				if(logClean)
					logg("#%s: OK", privdata->filename);
				strcpy(mess, "OK");
				break;
			case CL_VIRUS:
				snprintf(mess, sizeof(mess), "%s: %s FOUND", privdata->filename, virname);
				logg("#%s", mess);
				break;
			default:
				snprintf(mess, sizeof(mess), "%s: %s ERROR", privdata->filename, cl_strerror(rc));
				logg("!%s", mess);
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
		long nbytes;

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

				if(r_gethostbyname(hostname, &hostent, buf, sizeof(buf)) == 0)
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

	/*
	 * TODO: it would be useful to add a header if mbox.c/FOLLOWURLS was
	 * exceeded
	 */
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
		 * FIXME: This will give false positives if the
		 *	word "FOUND" is in the email, e.g. the
		 *	quarantine directory is /tmp/VIRUSES-FOUND
		 */
		char reject[1024];
		char **to, *virusname;

		/*
		 * Remove the "FOUND" word, and the space before it
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
				 * Re-alloc if we are about run out of buffer
				 * space
				 *
				 * TODO: Only append *to if it's a valid, local
				 *	email address
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
				ptr = cli_strrcpy(ptr, " ");
				ptr = cli_strrcpy(ptr, *to);
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
				fputs(_("Subject: Virus intercepted\n"), sendmail);

				if(templateHeaders) {
					/*
					 * For example, to state the character
					 * set of the message:
					 *	Content-Type: text/plain; charset=koi8-r
					 *
					 * Based on a suggestion by Denis
					 *	Eremenko <moonshade@mail.kz>
					 */
					FILE *fin = fopen(templateHeaders, "r");

					if(fin == NULL) {
						perror(templateHeaders);
						if(use_syslog)
							syslog(LOG_ERR, _("Can't open e-mail template header file %s"),
								templateHeaders);
					} else {
						int c;
						int lastc = EOF;

						while((c = getc(fin)) != EOF) {
							putc(c, sendmail);
							lastc = c;
						}
						fclose(fin);
						/*
						 * File not new line terminated
						 */
						if(lastc != '\n')
							fputs(_("\n"), sendmail);
					}
				}

				fputs(_("\n"), sendmail);

				if((templateFile == NULL) ||
				   (sendtemplate(ctx, templateFile, sendmail, virusname) < 0)) {
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
					fprintf(sendmail, _("contained %s and has not been accepted for delivery.\n"), virusname);

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
						syslog(LOG_ERR, _("%s: Failed to notify clamAV interception - see dead.letter"), sendmailId);
			} else if(use_syslog)
				syslog(LOG_WARNING, _("Can't execute '%s' to send virus notice"), cmd);
		}

		if(report && (quarantine == NULL) && (!advisory) &&
		   (strstr(virusname, "Phishing") != NULL)) {
			for(to = privdata->to; *to; to++) {
				smfi_delrcpt(ctx, *to);
				smfi_addheader(ctx, "X-Original-To", *to);
			}
			if(smfi_addrcpt(ctx, report) == MI_FAILURE) {
				/* It's a remote site */
				if(privdata->filename) {
					char cmd[1024];

					snprintf(cmd, sizeof(cmd) - 1,
						"mail -s \"%s\" %s < %s",
						virusname, report,
						privdata->filename);
					if(system(cmd) == 0)
						logg(_("#Reported phishing to %s"), report);
					else
						logg(_("^Couldn't report to %s\n"), report);
				} else {
					logg(_("^Can't set anti-phish header\n"));
					rc = (privdata->discard) ? SMFIS_DISCARD : SMFIS_REJECT;
				}
				if((!rejectmail) || privdata->discard)
					rc = SMFIS_DISCARD;
				else
					rc = SMFIS_REJECT;
			} else {
				setsubject(ctx, "Phishing attempt trapped by ClamAV and redirected");

				logg("Redirected phish to %s\n", report);
			}
		} else if(quarantine) {
			for(to = privdata->to; *to; to++) {
				smfi_delrcpt(ctx, *to);
				smfi_addheader(ctx, "X-Original-To", *to);
			}
			/*
			 * NOTE: on a closed relay this will not work
			 * if the recipient is a remote address
			 */
			if(smfi_addrcpt(ctx, quarantine) == MI_FAILURE) {
				logg(_("^Can't set quarantine user %s"), quarantine);
				rc = (privdata->discard) ? SMFIS_DISCARD : SMFIS_REJECT;
			} else {
				if(report &&
				   strstr(virusname, "Phishing") != NULL)
					(void)smfi_addrcpt(ctx, report);
				setsubject(ctx, virusname);

				logg("Redirected virus to %s", quarantine);
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

		if(quarantine_dir) {
			/*
			 * Cleanup filename here otherwise clamfi_free() will
			 * delete the file that we wish to keep because it
			 * is infected
			 */
			free(privdata->filename);
			privdata->filename = NULL;
		}

		/*
		 * Don't drop the message if it's been forwarded to a
		 * quarantine email
		 */
		snprintf(reject, sizeof(reject) - 1, _("virus %s detected by ClamAV - http://www.clamav.net"), virusname);
		smfi_setreply(ctx, (char *)privdata->rejectCode, "5.7.1", reject);
		broadcast(mess);

		if(blacklist_time && privdata->ip[0]) {
			logg(_("Will blacklist %s for %d seconds because of %s\n"),
				privdata->ip, blacklist_time, virusname);
			pthread_mutex_lock(&blacklist_mutex);
			(void)tableUpdate(blacklist, privdata->ip,
				(int)time((time_t *)0));
			pthread_mutex_unlock(&blacklist_mutex);
		}
	} else if((strstr(mess, "OK") == NULL) && (strstr(mess, "Empty file") == NULL)) {
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
			 *
			 * Note that this is simple minded and isn't aware of
			 *	any MIME segments in the message. In practice
			 *	this means that the message will only display
			 *	on users' terminals if the message is
			 *	plain/text
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
	decrement_connections();

	cli_dbgmsg("clamfi_abort returns\n");

	return cl_error;
}

static sfsistat
clamfi_close(SMFICTX *ctx)
{
	logg("*clamfi_close\n");

	clamfi_cleanup(ctx);
	decrement_connections();

	return SMFIS_CONTINUE;
}

static void
clamfi_cleanup(SMFICTX *ctx)
{
	struct privdata *privdata = (struct privdata *)smfi_getpriv(ctx);

	cli_dbgmsg("clamfi_cleanup\n");

	if(privdata) {
		clamfi_free(privdata, 0);
		smfi_setpriv(ctx, NULL);
	}
}

static void
clamfi_free(struct privdata *privdata, int keep)
{
	cli_dbgmsg("clamfi_free\n");

	if(privdata) {
#ifdef	SESSION
		struct session *session;
#endif
		if(privdata->body)
			free(privdata->body);

		if(privdata->dataSocket >= 0)
			close(privdata->dataSocket);

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
		}

		if(privdata->from) {
#ifdef	CL_DEBUG
			if(debug_level >= 9)
				cli_dbgmsg("Free privdata->from\n");
#endif
			free(privdata->from);
		}

		if(privdata->subject)
			free(privdata->subject);
		if(privdata->sender)
			free(privdata->sender);

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
#if	0
				char buf[64];

				/*
				 * Flush the remote end so that clamd doesn't
				 * get a SIGPIPE
				 */
				if(readTimeout)
					while(clamd_recv(privdata->cmdSocket, buf, sizeof(buf)) > 0)
						;
#endif
				close(privdata->cmdSocket);
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

		if(keep) {
			memset(privdata, '\0', sizeof(struct privdata));
			privdata->dataSocket = privdata->cmdSocket = -1;
		} else
			free(privdata);
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
					logg(_("!write failure (%u bytes) to clamd: %s\n"),
						len, buf);
#else
					logg(_("!write failure (%u bytes) to clamd: %s\n"),
						len, strerror(errno));
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
static long
clamd_recv(int sock, char *buf, size_t len)
{
	struct timeval tv;
	long ret;

	assert(sock >= 0);

	if(readTimeout == 0) {
		do
			/* TODO: Needs a test for ssize_t in configure */
			ret = (long)recv(sock, buf, len, 0);
		while((ret < 0) && (errno == EINTR));

		return ret;
	}

	tv.tv_sec = readTimeout;
	tv.tv_usec = 0;

	for(;;) {
		fd_set rfds;

		FD_ZERO(&rfds);
		FD_SET(sock, &rfds);

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

		if(privdata->filename == NULL)
			return 0;

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
			free(privdata->filename);
			privdata->filename = NULL;
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
			assert(freeServer < (int)numServers);

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
		if(clamfi_send(privdata, 0,
		    "Received: by clamav-milter\nFrom: %s\n",
		    privdata->from) <= 0)
			return 0;

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
		free(buf);
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
 *
 * It's quicker if the quarantine directory is on the same filesystem
 *	as the temporary directory
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
		logg(_("!mkdir %s failed\n"), newname);
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
#if	defined(MSDOS) || defined(C_CYGWIN) || defined(C_WINDOWS) || defined(C_OS2)
		if(strchr("/*?<>|\\\"+=,;:\t ", *ptr))
#else
		if(*ptr == '/')
#endif
			*ptr = '_';
	}
	cli_dbgmsg("qfile move '%s' to '%s'\n", privdata->filename, newname);

	if(move(privdata->filename, newname) < 0) {
		logg(_("^Can't rename %1$s to %2$s\n"),
			privdata->filename, newname);
		free(newname);
		return -1;
	}
	free(privdata->filename);
	privdata->filename = newname;

	logg(_("Email quarantined as %s\n"), newname);

	return 0;
}

/*
 * Move oldfile to newfile using the fastest possible method
 */
static int
move(const char *oldfile, const char *newfile)
{
	int ret, c;
	FILE *fin, *fout;
#ifdef	C_LINUX
	struct stat statb;
	int in, out;
	off_t offset;
#endif

	ret = rename(oldfile, newfile);
	if(ret >= 0)
		return 0;

	if((ret < 0) && (errno != EXDEV)) {
		perror(newfile);
		return -1;
	}

#ifdef	C_LINUX	/* >= 2.2 */
	in = open(oldfile, O_RDONLY);
	if(in < 0) {
		perror(oldfile);
		return -1;
	}

	if(fstat(in, &statb) < 0) {
		perror(oldfile);
		close(in);
		return -1;
	}
	out = open(newfile, O_WRONLY|O_CREAT, 0600);
	if(out < 0) {
		perror(newfile);
		close(in);
		return -1;
	}
	offset = (off_t)0;
	ret = sendfile(out, in, &offset, statb.st_size);
	close(in);
	if(ret < 0) {
		/*
		 * Fall back if sendfile fails, which will happen on Linux
		 * 2.6 :-(. FreeBSD works correctly, so the ifdef should be
		 * fixed
		 */
		close(out);
		unlink(newfile);

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
	} else
		close(out);
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

#if	0
/*
 * TODO: gethostbyname_r is non-standard so different operating
 * systems do it in different ways. Need more examples
 * Perhaps we could use res_search()?
 * Perhaps we could use http://www.chiark.greenend.org.uk/~ian/adns/
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
#endif

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

	logg(_("!No response from any clamd server - your AV system is not scanning emails\n"));

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

	while(!quitting) {
		unsigned int i;
		struct timespec ts;
		struct timeval tp;
		struct session *session;

		gettimeofday(&tp, NULL);

		ts.tv_sec = tp.tv_sec + freshclam_monitor;
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
		pthread_mutex_unlock(&watchdog_mutex);
		cli_dbgmsg("watchdog wakes\n");

		if(check_and_reload_database() != 0) {
			if(cl_error != SMFIS_ACCEPT) {
				smfi_stop();
				return NULL;
			}
			logg(_("!No emails will be scanned"));
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

		/* Garbage collect IP addresses no longer blacklisted */
		if(blacklist) {
			pthread_mutex_lock(&blacklist_mutex);
			tableIterate(blacklist, timeoutBlacklist);
			pthread_mutex_unlock(&blacklist_mutex);
		}
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

	if((!blacklist_time) && external)
		return NULL;	/* no need for this thread */

	while(!quitting) {
		struct timespec ts;
		struct timeval tp;

		gettimeofday(&tp, NULL);

		ts.tv_sec = tp.tv_sec + freshclam_monitor;
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
		pthread_mutex_unlock(&watchdog_mutex);
		cli_dbgmsg("watchdog wakes\n");

		/*
		 * TODO: sanity check that if n_children == 0, that
		 * root->refcount == 0. Unfortunatly root->refcount isn't
		 * thread-safe, since it's governed by a mutex that we can't
		 * see, and there's no access to it via an approved method
		 */
		if(check_and_reload_database() != 0) {
			if(cl_error != SMFIS_ACCEPT) {
				smfi_stop();
				return NULL;
			}
			logg(_("!No emails will be scanned"));
		}
		/* Garbage collect IP addresses no longer blacklisted */
		if(blacklist) {
			pthread_mutex_lock(&blacklist_mutex);
			tableIterate(blacklist, timeoutBlacklist);
			pthread_mutex_unlock(&blacklist_mutex);
		}
	}
	cli_dbgmsg("watchdog quits\n");
	return NULL;
}
#endif

/*
 * Check to see if the database needs to be reloaded
 *	Return 0 for success
 */
static int
check_and_reload_database(void)
{
	int rc;

	if(external)
		return 0;

	switch(cl_statchkdir(&dbstat)) {
		case 1:
			logg("^Database has changed, loading updated database\n");
			cl_statfree(&dbstat);
			rc = loadDatabase();
			if(rc != 0) {
				logg("!Failed to load updated database\n");
				return rc;
			}
			break;
		case 0:
			logg("*Database has not changed\n");
			break;
		default:
			logg("Database error - %s is stopping\n", progname);
			return 1;
	}
	return 0;	/* all OK */
}

static void
timeoutBlacklist(char *ip_address, int time_of_blacklist)
{
	if(time_of_blacklist == 0)	/* Must not blacklist this IP address */
		return;
	if((time((time_t *)0) - time_of_blacklist) > blacklist_time)
		tableRemove(blacklist, ip_address);
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
	/*extern const char *cl_retdbdir(void);	/* FIXME: should be included */
	int ret;
	unsigned int signatures, dboptions;
	char *daily;
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
		if(((cpt = cfgopt(copt, "DatabaseDirectory")) || (cpt = cfgopt(copt, "DataDirectory"))) && cpt->enabled)
			dbdir = cpt->strarg;
		else
			dbdir = cl_retdbdir();
	}

	daily = cli_malloc(strlen(dbdir) + 22);
	sprintf(daily, "%s/daily.cvd", dbdir);
	if(access(daily, R_OK) < 0)
		sprintf(daily, "%s/daily.inc/daily.info", dbdir);

	cli_dbgmsg("loadDatabase: check %s for updates\n", daily);

	d = cl_cvdhead(daily);

	if(d) {
		char *ptr;
		time_t t = d->stime;
#ifdef	HAVE_CTIME_R_2
		char buf[26];

		snprintf(clamav_version, VERSION_LENGTH,
			"ClamAV %s/%d/%s", VERSION, d->version,
			ctime_r(&t, buf));
#else
		snprintf(clamav_version, VERSION_LENGTH,
			"ClamAV %s/%d/%s", VERSION, d->version, ctime(&t));
#endif

		/* Remove ctime's trailing \n */
		if((ptr = strchr(clamav_version, '\n')) != NULL)
			*ptr = '\0';

		cl_cvdfree(d);
	} else
		/* TODO: use dbdir/daily.inc/daily.info */
		snprintf(clamav_version, VERSION_LENGTH,
			"ClamAV version %s, clamav-milter version %s",
			VERSION, CM_VERSION);

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
	signatures = 0;
	newroot = NULL;
	dboptions = 0;

	if(!cfgopt(copt, "DetectPhishing")->enabled) {
		dboptions |= CL_DB_NOPHISHING;
		logg("Not loading phishing signatures.\n");
	}

	ret = cl_load(dbdir, &newroot, &signatures, dboptions);
	if(ret != 0) {
		logg("!%s\n", cl_strerror(ret));
		return -1;
	}
	if(newroot == NULL) {
		logg("!Can't initialize the virus database.\n");
		return -1;
	}

	ret = cl_build(newroot);
	if(ret != 0) {
		logg("!Database initialization error: %s\n", cl_strerror(ret));
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
		cl_free(oldroot);
		logg("#Database correctly reloaded (%u viruses)", signatures);
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

	logg("!Segmentation fault :-( Bye..\n");

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
 *
 * You wouldn't believe the amount of time I used to waste chasing bug reports
 *	from people who's sendmail.cf didn't tally with the arguments given to
 *	clamav-milter before I put this check in!
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
 * If the given email address is whitelisted don't scan emails to them,
 *	the addresses are in angle brackets e.g. <foo@bar.com>.
 *
 * TODO: Allow regular expressions in the addresses
 * TODO: Syntax check the contents of the files
 * TODO: Allow emails of the form "name <address>"
 * TODO: Allow emails not of the form "<address>", i.e. no angle brackets
 * TODO: Assume that if a '@' is missing from the address, that all emails
 *	to that domain are to be whitelisted
 */
static int
isWhitelisted(const char *emailaddress)
{
	static table_t *whitelist;	/* never freed */

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
				syslog(LOG_ERR, _("Can't open whitelist file %s"),
					whitelistFile);
			return 0;
		}
		whitelist = tableCreate();

		if(whitelist == NULL) {
			if(use_syslog)
				syslog(LOG_ERR, _("Can't create whitelist table"));
			fclose(fin);
			return 0;
		}

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

	return 0;
}

/*
 * Blacklist IP addresses that send malware. Often in the phishing world, one
 * phish is quickly followed by another. IP addresses are blacklisted for one
 * minute. We can't blacklist for longer since DHCP means we could hit innocent
 * parties, and in theory malware could go through a smart host and affect
 * innocent parties
 *
 * Note that sites which can't be blacklisted will have their timestamp set
 * to 0, since that can never be less than blacklist_time seconds from now
 */
static int
isBlacklisted(const char *ip_address)
{
	time_t t;

	if(blacklist_time == 0)
		/* Blacklisting not being used */
		return 0;

	cli_dbgmsg("isBlacklisted %s\n", ip_address);

	if(isLocalAddr(inet_addr(ip_address)))
		return 0;

	pthread_mutex_lock(&blacklist_mutex);
	if(blacklist == NULL) {
		blacklist = tableCreate();

		pthread_mutex_unlock(&blacklist_mutex);

		if(blacklist == NULL)
			if(use_syslog)
				syslog(LOG_ERR, _("Can't create blacklist table"));
		return 0;
	}
	t = tableFind(blacklist, ip_address);
	pthread_mutex_unlock(&blacklist_mutex);

	if(t == (time_t)-1)
		/* IP address is not blacklisted */
		return 0;

	if(t == (time_t)0)
		/* IP cannot be blacklisted */
		return 0;

	if((time((time_t *)0) - t) <= blacklist_time)
		return 1;

	/* timedout: remove the IP from the blacklist */
	pthread_mutex_lock(&blacklist_mutex);
	tableRemove(blacklist, ip_address);
	pthread_mutex_unlock(&blacklist_mutex);

	return 0;
}

#ifdef	HAVE_RESOLV_H
/*
 * Determine our MX peers, they must never be blacklisted
 * See RFC1034 for the definition of the record formats
 *
 * This is only ever called once, which is wrong, but the overheard of calling
 * this from the watchdog isn't worth it
 */
static void
mx(void)
{
	const u_char *p, *end;
	char name[MAXHOSTNAMELEN + 1];
	char buf[BUFSIZ];
	union {
		HEADER h;
		u_char u[PACKETSZ];
	} q;
	const HEADER *hp;
	int len, i, was_initialised;

	if(gethostname(name, sizeof(name)) < 0) {
		perror("gethostname");
		return;
	}

	if(blacklist == NULL) {
		blacklist = tableCreate();

		if(blacklist == NULL)
			return;
	}

	was_initialised = _res.options & RES_INIT;

	if((!was_initialised) && res_init() < 0)
		return;

	len = res_query(name, C_IN, T_MX, (u_char *)&q, sizeof(q));
	if(len < 0) {
		if(!was_initialised)
			res_close();
		return;	/* Host has no MX records */
	}

	if((unsigned int)len > sizeof(q)) {
		if(!was_initialised)
			res_close();
		return;
	}

	hp = &(q.h);
	p = q.u + HFIXEDSZ;
	end = q.u + len;

	for(i = ntohs(hp->qdcount); i--; p += len + QFIXEDSZ)
		if((len = dn_skipname(p, end)) < 0) {
			if(!was_initialised)
				res_close();
			return;
		}

	i = ntohs(hp->ancount);

	while((--i >= 0) && (p < end)) {
		in_addr_t addr;
		u_short type, pref;
		u_long ttl;	/* unused */

		if((len = dn_expand(q.u, end, p, buf, sizeof(buf) - 1)) < 0)
			break;
		p += len;
		GETSHORT(type, p);
		p += INT16SZ;
		GETLONG(ttl, p);
		GETSHORT(len, p);
		if(type != T_MX) {
			p += len;
			continue;
		}
		GETSHORT(pref, p);
		if((len = dn_expand(q.u, end, p, buf, sizeof(buf) - 1)) < 0)
			break;
		p += len;
		addr = inet_addr(buf);
#ifdef	INADDR_NONE
		if(addr != INADDR_NONE) {
#else
		if(addr != (in_addr_t)-1) {
#endif
			if(use_syslog)
				syslog(LOG_INFO, "Won't blacklist %s", buf);
			(void)tableInsert(blacklist, buf, 0);
		} else
			resolve(buf);
	}
	if(!was_initialised)
		res_close();
}

/*
 * If the MX record points to a name, we need to resolve that name. This routine
 * does that
 */
static void
resolve(const char *host)
{
	const u_char *p, *end;
	char buf[BUFSIZ];
	union {
		HEADER h;
		u_char u[PACKETSZ];
	} q;
	const HEADER *hp;
	int len, i;

	if((host == NULL) || (*host == '\0'))
		return;

	len = res_query(host, C_IN, T_A, (u_char *)&q, sizeof(q));
	if(len < 0)
		return;	/* Host has no A records */

	if((unsigned int)len > sizeof(q))
		return;

	hp = &(q.h);
	p = q.u + HFIXEDSZ;
	end = q.u + len;

	for(i = ntohs(hp->qdcount); i--; p += len + QFIXEDSZ)
		if((len = dn_skipname(p, end)) < 0)
			return;

	i = ntohs(hp->ancount);

	while((--i >= 0) && (p < end)) {
		u_short type;
		u_long ttl;
		struct in_addr addr;
		const char *ip;

		if((len = dn_expand(q.u, end, p, buf, sizeof(buf) - 1)) < 0)
			 return;
		p += len;
		GETSHORT(type, p);
		p += INT16SZ;
		GETLONG(ttl, p);	/* unused */
		GETSHORT(len, p);
		if(type != T_A) {
			p += len;
			continue;
		}
		memcpy(&addr, p, sizeof(struct in_addr));
		p += 4;
		ip = inet_ntoa(addr);
		if(ip) {
			if(use_syslog)
				syslog(LOG_INFO, "Won't blacklist %s", ip);
			(void)tableInsert(blacklist, ip, 0);
		}
	}
}
#else	/*!HAVE_RESOLV_H */
static void
mx(void)
{
	logg(_("^MX peers will not be immune from being blacklisted"));

	if(blacklist == NULL)
		blacklist = tableCreate();
}
#endif	/* HAVE_RESOLV_H */

static sfsistat
black_hole(const struct privdata *privdata)
{
	int must_scan;
	char **to;

	to = privdata->to;
	must_scan = (*to) ? 0 : 1;

	for(; *to; to++) {
		char cmd[128];
		FILE *sendmail;

		snprintf(cmd, sizeof(cmd) - 1, "%s -bv \"%s\" < /dev/null 2>&1",
			SENDMAIL_BIN, *to);

		cli_dbgmsg("Calling %s\n", cmd);
		sendmail = popen(cmd, "r");

		if(sendmail) {
			char buf[BUFSIZ];

			while(fgets(buf, sizeof(buf), sendmail) != NULL) {
				if(cli_chomp(buf) == 0)
					continue;

				cli_dbgmsg("sendmail output: %s\n", buf);

				if(strstr(buf, "... deliverable: mailer ")) {
					const char *p = strstr(buf, ", user ");

					if(strcmp(&p[7], "/dev/null") != 0) {
						must_scan = 1;
						break;
					}
				}
			}
			pclose(sendmail);
		} else if(use_syslog) {
			syslog(LOG_WARNING, _("Can't execute '%s' to expand '%s'"),
				cmd, *to);
			must_scan = 1;
		}
		if(must_scan)
			break;
	}
	if(!must_scan) {
		/* All recipients map to /dev/null */
		if(use_syslog) {
			to = privdata->to;
			if(*to)
				syslog(LOG_NOTICE, "discarded, since all recipients (e.g. \"%s\") are /dev/null", *to);
			else
				syslog(LOG_NOTICE, "discarded, since all recipients are /dev/null");
		}
		return SMFIS_DISCARD;
	}
	return SMFIS_CONTINUE;
}

/* See also libclamav/mbox.c */
static int
useful_header(const char *cmd)
{
	if(strcasecmp(cmd, "From") == 0)
		return 1;
	if(strcasecmp(cmd, "Received") == 0)
		return 1;
	if(strcasecmp(cmd, "Content-Type") == 0)
		return 1;
	if(strcasecmp(cmd, "Content-Transfer-Encoding") == 0)
		return 1;
	if(strcasecmp(cmd, "Content-Disposition") == 0)
		return 1;
	if(strcasecmp(cmd, "De") == 0)
		return 1;

	return 0;
}

static int
increment_connections(void)
{
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
			struct timeval now;
			struct timezone tz;

			logg((dont_wait) ?
					_("hit max-children limit (%u >= %u)\n") :
					_("hit max-children limit (%u >= %u): waiting for some to exit\n"),
				n_children, max_children);

			if(dont_wait) {
				pthread_mutex_unlock(&n_children_mutex);
				return 0;
			}
			/*
			 * Wait for an amount of time for a child to go
			 *
			 * Use pthread_cond_timedwait rather than
			 * pthread_cond_wait since the sendmail which
			 * calls us will have a timeout that we don't
			 * want to exceed, stops sendmail getting
			 * fidgety.
			 *
			 * Patch from Damian Menscher
			 * <menscher@uiuc.edu> to ensure it wakes up
			 * when a child goes away
			 */
			gettimeofday(&now, &tz);
			do {
				logg(_("n_children %d: waiting %d seconds for some to exit"),
					n_children, child_timeout);

				if(child_timeout == 0) {
					pthread_cond_wait(&n_children_cond, &n_children_mutex);
					rc = 0;
				} else {
					timeout.tv_sec = now.tv_sec + child_timeout;
					timeout.tv_nsec = 0;

					rc = pthread_cond_timedwait(&n_children_cond, &n_children_mutex, &timeout);
				}
			} while((n_children >= max_children) && (rc != ETIMEDOUT));
			logg(_("Finished waiting, n_children = %d\n"), n_children);
		}
		n_children++;

		cli_dbgmsg(">n_children = %d\n", n_children);
		pthread_mutex_unlock(&n_children_mutex);

		if(child_timeout && (rc == ETIMEDOUT))
			logg(_("*Timeout waiting for a child to die\n"));
	}

	return 1;
}

static void
decrement_connections(void)
{
	if(max_children > 0) {
		pthread_mutex_lock(&n_children_mutex);
		cli_dbgmsg("decrement_connections: n_children = %d\n", n_children);
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
}
