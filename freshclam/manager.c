/*
 *  Copyright (C) 2002 - 2006 Tomasz Kojm <tkojm@clamav.net>
 *  HTTP/1.1 compliance by Arkadiusz Miskiewicz <misiek@pld.org.pl>
 *  Proxy support by Nigel Horne <njh@bandsman.co.uk>
 *  Proxy authorization support by Gernot Tenchio <g.tenchio@telco-tech.de>
 *		     (uses fmt_base64() from libowfat (http://www.fefe.de))
 *  CDIFF code (C) 2006 Sensory Networks, Inc.
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
 */
 
#ifdef	_MSC_VER
#include <winsock.h>	/* only needed in CL_EXPERIMENTAL */
#endif
#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

/* for strptime, it is POSIX, but defining _XOPEN_SOURCE to 600
 * fails on Solaris because it would require a c99 compiler,
 * 500 fails completely on Solaris, and FreeBSD, and w/o _XOPEN_SOURCE
 * strptime is not defined on Linux */
#define _GNU_SOURCE
#define __EXTENSIONS

#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <string.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#include <ctype.h>
#ifndef C_WINDOWS
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#endif
#include <sys/types.h>
#ifndef C_WINDOWS
#include <sys/socket.h>
#include <sys/time.h>
#endif
#include <time.h>
#include <fcntl.h>
#include <sys/stat.h>
#ifndef C_WINDOWS
#include <dirent.h>
#endif
#include <errno.h>
#include <zlib.h>

#include "target.h"

#include "manager.h"
#include "notify.h"
#include "dns.h"
#include "execute.h"
#include "nonblock.h"
#include "mirman.h"

#include "shared/optparser.h"
#include "shared/output.h"
#include "shared/misc.h"
#include "shared/cdiff.h"
#include "shared/tar.h"

#include "libclamav/clamav.h"
#include "libclamav/others.h"
#include "libclamav/str.h"
#include "libclamav/cvd.h"

#ifndef	O_BINARY
#define	O_BINARY	0
#endif

#ifndef C_WINDOWS
#define	closesocket(s)	close(s)
#endif

#define CHDIR_ERR(x)				\
	if(chdir(x) == -1)			\
	    logg("!Can't chdir to %s\n", x);

#ifndef HAVE_GETADDRINFO
static const char *ghbn_err(int err) /* hstrerror() */
{
    switch(err) {
	case HOST_NOT_FOUND:
	    return "Host not found";

	case NO_DATA:
	    return "No IP address";

	case NO_RECOVERY:
	    return "Unrecoverable DNS error";

	case TRY_AGAIN:
	    return "Temporary DNS error";

	default:
	    return "Unknown error";
    }
}
#endif

static int getclientsock(const char *localip, int prot)
{
	int socketfd = -1;

#ifdef SUPPORT_IPv6
    if(prot == AF_INET6)
	socketfd = socket(AF_INET6, SOCK_STREAM, 0);
    else
#endif
	socketfd = socket(AF_INET, SOCK_STREAM, 0);
    if(socketfd < 0) {
	logg("!Can't create new socket\n");
	return -1;
    }

    if(localip) {
#ifdef HAVE_GETADDRINFO
	    struct addrinfo *res;
	    int ret;

	ret = getaddrinfo(localip, NULL, NULL, &res);
	if(ret) {
	    logg("!Could not resolve local ip address '%s': %s\n", localip, gai_strerror(ret));
	    logg("^Using standard local ip address and port for fetching.\n");
	} else {
		char ipaddr[46];

	    if(bind(socketfd, res->ai_addr, res->ai_addrlen) != 0) {
		logg("!Could not bind to local ip address '%s': %s\n", localip, strerror(errno));
		logg("^Using default client ip.\n");
	    } else {
		    void *addr;

#ifdef SUPPORT_IPv6
		if(res->ai_family == AF_INET6)
		    addr = &((struct sockaddr_in6 *) res->ai_addr)->sin6_addr;
		else
#endif
		    addr = &((struct sockaddr_in *) res->ai_addr)->sin_addr;

		if(inet_ntop(res->ai_family, addr, ipaddr, sizeof(ipaddr)))
		    logg("*Using ip '%s' for fetching.\n", ipaddr);
	    }
	    freeaddrinfo(res);
	}

#else /* IPv4 */
	    struct hostent *he;

	if(!(he = gethostbyname(localip))) {
	    logg("!Could not resolve local ip address '%s': %s\n", localip, ghbn_err(h_errno));
	    logg("^Using standard local ip address and port for fetching.\n");
	} else {
		struct sockaddr_in client;
		unsigned char *ia;
		char ipaddr[16];

	    memset((char *) &client, 0, sizeof(client));
	    client.sin_family = AF_INET;
	    client.sin_addr = *(struct in_addr *) he->h_addr_list[0];
	    if(bind(socketfd, (struct sockaddr *) &client, sizeof(struct sockaddr_in)) != 0) {
		logg("!Could not bind to local ip address '%s': %s\n", localip, strerror(errno));
		logg("^Using default client ip.\n");
	    } else {
		ia = (unsigned char *) he->h_addr_list[0];
		sprintf(ipaddr, "%u.%u.%u.%u", ia[0], ia[1], ia[2], ia[3]);
		logg("*Using ip '%s' for fetching.\n", ipaddr);
	    }
	}
#endif
    }

    return socketfd;
}

static int wwwconnect(const char *server, const char *proxy, int pport, char *ip, const char *localip, int ctimeout, struct mirdat *mdat, int logerr, unsigned int can_whitelist)
{
	int socketfd, port, ret;
	unsigned int ips = 0, ignored = 0;
#ifdef HAVE_GETADDRINFO
	struct addrinfo hints, *res = NULL, *rp, *loadbal_rp = NULL;
	char port_s[6], loadbal_ipaddr[46];
	uint32_t loadbal = 1, minsucc = 0xffffffff, minfail = 0xffffffff;
	struct mirdat_ip *md;
#else
	struct sockaddr_in name;
	struct hostent *host;
	unsigned char *ia;
	int i;
#endif
	char ipaddr[46];
	const char *hostpt;

    if(ip)
	strcpy(ip, "???");

    if(proxy) {
	hostpt = proxy;

	if(!(port = pport)) {
		const struct servent *webcache = getservbyname("webcache", "TCP");

		if(webcache)
			port = ntohs(webcache->s_port);
		else
			port = 8080;

#ifndef	C_WINDOWS
		endservent();
#endif
	}

    } else {
	hostpt = server;
	port = 80;
    }

#ifdef HAVE_GETADDRINFO
    memset(&hints, 0, sizeof(hints));
#ifdef SUPPORT_IPv6
    hints.ai_family = AF_UNSPEC;
#else
    hints.ai_family = AF_INET;
#endif
    hints.ai_socktype = SOCK_STREAM;
    snprintf(port_s, sizeof(port_s), "%d", port);
    port_s[sizeof(port_s) - 1] = 0;
    ret = getaddrinfo(hostpt, port_s, &hints, &res);
    if(ret) {
	logg("%cCan't get information about %s: %s\n", logerr ? '!' : '^', hostpt, gai_strerror(ret));
	return -1;
    }

    for(rp = res; rp; rp = rp->ai_next) {
	    void *addr;

	ips++;
#ifdef SUPPORT_IPv6
	if(rp->ai_family == AF_INET6)
	    addr = &((struct sockaddr_in6 *) rp->ai_addr)->sin6_addr;
	else
#endif
	    addr = &((struct sockaddr_in *) rp->ai_addr)->sin_addr;

	if(!inet_ntop(rp->ai_family, addr, ipaddr, sizeof(ipaddr))) {
	    logg("%cinet_ntop() failed\n", logerr ? '!' : '^');
	    freeaddrinfo(res);
	    return -1;
	}

	if(mdat && (ret = mirman_check(addr, rp->ai_family, mdat, &md))) {
	    if(ret == 1)
		logg("*Ignoring mirror %s (due to previous errors)\n", ipaddr);
	    else
		logg("*Ignoring mirror %s (has connected too many times with an outdated version)\n", ipaddr);

	    ignored++;
	    if(!loadbal || rp->ai_next)
		continue;
	}

	if(mdat && loadbal) {
	    if(!ret) {
		if(!md) {
		    loadbal_rp = rp;
		    strncpy(loadbal_ipaddr, ipaddr, sizeof(loadbal_ipaddr));
		} else {
		    if(md->succ < minsucc && md->fail <= minfail) {
			minsucc = md->succ;
			minfail = md->fail;
			loadbal_rp = rp;
			strncpy(loadbal_ipaddr, ipaddr, sizeof(loadbal_ipaddr));
		    }
		    if(rp->ai_next)
			continue;
		}
	    }

	    if(!loadbal_rp) {
		if(!rp->ai_next) {
		    loadbal = 0;
		    rp = res;
		}
		continue;
	    }
	    rp = loadbal_rp;
	    strncpy(ipaddr, loadbal_ipaddr, sizeof(ipaddr));

	} else if(loadbal_rp == rp) {
	    continue;
	}

	if(ip)
	    strcpy(ip, ipaddr);

	if(rp != res)
	    logg("Trying host %s (%s)...\n", hostpt, ipaddr);

	socketfd = getclientsock(localip, rp->ai_family);
	if(socketfd < 0) {
	    freeaddrinfo(res);
	    return -1;
	}

#ifdef SO_ERROR
	if(wait_connect(socketfd, rp->ai_addr, rp->ai_addrlen, ctimeout) == -1) {
#else
	if(connect(socketfd, rp->ai_addr, rp->ai_addrlen) == -1) {
#endif
	    logg("Can't connect to port %d of host %s (IP: %s)\n", port, hostpt, ipaddr);
	    closesocket(socketfd);
	    if(loadbal) {
		loadbal = 0;
		rp = res;
	    }
	    continue;
	} else {
	    if(mdat) {
		if(rp->ai_family == AF_INET)
		    mdat->currip[0] = *((uint32_t *) addr);
		else
		    memcpy(mdat->currip, addr, 4 * sizeof(uint32_t));
		mdat->af = rp->ai_family;
	    }
	    freeaddrinfo(res);
	    return socketfd;
	}
    }
    freeaddrinfo(res);

#else /* IPv4 */

    if((host = gethostbyname(hostpt)) == NULL) {
        logg("%cCan't get information about %s: %s\n", logerr ? '!' : '^', hostpt, ghbn_err(h_errno));
	return -1;
    }

    for(i = 0; host->h_addr_list[i] != 0; i++) {
	/* this dirty hack comes from pink - Nosuid TCP/IP ping 1.6 */
	ia = (unsigned char *) host->h_addr_list[i];
	sprintf(ipaddr, "%u.%u.%u.%u", ia[0], ia[1], ia[2], ia[3]);

	ips++;
	if(mdat && (ret = mirman_check(&((struct in_addr *) ia)->s_addr, AF_INET, mdat, NULL))) {
	    if(ret == 1)
		logg("*Ignoring mirror %s (due to previous errors)\n", ipaddr);
	    else
		logg("*Ignoring mirror %s (has connected too many times with an outdated version)\n", ipaddr);
	    ignored++;
	    continue;
	}

	if(ip)
	    strcpy(ip, ipaddr);

	if(i > 0)
	    logg("Trying host %s (%s)...\n", hostpt, ipaddr);

	memset ((char *) &name, 0, sizeof(name));
	name.sin_family = AF_INET;
	name.sin_addr = *((struct in_addr *) host->h_addr_list[i]);
	name.sin_port = htons(port);

	socketfd = getclientsock(localip, AF_INET);
	if(socketfd < 0)
	    return -1;

#ifdef SO_ERROR
	if(wait_connect(socketfd, (struct sockaddr *) &name, sizeof(struct sockaddr_in), ctimeout) == -1) {
#else
	if(connect(socketfd, (struct sockaddr *) &name, sizeof(struct sockaddr_in)) == -1) {
#endif
	    logg("Can't connect to port %d of host %s (IP: %s)\n", port, hostpt, ipaddr);
	    closesocket(socketfd);
	    continue;
	} else {
	    if(mdat) {
		mdat->currip[0] = ((struct in_addr *) ia)->s_addr;
		mdat->af = AF_INET;
	    }
	    return socketfd;
	}
    }
#endif

    if(mdat && can_whitelist && ips && (ips == ignored))
	mirman_whitelist(mdat, 1);

    return -2;
}

static const char *readbline(int fd, char *buf, int bufsize, int filesize, int *bread)
{
	char *pt;
	int ret, end;

    if(!*bread) {
	if(bufsize < filesize)
	    lseek(fd, -bufsize, SEEK_END);
	*bread = read(fd, buf, bufsize - 1);
	if(!*bread || *bread == -1)
	    return NULL;
	buf[*bread] = 0;
    }

    pt = strrchr(buf, '\n');
    if(!pt)
	return NULL;
    *pt = 0;
    pt = strrchr(buf, '\n');
    if(pt) {
	return ++pt;
    } else if(*bread == filesize) {
	return buf;
    } else {
	*bread -= strlen(buf) + 1;
	end = filesize - *bread;
	if(end < bufsize) {
	    if((ret = lseek(fd, 0, SEEK_SET)) != -1)
		ret = read(fd, buf, end);
	} else {
	    if((ret = lseek(fd, end - bufsize, SEEK_SET)) != -1)
		ret = read(fd, buf, bufsize - 1);
	}
	if(!ret || ret == -1)
	    return NULL;
	buf[ret] = 0;
	*bread += ret;
	pt = strrchr(buf, '\n');
	if(!pt)
	    return buf;
	*pt = 0;
	pt = strrchr(buf, '\n');
	if(pt)
	    return ++pt;
	else if(strlen(buf))
	    return buf;
	else 
	    return NULL;
    }
}

static unsigned int fmt_base64(char *dest, const char *src, unsigned int len)
{
	unsigned short bits = 0,temp = 0;
	unsigned long written = 0;
	unsigned int i;
	const char base64[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";


    for(i = 0; i < len; i++) {
	temp <<= 8;
	temp += src[i];
	bits += 8;
	while(bits > 6) {
	    dest[written] = base64[((temp >> (bits - 6)) & 63)];
	    written++;
	    bits -= 6;
	}
    }

    if(bits) {
	temp <<= (6 - bits);
	dest[written] = base64[temp & 63];
	written++;
    }

    while(written & 3) {
	dest[written] = '=';
	written++;
    }

    return written;
}

static char *proxyauth(const char *user, const char *pass)
{
	int len;
	char *buf, *userpass, *auth;


    userpass = malloc(strlen(user) + strlen(pass) + 2);
    if(!userpass) {
	logg("!proxyauth: Can't allocate memory for 'userpass'\n");
	return NULL;
    }
    sprintf(userpass, "%s:%s", user, pass);

    buf = malloc((strlen(pass) + strlen(user)) * 2 + 4);
    if(!buf) {
	logg("!proxyauth: Can't allocate memory for 'buf'\n");
	free(userpass);
	return NULL;
    }

    len = fmt_base64(buf, userpass, strlen(userpass));
    free(userpass);
    buf[len] = '\0';
    auth = malloc(strlen(buf) + 30);
    if(!auth) {
	free(buf);
	logg("!proxyauth: Can't allocate memory for 'authorization'\n");
	return NULL;
    }

    sprintf(auth, "Proxy-Authorization: Basic %s\r\n", buf);
    free(buf);

    return auth;
}

/*
 * TODO:
 * - strptime() is most likely not portable enough
 */
int submitstats(const char *clamdcfg, const struct optstruct *opts)
{
	int fd, sd, bread, lread = 0, cnt, ret;
	char post[SUBMIT_MIN_ENTRIES * 256 + 512];
	char query[SUBMIT_MIN_ENTRIES * 256];
	char buff[512], statsdat[512], newstatsdat[512], uastr[128];
	char logfile[256], fbuff[FILEBUFF];
	char *pt, *pt2, *auth = NULL;
	const char *line, *country = NULL, *user, *proxy = NULL;
	struct optstruct *clamdopt;
	const struct optstruct *opt;
	struct stat sb;
	struct tm tms;
	time_t epoch;
	unsigned int qcnt, entries, submitted = 0, permfail = 0, port = 0;


    if((opt = optget(opts, "DetectionStatsCountry"))->enabled) {
	if(strlen(opt->strarg) != 2 || !isalpha(opt->strarg[0]) || !isalpha(opt->strarg[1])) {
	    logg("!SubmitDetectionStats: DetectionStatsCountry requires a two-letter country code\n");
	    return 56;
	}
	country = opt->strarg;
    }

    if(!(clamdopt = optparse(clamdcfg, 0, NULL, 1, OPT_CLAMD, 0, NULL))) {
	logg("!SubmitDetectionStats: Can't open or parse configuration file %s\n", clamdcfg);
	return 56;
    }

    if(!(opt = optget(clamdopt, "LogFile"))->enabled) {
	logg("!SubmitDetectionStats: LogFile needs to be enabled in %s\n", clamdcfg);
	optfree(clamdopt);
	return 56;
    }
    strncpy(logfile, opt->strarg, sizeof(logfile));
    logfile[sizeof(logfile) - 1] = 0;

    if(!optget(clamdopt, "LogTime")->enabled) {
	logg("!SubmitDetectionStats: LogTime needs to be enabled in %s\n", clamdcfg);
	optfree(clamdopt);
	return 56;
    }
    optfree(clamdopt);

    if((fd = open("stats.dat", O_RDONLY)) != -1) {
	if((bread = read(fd, statsdat, sizeof(statsdat) - 1)) == -1) {
	    logg("^SubmitDetectionStats: Can't read stats.dat\n");
	    bread = 0;
	}
	statsdat[bread] = 0;
	close(fd);
    } else {
	*statsdat = 0;
    }

    if((fd = open(logfile, O_RDONLY)) == -1) {
	logg("!SubmitDetectionStats: Can't open %s for reading\n", logfile);
	return 56;
    }

    if(fstat(fd, &sb) == -1) {
	logg("!SubmitDetectionStats: fstat() failed\n");
	close(fd);
	return 56;
    }

    while((line = readbline(fd, fbuff, FILEBUFF, sb.st_size, &lread)))
	if(strlen(line) >= 32 && !strcmp(&line[strlen(line) - 6], " FOUND"))
	    break;

    if(!line) {
	logg("SubmitDetectionStats: No detection records found\n");
	close(fd);
	return 1;
    }

    if(*statsdat && !strcmp(line, statsdat)) {
	logg("SubmitDetectionStats: No new detection records found\n");
	close(fd);
	return 1;
    } else {
	strncpy(newstatsdat, line, sizeof(newstatsdat));
    }

    if((opt = optget(opts, "HTTPUserAgent"))->enabled)
	strncpy(uastr, opt->strarg, sizeof(uastr));
    else
	snprintf(uastr, sizeof(uastr), PACKAGE"/%s (OS: "TARGET_OS_TYPE", ARCH: "TARGET_ARCH_TYPE", CPU: "TARGET_CPU_TYPE")%s%s", get_version(), country ? ":" : "", country ? country : "");
    uastr[sizeof(uastr) - 1] = 0;

    if((opt = optget(opts, "HTTPProxyServer"))->enabled) {
	proxy = opt->strarg;
	if(!strncasecmp(proxy, "http://", 7))
	    proxy += 7;

	if((opt = optget(opts, "HTTPProxyUsername"))->enabled) {
	    user = opt->strarg;
	    if(!(opt = optget(opts, "HTTPProxyPassword"))->enabled) {
		logg("!SubmitDetectionStats: HTTPProxyUsername requires HTTPProxyPassword\n");
		close(fd);
		return 56;
	    }
	    auth = proxyauth(user, opt->strarg);
	    if(!auth) {
		close(fd);
		return 56;
	    }
	}

	if((opt = optget(opts, "HTTPProxyPort"))->enabled)
	    port = opt->numarg;

	logg("*Connecting via %s\n", proxy);
    }

    ret = 0;
    memset(query, 0, sizeof(query));
    qcnt = 0;
    entries = 0;
    do {
	if(strlen(line) < 32 || strcmp(&line[strlen(line) - 6], " FOUND"))
	    continue;

	if(*statsdat && !strcmp(line, statsdat))
	    break;

	strncpy(buff, line, sizeof(buff));
	buff[sizeof(buff) - 1] = 0;

	if(!(pt = strstr(buff, " -> "))) {
	    logg("*SubmitDetectionStats: Skipping detection entry logged without time\b");
	    continue;
	}
	*pt = 0;
	pt += 4;

	if(!strptime(buff, "%a %b  %d %H:%M:%S %Y", &tms) || (epoch = mktime(&tms)) == -1) {
	    logg("!SubmitDetectionStats: Failed to convert date string\n");
	    ret = 1;
	    break;
	}

	pt2 = &pt[strlen(pt) - 6];
	*pt2 = 0;

	if(!(pt2 = strrchr(pt, ':'))) {
	    logg("!SubmitDetectionStats: Incorrect format of the log file (1)\n");
	    ret = 1;
	    break;
	}
	*pt2 = 0;
	pt2 += 2;

#ifdef C_WINDOWS
	if((pt = strrchr(pt, '\\')))
#else
	if((pt = strrchr(pt, '/')))
#endif
	    *pt++ = 0;
	if(!pt)
	    pt = (char*) "NOFNAME";

	qcnt += snprintf(&query[qcnt], sizeof(query) - qcnt, "ts[]=%u&fname[]=%s&virus[]=%s&", (unsigned int) epoch, pt, pt2);
	entries++;

	if(entries == SUBMIT_MIN_ENTRIES) {
	    sd = wwwconnect("stats.clamav.net", proxy, port, NULL, optget(opts, "LocalIPAddress")->strarg, optget(opts, "ConnectTimeout")->numarg, NULL, 0, 0);
	    if(sd == -1) {
		logg("!SubmitDetectionStats: Can't connect to server\n");
		ret = 52;
		break;
	    }

	    query[sizeof(query) - 1] = 0;
	    snprintf(post, sizeof(post),
		"POST http://stats.clamav.net/submit.php HTTP/1.0\r\n"
		"Host: stats.clamav.net\r\n%s"
		"Content-Type: application/x-www-form-urlencoded\r\n"
		"User-Agent: %s\r\n"
		"Content-Length: %u\r\n\n"
		"%s",
	    auth ? auth : "", uastr, (unsigned int) strlen(query), query);

	    if(send(sd, post, strlen(post), 0) < 0) {
		logg("!SubmitDetectionStats: Can't write to socket\n");
		ret = 52;
		closesocket(sd);
		break;
	    }

	    pt = post;
	    cnt = sizeof(post) - 1;
#ifdef SO_ERROR
	    while((bread = wait_recv(sd, pt, cnt, 0, optget(opts, "ReceiveTimeout")->numarg)) > 0) {
#else
	    while((bread = recv(sd, pt, cnt, 0)) > 0) {
#endif
		pt += bread;
		cnt -= bread;
		if(cnt <= 0)
		    break;
	    }
	    *pt = 0;
	    closesocket(sd);

	    if(bread < 0) {
		logg("!SubmitDetectionStats: Can't read from socket\n");
		ret = 52;
		break;
	    }

	    if(strstr(post, "SUBMIT_OK")) {
		submitted += entries;
		if(submitted + SUBMIT_MIN_ENTRIES > SUBMIT_MAX_ENTRIES)
		    break;
		qcnt = 0;
		entries = 0;
		memset(query, 0, sizeof(query));
		continue;
	    }

	    ret = 52;
	    if((pt = strstr(post, "SUBMIT_PERMANENT_FAILURE"))) {
		if(!submitted) {
		    permfail = 1;
		    if((pt + 32 <= post + sizeof(post)) && pt[24] == ':')
			logg("!SubmitDetectionStats: Remote server reported permanent failure: %s\n", &pt[25]);
		    else
			logg("!SubmitDetectionStats: Remote server reported permanent failure\n");
		}
	    } else if((pt = strstr(post, "SUBMIT_TEMPORARY_FAILURE"))) {
		if(!submitted) {
		    if((pt + 32 <= post + sizeof(post)) && pt[24] == ':')
			logg("!SubmitDetectionStats: Remote server reported temporary failure: %s\n", &pt[25]);
		    else
			logg("!SubmitDetectionStats: Remote server reported temporary failure\n");
		}
	    } else {
		if(!submitted)
		    logg("!SubmitDetectionStats: Incorrect answer from server\n");
	    }

	    break;
	}

    } while((line = readbline(fd, fbuff, FILEBUFF, sb.st_size, &lread)));

    close(fd);
    if(auth)
	free(auth);

    if(submitted || permfail) {
	if((fd = open("stats.dat", O_WRONLY | O_CREAT | O_TRUNC, 0600)) == -1) {
	    logg("^SubmitDetectionStats: Can't open stats.dat for writing\n");
	} else {
	    if((bread = write(fd, newstatsdat, sizeof(newstatsdat))) != sizeof(newstatsdat))
		logg("^SubmitDetectionStats: Can't write to stats.dat\n");
	    close(fd);
	}
    }

    if(ret == 0) {
	if(!submitted)
	    logg("SubmitDetectionStats: Not enough recent data for submission\n");
	else
	    logg("SubmitDetectionStats: Submitted %u records\n", submitted);
    }

    return ret;
}

static int Rfc2822DateTime(char *buf, time_t mtime)
{
	struct tm *gmt;

    gmt = gmtime(&mtime);
    return strftime(buf, 36, "%a, %d %b %Y %X GMT", gmt);
}

static struct cl_cvd *remote_cvdhead(const char *cvdfile, const char *localfile, const char *hostname, char *ip, const char *localip, const char *proxy, int port, const char *user, const char *pass, const char *uas, int *ims, int ctimeout, int rtimeout, struct mirdat *mdat, int logerr, unsigned int can_whitelist)
{
	char cmd[512], head[513], buffer[FILEBUFF], ipaddr[46], *ch, *tmp;
	int bread, cnt, sd;
	unsigned int i, j;
	char *remotename = NULL, *authorization = NULL;
	struct cl_cvd *cvd;
	char last_modified[36], uastr[128];


    if(proxy) {
        remotename = malloc(strlen(hostname) + 8);
	if(!remotename) {
	    logg("!remote_cvdhead: Can't allocate memory for 'remotename'\n");
	    return NULL;
	}
        sprintf(remotename, "http://%s", hostname);

	if(user) {
	    authorization = proxyauth(user, pass);
	    if(!authorization) {
		free(remotename);
		return NULL;
	    }
	}
    }

    if(!access(localfile, R_OK)) {
	cvd = cl_cvdhead(localfile);
	if(!cvd) {
	    logg("!remote_cvdhead: Can't parse file %s\n", localfile);
	    free(remotename);
	    free(authorization);
	    return NULL;
	}
	Rfc2822DateTime(last_modified, (time_t) cvd->stime);
	cl_cvdfree(cvd);
    } else {
	    time_t mtime = 1104119530;

	Rfc2822DateTime(last_modified, mtime);
	logg("*Assuming modification time in the past\n");
    }

    logg("*If-Modified-Since: %s\n", last_modified);

    logg("Reading CVD header (%s): ", cvdfile);

    if(uas)
	strncpy(uastr, uas, sizeof(uastr));
    else
	snprintf(uastr, sizeof(uastr), PACKAGE"/%s (OS: "TARGET_OS_TYPE", ARCH: "TARGET_ARCH_TYPE", CPU: "TARGET_CPU_TYPE")", get_version());
    uastr[sizeof(uastr) - 1] = 0;

    snprintf(cmd, sizeof(cmd),
	"GET %s/%s HTTP/1.0\r\n"
	"Host: %s\r\n%s"
	"User-Agent: %s\r\n"
	"Connection: close\r\n"
	"Range: bytes=0-511\r\n"
        "If-Modified-Since: %s\r\n"
        "\r\n", (remotename != NULL) ? remotename : "", cvdfile, hostname, (authorization != NULL) ? authorization : "", uastr, last_modified);

    free(remotename);
    free(authorization);

    memset(ipaddr, 0, sizeof(ipaddr));

    if(ip[0]) /* use ip to connect */
	sd = wwwconnect(ip, proxy, port, ipaddr, localip, ctimeout, mdat, logerr, can_whitelist);
    else
	sd = wwwconnect(hostname, proxy, port, ipaddr, localip, ctimeout, mdat, logerr, can_whitelist);

    if(sd < 0) {
	return NULL;
    } else {
	logg("*Connected to %s (IP: %s).\n", hostname, ipaddr);
	logg("*Trying to retrieve CVD header of http://%s/%s\n", hostname, cvdfile);
    }

    if(!ip[0])
	strcpy(ip, ipaddr);

    if(send(sd, cmd, strlen(cmd), 0) < 0) {
	logg("%cremote_cvdhead: write failed\n", logerr ? '!' : '^');
	closesocket(sd);
	return NULL;
    }

    tmp = buffer;
    cnt = FILEBUFF;
#ifdef SO_ERROR
    while((bread = wait_recv(sd, tmp, cnt, 0, rtimeout)) > 0) {
#else
    while((bread = recv(sd, tmp, cnt, 0)) > 0) {
#endif
	tmp += bread;
	cnt -= bread;
	if(cnt <= 0)
	    break;
    }
    closesocket(sd);

    if(bread == -1) {
	logg("%cremote_cvdhead: Error while reading CVD header from %s\n", logerr ? '!' : '^', hostname);
	mirman_update(mdat->currip, mdat->af, mdat, 1);
	return NULL;
    }

    if((strstr(buffer, "HTTP/1.1 404")) != NULL || (strstr(buffer, "HTTP/1.0 404")) != NULL) { 
	logg("%cCVD file not found on remote server\n", logerr ? '!' : '^');
	mirman_update(mdat->currip, mdat->af, mdat, 2);
	return NULL;
    }

    /* check whether the resource is up-to-date */
    if((strstr(buffer, "HTTP/1.1 304")) != NULL || (strstr(buffer, "HTTP/1.0 304")) != NULL) { 
	*ims = 0;
	logg("OK (IMS)\n");
	mirman_update(mdat->currip, mdat->af, mdat, 0);
	return NULL;
    } else {
	*ims = 1;
    }

    if(!strstr(buffer, "HTTP/1.1 200") && !strstr(buffer, "HTTP/1.0 200") &&
       !strstr(buffer, "HTTP/1.1 206") && !strstr(buffer, "HTTP/1.0 206")) {
	logg("%cUnknown response from remote server\n", logerr ? '!' : '^');
	mirman_update(mdat->currip, mdat->af, mdat, 1);
	return NULL;
    }

    i = 3;
    ch = buffer + i;
    while(i < sizeof(buffer)) {
	if (*ch == '\n' && *(ch - 1) == '\r' && *(ch - 2) == '\n' && *(ch - 3) == '\r') {
	    ch++;
	    i++;
	    break;
	}
	ch++;
	i++;
    }

    if(sizeof(buffer) - i < 512) {
	logg("%cremote_cvdhead: Malformed CVD header (too short)\n", logerr ? '!' : '^');
	mirman_update(mdat->currip, mdat->af, mdat, 1);
	return NULL;
    }

    memset(head, 0, sizeof(head));

    for(j = 0; j < 512; j++) {
	if(!ch || (ch && !*ch) || (ch && !isprint(ch[j]))) {
	    logg("%cremote_cvdhead: Malformed CVD header (bad chars)\n", logerr ? '!' : '^');
	    mirman_update(mdat->currip, mdat->af, mdat, 1);
	    return NULL;
	}
	head[j] = ch[j];
    }

    if(!(cvd = cl_cvdparse(head))) {
	logg("%cremote_cvdhead: Malformed CVD header (can't parse)\n", logerr ? '!' : '^');
	mirman_update(mdat->currip, mdat->af, mdat, 1);
    } else {
	logg("OK\n");
	mirman_update(mdat->currip, mdat->af, mdat, 0);
    }

    return cvd;
}

static int getfile(const char *srcfile, const char *destfile, const char *hostname, char *ip, const char *localip, const char *proxy, int port, const char *user, const char *pass, const char *uas, int ctimeout, int rtimeout, struct mirdat *mdat, int logerr, unsigned int can_whitelist)
{
	char cmd[512], uastr[128], buffer[FILEBUFF], *ch;
	int bread, fd, totalsize = 0,  rot = 0, totaldownloaded = 0,
	    percentage = 0, sd;
	unsigned int i;
	char *remotename = NULL, *authorization = NULL, *headerline, ipaddr[46];
	const char *rotation = "|/-\\";


    if(proxy) {
        remotename = malloc(strlen(hostname) + 8);
	if(!remotename) {
	    logg("!getfile: Can't allocate memory for 'remotename'\n");
	    return 75; /* FIXME */
	}
        sprintf(remotename, "http://%s", hostname);

	if(user) {
	    authorization = proxyauth(user, pass);
	    if(!authorization) {
		free(remotename);
		return 75; /* FIXME */
	    }
	}
    }

    if(uas)
	strncpy(uastr, uas, sizeof(uastr));
    else
	snprintf(uastr, sizeof(uastr), PACKAGE"/%s (OS: "TARGET_OS_TYPE", ARCH: "TARGET_ARCH_TYPE", CPU: "TARGET_CPU_TYPE")", get_version());
    uastr[sizeof(uastr) - 1] = 0;

    snprintf(cmd, sizeof(cmd),
	"GET %s/%s HTTP/1.0\r\n"
	"Host: %s\r\n%s"
	"User-Agent: %s\r\n"
#ifdef FRESHCLAM_NO_CACHE
	"Cache-Control: no-cache\r\n"
#endif
	"Connection: close\r\n"
	"\r\n", (remotename != NULL) ? remotename : "", srcfile, hostname, (authorization != NULL) ? authorization : "", uastr);

    if(remotename)
	free(remotename);

    if(authorization)
	free(authorization);

    memset(ipaddr, 0, sizeof(ipaddr));
    if(ip[0]) /* use ip to connect */
	sd = wwwconnect(ip, proxy, port, ipaddr, localip, ctimeout, mdat, logerr, can_whitelist);
    else
	sd = wwwconnect(hostname, proxy, port, ipaddr, localip, ctimeout, mdat, logerr, can_whitelist);

    if(sd < 0) {
	return 52;
    } else {
	logg("*Trying to download http://%s/%s (IP: %s)\n", hostname, srcfile, ipaddr);
    }

    if(!ip[0])
	strcpy(ip, ipaddr);

    if(send(sd, cmd, strlen(cmd), 0) < 0) {
	logg("%cgetfile: Can't write to socket\n", logerr ? '!' : '^');
	closesocket(sd);
	return 52;
    }

    /* read http headers */
    ch = buffer;
    i = 0;
    while(1) {
	/* recv one byte at a time, until we reach \r\n\r\n */
#ifdef SO_ERROR
	if((i >= sizeof(buffer) - 1) || wait_recv(sd, buffer + i, 1, 0, rtimeout) == -1) {
#else
	if((i >= sizeof(buffer) - 1) || recv(sd, buffer + i, 1, 0) == -1) {
#endif
	    logg("%cgetfile: Error while reading database from %s (IP: %s)\n", logerr ? '!' : '^', hostname, ipaddr);
	    mirman_update(mdat->currip, mdat->af, mdat, 1);
	    closesocket(sd);
	    return 52;
	}

	if(i > 2 && *ch == '\n' && *(ch - 1) == '\r' && *(ch - 2) == '\n' && *(ch - 3) == '\r') {
	    i++;
	    break;
	}
	ch++;
	i++;
    }

    buffer[i] = 0;

    /* check whether the resource actually existed or not */
    if((strstr(buffer, "HTTP/1.1 404")) != NULL || (strstr(buffer, "HTTP/1.0 404")) != NULL) { 
	logg("^getfile: %s not found on remote server (IP: %s)\n", srcfile, ipaddr);
	mirman_update(mdat->currip, mdat->af, mdat, 2);
	closesocket(sd);
	return 58;
    }

    if(!strstr(buffer, "HTTP/1.1 200") && !strstr(buffer, "HTTP/1.0 200") &&
       !strstr(buffer, "HTTP/1.1 206") && !strstr(buffer, "HTTP/1.0 206")) {
	logg("%cgetfile: Unknown response from remote server (IP: %s)\n", logerr ? '!' : '^', ipaddr);
	mirman_update(mdat->currip, mdat->af, mdat, 1);
	closesocket(sd);
	return 58;
    }

    /* get size of resource */
    for(i = 0; (headerline = cli_strtok(buffer, i, "\n")); i++){
        if(strstr(headerline, "Content-Length:")) { 
	    if((ch = cli_strtok(headerline, 1, ": "))) {
		totalsize = atoi(ch);
		free(ch);
	    } else {
		totalsize = 0;
	    }
        }
	free(headerline);
    }

    if((fd = open(destfile, O_WRONLY|O_CREAT|O_EXCL|O_BINARY, 0644)) == -1) {
	    char currdir[512];

	if(getcwd(currdir, sizeof(currdir)))
	    logg("!getfile: Can't create new file %s in %s\n", destfile, currdir);
	else
	    logg("!getfile: Can't create new file %s in the current directory\n", destfile);

	logg("Hint: The database directory must be writable for UID %d or GID %d\n", getuid(), getgid());
	closesocket(sd);
	return 57;
    }

#ifdef SO_ERROR
    while((bread = wait_recv(sd, buffer, FILEBUFF, 0, rtimeout)) > 0) {
#else
    while((bread = recv(sd, buffer, FILEBUFF, 0)) > 0) {
#endif
        if(write(fd, buffer, bread) != bread) {
	    logg("getfile: Can't write %d bytes to %s\n", bread, destfile);
	    unlink(destfile);
	    close(fd);
	    closesocket(sd);
	    return 57; /* FIXME */
	}

        if(totalsize > 0) {
	    totaldownloaded += bread;
            percentage = (int) (100 * (float) totaldownloaded / totalsize);
	}

        if(!mprintf_quiet) {
            if(totalsize > 0) {
                mprintf("Downloading %s [%3i%%]\r", srcfile, percentage);
            } else {
                mprintf("Downloading %s [%c]\r", srcfile, rotation[rot]);
                rot++;
                rot %= 4;
            }
            fflush(stdout);
        }
    }
    closesocket(sd);
    close(fd);

    if(totalsize > 0)
        logg("Downloading %s [%i%%]\n", srcfile, percentage);
    else
        logg("Downloading %s [*]\n", srcfile);

    mirman_update(mdat->currip, mdat->af, mdat, 0);
    return 0;
}

static int getcvd(const char *cvdfile, const char *newfile, const char *hostname, char *ip, const char *localip, const char *proxy, int port, const char *user, const char *pass, const char *uas, unsigned int newver, int ctimeout, int rtimeout, struct mirdat *mdat, int logerr, unsigned int can_whitelist)
{
	struct cl_cvd *cvd;
	int ret;


    logg("*Retrieving http://%s/%s\n", hostname, cvdfile);
    if((ret = getfile(cvdfile, newfile, hostname, ip, localip, proxy, port, user, pass, uas, ctimeout, rtimeout, mdat, logerr, can_whitelist))) {
        logg("%cCan't download %s from %s\n", logerr ? '!' : '^', cvdfile, hostname);
        unlink(newfile);
        return ret;
    }

    if((ret = cl_cvdverify(newfile))) {
        logg("!Verification: %s\n", cl_strerror(ret));
        unlink(newfile);
        return 54;
    }

    if(!(cvd = cl_cvdhead(newfile))) {
	logg("!Can't read CVD header of new %s database.\n", cvdfile);
	unlink(newfile);
	return 54;
    }

    if(cvd->version < newver) {
	logg("^Mirror %s is not synchronized.\n", ip);
	mirman_update(mdat->currip, mdat->af, mdat, 2);
    	cl_cvdfree(cvd);
	unlink(newfile);
	return 59;
    }

    cl_cvdfree(cvd);
    return 0;
}

static int chdir_tmp(const char *dbname, const char *tmpdir)
{
	char cvdfile[32];


    if(access(tmpdir, R_OK|W_OK) == -1) {
	sprintf(cvdfile, "%s.cvd", dbname);
	if(access(cvdfile, R_OK) == -1) {
	    sprintf(cvdfile, "%s.cld", dbname);
	    if(access(cvdfile, R_OK) == -1) {
		logg("!chdir_tmp: Can't access local %s database\n", dbname);
		return -1;
	    }
	}

	if(mkdir(tmpdir, 0755) == -1) {
	    logg("!chdir_tmp: Can't create directory %s\n", tmpdir);
	    return -1;
	}

	if(cli_cvdunpack(cvdfile, tmpdir) == -1) {
	    logg("!chdir_tmp: Can't unpack %s into %s\n", cvdfile, tmpdir);
	    cli_rmdirs(tmpdir);
	    return -1;
	}
    }

    if(chdir(tmpdir) == -1) {
	logg("!chdir_tmp: Can't change directory to %s\n", tmpdir);
	return -1;
    }

    return 0;
}

static int getpatch(const char *dbname, const char *tmpdir, int version, const char *hostname, char *ip, const char *localip, const char *proxy, int port, const char *user, const char *pass, const char *uas, int ctimeout, int rtimeout, struct mirdat *mdat, int logerr, unsigned int can_whitelist)
{
	char *tempname, patch[32], olddir[512];
	int ret, fd;


    if(!getcwd(olddir, sizeof(olddir))) {
	logg("!getpatch: Can't get path of current working directory\n");
	return 50; /* FIXME */
    }

    if(chdir_tmp(dbname, tmpdir) == -1)
	return 50;

    tempname = cli_gentemp(".");
    snprintf(patch, sizeof(patch), "%s-%d.cdiff", dbname, version);

    logg("*Retrieving http://%s/%s\n", hostname, patch);
    if((ret = getfile(patch, tempname, hostname, ip, localip, proxy, port, user, pass, uas, ctimeout, rtimeout, mdat, logerr, can_whitelist))) {
        logg("%cgetpatch: Can't download %s from %s\n", logerr ? '!' : '^', patch, hostname);
        unlink(tempname);
        free(tempname);
	CHDIR_ERR(olddir);
        return ret;
    }

    if((fd = open(tempname, O_RDONLY|O_BINARY)) == -1) {
	logg("!getpatch: Can't open %s for reading\n", tempname);
        unlink(tempname);
        free(tempname);
	CHDIR_ERR(olddir);
	return 55;
    }

    if(cdiff_apply(fd, 1) == -1) {
	logg("!getpatch: Can't apply patch\n");
	close(fd);
        unlink(tempname);
        free(tempname);
	CHDIR_ERR(olddir);
	return 70; /* FIXME */
    }

    close(fd);
    unlink(tempname);
    free(tempname);
    if(chdir(olddir) == -1) {
	logg("!getpatch: Can't chdir to %s\n", olddir);
	return 50; /* FIXME */
    }
    return 0;
}

static struct cl_cvd *currentdb(const char *dbname, char *localname)
{
	char db[32];
	struct cl_cvd *cvd = NULL;


    snprintf(db, sizeof(db), "%s.cvd", dbname);
    if(localname)
	strcpy(localname, db);

    if(access(db, R_OK) == -1) {
	snprintf(db, sizeof(db), "%s.cld", dbname);
	if(localname)
	    strcpy(localname, db);
    }

    if(!access(db, R_OK))
	cvd = cl_cvdhead(db);

    return cvd;
}

static int buildcld(const char *tmpdir, const char *dbname, const char *newfile, unsigned int compr)
{
	DIR *dir;
	char cwd[512], info[32], buff[513], *pt;
	struct dirent *dent;
	int fd, err = 0;
	gzFile *gzs = NULL;

    if(!getcwd(cwd, sizeof(cwd))) {
	logg("!buildcld: Can't get path of current working directory\n");
	return -1;
    }

    if(chdir(tmpdir) == -1) {
	logg("!buildcld: Can't access directory %s\n", tmpdir);
	return -1;
    }

    snprintf(info, sizeof(info), "%s.info", dbname);
    if((fd = open(info, O_RDONLY|O_BINARY)) == -1) {
	logg("!buildcld: Can't open %s\n", info);
	CHDIR_ERR(cwd);
	return -1;
    }

    if(read(fd, buff, 512) == -1) {
	logg("!buildcld: Can't read %s\n", info);
	CHDIR_ERR(cwd);
	close(fd);
	return -1;
    }
    buff[512] = 0;
    close(fd);

    if(!(pt = strchr(buff, '\n'))) {
	logg("!buildcld: Bad format of %s\n", info);
	CHDIR_ERR(cwd);
	return -1;
    }
    memset(pt, ' ', 512 + buff - pt);

    if((fd = open(newfile, O_WRONLY|O_CREAT|O_EXCL|O_BINARY, 0644)) == -1) {
	logg("!buildcld: Can't open %s for writing\n", newfile);
	CHDIR_ERR(cwd);
	return -1;
    }
    if(write(fd, buff, 512) != 512) {
	logg("!buildcld: Can't write to %s\n", newfile);
	CHDIR_ERR(cwd);
	unlink(newfile);
	close(fd);
	return -1;
    }

    if((dir = opendir(".")) == NULL) {
	logg("!buildcld: Can't open directory %s\n", tmpdir);
	CHDIR_ERR(cwd);
	unlink(newfile);
	close(fd);
	return -1;
    }

    if(compr) {
	close(fd);
	if(!(gzs = gzopen(newfile, "ab"))) {
	    logg("!buildcld: gzopen() failed for %s\n", newfile);
	    CHDIR_ERR(cwd);
	    unlink(newfile);
	    closedir(dir);
	    return -1;
	}
    }

    if(access("COPYING", R_OK)) {
	logg("!buildcld: COPYING file not found\n");
	err = 1;
    } else {
	if(tar_addfile(fd, gzs, "COPYING") == -1) {
	    logg("!buildcld: Can't add COPYING to .cld file\n");
	    err = 1;
	}
    }

    if(!err && !access("daily.cfg", R_OK)) {
	if(tar_addfile(fd, gzs, "daily.cfg") == -1) {
	    logg("!buildcld: Can't add daily.cfg to .cld file\n");
	    err = 1;
	}
    }

    if(err) {
	CHDIR_ERR(cwd);
	if(gzs)
	    gzclose(gzs);
	else
	    close(fd);
	unlink(newfile);
	return -1;
    }

    while((dent = readdir(dir))) {
#if !defined(C_INTERIX) && !defined(C_WINDOWS)
	if(dent->d_ino)
#endif
	{
	    if(!strcmp(dent->d_name, ".") || !strcmp(dent->d_name, "..") || !strcmp(dent->d_name, "COPYING") || !strcmp(dent->d_name, "daily.cfg"))
		continue;

	    if(tar_addfile(fd, gzs, dent->d_name) == -1) {
		logg("!buildcld: Can't add %s to .cld file\n", dent->d_name);
		CHDIR_ERR(cwd);
		if(gzs)
		    gzclose(gzs);
		else
		    close(fd);
		unlink(newfile);
		closedir(dir);
		return -1;
	    }
	}
    }
    closedir(dir);

    if(gzs) {
	if(gzclose(gzs)) {
	    logg("!buildcld: gzclose() failed for %s\n", newfile);
	    unlink(newfile);
	    return -1;
	}
    } else {
	if(close(fd) == -1) {
	    logg("!buildcld: close() failed for %s\n", newfile);
	    unlink(newfile);
	    return -1;
	}
    }

    if(chdir(cwd) == -1) {
	logg("!buildcld: Can't return to previous directory %s\n", cwd);
	return -1;
    }

    return 0;
}

static int updatedb(const char *dbname, const char *hostname, char *ip, int *signo, const struct optstruct *opts, const char *dnsreply, char *localip, int outdated, struct mirdat *mdat, int logerr)
{
	struct cl_cvd *current, *remote;
	const struct optstruct *opt;
	unsigned int nodb = 0, currver = 0, newver = 0, port = 0, i, j;
	int ret, ims = -1;
	char *pt, cvdfile[32], localname[32], *tmpdir = NULL, *newfile, newdb[32], cwd[512];
	const char *proxy = NULL, *user = NULL, *pass = NULL, *uas = NULL;
	unsigned int flevel = cl_retflevel(), remote_flevel = 0, maxattempts;
	unsigned int can_whitelist = 0;
	int ctimeout, rtimeout;


    snprintf(cvdfile, sizeof(cvdfile), "%s.cvd", dbname);

    if(!(current = currentdb(dbname, localname))) {
	nodb = 1;
    } else {
	mdat->dbflevel = current->fl;
    }

    if(!nodb && dnsreply) {
	    int field = 0;

	if(!strcmp(dbname, "main")) {
	    field = 1;
	} else if(!strcmp(dbname, "daily")) {
	    field = 2;
	} else if(!strcmp(dbname, "safebrowsing")) {
	    field = 6;
	} else {
	    logg("!updatedb: Unknown database name (%s) passed.\n", dbname);
	    cl_cvdfree(current);
	    return 70;
	}

	if(field && (pt = cli_strtok(dnsreply, field, ":"))) {
	    if(!cli_isnumber(pt)) {
		logg("^Broken database version in TXT record.\n");
	    } else {
		newver = atoi(pt);
		logg("*%s version from DNS: %d\n", cvdfile, newver);
	    }
	    free(pt);
	} else {
	    logg("^Invalid DNS reply. Falling back to HTTP mode.\n");
	}
    }

    if(dnsreply) {
	if((pt = cli_strtok(dnsreply, 5, ":"))) {
	    remote_flevel = atoi(pt);
	    free(pt);
	    if(remote_flevel && (remote_flevel - flevel < 4))
		can_whitelist = 1;
	}
    }

    /* Initialize proxy settings */
    if((opt = optget(opts, "HTTPProxyServer"))->enabled) {
	proxy = opt->strarg;
	if(strncasecmp(proxy, "http://", 7) == 0)
	    proxy += 7;

	if((opt = optget(opts, "HTTPProxyUsername"))->enabled) {
	    user = opt->strarg;
	    if((opt = optget(opts, "HTTPProxyPassword"))->enabled) {
		pass = opt->strarg;
	    } else {
		logg("HTTPProxyUsername requires HTTPProxyPassword\n");
		if(current)
		    cl_cvdfree(current);
		return 56;
	    }
	}

	if((opt = optget(opts, "HTTPProxyPort"))->enabled)
	    port = opt->numarg;

	logg("Connecting via %s\n", proxy);
    }

    if((opt = optget(opts, "HTTPUserAgent"))->enabled)
	uas = opt->strarg;

    ctimeout = optget(opts, "ConnectTimeout")->numarg;
    rtimeout = optget(opts, "ReceiveTimeout")->numarg;

    if(!nodb && !newver) {

	remote = remote_cvdhead(cvdfile, localname, hostname, ip, localip, proxy, port, user, pass, uas, &ims, ctimeout, rtimeout, mdat, logerr, can_whitelist);

	if(!nodb && !ims) {
	    logg("%s is up to date (version: %d, sigs: %d, f-level: %d, builder: %s)\n", localname, current->version, current->sigs, current->fl, current->builder);
	    *signo += current->sigs;
	    cl_cvdfree(current);
	    return 1;
	}

	if(!remote) {
	    logg("^Can't read %s header from %s (IP: %s)\n", cvdfile, hostname, ip);
	    cl_cvdfree(current);
	    return 58;
	}

	newver = remote->version;
	cl_cvdfree(remote);
    }

    if(!nodb && (current->version >= newver)) {
	logg("%s is up to date (version: %d, sigs: %d, f-level: %d, builder: %s)\n", localname, current->version, current->sigs, current->fl, current->builder);

	if(!outdated && flevel < current->fl) {
	    /* display warning even for already installed database */
	    logg("^Current functionality level = %d, recommended = %d\n", flevel, current->fl);
	    logg("Please check if ClamAV tools are linked against the proper version of libclamav\n");
	    logg("DON'T PANIC! Read http://www.clamav.net/support/faq\n");
	}

	*signo += current->sigs;
	cl_cvdfree(current);
	return 1;
    }


    if(current) {
	currver = current->version;
	cl_cvdfree(current);
    }

    /*
    if(ipaddr[0]) {
	hostfd = wwwconnect(ipaddr, proxy, port, NULL, localip);
    } else {
	hostfd = wwwconnect(hostname, proxy, port, ipaddr, localip);
	if(!ip[0])
	    strcpy(ip, ipaddr);
    }

    if(hostfd < 0) {
	if(ipaddr[0])
	    logg("Connection with %s (IP: %s) failed.\n", hostname, ipaddr);
	else
	    logg("Connection with %s failed.\n", hostname);
	return 52;
    };
    */

    if(!optget(opts, "ScriptedUpdates")->enabled)
	nodb = 1;

    if(!getcwd(cwd, sizeof(cwd))) {
	logg("!updatedb: Can't get path of current working directory\n");
	return 50; /* FIXME */
    }
    newfile = cli_gentemp(cwd);

    if(nodb) {
	ret = getcvd(cvdfile, newfile, hostname, ip, localip, proxy, port, user, pass, uas, newver, ctimeout, rtimeout, mdat, logerr, can_whitelist);
	if(ret) {
	    memset(ip, 0, 16);
	    free(newfile);
	    return ret;
	}
	snprintf(newdb, sizeof(newdb), "%s.cvd", dbname);

    } else {
	ret = 0;

	tmpdir = cli_gentemp(".");
	maxattempts = optget(opts, "MaxAttempts")->numarg;
	for(i = currver + 1; i <= newver; i++) {
	    for(j = 0; j < maxattempts; j++) {
		    int llogerr = logerr;
		if(logerr)
		    llogerr = (j == maxattempts - 1);
		ret = getpatch(dbname, tmpdir, i, hostname, ip, localip, proxy, port, user, pass, uas, ctimeout, rtimeout, mdat, llogerr, can_whitelist);
		if(ret == 52 || ret == 58) {
		    memset(ip, 0, 16);
		    continue;
		} else {
		    break;
		}
	    }
	    if(ret)
		break;
	}

	if(ret) {
	    cli_rmdirs(tmpdir);
	    free(tmpdir);
	    logg("^Incremental update failed, trying to download %s\n", cvdfile);
	    mirman_whitelist(mdat, 2);
	    ret = getcvd(cvdfile, newfile, hostname, ip, localip, proxy, port, user, pass, uas, newver, ctimeout, rtimeout, mdat, logerr, can_whitelist);
	    if(ret) {
		free(newfile);
		return ret;
	    }
	    snprintf(newdb, sizeof(newdb), "%s.cvd", dbname);
	} else {
	    if(buildcld(tmpdir, dbname, newfile, optget(opts, "CompressLocalDatabase")->enabled) == -1) {
		logg("!Can't create local database\n");
		cli_rmdirs(tmpdir);
		free(tmpdir);
		free(newfile);
		return 70; /* FIXME */
	    }
	    snprintf(newdb, sizeof(newdb), "%s.cld", dbname);
	    cli_rmdirs(tmpdir);
	    free(tmpdir);
	}
    }

    if(!(current = cl_cvdhead(newfile))) {
	logg("!Can't parse new database %s\n", newfile);
	unlink(newfile);
	free(newfile);
	return 55; /* FIXME */
    }

    if(!nodb && !access(localname, R_OK) && unlink(localname)) {
	logg("!Can't unlink %s. Please fix it and try again.\n", localname);
	unlink(newfile);
	free(newfile);
	return 53;
    }

#ifdef C_WINDOWS
    if(!access(newdb, R_OK) && unlink(newdb)) {
	logg("!Can't unlink %s. Please fix the problem manually and try again.\n", newdb);
	unlink(newfile);
	free(newfile);
	return 53;
    }
#endif

    if(rename(newfile, newdb) == -1) {
	logg("!Can't rename %s to %s: %s\n", newfile, newdb, strerror(errno));
	unlink(newfile);
	free(newfile);
	return 57;
    }
    free(newfile);

    logg("%s updated (version: %d, sigs: %d, f-level: %d, builder: %s)\n", newdb, current->version, current->sigs, current->fl, current->builder);

    if(flevel < current->fl) {
	logg("^Your ClamAV installation is OUTDATED!\n");
	logg("^Current functionality level = %d, recommended = %d\n", flevel, current->fl);
	logg("DON'T PANIC! Read http://www.clamav.net/support/faq\n");
    }

    *signo += current->sigs;
    cl_cvdfree(current);
    return 0;
}

int downloadmanager(const struct optstruct *opts, const char *hostname, const char *dbdir, int logerr)
{
	time_t currtime;
	int ret, updated = 0, outdated = 0, signo = 0;
	unsigned int ttl;
	char ipaddr[46], *dnsreply = NULL, *pt, *localip = NULL, *newver = NULL;
	const struct optstruct *opt;
	struct mirdat mdat;
#ifdef HAVE_RESOLV_H
	const char *dnsdbinfo;
#endif

    time(&currtime);
    logg("ClamAV update process started at %s", ctime(&currtime));
#ifdef HAVE_GETADDRINFO
    logg("*Using IPv6 aware code\n");
#endif

#ifdef HAVE_RESOLV_H
    dnsdbinfo = optget(opts, "DNSDatabaseInfo")->strarg;

    if(optget(opts, "no-dns")->enabled) {
	dnsreply = NULL;
    } else {
	if((dnsreply = txtquery(dnsdbinfo, &ttl))) {
	    logg("*TTL: %d\n", ttl);

	    if((pt = cli_strtok(dnsreply, 3, ":"))) {
		    int rt;
		    time_t ct;

		rt = atoi(pt);
		free(pt);
		time(&ct);
		if((int) ct - rt > 10800) {
		    logg("^DNS record is older than 3 hours.\n");
		    free(dnsreply);
		    dnsreply = NULL;
		}

	    } else {
		free(dnsreply);
		dnsreply = NULL;
	    }

	    if(dnsreply) {
		    int vwarning = 1;

		if((pt = cli_strtok(dnsreply, 4, ":"))) {
		    if(*pt == '0')
			vwarning = 0;

		    free(pt);
		}

		if((newver = cli_strtok(dnsreply, 0, ":"))) {
			char vstr[32];

		    logg("*Software version from DNS: %s\n", newver);
		    strncpy(vstr, get_version(), 32);
		    vstr[31] = 0;
		    if((pt = strstr(vstr, "-exp")) || (pt = strstr(vstr,"-broken")))
			*pt = 0;

		    if(vwarning && !strstr(vstr, "devel") && !strstr(vstr, "rc")) {
			if(strcmp(vstr, newver)) {
			    logg("^Your ClamAV installation is OUTDATED!\n");
			    logg("^Local version: %s Recommended version: %s\n", vstr, newver);
			    logg("DON'T PANIC! Read http://www.clamav.net/support/faq\n");
			    outdated = 1;
			}
		    }
		}
	    }
	}

	if(!dnsreply) {
	    logg("^Invalid DNS reply. Falling back to HTTP mode.\n");
	}
    }
#endif /* HAVE_RESOLV_H */

    if((opt = optget(opts, "LocalIPAddress"))->enabled)
	localip = opt->strarg;

    if(optget(opts, "HTTPProxyServer")->enabled)
	mirman_read("mirrors.dat", &mdat, 0);
    else
	mirman_read("mirrors.dat", &mdat, 1);

    memset(ipaddr, 0, sizeof(ipaddr));

    if((ret = updatedb("main", hostname, ipaddr, &signo, opts, dnsreply, localip, outdated, &mdat, logerr)) > 50) {
	if(dnsreply)
	    free(dnsreply);

	if(newver)
	    free(newver);

	mirman_write("mirrors.dat", &mdat);
	return ret;

    } else if(ret == 0)
	updated = 1;

    /* if ipaddr[0] != 0 it will use it to connect to the web host */
    if((ret = updatedb("daily", hostname, ipaddr, &signo, opts, dnsreply, localip, outdated, &mdat, logerr)) > 50) {
	if(dnsreply)
	    free(dnsreply);

	if(newver)
	    free(newver);

	mirman_write("mirrors.dat", &mdat);
	return ret;

    } else if(ret == 0)
	updated = 1;

    /* if ipaddr[0] != 0 it will use it to connect to the web host */
    if(!optget(opts, "SafeBrowsing")->enabled) {
	    const char *safedb = NULL;

	if(!access("safebrowsing.cvd", R_OK))
	    safedb = "safebrowsing.cvd";
	else if(!access("safebrowsing.cld", R_OK))
            safedb = "safebrowsing.cld";

	if(safedb) {
	    if(unlink(safedb))
		logg("^SafeBrowsing is disabled but can't remove old %s\n", safedb);
	    else
		logg("*%s removed\n", safedb);
	}
    } else if((ret = updatedb("safebrowsing", hostname, ipaddr, &signo, opts, dnsreply, localip, outdated, &mdat, logerr)) > 50) {
	if(dnsreply)
	    free(dnsreply);

	if(newver)
	    free(newver);

	mirman_write("mirrors.dat", &mdat);
	return ret;
    } else if(ret == 0)
	updated = 1;

    if(dnsreply)
	free(dnsreply);

    mirman_write("mirrors.dat", &mdat);

    if(updated) {
	if(optget(opts, "HTTPProxyServer")->enabled) {
	    logg("Database updated (%d signatures) from %s\n", signo, hostname);
	} else {
	    logg("Database updated (%d signatures) from %s (IP: %s)\n", signo, hostname, ipaddr);
	}

#ifdef BUILD_CLAMD
	if((opt = optget(opts, "NotifyClamd"))->active)
	    notify(opt->strarg);
#endif

	if((opt = optget(opts, "OnUpdateExecute"))->enabled)
	    execute("OnUpdateExecute", opt->strarg, opts);
    }

    if(outdated) {
	if((opt = optget(opts, "OnOutdatedExecute"))->enabled) {
		char *cmd = strdup(opt->strarg);

	    if((pt = newver)) {
		while(*pt) {
		    if(!strchr("0123456789.", *pt)) {
			logg("!downloadmanager: OnOutdatedExecute: Incorrect version number string\n");
			free(newver);
			newver = NULL;
			break;
		    }
		    pt++;
		}
	    }

	    if(newver && (pt = strstr(cmd, "%v"))) {
		    char *buffer = (char *) malloc(strlen(cmd) + strlen(newver) + 10);

		if(!buffer) {
		    logg("!downloadmanager: Can't allocate memory for buffer\n");
		    free(cmd);
		    if(newver)
			free(newver);
		    return 75;
		}

		*pt = 0; pt += 2;
		strcpy(buffer, cmd);
		strcat(buffer, newver);
		strcat(buffer, pt);
		free(cmd);
		cmd = strdup(buffer);
		free(buffer);
	    }

	    if(newver)
		execute("OnOutdatedExecute", cmd, opts);

	    free(cmd);
	}
    }

    if(newver)
	free(newver);

    return updated ? 0 : 1;
}
