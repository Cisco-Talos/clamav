/*
 *  Copyright (C) 2002 - 2005 Tomasz Kojm <tkojm@clamav.net>
 *  HTTP/1.1 compliance by Arkadiusz Miskiewicz <misiek@pld.org.pl>
 *  Proxy support by Nigel Horne <njh@bandsman.co.uk>
 *  Proxy authorization support by Gernot Tenchio <g.tenchio@telco-tech.de>
 *		     (uses fmt_base64() from libowfat (http://www.fefe.de))
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

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <clamav.h>
#include <errno.h>

#include "options.h"
#include "defaults.h"
#include "manager.h"
#include "notify.h"
#include "memory.h"
#include "output.h"
#include "misc.h"
#include "../libclamav/others.h"
#include "../libclamav/str.h" /* cli_strtok */
#include "dns.h"


int downloadmanager(const struct cfgstruct *copt, const struct optstruct *opt, const char *hostname)
{
	time_t currtime;
	int ret, updated = 0, signo = 0, ttl = -1;
	char ipaddr[16], *dnsreply = NULL, *pt;
	struct cfgstruct *cpt;
	char *localip = NULL;
	const char *arg = NULL;
#ifdef HAVE_RESOLV_H
	const char *dnsdbinfo;
#endif

    time(&currtime);
    logg("ClamAV update process started at %s", ctime(&currtime));

#ifndef HAVE_GMP
    logg("SECURITY WARNING: NO SUPPORT FOR DIGITAL SIGNATURES\n");
    logg("See the FAQ at http://www.clamav.net/faq.html for an explanation.\n");
#endif

#ifdef HAVE_RESOLV_H
    dnsdbinfo = cfgopt(copt, "DNSDatabaseInfo")->strarg;

    if(optl(opt, "no-dns")) {
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

		if((pt = cli_strtok(dnsreply, 0, ":"))) {

		    logg("*Software version from DNS: %s\n", pt);

		    if(vwarning && !strstr(cl_retver(), "devel") && !strstr(cl_retver(), "rc")) {
			if(strcmp(cl_retver(), pt)) {
			    logg("^Your ClamAV installation is OUTDATED!\n");
			    logg("^Local version: %s Recommended version: %s\n", cl_retver(), pt);
			    logg("DON'T PANIC! Read http://www.clamav.net/faq.html\n");
			}
		    }
		    free(pt);
		}

	    } else {
		if(dnsreply) {
		    free(dnsreply);
		    dnsreply = NULL;
		}
	    }
	}

	if(!dnsreply) {
	    logg("^Invalid DNS reply. Falling back to HTTP mode.\n");
	}
    }
#endif /* HAVE_RESOLV_H */

    if(optl(opt, "localip")) {
        localip = getargl(opt, "localip");
    } else if((cpt = cfgopt(copt, "LocalIPAddress"))->enabled) {
	localip = cpt->strarg;
    }

    memset(ipaddr, 0, sizeof(ipaddr));

    if((ret = downloaddb(DB1NAME, "main.cvd", hostname, ipaddr, &signo, copt, dnsreply, localip)) > 50) {
	if(dnsreply)
	    free(dnsreply);

	return ret;

    } else if(ret == 0)
	updated = 1;

    /* if ipaddr[0] != 0 it will use it to connect to the web host */
    if((ret = downloaddb(DB2NAME, "daily.cvd", hostname, ipaddr, &signo, copt, dnsreply, localip)) > 50) {
	if(dnsreply)
	    free(dnsreply);

	return ret;

    } else if(ret == 0)
	updated = 1;

    if(dnsreply)
	free(dnsreply);

    if(updated) {
	if(cfgopt(copt, "HTTPProxyServer")->enabled) {
	    logg("Database updated (%d signatures) from %s\n", signo, hostname);
	} else {
	    logg("Database updated (%d signatures) from %s (IP: %s)\n", signo, hostname, ipaddr);
	}

#ifdef BUILD_CLAMD
	if(optl(opt, "daemon-notify")) {
		const char *clamav_conf = getargl(opt, "daemon-notify");
	    if(!clamav_conf)
		clamav_conf = CONFDIR"/clamd.conf";

	    notify(clamav_conf);
	} else if((cpt = cfgopt(copt, "NotifyClamd"))->enabled) {
	    notify(cpt->strarg);
	}
#endif

	if(optl(opt, "on-update-execute"))
	    arg = getargl(opt, "on-update-execute");
	else if((cpt = cfgopt(copt, "OnUpdateExecute"))->enabled)
	    arg = cpt->strarg;

	if(arg) {
	    if(optc(opt, 'd'))
		execute("OnUpdateExecute", arg);
            else
		system(arg);
	}

	return 0;

    } else
	return 1;
}

int downloaddb(const char *localname, const char *remotename, const char *hostname, char *ip, int *signo, const struct cfgstruct *copt, const char *dnsreply, char *localip)
{
	struct cl_cvd *current, *remote;
	struct cfgstruct *cpt;
	int hostfd, nodb = 0, dbver = -1, ret, port = 0, ims = -1;
	char  *tempname, ipaddr[16], *pt;
	const char *proxy = NULL, *user = NULL, *pass = NULL;
	int flevel = cl_retflevel();


    if((current = cl_cvdhead(localname)) == NULL)
	nodb = 1;

    if(!nodb && dnsreply) {
	    int field = 0;

	if(!strcmp(remotename, "main.cvd")) {
	    field = 1;
	} else if(!strcmp(remotename, "daily.cvd")) {
	    field = 2;
	} else {
	    logg("^Unknown database name (%s) passed.\n", remotename);
	}

	if(field && (pt = cli_strtok(dnsreply, field, ":"))) {
	    if(!isnumb(pt)) {
		logg("^Broken database version in TXT record.\n");
	    } else {
		dbver = atoi(pt);
		logg("*%s version from DNS: %d\n", remotename, dbver);
	    }
	    free(pt);
	} else {
	    logg("^Invalid DNS reply. Falling back to HTTP mode.\n");
	}

    }

    /* Initialize proxy settings */
    if((cpt = cfgopt(copt, "HTTPProxyServer"))->enabled) {
	proxy = cpt->strarg;
	if(strncasecmp(proxy, "http://", 7) == 0)
	    proxy += 7;

	if((cpt = cfgopt(copt, "HTTPProxyUsername"))->enabled) {
	    user = cpt->strarg;
	    if((cpt = cfgopt(copt, "HTTPProxyPassword"))->enabled) {
		pass = cpt->strarg;
	    } else {
		logg("HTTPProxyUsername requires HTTPProxyPassword\n");
		if(current)
		    cl_cvdfree(current);
		return 56;
	    }
	}

	if((cpt = cfgopt(copt, "HTTPProxyPort"))->enabled)
	    port = cpt->numarg;

	logg("Connecting via %s\n", proxy);
    }

    memset(ipaddr, 0, sizeof(ipaddr));

    if(!nodb && dbver == -1) {
	if(ip[0]) /* use ip to connect */
	    hostfd = wwwconnect(ip, proxy, port, ipaddr, localip);
	else
	    hostfd = wwwconnect(hostname, proxy, port, ipaddr, localip);

	if(hostfd < 0) {
	    if(current)
		cl_cvdfree(current);
	    return 52;
	} else {
	    logg("*Connected to %s (IP: %s).\n", hostname, ipaddr);
	    logg("*Trying to retrieve http://%s/%s\n", hostname, remotename);
	}

	if(!ip[0])
	    strcpy(ip, ipaddr);

	remote = remote_cvdhead(remotename, hostfd, hostname, proxy, user, pass, &ims);

	if(!nodb && !ims) {
	    logg("%s is up to date (version: %d, sigs: %d, f-level: %d, builder: %s)\n", localname, current->version, current->sigs, current->fl, current->builder);
	    *signo += current->sigs;
	    close(hostfd);
	    cl_cvdfree(current);
	    return 1;
	}

	if(!remote) {
	    logg("^Can't read %s header from %s (IP: %s)\n", remotename, hostname, ipaddr);
	    close(hostfd);
	    if(current)
		cl_cvdfree(current);
	    return 58;
	}

	dbver = remote->version;
	cl_cvdfree(remote);
	close(hostfd);
    }

    if(!nodb && (current->version >= dbver)) {
	logg("%s is up to date (version: %d, sigs: %d, f-level: %d, builder: %s)\n", localname, current->version, current->sigs, current->fl, current->builder);

	if(flevel < current->fl) {
	    /* display warning even for already installed database */
	    logg("^Your ClamAV installation is OUTDATED!\n");
	    logg("^Current functionality level = %d, recommended = %d\n", flevel, current->fl);
	    logg("DON'T PANIC! Read http://www.clamav.net/faq.html\n");
	}

	*signo += current->sigs;
	cl_cvdfree(current);
	return 1;
    }

    if(current)
	cl_cvdfree(current);

    if(ipaddr[0]) {
	/* use ipaddr in order to connect to the same mirror */
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

    /* the temporary file is created in a directory owned by clamav so race
     * conditions are not possible
     */
    tempname = cli_gentemp(".");

    logg("*Retrieving http://%s/%s\n", hostname, remotename);
    if((ret = get_database(remotename, hostfd, tempname, hostname, proxy, user, pass))) {
        logg("^Can't download %s from %s (IP: %s)\n", remotename, hostname, ipaddr);
        unlink(tempname);
        free(tempname);
        close(hostfd);
        return ret;
    }

    close(hostfd);

    if((ret = cl_cvdverify(tempname))) {
        logg("^Verification: %s\n", cl_strerror(ret));
        unlink(tempname);
        free(tempname);
        return 54;
    }

    if((current = cl_cvdhead(tempname)) == NULL) {
	logg("^Can't read CVD header of new %s database.\n", localname);
	unlink(tempname);
	free(tempname);
	return 54;
    }

    if(current->version < dbver) {
	logg("^Mirrors are not fully synchronized. Please try again later.\n");
    	cl_cvdfree(current);
	unlink(tempname);
	free(tempname);
	return 59;
    }

    if(!nodb && unlink(localname)) {
	logg("^Can't unlink %s. Please fix it and try again.\n", localname);
    	cl_cvdfree(current);
	unlink(tempname);
	free(tempname);
	return 53;
    } else {
    	if(rename(tempname, localname) == -1) {
    	    logg("^Can't rename %s to %s: %s\n", tempname, localname, strerror(errno));
    	    if(errno == EEXIST) {
    	        unlink(localname);
    	        if(rename(tempname, localname) == -1)
                   logg("^All attempts to rename the temporary file failed: %s\n", strerror(errno));
            }
        }
    }

    logg("%s updated (version: %d, sigs: %d, f-level: %d, builder: %s)\n", localname, current->version, current->sigs, current->fl, current->builder);

    if(flevel < current->fl) {
	logg("^Your ClamAV installation is OUTDATED!\n");
	logg("^Current functionality level = %d, recommended = %d\n", flevel, current->fl);
	logg("DON'T PANIC! Read http://www.clamav.net/faq.html\n");
    }

    *signo += current->sigs;
    cl_cvdfree(current);
    free(tempname);
    return 0;
}

/* this function returns socket descriptor */
/* proxy support finshed by njh@bandsman.co.uk */
int wwwconnect(const char *server, const char *proxy, int pport, char *ip, char *localip)
{
	int socketfd = -1, port, i;
	struct sockaddr_in name;
	struct hostent *host;
	char ipaddr[16];
	unsigned char *ia;
	const char *hostpt;
	struct hostent *he = NULL;

    if(ip)
	strcpy(ip, "???");

    name.sin_family = AF_INET;

    if (localip) {
	if ((he = gethostbyname(localip)) == NULL) {
	    char *herr;
	    switch(h_errno) {
	        case HOST_NOT_FOUND:
		    herr = "Host not found";
		    break;

		case NO_DATA:
		    herr = "No IP address";
		    break;

		case NO_RECOVERY:
		    herr = "Unrecoverable DNS error";
		    break;

		case TRY_AGAIN:
		    herr = "Temporary DNS error";
		    break;

		default:
		    herr = "Unknown error";
		    break;
	    }
	    logg("!Could not resolve local ip address '%s': %s\n", localip, herr);
	    logg("^Using standard local ip address and port for fetching.\n");
	} else {
	    struct sockaddr_in client;
	    memset ((char *) &client, 0, sizeof(struct sockaddr_in));
	    client.sin_family = AF_INET;
	    client.sin_addr = *(struct in_addr *) he->h_addr_list[0];
	    if (bind(socketfd, (struct sockaddr *) &client, sizeof(struct sockaddr_in)) != 0) {
		logg("!Could not bind to local ip address '%s': %s\n", localip, strerror(errno));
		logg("^Using default client ip.\n");
	    } else {
		ia = (unsigned char *) he->h_addr_list[0];
		sprintf(ipaddr, "%u.%u.%u.%u", ia[0], ia[1], ia[2], ia[3]);
		logg("*Using ip '%s' for fetching.\n", ipaddr);
	    }
	}
    }
    if(proxy) {
	hostpt = proxy;

	if(!(port = pport)) {
#ifndef C_CYGWIN
		const struct servent *webcache = getservbyname("webcache", "TCP");

		if(webcache)
			port = ntohs(webcache->s_port);
		else
			port = 8080;

		endservent();
#else
		port = 8080;
#endif
	}

    } else {
	hostpt = server;
	port = 80;
    }

    if((host = gethostbyname(hostpt)) == NULL) {
	char *herr;
	switch(h_errno) {
	    case HOST_NOT_FOUND:
		herr = "Host not found";
		break;

	    case NO_DATA:
		herr = "No IP address";
		break;

	    case NO_RECOVERY:
		herr = "Unrecoverable DNS error";
		break;

	    case TRY_AGAIN:
		herr = "Temporary DNS error";
		break;

	    default:
		herr = "Unknown error";
		break;
	}
        logg("^Can't get information about %s: %s\n", hostpt, herr);
	return -1;
    }

    for(i = 0; host->h_addr_list[i] != 0; i++) {
	/* this dirty hack comes from pink - Nosuid TCP/IP ping 1.6 */
	ia = (unsigned char *) host->h_addr_list[i];
	sprintf(ipaddr, "%u.%u.%u.%u", ia[0], ia[1], ia[2], ia[3]);

	if(ip)
	    strcpy(ip, ipaddr);

	if(i > 0)
	    logg("Trying host %s (%s)...\n", hostpt, ipaddr);

	name.sin_addr = *((struct in_addr *) host->h_addr_list[i]);
	name.sin_port = htons(port);

#ifdef PF_INET
	socketfd = socket(PF_INET, SOCK_STREAM, 0);
#else
	socketfd = socket(AF_INET, SOCK_STREAM, 0);
#endif

	if(connect(socketfd, (struct sockaddr *) &name, sizeof(struct sockaddr_in)) == -1) {
	    logg("Can't connect to port %d of host %s (IP: %s)\n", port, hostpt, ipaddr);
	    close(socketfd);
	    continue;
	}

	return socketfd;
    }

    return -2;
}

int Rfc2822DateTime(char *buf, time_t mtime)
{
	struct tm *time;

    time = gmtime(&mtime);
    return strftime(buf, 36, "%a, %d %b %Y %X GMT", time);
}

struct cl_cvd *remote_cvdhead(const char *file, int socketfd, const char *hostname, const char *proxy, const char *user, const char *pass, int *ims)
{
	char cmd[512], head[513], buffer[FILEBUFF], *ch, *tmp;
	int i, j, bread, cnt;
	char *remotename = NULL, *authorization = NULL;
	struct cl_cvd *cvd;
	char last_modified[36];
	struct stat sb;


    if(proxy) {
        remotename = mmalloc(strlen(hostname) + 8);
        sprintf(remotename, "http://%s", hostname);

        if(user) {
            int len;
	    char *buf = mmalloc((strlen(pass) + strlen(user)) * 2 + 4);
	    char *userpass = mmalloc(strlen(user) + strlen(pass) + 2);
	    sprintf(userpass, "%s:%s", user, pass);
            len=fmt_base64(buf,userpass,strlen(userpass));
	    free(userpass);
            buf[len]='\0';
            authorization = mmalloc(strlen(buf) + 30);
            sprintf(authorization, "Proxy-Authorization: Basic %s\r\n", buf);
            free(buf);
        }
    }

    if(stat(file, &sb) != -1 && sb.st_mtime < time(NULL)) {
	Rfc2822DateTime(last_modified, sb.st_mtime);
    } else {
	    time_t mtime = 1104119530;
	Rfc2822DateTime(last_modified, mtime);
	logg("*Assuming modification time in the past\n");
    }

    logg("*If-Modified-Since: %s\n", last_modified);

    logg("Reading CVD header (%s): ", file);
#ifdef	NO_SNPRINTF
    sprintf(cmd, "GET %s/%s HTTP/1.1\r\n"
	"Host: %s\r\n%s"
	"User-Agent: "PACKAGE"/"VERSION"\r\n"
	"Connection: close\r\n"
	"Range: bytes=0-511\r\n"
        "If-Modified-Since: %s\r\n"
        "\r\n", (remotename != NULL)?remotename:"", file, hostname, (authorization != NULL)?authorization:"", last_modified);
#else
    snprintf(cmd, sizeof(cmd), "GET %s/%s HTTP/1.1\r\n"
	"Host: %s\r\n%s"
	"User-Agent: "PACKAGE"/"VERSION"\r\n"
	"Connection: close\r\n"
	"Range: bytes=0-511\r\n"
        "If-Modified-Since: %s\r\n"
        "\r\n", (remotename != NULL)?remotename:"", file, hostname, (authorization != NULL)?authorization:"", last_modified);
#endif
    write(socketfd, cmd, strlen(cmd));

    free(remotename);
    free(authorization);

    tmp = buffer;
    cnt = FILEBUFF;
    while ((bread = recv(socketfd, tmp, cnt, 0)) > 0) {
	tmp+=bread;
	cnt-=bread;
	if (cnt <= 0) break;
    }

    if(bread == -1) {
	logg("^Error while reading CVD header of database from %s\n", hostname);
	return NULL;
    }

    if((strstr(buffer, "HTTP/1.1 404")) != NULL || (strstr(buffer, "HTTP/1.0 404")) != NULL) { 
	logg("^CVD file not found on remote server\n");
	return NULL;
    }

    /* check whether the resource is up-to-date */
    if((strstr(buffer, "HTTP/1.1 304")) != NULL || (strstr(buffer, "HTTP/1.0 304")) != NULL) { 

	*ims = 0;
	logg("OK (IMS)\n");
	return NULL;
    } else {
	*ims = 1;
    }

    ch = buffer;
    i = 0;
    while (1) {
      if (*ch == '\n' && *(ch - 1) == '\r' && *(ch - 2) == '\n' && *(ch - 3) == '\r') {
	ch++;
	i++;
	break;
      }
      ch++;
      i++;
    }  

    memset(head, 0, sizeof(head));

    for (j=0; j<512; j++) {
      if (!ch || (ch && !*ch) || (ch && !isprint(ch[j]))) {
	logg("^Malformed CVD header detected.\n");
	return NULL;
      }
      head[j] = ch[j];
    }

    if((cvd = cl_cvdparse(head)) == NULL)
	logg("^Broken CVD header.\n");
    else
	logg("OK\n");

    return cvd;
}

int get_database(const char *dbfile, int socketfd, const char *file, const char *hostname, const char *proxy, const char *user, const char *pass)
{
	char cmd[512], buffer[FILEBUFF], *ch;
	int bread, fd, i, rot = 0;
	char *remotename = NULL, *authorization = NULL;
	const char *rotation = "|/-\\";


    if(proxy) {
        remotename = mmalloc(strlen(hostname) + 8);
        sprintf(remotename, "http://%s", hostname);

        if(user) {
            int len;
	    char *buf = mmalloc((strlen(pass) + strlen(user)) * 2 + 4);
	    char *userpass = mmalloc(strlen(user) + strlen(pass) + 2);
	    sprintf(userpass, "%s:%s", user, pass);
            len=fmt_base64(buf,userpass,strlen(userpass));
	    free(userpass);
            buf[len]='\0';
            authorization = mmalloc(strlen(buf) + 30);
            sprintf(authorization, "Proxy-Authorization: Basic %s\r\n", buf);
            free(buf);
        }
    }

#if defined(C_CYGWIN) || defined(C_OS2)
    if((fd = open(file, O_WRONLY|O_CREAT|O_EXCL|O_BINARY, 0644)) == -1) {
#else
    if((fd = open(file, O_WRONLY|O_CREAT|O_EXCL, 0644)) == -1) {
#endif
	    char currdir[512];

	getcwd(currdir, sizeof(currdir));
	logg("^Can't create new file %s in %s\n", file, currdir);
	logg("^The database directory must be writable for UID %d or GID %d\n", getuid(), getgid());
	return 57;
    }

#ifdef NO_SNPRINTF
    sprintf(cmd, "GET %s/%s HTTP/1.1\r\n"
	     "Host: %s\r\n%s"
	     "User-Agent: "PACKAGE"/"VERSION"\r\n"
	     "Cache-Control: no-cache\r\n"
	     "Connection: close\r\n"
	     "\r\n", (remotename != NULL)?remotename:"", dbfile, hostname, (authorization != NULL)?authorization:"");
#else
    snprintf(cmd, sizeof(cmd), "GET %s/%s HTTP/1.1\r\n"
	     "Host: %s\r\n%s"
	     "User-Agent: "PACKAGE"/"VERSION"\r\n"
	     "Cache-Control: no-cache\r\n"
	     "Connection: close\r\n"
	     "\r\n", (remotename != NULL)?remotename:"", dbfile, hostname, (authorization != NULL)?authorization:"");
#endif
    write(socketfd, cmd, strlen(cmd));

    free(remotename);
    free(authorization);

    /* read all the http headers */

    ch = buffer;
    i = 0;
    while (1) {
      /* recv one byte at a time, until we reach \r\n\r\n */

      if(recv(socketfd, buffer + i, 1, 0) == -1) {
        logg("^Error while reading database from %s\n", hostname);
        close(fd);
        unlink(file);
        return 52;
      }

      if (i>2 && *ch == '\n' && *(ch - 1) == '\r' && *(ch - 2) == '\n' && *(ch - 3) == '\r') {
	i++;
	break;
      }
      ch++;
      i++;
    }

    buffer[i] = 0;

    /* check whether the resource actually existed or not */

    if ((strstr(buffer, "HTTP/1.1 404")) != NULL) { 
      logg("^%s not found on remote server\n", dbfile);
      close(fd);
      unlink(file);
      return 58;
    }

    /* receive body and write it to disk */

    while((bread = read(socketfd, buffer, FILEBUFF))) {
	write(fd, buffer, bread);
	logg("Downloading %s [%c]\r", dbfile, rotation[rot]);
	fflush(stdout);
	rot++;
	rot %= 4;
    }

    logg("Downloading %s [*]\n", dbfile);
    close(fd);
    return 0;
}

const char base64[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

unsigned int fmt_base64(char* dest,const char* src,unsigned int len) {
    register const unsigned char* s=(const unsigned char*) src;
    unsigned short bits=0,temp=0;
    unsigned long written=0,i;
    for (i=0; i< len; ++i) {
	temp<<=8; temp+=s[i]; bits+=8;
	while (bits>6) {
	    if (dest) dest[written]=base64[((temp>>(bits-6))&63)];
	    ++written; bits-=6;
	}
    }
    if (bits) {
	temp<<=(6-bits);
	if (dest) dest[written]=base64[temp&63];
	++written;
    }
    while (written&3) { if (dest) dest[written]='='; ++written; }
    return written;
}
