/*
 *  Copyright (C) 2002 - 2004 Tomasz Kojm <tkojm@clamav.net>
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

#include "options.h"
#include "defaults.h"
#include "manager.h"
#include "notify.h"
#include "memory.h"
#include "output.h"
#include "../libclamav/others.h"
#include "../libclamav/str.h" /* cli_strtok */
#include "dns.h"


int downloadmanager(const struct cfgstruct *copt, const struct optstruct *opt, const char *hostname)
{
	time_t currtime;
	int ret, updated = 0, signo = 0, usedns;
	char ipaddr[16];
	struct cfgstruct *cpt;


    time(&currtime);
    mprintf("ClamAV update process started at %s", ctime(&currtime));
    logg("ClamAV update process started at %s", ctime(&currtime));

#ifndef HAVE_GMP
    mprintf("SECURITY WARNING: NO SUPPORT FOR DIGITAL SIGNATURES\n");
    mprintf("See the FAQ at http://www.clamav.net/faq.html for an explanation.\n");
    logg("SECURITY WARNING: NO SUPPORT FOR DIGITAL SIGNATURES\n");
    logg("See the FAQ at http://www.clamav.net/faq.html for an explanation.\n");
#endif

    optl(opt, "no-dns") ? (usedns = 0) : (usedns = 1);

    memset(ipaddr, 0, sizeof(ipaddr));

    if((ret = downloaddb(DB1NAME, "main.cvd", hostname, ipaddr, &signo, copt, usedns)) > 50)
	return ret;
    else if(ret == 0)
	updated = 1;

    /* if ipaddr[0] != 0 it will use it to connect to the web host */
    if((ret = downloaddb(DB2NAME, "daily.cvd", hostname, ipaddr, &signo, copt, usedns)) > 50)
	return ret;
    else if(ret == 0)
	updated = 1;

    if(updated) {
	if(cfgopt(copt, "HTTPProxyServer")) {
	    mprintf("Database updated (%d signatures) from %s.\n", signo, hostname);
	    logg("Database updated (%d signatures) from %s.\n", signo, hostname);
	} else {
	    mprintf("Database updated (%d signatures) from %s (%s).\n", signo, hostname, ipaddr);
	    logg("Database updated (%d signatures) from %s (%s).\n", signo, hostname, ipaddr);
	}

#ifdef BUILD_CLAMD
	if(optl(opt, "daemon-notify")) {
		const char *clamav_conf = getargl(opt, "daemon-notify");
	    if(!clamav_conf)
		clamav_conf = CONFDIR"/clamd.conf";

	    notify(clamav_conf);
	} else if((cpt = cfgopt(copt, "NotifyClamd"))) {
		const char *clamav_conf = cpt->strarg;
	    if(!clamav_conf)
		clamav_conf = CONFDIR"/clamd.conf";

	    notify(clamav_conf);
	}
#endif

	if(optl(opt, "on-update-execute"))
	    system(getargl(opt, "on-update-execute"));
	else if((cpt = cfgopt(copt, "OnUpdateExecute")))
	    system(cpt->strarg);

	return 0;

    } else
	return 1;
}

static int isnumb(const char *str)
{
	int i;

    for(i = 0; i < strlen(str); i++)
	if(!isdigit(str[i]))
	    return 0;

    return 1;
}

int downloaddb(const char *localname, const char *remotename, const char *hostname, char *ip, int *signo, const struct cfgstruct *copt, int usedns)
{
	struct cl_cvd *current, *remote;
	struct cfgstruct *cpt;
	int hostfd, nodb = 0, dbver = -1, ret, port = 0, ttl;
	char  *tempname, ipaddr[16], *dnsreply, *pt;
	const char *proxy = NULL, *user = NULL, *pass = NULL;
	int flevel = cl_retflevel();


    if((current = cl_cvdhead(localname)) == NULL)
	nodb = 1;


    if(!nodb && usedns && (cpt = cfgopt(copt, "DNSDatabaseInfo"))) {
	if((dnsreply = txtquery(cpt->strarg, &ttl))) {
		int field = 0;

	    mprintf("*TTL: %d\n", ttl);

	    if(!strcmp(remotename, "main.cvd")) {
		field = 1;
	    } else if(!strcmp(remotename, "daily.cvd")) {
		field = 2;
	    } else {
		mprintf("WARNING: Unknown database name (%s) passed.\n", remotename);
		logg("WARNING: Unknown database name (%s) passed.\n", remotename);
	    }

	    if(field && (pt = cli_strtok(dnsreply, 3, ":"))) {
		    int rt;
		    time_t ct;

		rt = atoi(pt);
		free(pt);
		time(&ct);
		if((int) ct - rt > 10800) {
		    mprintf("WARNING: DNS record is older than 3 hours.\n");
		    logg("WARNING: DNS record is older than 3 hours.\n");
		    field = 0;
		}

	    } else {
		field = 0;
	    }

	    if(field && (pt = cli_strtok(dnsreply, field, ":"))) {
		if(!isnumb(pt)) {
		    mprintf("WARNING: Broken database version in TXT record.\n");
		    logg("WARNING: Broken database version in TXT record.\n");
		} else {
		    dbver = atoi(pt);
		    mprintf("*%s version from DNS: %d\n", remotename, dbver);
		}
		free(pt);
	    } else {
		mprintf("WARNING: Invalid DNS reply.\n");
		logg("WARNING: Invalid DNS reply.\n");
	    }

	    if(field == 1 && (pt = cli_strtok(dnsreply, 0, ":"))) {
		mprintf("*Software version from DNS: %s\n", pt);
		if(!strstr(cl_retver(), "devel")) {
		    if(strcmp(cl_retver(), pt)) {
			mprintf("WARNING: Your ClamAV installation is OUTDATED - please update immediately!\n");
			mprintf("WARNING: Local version: %s Recommended version: %s\n", cl_retver(), pt);
			logg("WARNING: Your ClamAV installation is OUTDATED - please update immediately!\n");
			logg("WARNING: Local version: %s Recommended version: %s\n", cl_retver(), pt);
		    }
		}
		free(pt);
	    }

	    free(dnsreply);
	}
    }

    /* Initialize proxy settings */
    if((cpt = cfgopt(copt, "HTTPProxyServer"))) {
	proxy = cpt->strarg;
	if(strncasecmp(proxy, "http://", 7) == 0)
	    proxy += 7;

	if((cpt = cfgopt(copt, "HTTPProxyUsername"))) {
	    user = cpt->strarg;
	    if((cpt = cfgopt(copt, "HTTPProxyPassword"))) {
		pass = cpt->strarg;
	    } else {
		mprintf("HTTPProxyUsername requires HTTPProxyPassword\n");
		if(current)
		    cl_cvdfree(current);
		return 56;
	    }
	}

	if((cpt = cfgopt(copt, "HTTPProxyPort")))
	    port = cpt->numarg;

	mprintf("Connecting via %s\n", proxy);
    }

    memset(ipaddr, 0, sizeof(ipaddr));

    if(!nodb && dbver == -1) {
	if(ip[0]) /* use ip to connect */
	    hostfd = wwwconnect(ip, proxy, port, ipaddr);
	else
	    hostfd = wwwconnect(hostname, proxy, port, ipaddr);

	if(hostfd < 0) {
	    mprintf("@Connection with %s failed.\n", hostname);
	    if(current)
		cl_cvdfree(current);
	    return 52;
	} else {
	    mprintf("*Connected to %s (%s).\n", hostname, ipaddr);
	}

	if(!ip[0])
	    strcpy(ip, ipaddr);

	if(!(remote = remote_cvdhead(remotename, hostfd, hostname, proxy, user, pass))) {
	    mprintf("@Can't read %s header from %s (%s)\n", remotename, hostname, ipaddr);
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
	mprintf("%s is up to date (version: %d, sigs: %d, f-level: %d, builder: %s)\n", localname, current->version, current->sigs, current->fl, current->builder);
	logg("%s is up to date (version: %d, sigs: %d, f-level: %d, builder: %s)\n", localname, current->version, current->sigs, current->fl, current->builder);

	if(flevel < current->fl) {
	    /* display warning even for already installed database */
	    mprintf("WARNING: Your ClamAV installation is OUTDATED - please update immediately!\n");
	    mprintf("WARNING: Current functionality level = %d, required = %d\n", flevel, current->fl);
	    logg("WARNING: Your ClamAV installation is OUTDATED - please update immediately!\n");
	    logg("WARNING: Current functionality level = %d, required = %d\n", flevel, current->fl);
	}

	*signo += current->sigs;
	cl_cvdfree(current);
	return 1;
    }

    if(current)
	cl_cvdfree(current);

    if(ipaddr[0]) {
	/* use ipaddr in order to connect to the same mirror */
	hostfd = wwwconnect(ipaddr, proxy, port, NULL);
    } else {
	hostfd = wwwconnect(hostname, proxy, port, ipaddr);
	if(!ip[0])
	    strcpy(ip, ipaddr);
    }

    if(hostfd < 0) {
	if(ipaddr[0])
	    mprintf("@Connection with %s failed.\n", ipaddr);
	else
	    mprintf("@Connection with %s failed.\n", hostname);
	return 52;
    };

    /* the temporary file is created in a directory owned by clamav so race
     * conditions are not possible
     */
    tempname = cli_gentemp(".");

    if((ret = get_database(remotename, hostfd, tempname, hostname, proxy, user, pass))) {
        mprintf("@Can't download %s from %s\n", remotename, ipaddr);
        unlink(tempname);
        free(tempname);
        close(hostfd);
        return ret;
    }

    close(hostfd);

    if((ret = cl_cvdverify(tempname))) {
        mprintf("@Verification: %s\n", cl_strerror(ret));
        unlink(tempname);
        free(tempname);
        return 54;
    }

    if((current = cl_cvdhead(tempname)) == NULL) {
	mprintf("@Can't read CVD header of new %s database.\n", localname);
	unlink(tempname);
	free(tempname);
	return 54;
    }

    if(current->version < dbver) {
	mprintf("@Mirrors are not fully synchronized. Please try again later.\n");
    	cl_cvdfree(current);
	unlink(tempname);
	free(tempname);
	return 59;
    }

    if(!nodb && unlink(localname)) {
	mprintf("@Can't unlink %s. Please fix it and try again.\n", localname);
    	cl_cvdfree(current);
	unlink(tempname);
	free(tempname);
	return 53;
    } else
	rename(tempname, localname);


    mprintf("%s updated (version: %d, sigs: %d, f-level: %d, builder: %s)\n", localname, current->version, current->sigs, current->fl, current->builder);
    logg("%s updated (version: %d, sigs: %d, f-level: %d, builder: %s)\n", localname, current->version, current->sigs, current->fl, current->builder);

    if(flevel < current->fl) {
	mprintf("WARNING: Your ClamAV installation is OUTDATED - please update immediately!\n");
	mprintf("WARNING: Current functionality level = %d, required = %d\n", flevel, current->fl);
	logg("WARNING: Your ClamAV installation is OUTDATED - please update immediately!\n");
	logg("WARNING: Current functionality level = %d, required = %d\n", flevel, current->fl);
    }

    *signo += current->sigs;
    cl_cvdfree(current);
    free(tempname);
    return 0;
}

/* this function returns socket descriptor */
/* proxy support finshed by njh@bandsman.co.uk */
int wwwconnect(const char *server, const char *proxy, int pport, char *ip)
{
	int socketfd, port, i;
	struct sockaddr_in name;
	struct hostent *host;
	char ipaddr[16];
	unsigned char *ia;
	const char *hostpt;


    if(ip)
	strcpy(ip, "???");

    /* njh@bandsman.co.uk: for BEOS */
#ifdef PF_INET
    socketfd = socket(PF_INET, SOCK_STREAM, 0);
#else
    socketfd = socket(AF_INET, SOCK_STREAM, 0);
#endif

    name.sin_family = AF_INET;

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
        mprintf("@Can't get information about %s host.\n", hostpt);
	return -1;
    }

    for(i = 0; host->h_addr_list[i] != 0; i++) {
	/* this dirty hack comes from pink - Nosuid TCP/IP ping 1.6 */
	ia = (unsigned char *) host->h_addr_list[i];
	sprintf(ipaddr, "%u.%u.%u.%u", ia[0], ia[1], ia[2], ia[3]);

	if(ip)
	    strcpy(ip, ipaddr);

	if(i > 0)
	    mprintf("Trying host %s (%s)...\n", hostpt, ipaddr);

	name.sin_addr = *((struct in_addr *) host->h_addr_list[i]);
	name.sin_port = htons(port);

	if(connect(socketfd, (struct sockaddr *) &name, sizeof(struct sockaddr_in)) == -1) {
	    mprintf("@Can't connect to port %d of host %s (%s)\n", port, hostpt, ipaddr);
	    continue;
	}

	return socketfd;
    }

    close(socketfd);
    mprintf("@No servers could be reached. Giving up\n");
    return -2;
}

/* njh@bandsman.co.uk: added proxy support */
/* TODO: use a HEAD instruction to see if the file has been changed */
struct cl_cvd *remote_cvdhead(const char *file, int socketfd, const char *hostname, const char *proxy, const char *user, const char *pass)
{
	char cmd[512], head[513], buffer[FILEBUFF], *ch, *tmp;
	int i, j, bread, cnt;
	char *remotename = NULL, *authorization = NULL;
	struct cl_cvd *cvd;

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

    mprintf("Reading CVD header (%s): ", file);

#ifdef	NO_SNPRINTF
    sprintf(cmd, "GET %s/%s HTTP/1.1\r\n"
	"Host: %s\r\n%s"
	"User-Agent: "PACKAGE"/"VERSION"\r\n"
	"Cache-Control: no-cache\r\n"
	"Connection: close\r\n"
	"Range: bytes=0-511\r\n"
	"\r\n", (remotename != NULL)?remotename:"", file, hostname, (authorization != NULL)?authorization:"");
#else
    snprintf(cmd, sizeof(cmd), "GET %s/%s HTTP/1.1\r\n"
	"Host: %s\r\n%s"
	"User-Agent: "PACKAGE"/"VERSION"\r\n"
	"Cache-Control: no-cache\r\n"
	"Connection: close\r\n"
	"Range: bytes=0-511\r\n"
	"\r\n", (remotename != NULL)?remotename:"", file, hostname, (authorization != NULL)?authorization:"");
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
	mprintf("@Error while reading CVD header of database from %s\n", hostname);
	return NULL;
    }

    if ((strstr(buffer, "HTTP/1.1 404")) != NULL) { 
      mprintf("@CVD file not found on remote server\n");
      return NULL;
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
	mprintf("@Malformed CVD header detected.\n");
	return NULL;
      }
      head[j] = ch[j];
    }

    if((cvd = cl_cvdparse(head)) == NULL)
	mprintf("@Broken CVD header.\n");
    else
	mprintf("OK\n");

    return cvd;
}

/* njh@bandsman.co.uk: added proxy support */
/* TODO: use a HEAD instruction to see if the file has been changed */
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

#ifdef C_CYGWIN
    if((fd = open(file, O_WRONLY|O_CREAT|O_EXCL|O_BINARY, 0644)) == -1) {
#else
    if((fd = open(file, O_WRONLY|O_CREAT|O_EXCL, 0644)) == -1) {
#endif
	    char currdir[512];

	getcwd(currdir, sizeof(currdir));
	mprintf("@Can't create new file %s in %s\n", file, currdir);
	mprintf("@The database directory must be writable for UID %d or GID %d\n", getuid(), getgid());
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
        mprintf("@Error while reading database from %s\n", hostname);
        close(fd);
        unlink(file);
        return 52;
      }

      if (i>2 && *ch == '\n' && *(ch - 1) == '\r' && *(ch - 2) == '\n' && *(ch - 3) == '\r') {
	ch++;
	i++;
	break;
      }
      ch++;
      i++;
    }

    /* check whether the resource actually existed or not */

    if ((strstr(buffer, "HTTP/1.1 404")) != NULL) { 
      mprintf("@%s not found on remote server\n", dbfile);
      close(fd);
      unlink(file);
      return 58;
    }

    /* receive body and write it to disk */

    while((bread = read(socketfd, buffer, FILEBUFF))) {
	write(fd, buffer, bread);
	mprintf("Downloading %s [%c]\r", dbfile, rotation[rot]);
	fflush(stdout);
	rot++;
	rot %= 4;
    }

    mprintf("Downloading %s [*]\n", dbfile);
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
