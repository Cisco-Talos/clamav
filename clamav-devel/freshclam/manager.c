/*
 *  Copyright (C) 2002, 2003 Tomasz Kojm <zolw@konarski.edu.pl>
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

#include "others.h"
#include "options.h"
#include "defaults.h"
#include "manager.h"
#include "shared.h"
#include "notify.h"

int downloadmanager(const struct optstruct *opt, const char *hostname)
{
	time_t currtime;
	int ret, updated = 0, signo = 0;


    time(&currtime);
    mprintf("ClamAV update process started at %s", ctime(&currtime));
    logg("ClamAV update process started at %s", ctime(&currtime));

#ifndef HAVE_GMP
    mprintf("SECURITY WARNING: NO SUPPORT FOR DIGITAL SIGNATURES\n");
    logg("SECURITY WARNING: NO SUPPORT FOR DIGITAL SIGNATURES\n");
#endif

    if((ret = downloaddb(DB1NAME, "main.cvd", hostname, &signo, opt)) > 50)
	return ret;
    else if(ret == 0)
	updated = 1;

    if((ret = downloaddb(DB2NAME, "daily.cvd", hostname, &signo, opt)) > 50)
	return ret;
    else if(ret == 0)
	updated = 1;

    if(updated) {
	mprintf("Database updated (%d signatures) from %s.\n", signo, hostname);
	logg("Database updated (%d signatures) from %s.\n", signo, hostname);

#ifdef BUILD_CLAMD
	if(optl(opt, "daemon-notify")) {
		const char *clamav_conf = getargl(opt, "daemon-notify");
	    if(!clamav_conf)
		clamav_conf = DEFAULT_CFG;

	    notify(clamav_conf);
	}
#endif

	if(optl(opt, "on-update-execute"))
	    system(getargl(opt, "on-update-execute"));

	return 0;

    } else
	return 1;
}

int downloaddb(const char *localname, const char *remotename, const char *hostname, int *signo, const struct optstruct *opt)
{
	struct cl_cvd *current, *remote;
	int hostfd, nodb = 0, ret;
	char  *tempname;
	const char *proxy, *user;


    if((current = cl_cvdhead(localname)) == NULL)
	nodb = 1;

    if(optl(opt, "proxy-user"))
	user = getargl(opt, "proxy-user");
    else
	user = NULL;

    /*
     * njh@bandsman.co.uk: added proxy support. Tested using squid 2.4
     */
    if(optl(opt, "http-proxy")) {
	proxy = getargl(opt, "http-proxy");
	if(strncasecmp(proxy, "http://", 7) == 0)
	    proxy += 7;
    } else if((proxy = getenv("http_proxy"))) {
	char *no_proxy;

	if(strncasecmp(proxy, "http://", 7) == 0)
		proxy = &proxy[7];

	if((no_proxy = getenv("no_proxy"))) {
		const char *ptr;
		for(ptr = strtok(no_proxy, ","); ptr; ptr = strtok(NULL, ","))
			if(strcasecmp(ptr, hostname) == 0) {
				proxy = NULL;
				break;
			}
	}
	if(proxy && strlen(proxy) == 0)
		proxy = NULL;
    }
    if(proxy)
	mprintf("Connecting via %s\n", proxy);

    hostfd = wwwconnect(hostname, proxy);

    if(hostfd < 0) {
	mprintf("@Connection with %s failed.\n", hostname);
	return 52;
    } else
	mprintf("*Connected to %s.\n", hostname);


    if(!(remote = remote_cvdhead(remotename, hostfd, hostname, proxy, user))) {
	mprintf("@Can't read %s header from %s\n", remotename, hostname);
	close(hostfd);
	return 52;
    }

    *signo += current->sigs; /* we need to do it just here */

    if(current && (current->version >= remote->version)) {
	mprintf("%s is up to date (version: %d, sigs: %d, f-level: %d, builder: %s)\n", localname, current->version, current->sigs, current->fl, current->builder);
	logg("%s is up to date (version: %d, sigs: %d, f-level: %d, builder: %s)\n", localname, current->version, current->sigs, current->fl, current->builder);
	close(hostfd);
	cl_cvdfree(current);
	cl_cvdfree(remote);
	return 1;
    }

    if(current)
	cl_cvdfree(current);

    cl_cvdfree(remote);

    /* FIXME: We need to reconnect, because we won't be able to donwload
     * the database. The problem doesn't exist with my local apache.
     * Some code change is needed in get_md5_checksum().
     */
    /* begin bug work-around */
    close(hostfd);
    hostfd = wwwconnect(hostname, proxy);

    if(hostfd < 0) {
	mprintf("@Connection with %s failed.\n", hostname);
	return 52;
    };
    /* end */

    /* temporary file is created in clamav's directory thus we don't need
     * to create it immediately because race condition is not possible here
     */
    tempname = cl_gentemp(".");

    if(get_database(remotename, hostfd, tempname, hostname, proxy, user)) {
        mprintf("@Can't download %s from %s\n", remotename, hostname);
        unlink(tempname);
        free(tempname);
        close(hostfd);
        return 52;
    }

    close(hostfd);

    if((ret = cl_cvdverify(tempname))) {
        mprintf("@Verification: %s\n", cl_strerror(ret));
        unlink(tempname);
        free(tempname);
        return 54;
    }

    if(!nodb && unlink(localname)) {
	mprintf("@Can't unlink %s. Please fix it and try again.\n", localname);
	unlink(tempname);
	free(tempname);
	return 53;
    } else
	rename(tempname, localname);

    if((current = cl_cvdhead(localname)) == NULL) {
	mprintf("@Can't read CVD header of new %s database.\n", localname);
	return 54;
    }

    mprintf("%s updated (version: %d, sigs: %d, f-level: %d, builder: %s)\n", localname, current->version, current->sigs, current->fl, current->builder);
    logg("%s updated (version: %d, sigs: %d, f-level: %d, builder: %s)\n", localname, current->version, current->sigs, current->fl, current->builder);

    cl_cvdfree(current);
    free(tempname);
    return 0;
}

/* this function returns socket descriptor */
/* proxy support finshed by njh@bandsman.co.uk */
int
wwwconnect(const char *server, const char *proxy)
{
	int socketfd, port;
	struct sockaddr_in name;
	struct hostent *host;
	char *portpt, *proxycpy = NULL;
	const char *hostpt;


    /* njh@bandsman.co.uk: for BEOS */
#ifdef PF_INET
    socketfd = socket(PF_INET, SOCK_STREAM, 0);
#else
    socketfd = socket(AF_INET, SOCK_STREAM, 0);
#endif

    name.sin_family = AF_INET;

    if(proxy) {
	proxycpy = strdup(proxy);
	hostpt = proxycpy;
	portpt = strchr(proxycpy, ':');
	if(portpt) {
		*portpt = 0;
		port = atoi(++portpt);
	} else {
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
        if(proxycpy)
	    free(proxycpy);
	return -1;
    }

    name.sin_addr = *((struct in_addr *) host->h_addr);
    name.sin_port = htons(port);

    if(connect(socketfd, (struct sockaddr *) &name, sizeof(struct sockaddr_in)) == -1) {
	mprintf("@Can't connect to port %d of host %s\n", port, hostpt);
	close(socketfd);
	if(proxycpy)
	    free(proxycpy);
	return -2;
    }

    if(proxycpy)
	free(proxycpy);
    return socketfd;
}

/* njh@bandsman.co.uk: added proxy support */
/* TODO: use a HEAD instruction to see if the file has been changed */
struct cl_cvd *remote_cvdhead(const char *file, int socketfd, const char *hostname, const char *proxy, const char *user)
{
	char cmd[512], head[513], buffer[FBUFFSIZE], *ch, *tmp;
	int i, j, bread, cnt;
	char *remotename = NULL, *authorization = NULL;
	struct cl_cvd *cvd;

    if(proxy) {
        remotename = mmalloc(strlen(hostname) + 8);
        sprintf(remotename, "http://%s", hostname);

        if(user) {
            int len;
    	    char* buf = mmalloc(strlen(user)*2+4);
            len=fmt_base64(buf,user,strlen(user));
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
	"\r\n", (remotename != NULL)?remotename:"", file, hostname, (authorization != NULL)?authorization:"");
#else
    snprintf(cmd, sizeof(cmd), "GET %s/%s HTTP/1.1\r\n"
	     "Host: %s\r\n%s"
	     "User-Agent: "PACKAGE"/"VERSION"\r\n"
	     "Cache-Control: no-cache\r\n"
	     "Connection: close\r\n"
	     "\r\n", (remotename != NULL)?remotename:"", file, hostname, (authorization != NULL)?authorization:"");
#endif
    write(socketfd, cmd, strlen(cmd));

    free(remotename);
    free(authorization);

    tmp = buffer;
    cnt = FBUFFSIZE;
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
int
get_database(const char *dbfile, int socketfd, const char *file, const char *hostname, const char *proxy, const char *user)
{
	char cmd[512], buffer[FBUFFSIZE];
	char *ch;
	int bread, fd, i, rot = 0;
	char *remotename = NULL, *authorization = NULL;
	const char *rotation = "|/-\\";


    if(proxy) {
        remotename = mmalloc(strlen(hostname) + 8);
        sprintf(remotename, "http://%s", hostname);

        if(user) {
            int len;
	    char* buf = mmalloc(strlen(user)*2+4);
            len=fmt_base64(buf,user,strlen(user));
            buf[len]='\0';
            authorization = mmalloc(strlen(buf) + 30);
            sprintf(authorization, "Proxy-Authorization: Basic %s\r\n", buf);
            free(buf);
        }
    }

    if((fd = open(file, O_WRONLY|O_CREAT|O_EXCL, 0644)) == -1) {
	mprintf("@Can't open new file %s to write\n", file);
	perror("open");
	return -1;
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

    if ((bread = recv(socketfd, buffer, FBUFFSIZE, 0)) == -1) {
      mprintf("@Error while reading database from %s\n", hostname);
      return -1;
    }

    if ((strstr(buffer, "HTTP/1.1 404")) != NULL) { 
      mprintf("@%s not found on remote server\n", dbfile);
      return -1;
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

    write(fd, ch, bread - i);
    while((bread = read(socketfd, buffer, FBUFFSIZE))) {
	write(fd, buffer, bread);
	mprintf("Downloading %s [%c]\r", dbfile, rotation[rot]);
	fflush(stdout);
	rot = ++rot % 4;
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
