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
	char *oldmd5 = NULL, *old2md5 = NULL, *newmd5 = NULL, 
	     *new2md5 = NULL, *downmd5, *tempname;
	int hostfd, vir;
	short int updatedb = 0, updatedb2 = 0, nodb = 0, nodb2 = 0;
	time_t currtime;
	const char *proxy;	/* proxy support njh@bandsman.co.uk */
	const char *user;

    time(&currtime);
    logg("Checking for a new database - started at %s", ctime(&currtime));
    mprintf("Checking for a new database - started at %s", ctime(&currtime));


    /* first thing we want is a local file md5 checksum */
    if(fileinfo(DB1NAME, 1) == -1) {
	/* there is no database, so we just download a new one */
	nodb = 1; 
	mprintf(DB1NAME" not found in the data directory.\n");
    } else {
	if((oldmd5 = cl_md5file(DB1NAME)) == NULL) {
	    mprintf("@Can't create md5 checksum of the "DB1NAME" database.\n");
	    return 51;
	}
    }

    if(fileinfo(DB2NAME, 1) == -1) {
	nodb2 = 1; 
	mprintf(DB2NAME" not found in the data directory.\n");
    } else {
	if((old2md5 = cl_md5file(DB2NAME)) == NULL) {
	    mprintf("@Can't create md5 checksum of the "DB2NAME" database.\n");
	    return 51;
	}
    }


    if(optl(opt, "proxy-user")) {
	user = getargl(opt, "proxy-user");
    } else {
	user = NULL;
    }

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
	mprintf("*Connecting via %s\n", proxy);

    hostfd = wwwconnect(hostname, proxy);

    if(hostfd < 0) {
	mprintf("@Connection with %s failed.\n", hostname);
	return 52;
    } else
	mprintf("Connected to %s.\n", hostname);


    if((newmd5 = get_md5_checksum("viruses.md5", hostfd, hostname, proxy, user)) == NULL) {
	mprintf("@Can't get viruses.md5 sum from %s\n", hostname);
	close(hostfd);
	return 52;
    }

    /* ok, we have md5 sum from Internet */

    if(oldmd5 && !strncmp(oldmd5, newmd5, 32)) {
	mprintf(DB1NAME" is up to date.\n");
	logg(DB1NAME" is up to date.\n");
    } else
	updatedb = 1;

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

    if((new2md5 = get_md5_checksum("viruses2.md5", hostfd, hostname, proxy, user)) == NULL) {
	mprintf("@Can't get viruses2.md5 sum from %s\n", hostname);
	close(hostfd);
	return 52;
    }

    /* ok, we have md5 sum from Internet */

    if(old2md5 && !strncmp(old2md5, new2md5, 32)) {
	mprintf(DB2NAME" is up to date.\n");
	logg(DB2NAME" is up to date.\n");
    } else
	updatedb2 = 1;

    if(!updatedb && !updatedb2) {
	close(hostfd);
	return 1;
    }

    if(updatedb) {

	/* temporary file is created in clamav's directory thus we don't need
	 * to create it immediately, because race conditions are impossible
	 */
	tempname = cl_gentemp(".");

	/* download the database */
	/* FIXME: We need to reconnect, because we won't be able to donwload
	 * the database. The problem doesn't exist with my local apache.
	 * Some code change is needed in get_md5_checksum().
	 */

	/* begin bug work-around */
	close(hostfd);
	hostfd = wwwconnect(hostname, proxy);

	if(hostfd < 0) {
	    mprintf("@Connection with %s failed.\n", hostname);
	    free(tempname);
	    return 52;
	};
	/* end */

	if(get_database(DB1NAME, hostfd, tempname, hostname, proxy, user)) {
	    mprintf("@Can't download "DB1NAME" from %s\n", hostname);
	    unlink(tempname);
	    free(tempname);
	    close(hostfd);
	    return 52;
	}

	close(hostfd);

	/* ok, we have new database */
	if((downmd5 = cl_md5file(tempname)) == NULL) {
	    unlink(tempname);
	    free(tempname);
	    mprintf("@Can't create md5 checksum of the virus database.\n");
	    return 51;
	}

	if(!strcmp(newmd5, downmd5)) {
	    if(!nodb && unlink(DB1NAME)) {
		mprintf("@Can't unlink "DB1NAME" file. Fix the problem and try again.\n");
		unlink(tempname);
		free(tempname);
		return 53;
	    } else
		rename(tempname, DB1NAME);
	} else {
	    mprintf("@The checksum of "DB1NAME" database isn't ok. Please check it yourself or try again.\n");
	    unlink(tempname);
	    free(tempname);
	    return 54;
	}

	unlink(tempname);
	free(tempname);
	free(downmd5);
    }

    if(updatedb2) {
	tempname = cl_gentemp(".");

	/* download viruses.db2 */

	/* begin bug work-around */
	close(hostfd);
	hostfd = wwwconnect(hostname, proxy);

	if(hostfd < 0) {
	    mprintf("@Connection with %s failed.\n", hostname);
	    free(tempname);
	    return 52;
	};
	/* end */

	if(get_database(DB2NAME, hostfd, tempname, hostname, proxy, user)) {
	    mprintf("@Can't download "DB2NAME" from %s\n", hostname);
	    unlink(tempname);
	    free(tempname);
	    close(hostfd);
	    return 52;
	}

	close(hostfd);

	/* ok, we have new database */
	if((downmd5 = cl_md5file(tempname)) == NULL) {
	    unlink(tempname);
	    free(tempname);
	    mprintf("@Can't create md5 checksum of the virus database.\n");
	    return 51;
	}

	if(!strcmp(new2md5, downmd5)) {
	    if(!nodb2 && unlink(DB2NAME)) {
		mprintf("@Can't unlink "DB2NAME" file. Fix the problem and try again.\n");
		unlink(tempname);
		free(tempname);
		return 53;
	    } else
		rename(tempname, DB2NAME);
	} else {
	    mprintf("@The checksum of "DB2NAME" database isn't ok. Please check it yourself or try again.\n");
	    unlink(tempname);
	    free(tempname);
	    return 54;
	}

	unlink(tempname);
	free(tempname);
	free(downmd5);
    }

    vir = countlines(DB1NAME);
    vir += countlines(DB2NAME);

    mprintf("Database updated (containing in total %d signatures).\n", vir);
    logg("Database updated (containing in total %d signatures).\n", vir);

    if(optl(opt, "daemon-notify")) {
	    const char *clamav_conf = getargl(opt, "daemon-notify");
	if(!clamav_conf)
	    clamav_conf = DEFAULT_CFG;

	notify(clamav_conf);
    }

    if(optl(opt, "on-update-execute"))
	system(getargl(opt, "on-update-execute"));

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
char *
get_md5_checksum(const char *file, int socketfd, const char *hostname, const char *proxy, const char *user)
{
	char cmd[512], buffer[FBUFFSIZE];
	char *md5sum, *ch, *tmp;
	int i, j, bread, cnt;
	char *remotename = NULL, *authorization = NULL;

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

    mprintf("Reading md5 sum (%s): ", file);

#ifdef	NO_SNPRINTF
    sprintf(cmd, "GET %s/database/%s HTTP/1.1\r\n"
	"Host: %s\r\n%s"
	"User-Agent: "PACKAGE"/"VERSION"\r\n"
	"Cache-Control: no-cache\r\n"
	"Connection: close\r\n"
	"\r\n", (remotename != NULL)?remotename:"", file, hostname, (authorization != NULL)?authorization:"");
#else
    snprintf(cmd, sizeof(cmd), "GET %s/database/%s HTTP/1.1\r\n"
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
	mprintf("@Error while reading md5 sum of database from %s\n", hostname);
	return NULL;
    }

    if ((strstr(buffer, "HTTP/1.1 404")) != NULL) { 
      mprintf("@md5 sum not found on remote server\n");
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

    md5sum = (char *) mcalloc(33, sizeof(char));
    
    for (j=0; j<32; j++) {
      if (!ch || (ch && !*ch) || (ch && !isalnum(ch[j]))) {
	mprintf("@Malformed md5 checksum detected.\n");
	free(md5sum);
	return NULL;
      }
      md5sum[j] = ch[j];
    }

    mprintf("OK\n");
    return md5sum;
}

/* njh@bandsman.co.uk: added proxy support */
/* TODO: use a HEAD instruction to see if the file has been changed */
int
get_database(const char *dbfile, int socketfd, const char *file, const char *hostname, const char *proxy, const char *user)
{
	char cmd[512], buffer[FBUFFSIZE];
	char *ch;
	int bread, fd, i;
	char *remotename = NULL, *authorization = NULL;


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
    sprintf(cmd, "GET %s/database/%s HTTP/1.1\r\n"
	     "Host: %s\r\n%s"
	     "User-Agent: "PACKAGE"/"VERSION"\r\n"
	     "Cache-Control: no-cache\r\n"
	     "Connection: close\r\n"
	     "\r\n", (remotename != NULL)?remotename:"", dbfile, hostname, (authorization != NULL)?authorization:"");
#else
    snprintf(cmd, sizeof(cmd), "GET %s/database/%s HTTP/1.1\r\n"
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

    mprintf("Downloading %s ", dbfile);

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
	mprintf(".");
    }

    mprintf(" done\n");
    close(fd);
    return 0;
}

int countlines(const char *filename)
{
	FILE *fd;
	char buff[65536];
	int lines = 0;

    if((fd = fopen(filename, "r")) == NULL)
	return 0;

    while(fgets(buff, sizeof(buff), fd))
	lines++;

    fclose(fd);
    return lines;
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
