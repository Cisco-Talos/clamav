/*
 *  Copyright (C) 2002 Tomasz Kojm <zolw@konarski.edu.pl>
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
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <clamav.h>

#include "cfgfile.h"
#include "others.h"
#include "scanner.h"
#include "defaults.h"

int checksymlink(const char *path)
{
	struct stat statbuf;

    if(stat(path, &statbuf) == -1)
	return -1;

    if(S_ISDIR(statbuf.st_mode))
	return 1;

    if(S_ISREG(statbuf.st_mode))
	return 2;

    return 0;
}

/* :set nowrap, if you don't like this style ;)) */
int dirscan(const char *dirname, char **virname, unsigned long int *scanned, const struct cl_node *root, const struct cl_limits *limits, int options, const struct cfgstruct *copt, int odesc, unsigned int *reclev, short contscan)
{
	DIR *dd;
	struct dirent *dent;
	struct stat statbuf;
	struct cfgstruct *cpt;
	char *fname;
	int ret = 0;

    if((cpt = cfgopt(copt, "MaxDirectoryRecursion"))) {
	if(cpt->numarg) {
	    if(*reclev > cpt->numarg) {
		logg("*Directory recursion limit exceeded at %s\n", dirname);
		return 0;
	    }
	    (*reclev)++;
	}
    }

    if((dd = opendir(dirname)) != NULL) {
	while((dent = readdir(dd))) {
	    if(dent->d_ino) {
		if(strcmp(dent->d_name, ".") && strcmp(dent->d_name, "..")) {
		    /* build the full name */
		    fname = mcalloc(strlen(dirname) + strlen(dent->d_name) + 2, sizeof(char));
		    sprintf(fname, "%s/%s", dirname, dent->d_name);

		    /* stat the file */
		    if(lstat(fname, &statbuf) != -1) {
			if((S_ISDIR(statbuf.st_mode) && !S_ISLNK(statbuf.st_mode)) || (S_ISLNK(statbuf.st_mode) && (checksymlink(fname) == 1) && cfgopt(copt, "FollowDirectorySymlinks"))) {
			    if(dirscan(fname, virname, scanned, root, limits, options, copt, odesc, reclev, contscan) == 1) {
				free(fname);
				closedir(dd);
				return 1;
			    }
			} else
			    if(S_ISREG(statbuf.st_mode) || (S_ISLNK(statbuf.st_mode) && (checksymlink(fname) == 2) && cfgopt(copt, "FollowFileSymlinks")))
				if(cl_scanfile(fname, virname, scanned, root, limits, options) == CL_VIRUS) {
				    mdprintf(odesc, "%s: %s FOUND\n", fname, *virname);
				    logg("%s: %s FOUND\n", fname, *virname);
				    if(!contscan) {
					closedir(dd);
					free(fname);
					return 1;
				    } else
					ret = 2;
				}
		    }

		    free(fname);
		}
	    }
	}
    } else {
	return -1;
    }

    (*reclev)--;
    closedir(dd);
    return ret;

}

int scan(const char *filename, unsigned long int *scanned, const struct cl_node *root, const struct cl_limits *limits, int options, const struct cfgstruct *copt, int odesc, short contscan)
{
	struct stat sb;
	int ret = 0, reclev = 0;
	char *virname;


    /* check permissions  */
    if(access(filename, R_OK)) {
	mdprintf(odesc, "%s: Can't access the file ERROR\n", filename);
	return -1;
    }

    /* stat file */

    if(lstat(filename, &sb) == -1) {
	mdprintf(odesc, "%s: Can't lstat() the file ERROR\n", filename);
	return -1;
    }

    switch(sb.st_mode & S_IFMT) {
	case S_IFLNK:
	    if(!cfgopt(copt, "FollowFileSymlinks"))
		break;
	    /* else go to the next case */
	case S_IFREG: 
	    if(sb.st_size == 0) { /* empty file */
		mdprintf(odesc, "%s: Empty file\n", filename);
		return 0;
	    }
	    ret = cl_scanfile(filename, &virname, scanned, root, limits, options);
	    if(ret == CL_VIRUS) {
		mdprintf(odesc, "%s: %s FOUND\n", filename, virname);
		logg("%s: %s FOUND\n", filename, virname);
	    } else if(ret != CL_CLEAN) {
		mdprintf(odesc, "%s: %s ERROR\n", filename, cl_perror(ret));
		logg("%s: %s ERROR\n", filename, cl_perror(ret));
	    } 
	    break;
	case S_IFDIR:
	    ret = dirscan(filename, &virname, scanned, root, limits, options, copt, odesc, &reclev, contscan);
	    break;
	default:
	    mdprintf(odesc, "%s: Not supported file type ERROR\n", filename);
	    return -1;
    }

    if(!ret)
	mdprintf(odesc, "%s: OK\n", filename);

    return ret;
}

int scanstream(int odesc, unsigned long int *scanned, const struct cl_node *root, const struct cl_limits *limits, int options, const struct cfgstruct *copt)
{
	int ret, portscan = CL_DEFAULT_MAXPORTSCAN, sockfd, port, acceptd, tmpd, bread;
	long int size = 0, maxsize = 0;
	short binded = 0;
	char *virname, buff[32768];
	struct sockaddr_in server;
	struct cfgstruct *cpt;
	FILE *tmp;


    while(!binded && portscan--) {
	if((port = rndnum(60000)) < 1024)
	    port += 2139;

	memset((char *) &server, 0, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_port = htons(port);
	server.sin_addr.s_addr = INADDR_ANY;

	if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	    continue;

	if(bind(sockfd, (struct sockaddr *) &server, sizeof(struct sockaddr_in)) == -1)
	    close(sockfd);
	else
	    binded = 1;

    }

    if(!binded && !portscan) {
	mdprintf(odesc, "ERROR\n");
	logg("!ScanStream: Can't find any free port.\n");
	return -1;
    } else {
	listen(sockfd, 1);
	mdprintf(odesc, "PORT %d\n", port);
    }

    if((acceptd = accept(sockfd, NULL, NULL)) == -1) {
	close(sockfd);
	mdprintf(odesc, "accept() ERROR\n");
	logg("!ScanStream: accept() failed.\n");
	return -1;
    }

    if(cfgopt(copt, "StreamSaveToDisk")) {
	if((tmp = tmpfile()) == NULL) {
	    shutdown(sockfd, 2);
	    close(sockfd);
	    mdprintf(odesc, "Temporary file ERROR\n");
	    logg("!ScanStream: Can't create temporary file.\n");
	    return -1;
	}
	tmpd = fileno(tmp);

	if((cpt = cfgopt(copt, "StreamMaxLength")))
	    maxsize = cpt->numarg;

	while((bread = read(acceptd, buff, sizeof(buff))) > 0) {
	    size += bread;

	    if(maxsize && (size + sizeof(buff)) > maxsize) {
		shutdown(sockfd, 2);
		close(sockfd);
		mdprintf(odesc, "Size exceeded ERROR\n");
		logg("^ScanStream: Size exceeded (stopped at %d, max: %d)\n", size, maxsize);
		close(tmpd);
		return -1;
	    }

	    if(write(tmpd, buff, bread) < 0) {
		shutdown(sockfd, 2);
		close(sockfd);
		mdprintf(odesc, "Temporary file -> write ERROR\n");
		logg("!ScanStream: Can't write to temporary file.\n");
		close(tmpd);
		return -1;
	    }

	}

	lseek(tmpd, 0, SEEK_SET);
	ret = cl_scandesc(tmpd, &virname, scanned, root, limits, options);
	close(tmpd);

    } else
	ret = cl_scandesc(acceptd, &virname, scanned, root, limits, 0);

    close(acceptd);
    close(sockfd);

    if(ret == CL_VIRUS) {
	mdprintf(odesc, "stream: %s FOUND\n", virname);
	logg("stream: %s FOUND\n", virname);
    } else if(ret != CL_CLEAN) {
	mdprintf(odesc, "stream: %s ERROR\n", cl_perror(ret));
	logg("stream: %s ERROR\n", cl_perror(ret));
    } else
	mdprintf(odesc, "stream: OK\n");

    return ret;
}
