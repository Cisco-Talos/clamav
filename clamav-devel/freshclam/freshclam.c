/*
 *  Copyright (C) 2002, 2003 Tomasz Kojm <zolw@konarski.edu.pl>
 *			     Damien Curtain <damien@pagefault.org>
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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>

#include "options.h"
#include "shared.h"
#include "others.h"
#include "manager.h"
#include "defaults.h"
#include "freshclam.h"


void freshclam(struct optstruct *opt)
{
	int ret;
#ifndef C_CYGWIN
	struct passwd *user;
	char *newdir;
    char *unpuser;

    if(optc(opt, 'u'))
        unpuser = getargc(opt, 'u');
    else
        unpuser = UNPUSER;

    /* freshclam shouldn't work with root priviledges */
    if(!getuid()) { 
	if((user = getpwnam(unpuser)) == NULL) {
	    mprintf("@Can't get information about user %s.\n", unpuser);
	    exit(60); /* this is critical problem, so we just exit here */
	}

	setgroups(1, &user->pw_gid);
	setgid(user->pw_gid);
	setuid(user->pw_uid);
    }
#endif

    /* initialize some important variables */

    mprintf_disabled = 0;

    if(optc(opt, 'v')) mprintf_verbose = 1;
    else mprintf_verbose = 0;

    if(optl(opt, "quiet")) mprintf_quiet = 1;
    else mprintf_quiet = 0;

    if(optl(opt, "stdout")) mprintf_stdout = 1;
    else mprintf_stdout = 0;

    if(optc(opt, 'V')) {
	mprintf("freshclam / ClamAV version "VERSION"\n");
	mexit(0);
    }

    if(optc(opt, 'h')) {
	free_opt(opt);
    	help();
    }

    /* initialize logger */

    if(optl(opt, "log-verbose")) logverbose = 1;
    else logverbose = 0;

    if(optc(opt, 'l')) {
	logfile = getargc(opt, 'l');
	if(logg("--------------------------------------\n")) {
	    mprintf("!Problem with internal logger.\n");
	    mexit(1);
	}
    } else 
	logfile = NULL;

    /* change current working directory */
    if(optl(opt, "datadir"))
	newdir = getargl(opt, "datadir");
    else
	newdir = VIRUSDBDIR;

    if(chdir(newdir)) {
	mprintf("Can't change dir to %s\n", newdir);
	exit(50);
    } else
	mprintf("Current working dir is %s\n", newdir);


    if(optc(opt, 'd')) {
	    int bigsleep, checks;

	if(!optc(opt, 'c')) {
	    mprintf("@Daemon mode requires -c (--checks) option.\n");
	    mexit(40);
	}

	checks = atoi(getargc(opt, 'c'));

	if(checks <= 0 || checks > 50) {
	    mprintf("@Wrong number of checks\n");
	    mexit(41);
	}

	bigsleep = 24*3600 / checks;
	daemonize();

	while(1) {
	    ret = download(opt);

	    if(optl(opt, "on-error-execute"))
		if(ret > 1)
		    system(getargl(opt, "on-error-execute"));

	    logg("\n--------------------------------------\n");
	    sleep(bigsleep);
	}

    } else
	ret = download(opt);

    if(optl(opt, "on-error-execute"))
	if(ret > 1)
	    system(getargl(opt, "on-error-execute"));

    mexit(ret);

}

/*void free_mirror(mirrors* m)
{
    mirrors *n;
    
    while(m)
    {
        n = m->next;
        if(m->mirror != NULL)
            free(m->mirror);
        free(m);
        m = n;
    }

}*/

int download(struct optstruct *opt)
{
	int ret = 0;
	mirrors *m = NULL, *h = NULL;
	char *last = NULL;
	char *datadir, *mirror_last;
	int mirror_used = 0;

    /*
     * If the previous database update was not from the first host
     * listed in mirrors.txt it will have been saved to DBDIR/mirror.
     * In this case use this host one more time (if it is up) for
     * database updates then revert to the order in DBDIR/mirrors.txt
     */    
    last = parse_mirror(opt);

    if(last != NULL)
    {
        if((ret = downloadmanager(opt, last)) == 0)
        {
            mprintf("Database updated from last used mirror %s.\n", last);

	    if(optl(opt, "datadir"))
	    {
		datadir = getargl(opt, "datadir");
	    }
	    else
	    {	
		datadir = DATADIR;
	    }

	    if((mirror_last = malloc(sizeof(char) * (strlen(datadir) + strlen(MIRROR) + 1))) == NULL)
	    {
		fprintf(stderr, "ERROR: Can't allocate sufficient memory\n");
		mexit(1);
	    }

	    strcpy(mirror_last, datadir);
	    strcat(mirror_last, MIRROR);

	    if(unlink(mirror_last) == -1)
	    {
		fprintf(stderr, "ERROR: Can't unlink file %s !\n", mirror_last);
	    }

            free(last);
	    free(mirror_last);
            return ret;
        }

        /* Only continue if there is an error connecting to the host */
        if((ret != 52) && (ret != 54))
        {
            free(last);
            return ret;
        }

    	free(last);
    }
        
    /*
     * There's an error in __nss_hostname_digits_dots () from /lib/libc.so.6
     * which gets triggered here for some reason.....
     * Calling fflush is a temp workaround
     */    
    fflush(NULL);
    
    h = m = parse_mirrorcfg(opt);
    
    while(m != NULL)
    {
        if((ret = downloadmanager(opt, m->mirror)) == 0)
        {
            if(mirror_used)
            {
                logg("Database updated from mirror %s.\n", m->mirror);
                mprintf("Database updated from mirror %s.\n", m->mirror);
                write_mirror(opt, m->mirror);
            }
            else
            {
                logg("Database updated from %s.\n", m->mirror);
                mprintf("Database updated from %s.\n", m->mirror);
            }

            FREE_MIRROR(h);
            return ret;
        }

        /* If we contacted a mirror then record the fact even if we
         * don't update any databases this run
         */
        if(ret == 1)
        {
            if(mirror_used > 0)
                write_mirror(opt, m->mirror);
        
            FREE_MIRROR(h);
            return ret;
        }
           
        /* Only continue if there is an error connecting to the host */
        if((ret != 52) && (ret != 54))
        {
            FREE_MIRROR(h);
            return ret;
        }
        mirror_used++;
        m = m->next;
    }

    FREE_MIRROR(h);
    return ret;
}

void write_mirror(struct optstruct *opt, char * mirror)
{
    char *datadir, *mirror_last;
    FILE *fd;
    
    if(optl(opt, "datadir"))
    {
        datadir = getargl(opt, "datadir");
    }
    else
    {
        datadir = DATADIR;
    }

    if((mirror_last = malloc(sizeof(char) * (strlen(datadir) + strlen(MIRROR) + 1))) == NULL)
    {
        fprintf(stderr, "ERROR: Can't allocate sufficient memory\n");
        mexit(1);
    }

    strcpy(mirror_last, datadir);

    strcat(mirror_last, MIRROR);

    if((fd = fopen(mirror_last, "w")) == NULL)
    {
        /* No mirror was used last time - this is normal */
        fprintf(stderr, "ERROR: Can't create file %s !\n", mirror_last);
        free(mirror_last);
        return;
    }
    
    if(!fputs(mirror, fd))
    {
        fprintf(stderr, "ERROR: Can't write to file %s !\n", mirror_last);
    }

    fclose(fd);
    free(mirror_last);
    
    return;
}

/*
 * If the previous database update was not from the first host
 * listed in mirrors.txt it will have been saved to DBDIR/mirror.
 * In this case use this host one more time (if it is up) for
 * database updates then revert to the order in DBDIR/mirrors.txt
 */
char * parse_mirror(struct optstruct *opt)
{
    char *datadir = NULL, *mirror_last  = NULL, *last = NULL;
    FILE *fd;
    char buf[BUFSIZ];
    
    if(optl(opt, "datadir"))
    {
        datadir = getargl(opt, "datadir");
    }
    else
    {
        datadir = DATADIR;
    }

    if((mirror_last = malloc(sizeof(char) * (strlen(datadir) + strlen(MIRROR) + 1))) == NULL)
    {
        fprintf(stderr, "ERROR: Can't allocate sufficient memory\n");
        mexit(1);
    }

    strcpy(mirror_last, datadir);

    strcat(mirror_last, MIRROR);

    if((fd = fopen(mirror_last, "r")) == NULL)
    {
        /* No mirror was used last time - this is normal */
        free(mirror_last);
        return NULL;
    }

    while(fgets(buf, BUFSIZ, fd))
    {
        if(buf[0] == '#')
            continue;

        if(strlen(buf) > 0)
        {
            if((last = malloc(sizeof(char) * (strlen(buf) +1))) == NULL)
            {
                fprintf(stderr, "ERROR: Can't allocate sufficient memory\n");
                free(mirror_last);
                return NULL;
            }

            chomp(buf);
            strcpy(last, buf);
            break;
        }    
    }

    if(fclose(fd) != 0)
    {
        fprintf(stderr, "ERROR: Can't close fd !\n");
    }

    free(mirror_last);

    return last;
}

mirrors* parse_mirrorcfg(struct optstruct *opt)
{
    mirrors *head = NULL, *curr = NULL, *prev = NULL;
    char *datadir = NULL, *mirrorcfg = NULL;
    FILE *fd = NULL;
    char buf[BUFSIZ];
    int hosts_found = 0;
       
    if(optl(opt, "datadir"))
    {
        datadir = getargl(opt, "datadir");
    }
    else
    {
        datadir = DATADIR;
    }

    if((mirrorcfg = malloc(sizeof(char) * (strlen(datadir) + strlen(MIRROR_CFG) + 1))) == NULL)
    {
        fprintf(stderr, "ERROR: Can't allocate sufficient memory\n");
        mexit(1);
    }

    strcpy(mirrorcfg, datadir);

    strcat(mirrorcfg, MIRROR_CFG);

    if((fd = fopen(mirrorcfg, "r")) == NULL)
    {
        fprintf(stderr, "ERROR: Can't open mirror configuration file %s !\n", mirrorcfg);
        free(mirrorcfg);    
        mexit(1);
    }

    while(fgets(buf, BUFSIZ, fd))
    {
        if(buf[0] == '#')
            continue;

        if(strlen(buf) > 1)
        {
            if((curr = malloc(sizeof(struct _mirrors))) == NULL)
            {
                fprintf(stderr, "ERROR: Can't allocate sufficient memory\n");
                free(mirrorcfg);    
                FREE_MIRROR(head);
                return NULL;
            }

            curr->mirror = NULL;            
            curr->next   = NULL;
            
            if(head == NULL)
                head = curr;
            
            if(prev != NULL)
                prev->next = curr;

            if((curr->mirror = malloc(sizeof(char) * (strlen(buf) +1))) == NULL)
            {
                fprintf(stderr, "ERROR: Can't allocate sufficient memory\n");
                free(mirrorcfg);    
                FREE_MIRROR(head);
                return NULL;
            }

            chomp(buf);
            strcpy(curr->mirror, buf);
            prev = curr;
            hosts_found++;
        }
    }
    
    if(fclose(fd) != 0)
    {
        fprintf(stderr, "ERROR: Can't close fd !\n");
    }
    
    if(hosts_found == 0)
    {
        fprintf(stderr, "ERROR: No hosts defined in %s !\n",  mirrorcfg);
        FREE_MIRROR(head);
        free(mirrorcfg);    
        mexit(1);
    }

    free(mirrorcfg);    
    return head;
}

void daemonize(void)
{
	int i;

    for(i = 0; i < 3; i++)
	close(i);

    umask(0);

    if(fork())
	exit(0);

    setsid();
    mprintf_disabled = 1;
}

void help(void)
{

    mprintf_stdout = 1;

    mprintf("\n");
    mprintf("		   Clam AntiVirus: FreshClam  "VERSION"\n");
    mprintf("		   (c) 2002 Tomasz Kojm <zolw@konarski.edu.pl>\n");
    mprintf("	  \n");
    mprintf("    --help		    -h		show help\n");
    mprintf("    --version		    -V		print version number and exit\n");
    mprintf("    --verbose		    -v		be verbose\n");
    mprintf("    --quiet				be quiet, output only error messages\n");
    mprintf("    --stdout				write to stdout instead of stderr\n");
    mprintf("					(this help is always written to stdout)\n");
    mprintf("\n");
    mprintf("    --user=USER		    -u USER	run as USER\n");
    mprintf("    --daemon		    -d		run in daemon mode\n");
    mprintf("    --checks=#n             -c #n       #n checks by day, 1 <= n <= 50\n");
    mprintf("    --datadir=DIRECTORY                 download new database in DIRECTORY\n");
    mprintf("    --log=FILE		    -l FILE	save download report in FILE\n");
    mprintf("    --log-verbose			save additional informations\n");
    mprintf("    --http-proxy=hostname[:port]	use proxy server hostname\n");
    mprintf("    --proxy-user=username:passwd	use username/password for proxy auth\n");
    mprintf("    --daemon-notify[=/path/clamav.conf] send RELOAD command to clamd\n");
    mprintf("    --on-update-execute=[COMMAND]	execute the COMMAND after successful update\n");
    mprintf("    --on-error-execute=[COMMAND]	execute the COMMAND if errors occured\n");
    mprintf("\n");
    exit(0);
}
