/*
 *  Copyright (C) 2001-2002 Tomasz Kojm <zolw@konarski.edu.pl>
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
 * Sat Sep 14 22:18:20 CEST 2002: included getfirst*(), getnext*() functions
 *			from Alejandro Dubrovsky <s328940@student.uq.edu.au>
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define _GNU_SOURCE
#include "getopt.h"

#if defined(C_LINUX) && defined(CL_DEBUG)
#include <sys/resource.h>
#endif

#include "options.h"
#include "others.h"
#include "../libclamav/others.h"
#include "memory.h"

void clamd(struct optstruct *opt);

int main(int argc, char **argv)
{
	int ret, opt_index, i, len;
	struct optstruct *opt;

	const char *getopt_parameters = "hc:V";

	static struct option long_options[] = {
	    {"help", 0, 0, 'h'},
	    {"config-file", 1, 0, 'c'},
	    {"version", 0, 0, 'V'},
	    {"debug", 0, 0, 0},
	    {0, 0, 0, 0}
    	};

#if defined(C_LINUX) && defined(CL_DEBUG)
	/* njh@bandsman.co.uk: create a dump if needed */
	struct rlimit rlim;

    rlim.rlim_cur = rlim.rlim_max = RLIM_INFINITY;
    if(setrlimit(RLIMIT_CORE, &rlim) < 0)
	perror("setrlimit");
#endif
    opt=(struct optstruct*)mcalloc(1, sizeof(struct optstruct));
    opt->optlist = NULL;
    opt->filename = NULL;

    while(1) {

	opt_index=0;
	ret=getopt_long(argc, argv, getopt_parameters, long_options, &opt_index);

	if (ret == -1)
	    break;

	switch (ret) {
	    case 0:
		register_long_option(opt, long_options[opt_index].name);
		break;

    	    default:
		if(strchr(getopt_parameters, ret))
		    register_char_option(opt, ret);
		else {
		    fprintf(stderr, "ERROR: Unknown option passed.\n");
		    free_opt(opt);
		    exit(40);
		}
        }
    }

    if (optind < argc) {

        len=0;

	/* count length of non-option arguments */

	for(i=optind; i<argc; i++)
	    len+=strlen(argv[i]);

	len=len+argc-optind-1; /* add spaces between arguments */
	opt->filename=(char*)mcalloc(len + 256, sizeof(char));

        for(i=optind; i<argc; i++) {
	    strncat(opt->filename, argv[i], strlen(argv[i]));
	    if(i != argc-1)
		strncat(opt->filename, " ", 1);
	}

    }

    clamd(opt);

    free_opt(opt);

    cli_dbgmsg("exit main()");
    return(0);
}

void register_char_option(struct optstruct *opt, char ch)
{
	struct optnode *newnode;

    newnode = (struct optnode *) mmalloc(sizeof(struct optnode));
    newnode->optchar = ch;
    if(optarg != NULL) {
	newnode->optarg = (char *) mcalloc(strlen(optarg) + 1, sizeof(char));
	strcpy(newnode->optarg, optarg);
    } else newnode->optarg = NULL;

    newnode->optname = NULL;
    newnode->next = opt->optlist;
    opt->optlist = newnode;
}

void register_long_option(struct optstruct *opt, const char *optname)
{
	struct optnode *newnode;

    newnode = (struct optnode *) mmalloc(sizeof(struct optnode));
    newnode->optchar = 0;
    if(optarg != NULL) {
	newnode->optarg = (char *) mcalloc(strlen(optarg) + 1, sizeof(char));
	strcpy(newnode->optarg, optarg);
    } else newnode->optarg = NULL;

    newnode->optname = (char *) mcalloc(strlen(optname) + 1, sizeof(char));
    strcpy(newnode->optname, optname);
    newnode->next = opt->optlist;
    opt->optlist = newnode;
}

int optc(const struct optstruct *opt, char ch)
{
	struct optnode *handler;

    handler = opt->optlist;

    while(1) {
	if(handler) {
	    if(handler->optchar == ch) return 1;
	} else break;
	handler = handler->next;
    }

    return(0);
}

int optl(const struct optstruct *opt, const char *optname)
{
	struct optnode *handler;

    handler = opt->optlist;

    while(1) {
	if(handler) {
	    if(handler->optname)
		if(!strcmp(handler->optname, optname)) return 1;
	} else break;
	handler = handler->next;
    }

    return(0);
}

char *getargc(const struct optstruct *opt, char ch)
{
	struct optnode *handler;

    handler = opt->optlist;

    while(1) {
	if(handler) {
	    if(handler->optchar == ch) return handler->optarg;
	} else break;
	handler = handler->next;
    }

    return(NULL);
}

char *getfirstargc(const struct optstruct *opt, char ch, struct optnode **optnode)
{
	struct optnode *handler;

    handler = opt->optlist;

    while(1) {
	if(handler) {
	    if(handler->optchar == ch) {
	    	*optnode = handler;
	    	return handler->optarg;
	    }
	} else break;
	handler = handler->next;
    }
    *optnode = NULL;
    return(NULL);
}

char *getnextargc(struct optnode **optnode, char ch)
{
	struct optnode *handler;

    handler = (*optnode)->next;

    while(1) {
	if(handler) {
	    if(handler->optchar == ch) {
	    	*optnode = handler;
	    	return handler->optarg;
	    }
	} else break;
	handler = handler->next;
    }
    *optnode = NULL;
    return(NULL);
}


char *getargl(const struct optstruct *opt, const char *optname)
{
	struct optnode *handler;

    handler = opt->optlist;

    while(1) {
	if(handler) {
	    if(handler->optname)
		if(!strcmp(handler->optname, optname)) return handler->optarg;
	} else break;
	handler = handler->next;
    }

    return(NULL);
}

char *getfirstargl(const struct optstruct *opt, const char *optname, struct optnode **optnode)
{
	struct optnode *handler;

    handler = opt->optlist;

    while(1) {
	if(handler) {
	    if(handler->optname)
		if(!strcmp(handler->optname, optname)) {
			*optnode = handler;
			return handler->optarg;
		}
	} else break;
	handler = handler->next;
    }
    
    *optnode = NULL;
    return(NULL);
}

char *getnextargl(struct optnode **optnode, const char *optname)
{
	struct optnode *handler;

    handler = (*optnode)->next;

    while(1) {
	if(handler) {
	    if(handler->optname)
		if(!strcmp(handler->optname, optname)) {
			*optnode = handler;
			return handler->optarg;
		}
	} else break;
	handler = handler->next;
    }
    
    *optnode = NULL;
    return(NULL);
}



void free_opt(struct optstruct *opt)
{
	struct optnode *handler, *prev;

    if(!opt)
	return;

    handler = opt->optlist;

    while(handler != NULL) {
	handler->optchar = 0;
	if(handler->optarg) free(handler->optarg);
	if(handler->optname) free(handler->optname);
	prev = handler;
	handler = handler->next;
	free(prev);
    }

    if(opt->filename)
	free(opt->filename);
    free(opt);
}
