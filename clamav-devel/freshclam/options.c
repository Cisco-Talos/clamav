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
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <clamav.h>
#define _GNU_SOURCE
#include "getopt.h"

#include "options.h"
#include "output.h"

int freshclam(struct optstruct *opt);

static void register_char_opt(struct optstruct *opt, char ch, struct option* longopts);
static void register_long_opt(struct optstruct *opt, const char *optname, struct option* longopts);


int main(int argc, char **argv)
{
	int ret, opt_index, i, len;
	struct optstruct *opt;

	const char *getopt_parameters = "hvdp:Vl:c:u:";

	static struct option long_options[] = {
	    /* 
	     * WARNING: For compatibility reasons options marked as "not used"
	     *		must still be accepted !
	     */
	    {"help", 0, 0, 'h'},
	    {"quiet", 0, 0, 0},
	    {"verbose", 0, 0, 'v'},
	    {"debug", 0, 0, 0},
	    {"version", 0, 0, 'V'},
	    {"datadir", 1, 0, 0},
	    {"log", 1, 0, 'l'},
	    {"log-verbose", 0, 0, 0}, /* not used */
	    {"stdout", 0, 0, 0},
	    {"daemon", 0, 0, 'd'},
	    {"pid", 1, 0, 'p'},
	    {"user", 1, 0, 'u'}, /* not used */
	    {"config-file", 1, 0, 0},
	    {"checks", 1, 0, 'c'},
	    {"http-proxy", 1, 0, 0},
	    {"proxy-user", 1, 0, 0},
	    {"daemon-notify", 2, 0, 0},
	    {"on-update-execute", 1, 0, 0},
	    {"on-error-execute", 1, 0, 0},
	    {0, 0, 0, 0}
    	};


    opt=(struct optstruct*)mcalloc(1, sizeof(struct optstruct));
    opt->optlist = NULL;

    while(1) {

	opt_index=0;
	ret=getopt_long(argc, argv, getopt_parameters, long_options, &opt_index);

	if (ret == -1)
	    break;

	switch (ret) {
	    case 0:
		register_long_opt(opt, long_options[opt_index].name, long_options);
		break;

    	    default:
		if(strchr(getopt_parameters, ret))
		    register_char_opt(opt, ret, long_options);
		else {
		    mprintf("!Unknown option passed.\n");
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

    ret = freshclam(opt);

    free_opt(opt);

    return ret;
}

static struct option* find_char_opt(char optchar, struct option* longopts)
{
	int i;

    for (i=0; longopts[i].name; i++) {
	if ((char) longopts[i].val == optchar) {
	    return (&longopts[i]);
	}
    }
    return NULL;
}

static void register_char_opt(struct optstruct *opt, char ch, struct option* longopts)
{
	struct optnode *newnode;
	struct option  *longopt = find_char_opt(ch, longopts);

    newnode = (struct optnode *) mmalloc(sizeof(struct optnode));
    
    newnode->optchar = ch;
    if(optarg != NULL) {
	newnode->optarg = (char *) mcalloc(strlen(optarg) + 1, sizeof(char));
	strcpy(newnode->optarg, optarg);
    } else newnode->optarg = NULL;

    if (longopt) {
	newnode->optname = strdup(longopt->name);
    } else {
	newnode->optname = NULL;
    }
    newnode->next = opt->optlist;
    opt->optlist = newnode;
}

static struct option* find_long_opt(const char *optname, struct option* longopts)
{
	int i;

    for (i=0; longopts[i].name; i++) {
	if (strcmp(longopts[i].name, optname) == 0) {
	    return (&longopts[i]);
	}
    }
    return NULL;
}

static void register_long_opt(struct optstruct *opt, const char *optname, struct option* longopts)
{
	struct optnode *newnode;
	struct option  *longopt = find_long_opt(optname, longopts);

    newnode = (struct optnode *) mmalloc(sizeof(struct optnode));
    if (longopt) {
	newnode->optchar = longopt->val;
    } else {
	newnode->optchar = 0;
    }
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

void free_opt(struct optstruct *opt)
{
	struct optnode *handler, *prev;

    if(!opt)
	return;

    mprintf("*Freeing option list...");
    handler = opt->optlist;

    while(handler != NULL) {
	handler->optchar = 0;
	if(handler->optarg) free(handler->optarg);
	if(handler->optname) free(handler->optname);
	prev = handler;
	handler = handler->next;
	free(prev);
    }

    if (opt->filename)
	free(opt->filename);
    free(opt);
    mprintf("*done\n");
}
