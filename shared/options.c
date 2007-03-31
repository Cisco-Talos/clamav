/*
 *  Copyright (C) 2001 - 2007 Tomasz Kojm <tkojm@clamav.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
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
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define _GNU_SOURCE
#include "getopt.h"

#include "options.h"
#include "output.h"


static int register_option(struct optstruct *opt, const char *optlong, char optshort, const struct option *options_long, const char * const *accepted_long)
{
	struct optnode *newnode;
	int i, found = 0;
	const char *longname = NULL;


    if(optshort) {
	for(i = 0; options_long[i].name; i++) {
	    if(options_long[i].val == optshort) {
		longname = options_long[i].name;
		break;
	    }
	}
    } else
	longname = optlong;

    if(!longname) {
	mprintf("!register_option: No long option for -%c\n", optshort);
	return -1;
    }

    if(accepted_long) {
	for(i = 0; accepted_long[i]; i++)
	    if(!strcmp(accepted_long[i], longname))
		found = 1;

	if(!found) {
	    if(optshort)
		mprintf("WARNING: Ignoring option --%s (-%c)\n", longname, optshort);
	    else
		mprintf("WARNING: Ignoring option --%s\n", longname);

	    return 0;
	}
    }

    newnode = (struct optnode *) malloc(sizeof(struct optnode));
    if(!newnode) {
	mprintf("!register_long_option: malloc failed\n");
	return -1;
    }

    newnode->optshort = optshort;

    if(optarg) {
	newnode->optarg = (char *) malloc(strlen(optarg) + 1);
	if(!newnode->optarg) {
	    mprintf("!register_long_option: malloc failed\n");
	    free(newnode);
	    return -1;
	}
	strcpy(newnode->optarg, optarg);
    } else
	newnode->optarg = NULL;

    newnode->optlong = (char *) malloc(strlen(longname) + 1);
    if(!newnode->optlong) {
	mprintf("ERROR: register_long_option: malloc failed\n");
	free(newnode->optarg);
	free(newnode);
	return -1;
    }
    strcpy(newnode->optlong, longname);

    newnode->next = opt->optlist;
    opt->optlist = newnode;
    return 0;
}

void opt_free(struct optstruct *opt)
{
	struct optnode *handler, *prev;

    if(!opt)
	return;

    handler = opt->optlist;
    while(handler) {
	if(handler->optarg)
	    free(handler->optarg);
	if(handler->optlong)
	    free(handler->optlong);
	prev = handler;
	handler = handler->next;
	free(prev);
    }

    if(opt->filename)
    	free(opt->filename);

    free(opt);
}

struct optstruct *opt_parse(int argc, char * const *argv, const char *getopt_short, const struct option *options_long, const char * const *accepted_long)
{
	int ret, opt_index, i, len;
	struct optstruct *opt;
	const char *longname;


    opt = (struct optstruct *) calloc(1, sizeof(struct optstruct));
    if(!opt) {
	mprintf("!opt_parse: calloc failed\n");
	return NULL;
    }

    while(1) {
	opt_index = 0;
	ret = getopt_long(argc, argv, getopt_short, options_long, &opt_index);

	if(ret == -1)
	    break;

	switch(ret) {
	    case 0:
		if(register_option(opt, options_long[opt_index].name, 0, options_long, accepted_long) == -1) {
		    opt_free(opt);
		    return NULL;
		}
		break;

    	    default:
		if(strchr(getopt_short, ret)) {
		    if(opt_index)
			longname = options_long[opt_index].name;
		    else
			longname = NULL;

		    if(register_option(opt, longname, ret, options_long, accepted_long) == -1) {
			opt_free(opt);
			return NULL;
		    }

		} else {
		    mprintf("!Unknown option passed.\n");
		    opt_free(opt);
		    return NULL;
		}
	}
    }

    if(optind < argc) {
        len = 0;

	/* count length of non-option arguments */
	for(i = optind; i < argc; i++)
	    len += strlen(argv[i]);

	len += argc - optind - 1;
	opt->filename = (char *) calloc(len + 64, sizeof(char));
	if(!opt->filename) {
	    mprintf("!opt_parse: calloc failed\n");
	    opt_free(opt);
	    return NULL;
	}

        for(i = optind; i < argc; i++) {
	    strncat(opt->filename, argv[i], strlen(argv[i]));
	    if(i != argc - 1)
		strncat(opt->filename, "\t", 1);
	}
    }

    return opt;
}

int opt_check(const struct optstruct *opt, const char *optlong)
{
	struct optnode *handler;

    if(!opt) {
	mprintf("!opt_check: opt == NULL\n");
	return 0;
    }

    handler = opt->optlist;

    while(handler) {
	if(handler->optlong && !strcmp(handler->optlong, optlong))
	    return 1;

	handler = handler->next;
    }

    return 0;
}

char *opt_arg(const struct optstruct *opt, const char *optlong)
{
	struct optnode *handler;

    if(!opt) {
	mprintf("!opt_arg: opt == NULL\n");
	return 0;
    }

    handler = opt->optlist;

    while(handler) {
	if(handler->optlong && !strcmp(handler->optlong, optlong))
	    return handler->optarg;

	handler = handler->next;
    }

    return NULL;
}

char *opt_firstarg(const struct optstruct *opt, const char *optlong, const struct optnode **optnode)
{
	const struct optnode *handler;

    if(!opt) {
	mprintf("!opt_firstarg: opt == NULL\n");
	return 0;
    }

    handler = opt->optlist;

    while(handler) {
	if(handler->optlong && !strcmp(handler->optlong, optlong)) {
	    *optnode = handler;
	    return handler->optarg;
	}
	handler = handler->next;
    }

    *optnode = NULL;
    return NULL;
}

char *opt_nextarg(const struct optnode **optnode, const char *optlong)
{
	struct optnode *handler;

    if(!optnode || !*optnode) {
	mprintf("!opt_nextarg: *optnode == NULL\n");
	return 0;
    }

    handler = (*optnode)->next;

    while(handler) {
	if(handler->optlong && !strcmp(handler->optlong, optlong)) {
	    *optnode = handler;
	    return handler->optarg;
	}
	handler = handler->next;
    }

    *optnode = NULL;
    return NULL;
}
