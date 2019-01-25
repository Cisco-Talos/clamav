/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2010-2013 Sourcefire, Inc.
 *
 *  Authors: aCaB <acab@clamav.net>
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
 */

#include "dirent.h"
#include "libgen.h"

#include <malloc.h>

/* 
    I GIVE UP! The CRT is b0rked and cannot be helped.

    The documentation suggests to handle globbing automagically via linking in
    the msvc-provided setargv.obj. Unfortunately that thing has got any sort of bugs
    and perverts filenames rather than expanding them.

    The other suggested approach is to override the crt-builtin "_setargv" with a
    custom routine to manually process the command line args before they are fed to main.
    Now this is even funnier: the hook is indeed called bedore main(), but then its work
    is discarded and replaced with that of the default parser... how useful!
    After some debugging the problem turned out to be in the design. The flow is like:
    pre_c_init -> _setargv
    then
    pre_cpp_init -> _setargv
    Looking at the code in there, it clearly shows that both _init functions are 99% the
    same. In case you are wondering... yes, everything is done twice! Including the
    command line parsing...
    There is however a small difference: while pre_c_init correctly calls the custom
    _setargv if present, pre_cpp_init always calls the crt-builtin!
    If you want to double check this link the msvc-provided noarg.obj in, then break in main
    and see how argv and argc are actually set... If you try with setargv.obj, instead, you
    will see that it apparently works, but that's just a hack for which pre_cpp_init ends
    up calling __setargv instead of _setargv based on the _dowildcard flag.

    So the way to FIX this mess involves a small trick: in the _setargv override I
    don't just parse the command line properly, but I also turn my arguments into a new
    command line, which I use to replace the existing one. The replaced line will then be
    processed by pre_cpp_init and everything is fine.
    To replace the original line with the fixed one it's sufficient to replace the pointer
    returned by the __p__acmdln() function. The proto it "extern char **__p__acmdln(void)".

    Of course the trick only works if the line is crafted in a way that can be understood
    and parsed by the _setargv builtin.
    Apparently, however, the authors of this pile of crap which goes under the name of CRT,
    are not even able to keep their bugs consistent. So, while in MSVC 2008 it was enough to
    put each arg in "'s, in MSVC 2008 SP 1 you additionally need to take care of "escaped"
    quotes. I.e.: \".

    Whatever...
    I've given up trying to fit globbing below main. It's now hooked into main via a
    #define wrapper.
*/

static int glob_add(char *path, int *argc, char ***argv) {
    char *tail = strchr(path, '*'), *tailqmark;
    char *dup1, *dup2, *dir, *base, *taildirsep, *tailwldsep;
    struct dirent *de;
    int baselen, taillen, dirlen, mergedir = 0, outlen = 0;
    int qmarklen = 0;
    DIR *d;
    void *p;

    if(strlen(path) > 4 && !memcmp(path, "\\\\?\\", 4))
	tailqmark = strchr(&path[4], '?');
    else
	tailqmark = strchr(path, '?');

    if(tailqmark && (!tail || tailqmark < tail))
	tail = tailqmark;

    if(!tail) {
        p = realloc(*argv, sizeof(**argv) * (*argc + 1));
        if (p == NULL) {
            /* realloc() failed, print warning */
           fprintf(stderr, "warning: realloc() for '*argv' failed\n");
           return -1;
        }
        *argv = (char **)p;
        (*argv)[*argc] = path;
        (*argc)++;
        return strlen(path);
    }

    if(tail!=path && tail[-1] == '\\') {
	tail[-1] = '\0';
	mergedir = 1;
    }
    while(*tail) {
	if(*tail == '?') {
	    if(tail == tailqmark || qmarklen) 
		qmarklen++;
	    *tail = 0;
	} else if(*tail == '*') {
	    *tail = '\0';
	    qmarklen = 0;
	} else 
	    break;
	tail++;
    }
    taillen = strlen(tail);
    taildirsep = strchr(tail, '\\');
    if(taildirsep && taildirsep - tail == taillen - 1) {
	*taildirsep = '\0';
	taildirsep = NULL;
	taillen--;
    }
    if(!taildirsep)
	taildirsep = tail + taillen;

    tailwldsep = strchr(tail, '*');
    tailqmark = strchr(tail, '?');
    if(tailqmark && (!tailwldsep || tailqmark < tailwldsep))
	tailwldsep = tailqmark;
    if(!tailwldsep)
	tailwldsep = tail + taillen;

    baselen = strlen(path) + 1;
    dup1 = (char *)_alloca(baselen * 2);
    memcpy(dup1, path, baselen);
    dup2 = dup1 + baselen;
    memcpy(dup2, path, baselen);

    if(!mergedir) {
	dir = dirname(dup1);
	base = basename(dup2);
    } else {
	dir = dup1;
	base = dup2;
	*dup2 = '\0';
    }

    dirlen = strlen(dir);
    baselen = strlen(base);

    d = opendir(dir);
    while(d && (de = readdir(d))) {
	int namelen = strlen(de->d_name);
	char *newpath;

	if(!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
	if(namelen < baselen) continue;
	if(strncasecmp(base, de->d_name, baselen)) continue;
	if(de->d_type == DT_DIR && taildirsep < tailwldsep) {
	    int d_taillen = taildirsep - tail;
	    if(namelen < baselen + d_taillen) continue;
	    if(strncasecmp(tail, &de->d_name[namelen - d_taillen], d_taillen)) continue;
	    newpath = (char *)malloc(dirlen + namelen + taillen - d_taillen + 3);
	    if (newpath == NULL) { /* oops, malloc() has failed */
		fprintf(stderr, "warning: malloc() failed in function 'globadd'...\n");
		return -1;
	    }
	    sprintf(newpath, "%s\\%s\\%s", dir, de->d_name, &tail[d_taillen+1]);
	    outlen += glob_add(newpath, argc, argv);
	} else {
	    int d_taillen = tailwldsep - tail;
	    char *start;
	    if(namelen < baselen + d_taillen) continue;
	    if(qmarklen && baselen + qmarklen + d_taillen != namelen)	continue;
	    if(d_taillen == taillen) {
		start = &de->d_name[namelen - d_taillen];
		namelen = d_taillen;
	    } else {
		start = &de->d_name[baselen];
		namelen -= baselen;
	    }

	    for(; namelen >= d_taillen; start++, namelen--) {
		if(strncasecmp(start, tail, d_taillen)) continue;
		newpath = (char *)malloc(dirlen + (start - de->d_name) +  taillen + 2);
		if (newpath == NULL) { /* oops, malloc() has failed */
			fprintf(stderr, "warning: malloc() failed in function 'globadd'...\n");
			return -1;
		}
		sprintf(newpath, "%s\\", dir);
		memcpy(&newpath[dirlen + 1], de->d_name, start - de->d_name);
		strcpy(&newpath[dirlen + 1 + start - de->d_name], tail);
		outlen += glob_add(newpath, argc, argv);
	    }
	}
    }
    if(d) closedir(d);
    _freea(dup1);
    free(path);
    return outlen;
}

void w32_glob(int *argc_ptr, char ***argv_ptr) {
    wchar_t *wtmp = GetCommandLineW();
    char *cur, *begparm = NULL, *endparm = NULL;
    char **argv = NULL, c;
    int argc = 0, in_sq = 0, in_dq = 0, need_glob = 0, allarglen = 0, linelen;
    void *p;

    linelen = wcslen(wtmp);
    cur = (char *)_alloca(linelen * 6 + 1);
    if(!WideCharToMultiByte(CP_UTF8, 0, wtmp, -1, cur, linelen * 6 + 1, NULL, NULL))
	cur = GetCommandLineA();

    do {
	c = *cur;
	switch(c) {
	    case '\0':
		endparm = cur;
		break;
	    case ' ':
		if(begparm && !(in_sq | in_dq))
		    endparm = cur;
		break;
	    case '\'':
		if(!in_dq) {
		    in_sq = !in_sq;
		    if(!in_sq)
			endparm = cur;
		}
		break;
	    case '"':
		if(!in_sq) {
		    in_dq = !in_dq;
		    if(!in_dq)
			endparm = cur;
		}
		break;
	    case '*':
	    case '?':
		if(!in_sq)
		    need_glob = 1;
	    default:
		if(!begparm) {
		    begparm = cur;
		    endparm = NULL;
		}
	}
	if (begparm && endparm) {
	    if(begparm < endparm) {
			int arglen = 0;
		char *path = (char *)malloc(endparm - begparm + 1), *quotes;
		if (path == NULL) { /* oops, malloc() failed */
			fprintf(stderr, "warning: malloc() failed for '*path'...\n");
			return;
		}

		memcpy(path, begparm, endparm - begparm);
		path[endparm - begparm] = '\0';
		quotes = path;
		while((quotes = strchr(quotes, '"')))
		    memmove(quotes, quotes + 1, (endparm - begparm) - (quotes - path));
		if(argc && need_glob) {
		    arglen = glob_add(path, &argc, &argv);
		    if(!arglen) {
			path = (char *)malloc(endparm - begparm + 1);
			if (path == NULL) { /* oops, malloc() failed */
			    fprintf(stderr, "warning: malloc failed for 'path'...\n");
			    return;
			}
			memcpy(path, begparm, endparm - begparm);
			path[endparm - begparm] = '\0';
		    }
		}
		if(!arglen) {
		    p = realloc(argv, sizeof(*argv) * (argc + 1));
		    if (p == NULL) { /* realloc() failed */
    			fprintf(stderr, "warning: realloc() for 'argv' failed, original value unchanged...\n");
                return;
            }
            argv = (char **)p;
		    argv[argc] = path;
		    argc++;
		    arglen = endparm - begparm;
		}
		allarglen += arglen;
	    }
	    need_glob = 0;
	    in_sq = 0;
	    in_dq = 0;
	    begparm = NULL;
	    endparm = NULL;
	}
	cur++;
    } while (c);
    if(argc) {
	int i, argvlen = sizeof(*argv) * (argc + 1), argclen = 0;
	p = realloc(argv, argvlen + allarglen + argc);
	if (p == NULL) { /* oops, realloc() failed */
	    fprintf(stderr, "warning: realloc() for 'argv' failed, original value unchanged...\n");
		return;
	}
	argv = (char **)p;
	argv[argc] = NULL;
	for(i=0; i<argc; i++) {
	    int curlen = strlen(argv[i]) + 1;
	    char *curarg = (char *)argv + argvlen + argclen;
	    memcpy(curarg, argv[i], curlen);
	    argclen += curlen;
	    free(argv[i]);
	    argv[i] = curarg;
	}
    }
    *argc_ptr = argc;
    *argv_ptr = argv;
}
