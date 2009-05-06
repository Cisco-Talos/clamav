/*
 *  getopt.h - interface to my re-implementation of getopt.
 *  Copyright 1997, 2000, 2001, 2002, 2006, Benjamin Sittler
 *
 *  Permission is hereby granted, free of charge, to any person
 *  obtaining a copy of this software and associated documentation
 *  files (the "Software"), to deal in the Software without
 *  restriction, including without limitation the rights to use, copy,
 *  modify, merge, publish, distribute, sublicense, and/or sell copies
 *  of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *  
 *  The above copyright notice and this permission notice shall be
 *  included in all copies or substantial portions of the Software.
 *  
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 *  HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 *  WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 *  DEALINGS IN THE SOFTWARE.
 */

#ifndef _GETOPT_H_INCLUDED
#define _GETOPT_H_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif

/* UNIX-style short-argument parser */
extern int my_getopt(int argc, char *argv[], const char *opts);

extern int optind, opterr, optopt;
extern char *optarg;

struct option {
  const char *name;
  int has_arg;
  int *flag;
  int val;
};

/* human-readable values for has_arg */
#undef no_argument
#define no_argument 0
#undef required_argument
#define required_argument 1
#undef optional_argument
#define optional_argument 2

/* GNU-style long-argument parsers */
extern int my_getopt_long(int argc, char * argv[], const char *shortopts,
                       const struct option *longopts, int *longind);

extern int my_getopt_long_only(int argc, char * argv[], const char *shortopts,
                            const struct option *longopts, int *longind);

#ifdef __cplusplus
}
#endif

#endif /* _GETOPT_H_INCLUDED */
