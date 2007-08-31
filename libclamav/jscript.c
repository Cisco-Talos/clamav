/*
 *  Copyright (C) 2006 Nigel Horne <njh@clamav.net>
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
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 *
 * Save the JavaScript embedded in an HTML file, then run the script, saving
 * the output in a file that is to be scanned, then remove the script file
 *
 * FIXME:	Includes .c files here, which need to be separated out
 * FIXME:	The js code probably only compiles on GCC.
 * FIXME:	The js code needs re_compile_pattern, re_compile_fastmap,
 *			re_search, which NetBSD, and probably other platforms
 *			don't have
 * TODO:	Test with real malware
 * TODO:	Add mailfollowurls type feature
 * TODO:	Check the NGS code for vulnerabilities, leaks etc.
 * TODO:	Check the NGS code is thread safe
 * TODO:	Test code such as
 *	<script>
 *		document.writeln("<script> function f() { ..the real worm code..
 *			</script>"); f();
 *	</script>
 */
static	char	const	rcsid[] = "$Id: jscript.c,v 1.11 2006/12/13 15:25:34 njh Exp $";

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include "clamav.h"
#include "others.h"

#ifdef	CL_EXPERIMENTAL

#if	HAVE_MMAP

#include <memory.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <ctype.h>

#ifdef	HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "jscript.h"

#if HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif

/* Maximum filenames under various systems - njh */
#ifndef	NAME_MAX	/* e.g. Linux */
# ifdef	MAXNAMELEN	/* e.g. Solaris */
#   define	NAME_MAX	MAXNAMELEN
# else
#   ifdef	FILENAME_MAX	/* e.g. SCO */
#     define	NAME_MAX	FILENAME_MAX
#   else
#     define	NAME_MAX	256
#   endif
# endif
#endif

#ifdef	CL_THREAD_SAFE
#define	VM_TIMEOUT	5	/* In seconds: FIXME should be configurable */
#endif

#if	defined(VM_TIMEOUT) && (VM_TIMEOUT > 0)
#include <pthread.h>
#include <sys/time.h>
#include <signal.h>
#endif

static	int	run_js(const char *filename, const char *dir);
static	const	char	*cli_pmemstr(const char *haystack, size_t hs, const char *needle, size_t ns);

int
cli_scanjs(const char *dir, int desc)
{
	struct stat statb;
	off_t size;	/* total number of bytes in the file */
	char *buf;	/* start of memory mapped area */
	const char *p;
	long bytesleft;
	int created_output, done_header, rc;
	FILE *fout;
	char script_filename[NAME_MAX + 1];

	cli_dbgmsg("in cli_scanjs(%s)\n", dir);

	if(fstat(desc, &statb) < 0)
		return CL_EOPEN;

	size = (size_t)statb.st_size;

	if(size == 0)
		return CL_CLEAN;

	if(size <= 17)	/* doesn't even include <script></script> */
		return CL_EFORMAT;

	p = buf = mmap(NULL, size, PROT_READ, MAP_PRIVATE, desc, 0);
	if(buf == MAP_FAILED)
		return CL_EMEM;

	cli_dbgmsg("cli_scanjs: scanning %lu bytes\n", size);

	p = buf;
	bytesleft = size;
	created_output = done_header = 0;
	fout = NULL;

	while(p < &buf[size]) {
		const char *q = cli_pmemstr(p, bytesleft, "<script", 7);

		if(q == NULL)
			/* TODO: full case independant search */
			q = cli_pmemstr(p, bytesleft, "<SCRIPT", 7);

		if(q == NULL)
			break;

		/*
		 * TODO: check language is javascript
		 * TODO: follow src if mail-follow-urls is set
		 */

		bytesleft -= (q - p);
		p = q;

		q = cli_pmemstr(p, bytesleft, ">", 1);
		if(q == NULL)
			break;

		bytesleft -= (q - p);
		p = q;

		p++;
		bytesleft--;

		while(bytesleft) {
			char c;

			if(*p == '<') {
				p++;
				if(--bytesleft == 0)
					break;
				if((*p == '!') && !done_header) {
					while(bytesleft && (*p != '\n')) {
						p++;
						bytesleft--;
					}
					continue;
				}
				if((bytesleft >= 7) && (strncasecmp(p, "/script", 7) == 0)) {
					bytesleft -= 7;
					p = &p[7];
					while(bytesleft && (*p != '>')) {
						p++;
						bytesleft--;
					}
					if(fout) {
						fclose(fout);
						fout = NULL;
						(void)run_js(script_filename, dir);

						if(!cli_leavetemps_flag)
							unlink(script_filename);
					}
					done_header = 0;
					break;
				}
				c = '<';
			} else {
				/*c = tolower(*p);*/
				c = *p;
				p++;
				bytesleft--;
			}

			if(!done_header) {
				int fd;

				snprintf(script_filename, sizeof(script_filename), "%s/jsXXXXXX", dir);
#if	defined(C_LINUX) || defined(C_BSD) || defined(HAVE_MKSTEMP) || defined(C_SOLARIS) || defined(C_CYGWIN)
				fd = mkstemp(script_filename);
				fout = fdopen(fd, "wb");
				if(fout == NULL)
					close(fd);
#elif	defined(C_WINDOWS)
				if(_mktemp(script_filename) == NULL) {
					/* mktemp only allows 26 files */
					char *name = cli_gentemp(dir);
					if(name == NULL)
						fout = NULL;
					else {
						strcpy(script_filename, name);
						free(name);
						fout = fopen(script_filename, "wb");
					}
				} else
					fout = fopen(script_filename, "wb");
#else
				mktemp(script_filename);
				fout = fopen(script_filename, "wb");
#endif

				if(fout == NULL) {
					cli_errmsg("cli_scanjs: can't create temporary file %s: %s\n", script_filename, strerror(errno));
					munmap(buf, size);
					return CL_ETMPFILE;
				}
				cli_dbgmsg("Saving javascript to %s\n",
					script_filename);

				/*
				 * Create a document object, on web pages it's
				 *	used to send output to the browser
				 * FIXME: will create a file even if the script
				 *	is empty, e.g. src is somewhere else
				 */
				fputs("function createDoc() {\n", fout);
				fputs("\tfunction write(text) {\n", fout);
				/*
				 * Use System.print rather than print so that
				 *	a new line is not appended
				 */
				fputs("\t\tSystem.print(text);\n", fout);
				fputs("\t}\n", fout);
				fputs("}\n", fout);
				fputs("document = new createDoc();\n", fout);

				done_header = 1;
				created_output = 1;
			}
			putc(c, fout);
		}
	}

	munmap(buf, size);

	rc = CL_SUCCESS;

	if(!created_output)
		cli_dbgmsg("No javascript was detected\n");
	else if(fout) {
		fclose(fout);
		rc = run_js(script_filename, dir);

		if(!cli_leavetemps_flag)
			unlink(script_filename);
	}
	return rc;
}

#include "js/compiler.c"
#include "js/iostream.c"
#include "js/js.c"
#include "js/main.c"
#include "js/debug.c"
#include "js/crc32.c"

static	FILE *fout;

static	int
write_to_fout(void *context, unsigned char *buf, unsigned int len)
{
	return (int)fwrite(buf, (size_t)len, 1, fout);
}

#if	defined(VM_TIMEOUT) && (VM_TIMEOUT > 0)

struct args {
	const char *filename;
	const char *dir;
	pthread_cond_t	*cond;
	int	result;
};

static void *
js_thread(void *a)
{
	JSInterpPtr interp;
	char *outputfilename;
	struct args *args = (struct args *)a;
	const char *dir = args->dir;
	const char *filename = args->filename;
	int otype;

	cli_dbgmsg("run_js(%s)\n", filename);

	outputfilename = cli_gentemp(dir);
	if(outputfilename == NULL) {
		pthread_cond_broadcast(args->cond);
		args->result = CL_ETMPFILE;
		return NULL;
	}

	fout = fopen(outputfilename, "wb");
	if(fout == NULL) {
		pthread_cond_broadcast(args->cond);
		cli_warnmsg("Can't create %s\n", outputfilename);
		free(outputfilename);
		args->result = CL_ETMPFILE;
		return NULL;
	}

	cli_dbgmsg("Redirecting JS VM stdout to %s\n", outputfilename);
	free(outputfilename);

	/*
	 * Run NGS on the file
	 */
	interp = create_interp(write_to_fout);

	args->result = CL_EIO;	/* TODO: CL_TIMEOUT */

	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &otype);

	if(!js_eval_file(interp, filename)) {
		cli_warnmsg("JS failed: %s\n", js_error_message(interp));
		/*rc = CL_EIO;*/
	}

	/*
	 * If a pthread_cancel() is issued exactly here, js_destroy_interp()
	 * wouldn't be called, leading to a memory leak
	 */
	if(pthread_cond_broadcast(args->cond) < 0)
		perror("pthread_cond_broadcast");

	js_destroy_interp(interp);

	fclose(fout);

	args->result = CL_SUCCESS;
	return NULL;
}

static int
run_js(const char *filename, const char *dir)
{
	struct args args;
	pthread_t tid;
	struct timespec ts;
	struct timeval tp;
	pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
	pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

	args.filename = filename;
	args.dir = dir;
	args.cond = &cond;

	pthread_create(&tid, NULL, js_thread, &args);

	gettimeofday(&tp, NULL);

	ts.tv_sec = tp.tv_sec + VM_TIMEOUT;
	ts.tv_nsec = tp.tv_usec * 1000;

	pthread_mutex_lock(&mutex);
	if(pthread_cond_timedwait(&cond, &mutex, &ts) == ETIMEDOUT) {
		cli_warnmsg("Runaway javascript stopped after %d seconds\n",
			VM_TIMEOUT);
		/*pthread_kill(tid, SIGUSR1);*/
		if(pthread_cancel(tid) < 0)
			perror("pthread_cancel");
	}
	pthread_mutex_unlock(&mutex);
	pthread_join(tid, NULL);

	return args.result;
}
#else
static int
run_js(const char *filename, const char *dir)
{
	JSInterpPtr interp;
	char *outputfilename;

	cli_dbgmsg("run_js(%s)\n", filename);

	outputfilename = cli_gentemp(dir);
	if(outputfilename == NULL)
		return CL_ETMPFILE;

	fout = fopen(outputfilename, "wb");
	if(fout == NULL) {
		cli_warnmsg("Can't create %s\n", outputfilename);
		free(outputfilename);
		return CL_ETMPFILE;
	}

	cli_dbgmsg("Redirecting JS VM stdout to %s\n", outputfilename);
	free(outputfilename);

	/*
	 * Run NGS on the file
	 */
	interp = create_interp(write_to_fout);

	if(!js_eval_file(interp, filename)) {
		cli_warnmsg("JS failed: %s\n", js_error_message(interp));
		/*rc = CL_EIO;*/
	}

	js_destroy_interp(interp);

	fclose(fout);

	return CL_SUCCESS;
}
#endif

/* Copied from pdf.c :-( */
/*
 * like cli_memstr - but returns the location of the match
 * FIXME: need a case insensitive version`
 */
static const char *
cli_pmemstr(const char *haystack, size_t hs, const char *needle, size_t ns)
{
	const char *pt, *hay;
	size_t n;

	if(haystack == needle)
		return haystack;

	if(hs < ns)
		return NULL;

	if(memcmp(haystack, needle, ns) == 0)
		return haystack;

	pt = hay = haystack;
	n = hs;

	while((pt = memchr(hay, needle[0], n)) != NULL) {
		n -= (int) pt - (int) hay;
		if(n < ns)
			break;

		if(memcmp(pt, needle, ns) == 0)
			return pt;

		if(hay == pt) {
			n--;
			hay++;
		} else
			hay = pt;
	}

	return NULL;
}

#else

int
cli_scanjs(const char *dir, int desc)
{
	cli_warnmsg("File not decoded - JS decoding needs mmap() (for now)\n");
	return CL_CLEAN;
}
#endif	/*HAVE_MMAP*/

#else	/*!CL_EXPERIMENTAL*/

int
cli_scanjs(const char *dir, int desc)
{
	cli_warnmsg("JS decoding files not yet supported\n");
	return CL_EFORMAT;
}

#endif	/*CL_EXPERIMENTAL*/
