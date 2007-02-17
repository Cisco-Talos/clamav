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
 * Debug package. Don't use it in a production environment unless you have
 * a spare Cray. Bug reports about performance hit will be ignored unless
 * attached with patches that don't impact on results
 */
#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#ifdef	CL_DEBUG

#ifdef	C_LINUX
#define	LINUX
#define	ANSI
#endif
/*LINTLIBRARY*/
/*
 * 1.1: Unix:	_realloc gave bogue memcpy errors
 * 1.2: Unix:	now includes own malloc/free
 * 1.3: ptr2slot added cache and sentinal as it was(is?) a bottleneck
 * 1.4: Unix:	added isptrok().
 *		Creation of FILE_ID.DIZ file.
 * 1.5:	Unix:	Reduced platform dependancies. Ported to AIX Release 2.
 *	DOS:	Removed cprintf - now uses stderr.
 * 1.5.1:	isptrok now checks for NULL pointer
 * 1.5.2:	ptr2slot:	Installed direct cache
 * 1.5.3:	_realloc:	Call clear_cache
 * 2.0:		Now debugs more than just malloc calls
 * 2.1:		Added checkembedded pointer and mmap stuff
 * 2.1.1:	Check strcpy arguments are different
 * 2.1.2:	mprotect caused mem faults in realloc
 * 2.1.3:	fixed strdup dumps not appearing
 * 2.1.4:	2.1 fix now handles strdup messages better
 * 2.1.5:	checkembeddedptr() now checks it's argument is valid
 * 2.2:		_error: no longer repeats last message
 * 2.3:		Added underflowcheck
 *		Added total summary of leaks
 *		Added call to heapchk in exit routine leaks()
 * 2.3.1:	Reported to solaris: vsprintf format isn't const
 * 2.4:		Added information on leaked file descriptors
 * 2.4.1:	Need clear_cache when allocating new slot table if the
 *		slot table has moved
 * 2.5:		Support process watches
 * 2.6:		added last_free_size to report needless mallocs of something
 * 		just freed
 *
 * LATER:
 *	Stats on number of alloc/free calls
 */
/*
 * To compile on AIX 4.1.5
 *	cc -DAIX -DANSI -O2 -qroconst -U__STR__ -qro *.c
 * With gcc on SunOs:
 *	gcc -ansi -Wshadow -Wall -Wwrite-strings -pipe -O2 -Dsun *.c
 * With cc on SunOs
 *	cc -Dsun -O4 -pipe *.c
 * For perpos:
 *	cc8 -O2 -c -DPERPOS *.c
 * With cc on Solaris
 *	cc -DANSI -Dsolaris -fast -xO4 -fd -mc -v -Xc -xCC -xstrconst *.c
 * With gcc on linux
 *	gcc -DLINUX -pipe -Wshadow -Wwrite-strings -Wall -O2 -c debug.c
 */
#ifdef	lint
#define void	char
#endif

#ifdef	solaris
#ifndef	sun
#define	sun
#endif
#define	WATCH
#endif

#if	defined(sun) || defined(AIX) || defined(LINUX) || defined(_HPUX_SOURCE)
#ifdef	MAP_ANONYMOUS
#define	MPROTECT	/* has the mprotect system call */
#endif
#endif

#ifdef	WATCH

#undef	MPROTECT

#include <procfs.h>

static	int	watchfd = -1;

#endif

#include "debug.h"

#ifdef	UNIX
static	void	none(const caddr_t addr, size_t size);
static	void	ro(const caddr_t addr, size_t size);
static	void	rw(const caddr_t addr, size_t size);
static	void	slots_readonly(void);
static	void	slots_rw(void);

#else

#define	none(addr, size)
#define	ro(addr, size)
#define	rw(addr, size)
#define	slots_readonly()
#define	slots_rw()
#endif

#ifdef	MPROTECT
#include <sys/mman.h>
#endif

/*
 * If MAX_STACK_DEPTH is defined we try a stack trace.
 */
#if	defined(sun) && !defined(solaris)
#define	MAX_STACK_DEPTH	128
#endif

#ifdef	__sparc
#define	getpagesize()	4096
#endif

#ifdef	MAX_STACK_DEPTH

#ifdef	solaris

#include <nlist.h>
#include <sys/exechdr.h>
#else
#include <a.out.h>
#endif

#ifdef	sun
#include <stab.h>
#endif
#include <sys/file.h>
#endif

#define NJH_DEBUG

#ifndef min
#define min(a,b)	(((a) < (b)) ? (a) : (b))
#endif

#ifdef	MAX_STACK_DEPTH
/* for ultrix 0x38, 4.3 bsd 0x3d, other? */

#ifdef vax
#define	CRT0_ADDRESS		0x3d
#endif

#ifdef sun
#define	CRT0_ADDRESS		0x204c
#endif

#ifdef	M_XENIX
#define	CRT0_ADDRESS		0xD4	/* SCO Unix */
#endif

#ifdef mips
/*#define CRT0_ADDRESS		0x0	/* to be filled in later */
#endif

unsigned	mp_root_address = CRT0_ADDRESS;

#endif	/*MAX_STACK_DEPTH*/

/*#undef	PP2WIN*/

#if	defined(M_I86MM) || defined(M_I86SM)
static	void	*lastfreed = (void *)-1;
#else
static	void	*lastfreed = (void *)-1L;
#endif

static	int pagesz;	/* page size */

#ifndef	_NFILE
#define	_NFILE	NOFILE
#endif

static	int	fds[_NFILE];

#ifdef	NJH_DEBUG

#ifdef	PERPOS
#define	size_t	long
#define	pid_t	int
#define	INT_MAX	MAXINT
#define	UINT_MAX	(0xFFFFFFFF)
char	*getenv();
#endif

/*
 * LATER:
 *	Replace s_ptr with a pointer to a structure that contains
 *		long underflowcheck;
 *		void *data;
 *		long overflowcheck;
 * free will check these values as will db_heapchk and blkchk, and where
 * possible access to these areas will be restricted. This would add an underrun
 * check
 * ptr2slot will need modifying, as will anything that looks for 'B'
 */
typedef struct _slotstr {
#ifdef	UNDERFLOW	/* meaningless code! */
	char	s_underflowcheck;
#endif
	void	*s_ptr;	/* the allocated area */
	size_t	s_size;	/* its size */
	unsigned int	s_blkno;	/* program block reference number */
	unsigned int	s_freed:1;	/* whether it's been freed yet */
	const char	*s_file;
	unsigned	int	s_line;
#ifdef	MAX_STACK_DEPTH
	caddr_t		s_history[MAX_STACK_DEPTH];
#endif
} SLOT;

#define MAXSLOT 1024L

#if	defined(sun) && !defined(ANSI)
#define atexit(f)	on_exit(f)
#endif

#ifdef	PERPOS
#define atexit(f)
static	void	cdecl	leaks();

int
per_exit(status)
{
	leaks();
	exit(status);
}
#endif

static	unsigned	long	maxslots;
bool	check_for_leaks;
static	unsigned	int	in_db;
#ifdef	MSDOS
typedef	char	*caddr_t;
static	SLOT	huge	*slots;
#else
static	SLOT	*slots;
#endif
static	unsigned	long	slotc;
static	unsigned	int	blkno;

#define wsize	sizeof(unsigned int)	/* 386BSD stuff */
#define wmask	(wsize - 1)	/* 386BSD stuff */

#ifndef	ANSI
static void _error();
static void *_malloc();
static void *_calloc();
static void *_realloc();
static void _free();
static	void	cdecl	leaks();
#ifdef	MAX_STACK_DEPTH
static	void	mprof();
static	void	st_read();
#endif
static	const char *symname();
#else
#ifdef	solaris
static void _error(const char *file, unsigned int line, const caddr_t *history, char *format, ...);
#else
static void _error(const char *file, unsigned int line, const caddr_t *history, const char *format, ...);
#endif
static void *_malloc(size_t size, const char *file, unsigned int line);
static void *_calloc(size_t nel, size_t size, const char *file, unsigned int line);
static void *_realloc(char *ptr, size_t size, const char *file, unsigned int line);
static void _free(char *ptr, const char *file, unsigned int line);
static	void	cdecl	leaks(void);
#ifdef	MAX_STACK_DEPTH
static	void	mprof(SLOT *sp);
static	void	st_read(void);
static	const	char *symname(caddr_t pc);
#endif
#endif

#ifndef MSDOS
#undef	strcmp
#undef	memcpy
#undef	malloc
#undef	calloc
#undef	realloc
#undef	strdup
#undef	strcpy
#undef	free
#undef	heapchk
#undef	alloca
#undef	memset
#undef	strcat
#endif

#ifdef	MSDOS
static	void	*real_memcpy(register void *m1, register const void *m2, register size_t n);
static	void	*real_malloc(size_t nbytes);
static	void	real_free(void *cp);
static	void	*real_realloc(void *cp, size_t nbytes);
#else
#ifdef	ANSI
static	void	*real_memcpy();
static	void	*real_malloc();
static	void	*real_realloc();
#else
static	char	*real_memcpy();
static	char	*real_malloc();
static	char	*real_realloc();
#endif	/*ANSI*/
static	void	real_free();
#endif	/*MSDOS*/

static void
#ifdef	ANSI
#ifdef	solaris
_error(const char *file, unsigned int line, const caddr_t *history, char *format, ...)	/* stdargs method */
#else
_error(const char *file, unsigned int line, const caddr_t *history, const char *format, ...)	/* stdargs method */
#endif
#else
_error(file, line, history, format, va_alist)	/* varargs method */
char *file;
unsigned int line;
char *format;
const caddr_t *history;
va_dcl
#endif
{
	va_list v;
	char thismessage[160];	/* 2.2 */
	static char lastmessage[160];

	in_db++;

#ifdef	MSDOS
	if(file /*&& (_fstrcmp(file, __FILE__) != 0)*/)
#else
	if(file /*&& (strcmp(file, __FILE__) != 0)*/)
#endif
		fprintf(stderr, "%u of %s: ", line, file);
#ifdef	MAX_STACK_DEPTH
	else {
		register int i;
		register const char *sym;
		SLOT sp;
		register const char **fn;
		/*
		 * Functions to ignore in stack tracing
		 */
		static const char *ignore_functions[] = {
			"db_callocchk",
			"db_mallocchk",
			"db_strdupchk",
			"db_setname",
			"calloc",
			"malloc",
			"etext",
			NULL
		};

		st_read();

		if(history == NULL) {
			mprof(&sp);
			history = sp.s_history;
		}

		for(i = 0; (history[i] > (caddr_t)mp_root_address) && (i < MAX_STACK_DEPTH); i++)
			if(sym = symname(history[i])) {
				if(*sym) {
					for(fn = ignore_functions; *fn; fn++)
						if(strcmp(sym, *fn) == 0)
							break;
					if(*fn)
						continue;
					fprintf(stderr, "Around %s: ", sym);
					/*if(strcmp(sym, "main") == 0)*/
						break;
				}
			} else
				break;
	}
#endif	/*MAX_STACK_DEPTH*/

#if	defined(__STDC__) || defined(_MSC_VER) || defined(ANSI)
	va_start(v, format);
#else
	va_start(v);
#endif

	vsprintf(thismessage, format, v);

	va_end(v);

	if(file || (strcmp(lastmessage, thismessage) != 0)) {
		fputs(thismessage, stderr);
		putc('\n', stderr);
		strcpy(lastmessage, thismessage);
	}

	in_db--;
}

#ifdef	UNIX
/*
 * Does ptr point to a valid array of at least fd bytes
 */
static bool
isptrok(ptr, size)
const void *ptr;
size_t size;
{
	static int fd;

	if(size == 0)
		return(true);
	if(ptr == NULL) {
		_error(NULL, 0, NULL, "Null pointer to %u bytes", size);
		return(false);
	}

	if(in_db)
		return(true);

	if(fd == 0)
		fd = open("/dev/null", O_WRONLY);

	if(fd > 0) {
		register int i;
		register const char *cptr;

		if(size == INT_MAX)
			size = 1;

#if	0
		if((write(fd, ptr, size) < 0) && (errno == EFAULT)) {
			_error(NULL, 0, NULL, "Invalid pointer to %u bytes", size);
			return(false);
		}
#else
		cptr = (const char *)ptr;

		for(i = 0; i < size; i++)
			if((write(fd, cptr++, 1) < 0) && (errno == EFAULT)) {
				if(i == 0)
					_error(NULL, 0, NULL, "Invalid Pointer to %u bytes", size);
				else
					_error(NULL, 0, NULL, "Pointer to %u bytes only points to %u bytes", size, i);
				return(false);
			}
#endif
	}
	return(true);
}

#else

static bool
isptrok(ptr, size)
const void *ptr;
size_t size;
{
	if(ptr == NULL) {
#ifdef	M_I86LM
		_error(NULL, 0, NULL, "Null pointer to %lu bytes", (unsigned long)size);
#else
		_error(NULL, 0, NULL, "Null pointer to %u bytes", (unsigned int)size);
#endif
		return(false);
	}
	return(true);
}
#endif

#ifdef	MSDOS
#define	CACHE_SIZE	32
#define	CACHE_SHIFT	5
#define	CACHE_MASK	0x1F
#else
#define	CACHE_SIZE	64
#define	CACHE_SHIFT	6
#define	CACHE_MASK	0x3F
#endif

/*#define	CACHE_TRACE*/

#if	CACHE_SIZE
static struct cache {
	unsigned	long	index;
	bool		isvalid;
#ifdef	M_I86LM
	unsigned	long	tag;
#else
	unsigned	int	tag;
#endif
#ifdef	CACHE_TRACE
	unsigned	int	hits;
	unsigned	int	misses;
#endif
} cache[CACHE_SIZE];

static void
clear_cache()
{
	register struct cache *c;

	for(c = cache; c < &cache[CACHE_SIZE]; c++)
		c->isvalid = false;
}
#else
static void
clear_cache()
{
}
#endif

/*
 * NJH - get an sp from a pointer
 */
#ifdef	MSDOS
static SLOT huge *
#else
static SLOT *
#endif
#ifdef	ANSI
ptr2slot(const void *ptr)
#else
ptr2slot(ptr)
void *ptr;
#endif
{
#ifdef	M_I86LM
	register unsigned long tag;
#else
	register unsigned int tag;
#endif
#ifdef	MSDOS
	register SLOT huge *sp;
#else
	register SLOT *sp;
#endif
	register void *optr;
#if	CACHE_SIZE
	register struct cache *cacheelem;
#endif

	if(slotc) {
#if	CACHE_SIZE
		/*
		 * cache, but not if NULL - it may have been allocated
		 * since the last call
		 */
#ifdef	M_I86LM
		cacheelem = &cache[(unsigned long)ptr & CACHE_MASK];
		tag = (unsigned long)ptr >> CACHE_SHIFT;
#else
		cacheelem = &cache[(unsigned int)ptr & CACHE_MASK];
		tag = (unsigned int)ptr >> CACHE_SHIFT;
#endif
		if(cacheelem->isvalid && (tag == cacheelem->tag) && slots[cacheelem->index].s_ptr) {
#ifdef	assert
			assert(slots[cacheelem->index].s_ptr == ptr);
#endif
#ifdef	CACHE_TRACE
			cacheelem->hits++;
#endif
			return(&slots[cacheelem->index]);
		}

#ifdef	CACHE_TRACE
		/*
		 * Strictly speaking all times we're here counts as a miss,
		 * but I'm really interested in looking for hot-spots,
		 * not the initial filling of the cache
		 */
		if(cacheelem->isvalid)
			cacheelem->misses++;
#endif
		sp = slots;
		if(sp->s_ptr == ptr) {
			cacheelem->tag = tag;
			cacheelem->index = 0L;
			cacheelem->isvalid = true;
			return(sp);
		}
#else
		sp = slots;
		if(sp->s_ptr == ptr)
			return(sp);
#endif	/*CACHE_SIZE*/

		optr = slots[0].s_ptr;

		slots_rw();
		slots[0].s_ptr = (void *)ptr;	/* post a sentinal */
		/* start search at end - most likely that a match'll be there */
		for(sp = &slots[slotc - 1L]; sp->s_ptr != ptr; --sp)
			;
		slots[0].s_ptr = optr;
		slots_readonly();
#if	CACHE_SIZE
		if(sp != slots) {
			cacheelem->tag = tag;
			cacheelem->index = sp - slots;
			cacheelem->isvalid = true;
			return(sp);
		}
#else
		if(sp != slots)
			return(sp);
#endif
	}
	return(NULL);
}

#ifdef	MSDOS
#ifndef PP2WIN
static void huge *
hmemcpy(register void huge *m1, register const void huge *m2, unsigned long l)
{
	register unsigned char huge *dest = m1;
	register const unsigned char huge *source = m2;

	while(l--)
		*dest++ = *source++;
	return(m1);
}

static void huge *
hmemset(register void huge *s, unsigned char ch, unsigned long l)
{
	register unsigned char huge *t;

	t = s;
	while(l--)
		*t++ = (unsigned char)ch;
	return(s);
}
#endif
#endif

static	size_t	last_free_size;

/*
 *	_malloc - wrapper around malloc. Warns if unusual size given, or the
 *	real malloc returns a NULL pointer. Returns a pointer to the
 *	malloc'd area
 */
static void *
#ifdef	ANSI
_malloc(size_t size, const char *file, unsigned int line)
#else
_malloc(size, file, line)
size_t size;
char *file;
unsigned int line;
#endif
{

#ifdef	MSDOS
#ifdef PP2WIN
	static HGLOBAL hslots;
	register HGLOBAL hnewslots;
#endif
	register SLOT huge *sp;
#else
	register SLOT *sp, *oldslots;
#endif
	register char *ptr;
	register int i;
	static bool hasprinted;
	bool dofds;

	if(!hasprinted) {
		check_for_leaks = hasprinted = true;
		atexit(leaks);

		dofds = 1;
	} else
		dofds = 0;

	if(size == 0) {
		_error(file, line, NULL, "malloc: 0 bytes wanted");
		/*return(NULL);*/
	} else if(size == last_free_size) {
		in_db++;
		for(sp = slots; sp != &slots[slotc]; sp++)
			if(sp->s_freed && sp->s_file && file &&
			  (strcmp(sp->s_file, file) == 0) &&
			  (sp->s_size == last_free_size)) {
				_error(file, line, NULL, "malloc: %d bytes wanted which was freed at %d of %s", size, sp->s_line, sp->s_file);
				break;
			}
		in_db--;
	}
#ifdef PP2WIN
	if((ptr = (char *)rhpaca(1, size + 1)) == (char *) NULL) {
		_error(file, line, NULL, "malloc: unable to malloc %u bytes", size);
		return(NULL);
	}
#elif defined(M_I86LM)
	if((ptr = (char *)_fmalloc(size + 1)) == (char *) NULL) {
		_error(file, line, NULL, "malloc: unable to malloc %u bytes", size);
		return(NULL);
	}
#elif defined(MSDOS) && (defined(M_I86MM) || defined(M_I86SM))
	if((ptr = (char *)_nmalloc(size + 1)) == (char *) NULL) {
		_error(file, line, NULL, "malloc: unable to malloc %u bytes", size);
		return(NULL);
	}
#elif defined(MSDOS)
	if((ptr = (char *)malloc(size + 1)) == (char *) NULL) {
		_error(file, line, NULL, "malloc: unable to malloc %u bytes", size);
		return(NULL);
	}
#elif	defined(MPROTECT)
	if(!in_db) {
		/*
		 * Wasteful of memory - but it allows mprotect to work
		 */
		unsigned int alignment = (pagesz) ? pagesz : getpagesize();
		size_t nsize;

#define	round_to(i, nearest) \
		((((i) + (nearest) - 1) / (nearest)) * (nearest))

		nsize = round_to(size + 1, sizeof(int)) + alignment;
		ptr = real_malloc(nsize);
		if(ptr == (char *)NULL) {
			_error(file, line, NULL, "malloc: unable to malloc %u bytes", size);
			return(NULL);
		}
		mprotect(ptr, nsize, PROT_READ|PROT_WRITE);
		ptr = (char *)round_to((unsigned int)ptr, alignment);
	} else if((ptr = (char *)real_malloc(size + 1)) == (char *) NULL) {
		_error(file, line, NULL, "malloc: unable to malloc %u bytes", size);
		return(NULL);
	} else
		mprotect(ptr, size + 1, PROT_READ|PROT_WRITE);
#else
	if((ptr = (char *)real_malloc(size + 1)) == (char *) NULL) {
		_error(file, line, NULL, "malloc: unable to malloc %u bytes", size);
		return(NULL);
	}
#ifdef	WATCH
	rw(ptr, size + 1);
#endif
#endif

	ptr[size] = 'B';	/* crude bounds check */

	ro(&ptr[size], 1);

	if(slots == NULL) {
		in_db++;
#ifdef	MSDOS
#ifdef	PP2WIN
		hslots = GlobalAlloc(GMEM_MOVEABLE|GMEM_NODISCARD|GMEM_ZEROINIT,
				MAXSLOT * sizeof(SLOT));
		slots = (SLOT huge *)GlobalLock(hslots);
#else
		slots = (SLOT huge *)halloc(MAXSLOT, sizeof(SLOT));
		hmemset(slots, '\0', MAXSLOT * sizeof(SLOT));
#endif
#else
		slots = (SLOT *)real_malloc(MAXSLOT * sizeof(SLOT));
		memset(slots, '\0', MAXSLOT * sizeof(SLOT));
#endif
		maxslots = MAXSLOT;
		clear_cache();
		in_db--;
		slots_rw();
	}

	sp = ptr2slot(ptr);

	if(sp == NULL) {
		if(slotc == maxslots - 1L) {
			/* maybe we can salvage something */
			for(sp = slots; sp != &slots[slotc]; sp++)
				if(sp->s_ptr == NULL)
					break;	/* probably realloced */
			if(sp == &slots[slotc]) {
				/* run out of slots */
#ifdef	MSDOS
#ifdef	PP2WIN
				hnewslots = GlobalAlloc(GMEM_MOVEABLE|GMEM_NODISCARD|GMEM_ZEROINIT,
						(maxslots + MAXSLOT) * sizeof(SLOT));
				if(hnewslots == (HGLOBAL)NULL) {
					rhpfree(ptr);
					rhpw_mbox("can't increase maxslots", "Callbook on disc");
					return(NULL);
				}
				sp = (SLOT huge *)GlobalLock(hnewslots);
				hmemcpy(sp, slots, maxslots * sizeof(SLOT));
				GlobalUnlock(hslots);
				GlobalFree(hslots);
				slots = sp;
				hslots = hnewslots;
#else	/*!PP2WIN*/
				if(sp = (SLOT huge *)halloc(maxslots + MAXSLOT, sizeof(SLOT)))
					hmemcpy(sp, slots, maxslots * sizeof(SLOT));
				else {
#ifdef	M_I86LM
					_ffree(ptr);
#else
					_nfree(ptr);
#endif
					_error(file, line, NULL, "can't increase maxslots to %lu", maxslots);
					return(NULL);
				}
				hfree(slots);
				slots = sp;
				hmemset(&slots[maxslots], '\0', MAXSLOT * sizeof(SLOT));
#endif	/*PP2WIN*/
				maxslots += MAXSLOT;
#else	/*!MSDOS*/
				slots_rw();
				maxslots += MAXSLOT;
				oldslots = slots;
				slots = (SLOT *)real_realloc((char *)slots, maxslots * sizeof(SLOT));
				slots_rw();
				in_db++;
				memset(&slots[maxslots - MAXSLOT], '\0', MAXSLOT * sizeof(SLOT));
				in_db--;
#endif
				sp = &slots[slotc++];
				/*
				 * 2.4.1 fix
				 */
#ifdef	UNIX
				if(slots != oldslots) {
					clear_cache();
					none((caddr_t)oldslots, (maxslots - MAXSLOT) * sizeof(SLOT));
				}
#else
				clear_cache();
#endif
			}
		} else
			sp = &slots[slotc++];
	} else if(!sp->s_freed)
		_error(file, line, NULL, "malloc: malloc returned a non-freed pointer");

#ifdef	MAX_STACK_DEPTH
	if(!in_db)
		mprof(sp);
#endif

	if((unsigned)(sp - slots) > maxslots)
		fputs("sp overflow\n", stderr);

	slots_rw();
	sp->s_size = size;
	sp->s_freed = false;
	sp->s_ptr = ptr;
	sp->s_blkno = blkno;
	sp->s_file = file;
	sp->s_line = line;
#ifdef	UNDERFLOW
	sp->s_underflowcheck = 'B';
#endif
	slots_readonly();

	if(dofds)
		/*
		 * Leave this to the last possible moment so that /dev/null
		 * and /dev/zero have already been opened. That should stop us
		 * getting bogus fd leak errors
		 */
		for(i = 0; i < _NFILE; i++)
			fds[i] = ((lseek(i, (off_t)0, SEEK_CUR) >= 0) || (errno != EBADF));
	return(ptr);
}

/*
 *	_calloc - wrapper for calloc. Calls _malloc to allocate the area, and
 *	then sets the contents of the area to NUL bytes. Returns its address.
 */
static void *
#ifdef	ANSI
_calloc(size_t nel, size_t size, const char *file, unsigned int line)
#else
_calloc(nel, size, file, line)
size_t nel, size;
char *file;
unsigned int line;
#endif
{
	register size_t tot;
	register void *ptr;

	tot = nel * size;
	if(ptr = _malloc(tot, file, line)) {
		in_db++;
		memset(ptr, '\0', tot);
		in_db--;
	}
	return(ptr);
}

/*
 *	_realloc - wrapper for realloc. Checks area already alloc'd and
 *	not freed. Returns its address
 */
static void *
#ifdef	ANSI
_realloc(char *ptr, size_t size, const char *file, unsigned int line)
#else
_realloc(ptr, size, file, line)
char *ptr;
size_t size;
char *file;
unsigned int line;
#endif
{
	register char *optr = ptr;
#ifdef	MSDOS
	register SLOT huge *sp, const huge *nsp;
#ifdef	PP2WIN
	register char *nptr;
#endif
#else
	register SLOT *sp, *nsp;
#endif

	if(slots == NULL)
		_error(file, line, NULL, "realloc: called before any alloc");
	sp = ptr2slot(ptr);
	if(sp == NULL) {
		_error(file, line, NULL, "realloc: realloc on unallocated area");
		return(NULL);
	}
	if(sp->s_freed) {
		_error(file, line, NULL, "realloc: realloc on freed area (block freed at %d of %s)", sp->s_line, sp->s_file);
		return(NULL);
	}
	in_db++;
	if(ptr[sp->s_size] != 'B') /* bounds check */
		_error(file, line, NULL, "realloc: overflow of %u bytes", sp->s_size);
#ifdef	UNDERFLOW
	else if(sp->s_underflowcheck != 'B')
		_error(file, line, NULL, "realloc: underflow of %u bytes", sp->s_size);
#endif
	else if(sp->s_size == size) {
		if(sp->s_file)
			_error(file, line, NULL, "realloc: want same size %u bytes as %d of %s",
				size, sp->s_line, sp->s_file);
		else
			_error(file, line, NULL, "realloc: want same size %u bytes", size);
	} else if(size == 0)
		_error(file, line, NULL, "realloc: 0 bytes wanted");
#ifdef	PP2WIN
	else if((nptr = rhpaca(1, size + 1)) == (char *)NULL)
		_error(file, line, NULL, "realloc: realloc failure %u bytes", size);
#elif	defined(M_I86LM)
	else if((ptr = _frealloc(ptr, size + 1)) == (char *)NULL)
		_error(file, line, NULL, "realloc: realloc failure %u bytes", size);
#elif	defined(MSDOS) && (defined(M_I86MM) || defined(M_I86SM))
	else if((ptr = _nrealloc(ptr, size + 1)) == (char *)NULL)
		_error(file, line, NULL, "realloc: realloc failure %u bytes", size);
#else
	else if((ptr = real_realloc(ptr, size + 1)) == (char *)NULL)
		_error(file, line, NULL, "realloc: realloc failure %u bytes", size);
#endif
	else {
		if(ptr != optr)
			if(nsp = ptr2slot(optr))
				none(optr, nsp->s_size);
		rw(ptr, size);
#ifdef	PP2WIN
		real_memcpy(nptr, ptr, min(sp->s_size, size));
		rhpfree(ptr);	/* don't call freechk here */
		ptr[size - 1] = '\0';
		ptr = nptr;
#endif
		/*
		 * If it's a completely new pointer, mark that
		 * the old pointer is no longer used.
		 *
		 * If we're still using the old pointer to save
		 * reshuffle/memcpy in real_realloc, make sure that the new
		 * pointer is a sensible one
		 */
		slots_rw();
		for(nsp = slots; nsp != &slots[slotc]; nsp++)
			if((nsp->s_ptr == optr) && (ptr != optr))
				nsp->s_freed = true;
			else if((nsp->s_ptr == ptr) && (nsp != sp)) {
				if(!nsp->s_freed)
					_error(file, line, NULL, "realloc: returns pointer already in use");
				nsp->s_ptr = NULL;
			}
		/* Clearing the entire cache is OTT but safe */
		clear_cache();
		rw(&ptr[size], 1);
		ptr[size] = 'B';	/* crude bounds check */
		ro(&ptr[size], 1);
		sp->s_ptr = ptr;
		sp->s_size = size;
		sp->s_blkno = blkno;
		sp->s_freed = false;
		sp->s_file = file;
		sp->s_line = line;
#ifdef	UNDERFLOW
		sp->s_underflowcheck = 'B';
#endif
		slots_readonly();
	}
	in_db--;
	return(ptr);
}

#ifdef	sun
static const SLOT *
checkembeddedptr(memblock, size)
const void *memblock;
int size;
{
	(void)isptrok(memblock, size);
	return(NULL);
}

#else

#ifdef	MSDOS
static const SLOT huge *
#else
static const SLOT *
#endif
#ifdef	ANSI
checkembeddedptr(const void *memblock, int size)
#else
checkembeddedptr(memblock, size)
char *memblock;
int size;
#endif
{
#ifdef	ANSI
	const void **p;
#else
	void **p;
#endif

#ifdef	MSDOS
	register const SLOT huge *sp;
#else
	register const SLOT *sp;
#endif

#ifdef	sun
	/* Need to word align the pointer - sigh */
	{
		unsigned long t;

		t = (unsigned long)memblock;

		if(t & wmask) {
			t &= ~wmask;
			p = (void **)t;
			p += sizeof(void *);
			size -= sizeof(void *);
		} else
			p = (void **)memblock;
	}
#else
#ifdef	ANSI
	p = (const void **)memblock;
#else
	p = (void **)memblock;
#endif
#endif

	if(!isptrok(p, size))	/* 2.1.5 */
		return(NULL);

	while(size > 0) {
		if(*p && (sp = ptr2slot(*p)))
			if(!sp->s_freed)
				return(sp);
		p++;	/* 2.1.5 - was p += sizeof(void *) */
		size -= sizeof(void *);
	}

	return(NULL);
}
#endif

/* 2.1.3 added const */
static	const	unsigned	int	strdupline = __LINE__;

/*
 *	_free - wrapper for free. Loop through allocated slots, until you
 *	find the one corresponding to pointer. If none, then it's an attempt
 *	to free an unallocated area. If it's already freed, then tell user.
 */
static void
#ifdef	ANSI
_free(char *memblock, const char *file, unsigned int line)
#else
_free(memblock, file, line)
char *memblock;
char *file;
unsigned int line;
#endif
{
#ifdef	MSDOS
	register SLOT huge *sp;
	register const SLOT huge *ssp;
#else
	register SLOT *sp;
	register const SLOT *ssp;
#endif

	sp = ptr2slot(memblock);
	in_db++;
	if(sp == NULL) {
		_error(file, line, NULL, "free: free not previously malloc'd");
		in_db--;
		return;
	}
	if(sp->s_freed)
		_error(file, line, NULL, "free after previous freeing %u bytes", sp->s_size);
	else if(memblock[sp->s_size] != 'B')	/* bounds check */
		_error(file, line, NULL, "free: overflow of %u bytes allocated %u of %s", sp->s_size,
			sp->s_line, sp->s_file);
#ifdef	UNDERFLOW
	else if(sp->s_underflowcheck != 'B')
		_error(file, line, NULL, "free: underflow of %u bytes allocated %u of %s", sp->s_size,
			sp->s_line, sp->s_file);
#endif
	else {
		/*
		 * LATER: warn if the block to be freed contains any pointers
		 * which haven't been freed. Warn if it does, otherwise
		 * clear the area
		 */
		rw(memblock, sp->s_size);
		ssp = NULL;
		if(file /*&& (strcmp(file, __FILE__) != 0)*/) {
			/*
			 * Find the first part of the memory that was
			 * actually used at some time
			 */
			register char *ptr;
			register size_t nbytes = sp->s_size;

			for(ptr = memblock; nbytes && (*ptr == '\0'); ptr++)
				nbytes--;

			/*
			 * The checkembeddedptr code produces a lot of false
			 *	positives when freeing a linked list, even
			 *	if the code is correct.
			 * TODO: only warn on first embeddedpoiner free
			 */
			if(nbytes == 0) {
				if(sp->s_file)
					_error(file, line, NULL, "free: %u bytes (allocated %d of %s) may never have been used",
						sp->s_size, sp->s_line, sp->s_file);
				else
					_error(file, line, NULL, "free: %u bytes may never have been used", sp->s_size);
			/*} else if(ssp = checkembeddedptr(ptr, nbytes)) {*/
			} else if(ssp = checkembeddedptr(memblock, sp->s_size)) {
				if(ssp->s_file) {
					if((strcmp(ssp->s_file, __FILE__) == 0) && (ssp->s_line == strdupline))
						_error(file, line, NULL, "free: pointer possibly points to data which contains unfree strdup: \"%s\"", (const char *)ssp->s_ptr);
					else
						_error(file, line, NULL, "free: pointer possibly points to data which contains unfree pointer from %d of %s", ssp->s_line, ssp->s_file);
				} else
					_error(file, line, NULL, "free: pointer possibly points to data which contains unfree pointer to %u bytes", ssp->s_size);
			}
		} else if(ssp = checkembeddedptr(memblock, sp->s_size)) {
			if(ssp->s_file) {
				if((strcmp(ssp->s_file, __FILE__) == 0) && (ssp->s_line == strdupline))
					_error(NULL, 0L, NULL, "free: pointer possibly points to data which contains unfree strdup: \"%s\"", (const char *)ssp->s_ptr);
				else
					_error(NULL, 0, NULL, "free: pointer possibly points to data which contains unfree pointer from %d of %s", ssp->s_line, ssp->s_file);
			} else
				_error(NULL, 0, NULL, "free: pointer possibly points to data which contains unfree pointer to %u bytes", ssp->s_size);
		}
#ifdef	PP2WIN
		rhpfree(memblock);
#elif	defined(M_I86LM)
		(void)_ffree(memblock);
#elif	defined(MSDOS) && (defined(M_I86MM) || defined(M_I86SM))
		(void)_nfree(memblock);
#else
		(void)real_free(memblock);
#endif
		/* if(sp->s_file[0])
			sp->s_file[0] = '\0'; */
		if(ssp == NULL) {
#ifdef	MSDOS
			memset(memblock, '\0', sp->s_size);	/* stop re-use of the area */
#else
			/*
			 * Also stop access to the 'B' byte
			 */
			/*rw(&memblock[sp->s_size], 1);*/
			none(memblock, sp->s_size + 1);
#endif
		}
	}
	slots_rw();
	sp->s_freed = true;
	sp->s_file = file;
	sp->s_line = line;
	slots_readonly();
	last_free_size = sp->s_size;
	in_db--;
}

void _pascal	/* NJH */
#ifdef	ANSI
db_heapchk(const char *file, int line)
#else
db_heapchk(file, line)
char *file;
int line;
#endif
{
#ifdef	MSDOS
	register SLOT huge *sp;
#else
	register SLOT *sp;
#endif

#if	defined(_MSC_VER) && (_MSC_VER >= 600)
#ifndef PP2WIN
	if(_heapchk() != _HEAPOK)
		_error(file, line, NULL, "Possible memory corruption");
#endif
#endif
	for(sp = slots; sp != &slots[slotc]; sp++)
		if((!sp->s_freed) && sp->s_file) {
			register const char *ptr = sp->s_ptr;

			if(ptr == NULL) {
				_error(file, line, NULL, "Unexpected NULL pointer");
				return;
			}
#ifndef	MSDOS
			rw(&ptr[sp->s_size], 1);
#endif
			if(!isptrok(ptr, sp->s_size))
				_error(file, line, NULL, "Pointer to %u bytes from %d of %s has become invalid", sp->s_size, sp->s_line, sp->s_file);
#ifdef	UNDERFLOW
			else if((ptr[sp->s_size] != 'B') || (sp->s_underflowcheck != 'B'))
#else
			else if(ptr[sp->s_size] != 'B')
#endif
				_error(file, line, NULL, "Corruption of %u bytes from %d of %s", sp->s_size, sp->s_line, sp->s_file);
		}
}

/*
 *	_blkstart - start of a program block. Increase the block reference
 *	number by one.
 */
void
_blkstart()
{
	blkno++;
}

/*
 *	_blkend - end of a program block. Check all areas allocated in this
 *	block have been freed. Decrease the block number by one.
 */
void
_blkend()
{
#ifdef	MSDOS
	register SLOT huge *sp;
#else
	register SLOT *sp;
#endif

	if(blkno == 0) {
		_error(NULL, 0, NULL, "_blkend: unmatched call to _blkend");
		return;
	}
	for(sp = slots; sp != &slots[slotc]; sp++)
		if(sp->s_blkno == blkno && !sp->s_freed)
			_error(NULL, 0, NULL, "_blkend: %u bytes unfreed", sp->s_size);
	blkno--;
}

/*
 *	_blkignore - find the slot corresponding to ptr, and set its block
 *	number to zero, to avoid _blkend picking it up when checking.
 */
void
_blkignore(ptr)
void	*ptr;
{
#ifdef	MSDOS
	register SLOT huge *sp;
#else
	register SLOT *sp;
#endif

	if(sp = ptr2slot(ptr))
		sp->s_blkno = 0;
	else
		_error(NULL, 0, NULL, "_blkignore: pointer has not been allocated");
}

/*
 * NJH:
 *	Check a block is still valid
 */
bool
#ifdef	ANSI
_blkchk(const char *ptr)
#else
_blkchk(ptr)
char *ptr;
#endif
{
#ifdef	MSDOS
	register SLOT huge *sp;
#else
	register SLOT *sp;
#endif

	if(sp = ptr2slot(ptr)) {
#ifdef	UNDERFLOW
		if((!sp->s_freed) && ((ptr[sp->s_size] != 'B') || (sp->s_underflowcheck != 'B'))) {
#else
		if((!sp->s_freed) && (ptr[sp->s_size] != 'B')) {
#endif
			_error(NULL, 0, NULL, "_blkcheck: possible corruption of %u bytes", sp->s_size);
			return(false);
		}
		return(true);	/* it's one of ours so it's safe */
	}
	return(isptrok(ptr, (sp) ? sp->s_size : 1));
}

/* what's the length of the thing this points to */
static size_t
#ifdef	ANSI
blklen(const void *ptr, bool isstring)
#else
blklen(ptr, isstring)
void *ptr;
bool isstring;
#endif
{
	register size_t len = (_blkchk(ptr) && ptr && isstring) ? strlen(ptr) : 0;

	if(slots) {
#ifdef	MSDOS
		register const SLOT huge *sp;
#else
		register const SLOT *sp;
#endif
		if(sp = ptr2slot(ptr))
			if(!sp->s_freed) {	/* may be allocated elsewhere */
				if(len > sp->s_size)
					_error(NULL, 0, NULL, "string may not be NUL terminated");
				return(sp->s_size);
			}
	}
	if(ptr && isstring)
		return(len + 1);
	/*
	 * It would seem sensible to return UINT_MAX here, but on some systems
	 * size_t is a signed int (e.g. on sunos)
	 */
	return(INT_MAX);
}
#endif	/*NJH_DEBUG*/

/*
 * common/debug.c:
 *	Allocate & free memory plus checks
 */
void *pascal
db_mallocchk(size, file, line)
size_t size;
const char *file;
int line;
{
	void *p = db_callocchk(1, size, file, line);

	if(p) {
		in_db++;
		memset(p, 0xEE, size);
		in_db--;
	}
	return(p);
}

void *pascal
db_callocchk(nelem, size, file, line)	/* like calloc */
size_t nelem, size;
const char *file;
int line;
{
	register void *area;

#ifdef	MSDOS
	if((long)nelem * (long)size > 65535L) {
#ifdef	NJH_DEBUG
		_error(file, line, NULL, "Too big");
#else
		errstring = "Too big";
#endif
		return(NULL);
	}
#endif
	lastfreed = NULL;

#ifdef	NJH_DEBUG
	if(area = _calloc(nelem, size, file, line))
		return(area);
#else
#ifdef	PP2WIN
	if(area = rhpaca((PP16)nelem, (PP16)size))
		return(area);
#else
	if(area = calloc(nelem, size))
		return(area);
#endif	/*PP2WIN*/
#endif
	/* remove_urgent(); */
#ifdef	PP2WIN
	if(area = rhpaca((PP16)nelem, (PP16)size))
		return(area);
#else
#ifdef	MSDOS
	_heapmin();
#endif

#ifdef	NJH_DEBUG
	if(area = _calloc(nelem, size, file, line))
		return(area);
#else
	if(area = calloc(nelem, size))
		return(area);
#endif
#endif	/*PP2WIN*/

#ifdef	NJH_DEBUG
	_error(file, line, NULL, "calloc of %u bytes failed", nelem * size);
#endif

	return((void *)NULL);
}

void *pascal
db_reallocchk(oarea, size, file, line)	/* like realloc */
void *oarea;
size_t size;
const char *file;
int line;
{
	register void *area;

	if(oarea == NULL)
		return(db_mallocchk(size, file, line));
	lastfreed = NULL;

#ifdef	NJH_DEBUG
	if(area = _realloc(oarea, size, file, line))
		return(area);
#else
#ifdef	PP2WIN
	area = db_mallocchk(size, file, line);
	if(area == NULL)
		return((void *)NULL);
	real_memcpy(area, oarea, size);
	rhpfree(oarea);
	return(area);
#else
	if(area = realloc(oarea, size))
		return(area);
#endif
#endif
	/* remove_urgent(); */
#ifdef	MSDOS
	_heapmin();
#endif
#ifdef	NJH_DEBUG
	if(area = _realloc(oarea, size, file, line))
		return(area);
	_error(file, line, NULL, "realloc: No more memory");
	return((void *)NULL);
#else
	return(realloc(oarea, size));
#endif
}

#ifdef	NJH_DEBUG
#undef	strdup
#ifndef	PERPOS
char *cdecl
#ifdef	ANSI
strdup(const char *string)
#else
strdup(string)
char *string;
#endif
{
	/* 2.1.3 changed NULL to __FILE__ */
	return(db_strdupchk(string, __FILE__, strdupline));
}
#endif

char *cdecl
#ifdef	ANSI
_strdup(const char *string)
#else
_strdup(string)
char *string;
#endif
{
	/* 2.1.3 changed NULL to __FILE__ */
	return(db_strdupchk(string, __FILE__, strdupline));
}

char *pascal
#ifdef	ANSI
db_strdupchk(const char *string, const char *file, int line)	/* like strdup */
#else
db_strdupchk(string, file, line)	/* like strdup */
char *string, *file;
int line;
#endif
{
	register char *area;
#ifndef PP2WIN
	register size_t len;
#endif

	if(string == NULL) {
		_error(file, line, NULL, "Attempt to strdup NULL");
		return(NULL);
	}
	if(!_blkchk(string))
		return(NULL);

	lastfreed = NULL;

#ifdef	PP2WIN
	area = db_mallocchk(strlen(string) + 1, file, line);
	if(area == NULL)
		return((char *)NULL);
	return(strcpy(area, string));
#else
	len = strlen(string) + 1;
	if(area = _malloc(len, file, line))
		return(real_memcpy(area, string, len));
#ifdef	MSDOS
	_heapmin();
	if(area = _malloc(len, file, line))
		return(real_memcpy(area, string, len));
#endif

#ifdef	NJH_DEBUG
	_error(file, line, NULL, "strdupchk: No more memory");
#endif

	return((char *)NULL);
#endif	/*PP2WIN*/
}

#ifndef DBMALLOC
int cdecl
#ifdef	ANSI
strcmp(register const char *s1, register const char *s2)
#else
strcmp(s1, s2)
register char *s1, *s2;
#endif
{
	if(in_db == 0) {
		if((s1 == NULL) || (s2 == NULL)) {
			_error(NULL, 0, NULL, "Attempt to strcmp NULL");
			return(0);
		}
		if(s1 == s2) {
			_error(NULL, 0, NULL, "strcmp: no affect (\"%s\")", s1);
			return(0);
		}
		_blkchk(s1);
		_blkchk(s2);
	}
	while(*s1 == *s2++)
		if(*s1++ == '\0')
			return(0);
	return(*(unsigned char *)s1 - *(unsigned char *)--s2);
}

char *cdecl
#ifdef	ANSI
strcpy(register char *s1, register const char *s2)
#else
strcpy(s1, s2)
register char *s1, *s2;
#endif
{
	if(in_db == 0) {
		register size_t sz1, sz2;

		if(s1 == NULL) {
			_error(NULL, 0, NULL, "Attempt to strcpy to NULL");
			return(NULL);
		}
		if(s2 == NULL) {
			_error(NULL, 0, NULL, "Attempt to strcpy from NULL");
			return(NULL);
		}
		if(s1 == s2) {
			_error(NULL, 0, NULL, "strcpy: %s (no affect)", s1);
			return(NULL);
		}
		sz1 = blklen(s1, false);
		if(sz1 != INT_MAX) {
			/* +1 because of the null byte */
			sz2 = strlen(s2) + 1;
			if(sz2 > sz1) {
				_error(NULL, 0, NULL, "Attempt to strcpy \"%s\" on top of %u bytes", s2, sz1);
				return(NULL);
			}
			if(sz2 > 3 * wsize) {
				/* We know the length */
				return(real_memcpy(s1, s2, sz2));
			}
		}
	}

	{
		register char *ret = s1;

		while(*s1++ = *s2++)
			;
		return(ret);
	}

	/*{
		register char c;
		register const int off = s1 - s2 - 1;

		do
			c = *s2++;
		while(s1[off] = c]);

		return(s1);
	}*/
}

char *cdecl
#ifdef	ANSI
strcat(register char *s1, register const char *s2)
#else
strcat(s1, s2)
register char *s1, *s2;
#endif
{
	register char *ret = s1;

	if(in_db == 0) {
		if((s1 == NULL) || (s2 == NULL)) {
			_error(NULL, 0, NULL, "Attempt to strcat NULL");
			return(NULL);
		}
		_blkchk(s1);
		_blkchk(s2);
		if(strlen(s2) > strlen(s2) + blklen(s2, false))
			_error(NULL, 0, NULL, "May not be enough room for strcat");
	}

	while(*s1++)
		;
	--s1;
	while(*s1++ = *s2++)
		;
	return(ret);
}

#ifdef	ANSI
void *_pascal
db_memcpy(register void *m1, register const void *m2, size_t n, const char *file, int line)
#else
void *_pascal
db_memcpy(m1, m2, n, file, line)
register char *m1, *m2;
size_t n;
char *file;
#endif
{
	if((n == 0) || (m1 == m2)) {	/* nothing to do */
		/*
		 * On SunOs printfs generate memcpy with 0 bytes, so
		 * this message appears from printfs in this file, hence
		 * the need to check even if in_db - we don't want to call
		 * real_memcpy with 0 bytes as it'll dump core
		 */
		if(!in_db)
			_error(file, line, NULL, "memcpy: %s (no affect)", (n == 0) ? "n == 0" : "m1 == m2");
		return(m1);
	}
	if(in_db == 0) {
		register size_t size;

		if((m1 == NULL) || (m2 == NULL)) {
			_error(file, line, NULL, "Attempt to memcpy NULL");
			return(NULL);
		}
		size = blklen(m1, false);
		if(n > size) {
			_error(file, line, NULL, "Attempt to memcpy %u on top of %u bytes", n, size);
			n = size;
		}
		if(!isptrok(m1, size))
			return(NULL);

		size = blklen(m2, false);
		if(n > size) {
			_error(file, line, NULL, "Attempt to memcpy %u from %u bytes", n, size);
			n = size;
#ifdef	M_I86SM
		} else if(((unsigned short)m1 > (unsigned short)m2) && ((unsigned short)m1 < (unsigned short)m2 + n))
#else
		} else if(((unsigned long)m1 > (unsigned long)m2) && ((unsigned long)m1 < (unsigned long)m2 + n))
#endif
			_error(file, line, NULL, "Warning: overlapping memcpy");
		if(!isptrok(m2, size))
			return(NULL);
	}
	return(real_memcpy(m1, m2, n));
}

#ifdef	MSDOS	/* can't trust sizeofs */
#ifdef	ANSI
void *cdecl
memset(void *s, int ch, size_t n)
#else
char *cdecl
memset(s, ch, n)
void *s;
int ch;
size_t n;
#endif
{
	register unsigned char *t;

	if(in_db == 0) {
		register size_t size;

		if(s == NULL) {
			_error(NULL, 0, NULL, "Attempt to memset NULL");
			return(NULL);
		}
		size = blklen(s, false);
		if(n > size) {
			_error(NULL, 0, NULL, "Attempt to memset %u with %u bytes", size, n);
			return(NULL);
		}
	}
	t = s;
	while(n--)
		*t++ = (unsigned char)ch;
	return(s);
}

static void *
real_memcpy(register void *m1, register const void *m2, register size_t n)
{
	register unsigned char *dest;
	register const unsigned char *source;

	dest = m1;
	source = m2;
	while(n--)
		*dest++ = *source++;
	return(m1);
}

#ifdef	_MSC_VER
/* the MSC provided fread/fwrite have a near call to memcmp */
size_t __cdecl
fread(void *buffer, size_t size, size_t count, FILE *stream)
{
	register size_t ret = 0;
	register size_t offset, buflen;
	register char *buf = (char *)buffer;
	register int c;

	buflen = blklen(buffer, false);
	if((count * size) > buflen) {
		_error(NULL, 0, NULL, "Attempt to fread %u on top of %u bytes", count * size, buflen);
		return(0);
	}
	while(count--) {
		for(offset = size; offset; offset--) {
			c = getc(stream);
			if(c == EOF)
				return(ret);
			*buf++ = (char)c;
		}
		ret++;
	}
	return(ret);
}

size_t __cdecl
fwrite(const void *buffer, size_t size, size_t count, FILE *stream)
{
	register size_t ret = 0;
	register size_t offset, buflen;
	register char *buf = (char *)buffer;

	buflen = blklen(buffer, false);
	if((count * size) > buflen) {
		_error(NULL, 0, NULL, "Attempt to fwrite %u on top of %u bytes", count * size, buflen);
		return(0);
	}
	while(count--) {
		for(offset = size; offset; offset--) {
			putc(*buf, stream);
			if(ferror(stream))
				return(ret);
			buf++;
		}
		ret++;
	}
	return(ret);
}
#endif	/*MSC*/

#else	/*!MSDOS*/

#ifdef	ANSI
void *cdecl
memset(void *s, int ch, size_t n)
#else
char *cdecl
memset(s, ch, n)
char *s;
int ch; size_t n;
#endif
{
	register size_t size, t;
	register unsigned int c;
	register unsigned char *dst;

	if(in_db == 0) {
		if(s == NULL) {
			_error(NULL, 0, NULL, "Attempt to memset NULL");
			return(NULL);
		}
		size = blklen(s, false);
		if(n > size) {
			_error(NULL, 0, NULL, "Attempt to memset %u with %u bytes", size, n);
			return(NULL);
		}
	}
	/*for(p = s; n--; *p++ = (unsigned char)ch)
		;*/

	dst = (unsigned char *)s;
	/*
	 * If not enough words, just fill bytes. A length >= 2 words
	 * guarantees that at least one of them is `complete' after
	 * any necessary alignment. For instance:
	 *
	 *	|-----------|-----------|-----------|
	 *	|00|01|02|03|04|05|06|07|08|09|0A|00|
	 *		  ^---------------------^
	 *		dst		dst+length-1
	 *
	 * but we use a minimum of 3 here since the overhead of the code
	 * to do word writes is substantial.
	 */
	if(n < 3 * wsize) {
		while(n--)
			*dst++ = (unsigned char)ch;
		return(s);
	}

	if((c = (unsigned char)ch) != 0) {	/* Fill the word. */
		c = (c << 8) | c;	/* u_int is 16 bits. */
#if UINT_MAX > 0xffff
		c = (c << 16) | c;	/* u_int is 32 bits. */
#endif
#if UINT_MAX > 0xffffffff
		c = (c << 32) | c;	/* u_int is 64 bits. */
#endif
	}
	/* Align destination by filling in bytes. */
	if((t = (int)dst & wmask) != 0) {
		t = wsize - t;
		n -= t;
		do
			*dst++ = (unsigned char)ch;
		while(--t != 0);
	}

	/* Fill words. Length was >= 2*words so we know t >= 1 here. */
	t = n / wsize;
	do {
		*(unsigned int *)dst = c;
		dst += wsize;
	} while (--t != 0);

	/* Mop up trailing bytes, if any. */
	t = n & wmask;
	/*if(t != 0)
		do
			*dst++ = (unsigned char)ch;
		while (--t != 0);*/
	while(t--)
		*dst++ = (unsigned char)ch;
	return(s);

}

#ifdef	ANSI
static void *cdecl
real_memcpy(void *m1, const void *m2, size_t n)
#else
static char *cdecl
real_memcpy(m1, m2, n)
char *m1, *m2;
register size_t n;
#endif
{
	register char *dst = m1;
	register const char *src = m2;
	register int t;

	if ((unsigned long)dst < (unsigned long)src) {
		/*
		 * Copy forward.
		 */
		t = (int)src;	/* only need low bits */
		if ((t | (int)dst) & wmask) {
			/*
			 * Try to align operands. This cannot be done
			 * unless the low bits match.
			 */
			if ((t ^ (int)dst) & wmask || n < wsize)
				t = n;
			else
				t = wsize - (t & wmask);
			n -= t;
			do
				*dst++ = *src++;
			while(--t);
		}
		/*
		 * Copy whole words, then mop up any trailing bytes.
		 */
		t = n / wsize;
		/*if(t)
			do {
				*(unsigned int *)dst = *(unsigned int *)src;
				src += wsize;
				dst += wsize;
			} while(--t);*/
		while(t--) {
			*(unsigned int *)dst = *(unsigned int *)src;
			src += wsize;
			dst += wsize;
		}
		t = n & wmask;
		/*if(t)
			do
				*dst++ = *src++;
			while(--t);*/
		while(t--)
			*dst++ = *src++;
	} else {
		/*
		 * Copy backwards. Otherwise essentially the same.
		 * Alignment works as before, except that it takes
		 * (t&wmask) bytes to align, not wsize-(t&wmask).
		 */
		src += n;
		dst += n;
		t = (int)src;
		if ((t | (int)dst) & wmask) {
			if ((t ^ (int)dst) & wmask || n <= wsize)
				t = n;
			else
				t &= wmask;
			n -= t;
			do
				*--dst = *--src;
			while(--t);
		}
		t = n / wsize;
		/*if(t)
			do {
				src -= wsize;
				dst -= wsize;
				*(unsigned int *)dst = *(unsigned int *)src;
			} while(--t);*/
		while(t--) {
			src -= wsize;
			dst -= wsize;
			*(unsigned int *)dst = *(unsigned int *)src;
		}
		t = n & wmask;
		/*if(t)
			do
				*--dst = *--src;
			while(--t);*/
		while(t--)
			*--dst = *--src;
	}
	return(m1);
}

#endif	/*MSDOS*/

int cdecl
#ifdef	ANSI
memcmp(const void *m1, const void *m2, size_t n)
#else
memcmp(m1, m2, n)
register void *m1, *m2;
size_t n;
#endif
{
	register const unsigned char *s1 = m1, *s2 = m2;

	if(in_db == 0) {
		register size_t size;

		if((m1 == NULL) || (m2 == NULL)) {
			_error(NULL, 0, NULL, "Attempt to memcmp NULL");
			return(0);
		}
		if((n == 0) || (m1 == m2)) {	/* nothing to do */
			_error(NULL, 0, NULL, "memcmp: %s (no affect)", (n == 0) ? "n == 0" : "m1 == m2");
			return(0);
		}
		size = blklen(m1, false);
		if(n > size) {
			_error(NULL, 0, NULL, "Attempt to memcmp arg1 %u for %u bytes", size, n);
			return(0);
		}
		size = blklen(m2, false);
		if(n > size) {
			_error(NULL, 0, NULL, "Attempt to memcmp arg2 %u for %u bytes", size, n);
			return(0);
		}
	}
	/*
	 * We know n >= 1 because of the above test and because memcmp
	 * isn't called from within this package, so do while is better
	 */
	do
		if(*s1++ != *s2++)
			return(*--s1 - *--s2);
	while(--n);
	return(0);
}

#endif	/*DBMALLOC*/

#else	/*!NJH_DEBUG*/

char *pascal
db_strdupchk(string, file, line)	/* like strdup */
const char *string, *file;
{
	register char *area;

	if(string == NULL) {
		errstring = "Attempt to strdup NULL";
		return(NULL);
	}
	lastfreed = NULL;

#ifdef	PP2WIN
	area = db_mallocchk(strlen(string) + 1, file, line);
	if(area == NULL)
		return((char *)NULL);
	return(strcpy(area, string));
#else
	if(area = strdup(string))
		return(area);
	remove_urgent();
#ifdef	MSDOS
	_heapmin();
#endif
	if(area = strdup(string))
		return(area);
	if(errstring == (char *)NULL)
		errstring = MEM;
	return((char *)NULL);
#endif	/*PP2WIN*/
}
#endif

void pascal
db_freechk(memblock, file, line)
void *memblock;
const char *file;
int line;
{
	if(memblock) {
		if(memblock == lastfreed) {
			_error(file, line, NULL, "Attempt to refree pointer");
			return;
		}
#ifdef	NJH_DEBUG
		_free(memblock, file, line);
#else
#ifdef	PP2WIN
		rhpfree(memblock);
#else
		free(memblock);
#endif
#endif
		lastfreed = memblock;
	} else
		_error(file, line, NULL, "Attempt to free NULL pointer");
}

#if	defined(unix) || defined(_HPUX_SOURCE) || defined(UNIX)

/* write around for DOS alloca: NJH call mallocchk and freechk */
/* alloca.c -- allocate automatically reclaimed memory
   (Mostly) portable public-domain implementation -- D A Gwyn

   This implementation of the PWB library alloca function,
   which is used to allocate space off the run-time stack so
   that it is automatically reclaimed upon procedure exit,
   was inspired by discussions with J. Q. Johnson of Cornell.
   J.Otto Tennant <jot@cray.com> contributed the Cray support.

   There are some preprocessor constants that can
   be defined when compiling for your specific system, for
   improved efficiency; however, the defaults should be okay.

   The general concept of this implementation is to keep
   track of all alloca-allocated blocks, and reclaim any
   that are found to be deeper in the stack than the current
   invocation.  This heuristic does not reclaim storage as
   soon as it becomes invalid, but it will do so eventually.

   As a special case, alloca(0) reclaims storage without
   allocating any.  It is a good idea to use alloca(0) in
   your main control loop, etc. to force garbage collection.  */

/*#ifdef HAVE_CONFIG_H*/
#if	0
#if defined (emacs) || defined (CONFIG_BROKETS)
#include <config.h>
#else
#include "config.h"
#endif
#endif

/* If someone has defined alloca as a macro,
   there must be some other way alloca is supposed to work.  */
#ifndef alloca

#ifdef emacs
#ifdef static
/* actually, only want this if static is defined as ""
   -- this is for usg, in which emacs must undefine static
   in order to make unexec workable
   */
#ifndef STACK_DIRECTION
you
lose
-- must know STACK_DIRECTION at compile-time
#endif /* STACK_DIRECTION undefined */
#endif /* static */
#endif /* emacs */

/* If your stack is a linked list of frames, you have to
   provide an "address metric" ADDRESS_FUNCTION macro.  */

#if defined (CRAY) && defined (CRAY_STACKSEG_END)
long i00afunc ();
#define ADDRESS_FUNCTION(arg) (char *) i00afunc (&(arg))
#else
#define ADDRESS_FUNCTION(arg) &(arg)
#endif

#if __STDC__
typedef void *pointer;
#else
typedef char *pointer;
#endif

#ifndef	NULL
#define	NULL	0
#endif

/* Different portions of Emacs need to call different versions of
   malloc.  The Emacs executable needs alloca to call xmalloc, because
   ordinary malloc isn't protected from input signals.  On the other
   hand, the utilities in lib-src need alloca to call malloc; some of
   them are very simple, and don't have an xmalloc routine.

   Non-Emacs programs expect this to call use xmalloc.

   Callers below should use malloc.  */

#ifndef emacs
/* #define malloc xmalloc */
#endif

/* Define STACK_DIRECTION if you know the direction of stack
   growth for your system; otherwise it will be automatically
   deduced at run-time.

   STACK_DIRECTION > 0 => grows toward higher addresses
   STACK_DIRECTION < 0 => grows toward lower addresses
   STACK_DIRECTION = 0 => direction of growth unknown  */

#ifndef STACK_DIRECTION
#define	STACK_DIRECTION	0	/* Direction unknown.  */
#endif

#if STACK_DIRECTION != 0

#define	STACK_DIR	STACK_DIRECTION	/* Known at compile-time.  */

#else /* STACK_DIRECTION == 0; need run-time code.  */

static int stack_dir;		/* 1 or -1 once known.  */
#define	STACK_DIR	stack_dir

static void
find_stack_direction ()
{
  static char *addr = NULL;	/* Address of first `dummy', once known.  */
  auto char dummy;		/* To get stack address.  */

  if (addr == NULL)
    {				/* Initial entry.  */
      addr = ADDRESS_FUNCTION (dummy);

      find_stack_direction ();	/* Recurse once.  */
    }
  else
    {
	/* Second entry.  */
      if (ADDRESS_FUNCTION (dummy) > addr)
	stack_dir = 1;		/* Stack grew upward.  */
      else
	stack_dir = -1;		/* Stack grew downward.  */
    }
}

#endif /* STACK_DIRECTION == 0 */

/* An "alloca header" is used to:
   (a) chain together all alloca'ed blocks;
   (b) keep track of stack depth.

   It is very important that sizeof(header) agree with malloc
   alignment chunk size.  The following default should work okay.  */

#ifndef	ALIGN_SIZE
#define	ALIGN_SIZE	sizeof(double)
#endif

typedef union hdr
{
  char align[ALIGN_SIZE];	/* To force sizeof(header).  */
  struct
    {
      union hdr *next;		/* For chaining headers.  */
      char *deep;		/* For stack depth measure.  */
    } h;
} header;

static header *last_alloca_header = NULL;	/* -> last alloca header.  */

/* Return a pointer to at least SIZE bytes of storage,
   which will be automatically reclaimed upon exit from
   the procedure that called alloca.  Originally, this space
   was supposed to be taken from the current stack frame of the
   caller, but that method cannot be made to work for some
   implementations of C, for example under Gould's UTX/32.  */

void *pascal
alloca(size)
size_t size;
{
	return(db_alloca(size, NULL, 0));
}

void *pascal
db_alloca(size, file, line)
size_t size;
const char *file;
int line;
{
  auto char probe;		/* Probes stack depth: */
  register char *depth = ADDRESS_FUNCTION (probe);

#if STACK_DIRECTION == 0
  if (STACK_DIR == 0)		/* Unknown growth direction.  */
    find_stack_direction ();
#endif

  /* Reclaim garbage, defined as all alloca'd storage that
     was allocated from deeper in the stack than currently. */

  {
    register header *hp;	/* Traverses linked list.  */

    for (hp = last_alloca_header; hp != NULL;)
      if ((STACK_DIR > 0 && hp->h.deep > depth)
	  || (STACK_DIR < 0 && hp->h.deep < depth))
	{
	  register header *np = hp->h.next;

	  db_freechk ((pointer) hp, file, line);	/* Collect garbage.  */

	  hp = np;		/* -> next header.  */
	}
      else
	break;			/* Rest are not deeper.  */

    last_alloca_header = hp;	/* -> last valid storage.  */
  }

  if (size == 0)
    return NULL;		/* No allocation required.  */

  /* Allocate combined header + user data storage.  */

  {
#ifdef	NJH_DEBUG
    register pointer new = db_mallocchk (sizeof (header) + size, file, line);
#else
    register pointer new = mallocchk (sizeof (header) + size);
#endif
    /* Address of header.  */

    ((header *) new)->h.next = last_alloca_header;
    ((header *) new)->h.deep = depth;

    last_alloca_header = (header *) new;

    /* User storage begins just after header.  */

    return (pointer) ((char *) new + sizeof (header));
  }
}

#if defined (CRAY) && defined (CRAY_STACKSEG_END)

#ifdef DEBUG_I00AFUNC
#include <stdio.h>
#endif

#ifndef CRAY_STACK
#define CRAY_STACK
#ifndef CRAY2
/* Stack structures for CRAY-1, CRAY X-MP, and CRAY Y-MP */
struct stack_control_header
  {
    long shgrow:32;		/* Number of times stack has grown.  */
    long shaseg:32;		/* Size of increments to stack.  */
    long shhwm:32;		/* High water mark of stack.  */
    long shsize:32;		/* Current size of stack (all segments).  */
  };

/* The stack segment linkage control information occurs at
   the high-address end of a stack segment.  (The stack
   grows from low addresses to high addresses.)  The initial
   part of the stack segment linkage control information is
   0200 (octal) words.  This provides for register storage
   for the routine which overflows the stack.  */

struct stack_segment_linkage
  {
    long ss[0200];		/* 0200 overflow words.  */
    long sssize:32;		/* Number of words in this segment.  */
    long ssbase:32;		/* Offset to stack base.  */
    long:32;
    long sspseg:32;		/* Offset to linkage control of previous
				   segment of stack.  */
    long:32;
    long sstcpt:32;		/* Pointer to task common address block.  */
    long sscsnm;		/* Private control structure number for
				   microtasking.  */
    long ssusr1;		/* Reserved for user.  */
    long ssusr2;		/* Reserved for user.  */
    long sstpid;		/* Process ID for pid based multi-tasking.  */
    long ssgvup;		/* Pointer to multitasking thread giveup.  */
    long sscray[7];		/* Reserved for Cray Research.  */
    long ssa0;
    long ssa1;
    long ssa2;
    long ssa3;
    long ssa4;
    long ssa5;
    long ssa6;
    long ssa7;
    long sss0;
    long sss1;
    long sss2;
    long sss3;
    long sss4;
    long sss5;
    long sss6;
    long sss7;
  };

#else /* CRAY2 */
/* The following structure defines the vector of words
   returned by the STKSTAT library routine.  */
struct stk_stat
  {
    long now;			/* Current total stack size.  */
    long maxc;			/* Amount of contiguous space which would
				   be required to satisfy the maximum
				   stack demand to date.  */
    long high_water;		/* Stack high-water mark.  */
    long overflows;		/* Number of stack overflow ($STKOFEN) calls.  */
    long hits;			/* Number of internal buffer hits.  */
    long extends;		/* Number of block extensions.  */
    long stko_mallocs;		/* Block allocations by $STKOFEN.  */
    long underflows;		/* Number of stack underflow calls ($STKRETN).  */
    long stko_free;		/* Number of deallocations by $STKRETN.  */
    long stkm_free;		/* Number of deallocations by $STKMRET.  */
    long segments;		/* Current number of stack segments.  */
    long maxs;			/* Maximum number of stack segments so far.  */
    long pad_size;		/* Stack pad size.  */
    long current_address;	/* Current stack segment address.  */
    long current_size;		/* Current stack segment size.  This
				   number is actually corrupted by STKSTAT to
				   include the fifteen word trailer area.  */
    long initial_address;	/* Address of initial segment.  */
    long initial_size;		/* Size of initial segment.  */
  };

/* The following structure describes the data structure which trails
   any stack segment.  I think that the description in 'asdef' is
   out of date.  I only describe the parts that I am sure about.  */

struct stk_trailer
  {
    long this_address;		/* Address of this block.  */
    long this_size;		/* Size of this block (does not include
				   this trailer).  */
    long unknown2;
    long unknown3;
    long link;			/* Address of trailer block of previous
				   segment.  */
    long unknown5;
    long unknown6;
    long unknown7;
    long unknown8;
    long unknown9;
    long unknown10;
    long unknown11;
    long unknown12;
    long unknown13;
    long unknown14;
  };

#endif /* CRAY2 */
#endif /* not CRAY_STACK */

#ifdef CRAY2
/* Determine a "stack measure" for an arbitrary ADDRESS.
   I doubt that "lint" will like this much. */

static long
i00afunc (long *address)
{
  struct stk_stat status;
  struct stk_trailer *trailer;
  long *block, size;
  long result = 0;

  /* We want to iterate through all of the segments.  The first
     step is to get the stack status structure.  We could do this
     more quickly and more directly, perhaps, by referencing the
     $LM00 common block, but I know that this works.  */

  STKSTAT (&status);

  /* Set up the iteration.  */

  trailer = (struct stk_trailer *) (status.current_address
				    + status.current_size
				    - 15);

  /* There must be at least one stack segment.  Therefore it is
     a fatal error if "trailer" is null.  */

  if (trailer == 0)
    abort ();

  /* Discard segments that do not contain our argument address.  */

  while (trailer != 0)
    {
      block = (long *) trailer->this_address;
      size = trailer->this_size;
      if (block == 0 || size == 0)
	abort ();
      trailer = (struct stk_trailer *) trailer->link;
      if ((block <= address) && (address < (block + size)))
	break;
    }

  /* Set the result to the offset in this segment and add the sizes
     of all predecessor segments.  */

  result = address - block;

  if (trailer == 0)
    {
      return result;
    }

  do
    {
      if (trailer->this_size <= 0)
	abort ();
      result += trailer->this_size;
      trailer = (struct stk_trailer *) trailer->link;
    }
  while (trailer != 0);

  /* We are done.  Note that if you present a bogus address (one
     not in any segment), you will get a different number back, formed
     from subtracting the address of the first block.  This is probably
     not what you want.  */

  return (result);
}

#else /* not CRAY2 */
/* Stack address function for a CRAY-1, CRAY X-MP, or CRAY Y-MP.
   Determine the number of the cell within the stack,
   given the address of the cell.  The purpose of this
   routine is to linearize, in some sense, stack addresses
   for alloca.  */

static long
i00afunc (long address)
{
  long stkl = 0;

  long size, pseg, this_segment, stack;
  long result = 0;

  struct stack_segment_linkage *ssptr;

  /* Register B67 contains the address of the end of the
     current stack segment.  If you (as a subprogram) store
     your registers on the stack and find that you are past
     the contents of B67, you have overflowed the segment.

     B67 also points to the stack segment linkage control
     area, which is what we are really interested in.  */

  stkl = CRAY_STACKSEG_END ();
  ssptr = (struct stack_segment_linkage *) stkl;

  /* If one subtracts 'size' from the end of the segment,
     one has the address of the first word of the segment.

     If this is not the first segment, 'pseg' will be
     nonzero.  */

  pseg = ssptr->sspseg;
  size = ssptr->sssize;

  this_segment = stkl - size;

  /* It is possible that calling this routine itself caused
     a stack overflow.  Discard stack segments which do not
     contain the target address.  */

  while (!(this_segment <= address && address <= stkl))
    {
#ifdef DEBUG_I00AFUNC
	fprintf (stderr, "%011o %011o %011o\n", this_segment, address, stkl);
#endif
      if (pseg == 0)
	break;
      stkl = stkl - pseg;
      ssptr = (struct stack_segment_linkage *) stkl;
      size = ssptr->sssize;
      pseg = ssptr->sspseg;
      this_segment = stkl - size;
    }

  result = address - this_segment;

  /* If you subtract pseg from the current end of the stack,
     you get the address of the previous stack segment's end.
     This seems a little convoluted to me, but I'll bet you save
     a cycle somewhere.  */

  while (pseg != 0)
    {
#ifdef DEBUG_I00AFUNC
	fprintf (stderr, "%011o %011o\n", pseg, size);
#endif
      stkl = stkl - pseg;
      ssptr = (struct stack_segment_linkage *) stkl;
      size = ssptr->sssize;
      pseg = ssptr->sspseg;
      result += size;
    }
  return (result);
}

#endif /* not CRAY2 */
#endif /* CRAY */

#endif /* no alloca */

#endif	/*UNIX*/

#undef	memcpy
#undef	malloc
#undef	calloc
#undef	realloc
#undef	free
#undef	strdup

/*
 * Stubs to force calls of our code which call rhpfree etc.
 * rhpaca and rhpfree call better windows routines and yield
 */
#ifdef	ANSI
void *cdecl
memcpy(register void *m1, register const void *m2, size_t n)
#else
char *cdecl
memcpy(m1, m2, n)
register char *m1, *m2;
size_t n;
#endif
{
	/*return(db_memcpy(m1, m2, n, __FILE__, __LINE__));*/
	return(db_memcpy(m1, m2, n, NULL, 0));
}

#ifdef	ANSI
void * cdecl
malloc(size_t size)
#else
char *cdecl
malloc(size)
size_t size;
#endif
{
	return(db_mallocchk(size, NULL, 0));
}

#ifdef	ANSI
void *cdecl
calloc(size_t nelem, size_t size)
#else
char *cdecl
calloc(nelem, size)
size_t nelem, size;
#endif
{
	return(db_callocchk(nelem, size, NULL, 0));
}

#ifdef	ANSI
void *cdecl
realloc(void *oarea, size_t size)
#else
char *
realloc(oarea, size)
void *oarea;
size_t size;
#endif
{
	return(db_reallocchk(oarea, size, NULL, 0));
}

#ifndef NJH_DEBUG
char * cdecl
strdup(const char *string)
{
	return(db_strdupchk(string, NULL, 0));
}
#endif

#ifdef	ANSI
void cdecl
free(void *memblock)
#else
#ifndef	sun
void
#endif
free(memblock)
char *memblock;
#endif
{
	db_freechk(memblock, NULL, 0);
}

#ifndef	MSDOS
static	char	*exec_name;

void
db_setname(progname)
const char *progname;
{
	if(exec_name)
		db_freechk(exec_name, NULL, 0);
	exec_name = db_strdupchk(progname, NULL, 0);
}
#endif

static void cdecl
#ifdef	ANSI
leaks(void)
#else
leaks()
#endif
{
	unsigned long leaks = 0L;
	register int i;
#ifdef	CACHE_TRACE
	register const struct cache *c;

	for(c = cache, i = 0; i < CACHE_SIZE; c++, i++)
		printf("cache %d: %d/%d\n", i, c->hits, c->misses);
#endif

	if(check_for_leaks && slotc) {
#ifdef	MSDOS
		register SLOT const huge *sp;
#else
		register SLOT const *sp;
#endif
		register int count = 0;

#ifdef	WATCH
		if(watchfd >= 0) {
			close(watchfd);
			watchfd = -1;
		}
#endif

		db_heapchk(NULL, 0);

#ifdef	UNIX
		db_alloca(0, __FILE__, __LINE__);
#endif

#ifdef	MAX_STACK_DEPTH
		st_read();
#endif

		if(in_db++)
			/*
			 * This can occur if a signal such as SIGINT
			 * is caught and the handler calls exit if the
			 * interrupt happens when in_db is set
			 */
			fputs("Warning: Unexpected check for leaks call\n", stderr);

		for(sp = slots; sp != &slots[slotc]; sp++)
			if((!sp->s_freed) && sp->s_size) {
				count++;
				leaks += sp->s_size;
#ifdef	MSDOS
				if(sp->s_file && (_fstrcmp(sp->s_file, __FILE__) == 0) && (sp->s_line == strdupline))
#else
				if(sp->s_file && (strcmp(sp->s_file, __FILE__) == 0) && (sp->s_line == strdupline))
#endif
#ifdef	MAX_STACK_DEPTH
					_error(NULL, 0L, sp->s_history, "unfree strdup: \"%s\"", (const char *)sp->s_ptr);
#else
					_error(NULL, 0L, NULL, "unfree strdup: \"%s\"", (const char *)sp->s_ptr);
#endif
				else
					_error(sp->s_file, sp->s_line, NULL, "unfree memory %u bytes", sp->s_size);
			}
#ifdef	MAX_STACK_DEPTH
			else if(exec_name && sp->s_history[0])
				_error(NULL, 0, sp->s_history, "unfree memory %u bytes", sp->s_size);
#endif
		if(leaks)
			fprintf(stderr, "Summary:\n\t%lu bytes in %d memory leak%c\n",
				leaks, count, (count == 1) ? ' ' : 's');
		count = 0;
		for(i = 0; i < _NFILE; i++)
			if((lseek(i, 0, SEEK_CUR) >= 0) || (errno != EBADF))
				if(!fds[i]) {
#ifdef	MSDOS
					fprintf(stderr, "leaked file descriptor %d\n", i);
#else
					int flags = 0, ispipe;

					if(fcntl(i, F_GETFL, &flags) < 0)
						perror("fcntl");
					fputs("leaked ", stderr);
					switch(flags & 3) {
						case O_RDONLY:
							fputs("read ", stderr);
							break;
						case O_WRONLY:
							fputs("write ", stderr);
							break;
						case O_RDWR:
							fputs("read/write ", stderr);
							break;
					}
					ispipe = ((lseek(i, 0, SEEK_CUR) < 0) && (errno == ESPIPE));
					if(ispipe)
						fputs("pipe ", stderr);
					else if(flags & O_APPEND)
						fputs("append ", stderr);
					fprintf(stderr, "file descriptor %d ", i);
#ifdef	__BEOS__
					putchar('\n');
#else
					if(ispipe)
						putchar('\n');
					else {
						struct stat statb;

						if(fstat(i, &statb) < 0)
							perror("fstat");
						fprintf(stderr, "to inode %d\n", (int)statb.st_ino);
						fprintf(stderr, "to inode %d on device %d/%d\n", (int)statb.st_ino, (int)major(statb.st_dev), (int)minor(statb.st_dev));
					}
#endif
#endif
					count++;
				}
		if(count > 1)
			fprintf(stderr, "%d file descriptor leaks\n", count);
		check_for_leaks = false;
		in_db--;
	}
}

#ifndef	MSDOS

#define RCHECK

/*
 * Copyright (c) 1983 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *	notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *	notice, this list of conditions and the following disclaimer in the
 *	documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *	must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *	may be used to endorse or promote products derived from this software
 *	without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#if defined(LIBC_SCCS) && !defined(lint)
// static char sccsid[] = "@(#)malloc.c 5.11 (Berkeley) 2/23/91";
#endif /* LIBC_SCCS and not lint */

/*
 * malloc.c (Caltech) 2/21/82
 * Chris Kingsley, kingsley@cit-20.
 *
 * This is a very fast storage allocator. It allocates blocks of a small
 * number of different sizes, and keeps free lists of each size. Blocks that
 * don't exactly fit are passed up to the next larger size. In this
 * implementation, the available sizes are 2^n-4 (or 2^n-10) bytes long.
 * This is designed for use in a virtual memory environment.
 */

#include <sys/types.h>
/* #include <stdlib.h>
   #include <string.h>
   #include <unistd.h> */

#ifndef NULL
#define NULL 0
#endif

static void morecore();
static int findbucket();

/*
 * The overhead on a block is at least 4 bytes. When free, this space
 * contains a pointer to the next free block, and the bottom two bits must
 * be zero. When in use, the first byte is set to MAGIC, and the second
 * byte is the size index. The remaining bytes are for alignment.
 * If range checking is enabled then a second word holds the size of the
 * requested block, less 1, rounded up to a multiple of sizeof(RMAGIC).
 * The order of elements is critical: ov_magic must overlay the low order
 * bits of ov_next, and ov_magic can not be a valid ov_next bit pattern.
 */
union	overhead {
	union	overhead *ov_next;	/* when free */
	struct {
		unsigned char	ovu_magic;	/* magic number */
		unsigned char	ovu_index;	/* bucket # */
#ifdef RCHECK
		unsigned short	ovu_rmagic;	/* range magic number */
		unsigned int	ovu_size;	/* actual block size */
#endif
	} ovu;
#define ov_magic	ovu.ovu_magic
#define ov_index	ovu.ovu_index
#define ov_rmagic	ovu.ovu_rmagic
#define ov_size		ovu.ovu_size
};

#define MAGIC	0xef	/* magic # on accounting info */
#define RMAGIC	0x5555	/* magic # on range info */

#ifdef RCHECK
#define RSLOP	sizeof (unsigned short)
#else
#define RSLOP	0
#endif

/*
 * nextf[i] is the pointer to the next free block of size 2^(i+3). The
 * smallest allocatable block is 8 bytes. The overhead information
 * precedes the data area returned to the user.
 */
#define NBUCKETS 30
static	union overhead *nextf[NBUCKETS];
#if	defined(_HPUX_SOURCE) || defined(solaris) || defined(AIX) || defined(LINUX)
extern	void *sbrk();
#else
extern	char *sbrk();
#endif

static	int pagebucket;	/* page size bucket */

#ifdef MSTATS
/*
 * nmalloc[i] is the difference between the number of mallocs and frees
 * for a given block size.
 */
static	unsigned int nmalloc[NBUCKETS];
#include <stdio.h>
#endif

#if defined(DEBUG) || defined(RCHECK)
#define ASSERT(p)	if (!(p)) botch("p")
/* #include <stdio.h> */
static void
#ifdef	ANSI
botch(const char *s)
#else
botch(s)
char *s;
#endif
{
	/* fprintf(stderr, "\r\nassertion botched: %s\r\n", s); */
	_error(NULL, 0, NULL, "\r\nassertion botched: %s\r", s);
	(void) fflush(stderr);	/* just in case user buffered it */
	abort();
}
#else
#define ASSERT(p)
#endif

#if	defined(MAP_ANONYMOUS) && defined(MPROTECT)
static void *
#ifdef	ANSI
grab_mem(size_t size)
#else
grab_mem(size)
size_t size;
#endif
{
	static caddr_t	startAddr;

	caddr_t	allocation = (caddr_t) mmap(
		 startAddr
		,(int)size
		,PROT_READ|PROT_WRITE
		,MAP_PRIVATE|MAP_ANONYMOUS
		,-1
		,0);

	if ( allocation == (caddr_t)-1 ) {
		_error(NULL, 0, NULL, "mmap failed - using sbrk");
		return(sbrk(size));
	}

#ifndef	__hpux
	/*
	 * Set the "address hint" for the next mmap() so that it will abut
	 * the mapping we just created.
	 *
	 * HP/UX 9.01 has a kernel bug that makes mmap() fail sometimes
	 * when given a non-zero address hint, so we'll leave the hint set
	 * to zero on that system. HP recently told me this is now fixed.
	 * Someone please tell me when it is probable to assume that most
	 * of those systems that were running 9.01 have been upgraded.
	 */
	startAddr = allocation + size;
#endif

	return((void *)allocation);
}
#else
static void *
grab_mem(size)
size_t size;
{
	return(sbrk(size));
}
#endif

#ifdef	ANSI
static void *
real_malloc(size_t nbytes)
#else
static char *
real_malloc(nbytes)
size_t nbytes;
#endif
{
	register union overhead *op;
	register int bucket, n;
	register unsigned amt;

	/*
	 * First time malloc is called, setup page size and
	 * align break pointer so all data will be page aligned.
	 */
	if (pagesz == 0) {
#if	defined(sun) || defined(AIX)
		pagesz = n = getpagesize();
#else
		pagesz = n = 4096;
#endif
		op = (union overhead *)sbrk(0);
		n = n - sizeof (*op) - ((int)op & (n - 1));
		if (n < 0)
			n += pagesz;
		if (n) {
			if (grab_mem(n) == (char *)-1)
				return (NULL);
		}
		bucket = 0;
		amt = 8;
		while (pagesz > amt) {
			amt <<= 1;
			bucket++;
		}
		pagebucket = bucket;
	}
	/*
	 * Convert amount of memory requested into closest block size
	 * stored in hash buckets which satisfies request.
	 * Account for space used per block for accounting.
	 */
	if (nbytes <= (n = pagesz - sizeof (*op) - RSLOP)) {
#ifndef RCHECK
		amt = 8;	/* size of first bucket */
		bucket = 0;
#else
		amt = 16;	/* size of first bucket */
		bucket = 1;
#endif
		n = -(sizeof (*op) + RSLOP);
	} else {
		amt = pagesz;
		bucket = pagebucket;
	}
	while (nbytes > amt + n) {
		amt <<= 1;
		if (amt == 0)
			return (NULL);
		bucket++;
	}
	/*
	 * If nothing in hash bucket right now,
	 * request more memory from the system.
	 */
	if ((op = nextf[bucket]) == NULL) {
		morecore(bucket);
		if ((op = nextf[bucket]) == NULL)
			return (NULL);
	}
	/* remove from linked list */
	nextf[bucket] = op->ov_next;
	op->ov_magic = MAGIC;
	op->ov_index = (unsigned char)bucket;
#ifdef MSTATS
	nmalloc[bucket]++;
#endif
#ifdef RCHECK
	/*
	 * Record allocated size of block and
	 * bound space with magic numbers.
	 */
	op->ov_size = (nbytes + RSLOP - 1) & ~(RSLOP - 1);
	op->ov_rmagic = RMAGIC;
	rw((caddr_t)(op + 1), op->ov_size + 1);

	*(unsigned short *)((caddr_t)(op + 1) + op->ov_size) = RMAGIC;
#endif
	return ((char *)(op + 1));
}

/*
 * Allocate more memory to the indicated bucket.
 */
static void
morecore(bucket)
int bucket;
{
	register union overhead *op;
	register int sz;	/* size of desired block */
	int amt;	/* amount to allocate */
	int nblks;	/* how many blocks we get */

	/*
	 * sbrk_size <= 0 only for big, FLUFFY, requests (about
	 * 2^30 bytes on a VAX, I think) or for a negative arg.
	 */
	sz = 1 << (bucket + 3);
#ifdef DEBUG
	ASSERT(sz > 0);
#else
	if (sz <= 0)
		return;
#endif
	ASSERT(pagesz > 0);

	if (sz < pagesz) {
		amt = pagesz;
		nblks = amt / sz;
	} else {
		amt = sz + pagesz;
		nblks = 1;
	}
#ifdef	MPROTECT
	op = (union overhead *)grab_mem(amt + sz);	/* 2.1.2 fix */
#else
	op = (union overhead *)grab_mem(amt);
#endif
	/* no more room! */
	if ((int)op == -1)
		return;
	/*
	 * Add new memory allocated to that on
	 * free list for this hash bucket.
	 */
	nextf[bucket] = op;

	while (--nblks > 0) {
		op->ov_next = (union overhead *)((caddr_t)op + sz);
		op = (union overhead *)((caddr_t)op + sz);
	}
}

static void
#ifdef	ANSI
real_free(void *cp)
#else
real_free(cp)
void *cp;
#endif
{
	register int size;
	register union overhead *op;

	if (cp == NULL)
		return;
	op = (union overhead *)((caddr_t)cp - sizeof (union overhead));
#ifdef DEBUG
	ASSERT(op->ov_magic == MAGIC);	/* make sure it was in use */
#else
	if (op->ov_magic != MAGIC)
		return;	/* sanity */
#endif
#ifdef RCHECK
	ASSERT(op->ov_rmagic == RMAGIC);
	ASSERT(*(unsigned short *)((caddr_t)(op + 1) + op->ov_size) == RMAGIC);
#endif
	size = op->ov_index;
	ASSERT(size < NBUCKETS);
	op->ov_next = nextf[size];	/* also clobbers ov_magic */
	nextf[size] = op;
#ifdef MSTATS
	nmalloc[size]--;
#endif
}

/*
 * When a program attempts "storage compaction" as mentioned in the
 * old malloc man page, it realloc's an already freed block. Usually
 * this is the last block it freed; occasionally it might be farther
 * back. We have to search all the free lists for the block in order
 * to determine its bucket: 1st we make one pass thru the lists
 * checking only the first block in each; if that fails we search
 * ``realloc_srchlen'' blocks in each list for a match (the variable
 * is extern so the caller can modify it). If that fails we just copy
 * however many bytes was given to realloc() and hope it's not huge.
 */
#define	realloc_srchlen 4	/* 4 should be plenty, -1 =>'s whole list */

#ifdef	ANSI
static void *
real_realloc(void *cp, size_t nbytes)
#else
static char *
real_realloc(cp, nbytes)
char *cp;
size_t nbytes;
#endif
{
	register unsigned int onb;
	register int i;
	union overhead *op;
	char *res;
	int was_alloced = 0;

	if (cp == NULL)
		return (real_malloc(nbytes));
	op = (union overhead *)((caddr_t)cp - sizeof (union overhead));
	if (op->ov_magic == MAGIC) {
		was_alloced++;
		i = op->ov_index;
	} else {
		/*
		 * Already free, doing "compaction".
		 *
		 * Search for the old block of memory on the
		 * free list. First, check the most common
		 * case (last element free'd), then (this failing)
		 * the last ``realloc_srchlen'' items free'd.
		 * If all lookups fail, then assume the size of
		 * the memory block being realloc'd is the
		 * largest possible (so that all "nbytes" of new
		 * memory are copied into). Note that this could cause
		 * a memory fault if the old area was tiny, and the moon
		 * is gibbous. However, that is very unlikely.
		 */
		if ((i = findbucket(op, 1)) < 0 &&
		    (i = findbucket(op, realloc_srchlen)) < 0)
			i = NBUCKETS;
	}
	onb = 1 << (i + 3);
	if (onb < pagesz)
		onb -= sizeof (*op) + RSLOP;
	else
		onb += pagesz - sizeof (*op) - RSLOP;
	/* avoid the copy if same size block */
	if (was_alloced) {
		if (i) {
			i = 1 << (i + 2);
			if (i < pagesz)
				i -= sizeof (*op) + RSLOP;
			else
				i += pagesz - sizeof (*op) - RSLOP;
		}
		if (nbytes <= onb && nbytes > i) {
#ifdef RCHECK
			op->ov_size = (nbytes + RSLOP - 1) & ~(RSLOP - 1);
			*(unsigned short *)((caddr_t)(op + 1) + op->ov_size) = RMAGIC;
#endif
			return(cp);
		} else
			real_free(cp);
	}
	if ((res = real_malloc(nbytes)) == NULL)
		return (NULL);
	if (cp != res)	/* common optimization if "compacting" */
		return(real_memcpy(res, cp, (nbytes < onb) ? nbytes : onb));
	return (res);
}

/*
 * Search ``srchlen'' elements of each free list for a block whose
 * header starts at ``freep''. If srchlen is -1 search the whole list.
 * Return bucket number, or -1 if not found.
 */
static int
findbucket(freep, srchlen)
union overhead *freep;
int srchlen;
{
	register int i, j;

	for (i = 0; i < NBUCKETS; i++) {
		register union overhead *p;

		j = 0;
		for (p = nextf[i]; p && j != srchlen; p = p->ov_next) {
			if (p == freep)
				return (i);
			j++;
		}
	}
	return (-1);
}

#ifdef MSTATS
/*
 * mstats - print out statistics about malloc
 *
 * Prints two lines of numbers, one showing the length of the free list
 * for each size category, the second showing the number of mallocs -
 * frees for each size category.
 */
mstats(s)
char *s;
{
	register int i, j;
	register union overhead *p;
	int totfree = 0,
	totused = 0;

	fprintf(stderr, "Memory allocation statistics %s\nfree:\t", s);
	for (i = 0; i < NBUCKETS; i++) {
		for (j = 0, p = nextf[i]; p; p = p->ov_next, j++)
			;
		fprintf(stderr, " %d", j);
		totfree += j * (1 << (i + 3));
	}
	fputs("\nused:\t", stderr);
	for (i = 0; i < NBUCKETS; i++) {
		fprintf(stderr, " %d", nmalloc[i]);
		totused += nmalloc[i] * (1 << (i + 3));
	}
	fprintf(stderr, "\n\tTotal in use: %d, total free: %d\n",
	   totused, totfree);
}
#endif	/* MSTATS */
#endif	/* UNIX */

#ifdef	UNIX

#define	tst(a,b) (*mode == 'r' ? (b) : (a))
#define	RDR	0
#define	WTR	1

extern FILE *fdopen();

#ifndef	NOFILES_MIN
#ifdef	NOFILE
#define	NOFILES_MIN	NOFILE
#elif	defined(_NFILE)
#define	NOFILES_MIN	_NFILE
#elif	defined(OPEN_MAX)
#define	NOFILES_MIN	OPEN_MAX
#else
#define	NOFILES_MIN	20
#endif
#endif

#ifndef	OPEN_MAX
#define	OPEN_MAX	64
#endif

static pid_t popen_pid[NOFILES_MIN];

static void
execshell(cmd)
const char *cmd;
{
	register const char *shell;

	if(strpbrk(cmd, " =?*[|&$<>") == (char *)NULL) {
		(void)execl(cmd, cmd, (char *)0);
		(void)execlp(cmd, cmd, (char *)0);
	}
	shell = getenv("SHELL");
	(void) execl((shell) ? shell : "/bin/sh", "sh", "-c", cmd, (char *)0);
}

#ifndef	PERPOS
#define	WAITPID
#endif

FILE *
popen(cmd, mode)
const char *cmd, *mode;
{
	register pid_t *poptr, pid;
	register int myside, yourside;
	int stdio;
	int p[2];

	if(!_blkchk(cmd) || !_blkchk(mode) || (*mode != 'r' && *mode != 'w')) {
		errno = EINVAL;
		return(NULL);
	}

	if(pipe(p) < 0)
		return(NULL);

	myside = tst(p[WTR], p[RDR]);
	yourside = tst(p[RDR], p[WTR]);
#ifdef	SIGCLD
	signal(SIGCLD, SIG_DFL);
#endif

	switch(pid = fork()) {
		case 0:
			/* myside and yourside reverse roles in child */
			/* close all pipes from other popen's */
			for (poptr = popen_pid; poptr < popen_pid+NOFILES_MIN; poptr++)
				if(*poptr)
					close(poptr - popen_pid);
			stdio = tst(0, 1);
			(void) close(myside);
			(void) close(stdio);
			(void) fcntl(yourside, F_DUPFD, stdio);
			(void) close(yourside);
			setuid(getuid());
			execshell(cmd);
			_exit(1);
		case -1:
			return(NULL);
		default:
			popen_pid[myside] = pid;
			(void) close(yourside);
			return(fdopen(myside, mode));
	}
}

int
pclose(ptr)
FILE *ptr;
{
	register int f, r;
#ifdef	sun
	int status;
	void (*hstat)(), (*istat)(), (*qstat)(), (*astat)();
#else
	int status, (*hstat)(), (*istat)(), (*qstat)(), (*astat)();
#endif
	register int oalarm;

	if(!_blkchk((char *)ptr))
		return(-1);

	f = fileno(ptr);
	if(popen_pid[f] == 0) {
		_error(NULL, 0, NULL, "pclose with no popen");
		return(-1);
	}
	(void) fclose(ptr);
	istat = signal(SIGINT, SIG_IGN);
	qstat = signal(SIGQUIT, SIG_IGN);
	hstat = signal(SIGHUP, SIG_IGN);
	astat = signal(SIGALRM, SIG_IGN);
	oalarm = alarm(0);
#ifdef	WAITPID
	do
		r = waitpid(popen_pid[f], &status, 0);
	while((r == -1) && errno == EINTR);
#else
	while(((r = wait(&status)) != popen_pid[f]) && (r != -1))
		;
#endif
	(void) signal(SIGINT, istat);
	(void) signal(SIGQUIT, qstat);
	(void) signal(SIGHUP, hstat);
	(void) signal(SIGALRM, astat);
	if(oalarm)
		alarm(oalarm);
	/* mark this pipe closed */
	popen_pid[f] = 0;
	return((r == -1) ? -1 : status);
}

int
system(s)
const char *s;
{
	int status;
	register pid_t pid;
#ifdef	sun
	register void (*cstat)(), (*istat)(), (*qstat)();
	register int w;
#else
	register int (*cstat)(), (*istat)(), (*qstat)(), w;
#endif

	if(!_blkchk(s))
		return(-1);

	cstat = signal(SIGCHLD, SIG_IGN);

	switch(pid = fork()) {
		case 0:
			setuid(getuid());
			signal(SIGCHLD, cstat);
			execshell(s);
			_exit(127);
		case -1:
			return(-1);
	}
	istat = signal(SIGINT, SIG_IGN);
	qstat = signal(SIGQUIT, SIG_IGN);
#ifdef	WAITPID
	w = waitpid(pid, &status, 0);
#else
	while((w = wait(&status)) != pid && w != -1)
		;
#endif
	(void) signal(SIGINT, istat);
	(void) signal(SIGQUIT, qstat);
	(void)signal(SIGCHLD, cstat);
	return((w == -1) ? -1 : status);
}

#endif	/*UNIX*/

/*-
 * Copyright (c) 1980, 1983, 1990 The Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#if defined(LIBC_SCCS) && !defined(lint)
static char sccsid[] = "@(#)qsort.c	5.9 (Berkeley) 2/23/91";
#endif /* LIBC_SCCS and not lint */

/*
 * MTHRESH is the smallest partition for which we compare for a median
 * value instead of using the middle value.
 */
#define	MTHRESH	6

/*
 * THRESH is the minimum number of entries in a partition for continued
 * partitioning.
 */
#define	THRESH	4

static	void	insertion_sort();
static	void	quick_sort();

#ifdef	ANSI
/*
 * Nightmare definition because different Unix suppliers can't get it right
 */
#if	defined(sun) && !defined(solaris)
int
#else
void cdecl
#endif
qsort(bot, nmemb, size, compar)
void *bot;
size_t nmemb, size;
int (cdecl *compar)(const void *, const void *);
#else
#ifdef	_HPUX_SOURCE
void
qsort(bot, nmemb, size, compar)
void *bot;
size_t nmemb, size;
int (cdecl *compar)();
#else
qsort(bot, nmemb, size, compar)
char *bot;
int (*compar)();
#endif
#endif
{
	if (nmemb <= 1) {
		_error(NULL, 0, NULL, "qsort called on 0 or 1 records");
#if	defined(sun) && !defined(solaris)
		return(0);
#else
		return;
#endif
	}

	if(blklen(bot, false) < (nmemb * size)) {
		_error(NULL, 0, NULL, "qsort: buffer isn't that big");
#if	defined(sun) && !defined(solaris)
		return(0);
#else
		return;
#endif
	}

	if (nmemb >= THRESH)
		quick_sort(bot, nmemb, size, compar);
	else
		insertion_sort(bot, nmemb, size, compar);

#if	defined(sun) && !defined(solaris)
	return(0);
#endif
}

/*
 * Swap two areas of size number of bytes.  Although qsort(3) permits random
 * blocks of memory to be sorted, sorting pointers is almost certainly the
 * common case (and, were it not, could easily be made so).  Regardless, it
 * isn't worth optimizing; the SWAP's get sped up by the cache, and pointer
 * arithmetic gets lost in the time required for comparison function calls.
 */
#define	SWAP(a, b) { \
	cnt = size; \
	do { \
		ch = *a; \
		*a++ = *b; \
		*b++ = ch; \
	} while (--cnt); \
}

/*
 * Knuth, Vol. 3, page 116, Algorithm Q, step b, argues that a single pass
 * of straight insertion sort after partitioning is complete is better than
 * sorting each small partition as it is created.  This isn't correct in this
 * implementation because comparisons require at least one (and often two)
 * function calls and are likely to be the dominating expense of the sort.
 * Doing a final insertion sort does more comparisons than are necessary
 * because it compares the "edges" and medians of the partitions which are
 * known to be already sorted.
 *
 * This is also the reasoning behind selecting a small THRESH value (see
 * Knuth, page 122, equation 26), since the quicksort algorithm does less
 * comparisons than the insertion sort.
 */
#define	SORT(bot, n) { \
	if (n > 1) \
		if (n == 2) { \
			t1 = bot + size; \
			if (compar(t1, bot) < 0) \
				SWAP(t1, bot); \
		} else \
			insertion_sort(bot, n, size, compar); \
}

static void
quick_sort(bot, nmemb, size, compar)
	register char *bot;
	register int size;
	int nmemb, (cdecl *compar)();
{
	register int cnt;
	register unsigned char ch;
	register char *top, *mid, *t1, *t2;
	register int n1, n2;
	char *bsv;

	/* bot and nmemb must already be set. */
partition:

	/* find mid and top elements */
	mid = bot + size * (nmemb >> 1);
	top = bot + (nmemb - 1) * size;

	/*
	 * Find the median of the first, last and middle element (see Knuth,
	 * Vol. 3, page 123, Eq. 28).  This test order gets the equalities
	 * right.
	 */
	if (nmemb >= MTHRESH) {
		n1 = compar(bot, mid);
		n2 = compar(mid, top);
		if (n1 < 0 && n2 > 0)
			t1 = compar(bot, top) < 0 ? top : bot;
		else if (n1 > 0 && n2 < 0)
			t1 = compar(bot, top) > 0 ? top : bot;
		else
			t1 = mid;

		/* if mid element not selected, swap selection there */
		if (t1 != mid) {
			SWAP(t1, mid);
			mid -= size;
		}
	}

	/* Standard quicksort, Knuth, Vol. 3, page 116, Algorithm Q. */
#define	didswap	n1
#define	newbot	t1
#define	replace	t2
	didswap = 0;
	for (bsv = bot;;) {
		for (; bot < mid && compar(bot, mid) <= 0; bot += size);
		while (top > mid) {
			if (compar(mid, top) <= 0) {
				top -= size;
				continue;
			}
			newbot = bot + size;	/* value of bot after swap */
			if (bot == mid)		/* top <-> mid, mid == top */
				replace = mid = top;
			else {			/* bot <-> top */
				replace = top;
				top -= size;
			}
			goto swap;
		}
		if (bot == mid)
			break;

		/* bot <-> mid, mid == bot */
		replace = mid;
		newbot = mid = bot;		/* value of bot after swap */
		top -= size;

swap:		SWAP(bot, replace);
		bot = newbot;
		didswap = 1;
	}

	/*
	 * Quicksort behaves badly in the presence of data which is already
	 * sorted (see Knuth, Vol. 3, page 119) going from O N lg N to O N^2.
	 * To avoid this worst case behavior, if a re-partitioning occurs
	 * without swapping any elements, it is not further partitioned and
	 * is insert sorted.  This wins big with almost sorted data sets and
	 * only loses if the data set is very strangely partitioned.  A fix
	 * for those data sets would be to return prematurely if the insertion
	 * sort routine is forced to make an excessive number of swaps, and
	 * continue the partitioning.
	 */
	if (!didswap) {
		insertion_sort(bsv, nmemb, size, compar);
		return;
	}

	/*
	 * Re-partition or sort as necessary.  Note that the mid element
	 * itself is correctly positioned and can be ignored.
	 */
#define	nlower	n1
#define	nupper	n2
	bot = bsv;
	nlower = (mid - bot) / size;	/* size of lower partition */
	mid += size;
	nupper = nmemb - nlower - 1;	/* size of upper partition */

	/*
	 * If must call recursively, do it on the smaller partition; this
	 * bounds the stack to lg N entries.
	 */
	if (nlower > nupper) {
		if (nupper >= THRESH)
			quick_sort(mid, nupper, size, compar);
		else {
			SORT(mid, nupper);
			if (nlower < THRESH) {
				SORT(bot, nlower);
				return;
			}
		}
		nmemb = nlower;
	} else {
		if (nlower >= THRESH)
			quick_sort(bot, nlower, size, compar);
		else {
			SORT(bot, nlower);
			if (nupper < THRESH) {
				SORT(mid, nupper);
				return;
			}
		}
		bot = mid;
		nmemb = nupper;
	}
	goto partition;
	/* NOTREACHED */
}

static void
insertion_sort(bot, nmemb, size, compar)
	char *bot;
	register int size;
	int nmemb, (cdecl *compar)();
{
	register int cnt;
	register unsigned char ch;
	register char *s1, *s2, *t1, *t2, *top;

	/*
	 * A simple insertion sort (see Knuth, Vol. 3, page 81, Algorithm
	 * S).  Insertion sort has the same worst case as most simple sorts
	 * (O N^2).  It gets used here because it is (O N) in the case of
	 * sorted data.
	 */
	top = bot + nmemb * size;
	for (t1 = bot + size; t1 < top;) {
		for (t2 = t1; (t2 -= size) >= bot && compar(t1, t2) < 0;);
		if (t1 != (t2 += size)) {
			/* Bubble bytes up through each element. */
			for (cnt = size; cnt--; ++t1) {
				ch = *t1;
				for (s1 = s2 = t1; (s2 -= size) >= t2; s1 = s2)
					*s1 = *s2;
				*s1 = ch;
			}
		} else
			t1 += size;
	}
}

#if	0
mprotect(addr, len, prot)
caddr_t addr;
{
	errno = EINVAL;
	return(-1);
}
#endif

#ifdef	MAX_STACK_DEPTH

#define	SHORT_CALLSTACK_SIZE	5

static int		fstk_i;
static int	no_call_graph = 0;

#if (defined(vax) || (defined(sun) && !defined(sun4)))
#define get_current_fp(first_local) ((unsigned)&(first_local) + 4)
#endif

#if (defined(vax) || defined(sun))
#include <sys/types.h>
#ifdef	solaris
#include <sys/frame.h>
#else
#include <frame.h>
#endif
#define prev_fp_from_fp(fp)	(unsigned)(((struct frame *)(fp))->fr_savfp)
#define ret_addr_from_fp(fp)	(unsigned)(((struct frame *)(fp))->fr_savpc)
#endif

static void
mprof(sp)
SLOT *sp;
{
    unsigned	first_local;		/* WARNING -- This MUST be the first
					 * local variable in this function.
					 */
    unsigned	fp;
    unsigned	ret_addr;
    register int i;

#ifdef mips
    pPDR pdr;
#endif

    fstk_i = 0;

    /* gather return addresses from the callstack
     */
#ifndef mips
    fp = get_current_fp(first_local);
    ret_addr = ret_addr_from_fp(fp);

    /* Step back 1 frame (to the caller of malloc)
     */
    fp = prev_fp_from_fp(fp);
    ret_addr = ret_addr_from_fp(fp);

    i = 0;
    while((ret_addr > mp_root_address) && (i < MAX_STACK_DEPTH)){
	if (no_call_graph && (fstk_i > SHORT_CALLSTACK_SIZE))
	  break;

	sp->s_history[i++] = (caddr_t)ret_addr;
	fstk_i++;
	fp = prev_fp_from_fp(fp);
	if (fp == 0) break;
	ret_addr = ret_addr_from_fp(fp);
    }
#else
    get31();
    pdr = getpdr(intloc);
    getsp();
    fp = intloc;
    ret_addr = getretaddr(&fp, pdr);	/* fp is changed */

    /* Step back 1 frame (to the caller of malloc) */
    pdr = getpdr(ret_addr);
    ret_addr = getretaddr(&fp, pdr);	/* fp is changed */

    while (ret_addr > mp_root_address) {
	if (no_call_graph && (fstk_i > SHORT_CALLSTACK_SIZE))
	  break;

	fpcs[fstk_i] = ret_addr;
	fstk_i++;
	pdr = getpdr(ret_addr);
	ret_addr = getretaddr(&fp, pdr);	/* fp is updated */
    }
#endif
}

static struct sym {
	char sym[33];
	caddr_t off;
} *s;
static unsigned long size_s;

static void
st_read()
{
	struct exec e;
	register struct nlist *n, *nlist;
	register struct sym *sym;
	register int fd;
	register long l;

	if((exec_name == NULL) || (s != NULL))
		return;

	fd = open(exec_name, 0);
	read(fd, &e, sizeof(e));

	if(e.a_syms == 0) {
		/*puts("stripped");*/
		close(fd);
		return;
	}

	in_db++;

	lseek(fd, N_SYMOFF(e), SEEK_SET);
	nlist = n = (struct nlist *)db_mallocchk(e.a_syms * sizeof(struct nlist), NULL, 0);
	sym = s = (struct sym *)db_mallocchk(e.a_syms * sizeof(struct sym), NULL, 0);
	read(fd, n, e.a_syms * sizeof(struct nlist));
	size_s = 0;

	for(l = 0; l < e.a_syms; l++, n++) {
		register char *ptr;

		if(n->n_type&N_STAB) {
			/* compiled with `-g' */
			if(n->n_type != N_FUN)
				continue;
		} else {
			if((n->n_type&N_TYPE) != N_TEXT)
				continue;
			if(!(n->n_type&N_EXT))
				continue;
		}
		sym->off = (caddr_t)n->n_value;
		lseek(fd, N_STROFF(e) + n->n_un.n_strx, SEEK_SET);
		read(fd, sym->sym, sizeof(sym->sym) - 1);
		if(ptr = strrchr(sym->sym, ':'))
			*ptr = '\0';
		size_s++;
		sym++;
	}

#ifdef	assert
	assert(size_s <= e.a_syms);
#endif

	close(fd);
	db_freechk(nlist, NULL, 0);
	if(size_s == 0) {
		db_freechk(s, NULL, 0);
		s = NULL;
	} else
		s = (struct sym *)db_reallocchk(s, size_s * sizeof(struct sym), NULL, 0);

	in_db--;
}

static const char *
symname(pc)
caddr_t pc;
{
	register struct sym *sym, *keep;
	register long l;
	register int diff;

	if(s == NULL)
		return(NULL);

	diff = 0;
	keep = NULL;

	for(sym = s, l = 0; l < size_s; l++, sym++)
		if((pc > sym->off) && ((pc < sym->off + diff) || (diff == 0))) {
			diff = pc - sym->off;
			keep = sym;
		}

	if(keep)
		return((keep->sym[0] == '_') ? &keep->sym[1] : keep->sym);
	return(NULL);
}
#endif	/*MAX_STACK_DEPTH*/

#ifdef	UNIX
static void
slots_rw(void)
{
	rw((caddr_t)slots, maxslots * sizeof(SLOT));
}


static void
slots_readonly(void)
{
	ro((caddr_t)slots, maxslots * sizeof(SLOT));
}

static void
ro(const caddr_t addr, size_t size)
{
#ifdef	MPROTECT
	mprotect(addr, size, PROT_READ);
#endif
#ifdef	WATCH
	struct {
		int ctl;
		prwatch_t p;
	} msg;

	if(watchfd < 0) {
		watchfd = open("/proc/self/ctl", O_WRONLY|O_EXCL);
		if(watchfd < 0)
			return;
	}

	msg.p.pr_vaddr = (uintptr_t)addr;
	msg.p.pr_size = size;
	msg.p.pr_wflags = WA_WRITE;
	msg.ctl = PCWATCH;

	if(write(watchfd, &msg, sizeof(msg)) < 0)
		puts("ro");
#endif
}

static void
rw(const caddr_t addr, size_t size)
{
#ifdef	MPROTECT
	mprotect(addr, size, PROT_READ|PROT_WRITE);
#endif
#ifdef	WATCH
	struct {
		int ctl;
		prwatch_t p;
	} msg;

	if(watchfd < 0)
		return;

	msg.p.pr_vaddr = (uintptr_t)addr;
	msg.p.pr_size = size;
	msg.p.pr_wflags = 0;
	msg.ctl = PCWATCH;

	if(write(watchfd, &msg, sizeof(msg)) < 0)
		puts("rw");
#endif
}

static void
none(const caddr_t addr, size_t size)
{
#ifdef	MPROTECT
	mprotect(addr, size, PROT_NONE);
#endif
#ifdef	WATCH
	struct {
		int ctl;
		prwatch_t p;
	} msg;

	if(watchfd < 0) {
		watchfd = open("/proc/self/ctl", O_WRONLY|O_EXCL);
		if(watchfd < 0)
			return;
	}

	msg.p.pr_vaddr = (uintptr_t)addr;
	msg.p.pr_size = size;
	msg.p.pr_wflags = WA_WRITE|WA_READ;
	msg.ctl = PCWATCH;

	if(write(watchfd, &msg, sizeof(msg)) < 0)
		puts("none");
#endif
}
#endif	/*UNIX*/

#endif	/*CL_DEBUG*/
