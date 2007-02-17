/*
 * Header file for public domain tar (tape archive) program.
 *
 * @(#)tar.h 1.20 86/10/29	Public Domain.
 *
 * Created 25 August 1985 by John Gilmore, ihnp4!hoptoad!gnu.
 *
 * $Id: is_tar.h,v 1.2 2007/02/11 00:41:13 tkojm Exp $ # checkin only
 */

/*
 * Header block on tape.
 *
 * I'm going to use traditional DP naming conventions here.
 * A "block" is a big chunk of stuff that we do I/O on.
 * A "record" is a piece of info that we care about.
 * Typically many "record"s fit into a "block".
 */
#define	RECORDSIZE	512
#define	NAMSIZ	100
#define	TUNMLEN	32
#define	TGNMLEN	32

union record {
	char		charptr[RECORDSIZE];
	struct header {
		char	name[NAMSIZ];
		char	mode[8];
		char	uid[8];
		char	gid[8];
		char	size[12];
		char	mtime[12];
		char	chksum[8];
		char	linkflag;
		char	linkname[NAMSIZ];
		char	magic[8];
		char	uname[TUNMLEN];
		char	gname[TGNMLEN];
		char	devmajor[8];
		char	devminor[8];
	} header;
};

/* The magic field is filled with this if uname and gname are valid. */
#define	TMAGIC		"ustar  "	/* 7 chars and a null */

int is_tar(unsigned char *buf, unsigned int nbytes);
