/* $Id$ */

/*
 * Copyright (c) 1988-1997 Sam Leffler
 * Copyright (c) 1991-1997 Silicon Graphics, Inc.
 *
 * Permission to use, copy, modify, distribute, and sell this software and 
 * its documentation for any purpose is hereby granted without fee, provided
 * that (i) the above copyright notices and this permission notice appear in
 * all copies of the software and related documentation, and (ii) the names of
 * Sam Leffler and Silicon Graphics may not be used in any advertising or
 * publicity relating to the software without the specific, prior written
 * permission of Sam Leffler and Silicon Graphics.
 * 
 * THE SOFTWARE IS PROVIDED "AS-IS" AND WITHOUT WARRANTY OF ANY KIND, 
 * EXPRESS, IMPLIED OR OTHERWISE, INCLUDING WITHOUT LIMITATION, ANY 
 * WARRANTY OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.  
 * 
 * IN NO EVENT SHALL SAM LEFFLER OR SILICON GRAPHICS BE LIABLE FOR
 * ANY SPECIAL, INCIDENTAL, INDIRECT OR CONSEQUENTIAL DAMAGES OF ANY KIND,
 * OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
 * WHETHER OR NOT ADVISED OF THE POSSIBILITY OF DAMAGE, AND ON ANY THEORY OF 
 * LIABILITY, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE 
 * OF THIS SOFTWARE.
 */

#include "tif_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_IO_H
# include <io.h>
#endif

#include "tiffio.h"

#ifndef O_BINARY
# define O_BINARY	0
#endif

char*	appname;
char*	curfile;
int	swabflag;
int	bigendian;
int	typeshift[14];		/* data type shift counts */
long	typemask[14];		/* data type masks */
uint32	maxitems = 24;		/* maximum indirect data items to print */

char*	bytefmt = "%s%#02x";		/* BYTE */
char*	sbytefmt = "%s%d";		/* SBYTE */
char*	shortfmt = "%s%u";		/* SHORT */
char*	sshortfmt = "%s%d";		/* SSHORT */
char*	longfmt = "%s%lu";		/* LONG */
char*	slongfmt = "%s%ld";		/* SLONG */
char*	rationalfmt = "%s%g";		/* RATIONAL */
char*	srationalfmt = "%s%g";		/* SRATIONAL */
char*	floatfmt = "%s%g";		/* FLOAT */
char*	doublefmt = "%s%g";		/* DOUBLE */
char*	ifdfmt = "%s%#04x";		/* IFD offset */

static	void dump(int, off_t);
extern	int optind;
extern	char* optarg;

void
usage()
{
	fprintf(stderr, "usage: %s [-h] [-o offset] [-m maxitems] file.tif ...\n", appname);
	exit(-1);
}

int
main(int argc, char* argv[])
{
	int one = 1, fd;
	int multiplefiles = (argc > 1);
	int c;
	uint32 diroff = (uint32) 0;
	bigendian = (*(char *)&one == 0);

	appname = argv[0];
	while ((c = getopt(argc, argv, "m:o:h")) != -1) {
		switch (c) {
		case 'h':			/* print values in hex */
			shortfmt = "%s%#x";
			sshortfmt = "%s%#x";
			longfmt = "%s%#lx";
			slongfmt = "%s%#lx";
			break;
		case 'o':
			diroff = (uint32) strtoul(optarg, NULL, 0);
			break;
		case 'm':
			maxitems = strtoul(optarg, NULL, 0);
			break;
		default:
			usage();
		}
	}
	if (optind >= argc)
		usage();
	for (; optind < argc; optind++) {
		fd = open(argv[optind], O_RDONLY|O_BINARY, 0);
		if (fd < 0) {
			perror(argv[0]);
			return (-1);
		}
		if (multiplefiles)
			printf("%s:\n", argv[optind]);
		curfile = argv[optind];
		swabflag = 0;
		dump(fd, diroff);
		close(fd);
	}
	return (0);
}

static	TIFFHeader hdr;

#define	ord(e)	((int)e)

/*
 * Initialize shift & mask tables and byte
 * swapping state according to the file
 * byte order.
 */
static void
InitByteOrder(int magic)
{
	typemask[0] = 0;
	typemask[ord(TIFF_BYTE)] = 0xff;
	typemask[ord(TIFF_SBYTE)] = 0xff;
	typemask[ord(TIFF_UNDEFINED)] = 0xff;
	typemask[ord(TIFF_SHORT)] = 0xffff;
	typemask[ord(TIFF_SSHORT)] = 0xffff;
	typemask[ord(TIFF_LONG)] = 0xffffffff;
	typemask[ord(TIFF_SLONG)] = 0xffffffff;
	typemask[ord(TIFF_IFD)] = 0xffffffff;
	typemask[ord(TIFF_RATIONAL)] = 0xffffffff;
	typemask[ord(TIFF_SRATIONAL)] = 0xffffffff;
	typemask[ord(TIFF_FLOAT)] = 0xffffffff;
	typemask[ord(TIFF_DOUBLE)] = 0xffffffff;
	typeshift[0] = 0;
	typeshift[ord(TIFF_LONG)] = 0;
	typeshift[ord(TIFF_SLONG)] = 0;
	typeshift[ord(TIFF_IFD)] = 0;
	typeshift[ord(TIFF_RATIONAL)] = 0;
	typeshift[ord(TIFF_SRATIONAL)] = 0;
	typeshift[ord(TIFF_FLOAT)] = 0;
	typeshift[ord(TIFF_DOUBLE)] = 0;
	if (magic == TIFF_BIGENDIAN || magic == MDI_BIGENDIAN) {
		typeshift[ord(TIFF_BYTE)] = 24;
		typeshift[ord(TIFF_SBYTE)] = 24;
		typeshift[ord(TIFF_SHORT)] = 16;
		typeshift[ord(TIFF_SSHORT)] = 16;
		swabflag = !bigendian;
	} else {
		typeshift[ord(TIFF_BYTE)] = 0;
		typeshift[ord(TIFF_SBYTE)] = 0;
		typeshift[ord(TIFF_SHORT)] = 0;
		typeshift[ord(TIFF_SSHORT)] = 0;
		swabflag = bigendian;
	}
}

static	off_t ReadDirectory(int, unsigned, off_t);
static	void ReadError(char*);
static	void Error(const char*, ...);
static	void Fatal(const char*, ...);

static void
dump(int fd, off_t diroff)
{
	unsigned i;

	lseek(fd, (off_t) 0, 0);
	if (read(fd, (char*) &hdr, sizeof (hdr)) != sizeof (hdr))
		ReadError("TIFF header");
	/*
	 * Setup the byte order handling.
	 */
	if (hdr.tiff_magic != TIFF_BIGENDIAN && hdr.tiff_magic != TIFF_LITTLEENDIAN &&
#if HOST_BIGENDIAN
	    // MDI is sensitive to the host byte order, unlike TIFF
	    MDI_BIGENDIAN != hdr.tiff_magic )
#else
	    MDI_LITTLEENDIAN != hdr.tiff_magic )
#endif
		Fatal("Not a TIFF or MDI file, bad magic number %u (%#x)",
		    hdr.tiff_magic, hdr.tiff_magic);
	InitByteOrder(hdr.tiff_magic);
	/*
	 * Swap header if required.
	 */
	if (swabflag) {
		TIFFSwabShort(&hdr.tiff_version);
		TIFFSwabLong(&hdr.tiff_diroff);
	}
	/*
	 * Now check version (if needed, it's been byte-swapped).
	 * Note that this isn't actually a version number, it's a
	 * magic number that doesn't change (stupid).
	 */
	if (hdr.tiff_version != TIFF_VERSION)
		Fatal("Not a TIFF file, bad version number %u (%#x)",
		    hdr.tiff_version, hdr.tiff_version); 
	printf("Magic: %#x <%s-endian> Version: %#x\n",
	    hdr.tiff_magic,
	    hdr.tiff_magic == TIFF_BIGENDIAN ? "big" : "little",
	    hdr.tiff_version);
	if (diroff == 0)
	    diroff = hdr.tiff_diroff;
	for (i = 0; diroff != 0; i++) {
		if (i > 0)
			putchar('\n');
		diroff = ReadDirectory(fd, i, diroff);
	}
}

static int datawidth[] = {
    0,	/* nothing */
    1,	/* TIFF_BYTE */
    1,	/* TIFF_ASCII */
    2,	/* TIFF_SHORT */
    4,	/* TIFF_LONG */
    8,	/* TIFF_RATIONAL */
    1,	/* TIFF_SBYTE */
    1,	/* TIFF_UNDEFINED */
    2,	/* TIFF_SSHORT */
    4,	/* TIFF_SLONG */
    8,	/* TIFF_SRATIONAL */
    4,	/* TIFF_FLOAT */
    8,	/* TIFF_DOUBLE */
    4	/* TIFF_IFD */
};
#define	NWIDTHS	(sizeof (datawidth) / sizeof (datawidth[0]))
static	int TIFFFetchData(int, TIFFDirEntry*, void*);
static	void PrintTag(FILE*, uint16);
static	void PrintType(FILE*, uint16);
static	void PrintData(FILE*, uint16, uint32, unsigned char*);
static	void PrintByte(FILE*, const char*, TIFFDirEntry*);
static	void PrintShort(FILE*, const char*, TIFFDirEntry*);
static	void PrintLong(FILE*, const char*, TIFFDirEntry*);

/*
 * Read the next TIFF directory from a file
 * and convert it to the internal format.
 * We read directories sequentially.
 */
static off_t
ReadDirectory(int fd, unsigned ix, off_t off)
{
	register TIFFDirEntry *dp;
	register unsigned int n;
	TIFFDirEntry *dir = 0;
	uint16 dircount;
	int space;
	uint32 nextdiroff = 0;

	if (off == 0)			/* no more directories */
		goto done;
	if (lseek(fd, (off_t) off, 0) != off) {
		Fatal("Seek error accessing TIFF directory");
		goto done;
	}
	if (read(fd, (char*) &dircount, sizeof (uint16)) != sizeof (uint16)) {
		ReadError("directory count");
		goto done;
	}
	if (swabflag)
		TIFFSwabShort(&dircount);
	dir = (TIFFDirEntry *)_TIFFmalloc(dircount * sizeof (TIFFDirEntry));
	if (dir == NULL) {
		Fatal("No space for TIFF directory");
		goto done;
	}
	n = read(fd, (char*) dir, dircount*sizeof (*dp));
	if (n != dircount*sizeof (*dp)) {
		n /= sizeof (*dp);
		Error(
	    "Could only read %u of %u entries in directory at offset %#lx",
		    n, dircount, (unsigned long) off);
		dircount = n;
	}
	if (read(fd, (char*) &nextdiroff, sizeof (uint32)) != sizeof (uint32))
		nextdiroff = 0;
	if (swabflag)
		TIFFSwabLong(&nextdiroff);
	printf("Directory %u: offset %lu (%#lx) next %lu (%#lx)\n", ix,
	    (unsigned long)off, (unsigned long)off,
	    (unsigned long)nextdiroff, (unsigned long)nextdiroff);
	for (dp = dir, n = dircount; n > 0; n--, dp++) {
		if (swabflag) {
			TIFFSwabArrayOfShort(&dp->tdir_tag, 2);
			TIFFSwabArrayOfLong(&dp->tdir_count, 2);
		}
		PrintTag(stdout, dp->tdir_tag);
		putchar(' ');
		PrintType(stdout, dp->tdir_type);
		putchar(' ');
		printf("%lu<", (unsigned long) dp->tdir_count);
		if (dp->tdir_type >= NWIDTHS) {
			printf(">\n");
			continue;
		}
		space = dp->tdir_count * datawidth[dp->tdir_type];
		if (space <= 0) {
			printf(">\n");
			Error("Invalid count for tag %u", dp->tdir_tag);
			continue;
                }
		if (space <= 4) {
			switch (dp->tdir_type) {
			case TIFF_FLOAT:
			case TIFF_UNDEFINED:
			case TIFF_ASCII: {
				unsigned char data[4];
				_TIFFmemcpy(data, &dp->tdir_offset, 4);
				if (swabflag)
					TIFFSwabLong((uint32*) data);
				PrintData(stdout,
				    dp->tdir_type, dp->tdir_count, data);
				break;
			}
			case TIFF_BYTE:
				PrintByte(stdout, bytefmt, dp);
				break;
			case TIFF_SBYTE:
				PrintByte(stdout, sbytefmt, dp);
				break;
			case TIFF_SHORT:
				PrintShort(stdout, shortfmt, dp);
				break;
			case TIFF_SSHORT:
				PrintShort(stdout, sshortfmt, dp);
				break;
			case TIFF_LONG:
				PrintLong(stdout, longfmt, dp);
				break;
			case TIFF_SLONG:
				PrintLong(stdout, slongfmt, dp);
				break;
			case TIFF_IFD:
				PrintLong(stdout, ifdfmt, dp);
				break;
			}
		} else {
			unsigned char *data = (unsigned char *)_TIFFmalloc(space);
			if (data) {
				if (TIFFFetchData(fd, dp, data)) {
					if (dp->tdir_count > maxitems) {
						PrintData(stdout, dp->tdir_type,
						    maxitems, data);
						printf(" ...");
					} else
						PrintData(stdout, dp->tdir_type,
						    dp->tdir_count, data);
                                }
				_TIFFfree(data);
			} else
				Error("No space for data for tag %u",
				    dp->tdir_tag);
		}
		printf(">\n");
	}
done:
	if (dir)
		_TIFFfree((char *)dir);
	return (nextdiroff);
}

static	struct tagname {
	uint16	tag;
	char*	name;
} tagnames[] = {
    { TIFFTAG_SUBFILETYPE,	"SubFileType" },
    { TIFFTAG_OSUBFILETYPE,	"OldSubFileType" },
    { TIFFTAG_IMAGEWIDTH,	"ImageWidth" },
    { TIFFTAG_IMAGELENGTH,	"ImageLength" },
    { TIFFTAG_BITSPERSAMPLE,	"BitsPerSample" },
    { TIFFTAG_COMPRESSION,	"Compression" },
    { TIFFTAG_PHOTOMETRIC,	"Photometric" },
    { TIFFTAG_THRESHHOLDING,	"Threshholding" },
    { TIFFTAG_CELLWIDTH,	"CellWidth" },
    { TIFFTAG_CELLLENGTH,	"CellLength" },
    { TIFFTAG_FILLORDER,	"FillOrder" },
    { TIFFTAG_DOCUMENTNAME,	"DocumentName" },
    { TIFFTAG_IMAGEDESCRIPTION,	"ImageDescription" },
    { TIFFTAG_MAKE,		"Make" },
    { TIFFTAG_MODEL,		"Model" },
    { TIFFTAG_STRIPOFFSETS,	"StripOffsets" },
    { TIFFTAG_ORIENTATION,	"Orientation" },
    { TIFFTAG_SAMPLESPERPIXEL,	"SamplesPerPixel" },
    { TIFFTAG_ROWSPERSTRIP,	"RowsPerStrip" },
    { TIFFTAG_STRIPBYTECOUNTS,	"StripByteCounts" },
    { TIFFTAG_MINSAMPLEVALUE,	"MinSampleValue" },
    { TIFFTAG_MAXSAMPLEVALUE,	"MaxSampleValue" },
    { TIFFTAG_XRESOLUTION,	"XResolution" },
    { TIFFTAG_YRESOLUTION,	"YResolution" },
    { TIFFTAG_PLANARCONFIG,	"PlanarConfig" },
    { TIFFTAG_PAGENAME,		"PageName" },
    { TIFFTAG_XPOSITION,	"XPosition" },
    { TIFFTAG_YPOSITION,	"YPosition" },
    { TIFFTAG_FREEOFFSETS,	"FreeOffsets" },
    { TIFFTAG_FREEBYTECOUNTS,	"FreeByteCounts" },
    { TIFFTAG_GRAYRESPONSEUNIT,	"GrayResponseUnit" },
    { TIFFTAG_GRAYRESPONSECURVE,"GrayResponseCurve" },
    { TIFFTAG_GROUP3OPTIONS,	"Group3Options" },
    { TIFFTAG_GROUP4OPTIONS,	"Group4Options" },
    { TIFFTAG_RESOLUTIONUNIT,	"ResolutionUnit" },
    { TIFFTAG_PAGENUMBER,	"PageNumber" },
    { TIFFTAG_COLORRESPONSEUNIT,"ColorResponseUnit" },
    { TIFFTAG_TRANSFERFUNCTION,	"TransferFunction" },
    { TIFFTAG_SOFTWARE,		"Software" },
    { TIFFTAG_DATETIME,		"DateTime" },
    { TIFFTAG_ARTIST,		"Artist" },
    { TIFFTAG_HOSTCOMPUTER,	"HostComputer" },
    { TIFFTAG_PREDICTOR,	"Predictor" },
    { TIFFTAG_WHITEPOINT,	"Whitepoint" },
    { TIFFTAG_PRIMARYCHROMATICITIES,"PrimaryChromaticities" },
    { TIFFTAG_COLORMAP,		"Colormap" },
    { TIFFTAG_HALFTONEHINTS,	"HalftoneHints" },
    { TIFFTAG_TILEWIDTH,	"TileWidth" },
    { TIFFTAG_TILELENGTH,	"TileLength" },
    { TIFFTAG_TILEOFFSETS,	"TileOffsets" },
    { TIFFTAG_TILEBYTECOUNTS,	"TileByteCounts" },
    { TIFFTAG_BADFAXLINES,	"BadFaxLines" },
    { TIFFTAG_CLEANFAXDATA,	"CleanFaxData" },
    { TIFFTAG_CONSECUTIVEBADFAXLINES, "ConsecutiveBadFaxLines" },
    { TIFFTAG_SUBIFD,		"SubIFD" },
    { TIFFTAG_INKSET,		"InkSet" },
    { TIFFTAG_INKNAMES,		"InkNames" },
    { TIFFTAG_NUMBEROFINKS,	"NumberOfInks" },
    { TIFFTAG_DOTRANGE,		"DotRange" },
    { TIFFTAG_TARGETPRINTER,	"TargetPrinter" },
    { TIFFTAG_EXTRASAMPLES,	"ExtraSamples" },
    { TIFFTAG_SAMPLEFORMAT,	"SampleFormat" },
    { TIFFTAG_SMINSAMPLEVALUE,	"SMinSampleValue" },
    { TIFFTAG_SMAXSAMPLEVALUE,	"SMaxSampleValue" },
    { TIFFTAG_JPEGPROC,		"JPEGProcessingMode" },
    { TIFFTAG_JPEGIFOFFSET,	"JPEGInterchangeFormat" },
    { TIFFTAG_JPEGIFBYTECOUNT,	"JPEGInterchangeFormatLength" },
    { TIFFTAG_JPEGRESTARTINTERVAL,"JPEGRestartInterval" },
    { TIFFTAG_JPEGLOSSLESSPREDICTORS,"JPEGLosslessPredictors" },
    { TIFFTAG_JPEGPOINTTRANSFORM,"JPEGPointTransform" },
    { TIFFTAG_JPEGTABLES,       "JPEGTables" },
    { TIFFTAG_JPEGQTABLES,	"JPEGQTables" },
    { TIFFTAG_JPEGDCTABLES,	"JPEGDCTables" },
    { TIFFTAG_JPEGACTABLES,	"JPEGACTables" },
    { TIFFTAG_YCBCRCOEFFICIENTS,"YCbCrCoefficients" },
    { TIFFTAG_YCBCRSUBSAMPLING,	"YCbCrSubsampling" },
    { TIFFTAG_YCBCRPOSITIONING,	"YCbCrPositioning" },
    { TIFFTAG_REFERENCEBLACKWHITE, "ReferenceBlackWhite" },
    { TIFFTAG_REFPTS,		"IgReferencePoints (Island Graphics)" },
    { TIFFTAG_REGIONTACKPOINT,	"IgRegionTackPoint (Island Graphics)" },
    { TIFFTAG_REGIONWARPCORNERS,"IgRegionWarpCorners (Island Graphics)" },
    { TIFFTAG_REGIONAFFINE,	"IgRegionAffine (Island Graphics)" },
    { TIFFTAG_MATTEING,		"OBSOLETE Matteing (Silicon Graphics)" },
    { TIFFTAG_DATATYPE,		"OBSOLETE DataType (Silicon Graphics)" },
    { TIFFTAG_IMAGEDEPTH,	"ImageDepth (Silicon Graphics)" },
    { TIFFTAG_TILEDEPTH,	"TileDepth (Silicon Graphics)" },
    { 32768,			"OLD BOGUS Matteing tag" },
    { TIFFTAG_COPYRIGHT,	"Copyright" },
    { TIFFTAG_ICCPROFILE,	"ICC Profile" },
    { TIFFTAG_JBIGOPTIONS,	"JBIG Options" },
    { TIFFTAG_STONITS,		"StoNits" },
};
#define	NTAGS	(sizeof (tagnames) / sizeof (tagnames[0]))

static void
PrintTag(FILE* fd, uint16 tag)
{
	register struct tagname *tp;

	for (tp = tagnames; tp < &tagnames[NTAGS]; tp++)
		if (tp->tag == tag) {
			fprintf(fd, "%s (%u)", tp->name, tag);
			return;
		}
	fprintf(fd, "%u (%#x)", tag, tag);
}

static void
PrintType(FILE* fd, uint16 type)
{
	static char *typenames[] = {
	    "0",
	    "BYTE",
	    "ASCII",
	    "SHORT",
	    "LONG",
	    "RATIONAL",
	    "SBYTE",
	    "UNDEFINED",
	    "SSHORT",
	    "SLONG",
	    "SRATIONAL",
	    "FLOAT",
	    "DOUBLE"
	};
#define	NTYPES	(sizeof (typenames) / sizeof (typenames[0]))

	if (type < NTYPES)
		fprintf(fd, "%s (%u)", typenames[type], type);
	else
		fprintf(fd, "%u (%#x)", type, type);
}
#undef	NTYPES

static void
PrintByte(FILE* fd, const char* fmt, TIFFDirEntry* dp)
{
	char* sep = "";

	if (hdr.tiff_magic == TIFF_BIGENDIAN) {
		switch ((int)dp->tdir_count) {
		case 4: fprintf(fd, fmt, sep, dp->tdir_offset&0xff);
			sep = " ";
		case 3: fprintf(fd, fmt, sep, (dp->tdir_offset>>8)&0xff);
			sep = " ";
		case 2: fprintf(fd, fmt, sep, (dp->tdir_offset>>16)&0xff);
			sep = " ";
		case 1: fprintf(fd, fmt, sep, dp->tdir_offset>>24);
		}
	} else {
		switch ((int)dp->tdir_count) {
		case 4: fprintf(fd, fmt, sep, dp->tdir_offset>>24);
			sep = " ";
		case 3: fprintf(fd, fmt, sep, (dp->tdir_offset>>16)&0xff);
			sep = " ";
		case 2: fprintf(fd, fmt, sep, (dp->tdir_offset>>8)&0xff);
			sep = " ";
		case 1: fprintf(fd, fmt, sep, dp->tdir_offset&0xff);
		}
	}
}

static void
PrintShort(FILE* fd, const char* fmt, TIFFDirEntry* dp)
{
	char *sep = "";

	if (hdr.tiff_magic == TIFF_BIGENDIAN) {
		switch (dp->tdir_count) {
		case 2: fprintf(fd, fmt, sep, dp->tdir_offset&0xffff);
			sep = " ";
		case 1: fprintf(fd, fmt, sep, dp->tdir_offset>>16);
		}
	} else {
		switch (dp->tdir_count) {
		case 2: fprintf(fd, fmt, sep, dp->tdir_offset>>16);
			sep = " ";
		case 1: fprintf(fd, fmt, sep, dp->tdir_offset&0xffff);
		}
	}
}

static void
PrintLong(FILE* fd, const char* fmt, TIFFDirEntry* dp)
{
	fprintf(fd, fmt, "", (long) dp->tdir_offset);
}

#include <ctype.h>

static void
PrintASCII(FILE* fd, uint32 cc, const unsigned char* cp)
{
	for (; cc > 0; cc--, cp++) {
		const char* tp;

		if (isprint(*cp)) {
			fputc(*cp, fd);
			continue;
		}
		for (tp = "\tt\bb\rr\nn\vv"; *tp; tp++)
			if (*tp++ == *cp)
				break;
		if (*tp)
			fprintf(fd, "\\%c", *tp);
		else if (*cp)
			fprintf(fd, "\\%03o", *cp);
		else
			fprintf(fd, "\\0");
	}
}

static void
PrintData(FILE* fd, uint16 type, uint32 count, unsigned char* data)
{
	char* sep = "";

	switch (type) {
	case TIFF_BYTE:
		while (count-- > 0)
			fprintf(fd, bytefmt, sep, *data++), sep = " ";
		break;
	case TIFF_SBYTE:
		while (count-- > 0)
			fprintf(fd, sbytefmt, sep, *(char *)data++), sep = " ";
		break;
	case TIFF_UNDEFINED:
		while (count-- > 0)
			fprintf(fd, bytefmt, sep, *data++), sep = " ";
		break;
	case TIFF_ASCII:
		PrintASCII(fd, count, data);
		break;
	case TIFF_SHORT: {
		uint16 *wp = (uint16*)data;
		while (count-- > 0)
			fprintf(fd, shortfmt, sep, *wp++), sep = " ";
		break;
	}
	case TIFF_SSHORT: {
		int16 *wp = (int16*)data;
		while (count-- > 0)
			fprintf(fd, sshortfmt, sep, *wp++), sep = " ";
		break;
	}
	case TIFF_LONG: {
		uint32 *lp = (uint32*)data;
		while (count-- > 0) {
			fprintf(fd, longfmt, sep, (unsigned long) *lp++);
			sep = " ";
		}
		break;
	}
	case TIFF_SLONG: {
		int32 *lp = (int32*)data;
		while (count-- > 0)
			fprintf(fd, slongfmt, sep, (long) *lp++), sep = " ";
		break;
	}
	case TIFF_RATIONAL: {
		uint32 *lp = (uint32*)data;
		while (count-- > 0) {
			if (lp[1] == 0)
				fprintf(fd, "%sNan (%lu/%lu)", sep,
				    (unsigned long) lp[0],
				    (unsigned long) lp[1]);
			else
				fprintf(fd, rationalfmt, sep,
				    (double)lp[0] / (double)lp[1]);
			sep = " ";
			lp += 2;
		}
		break;
	}
	case TIFF_SRATIONAL: {
		int32 *lp = (int32*)data;
		while (count-- > 0) {
			if (lp[1] == 0)
				fprintf(fd, "%sNan (%ld/%ld)", sep,
				    (long) lp[0], (long) lp[1]);
			else
				fprintf(fd, srationalfmt, sep,
				    (double)lp[0] / (double)lp[1]);
			sep = " ";
			lp += 2;
		}
		break;
	}
	case TIFF_FLOAT: {
		float *fp = (float *)data;
		while (count-- > 0)
			fprintf(fd, floatfmt, sep, *fp++), sep = " ";
		break;
	}
	case TIFF_DOUBLE: {
		double *dp = (double *)data;
		while (count-- > 0)
			fprintf(fd, doublefmt, sep, *dp++), sep = " ";
		break;
	}
	case TIFF_IFD: {
		uint32 *lp = (uint32*)data;
		while (count-- > 0) {
			fprintf(fd, ifdfmt, sep, (unsigned long) *lp++);
			sep = " ";
		}
		break;
	}
	}
}

/*
 * Fetch a contiguous directory item.
 */
static int
TIFFFetchData(int fd, TIFFDirEntry* dir, void* cp)
{
	int cc, w;

	w = (dir->tdir_type < NWIDTHS ? datawidth[dir->tdir_type] : 0);
	cc = dir->tdir_count * w;
	if (lseek(fd, (off_t)dir->tdir_offset, 0) != (off_t)-1
	    && read(fd, cp, cc) != -1) {
		if (swabflag) {
			switch (dir->tdir_type) {
			case TIFF_SHORT:
			case TIFF_SSHORT:
				TIFFSwabArrayOfShort((uint16*) cp,
				    dir->tdir_count);
				break;
			case TIFF_LONG:
			case TIFF_SLONG:
			case TIFF_FLOAT:
			case TIFF_IFD:
				TIFFSwabArrayOfLong((uint32*) cp,
				    dir->tdir_count);
				break;
			case TIFF_RATIONAL:
				TIFFSwabArrayOfLong((uint32*) cp,
				    2*dir->tdir_count);
				break;
			case TIFF_DOUBLE:
				TIFFSwabArrayOfDouble((double*) cp,
				    dir->tdir_count);
				break;
			}
		}
		return (cc);
	}
	Error("Error while reading data for tag %u", dir->tdir_tag);
	return (0);
}

static void
ReadError(char* what)
{
	Fatal("Error while reading %s", what);
}

#include <stdarg.h>

static void
vError(FILE* fd, const char* fmt, va_list ap)
{
	fprintf(fd, "%s: ", curfile);
	vfprintf(fd, fmt, ap);
	fprintf(fd, ".\n");
}

static void
Error(const char* fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vError(stderr, fmt, ap);
	va_end(ap);
}

static void
Fatal(const char* fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vError(stderr, fmt, ap);
	va_end(ap);
	exit(-1);
}

/* vim: set ts=8 sts=8 sw=8 noet: */
