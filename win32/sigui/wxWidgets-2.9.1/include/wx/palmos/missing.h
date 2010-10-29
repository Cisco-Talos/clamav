/******************************************************************************
 * Name:        include/wx/palmos/missing.h
 * Purpose:     the missing declarations for wxPalm
 * Author:      Yunhui Fu
 * Created:     2007-10-18
 * Modified by:
 * RCS-ID:      $Id$
 * Copyright:   (c) 2007 Yunhui Fu
 * Licence:     wxWindows licence
 ******************************************************************************/

#ifndef _PALMOS_STDIO_FAKE_H
#define _PALMOS_STDIO_FAKE_H

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <PalmTypes.h>
#include <MemoryMgr.h> // Core/System/
#include <StringMgr.h> // Core/System/
#include <UIResources.h> // alertRscType,MenuRscType
#include <ErrorMgr.h>
#include <DataMgr.h>

#ifdef __cplusplus
#define _PSF_BEGIN_EXTERN_C extern "C" {
#define _PSF_END_EXTERN_C }
#else
#define _PSF_BEGIN_EXTERN_C
#define _PSF_END_EXTERN_C
#endif

#if __WXPALMOS6__
    #include <wchar.h> // wint_t
    #include <unistd.h> // access(), rmdir()
    #include <time.h>
    #include <StatusBar.h>
    #include <Loader.h>
    #include <PalmTypesCompatibility.h> // UInt8,UInt16,...
#else
    #if !defined(__MWERKS__)
        #include <PenInputMgr.h>
    #endif

    #define uint32_t UInt32
    #define uint16_t UInt16
    #define uint8_t  UInt8
#endif // __WXPALMOS6__
#if __WXPALMOS6__
    #define POS_VFSImportDatabaseFromFile(a,b,cardno,d) VFSImportDatabaseFromFile(a,b,d)
    #define POS_VFSImportDatabaseFromFileCustom(a,b,cardno,d,e,f) VFSImportDatabaseFromFileCustom(a,b,d,e,f)
    #define POS_VFSExportDatabaseToFile(a,b,cardno,d) VFSExportDatabaseToFile(a,b,d)
    #define POS_VFSExportDatabaseToFileCustom(a,b,cardno,d,e,f) VFSExportDatabaseToFileCustom(a,b,d,e,f)
    #define POS_DmGetResource(a,b,c) DmGetResource(a,b,c)
    #define POS_FrmSetMenu(a,b,c)    FrmSetMenu(a,b,c)
    #define POS_FrmCustomAlert(a,b,c,d,e) FrmCustomAlert(a,b,c,d,e)
    #define POS_MemNumRAMHeaps()    MemNumRAMHeaps()
    #define POS_SysBatteryInfo(a,b,c,d,e,f,g,h) SysBatteryInfo(a,b,c,d,e,f,g,h)
#else // __WXPALMOS5__
    #define POS_VFSImportDatabaseFromFile(a,b,cardno,d) VFSImportDatabaseFromFile(a,b,cardno,d)
    #define POS_VFSImportDatabaseFromFileCustom(a,b,cardno,d,e,f) VFSImportDatabaseFromFileCustom(a,b,cardno,d,e,f)
    #define POS_VFSExportDatabaseToFile(a,b,cardno,d) VFSExportDatabaseToFile(a,b,d)
    #define POS_VFSExportDatabaseToFileCustom(a,b,cardno,d,e,f) VFSExportDatabaseToFileCustom(a,b,cardno,d,e,f)
    #define POS_DmGetResource(a,b,c) DmGetResource(b,c)
    #define POS_FrmSetMenu(a,b,c)    FrmSetMenu(a,c)
    #define POS_FrmCustomAlert(a,b,c,d,e) FrmCustomAlert(b,c,d,e)
    #define POS_MemNumRAMHeaps()    MemNumRAMHeaps(0)
    #define POS_SysBatteryInfo(a,b,c,d,e,f,g,h) SysBatteryInfo(a,b,c,e,f,g,h)
#define MemCardInfoV40 MemCardInfo
#define FileOpenV50 FileOpen
#define ExgDBWriteV40 ExgDBWrite
#define DmSortRecordInfoPtr SortRecordInfoPtr

#define ErrFatalErrorInContext(fileName, lineNum, errMsg) ErrDisplayFileLineMsg(fileName, lineNum, errMsg)
#endif // __WXPALMOS6__

_PSF_BEGIN_EXTERN_C

#if __WXPALMOS5__

#if defined(__MWERKS__)
//#include <unix_stdarg.h>
#endif

#if 1
#define strcpy(x,y)    StrCopy((char*)(x),(char*)(y))
#define strncpy(x,y,z) StrNCopy((x),(y),(z))
#define strcmp(x,y)    StrCompare((x),(y))
#define strcat(x,y)    StrCat((x),(y))
#define strlen(x)      StrLen((char*)(x))
#define strchr(x,y)    StrChr((x),(y))
#define strstr(x,y)    StrStr((x),(y))
#define strcasecmp(x,y) StrCaselessCompare((x),(y))

#define memcpy(x,y,z)  ((0 == MemMove((x),(void *)(y),(z))) ? (x) : (0))
#define memset(x,y,z)  (MemSet((x),(z),(y)))
#define memcmp(x,y,z)  (MemCmp((x),(y),(z)))
#endif

#include "sections.h"
#ifndef int8_t
#define int8_t char
#define int16_t short
#define int64_t long long
#define uint64_t unsigned int64_t

#endif
#define wint_t int

#define ssize_t long
#define size_t  uint32_t
#define off_t ssize_t

#if 0
#undef malloc
#undef realloc
#undef free
#define malloc(x) MemPtrNew(x)
#define free(x) MemPtrFree(x)
void * realloc (void *p, size_t newsize);
#endif
char * strdup (const char *old);

// copy from Core/System/Unix/unix_stdio.h
#ifndef _STDLIB
    #define sprintf StrPrintF
    #define vsprintf(x,y,z) StrVPrintF(x,(const Char *)y,z)
#else
    int vsprintf(char *, const char *, _Va_list);
#endif
int sscanf(const char *, const char *, ...);

///////////////////// time ////////////////////
#define time_t uint64_t
time_t time(time_t *T);

struct tm {
    int8_t tm_gmtoff;
    int8_t tm_isdst;
    uint8_t tm_sec;
    uint8_t tm_min;
    uint8_t tm_hour;
    uint8_t tm_wday;
    uint8_t tm_mday;
    uint8_t tm_mon;
    uint16_t tm_yday;
    uint64_t tm_year;
};

#define HAVE_LOCALTIME_R 1
extern struct tm *localtime (const time_t *CLOCK); // datetime.cpp: GetTmNow(void)
extern struct tm *localtime_r (const time_t *CLOCK, struct tm *RES);

#define HAVE_GMTIME_R 1
extern struct tm *gmtime (const time_t *CLOCK);
extern struct tm *gmtime_r (const time_t *CLOCK, struct tm *RES);

extern time_t mktime (struct tm *TIMP);
double difftime (time_t TIM1, time_t TIM2);

char *ctime(const time_t *CLOCK);
char *ctime_r(const time_t *CLOCK, char *BUF);

//#define HAVE_STRFTIME 1
extern size_t strftime(char *S, size_t MAXSIZE, const char *FORMAT, const struct tm *TIMP);

///////////////////// locale.h ////////////////////
struct lconv
{
  char *decimal_point;
  char *thousands_sep;
  char *grouping;
  char *int_curr_symbol;
  char *currency_symbol;
  char *mon_decimal_point;
  char *mon_thousands_sep;
  char *mon_grouping;
  char *positive_sign;
  char *negative_sign;
  char int_frac_digits;
  char frac_digits;
  char p_cs_precedes;
  char p_sep_by_space;
  char n_cs_precedes;
  char n_sep_by_space;
  char p_sign_posn;
  char n_sign_posn;
};
char *setlocale(int CATEGORY, const char *LOCALE);
struct lconv *localeconv(void);

char *_setlocale_r(void *REENT, int CATEGORY, const char *LOCALE);
struct lconv *_localeconv_r(void *REENT);
///////////////////// stdlib.h ////////////////////

#if !defined(__MWERKS__)
    #if !defined(__WCHAR_TYPE__) || \
        (!defined(__GNUC__) || wxCHECK_GCC_VERSION(2, 96))
        #define wchar_t int
    #else /* __WCHAR_TYPE__ and gcc < 2.96 */
        #define wchar_t __WCHAR_TYPE__
    #endif /* __WCHAR_TYPE__ */
#endif
int _watoi(wchar_t * nptr);
long _watol(wchar_t * nptr);
double _watof(wchar_t *nptr);
#define watoi(a) _watoi((wchar_t *)(a))
#define watol(a) _watol((wchar_t *)(a))
#define watof(a) _watof((wchar_t *)(a))
int mbstowcs(wchar_t *PWC, const char *S, size_t N);
int wcstombs(const char *S, wchar_t *PWC, size_t N);

///////////////////// fcntl.h ////////////////////
#define    O_RDONLY    0x01
#define    O_WRONLY    0x02
#define    O_RDWR    0x04
#define    O_APPEND    0x08
#define    O_CREAT   0x10
#define    O_TRUNC   0x20
#define    O_EXCL    0x40
#define O_SYNC    0x80

// io.h
int open (const char*, int, ...);
int read (int, void*, unsigned int);
int write (int, const void*, unsigned int);
int close (int);
long lseek (int, long, int);

///////////////////// stdio.h ////////////////////
int remove(const char *FILENAME);
int rename(const char *OLD, const char *NEW);

///////////////////// unistd.h ////////////////////
int access (const char *path, int amode);
int rmdir (const char *path);

///////////////////// FILE ////////////////////
#ifndef NULL
#define NULL ((void *)(0))
#endif

#define FILE void
#undef stdin
#undef stdout
#undef stderr
#define stdin NULL
#define stdout NULL
#define stderr NULL

#define    SEEK_SET    0    /* set file offset to offset */
#define    SEEK_CUR    1    /* set file offset to current plus offset */
#define    SEEK_END    2    /* set file offset to EOF plus offset */

FILE *    fopen (const char *_name, const char *_type);
int    fclose (FILE *);
size_t fread (void *buf, size_t _size, size_t _n, FILE *);
size_t    fwrite (const void *buf , size_t _size, size_t _n, FILE *);
int    fseek (FILE *, long, int);
long ftell ( FILE *);
int    feof (FILE *);
int    ferror (FILE *);
void clearerr (FILE *);
FILE *freopen(const char *fn, const char *mode, FILE *fp);
//FILE *_freopen_r(struct _reent *PTR, const char *fn, const char *mode, FILE *fp);

extern int fflush (FILE *FP);
extern int fputs (const char *S, FILE *FP);
extern int fputc (int CH, FILE *FP);

//int printf(const char *format, ...);
int fprintf(FILE *stream, const char *format, ...);
//int sprintf(char *str, const char *format, ...);
//int snprintf(char *str, size_t size, const char *format, ...);
//int vfprintf(FILE * restrict stream, const char * restrict format, va_list ap);
//int vsprintf(char * restrict str, const char * restrict format, va_list ap);
//int vsnprintf(char * restrict str, size_t size, const char * restrict format, va_list ap);
int vsscanf (const char *s, const char *format, va_list param);

///////////////////// string ////////////////////
char *strerror(int ERRNUM);

///////////////////// ctype.h ////////////////////
extern int isascii(int C);

///////////////////// stdlib ////////////////////
void qsort(void *base, size_t nmemb, size_t size, int (*compar)(const void *, const void *));
void qsort_r(void *base, size_t nmemb, size_t size, void *thunk, int (*compar)(void *, const void *, const void *));
//int heapsort(void *base, size_t nmemb, size_t size, int (*compar)(const void *, const void *));
//int mergesort(void *base, size_t nmemb, size_t size, int (*compar)(const void *, const void *));
void *bsearch(const void *key, const void *base, size_t nmemb,size_t size, int (*compar)(const void *, const void *));

char *getenv(const char *NAME);

double atof(const char *S);
double strtod(const char *STR, char **TAIL);
double _strtod_r(void *REENT, const char *STR, char **TAIL);

///////////////////// math.h ////////////////////
#define __IMPORT

union __dmath
{
  unsigned long i[2];
  double d;
};

union __fmath
{
  unsigned long i[1];
  float f;
};

union __ldmath
{
  unsigned long i[4];
  long double ld;
};
#if defined(__GNUC__) && \
  ( (__GNUC__ >= 4) || \
    ( (__GNUC__ >= 3) && defined(__GNUC_MINOR__) && (__GNUC_MINOR__ >= 3) ) )

 /* gcc >= 3.3 implicitly defines builtins for HUGE_VALx values.  */

 #ifndef HUGE_VAL
  #define HUGE_VAL (__builtin_huge_val())
 #endif

 #ifndef HUGE_VALF
  #define HUGE_VALF (__builtin_huge_valf())
 #endif

 #ifndef HUGE_VALL
  #define HUGE_VALL (__builtin_huge_vall())
 #endif

#else /* !gcc >= 3.3  */

 /* No builtins.  Use floating-point unions instead.  Declare as an array
    without bounds so no matter what small data support a port and/or
    library has, the reference will be via the general method for accessing
    globals. */

 #ifndef HUGE_VAL
  extern __IMPORT const union __dmath __infinity[];
  #define HUGE_VAL (__infinity[0].d)
 #endif

 #ifndef HUGE_VALF
  extern __IMPORT const union __fmath __infinityf[];
  #define HUGE_VALF (__infinityf[0].f)
 #endif

 #ifndef HUGE_VALL
  extern __IMPORT const union __ldmath __infinityld[];
  #define HUGE_VALL (__infinityld[0].ld)
 #endif

#endif /* !gcc >= 3.3  */
#undef __IMPORT

///////////////////// PalmOS6 ////////////////////
#define status_t Err

// TimeMgr.h
time_t SysTimeToMilliSecs(time_t systime);
time_t SysTimeInSecs(time_t secs);

///////////////////// END ////////////////////

#endif // __WXPALMOS5__

///////////////////// wctype.h ////////////////////
extern int iswalnum(wint_t C);
extern int iswalpha(wint_t C);
extern int iswcntrl(wint_t C);
extern int iswdigit(wint_t C);
extern int iswgraph(wint_t C);
extern int iswlower(wint_t C);
extern int iswprint(wint_t C);
extern int iswpunct(wint_t C);
extern int iswspace(wint_t C);
extern int iswupper(wint_t C);
extern int iswxdigit(wint_t C);

extern wint_t towlower(wint_t C);
extern wint_t towupper(wint_t C);
extern size_t wcsftime(wchar_t *strDest, size_t maxsize, const wchar_t *format, const struct tm *timeptr);

size_t wcslen (const wchar_t * str);
wchar_t * wcscpy (wchar_t * dst, const wchar_t * src);
wchar_t * wcsncpy (wchar_t * dst, const wchar_t * src, size_t n);
wchar_t * wcscat (wchar_t * dst, const wchar_t * src);
wchar_t * wcsncat (wchar_t * dst, const wchar_t * src, size_t n);
int wcscmp (const wchar_t * str1, const wchar_t * str2);
int wcsncmp (const wchar_t * str1, const wchar_t * str2, size_t n);
wchar_t * wcschr (const wchar_t * str, const wchar_t chr);
int wcscoll (const wchar_t *str1, const wchar_t * str2);
size_t wcsxfrm (wchar_t * str1, const wchar_t * str2, size_t n);
wchar_t * wcsrchr (const wchar_t * str, wchar_t chr);
wchar_t * wcspbrk (const wchar_t * str, const wchar_t * set);
size_t wcsspn (const wchar_t * str, const wchar_t * set);
size_t wcscspn (const wchar_t * str, const wchar_t * set);
wchar_t * wcsstr (const wchar_t * str, const wchar_t * pat);
wchar_t * wcstok (wchar_t * str, const wchar_t * set, wchar_t ** );

long wcstol (const wchar_t * str, wchar_t ** end, int base);
unsigned long wcstoul (const wchar_t * a, wchar_t ** b, int c);
double wcstod (const wchar_t * a, wchar_t ** b);

char * setlocale (int category, const char *locale);

#define O_BINARY 0x00 /* for DOS compability */
extern int eof(int fd);
//extern int remove(const char *fn);
extern int access(const char *path, int amode);
extern off_t lseek(int fildes, off_t offset, int whence);

//TxtCharIsAlNum
//#define isalpha(a) TxtCharIsAlpha(a)
//TxtCharIsCntrl TxtCharIsDelim TxtCharIsDigit TxtCharIsGraph TxtCharIsHardKey TxtCharIsHex TxtCharIsLower TxtCharIsPrint TxtCharIsPunct TxtCharIsSpace TxtCharIsUpper

#include "pfall.h"

_PSF_END_EXTERN_C

#endif // _PALMOS_STDIO_FAKE_H
