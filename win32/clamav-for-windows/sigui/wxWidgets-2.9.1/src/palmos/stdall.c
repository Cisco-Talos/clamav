/******************************************************************************
 * Name:        src/palmos/stdall.c
 * Purpose:     the missing functions of Palm OS for wxPalm
 * Author:      Yunhui Fu
 * Created:     2007-10-18
 * Modified by: 
 * RCS-ID:      $Id$
 * Copyright:   (c) 2007 Yunhui Fu
 * Licence:     wxWindows licence
 ******************************************************************************/

#include <Preferences.h> // Core/System/
#include <DateTime.h> //Core/System/, DateToAscii() etc.
#include <TimeMgr.h> //Core/System/, TimGetTicks()

#include "wx/defs.h"
#define PALMOS_TRACE(msg) ErrFatalErrorInContext(__FILE__, __LINE__, msg)

#if __WXPALMOS6__

#ifdef TARGET_PLATFORM
#if TARGET_PLATFORM != TARGET_PLATFORM_PALMSIM_WIN32
void
exit (int exitno)
{
}
#endif
#endif

#else

#define SEC_1904_1970 2082844800LU//0x7C25B080 // 0x7C25B080 == 2082844800LU

time_t
time (time_t *T)
{
    UInt32 sec;
    // UInt32 TimGetSeconds(void); // seconds since 1/1/1904
    // void TimSetSeconds (UInt32 seconds); // seconds since 1/1/1904
    // UInt32 TimGetTicks(void); // ticks since power on
    sec = TimGetSeconds ();
    if (T) {
        *T = sec - SEC_1904_1970;
    }
    return (sec - SEC_1904_1970);
}

static struct tm *
palmtimet2unixtm (const time_t t, struct tm *ptm)
{
    DateTimeType dt;
    memset (&dt, 0, sizeof (dt));
    memset (ptm, 0, sizeof (*ptm));
    TimSecondsToDateTime (t, &dt);
    ptm->tm_sec  = dt.second;
    ptm->tm_min  = dt.minute;
    ptm->tm_hour = dt.hour;
    ptm->tm_mday = dt.day;
    ptm->tm_mon  = dt.month;
    ptm->tm_year = dt.year;
    ptm->tm_wday = dt.weekDay;

    //ptm->tm_wday = DayOfWeek (dt.month, dt.day, dt.year);
    //ptm->tm_mday = DayOfMonth (dt.month, dt.day, dt.year);
    return ptm;
}

struct tm *
gmtime_r (const time_t *pt, struct tm *ptm)
{
    UInt32 utcTime;
    Int16 timeZone = PrefGetPreference(prefTimeZone);
    Int16 daylightSavingAdjustment = PrefGetPreference(prefDaylightSavingAdjustment);

    if ((NULL == pt) || (NULL == ptm)) {
        return NULL;
    }
    utcTime = TimTimeZoneToUTC (*pt + SEC_1904_1970, timeZone, daylightSavingAdjustment);
    palmtimet2unixtm (utcTime, ptm);
    return ptm;
}

struct tm *
localtime_r (const time_t *pt, struct tm *ptm)
{
    UInt32 utcTime;
    Int16 timeZone = PrefGetPreference(prefTimeZone);
    Int16 daylightSavingAdjustment = PrefGetPreference(prefDaylightSavingAdjustment);
    if ((NULL == pt) || (NULL == ptm)) {
        return NULL;
    }
    utcTime = TimUTCToTimeZone (*pt + SEC_1904_1970, timeZone, daylightSavingAdjustment);
    palmtimet2unixtm (utcTime, ptm);
    return ptm;
}
/*
static struct tm g_gmtime_info;

struct tm *
gmtime (const time_t *CLOCK)
{
    if (NULL == CLOCK) {
        return NULL;
    }
    if (NULL == gmtime_r (CLOCK, &g_gmtime_info)) {
        return NULL;
    }
    return &g_gmtime_info;
}
*/
static struct tm g_localtime_info;

struct tm *
localtime (const time_t *CLOCK)
{
    if (NULL == CLOCK) {
        return NULL;
    }
    if (NULL == localtime_r (CLOCK, &g_localtime_info)) {
        return NULL;
    }
    return &g_localtime_info;
}

static char * g_strftime_wdayconv[][2] = {
    {"Sun", "Sunday"},
    {"Mon", "Monday"},
    {"Tue", "Tuesday"},
    {"Wed", "Wednesday"},
    {"Thu", "Thursday"},
    {"Fri", "Friday"},
    {"Sat", "Saturday"},
};

static char * g_strftime_monconv[][2] = {
    {"Jan", "January"},
    {"Feb", "Febuary"},
    {"Mar", "March"},
    {"Apr", "April"},
    {"May", "May"},
    {"Jun", "June"},
    {"Jul", "July"},
    {"Aug", "August"},
    {"Sep", "September"},
    {"Oct", "October"},
    {"Nov", "November"},
    {"Dec", "December"},
};
#define SFCONV_ABBR 0
#define SFCONV_FULL 1

size_t
strftime (char *buf, size_t sz_buf, const char *fmt, const struct tm *ptm)
{
    char *p;
    char *pret;
    if ((timeStringLength > sz_buf) || (strlen (fmt) < 1)) {
        return 0;
    }
    memset (buf, 0, sz_buf);
    p = fmt;
    pret = buf;
    for (; *p != '\0';) {
        if ('%' == *p) {
            p ++;
            if (*p == '\0') {
                break;
            }
            // FIXME: test the overflow of the buffer
            switch (*p) {
            case 'a':
                strcpy (pret, g_strftime_wdayconv[ptm->tm_wday % 7][SFCONV_ABBR]);
                pret += 3;
                break;
            case 'A':
                strcpy (pret, g_strftime_wdayconv[ptm->tm_wday % 7][SFCONV_FULL]);
                pret += strlen (g_strftime_wdayconv[ptm->tm_wday % 7][SFCONV_FULL]);
                break;
            case 'b':
                strcpy (pret, g_strftime_monconv[ptm->tm_mon % 12][SFCONV_ABBR]);
                pret += 3;
                break;
            case 'B':
                strcpy (pret, g_strftime_monconv[ptm->tm_mon % 12][SFCONV_FULL]);
                pret += strlen (g_strftime_monconv[ptm->tm_mon % 12][SFCONV_FULL]);
                break;
            case 'c':
                strcpy (pret, g_strftime_wdayconv[ptm->tm_wday % 7][SFCONV_ABBR]);
                pret += 3;
                *pret = ' ';
                pret ++;
                strcpy (pret, g_strftime_monconv[ptm->tm_mon % 12][SFCONV_ABBR]);
                pret += 3;
                *pret = ' ';
                pret ++;
                sprintf (pret, "%d %02d:%02d:%02d %d", ptm->tm_mday,
                    ptm->tm_hour, ptm->tm_min, ptm->tm_sec, ptm->tm_year);
                pret += strlen (pret);
                break;
            case 'd':
                sprintf (pret, "%02d", ptm->tm_mday % 31);
                pret += 2;
                break;
            case 'H':
                sprintf (pret, "%02d", ptm->tm_hour % 24);
                pret += 2;
                break;
            case 'I':
                sprintf (pret, "%02d", (ptm->tm_hour % 12) + 1);
                pret += 2;
                break;
            case 'j':
                sprintf (pret, "%03d", ptm->tm_year % 400);
                pret += 3;
                break;
            case 'm':
                sprintf (pret, "%02d", (ptm->tm_mon % 12) + 1);
                pret += 2;
                break;
            case 'M':
                sprintf (pret, "%02d", ptm->tm_min % 60);
                pret += 2;
                break;
            case 'p':
                if (ptm->tm_hour > 12) {
                    strcpy (pret, "PM");
                    break;
                }
                strcpy (pret, "AM");
                pret += 2;
                break;
            case 'S':
                sprintf (pret, "%02d", ptm->tm_sec % 61);
                pret += 2;
                break;
            case 'U':
                // FIXME: Week number with the first Sunday as the first day of week one (00-53)
                sprintf (pret, "%02d", ptm->tm_yday / 7);
                pret += 2;
                break;
            case 'w':
                sprintf (pret, "%d", ptm->tm_wday % 7);
                pret += 1;
                break;
            case 'W':
                // FIXME: Week number with the first Sunday as the first day of week one (00-53)
                sprintf (pret, "%02d", ptm->tm_yday / 7);
                pret += 2;
                break;
            case 'x':
                sprintf (pret, "%02d/%02d/%02d",
                    ptm->tm_mon, ptm->tm_mday, ptm->tm_year - 1900);
                pret += strlen (pret);
                break;
            case 'X':
                sprintf (pret, "%02d:%02d:%02d",
                    ptm->tm_hour, ptm->tm_min, ptm->tm_sec);
                pret += strlen (pret);
                break;
            case 'y':
                sprintf (pret, "%02d", ptm->tm_year - 1900);
                pret += 2;
                break;
            case 'Y':
                sprintf (pret, "%02d", ptm->tm_year);
                pret += strlen (pret);
                break;
            case 'Z':
            {
                LmLocaleType ll;
                ll.language = lmAnyLanguage;
                ll.country = 0;
                TimeZoneToAscii (ptm->tm_gmtoff, &ll, pret);
            }
                pret += strlen (pret);
                break;
            case '%':
                *pret = *p;
                pret ++;
                break;
            }
        } else {
            *pret = *p;
            pret ++;
        }
        p ++;
    }
    return 0;
}

time_t
mktime (struct tm *ptm)
{
    DateTimeType dt;
    if (NULL == ptm) {
        return 0;
    }
    memset (&dt, 0, sizeof (dt));
    dt.second  = ptm->tm_sec;
    dt.minute  = ptm->tm_min;
    dt.hour    = ptm->tm_hour;
    dt.day     = ptm->tm_mday;
    dt.month   = ptm->tm_mon;
    dt.year    = ptm->tm_year;
    dt.weekDay = ptm->tm_wday;
    return TimDateTimeToSeconds (&dt);
}

int
vsscanf (const char *s, const char *format, va_list param)
{
    return -1;
}

FILE * fopen (const char *_name, const char *_type) {return NULL;}
int fclose (FILE *fp) {return 0;}
size_t fread (void *buf, size_t _size, size_t _n, FILE *fp) {return 0;}
size_t fwrite (const void *buf , size_t _size, size_t _n, FILE *fp) {return 0;}
int fseek (FILE *fp, long offset, int whence) {return -1;}
long ftell (FILE *fp) {return -1;}
int feof (FILE *fp) {return -1;}
int ferror (FILE *fp) {return -1;}
void clearerr (FILE *fp) {}

#endif // __WXPALMOS6__

#define _BIT_ALPHA  0X0001
#define _BIT_BLANK  0X0002
#define _BIT_CNTRL  0X0004
#define _BIT_DIGIT  0X0008
#define _BIT_GRAPH  0X0010
#define _BIT_LOWER  0X0020
#define _BIT_PRINT  0X0040
#define _BIT_PUNCT  0X0080
#define _BIT_SPACE  0X0100
#define _BIT_UPPER  0X0200
#define _BIT_XDIGIT 0X0400

int iswalnum(wint_t C) {return 0;}
int iswalpha(wint_t C) {return 0;}
int iswcntrl(wint_t C) {return 0;}
int iswdigit(wint_t C) {return 0;}
int iswgraph(wint_t C) {return 0;}
int iswlower(wint_t C) {return 0;}
int iswprint(wint_t C) {return 0;}
int iswpunct(wint_t C) {return 0;}
int iswspace(wint_t C) {return 0;}
int iswupper(wint_t C) {return 0;}
int iswxdigit(wint_t C) {return 0;}

wint_t towlower(wint_t C) {return 0;}
wint_t towupper(wint_t C) {return 0;}
size_t wcsftime(wchar_t *strDest, size_t maxsize, const wchar_t *format, const struct tm *timeptr) {return 0;}

size_t
wcslen (const wchar_t * str)
{
    size_t i;
    for (i = 0; str[i] != 0; i ++);
    return i;
}

wchar_t *
wcscpy (wchar_t * dst, const wchar_t * src)
{
    size_t len;
    len = wcslen (src);
    if (len < 1) {
        return NULL;
    }
    memmove (dst, src, len * sizeof (wchar_t));
    dst[len] = 0;
    return dst;
}

wchar_t *
wcsncpy (wchar_t * dst, const wchar_t * src, size_t len_max)
{
    size_t len;
    len = wcslen (src);
    if (len < 1) {
        return NULL;
    }
    if (len_max < len + 1) {
        len = len_max - 1;
    }
    if (len > 0) {
        memmove (dst, src, len * sizeof (wchar_t));
    }
    dst[len] = 0;
    return dst;
}

wchar_t *
wcscat (wchar_t * dst, const wchar_t * src)
{
    size_t len_dst;
    len_dst = wcslen (dst);
    return wcscpy (dst + len_dst, src);
}

wchar_t *
wcsncat (wchar_t * dst, const wchar_t * src, size_t n)
{
    size_t len_dst;
    len_dst = wcslen (dst);
    return wcsncpy (dst + len_dst, src, n);
}

#define SYS_IS_BIGENDIAN 0

#if SYS_IS_BIGENDIAN
#define _wcmcmp(a,b,len) memcmp((a),(b),(len) * sizeof (wchar_t))
#else // SYS_IS_BIGENDIAN
int
_wcmcmp (const wchar_t * str1, const wchar_t * str2, size_t len)
{
    size_t i;
    for (i = 0; i < len; i ++) {
        if (str1[i] == str2[i]) {
            continue;
        } else if (str1[i] < str2[i]) {
            return -1;
        }
        return 1;
    }
    return 0;
}
#endif // SYS_IS_BIGENDIAN

int
wcscmp (const wchar_t * str1, const wchar_t * str2)
{
    int ret;
    size_t len;
    size_t len1;
    size_t len2;
    len1 = wcslen (str1);
    len2 = wcslen (str2);
    len = len1;
    if (len > len2) {
        len = len2;
    }
    ret = _wcmcmp (str1, str2, len);
    if (0 == ret) {
        if (len1 > len2) {
            return -1;
        } else if (len1 == len2) {
            return 0;
        }
        return 1;
    }
    return ret;
}

int
wcsncmp (const wchar_t * str1, const wchar_t * str2, size_t n)
{
    int ret;
    size_t len;
    size_t len1;
    size_t len2;
    len1 = wcslen (str1);
    len2 = wcslen (str2);
    len = len1;
    if (len > len2) {
        len = len2;
    }
    if (len > n) {
        len = n;
    }
    ret = _wcmcmp (str1, str2, len);
    if (0 == ret) {
        if (len >= n) {
            return 0;
        }
        if (len1 > len2) {
            return -1;
        } else if (len1 == len2) {
            return 0;
        }
        return 1;
    }
    return ret;
}

wchar_t *
wcschr (const wchar_t * str, const wchar_t chr)
{
    wchar_t * str2 = (wchar_t *)str;
    size_t i;
    size_t len;
    len = wcslen (str2);
    for (i = 0; i < len; i ++) {
        if (str2[i] == chr) {
            str2 += i;
            return str2;
        }
    }
    return NULL;
}

int wcscoll (const wchar_t *str1, const wchar_t * str2) {return wcscmp(str1, str2);}

/*
 * wcsxfrm: Transfom the wide-char str2 and place the result into the str1,
 * return the length of the wide-char, return -1 on error.
 */
size_t
wcsxfrm (wchar_t * str1, const wchar_t * str2, size_t n)
{
    wcsncpy (str1, str2, n);
    return wcslen (str1);
}

wchar_t *
wcsrchr (const wchar_t * str, wchar_t chr)
{
    wchar_t * str2 = (wchar_t *)str;
    ssize_t i;
    i = wcslen (str2);
    for (; i >= 0; i ++) {
        if (str2[i] == chr) {
            str2 += i;
            return str2;
        }
    }
    return NULL;
}

wchar_t *
wcspbrk (const wchar_t * str, const wchar_t * set)
{
    wchar_t * str2 = (wchar_t *)str;
    size_t i;
    size_t j;
    size_t len;
    size_t len_set;
    len = wcslen (str2);
    len_set = wcslen (set);
    for (i = 0; i < len; i ++) {
        for (j = 0; j < len_set; j ++) {
            if (str2[i] == set[j]) {
                str2 += i;
                return str2;
            }
        }
    }
    return NULL;
}

/*
 * wcsspn: compute the maxinum initial segment of the wide-char str which consists entirely of wide-char codes from the set.
 * returnt he length of the initial substring of str
 * examples:
 * str="13134abcde", set="1234567890", wcsspn(str,set)==5
 * str="abcde", set="1234567890", wcsspn(str,set)==0
 */
size_t
wcsspn (const wchar_t * str, const wchar_t * set)
{
    size_t i;
    size_t j;
    size_t len;
    size_t len_set;
    len = wcslen (str);
    len_set = wcslen (set);
    for (i = 0; i < len; i ++) {
        for (j = 0; j < len_set; j ++) {
            if (str[i] == set[j]) {
                break;
            }
        }
        if (j >= len_set) {
            return i;
        }
    }
    return i;
}

/*
 * wcscspn: determines the length of the initial segment of str which consists entirely of characters not found in set.
 * examples:
 * str="13134abcde", set="1234567890", wcsspn(str,set)==0
 * str="abcde123", set="1234567890", wcsspn(str,set)==5
*/
size_t
wcscspn (const wchar_t * str, const wchar_t * set)
{
    size_t i;
    size_t j;
    size_t len;
    size_t len_set;
    len = wcslen (str);
    len_set = wcslen (set);
    for (i = 0; i < len; i ++) {
        for (j = 0; j < len_set; j ++) {
            if (str[i] == set[j]) {
                break;
            }
        }
        if (j < len_set) {
            return i;
        }
    }
    return i;
}

wchar_t *
wcsstr (const wchar_t * str, const wchar_t * pat)
{
    // TODO: improvement the alg for search
    wchar_t *p;
    p = wcschr (str, pat[0]);
    for (; NULL != p;) {
        if (0 == wcscmp (p, pat)) {
            return p;
        }
        p = wcschr (p, pat[0]);
    }
    return NULL;
}

wchar_t *
wcstok (wchar_t * str, const wchar_t * set, wchar_t ** a)
{
    wchar_t * p;
    if (NULL == str) {
        if (NULL == a) {
            return NULL;
        }
        str = *a;
    }
    if (NULL == str) {
        return NULL;
    }
    p = wcspbrk (str, set);
    if (NULL == p) {
        return NULL;
    }
    *p = 0;
    *a = p;
    return str;
}

#define iswblank iswspace
//#define ULONG_MAX INT_MAX
unsigned long
wcstoul (const wchar_t *nptr, wchar_t **endptr, int base)
{
    int flg_overflow;
    //int val_remain;
    unsigned long val_ch;
    unsigned long val_old;
    unsigned long val;
    /* check the base */
    if ((1 == base) || (base > 36) || (base < 0)) {
        // error
        return 0;
    }
    // skip blank
    while (iswblank (*nptr)) {nptr ++;}
    if (0 == *nptr) {
        return 0;
    }
    if (0 == base) {
        // auto detect
        switch (*nptr) {
        case '0':
            if (('x' == *(nptr + 1)) || ('X' == *(nptr + 1))) {
                base = 16;
                nptr += 2;
            } else {
                nptr += 1;
                base = 8;
            }
            break;
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9':
            base = 10;
            break;
        }
    } else {
        if (16 == base) {
            // detect if it has '0x' or '0X'
            if (('0' == *nptr) && (('x' == *(nptr + 1)) || ('x' == *(nptr + 1)))) {
                nptr += 2;
            }
        }
    }
    if (0 == base) {
        // error
        return 0;
    }
    val = 0;
    val_old = 0;
    flg_overflow = 0;
    //val_remain = ULONG_MAX % base;
    for (; '\0' != *nptr; nptr ++) {
        val_ch = *nptr;
        if (('0' <= val_ch) && (val_ch <= '9')) {
            val_ch -= '0';
        } else if (('a' <= val_ch) && (val_ch <= 'z')) {
            val_ch = val_ch - 'a' + 10;
        } else if (('A' <= val_ch) && (val_ch <= 'Z')) {
            val_ch = val_ch - 'A' + 10;
        } else {
            // val_ch = base + 1;
            break;
        }
        if (val_ch >= base) {
            break;
        }
        if (flg_overflow) continue;
        val_old = val;
        val *= base;
        val += val_ch;
        if (val_old > val) {
            flg_overflow = 1;
        }
    }
    if (flg_overflow) {
        val = ULONG_MAX;
    }
    if (0L != endptr) {
        *endptr = (wchar_t *)nptr;
    }
    return val;
}

long
wcstol (const wchar_t * str, wchar_t ** end, int base)
{
    int sign = 0;
    unsigned long val0;
    long val;
    wchar_t ch;
    // skip blank
    for (; iswblank (*str); str ++) {
    }
    for (ch = *str; (ch == '-') || (ch == '+'); str ++) {
    }
    // the sign
    if ('-' == ch) {
        sign = 1;
        str ++;
    }
    val0 = wcstoul (str, end, base);
    if (val0 >= LONG_MAX) {
        // overflow
        val = LONG_MAX;
        if (sign) {
            val = LONG_MIN;
        }
    } else {
        val = val0;
        if (sign) {
            val = -val0;
        }
    }
    return val;
}

double
wcstod (const wchar_t * str, wchar_t ** end)
{
    double val;
    double mantissa;
    unsigned long divisor;
    unsigned long power;
    int sign;
    int sign_power;
    wchar_t *pend;
    wchar_t ch;
    // skip blank
    for (; iswblank (*str); str ++) {
    }
    for (ch = *str; (ch == '-') || (ch == '+'); str ++) {
    }
    // the sign
    sign = 0;
    if ('-' == ch) {
        sign = 1;
        str ++;
    }
    // skip leading zero
    for (; '0' == (*str); str ++) {
    }
    val = 0.0;
    mantissa = 0.0;
    divisor = 0;
    power = 0.0;
    // integer part
    for (ch = *str; ('0' <= ch) && (ch <= '9'); str ++) {
        ch -= '0';
        val *= 10;
        val += ch;
    }
    // floating point & mantissa
    if ('.' == *str) {
        str ++;
        for (ch = *str; ('0' <= ch) && (ch <= '9'); str ++) {
            ch -= '0';
            mantissa *= 10.0;
            mantissa += ch;
            divisor ++;
        }
    }
    for (; divisor > 0; divisor --) {
        mantissa /= 10.0;
    }
    val += mantissa;
    sign_power = 0;
    if (('e' == *str) || ('E' == *str)) {
        str ++;
        if ('-' == ch) {
            sign_power = 1;
            str ++;
        }
        pend = NULL;
        power = wcstoul (str, &pend, 10);
        if (NULL != pend) {
            str = pend;
        }
    }
    if (power > 0) {
        if (sign_power) {
            for (; power > 0; power --) {
                val /= 10.0;
            }
        } else {
            for (; power > 0; power --) {
                val *= 10.0;
            }
        }
    }
    if (sign) {
        val = - val;
    }
    if (end) {
        *end = (wchar_t *)str;
    }
    return val;
}

char * setlocale (int category, const char *locale) {return NULL;}

int
eof (int fd)
{
    return 0;
}

int
remove (const char *fn)
{
    return svfs_filedelete (fn);
}

// access(): check access permissions of a file or pathname
// R_OK: read permission
// W_OK: write permission
// X_OK: execute/search permission
// F_OK: existence test
//All components of the pathname path are checked for access permissions (including F_OK)
int access(const char *path, int amode) {return amode;}

off_t lseek(int fildes, off_t offset, int whence) {return 0;}
