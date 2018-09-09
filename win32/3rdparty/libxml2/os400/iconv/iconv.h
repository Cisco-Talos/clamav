/**
***     Declarations for the iconv wrappers.
***
***     See Copyright for the status of this software.
***
***     Author: Patrick Monnerat <pm@datasphere.ch>, DATASPHERE S.A.
**/

#ifndef __ICONV_H_
#define __ICONV_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>             /* For size_t. */


typedef void *  Iconv_t;


Iconv_t         IconvOpen(const char * tocode, const char * fromcode);
size_t          Iconv(Iconv_t cd, char * * inbuf, size_t * inbytesleft,
                                        char * * outbuf, size_t * outbytesleft);
int             IconvClose(Iconv_t cd);


#ifndef USE_SYSTEM_ICONV
#define iconv_t         Iconv_t
#define iconv_open      IconvOpen
#define iconv           Iconv
#define iconv_close     IconvClose
#endif


#ifdef __cplusplus
}
#endif

#endif
