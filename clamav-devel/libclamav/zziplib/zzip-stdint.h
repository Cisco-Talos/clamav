#ifndef _ZZIP__STDINT_H /* zzip-stdint.h */
#define _ZZIP__STDINT_H 1
/* this file ensures that we have some kind of typedef declarations for
   unsigned C9X typedefs. The ISO C 9X: 7.18 Integer types file is stdint.h
 */

#include <zzip-conf.h> 

/* enforce use of ifdef'd C9X entries in system headers */
#define __USE_ANSI 1
#define __USE_ISOC9X 1

#ifdef ZZIP_HAVE_STDINT_H
    /* ISO C 9X: 7.18 Integer types <stdint.h> */
#include <stdint.h>
#elif defined ZZIP_HAVE_SYS_INT_TYPES_H /*solaris*/
#include <sys/int_types.h>
#elif defined ZZIP_HAVE_INTTYPES_H /*freebsd*/
#include <inttypes.h>
#else
    typedef unsigned char uint8_t;      typedef signed char int8_t;

# if ZZIP_SIZEOF_INT && ZZIP_SIZEOF_INT == 2
    typedef unsigned int uint16_t;      typedef signed int int16_t;
# elif ZZIP_SIZEOF_SHORT && ZZIP_SIZEOF_SHORT == 2
    typedef unsigned short uint16_t;    typedef signed short int16_t;
# else
#   error unable to typedef int16_t from either int or short
    typedef unsigned short uint16_t;    typedef signed short int16_t;
# endif

# if defined ZZIP_SIZEOF_INT && ZZIP_SIZEOF_INT == 4
    typedef unsigned int uint32_t;      typedef signed int int32_t;
# elif defined ZZIP_SIZEOF_LONG && ZZIP_SIZEOF_LONG == 4
    typedef unsigned long uint32_t;     typedef signed long int32_t;
# else
#   error unable to typedef int32_t from either int or long
    typedef unsigned long uint32_t;     typedef signed long int32_t;
# endif
#endif

#endif /*_ZZIP_STDINT_H*/

