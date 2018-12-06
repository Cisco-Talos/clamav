# Define a warning for the user, so they don't edit clamav-types.h
AC_SUBST(GENERATE_WARNING, ["Warning: This file is generated with ./configure. Do not edit!"])

# Initialize definitions to empty strings, in case they're not needed.
AC_SUBST(INT8_DEF, [""])
AC_SUBST(UINT8_DEF, [""])
AC_SUBST(INT16_DEF, [""])
AC_SUBST(UINT16_DEF, [""])
AC_SUBST(INT32_DEF, [""])
AC_SUBST(UINT32_DEF, [""])
AC_SUBST(INT64_DEF, [""])
AC_SUBST(UINT64_DEF, [""])

# Check sys/int_types.h first, to give it higher priority on Solaris
AC_CHECK_HEADER(
    [sys/int_types.h], 
    [ dnl Found
        AC_SUBST(INT_TYPES_HEADER, ["#include <sys/int_types.h>"])
    ], 
    [ dnl Not-found
        AC_CHECK_HEADER(
            [inttypes.h], 
            [ dnl Found; C99: inttypes.h should include stdint.h; more universal because some older platforms don't provide stdint.h
                AC_SUBST(INT_TYPES_HEADER, ["#include <inttypes.h>"])
            ], 
            [ dnl Not-found
                AC_CHECK_HEADER(
                    [stdint.h], 
                    [ dnl Found
                        AC_SUBST(INT_TYPES_HEADER, ["#include <stdint.h>"])
                    ], 
                    [ dnl Not-found
                        AC_COMPILE_IFELSE(
                            [ dnl Check if Windows (Cygwin), using auto-defined _MSC_VER
                                AC_LANG_PROGRAM([
                                    [
                                        #ifndef _MSC_VER
                                            error: _MSC_VER not found!
                                        #endif]
                                    ]
                                )
                            ],
                            [ dnl It's Windows, stdint.h should exist.
                                AC_SUBST(INT_TYPES_HEADER, ["#include <stdint.h>"])
                            ],
                            [ dnl No int types header available. We'll define the types manually.
                                AC_SUBST(INT8_DEF, ["typedef signed char int8_t;"])
                                AC_SUBST(UINT8_DEF, ["typedef unsigned char uint8_t;"])

                                if test $ac_cv_sizeof_int = 2; then 
                                    AC_SUBST(INT16_DEF, ["typedef signed int int16_t;"])
                                    AC_SUBST(UINT16_DEF, ["typedef unsigned int uint16_t;"])
                                elif test $ac_cv_sizeof_short = 2; then 
                                    AC_SUBST(INT16_DEF, ["typedef signed short int16_t;"])
                                    AC_SUBST(UINT16_DEF, ["typedef unsigned short uint16_t;"])
                                fi

                                if test $ac_cv_sizeof_int = 4; then 
                                    AC_SUBST(INT32_DEF, ["typedef signed int int32_t;"])
                                    AC_SUBST(UINT32_DEF, ["typedef unsigned int uint32_t;"])
                                elif test $ac_cv_sizeof_long = 4; then 
                                    AC_SUBST(INT32_DEF, ["typedef signed long int32_t;"])
                                    AC_SUBST(UINT32_DEF, ["typedef unsigned long uint32_t;"])
                                fi

                                if test $ac_cv_sizeof_long = 8; then 
                                    AC_SUBST(INT64_DEF, ["typedef signed long int64_t;"])
                                    AC_SUBST(UINT64_DEF, ["typedef unsigned long uint64_t;"])
                                elif test $ac_cv_sizeof_long_long = 8; then 
                                    AC_SUBST(INT64_DEF, ["typedef signed long long int64_t;"])
                                    AC_SUBST(UINT64_DEF, ["typedef unsigned long long uint64_t;"])
                                fi
                            ]
                        )
                    ],
                )
            ],
        )
    ],
)

# If _SF64_PREFIX isn't defined, this may be used.
if test $ac_cv_sizeof_int = 4; then 
    AC_SUBST(DEFINE_SF32_PREFIX, ["#define _SF32_PREFIX \"\""])
elif test $ac_cv_sizeof_long = 4; then 
    AC_SUBST(DEFINE_SF32_PREFIX, ["#define _SF32_PREFIX \"l\""])
fi

# If _SF32_PREFIX isn't defined, this may be used.
if test $ac_cv_sizeof_long = 8; then 
    AC_SUBST(DEFINE_SF64_PREFIX, ["#define _SF64_PREFIX \"l\""])
elif test $ac_cv_sizeof_long_long = 8; then 
    AC_SUBST(DEFINE_SF64_PREFIX, ["#define _SF64_PREFIX \"ll\""])
fi
