#ifdef __APPLE__

/* Define to 1 if you have the <assert.h> header file. */
#define HAVE_ASSERT_H 1

/* Define to 1 if you have the <fcntl.h> header file. */
#define HAVE_FCNTL_H 1

/* Define as 0 or 1 according to the floating point format suported by the
   machine */
#define HAVE_IEEEFP 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <io.h> header file. */
/* #undef HAVE_IO_H */

/* Define to 1 if you have the <search.h> header file. */
#define HAVE_SEARCH_H 1

/* The size of a `int', as computed by sizeof. */
#define SIZEOF_INT 4

/* The size of a `long', as computed by sizeof. */
#ifdef __LP64__
#define SIZEOF_LONG 8
#else
#define SIZEOF_LONG 4
#endif

#if __BIG_ENDIAN__
    /* Set the native cpu bit order */
    #define HOST_FILLORDER FILLORDER_MSB2LSB
    
    /* Define to 1 if your processor stores words with the most significant byte
    first (like Motorola and SPARC, unlike Intel and VAX). */
    #define WORDS_BIGENDIAN 1
#else
    /* Set the native cpu bit order */
    #define HOST_FILLORDER FILLORDER_LSB2MSB
    
    /* Define to 1 if your processor stores words with the most significant byte
        first (like Motorola and SPARC, unlike Intel and VAX). */
    /* #undef WORDS_BIGENDIAN */
#endif

/* Define to `__inline__' or `__inline' if that's what the C compiler
   calls it, or to nothing if 'inline' is not supported under any name.  */
#ifndef __cplusplus
# ifndef inline
#  define inline __inline
# endif
#endif

#else /* __APPLE__ */

/* Define to 1 if you have the <assert.h> header file. */
#define HAVE_ASSERT_H 1

/* Define to 1 if you have the <fcntl.h> header file. */
#define HAVE_FCNTL_H 1

/* Define as 0 or 1 according to the floating point format suported by the
   machine */
#define HAVE_IEEEFP 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <io.h> header file. */
#define HAVE_IO_H 1

/* Define to 1 if you have the <search.h> header file. */
#define HAVE_SEARCH_H 1

/* The size of a `int', as computed by sizeof. */
#define SIZEOF_INT 4

/* The size of a `long', as computed by sizeof. */
#define SIZEOF_LONG 4

/* Set the native cpu bit order */
#define HOST_FILLORDER FILLORDER_LSB2MSB

/* Define to 1 if your processor stores words with the most significant byte
   first (like Motorola and SPARC, unlike Intel and VAX). */
/* #undef WORDS_BIGENDIAN */

/* Define to `__inline__' or `__inline' if that's what the C compiler
   calls it, or to nothing if 'inline' is not supported under any name.  */
#ifndef __cplusplus
# ifndef inline
#  define inline __inline
# endif
#endif

#if !defined (__BORLANDC__) && !defined (__WATCOMC__)
   #define lfind _lfind
#endif

#ifdef __DMC__
#define HAVE_INT32
typedef	long int32;
#endif

#ifdef _WIN32_WCE
#   undef HAVE_FCNTL_H
#   undef HAVE_SYS_TYPES_H

    /*
       CE headers don't define these standard constants (not even underscored
       versions), provide our own replacements as they seem to be only used in
       libtiff own code anyhow.
     */
#   define   O_RDONLY    0x0000
#   define   O_WRONLY    0x0001
#   define   O_RDWR      0x0002
#   define   O_CREAT     0x0100
#   define   O_TRUNC     0x0200
#   define   O_EXCL      0x0400
#endif /* _WIN32_WCE */

#endif /* __APPLE__/!__APPLE__ */
