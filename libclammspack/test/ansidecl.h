/* Compiler compatibility macros
   Copyright (C) 1991-2024 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston, MA 02110-1301, USA.  */

/* For ease of writing code which uses GCC extensions but needs to be
   portable to other compilers, we provide the GCC_VERSION macro that
   simplifies testing __GNUC__ and __GNUC_MINOR__ together, and various
   wrappers around __attribute__.  Also, __extension__ will be #defined
   to nothing if it doesn't work.  See below.  */

#ifndef	_ANSIDECL_H
#define _ANSIDECL_H	1

#ifdef __cplusplus
extern "C" {
#endif

/* Every source file includes this file,
   so they will all get the switch for lint.  */
/* LINTLIBRARY */

/* Using MACRO(x,y) in cpp #if conditionals does not work with some
   older preprocessors.  Thus we can't define something like this:

#define HAVE_GCC_VERSION(MAJOR, MINOR) \
  (__GNUC__ > (MAJOR) || (__GNUC__ == (MAJOR) && __GNUC_MINOR__ >= (MINOR)))

and then test "#if HAVE_GCC_VERSION(2,7)".

So instead we use the macro below and test it against specific values.  */

/* This macro simplifies testing whether we are using gcc, and if it
   is of a particular minimum version. (Both major & minor numbers are
   significant.)  This macro will evaluate to 0 if we are not using
   gcc at all.  */
#ifndef GCC_VERSION
#define GCC_VERSION (__GNUC__ * 1000 + __GNUC_MINOR__)
#endif /* GCC_VERSION */

/* inline requires special treatment; it's in C99, and GCC >=2.7 supports
   it too, but it's not in C89.  */
#undef inline
#if (!defined(__cplusplus) && __STDC_VERSION__ >= 199901L) || defined(__cplusplus) || (defined(__SUNPRO_C) && defined(__C99FEATURES__))
/* it's a keyword */
#else
# if GCC_VERSION >= 2007
#  define inline __inline__   /* __inline__ prevents -pedantic warnings */
# else
#  define inline  /* nothing */
# endif
#endif

/* Define macros for some gcc attributes.  This permits us to use the
   macros freely, and know that they will come into play for the
   version of gcc in which they are supported.  */

#if (GCC_VERSION < 2007)
# define __attribute__(x)
#endif

/* Attribute __malloc__ on functions was valid as of gcc 2.96. */
#ifndef ATTRIBUTE_MALLOC
# if (GCC_VERSION >= 2096)
#  define ATTRIBUTE_MALLOC __attribute__ ((__malloc__))
# else
#  define ATTRIBUTE_MALLOC
# endif /* GNUC >= 2.96 */
#endif /* ATTRIBUTE_MALLOC */

/* Attributes on labels were valid as of gcc 2.93 and g++ 4.5.  For
   g++ an attribute on a label must be followed by a semicolon.  */
#ifndef ATTRIBUTE_UNUSED_LABEL
# ifndef __cplusplus
#  if GCC_VERSION >= 2093
#   define ATTRIBUTE_UNUSED_LABEL ATTRIBUTE_UNUSED
#  else
#   define ATTRIBUTE_UNUSED_LABEL
#  endif
# else
#  if GCC_VERSION >= 4005
#   define ATTRIBUTE_UNUSED_LABEL ATTRIBUTE_UNUSED ;
#  else
#   define ATTRIBUTE_UNUSED_LABEL
#  endif
# endif
#endif

/* Similarly to ARG_UNUSED below.  Prior to GCC 3.4, the C++ frontend
   couldn't parse attributes placed after the identifier name, and now
   the entire compiler is built with C++.  */
#ifndef ATTRIBUTE_UNUSED
#if GCC_VERSION >= 3004
#  define ATTRIBUTE_UNUSED __attribute__ ((__unused__))
#else
#define ATTRIBUTE_UNUSED
#endif
#endif /* ATTRIBUTE_UNUSED */

/* Before GCC 3.4, the C++ frontend couldn't parse attributes placed after the
   identifier name.  */
#if ! defined(__cplusplus) || (GCC_VERSION >= 3004)
# define ARG_UNUSED(NAME) NAME ATTRIBUTE_UNUSED
#else /* !__cplusplus || GNUC >= 3.4 */
# define ARG_UNUSED(NAME) NAME
#endif /* !__cplusplus || GNUC >= 3.4 */

#ifndef ATTRIBUTE_NORETURN
#define ATTRIBUTE_NORETURN __attribute__ ((__noreturn__))
#endif /* ATTRIBUTE_NORETURN */

/* Attribute `nonnull' was valid as of gcc 3.3.  */
#ifndef ATTRIBUTE_NONNULL
# if (GCC_VERSION >= 3003)
#  define ATTRIBUTE_NONNULL(m) __attribute__ ((__nonnull__ (m)))
# else
#  define ATTRIBUTE_NONNULL(m)
# endif /* GNUC >= 3.3 */
#endif /* ATTRIBUTE_NONNULL */

/* Attribute `returns_nonnull' was valid as of gcc 4.9.  */
#ifndef ATTRIBUTE_RETURNS_NONNULL
# if (GCC_VERSION >= 4009)
#  define ATTRIBUTE_RETURNS_NONNULL __attribute__ ((__returns_nonnull__))
# else
#  define ATTRIBUTE_RETURNS_NONNULL
# endif /* GNUC >= 4.9 */
#endif /* ATTRIBUTE_RETURNS_NONNULL */

/* Attribute `pure' was valid as of gcc 3.0.  */
#ifndef ATTRIBUTE_PURE
# if (GCC_VERSION >= 3000)
#  define ATTRIBUTE_PURE __attribute__ ((__pure__))
# else
#  define ATTRIBUTE_PURE
# endif /* GNUC >= 3.0 */
#endif /* ATTRIBUTE_PURE */

/* Use ATTRIBUTE_PRINTF when the format specifier must not be NULL.
   This was the case for the `printf' format attribute by itself
   before GCC 3.3, but as of 3.3 we need to add the `nonnull'
   attribute to retain this behavior.  */
#ifndef ATTRIBUTE_PRINTF
#define ATTRIBUTE_PRINTF(m, n) __attribute__ ((__format__ (__printf__, m, n))) ATTRIBUTE_NONNULL(m)
#define ATTRIBUTE_PRINTF_1 ATTRIBUTE_PRINTF(1, 2)
#define ATTRIBUTE_PRINTF_2 ATTRIBUTE_PRINTF(2, 3)
#define ATTRIBUTE_PRINTF_3 ATTRIBUTE_PRINTF(3, 4)
#define ATTRIBUTE_PRINTF_4 ATTRIBUTE_PRINTF(4, 5)
#define ATTRIBUTE_PRINTF_5 ATTRIBUTE_PRINTF(5, 6)
#endif /* ATTRIBUTE_PRINTF */

/* Use ATTRIBUTE_FPTR_PRINTF when the format attribute is to be set on
   a function pointer.  Format attributes were allowed on function
   pointers as of gcc 3.1.  */
#ifndef ATTRIBUTE_FPTR_PRINTF
# if (GCC_VERSION >= 3001)
#  define ATTRIBUTE_FPTR_PRINTF(m, n) ATTRIBUTE_PRINTF(m, n)
# else
#  define ATTRIBUTE_FPTR_PRINTF(m, n)
# endif /* GNUC >= 3.1 */
# define ATTRIBUTE_FPTR_PRINTF_1 ATTRIBUTE_FPTR_PRINTF(1, 2)
# define ATTRIBUTE_FPTR_PRINTF_2 ATTRIBUTE_FPTR_PRINTF(2, 3)
# define ATTRIBUTE_FPTR_PRINTF_3 ATTRIBUTE_FPTR_PRINTF(3, 4)
# define ATTRIBUTE_FPTR_PRINTF_4 ATTRIBUTE_FPTR_PRINTF(4, 5)
# define ATTRIBUTE_FPTR_PRINTF_5 ATTRIBUTE_FPTR_PRINTF(5, 6)
#endif /* ATTRIBUTE_FPTR_PRINTF */

/* Use ATTRIBUTE_NULL_PRINTF when the format specifier may be NULL.  A
   NULL format specifier was allowed as of gcc 3.3.  */
#ifndef ATTRIBUTE_NULL_PRINTF
# if (GCC_VERSION >= 3003)
#  define ATTRIBUTE_NULL_PRINTF(m, n) __attribute__ ((__format__ (__printf__, m, n)))
# else
#  define ATTRIBUTE_NULL_PRINTF(m, n)
# endif /* GNUC >= 3.3 */
# define ATTRIBUTE_NULL_PRINTF_1 ATTRIBUTE_NULL_PRINTF(1, 2)
# define ATTRIBUTE_NULL_PRINTF_2 ATTRIBUTE_NULL_PRINTF(2, 3)
# define ATTRIBUTE_NULL_PRINTF_3 ATTRIBUTE_NULL_PRINTF(3, 4)
# define ATTRIBUTE_NULL_PRINTF_4 ATTRIBUTE_NULL_PRINTF(4, 5)
# define ATTRIBUTE_NULL_PRINTF_5 ATTRIBUTE_NULL_PRINTF(5, 6)
#endif /* ATTRIBUTE_NULL_PRINTF */

/* Attribute `sentinel' was valid as of gcc 3.5.  */
#ifndef ATTRIBUTE_SENTINEL
# if (GCC_VERSION >= 3005)
#  define ATTRIBUTE_SENTINEL __attribute__ ((__sentinel__))
# else
#  define ATTRIBUTE_SENTINEL
# endif /* GNUC >= 3.5 */
#endif /* ATTRIBUTE_SENTINEL */


#ifndef ATTRIBUTE_ALIGNED_ALIGNOF
# if (GCC_VERSION >= 3000)
#  define ATTRIBUTE_ALIGNED_ALIGNOF(m) __attribute__ ((__aligned__ (__alignof__ (m))))
# else
#  define ATTRIBUTE_ALIGNED_ALIGNOF(m)
# endif /* GNUC >= 3.0 */
#endif /* ATTRIBUTE_ALIGNED_ALIGNOF */

/* Useful for structures whose layout must match some binary specification
   regardless of the alignment and padding qualities of the compiler.  */
#ifndef ATTRIBUTE_PACKED
# define ATTRIBUTE_PACKED __attribute__ ((packed))
#endif

/* Attribute `hot' and `cold' was valid as of gcc 4.3.  */
#ifndef ATTRIBUTE_COLD
# if (GCC_VERSION >= 4003)
#  define ATTRIBUTE_COLD __attribute__ ((__cold__))
# else
#  define ATTRIBUTE_COLD
# endif /* GNUC >= 4.3 */
#endif /* ATTRIBUTE_COLD */
#ifndef ATTRIBUTE_HOT
# if (GCC_VERSION >= 4003)
#  define ATTRIBUTE_HOT __attribute__ ((__hot__))
# else
#  define ATTRIBUTE_HOT
# endif /* GNUC >= 4.3 */
#endif /* ATTRIBUTE_HOT */

/* Attribute 'no_sanitize_undefined' was valid as of gcc 4.9.  */
#ifndef ATTRIBUTE_NO_SANITIZE_UNDEFINED
# if (GCC_VERSION >= 4009)
#  define ATTRIBUTE_NO_SANITIZE_UNDEFINED __attribute__ ((no_sanitize_undefined))
# else
#  define ATTRIBUTE_NO_SANITIZE_UNDEFINED
# endif /* GNUC >= 4.9 */
#endif /* ATTRIBUTE_NO_SANITIZE_UNDEFINED */

/* Attribute 'nonstring' was valid as of gcc 8.  */
#ifndef ATTRIBUTE_NONSTRING
# if GCC_VERSION >= 8000
#  define ATTRIBUTE_NONSTRING __attribute__ ((__nonstring__))
# else
#  define ATTRIBUTE_NONSTRING
# endif
#endif

/* Attribute `alloc_size' was valid as of gcc 4.3.  */
#ifndef ATTRIBUTE_RESULT_SIZE_1
# if (GCC_VERSION >= 4003)
#  define ATTRIBUTE_RESULT_SIZE_1 __attribute__ ((alloc_size (1)))
# else
#  define ATTRIBUTE_RESULT_SIZE_1
#endif
#endif

#ifndef ATTRIBUTE_RESULT_SIZE_2
# if (GCC_VERSION >= 4003)
#  define ATTRIBUTE_RESULT_SIZE_2 __attribute__ ((alloc_size (2)))
# else
#  define ATTRIBUTE_RESULT_SIZE_2
#endif
#endif

#ifndef ATTRIBUTE_RESULT_SIZE_1_2
# if (GCC_VERSION >= 4003)
#  define ATTRIBUTE_RESULT_SIZE_1_2 __attribute__ ((alloc_size (1, 2)))
# else
#  define ATTRIBUTE_RESULT_SIZE_1_2
#endif
#endif

/* Attribute `warn_unused_result' was valid as of gcc 3.3.  */
#ifndef ATTRIBUTE_WARN_UNUSED_RESULT
# if GCC_VERSION >= 3003
#  define ATTRIBUTE_WARN_UNUSED_RESULT __attribute__ ((__warn_unused_result__))
# else
#  define ATTRIBUTE_WARN_UNUSED_RESULT
# endif
#endif

/* We use __extension__ in some places to suppress -pedantic warnings
   about GCC extensions.  This feature didn't work properly before
   gcc 2.8.  */
#if GCC_VERSION < 2008
#define __extension__
#endif

/* This is used to declare a const variable which should be visible
   outside of the current compilation unit.  Use it as
     EXPORTED_CONST int i = 1;
   This is because the semantics of const are different in C and C++.
   "extern const" is permitted in C but it looks strange, and gcc
   warns about it when -Wc++-compat is not used.  */
#ifdef __cplusplus
#define EXPORTED_CONST extern const
#else
#define EXPORTED_CONST const
#endif

/* Be conservative and only use enum bitfields with C++ or GCC.
   FIXME: provide a complete autoconf test for buggy enum bitfields.  */

#ifdef __cplusplus
#define ENUM_BITFIELD(TYPE) enum TYPE
#elif (GCC_VERSION > 2000)
#define ENUM_BITFIELD(TYPE) __extension__ enum TYPE
#else
#define ENUM_BITFIELD(TYPE) unsigned int
#endif

#if defined(__cplusplus) && __cpp_constexpr >= 200704
#define CONSTEXPR constexpr
#else
#define CONSTEXPR
#endif

/* A macro to disable the copy constructor and assignment operator.
   When building with C++11 and above, the methods are explicitly
   deleted, causing a compile-time error if something tries to copy.
   For C++03, this just declares the methods, causing a link-time
   error if the methods end up called (assuming you don't
   define them).  For C++03, for best results, place the macro
   under the private: access specifier, like this,

   class name_lookup
   {
     private:
       DISABLE_COPY_AND_ASSIGN (name_lookup);
   };

   so that most attempts at copy are caught at compile-time.  */

#if defined(__cplusplus) && __cplusplus >= 201103
#define DISABLE_COPY_AND_ASSIGN(TYPE)		\
  TYPE (const TYPE&) = delete;			\
  void operator= (const TYPE &) = delete
  #else
#define DISABLE_COPY_AND_ASSIGN(TYPE)		\
  TYPE (const TYPE&);				\
  void operator= (const TYPE &)
#endif /* __cplusplus >= 201103 */

#ifdef __cplusplus
}
#endif

#endif	/* ansidecl.h	*/