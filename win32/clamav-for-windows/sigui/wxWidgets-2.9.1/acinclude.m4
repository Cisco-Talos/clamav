dnl ---------------------------------------------------------------------------
dnl
dnl Macros for configure.in for wxWindows by Robert Roebling, Phil Blecker,
dnl Vadim Zeitlin and Ron Lee
dnl
dnl This script is under the wxWindows licence.
dnl
dnl Version: $Id$
dnl ---------------------------------------------------------------------------


dnl ===========================================================================
dnl Objective-C(++) related macros
dnl ===========================================================================
m4_define([AC_WX_LANG_OBJECTIVEC],
[AC_LANG(C)
ac_ext=m
])

m4_define([AC_WX_LANG_OBJECTIVECPLUSPLUS],
[AC_LANG(C++)
ac_ext=mm
])

dnl ===========================================================================
dnl macros to find the a file in the list of include/lib paths
dnl ===========================================================================

dnl ---------------------------------------------------------------------------
dnl call WX_PATH_FIND_INCLUDES(search path, header name), sets ac_find_includes
dnl to the full name of the file that was found or leaves it empty if not found
dnl ---------------------------------------------------------------------------
AC_DEFUN([WX_PATH_FIND_INCLUDES],
[
ac_find_includes=
for ac_dir in $1 /usr/include;
  do
    if test -f "$ac_dir/$2"; then
      ac_find_includes=$ac_dir
      break
    fi
  done
])

dnl ---------------------------------------------------------------------------
dnl call WX_PATH_FIND_LIBRARIES(search path, lib name), sets ac_find_libraries
dnl to the full name of the file that was found or leaves it empty if not found
dnl ---------------------------------------------------------------------------
AC_DEFUN([WX_PATH_FIND_LIBRARIES],
[
  ac_find_libraries=
  for ac_dir in $1;
  do
    for ac_extension in a so sl dylib dll.a; do
      if test -f "$ac_dir/lib$2.$ac_extension"; then
        ac_find_libraries=$ac_dir
        break 2
      fi
    done
  done
])

dnl ---------------------------------------------------------------------------
dnl return list of standard library paths
dnl ---------------------------------------------------------------------------
dnl return all default locations:
dnl   - /usr/lib: standard
dnl   - /usr/lib32: n32 ABI on IRIX
dnl   - /usr/lib64: n64 ABI on IRIX
dnl   - /usr/lib/64: 64 bit ABI on Solaris and Linux x86-64
dnl
dnl NB: if any of directories in the list is not a subdir of /usr, code setting
dnl     wx_cv_std_libpath needs to be updated
AC_DEFUN([WX_STD_LIBPATH], [/usr/lib /usr/lib32 /usr/lib/64 /usr/lib64])

dnl ---------------------------------------------------------------------------
dnl Path to include, already defined
dnl ---------------------------------------------------------------------------
AC_DEFUN([WX_INCLUDE_PATH_EXIST],
[
  dnl never add -I/usr/include to the CPPFLAGS
  if test "x$1" = "x/usr/include"; then
    ac_path_to_include=""
  else
    echo "$2" | grep "\-I$1" > /dev/null
    result=$?
    if test $result = 0; then
      ac_path_to_include=""
    else
      ac_path_to_include=" -I$1"
    fi
  fi
])

dnl ---------------------------------------------------------------------------
dnl Usage: WX_LINK_PATH_EXIST(path, libpath)
dnl
dnl Set ac_path_to_link to nothing if path is already in libpath of to -Lpath
dnl if it is not, so that libpath can be set to "$libpath$ac_path_to_link"
dnl after calling this function
dnl ---------------------------------------------------------------------------
AC_DEFUN([WX_LINK_PATH_EXIST],
[
  dnl never add -L/usr/libXXX explicitely to libpath
  if test "$1" = "default location"; then
    ac_path_to_link=""
  else
    echo "$2" | grep "\-L$1" > /dev/null
    result=$?
    if test $result = 0; then
      ac_path_to_link=""
    else
      ac_path_to_link=" -L$1"
    fi
  fi
])

dnl ===========================================================================
dnl C++ features test
dnl ===========================================================================

dnl ---------------------------------------------------------------------------
dnl WX_CPP_NEW_HEADERS checks whether the compiler has "new" <iostream> header
dnl or only the old <iostream.h> one - it may be generally assumed that if
dnl <iostream> exists, the other "new" headers (without .h) exist too.
dnl
dnl call WX_CPP_NEW_HEADERS(actiof-if-true, action-if-false)
dnl ---------------------------------------------------------------------------

AC_DEFUN([WX_CPP_NEW_HEADERS],
[
    AC_LANG_SAVE
    AC_LANG_CPLUSPLUS

    AC_CHECK_HEADERS([iostream],,, [ ])

    if test "$ac_cv_header_iostream" = "yes" ; then
      ifelse([$1], , :, [$1])
    else
      ifelse([$2], , :, [$2])
    fi

    AC_LANG_RESTORE
])

dnl ---------------------------------------------------------------------------
dnl WX_CPP_EXPLICIT checks whether the C++ compiler support the explicit
dnl keyword and defines HAVE_EXPLICIT if this is the case
dnl ---------------------------------------------------------------------------

AC_DEFUN([WX_CPP_EXPLICIT],
[
  AC_CACHE_CHECK([if C++ compiler supports the explicit keyword],
                 wx_cv_explicit,
  [
    AC_LANG_SAVE
    AC_LANG_CPLUSPLUS

    dnl do the test in 2 steps: first check that the compiler knows about the
    dnl explicit keyword at all and then verify that it really honours it
    AC_TRY_COMPILE(
      [
        class Foo { public: explicit Foo(int) {} };
      ],
      [
        return 0;
      ],
      [
        AC_TRY_COMPILE(
            [
                class Foo { public: explicit Foo(int) {} };
                static void TakeFoo(const Foo& foo) { }
            ],
            [
                TakeFoo(17);
                return 0;
            ],
            wx_cv_explicit=no,
            wx_cv_explicit=yes
        )
      ],
      wx_cv_explicit=no
    )

    AC_LANG_RESTORE
  ])

  if test "$wx_cv_explicit" = "yes"; then
    AC_DEFINE(HAVE_EXPLICIT)
  fi
])

dnl ---------------------------------------------------------------------------
dnl WX_CHECK_FUNCS(FUNCTIONS...,
dnl                [ACTION-IF-FOUND],
dnl                [ACTION-IF-NOT-FOUND],
dnl                [EXTRA-DEFINES-AND-INCLUDES],
dnl                [EXTRA-TEST-CODE])
dnl
dnl Checks that the functions listed in FUNCTIONS exist in the headers and the
dnl libs. For each function, if it is found then defines 'HAVE_FUNCTION' and
dnl executes ACTION-IF-FOUND, otherwise executes ACTION-IF-NOT-FOUND.
dnl
dnl The code from EXTRA-DEFINES-AND-INCLUDES is inserted into the test before
dnl the default headers are included, and EXTRA-TEST-CODE is inserted into
dnl the main() function after the default test for existence.
dnl
dnl Examples:
dnl   # the simple case
dnl   WX_CHECK_FUNCS(stat)
dnl   # use break to finish the loop early
dnl   WX_CHECK_FUNCS(mkstemp mktemp, break)
dnl   # extra defines
dnl   WX_CHECK_FUNCS(strtok_r, [], [], [#define _RREENTRANT])
dnl   # extra includes
dnl   WX_CHECK_FUNCS(swprintf, [], [], [#include <wchar.h>])
dnl   # checking the signature with extra test code
dnl   WX_CHECK_FUNCS(gettimeofday, [], [], [#include <sys/time.h>]
dnl     [struct timeval tv; struct timezone tz; gettimeofday(&tv, &tz)])
dnl ---------------------------------------------------------------------------

AC_DEFUN([WX_CHECK_FUNCS],
[
  for wx_func in $1
  do
    AC_CACHE_CHECK(
      [for $wx_func],
      [wx_cv_func_$wx_func],
      [
        AC_LINK_IFELSE(
          [
            AC_LANG_PROGRAM(
              [
                $4
                AC_INCLUDES_DEFAULT
              ],
              [
                #ifndef $wx_func
                  &$wx_func;
                #endif
                $5
              ])
          ],
          [eval wx_cv_func_$wx_func=yes],
          [eval wx_cv_func_$wx_func=no])
      ])

    if eval test \$wx_cv_func_$wx_func = yes
    then
      AC_DEFINE_UNQUOTED(AS_TR_CPP([HAVE_$wx_func]))
      $2
    else
      :
      $3
    fi
  done
])

dnl ---------------------------------------------------------------------------
dnl a slightly better AC_C_BIGENDIAN macro which allows cross-compiling
dnl ---------------------------------------------------------------------------

AC_DEFUN([WX_C_BIGENDIAN],
[AC_CACHE_CHECK([whether byte ordering is bigendian], ac_cv_c_bigendian,
[ac_cv_c_bigendian=unknown
# See if sys/param.h defines the BYTE_ORDER macro.
AC_TRY_COMPILE([#include <sys/types.h>
#include <sys/param.h>], [
#if !BYTE_ORDER || !BIG_ENDIAN || !LITTLE_ENDIAN
 bogus endian macros
#endif], [# It does; now see whether it defined to BIG_ENDIAN or not.
AC_TRY_COMPILE([#include <sys/types.h>
#include <sys/param.h>], [
#if BYTE_ORDER != BIG_ENDIAN
 not big endian
#endif], ac_cv_c_bigendian=yes, ac_cv_c_bigendian=no)])
if test $ac_cv_c_bigendian = unknown; then
AC_TRY_RUN([main () {
  /* Are we little or big endian?  From Harbison&Steele.  */
  union
  {
    long l;
    char c[sizeof (long)];
  } u;
  u.l = 1;
  exit (u.c[sizeof (long) - 1] == 1);
}], [ac_cv_c_bigendian=no], [ac_cv_c_bigendian=yes], [ac_cv_c_bigendian=unknown])
fi])
if test $ac_cv_c_bigendian = unknown; then
  AC_MSG_WARN([Assuming little-endian target machine - this may be overriden by adding the line "ac_cv_c_bigendian=${ac_cv_c_bigendian='yes'}" to config.cache file])
fi
if test $ac_cv_c_bigendian = yes; then
  AC_DEFINE(WORDS_BIGENDIAN)
fi
])

dnl ---------------------------------------------------------------------------
dnl override AC_ARG_ENABLE/WITH to handle options defaults
dnl ---------------------------------------------------------------------------

dnl this macro checks for a three-valued command line --with argument:
dnl   possible arguments are 'yes', 'no', 'sys', or 'builtin'
dnl usage: WX_ARG_SYS_WITH(option, helpmessage, variable-name)
dnl
dnl the default value (used if the option is not specified at all) is the value
dnl of wxUSE_ALL_FEATURES (which is "yes" by default but can be changed by
dnl giving configure --disable-all-features option)
AC_DEFUN([WX_ARG_SYS_WITH],
        [
          AC_MSG_CHECKING([for --with-$1])
          AC_ARG_WITH($1, [$2],
                      [
                        if test "$withval" = yes; then
                          AS_TR_SH(wx_cv_use_$1)='$3=yes'
                        elif test "$withval" = no; then
                          AS_TR_SH(wx_cv_use_$1)='$3=no'
                        elif test "$withval" = sys; then
                          AS_TR_SH(wx_cv_use_$1)='$3=sys'
                        elif test "$withval" = builtin; then
                          AS_TR_SH(wx_cv_use_$1)='$3=builtin'
                        else
                          AC_MSG_ERROR([Invalid value for --with-$1: should be yes, no, sys, or builtin])
                        fi
                      ],
                      [
                        AS_TR_SH(wx_cv_use_$1)='$3=${'DEFAULT_$3":-$wxUSE_ALL_FEATURES}"
                      ])

          eval "$AS_TR_SH(wx_cv_use_$1)"

          if test "$$3" = yes; then
            AC_MSG_RESULT(yes)
          elif test "$$3" = no; then
            AC_MSG_RESULT(no)
          elif test "$$3" = sys; then
            AC_MSG_RESULT([system version])
          elif test "$$3" = builtin; then
            AC_MSG_RESULT([builtin version])
          else
            AC_MSG_ERROR([Invalid value for --with-$1: should be yes, no, sys, or builtin])
          fi
        ])

dnl this macro simply checks for a command line argument
dnl usage: WX_ARG_WITH(option, helpmessage, variable-name, [withstring])
AC_DEFUN([WX_ARG_WITH],
        [
          withstring=$4
          defaultval=$wxUSE_ALL_FEATURES
          if test -z "$defaultval"; then
              if test x"$withstring" = xwithout; then
                  defaultval=yes
              else
                  defaultval=no
              fi
          fi
          AC_MSG_CHECKING([for --${withstring:-with}-$1])
          AC_ARG_WITH($1, [$2],
                      [
                        if test "$withval" = yes; then
                          AS_TR_SH(wx_cv_use_$1)='$3=yes'
                        else
                          AS_TR_SH(wx_cv_use_$1)='$3=no'
                        fi
                      ],
                      [
                        AS_TR_SH(wx_cv_use_$1)='$3=${'DEFAULT_$3":-$defaultval}"
                      ])

          eval "$AS_TR_SH(wx_cv_use_$1)"

          if test x"$withstring" = xwithout; then
            if test $$3 = yes; then
              result=no
            else
              result=yes
            fi
          else
            result=$$3
          fi

          AC_MSG_RESULT($result)
        ])

dnl same as WX_ARG_WITH but makes it clear that the option is enabled by default
AC_DEFUN([WX_ARG_WITHOUT], [WX_ARG_WITH($1, [$2], $3, without)])

dnl like WX_ARG_WITH but uses AC_ARG_ENABLE instead of AC_ARG_WITH
dnl usage: WX_ARG_ENABLE(option, helpmessage, var, [enablestring], [default])
dnl
dnl enablestring can be omitted or a literal string "disable" and allows to
dnl show "checking for --disable-foo" message when running configure instead of
dnl the default "checking for --enable-foo" one whih is useful for the options
dnl enabled by default
dnl
dnl the "default" argument can be omitted or contain the default value to use
dnl for the option if it's unspecified
AC_DEFUN([WX_ARG_ENABLE],
        [
          enablestring=$4
          defaultval=$5
          if test -z "$defaultval"; then
              if test x"$enablestring" = xdisable; then
                  defaultval=yes
              else
                  defaultval=no
              fi
          fi

          AC_MSG_CHECKING([for --${enablestring:-enable}-$1])
          AC_ARG_ENABLE($1, [$2],
                        [
                          if test "$enableval" = yes; then
                            AS_TR_SH(wx_cv_use_$1)='$3=yes'
                          else
                            AS_TR_SH(wx_cv_use_$1)='$3=no'
                          fi
                        ],
                        [
                          AS_TR_SH(wx_cv_use_$1)='$3=${'DEFAULT_$3":-$defaultval}"
                        ])

          eval "$AS_TR_SH(wx_cv_use_$1)"

          if test x"$enablestring" = xdisable; then
            if test $$3 = no; then
              result=yes
            else
              result=no
            fi
          else
            result=$$3
          fi

          AC_MSG_RESULT($result)
        ])

dnl the same as WX_ARG_ENABLE but makes it more clear that the option is
dnl enabled by default
AC_DEFUN([WX_ARG_DISABLE], [WX_ARG_ENABLE($1, [$2], $3, disable)])

dnl same as WX_ARG_ENABLE but defaults to wxUSE_ALL_FEATURES instead of "yes"
AC_DEFUN([WX_ARG_FEATURE], [WX_ARG_ENABLE($1, [$2], $3,, $wxUSE_ALL_FEATURES)])

dnl Like WX_ARG_ENABLE but accepts a parameter.
dnl
dnl Usage:
dnl   WX_ARG_ENABLE_PARAM(option, helpmessage, variable-name, enablestring)
dnl
dnl Example:
dnl   WX_ARG_ENABLE_PARAM(foo, [[  --enable-foo[=bar] use foo]], wxUSE_FOO)
dnl
dnl  --enable-foo       wxUSE_FOO=yes
dnl  --disable-foo      wxUSE_FOO=no
dnl  --enable-foo=bar   wxUSE_FOO=bar
dnl  <not given>        wxUSE_FOO=$DEFAULT_wxUSE_FOO
dnl
AC_DEFUN([WX_ARG_ENABLE_PARAM],
        [
          enablestring=$4
          AC_MSG_CHECKING([for --${enablestring:-enable}-$1])
          AC_ARG_ENABLE($1, [$2],
                        [
                          wx_cv_use_$1="$3='$enableval'"
                        ],
                        [
                          wx_cv_use_$1='$3='$DEFAULT_$3
                        ])

          eval "$wx_cv_use_$1"

          AC_MSG_RESULT([$$3])
        ])

dnl ===========================================================================
dnl Linker features test
dnl ===========================================================================

dnl ---------------------------------------------------------------------------
dnl WX_VERSIONED_SYMBOLS checks whether the linker can create versioned
dnl symbols. If it can, sets LDFLAGS_VERSIONING to $CXX flags needed to use
dnl version script file named versionfile
dnl
dnl call WX_VERSIONED_SYMBOLS(versionfile)
dnl ---------------------------------------------------------------------------
AC_DEFUN([WX_VERSIONED_SYMBOLS],
[
    case "${host}" in
        *-*-cygwin* | *-*-mingw* )
            dnl although ld does support version script option on these
            dnl platforms, it doesn't make much sense to use it under Win32
            dnl and, moreover, this breaks linking because of a bug in handling
            dnl paths in -Wl,--version-script,path option (if we ever do need
            dnl to use it for cygwin/mingw32, keep in mind that replacing last
            dnl comma with the equal sign works) so
            dnl simply disable it
            wx_cv_version_script=no
            ;;

        *)
            AC_CACHE_CHECK([if the linker accepts --version-script], wx_cv_version_script,
            [
                echo "VER_1 { *; };" >conftest.sym
                echo "int main() { return 0; }" >conftest.cpp

                if AC_TRY_COMMAND([
                        $CXX -o conftest.output $CXXFLAGS $CPPFLAGS $LDFLAGS conftest.cpp
                        -Wl,--version-script,conftest.sym >/dev/null 2>conftest.stderr]) ; then
                  if test -s conftest.stderr ; then
                      wx_cv_version_script=no
                  else
                      wx_cv_version_script=yes
                  fi
                else
                  wx_cv_version_script=no
                fi

                dnl There's a problem in some old linkers with --version-script that
                dnl can cause linking to fail when you have objects with vtables in
                dnl libs 3 deep.  This is known to happen in netbsd and openbsd with
                dnl ld 2.11.2.
                dnl
                dnl To test for this we need to make some shared libs and
                dnl unfortunately we can't be sure of the right way to do that. If the
                dnl first two compiles don't succeed then it looks like the test isn't
                dnl working and the result is ignored, but if OTOH the first two
                dnl succeed but the third does not then the bug has been detected and
                dnl the --version-script flag is dropped.
                if test $wx_cv_version_script = yes
                then
                  echo "struct B { virtual ~B() { } }; \
                        struct D : public B { }; \
                        void F() { D d; }" > conftest.cpp

                  if AC_TRY_COMMAND([
                        $CXX -shared -fPIC -o conftest1.output $CXXFLAGS $CPPFLAGS $LDFLAGS conftest.cpp
                        -Wl,--version-script,conftest.sym >/dev/null 2>/dev/null]) &&
                     AC_TRY_COMMAND([
                        $CXX -shared -fPIC -o conftest2.output $CXXFLAGS $CPPFLAGS $LDFLAGS conftest.cpp
                        -Wl,--version-script,conftest.sym conftest1.output >/dev/null 2>/dev/null])
                  then
                    if AC_TRY_COMMAND([
                          $CXX -shared -fPIC -o conftest3.output $CXXFLAGS $CPPFLAGS $LDFLAGS conftest.cpp
                          -Wl,--version-script,conftest.sym conftest2.output conftest1.output >/dev/null 2>/dev/null])
                    then
                      wx_cv_version_script=yes
                    else
                      wx_cv_version_script=no
                    fi
                  fi
                fi

                rm -f conftest.output conftest.stderr conftest.sym conftest.cpp
                rm -f conftest1.output conftest2.output conftest3.output
            ])

            if test $wx_cv_version_script = yes ; then
                LDFLAGS_VERSIONING="-Wl,--version-script,$1"
            fi
            ;;
    esac
])


dnl ===========================================================================
dnl "3rd party" macros included here because they are not widely available
dnl ===========================================================================

dnl ---------------------------------------------------------------------------
dnl test for availability of iconv()
dnl ---------------------------------------------------------------------------

dnl From Bruno Haible.

AC_DEFUN([AM_ICONV],
[
  dnl Some systems have iconv in libc, some have it in libiconv (OSF/1 and
  dnl those with the standalone portable GNU libiconv installed).

  AC_ARG_WITH([libiconv-prefix],
[  --with-libiconv-prefix=DIR  search for libiconv in DIR/include and DIR/lib], [
    for dir in `echo "$withval" | tr : ' '`; do
      if test -d $dir/include; then CPPFLAGS="$CPPFLAGS -I$dir/include"; fi
      if test -d $dir/lib; then LDFLAGS="$LDFLAGS -L$dir/lib"; fi
    done
   ])

  AC_CACHE_CHECK(for iconv, am_cv_func_iconv, [
    am_cv_func_iconv="no, consider installing GNU libiconv"
    am_cv_lib_iconv=no
    AC_TRY_LINK([#include <stdlib.h>
#include <iconv.h>],
      [iconv_t cd = iconv_open("","");
       iconv(cd,NULL,NULL,NULL,NULL);
       iconv_close(cd);],
      am_cv_func_iconv=yes)
    if test "$am_cv_func_iconv" != yes; then
      am_save_LIBS="$LIBS"
      LIBS="$LIBS -liconv"
      AC_TRY_LINK([#include <stdlib.h>
#include <iconv.h>],
        [iconv_t cd = iconv_open("","");
         iconv(cd,NULL,NULL,NULL,NULL);
         iconv_close(cd);],
        am_cv_lib_iconv=yes
        am_cv_func_iconv=yes)
      LIBS="$am_save_LIBS"
    fi
  ])
  if test "$am_cv_func_iconv" = yes; then
    AC_DEFINE(HAVE_ICONV, 1, [Define if you have the iconv() function.])
    AC_CACHE_CHECK([if iconv needs const], wx_cv_func_iconv_const,
      AC_TRY_COMPILE([
#include <stdlib.h>
#include <iconv.h>
extern
#ifdef __cplusplus
"C"
#endif
#if defined(__STDC__) || defined(__cplusplus)
size_t iconv (iconv_t cd, char * *inbuf, size_t *inbytesleft, char * *outbuf, size_t *outbytesleft);
#else
size_t iconv();
#endif
        ],
        [],
        wx_cv_func_iconv_const="no",
        wx_cv_func_iconv_const="yes"
      )
    )

    iconv_const=
    if test "x$wx_cv_func_iconv_const" = "xyes"; then
        iconv_const="const"
    fi

    AC_DEFINE_UNQUOTED(ICONV_CONST, $iconv_const,
      [Define as const if the declaration of iconv() needs const.])
  fi
  LIBICONV=
  if test "$am_cv_lib_iconv" = yes; then
    LIBICONV="-liconv"
  fi
  AC_SUBST(LIBICONV)
])

dnl ---------------------------------------------------------------------------
dnl AC_SYS_LARGEFILE (partly based on the code from autoconf 2.5x)
dnl ---------------------------------------------------------------------------

dnl WX_SYS_LARGEFILE_TEST
dnl
dnl NB: original autoconf test was checking if compiler supported 6 bit off_t
dnl     arithmetic properly but this failed miserably with gcc under Linux
dnl     whereas the system still supports 64 bit files, so now simply check
dnl     that off_t is big enough
define(WX_SYS_LARGEFILE_TEST,
[typedef struct {
    unsigned int field: sizeof(off_t) == 8;
} wxlf;
])


dnl WX_SYS_LARGEFILE_MACRO_VALUE(C-MACRO, VALUE, CACHE-VAR)
define(WX_SYS_LARGEFILE_MACRO_VALUE,
[
    AC_CACHE_CHECK([for $1 value needed for large files], [$3],
        [
          AC_TRY_COMPILE([#define $1 $2
                          #include <sys/types.h>],
                         WX_SYS_LARGEFILE_TEST,
                         [$3=$2],
                         [$3=no])
        ]
    )

    if test "$$3" != no; then
        wx_largefile=yes
        AC_DEFINE_UNQUOTED([$1], [$$3])
    fi
])


dnl AC_SYS_LARGEFILE
dnl ----------------
dnl By default, many hosts won't let programs access large files;
dnl one must use special compiler options to get large-file access to work.
dnl For more details about this brain damage please see:
dnl http://www.sas.com/standards/large.file/x_open.20Mar96.html
AC_DEFUN([AC_SYS_LARGEFILE],
[AC_ARG_ENABLE(largefile,
               [  --disable-largefile     omit support for large files])
if test "$enable_largefile" != no; then
    dnl _FILE_OFFSET_BITS==64 is needed for Linux, Solaris, ...
    dnl _LARGE_FILES -- for AIX
    wx_largefile=no
    WX_SYS_LARGEFILE_MACRO_VALUE(_FILE_OFFSET_BITS, 64, ac_cv_sys_file_offset_bits)
    if test "x$wx_largefile" != "xyes"; then
        WX_SYS_LARGEFILE_MACRO_VALUE(_LARGE_FILES, 1, ac_cv_sys_large_files)
    fi

    AC_MSG_CHECKING(if large file support is available)
    if test "x$wx_largefile" = "xyes"; then
        AC_DEFINE(HAVE_LARGEFILE_SUPPORT)
    fi
    AC_MSG_RESULT($wx_largefile)
fi
])

