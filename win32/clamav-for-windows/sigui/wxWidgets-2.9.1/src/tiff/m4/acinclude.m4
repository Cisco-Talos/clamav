dnl ---------------------------------------------------------------------------
dnl Message output
dnl ---------------------------------------------------------------------------
AC_DEFUN([LOC_MSG],[echo "$1"])

dnl ---------------------------------------------------------------------------
dnl Available from the GNU Autoconf Macro Archive at:
dnl http://www.gnu.org/software/ac-archive/vl_prog_cc_warnings.html
dnl ---------------------------------------------------------------------------

dnl @synopsis VL_PROG_CC_WARNINGS([ANSI])
dnl
dnl Enables a reasonable set of warnings for the C compiler.
dnl Optionally, if the first argument is nonempty, turns on flags which
dnl enforce and/or enable proper ANSI C if such are known with the
dnl compiler used.
dnl
dnl Currently this macro knows about GCC, Solaris C compiler, Digital
dnl Unix C compiler, C for AIX Compiler, HP-UX C compiler, IRIX C
dnl compiler, NEC SX-5 (Super-UX 10) C compiler, and Cray J90 (Unicos
dnl 10.0.0.8) C compiler.
dnl
dnl @category C
dnl @author Ville Laurikari <vl@iki.fi>
dnl @version 2002-04-04
dnl @license AllPermissive

AC_DEFUN([VL_PROG_CC_WARNINGS], [
  ansi=$1
  if test -z "$ansi"; then
    msg="for C compiler warning flags"
  else
    msg="for C compiler warning and ANSI conformance flags"
  fi
  AC_CACHE_CHECK($msg, vl_cv_prog_cc_warnings, [
    if test -n "$CC"; then
      cat > conftest.c <<EOF
int main(int argc, char **argv) { return 0; }
EOF

      dnl GCC. -W option has been renamed in -wextra in latest gcc versions.
      if test "$GCC" = "yes"; then
        if test -z "$ansi"; then
          vl_cv_prog_cc_warnings="-Wall -W"
        else
          vl_cv_prog_cc_warnings="-Wall -W -ansi -pedantic"
        fi

      dnl Most compilers print some kind of a version string with some command
      dnl line options (often "-V").  The version string should be checked
      dnl before doing a test compilation run with compiler-specific flags.
      dnl This is because some compilers (like the Cray compiler) only
      dnl produce a warning message for unknown flags instead of returning
      dnl an error, resulting in a false positive.  Also, compilers may do
      dnl erratic things when invoked with flags meant for a different
      dnl compiler.

      dnl Solaris C compiler
      elif $CC -V 2>&1 | grep -i "WorkShop" > /dev/null 2>&1 &&
           $CC -c -v -Xc conftest.c > /dev/null 2>&1 &&
           test -f conftest.o; then
        if test -z "$ansi"; then
          vl_cv_prog_cc_warnings="-v"
        else
          vl_cv_prog_cc_warnings="-v -Xc"
        fi

      dnl Digital Unix C compiler
      elif $CC -V 2>&1 | grep -i "Digital UNIX Compiler" > /dev/null 2>&1 &&
           $CC -c -verbose -w0 -warnprotos -std1 conftest.c > /dev/null 2>&1 &&
           test -f conftest.o; then
        if test -z "$ansi"; then
          vl_cv_prog_cc_warnings="-verbose -w0 -warnprotos"
        else
          vl_cv_prog_cc_warnings="-verbose -w0 -warnprotos -std1"
        fi

      dnl C for AIX Compiler
      elif $CC 2>&1 | grep -i "C for AIX Compiler" > /dev/null 2>&1 &&
           $CC -c -qlanglvl=ansi -qinfo=all conftest.c > /dev/null 2>&1 &&
           test -f conftest.o; then
        if test -z "$ansi"; then
          vl_cv_prog_cc_warnings="-qsrcmsg -qinfo=all:noppt:noppc:noobs:nocnd"
        else
          vl_cv_prog_cc_warnings="-qsrcmsg -qinfo=all:noppt:noppc:noobs:nocnd -qlanglvl=ansi"
        fi

      dnl IRIX C compiler
      elif $CC -version 2>&1 | grep -i "MIPSpro Compilers" > /dev/null 2>&1 &&
           $CC -c -fullwarn -ansi -ansiE conftest.c > /dev/null 2>&1 &&
           test -f conftest.o; then
        if test -z "$ansi"; then
          vl_cv_prog_cc_warnings="-fullwarn"
        else
          vl_cv_prog_cc_warnings="-fullwarn -ansi -ansiE"
        fi

      dnl HP-UX C compiler
      elif what $CC 2>&1 | grep -i "HP C Compiler" > /dev/null 2>&1 &&
           $CC -c -Aa +w1 conftest.c > /dev/null 2>&1 &&
           test -f conftest.o; then
        if test -z "$ansi"; then
          vl_cv_prog_cc_warnings="+w1"
        else
          vl_cv_prog_cc_warnings="+w1 -Aa"
        fi

      dnl The NEC SX-5 (Super-UX 10) C compiler
      elif $CC -V 2>&1 | grep "/SX" > /dev/null 2>&1 &&
           $CC -c -pvctl[,]fullmsg -Xc conftest.c > /dev/null 2>&1 &&
           test -f conftest.o; then
        if test -z "$ansi"; then
          vl_cv_prog_cc_warnings="-pvctl[,]fullmsg"
        else
          vl_cv_prog_cc_warnings="-pvctl[,]fullmsg -Xc"
        fi

      dnl The Cray C compiler (Unicos)
      elif $CC -V 2>&1 | grep -i "Cray" > /dev/null 2>&1 &&
           $CC -c -h msglevel 2 conftest.c > /dev/null 2>&1 &&
           test -f conftest.o; then
        if test -z "$ansi"; then
          vl_cv_prog_cc_warnings="-h msglevel 2"
        else
          vl_cv_prog_cc_warnings="-h msglevel 2 -h conform"
        fi

      fi
      rm -f conftest.*
    fi
    if test -n "$vl_cv_prog_cc_warnings"; then
      CFLAGS="$CFLAGS $vl_cv_prog_cc_warnings"
    else
      vl_cv_prog_cc_warnings="unknown"
    fi
  ])
])dnl

dnl ---------------------------------------------------------------------------
dnl Available from the GNU Autoconf Macro Archive at:
dnl http://autoconf-archive.cryp.to/ax_lang_compiler_ms.html
dnl ---------------------------------------------------------------------------

dnl @synopsis AX_LANG_COMPILER_MS
dnl
dnl Check whether the compiler for the current language is Microsoft.
dnl
dnl This macro is modeled after _AC_LANG_COMPILER_GNU in the GNU
dnl Autoconf implementation.
dnl
dnl @category InstalledPackages
dnl @author Braden McDaniel <braden@endoframe.com>
dnl @version 2004-11-15
dnl @license AllPermissive

AC_DEFUN([AX_LANG_COMPILER_MS],
[AC_CACHE_CHECK([whether we are using the Microsoft _AC_LANG compiler],
                [ax_cv_[]_AC_LANG_ABBREV[]_compiler_ms],
[AC_COMPILE_IFELSE([AC_LANG_PROGRAM([], [[#ifndef _MSC_VER
       choke me
#endif
]])],
                   [ax_compiler_ms=yes],
                   [ax_compiler_ms=no])
ax_cv_[]_AC_LANG_ABBREV[]_compiler_ms=$ax_compiler_ms
])])

dnl ---------------------------------------------------------------------------
dnl Available from the GNU Autoconf Macro Archive at:
dnl http://www.gnu.org/software/ac-archive/ax_check_gl.html
dnl ---------------------------------------------------------------------------

dnl @synopsis AX_CHECK_GL
dnl
dnl Check for an OpenGL implementation. If GL is found, the required
dnl compiler and linker flags are included in the output variables
dnl "GL_CFLAGS" and "GL_LIBS", respectively. This macro adds the
dnl configure option "--with-apple-opengl-framework", which users can
dnl use to indicate that Apple's OpenGL framework should be used on Mac
dnl OS X. If Apple's OpenGL framework is used, the symbol
dnl "HAVE_APPLE_OPENGL_FRAMEWORK" is defined. If no GL implementation
dnl is found, "no_gl" is set to "yes".
dnl
dnl @category InstalledPackages
dnl @author Braden McDaniel <braden@endoframe.com>
dnl @version 2004-11-15
dnl @license AllPermissive

AC_DEFUN([AX_CHECK_GL],
[AC_REQUIRE([AC_PATH_X])dnl
AC_REQUIRE([ACX_PTHREAD])dnl

#
# There isn't a reliable way to know we should use the Apple OpenGL framework
# without a configure option.  A Mac OS X user may have installed an
# alternative GL implementation (e.g., Mesa), which may or may not depend on X.
#
AC_ARG_WITH([apple-opengl-framework],
            [AC_HELP_STRING([--with-apple-opengl-framework],
                            [use Apple OpenGL framework (Mac OS X only)])])
if test "X$with_apple_opengl_framework" = "Xyes"; then
  AC_DEFINE([HAVE_APPLE_OPENGL_FRAMEWORK], [1],
            [Use the Apple OpenGL framework.])
  GL_LIBS="-framework OpenGL"
else
  AC_LANG_PUSH(C)

  AX_LANG_COMPILER_MS
  if test X$ax_compiler_ms = Xno; then
    GL_CFLAGS="${PTHREAD_CFLAGS}"
    GL_LIBS="${PTHREAD_LIBS} -lm"
  fi

  #
  # Use x_includes and x_libraries if they have been set (presumably by
  # AC_PATH_X).
  #
  if test "X$no_x" != "Xyes"; then
    if test -n "$x_includes"; then
      GL_CFLAGS="-I${x_includes} ${GL_CFLAGS}"
    fi
    if test -n "$x_libraries"; then
      GL_LIBS="-L${x_libraries} -lX11 ${GL_LIBS}"
    fi
  fi

  AC_CHECK_HEADERS([windows.h])

  AC_CACHE_CHECK([for OpenGL library], [ax_cv_check_gl_libgl],
  [ax_cv_check_gl_libgl="no"
  ax_save_CPPFLAGS="${CPPFLAGS}"
  CPPFLAGS="${GL_CFLAGS} ${CPPFLAGS}"
  ax_save_LIBS="${LIBS}"
  LIBS=""
  ax_check_libs="-lopengl32 -lGL"
  for ax_lib in ${ax_check_libs}; do
    if test X$ax_compiler_ms = Xyes; then
      ax_try_lib=`echo $ax_lib | sed -e 's/^-l//' -e 's/$/.lib/'`
    else
      ax_try_lib="${ax_lib}"
    fi
    LIBS="${ax_try_lib} ${GL_LIBS} ${ax_save_LIBS}"
    AC_LINK_IFELSE(
    [AC_LANG_PROGRAM([[
# if HAVE_WINDOWS_H && defined(_WIN32)
#   include <windows.h>
# endif
# include <GL/gl.h>]],
                     [[glBegin(0)]])],
    [ax_cv_check_gl_libgl="${ax_try_lib}"; break])
  done
  LIBS=${ax_save_LIBS}
  CPPFLAGS=${ax_save_CPPFLAGS}])

  if test "X${ax_cv_check_gl_libgl}" = "Xno"; then
    no_gl="yes"
    GL_CFLAGS=""
    GL_LIBS=""
  else
    GL_LIBS="${ax_cv_check_gl_libgl} ${GL_LIBS}"
  fi
  AC_LANG_POP(C)
fi

AC_SUBST([GL_CFLAGS])
AC_SUBST([GL_LIBS])
])dnl

dnl ---------------------------------------------------------------------------
dnl Available from the GNU Autoconf Macro Archive at:
dnl http://www.gnu.org/software/ac-archive/ax_check_glu.html
dnl ---------------------------------------------------------------------------

dnl @synopsis AX_CHECK_GLU
dnl
dnl Check for GLU. If GLU is found, the required preprocessor and
dnl linker flags are included in the output variables "GLU_CFLAGS" and
dnl "GLU_LIBS", respectively. This macro adds the configure option
dnl "--with-apple-opengl-framework", which users can use to indicate
dnl that Apple's OpenGL framework should be used on Mac OS X. If
dnl Apple's OpenGL framework is used, the symbol
dnl "HAVE_APPLE_OPENGL_FRAMEWORK" is defined. If no GLU implementation
dnl is found, "no_glu" is set to "yes".
dnl
dnl @category InstalledPackages
dnl @author Braden McDaniel <braden@endoframe.com>
dnl @version 2004-11-15
dnl @license AllPermissive

AC_DEFUN([AX_CHECK_GLU],
[AC_REQUIRE([AX_CHECK_GL])dnl
AC_REQUIRE([AC_PROG_CXX])dnl
GLU_CFLAGS="${GL_CFLAGS}"
if test "X${with_apple_opengl_framework}" != "Xyes"; then
  AC_CACHE_CHECK([for OpenGL Utility library], [ax_cv_check_glu_libglu],
  [ax_cv_check_glu_libglu="no"
  ax_save_CPPFLAGS="${CPPFLAGS}"
  CPPFLAGS="${GL_CFLAGS} ${CPPFLAGS}"
  ax_save_LIBS="${LIBS}"
  LIBS=""
  ax_check_libs="-lglu32 -lGLU"
  for ax_lib in ${ax_check_libs}; do
    if test X$ax_compiler_ms = Xyes; then
      ax_try_lib=`echo $ax_lib | sed -e 's/^-l//' -e 's/$/.lib/'`
    else
      ax_try_lib="${ax_lib}"
    fi
    LIBS="${ax_try_lib} ${GL_LIBS} ${ax_save_LIBS}"
    #
    # libGLU typically links with libstdc++ on POSIX platforms. However,
    # setting the language to C++ means that test program source is named
    # "conftest.cc"; and Microsoft cl doesn't know what to do with such a
    # file.
    #
    AC_LANG_PUSH([C++])
    if test X$ax_compiler_ms = Xyes; then
      AC_LANG_PUSH([C])
    fi
    AC_LINK_IFELSE(
    [AC_LANG_PROGRAM([[
# if HAVE_WINDOWS_H && defined(_WIN32)
#   include <windows.h>
# endif
# include <GL/glu.h>]],
                     [[gluBeginCurve(0)]])],
    [ax_cv_check_glu_libglu="${ax_try_lib}"; break])
    if test X$ax_compiler_ms = Xyes; then
      AC_LANG_POP([C])
    fi
    AC_LANG_POP([C++])
  done
  LIBS=${ax_save_LIBS}
  CPPFLAGS=${ax_save_CPPFLAGS}])
  if test "X${ax_cv_check_glu_libglu}" = "Xno"; then
    no_glu="yes"
    GLU_CFLAGS=""
    GLU_LIBS=""
  else
    GLU_LIBS="${ax_cv_check_glu_libglu} ${GL_LIBS}"
  fi
fi
AC_SUBST([GLU_CFLAGS])
AC_SUBST([GLU_LIBS])
])

dnl ---------------------------------------------------------------------------
dnl Available from the GNU Autoconf Macro Archive at:
dnl http://www.gnu.org/software/ac-archive/ax_check_glut.html
dnl ---------------------------------------------------------------------------

dnl @synopsis AX_CHECK_GLUT
dnl
dnl Check for GLUT. If GLUT is found, the required compiler and linker
dnl flags are included in the output variables "GLUT_CFLAGS" and
dnl "GLUT_LIBS", respectively. This macro adds the configure option
dnl "--with-apple-opengl-framework", which users can use to indicate
dnl that Apple's OpenGL framework should be used on Mac OS X. If
dnl Apple's OpenGL framework is used, the symbol
dnl "HAVE_APPLE_OPENGL_FRAMEWORK" is defined. If GLUT is not found,
dnl "no_glut" is set to "yes".
dnl
dnl @category InstalledPackages
dnl @author Braden McDaniel <braden@endoframe.com>
dnl @version 2004-11-15
dnl @license AllPermissive

AC_DEFUN([AX_CHECK_GLUT],
[AC_REQUIRE([AX_CHECK_GLU])dnl
AC_REQUIRE([AC_PATH_XTRA])dnl

if test "X$with_apple_opengl_framework" = "Xyes"; then
  GLUT_CFLAGS="${GLU_CFLAGS}"
  GLUT_LIBS="-framework GLUT -lobjc ${GL_LIBS}"
else
  GLUT_CFLAGS=${GLU_CFLAGS}
  GLUT_LIBS=${GLU_LIBS}

  #
  # If X is present, assume GLUT depends on it.
  #
  if test "X${no_x}" != "Xyes"; then
    GLUT_LIBS="${X_PRE_LIBS} -lXmu -lXi ${X_EXTRA_LIBS} ${GLUT_LIBS}"
  fi

  AC_LANG_PUSH(C)

  ax_save_CPPFLAGS="${CPPFLAGS}"
  CPPFLAGS="${GLUT_CFLAGS} ${CPPFLAGS}"

  AC_CACHE_CHECK([for GLUT library], [ax_cv_check_glut_libglut],
  [ax_cv_check_glut_libglut="no"
  ax_save_LIBS="${LIBS}"
  LIBS=""
  ax_check_libs="-lglut32 -lglut"
  for ax_lib in ${ax_check_libs}; do
    if test X$ax_compiler_ms = Xyes; then
      ax_try_lib=`echo $ax_lib | sed -e 's/^-l//' -e 's/$/.lib/'`
    else
      ax_try_lib="${ax_lib}"
    fi
    LIBS="${ax_try_lib} ${GLUT_LIBS} ${ax_save_LIBS}"
    AC_LINK_IFELSE(
    [AC_LANG_PROGRAM([[
# if HAVE_WINDOWS_H && defined(_WIN32)
#   include <windows.h>
# endif
# include <GL/glut.h>]],
                     [[glutMainLoop()]])],
    [ax_cv_check_glut_libglut="${ax_try_lib}"; break])

  done
  LIBS=${ax_save_LIBS}
  ])
  CPPFLAGS="${ax_save_CPPFLAGS}"
  AC_LANG_POP(C)

  if test "X${ax_cv_check_glut_libglut}" = "Xno"; then
    no_glut="yes"
    GLUT_CFLAGS=""
    GLUT_LIBS=""
  else
    GLUT_LIBS="${ax_cv_check_glut_libglut} ${GLUT_LIBS}"
  fi
fi

AC_SUBST([GLUT_CFLAGS])
AC_SUBST([GLUT_LIBS])
])dnl

dnl ---------------------------------------------------------------------------
dnl Available from the GNU Autoconf Macro Archive at:
dnl http://www.gnu.org/software/ac-archive/acx_pthread.html
dnl ---------------------------------------------------------------------------

dnl @synopsis ACX_PTHREAD([ACTION-IF-FOUND[, ACTION-IF-NOT-FOUND]])
dnl
dnl This macro figures out how to build C programs using POSIX threads.
dnl It sets the PTHREAD_LIBS output variable to the threads library and
dnl linker flags, and the PTHREAD_CFLAGS output variable to any special
dnl C compiler flags that are needed. (The user can also force certain
dnl compiler flags/libs to be tested by setting these environment
dnl variables.)
dnl
dnl Also sets PTHREAD_CC to any special C compiler that is needed for
dnl multi-threaded programs (defaults to the value of CC otherwise).
dnl (This is necessary on AIX to use the special cc_r compiler alias.)
dnl
dnl NOTE: You are assumed to not only compile your program with these
dnl flags, but also link it with them as well. e.g. you should link
dnl with $PTHREAD_CC $CFLAGS $PTHREAD_CFLAGS $LDFLAGS ... $PTHREAD_LIBS
dnl $LIBS
dnl
dnl If you are only building threads programs, you may wish to use
dnl these variables in your default LIBS, CFLAGS, and CC:
dnl
dnl        LIBS="$PTHREAD_LIBS $LIBS"
dnl        CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
dnl        CC="$PTHREAD_CC"
dnl
dnl In addition, if the PTHREAD_CREATE_JOINABLE thread-attribute
dnl constant has a nonstandard name, defines PTHREAD_CREATE_JOINABLE to
dnl that name (e.g. PTHREAD_CREATE_UNDETACHED on AIX).
dnl
dnl ACTION-IF-FOUND is a list of shell commands to run if a threads
dnl library is found, and ACTION-IF-NOT-FOUND is a list of commands to
dnl run it if it is not found. If ACTION-IF-FOUND is not specified, the
dnl default action will define HAVE_PTHREAD.
dnl
dnl Please let the authors know if this macro fails on any platform, or
dnl if you have any other suggestions or comments. This macro was based
dnl on work by SGJ on autoconf scripts for FFTW (www.fftw.org) (with
dnl help from M. Frigo), as well as ac_pthread and hb_pthread macros
dnl posted by Alejandro Forero Cuervo to the autoconf macro repository.
dnl We are also grateful for the helpful feedback of numerous users.
dnl
dnl @category InstalledPackages
dnl @author Steven G. Johnson <stevenj@alum.mit.edu>
dnl @version 2005-01-14
dnl @license GPLWithACException

AC_DEFUN([ACX_PTHREAD], [
AC_REQUIRE([AC_CANONICAL_HOST])
AC_LANG_SAVE
AC_LANG_C
acx_pthread_ok=no

# We used to check for pthread.h first, but this fails if pthread.h
# requires special compiler flags (e.g. on True64 or Sequent).
# It gets checked for in the link test anyway.

# First of all, check if the user has set any of the PTHREAD_LIBS,
# etcetera environment variables, and if threads linking works using
# them:
if test x"$PTHREAD_LIBS$PTHREAD_CFLAGS" != x; then
        save_CFLAGS="$CFLAGS"
        CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
        save_LIBS="$LIBS"
        LIBS="$PTHREAD_LIBS $LIBS"
        AC_MSG_CHECKING([for pthread_join in LIBS=$PTHREAD_LIBS with CFLAGS=$PTHREAD_CFLAGS])
        AC_TRY_LINK_FUNC(pthread_join, acx_pthread_ok=yes)
        AC_MSG_RESULT($acx_pthread_ok)
        if test x"$acx_pthread_ok" = xno; then
                PTHREAD_LIBS=""
                PTHREAD_CFLAGS=""
        fi
        LIBS="$save_LIBS"
        CFLAGS="$save_CFLAGS"
fi

# We must check for the threads library under a number of different
# names; the ordering is very important because some systems
# (e.g. DEC) have both -lpthread and -lpthreads, where one of the
# libraries is broken (non-POSIX).

# Create a list of thread flags to try.  Items starting with a "-" are
# C compiler flags, and other items are library names, except for "none"
# which indicates that we try without any flags at all, and "pthread-config"
# which is a program returning the flags for the Pth emulation library.

acx_pthread_flags="pthreads none -Kthread -kthread lthread -pthread -pthreads -mthreads pthread --thread-safe -mt pthread-config"

# The ordering *is* (sometimes) important.  Some notes on the
# individual items follow:

# pthreads: AIX (must check this before -lpthread)
# none: in case threads are in libc; should be tried before -Kthread and
#       other compiler flags to prevent continual compiler warnings
# -Kthread: Sequent (threads in libc, but -Kthread needed for pthread.h)
# -kthread: FreeBSD kernel threads (preferred to -pthread since SMP-able)
# lthread: LinuxThreads port on FreeBSD (also preferred to -pthread)
# -pthread: Linux/gcc (kernel threads), BSD/gcc (userland threads)
# -pthreads: Solaris/gcc
# -mthreads: Mingw32/gcc, Lynx/gcc
# -mt: Sun Workshop C (may only link SunOS threads [-lthread], but it
#      doesn't hurt to check since this sometimes defines pthreads too;
#      also defines -D_REENTRANT)
# pthread: Linux, etcetera
# --thread-safe: KAI C++
# pthread-config: use pthread-config program (for GNU Pth library)

case "${host_cpu}-${host_os}" in
        *solaris*)

        # On Solaris (at least, for some versions), libc contains stubbed
        # (non-functional) versions of the pthreads routines, so link-based
        # tests will erroneously succeed.  (We need to link with -pthread or
        # -lpthread.)  (The stubs are missing pthread_cleanup_push, or rather
        # a function called by this macro, so we could check for that, but
        # who knows whether they'll stub that too in a future libc.)  So,
        # we'll just look for -pthreads and -lpthread first:

        acx_pthread_flags="-pthread -pthreads pthread -mt $acx_pthread_flags"
        ;;
esac

if test x"$acx_pthread_ok" = xno; then
for flag in $acx_pthread_flags; do

        case $flag in
                none)
                AC_MSG_CHECKING([whether pthreads work without any flags])
                ;;

                -*)
                AC_MSG_CHECKING([whether pthreads work with $flag])
                PTHREAD_CFLAGS="$flag"
                ;;

		pthread-config)
		AC_CHECK_PROG(acx_pthread_config, pthread-config, yes, no)
		if test x"$acx_pthread_config" = xno; then continue; fi
		PTHREAD_CFLAGS="`pthread-config --cflags`"
		PTHREAD_LIBS="`pthread-config --ldflags` `pthread-config --libs`"
		;;

                *)
                AC_MSG_CHECKING([for the pthreads library -l$flag])
                PTHREAD_LIBS="-l$flag"
                ;;
        esac

        save_LIBS="$LIBS"
        save_CFLAGS="$CFLAGS"
        LIBS="$PTHREAD_LIBS $LIBS"
        CFLAGS="$CFLAGS $PTHREAD_CFLAGS"

        # Check for various functions.  We must include pthread.h,
        # since some functions may be macros.  (On the Sequent, we
        # need a special flag -Kthread to make this header compile.)
        # We check for pthread_join because it is in -lpthread on IRIX
        # while pthread_create is in libc.  We check for pthread_attr_init
        # due to DEC craziness with -lpthreads.  We check for
        # pthread_cleanup_push because it is one of the few pthread
        # functions on Solaris that doesn't have a non-functional libc stub.
        # We try pthread_create on general principles.
        AC_TRY_LINK([#include <pthread.h>],
                    [pthread_t th; pthread_join(th, 0);
                     pthread_attr_init(0); pthread_cleanup_push(0, 0);
                     pthread_create(0,0,0,0); pthread_cleanup_pop(0); ],
                    [acx_pthread_ok=yes])

        LIBS="$save_LIBS"
        CFLAGS="$save_CFLAGS"

        AC_MSG_RESULT($acx_pthread_ok)
        if test "x$acx_pthread_ok" = xyes; then
                break;
        fi

        PTHREAD_LIBS=""
        PTHREAD_CFLAGS=""
done
fi

# Various other checks:
if test "x$acx_pthread_ok" = xyes; then
        save_LIBS="$LIBS"
        LIBS="$PTHREAD_LIBS $LIBS"
        save_CFLAGS="$CFLAGS"
        CFLAGS="$CFLAGS $PTHREAD_CFLAGS"

        # Detect AIX lossage: JOINABLE attribute is called UNDETACHED.
	AC_MSG_CHECKING([for joinable pthread attribute])
	attr_name=unknown
	for attr in PTHREAD_CREATE_JOINABLE PTHREAD_CREATE_UNDETACHED; do
	    AC_TRY_LINK([#include <pthread.h>], [int attr=$attr;],
                        [attr_name=$attr; break])
	done
        AC_MSG_RESULT($attr_name)
        if test "$attr_name" != PTHREAD_CREATE_JOINABLE; then
            AC_DEFINE_UNQUOTED(PTHREAD_CREATE_JOINABLE, $attr_name,
                               [Define to necessary symbol if this constant
                                uses a non-standard name on your system.])
        fi

        AC_MSG_CHECKING([if more special flags are required for pthreads])
        flag=no
        case "${host_cpu}-${host_os}" in
            *-aix* | *-freebsd* | *-darwin*) flag="-D_THREAD_SAFE";;
            *solaris* | *-osf* | *-hpux*) flag="-D_REENTRANT";;
        esac
        AC_MSG_RESULT(${flag})
        if test "x$flag" != xno; then
            PTHREAD_CFLAGS="$flag $PTHREAD_CFLAGS"
        fi

        LIBS="$save_LIBS"
        CFLAGS="$save_CFLAGS"

        # More AIX lossage: must compile with cc_r
        AC_CHECK_PROG(PTHREAD_CC, cc_r, cc_r, ${CC})
else
        PTHREAD_CC="$CC"
fi

AC_SUBST(PTHREAD_LIBS)
AC_SUBST(PTHREAD_CFLAGS)
AC_SUBST(PTHREAD_CC)

# Finally, execute ACTION-IF-FOUND/ACTION-IF-NOT-FOUND:
if test x"$acx_pthread_ok" = xyes; then
        ifelse([$1],,AC_DEFINE(HAVE_PTHREAD,1,[Define if you have POSIX threads libraries and header files.]),[$1])
        :
else
        acx_pthread_ok=no
        $2
fi
AC_LANG_RESTORE
])dnl ACX_PTHREAD
