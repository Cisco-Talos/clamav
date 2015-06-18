dnl Autoconf macros for libprelude
dnl $id$

# Modified for LIBPRELUDE -- Yoann Vandoorselaere
# Modified for LIBGNUTLS -- nmav
# Configure paths for LIBGCRYPT
# Shamelessly stolen from the one of XDELTA by Owen Taylor
# Werner Koch   99-12-09

dnl AM_PATH_LIBPRELUDE([MINIMUM-VERSION, [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND ]]], THREAD_SUPPORT)
dnl Test for libprelude, and define LIBPRELUDE_PREFIX, LIBPRELUDE_CFLAGS, LIBPRELUDE_PTHREAD_CFLAGS,
dnl LIBPRELUDE_LDFLAGS, and LIBPRELUDE_LIBS
dnl
AC_DEFUN([AM_PATH_LIBPRELUDE],
[dnl
dnl Get the cflags and libraries from the libprelude-config script
dnl
AC_ARG_WITH(libprelude-prefix, AC_HELP_STRING(--with-libprelude-prefix=PFX,
            Prefix where libprelude is installed (optional)),
            libprelude_config_prefix="$withval", libprelude_config_prefix="")

  if test x$libprelude_config_prefix != x ; then
     if test x${LIBPRELUDE_CONFIG+set} != xset ; then
        LIBPRELUDE_CONFIG=$libprelude_config_prefix/bin/libprelude-config
     fi
  fi

  AC_PATH_PROG(LIBPRELUDE_CONFIG, libprelude-config, no)
  if test "$LIBPRELUDE_CONFIG" != "no"; then
	if $($LIBPRELUDE_CONFIG --thread > /dev/null 2>&1); then
		LIBPRELUDE_PTHREAD_CFLAGS=`$LIBPRELUDE_CONFIG --thread --cflags`

		if test x$4 = xtrue || test x$4 = xyes; then
			libprelude_config_args="--thread"
		else
			libprelude_config_args="--no-thread"
		fi
	else
		LIBPRELUDE_PTHREAD_CFLAGS=`$LIBPRELUDE_CONFIG --pthread-cflags`
	fi
  fi

  min_libprelude_version=ifelse([$1], ,0.1.0,$1)
  AC_MSG_CHECKING(for libprelude - version >= $min_libprelude_version)
  no_libprelude=""
  if test "$LIBPRELUDE_CONFIG" = "no" ; then
    no_libprelude=yes
  else
    LIBPRELUDE_CFLAGS=`$LIBPRELUDE_CONFIG $libprelude_config_args --cflags`
    LIBPRELUDE_LDFLAGS=`$LIBPRELUDE_CONFIG $libprelude_config_args --ldflags`
    LIBPRELUDE_LIBS=`$LIBPRELUDE_CONFIG $libprelude_config_args --libs`
    LIBPRELUDE_PREFIX=`$LIBPRELUDE_CONFIG $libprelude_config_args --prefix`
    LIBPRELUDE_CONFIG_PREFIX=`$LIBPRELUDE_CONFIG $libprelude_config_args --config-prefix`
    libprelude_config_version=`$LIBPRELUDE_CONFIG $libprelude_config_args --version`


      ac_save_CFLAGS="$CFLAGS"
      ac_save_LDFLAGS="$LDFLAGS"
      ac_save_LIBS="$LIBS"
      CFLAGS="$CFLAGS $LIBPRELUDE_CFLAGS"
      LDFLAGS="$LDFLAGS $LIBPRELUDE_LDFLAGS"
      LIBS="$LIBS $LIBPRELUDE_LIBS"
dnl
dnl Now check if the installed libprelude is sufficiently new. Also sanity
dnl checks the results of libprelude-config to some extent
dnl
      rm -f conf.libpreludetest
      AC_TRY_RUN([
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libprelude/prelude.h>

int
main ()
{
    system ("touch conf.libpreludetest");

    if( strcmp( prelude_check_version(NULL), "$libprelude_config_version" ) )
    {
      printf("\n*** 'libprelude-config --version' returned %s, but LIBPRELUDE (%s)\n",
             "$libprelude_config_version", prelude_check_version(NULL) );
      printf("*** was found! If libprelude-config was correct, then it is best\n");
      printf("*** to remove the old version of LIBPRELUDE. You may also be able to fix the error\n");
      printf("*** by modifying your LD_LIBRARY_PATH enviroment variable, or by editing\n");
      printf("*** /etc/ld.so.conf. Make sure you have run ldconfig if that is\n");
      printf("*** required on your system.\n");
      printf("*** If libprelude-config was wrong, set the environment variable LIBPRELUDE_CONFIG\n");
      printf("*** to point to the correct copy of libprelude-config, and remove the file config.cache\n");
      printf("*** before re-running configure\n");
    }
    else if ( strcmp(prelude_check_version(NULL), LIBPRELUDE_VERSION ) ) {
        printf("\n*** LIBPRELUDE header file (version %s) does not match\n", LIBPRELUDE_VERSION);
        printf("*** library (version %s)\n", prelude_check_version(NULL) );
    }
    else {
      if ( prelude_check_version( "$min_libprelude_version" ) )
        return 0;
      else {
        printf("no\n*** An old version of LIBPRELUDE (%s) was found.\n",
                prelude_check_version(NULL) );
        printf("*** You need a version of LIBPRELUDE newer than %s. The latest version of\n",
               "$min_libprelude_version" );
        printf("*** LIBPRELUDE is always available from http://www.prelude-ids.com/development/download/\n");
        printf("*** \n");
        printf("*** If you have already installed a sufficiently new version, this error\n");
        printf("*** probably means that the wrong copy of the libprelude-config shell script is\n");
        printf("*** being found. The easiest way to fix this is to remove the old version\n");
        printf("*** of LIBPRELUDE, but you can also set the LIBPRELUDE_CONFIG environment to point to the\n");
        printf("*** correct copy of libprelude-config. (In this case, you will have to\n");
        printf("*** modify your LD_LIBRARY_PATH enviroment variable, or edit /etc/ld.so.conf\n");
        printf("*** so that the correct libraries are found at run-time))\n");
      }
    }
    return 1;
}
],, no_libprelude=yes,[echo $ac_n "cross compiling; assumed OK... $ac_c"])
       CFLAGS="$ac_save_CFLAGS"
       LIBS="$ac_save_LIBS"
       LDFLAGS="$ac_save_LDFLAGS"
  fi

  if test "x$no_libprelude" = x ; then
     AC_MSG_RESULT(yes)
     ifelse([$2], , :, [$2])
  else
     if test -f conf.libpreludetest ; then
        :
     else
        AC_MSG_RESULT(no)
     fi
     if test "$LIBPRELUDE_CONFIG" = "no" ; then
       echo "*** The libprelude-config script installed by LIBPRELUDE could not be found"
       echo "*** If LIBPRELUDE was installed in PREFIX, make sure PREFIX/bin is in"
       echo "*** your path, or set the LIBPRELUDE_CONFIG environment variable to the"
       echo "*** full path to libprelude-config."
     else
       if test -f conf.libpreludetest ; then
        :
       else
          echo "*** Could not run libprelude test program, checking why..."
          CFLAGS="$CFLAGS $LIBPRELUDE_CFLAGS"
          LDFLAGS="$LDFLAGS $LIBPRELUDE_LDFLAGS"
          LIBS="$LIBS $LIBPRELUDE_LIBS"
          AC_TRY_LINK([
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libprelude/prelude.h>
],      [ return !!prelude_check_version(NULL); ],
        [ echo "*** The test program compiled, but did not run. This usually means"
          echo "*** that the run-time linker is not finding LIBPRELUDE or finding the wrong"
          echo "*** version of LIBPRELUDE. If it is not finding LIBPRELUDE, you'll need to set your"
          echo "*** LD_LIBRARY_PATH environment variable, or edit /etc/ld.so.conf to point"
          echo "*** to the installed location  Also, make sure you have run ldconfig if that"
          echo "*** is required on your system"
          echo "***"
          echo "*** If you have an old version installed, it is best to remove it, although"
          echo "*** you may also be able to get things to work by modifying LD_LIBRARY_PATH"
          echo "***" ],
        [ echo "*** The test program failed to compile or link. See the file config.log for the"
          echo "*** exact error that occured. This usually means LIBPRELUDE was incorrectly installed"
          echo "*** or that you have moved LIBPRELUDE since it was installed. In the latter case, you"
          echo "*** may want to edit the libprelude-config script: $LIBPRELUDE_CONFIG" ])
          CFLAGS="$ac_save_CFLAGS"
          LDFLAGS="$ac_save_LDFLAGS"
          LIBS="$ac_save_LIBS"
       fi
     fi
     LIBPRELUDE_CFLAGS=""
     LIBPRELUDE_LDFLAGS=""
     LIBPRELUDE_LIBS=""
     ifelse([$3], , :, [$3])
  fi
  rm -f conf.libpreludetest
  AC_SUBST(LIBPRELUDE_CFLAGS)
  AC_SUBST(LIBPRELUDE_PTHREAD_CFLAGS)
  AC_SUBST(LIBPRELUDE_LDFLAGS)
  AC_SUBST(LIBPRELUDE_LIBS)
  AC_SUBST(LIBPRELUDE_PREFIX)
  AC_SUBST(LIBPRELUDE_CONFIG_PREFIX)

  m4_ifdef([LT_INIT],
           [AC_DEFINE([PRELUDE_APPLICATION_USE_LIBTOOL2], [], [Define whether application use libtool >= 2.0])],
           [])

])

dnl *-*wedit:notab*-*  Please keep this as the last line.
