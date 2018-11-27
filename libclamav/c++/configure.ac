dnl   This program is free software; you can redistribute it and/or modify
dnl   it under the terms of the GNU General Public License as published by
dnl   the Free Software Foundation; either version 2 of the License, or
dnl   (at your option) any later version.
dnl
dnl   This program is distributed in the hope that it will be useful,
dnl   but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl   GNU General Public License for more details.
dnl
dnl   You should have received a copy of the GNU General Public License
dnl   along with this program; if not, write to the Free Software
dnl   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
dnl   MA 02110-1301, USA.

AC_PREREQ([2.59])
AC_INIT([libclamavc++],[devel],[https://bugzilla.clamav.net])
AC_CONFIG_AUX_DIR([config])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADER([clamavcxx-config.h])
AC_CANONICAL_TARGET
AM_INIT_AUTOMAKE([1.9 -Wall -Wportability foreign no-define color-tests tar-pax])
AM_SILENT_RULES([yes])

cxxset=${CXXFLAGS+set}
AC_PROG_CXX
AC_C_BIGENDIAN

if test "$cxxset" != set; then
# don't use the default -O2 -g because -g bloats the C++ binaries too much
  CXXFLAGS="-O2"
fi
case "$target_os" in
solaris*)
  CXXFLAGS="$CXXFLAGS -include llvm/include/llvm/System/Solaris.h"
  AC_MSG_NOTICE([Building on Solaris])
  ;;
esac

m4_include([../../m4/reorganization/libs/openssl.m4])
AC_SUBST(SSL_CPPFLAGS, [$SSL_CPPFLAGS])

AM_MAINTAINER_MODE
LT_INIT([disable-static])
if test "$GXX" != "yes"; then
    AC_MSG_ERROR([GNU C++ compiler not found, not building LLVM])
fi

AC_CHECK_GNU_MAKE
GMAKE="$llvm_cv_gnu_make_command"
AC_SUBST([GMAKE])

m4_include(m4/llvm-opts.m4)
if test "x$llvmflagerrmsg" != "x"; then
    AC_MSG_ERROR([$llvmflagerrmsg])
fi

dnl Version number check
if test "x$llvmconfig" != "x"; then
    AC_MSG_NOTICE([Using external LLVM])
else
    packaged_llvm="yes"
    dnl macro not available in older autotools
    AC_CONFIG_SUBDIRS([llvm])
fi

llvmver_prefix=`expr "$llvmver" : '\([[^0-9]]*\)'`
llvmver_frag=${llvmver#$llvmver_prefix}

llvmver_major=`expr "$llvmver_frag" : '\([[0-9]]*\)'`
llvmver_frag=${llvmver_frag#*\.}
llvmver_minor=`expr "$llvmver_frag" : '\([[0-9]]*\)'`
llvmver_frag=${llvmver_frag#*\.}
llvmver_patch=`expr "$llvmver_frag" : '\([[0-9]]*\)'`

dnl suffix unused as of LLVM 3.4.1
llvmver_suffix=
if test "x$llvmver_patch" = "x"; then
    llvmver_patch=0
fi

AC_MSG_CHECKING([for supported LLVM version])
llvmver_test=${llvmver_major}${llvmver_minor}${llvmver_patch}
if test "x$packaged_llvm" = "xyes"; then
    AC_MSG_RESULT([ok ($llvmver)])
elif test $llvmver_test -lt 290; then
    AC_MSG_RESULT([no ($llvmver)])
    AC_MSG_ERROR([LLVM >= 2.9 required, but "$llvmver"($llvmver_test) found])
elif test $llvmver_test -lt 360; then
    llvmcomp="jit nativecodegen scalaropts ipo"
    AC_MSG_RESULT([ok ($llvmver)])
elif test $llvmver_test -lt 370; then
    dnl LLVM 3.6.0 removed jit, so we have to use mcjit
    dnl and we're using InitializeNativeTargetAsmParser, so we need the architecture specific parsers
    llvmcomp="mcjit nativecodegen scalaropts ipo x86asmparser powerpcasmparser"
    AC_MSG_RESULT([ok ($llvmver)])
else
    AC_MSG_RESULT([no ($llvmver)])
    AC_MSG_ERROR([LLVM < 3.7 required, but "$llvmver"($llvmver_test) found])
fi

dnl acquire the required flags to properly link in external LLVM
if test "x$llvmconfig" != "x"; then
    AC_SUBST(LLVMCONFIG_CXXFLAGS, [`$llvmconfig --cxxflags`])

    if test "x$llvm_linking" = "xdynamic"; then
        AC_SUBST(LLVMCONFIG_LDFLAGS, [`$llvmconfig --ldflags`])
        AC_SUBST(LLVMCONFIG_LIBS, [-lLLVM-$llvmver])
        AC_SUBST(LLVMCONFIG_LIBFILES, [])
    else
        if test $llvmver_test -ge 350; then
           dnl LLVM 3.5.0 and after splits linker flags into two sets
           ldflags=`$llvmconfig --ldflags`
           syslibs=`$llvmconfig --system-libs`
           AC_SUBST(LLVMCONFIG_LDFLAGS, ["$ldflags $syslibs"])
        else
           AC_SUBST(LLVMCONFIG_LDFLAGS, [`$llvmconfig --ldflags`])
        fi
        AC_SUBST(LLVMCONFIG_LIBS, [`$llvmconfig --libs $llvmcomp`])
        AC_SUBST(LLVMCONFIG_LIBFILES, [`$llvmconfig --libfiles $llvmcomp`])
    fi

    AC_MSG_NOTICE([CXXFLAGS from llvm-config: $LLVMCONFIG_CXXFLAGS])
    AC_MSG_NOTICE([LDFLAGS from llvm-config: $LLVMCONFIG_LDFLAGS])
    AC_MSG_NOTICE([LIBS from llvm-config: $LLVMCONFIG_LIBS])
fi
dnl patch does not affect clamav source (yet)
llvmver_int=${llvmver_major}${llvmver_minor}
AC_SUBST([LLVM_VERSION], [$llvmver_int])

AC_ARG_ENABLE([llvm],AC_HELP_STRING([-enable-llvm],
				    [Enable 'llvm' JIT/verifier support @<:@default=auto@:>@]),
				    [enable_llvm=$enableval], [enable_llvm="auto"])

AC_ARG_ENABLE(optimized, AC_HELP_STRING([-enable-optimized],
	      [Compile with optimizations enabled (default is YES)]),
	      enable_optimized=$enableval, enable_optimized=default)
AM_CONDITIONAL(DEBUG_BUILD,[test "x$enable_optimized" = "xno"])

dnl Set configure args for subdir
if test "$enable_optimized" = "default"; then
    ac_configure_args="$ac_configure_args --enable-optimized"
fi

dnl Pretend that GNU make is available for LLVM, we don't use LLVM's buildsystem
dnl anyway (except for make check)
ac_configure_args="$ac_configure_args llvm_cv_gnu_make_command=make"
AC_ARG_ENABLE(all-jit-targets, AC_HELP_STRING([-enable-all-jit-targets],
	      [Build all the targets that support JIT for testing (default NO)]),
	      enable_alltargets=$enableval, enable_alltargets=no)
if test "$enable_alltargets" = "yes"; then
    new_args="$ac_configure_args --enable-targets=x86,powerpc --enable-bindings=none --enable-libffi=no --without-llvmgcc --without-llvmgxx"
else
    new_args="$ac_configure_args --enable-targets=host-only --enable-bindings=none --enable-libffi=no --without-llvmgcc --without-llvmgxx"
fi
ac_configure_args=`echo $new_args | sed -e 's/-Werror //g'`

if test "$enable_llvm" = "auto"; then
    dnl Do some sanity checks, and don't automatically build on platforms
    dnl that are not supported or have broken compilers.
    dnl The user can override this by specifying --enable-llvm=yes.
    AC_MSG_CHECKING([for supported C++ compiler version])
    gxx_version=`${CXX} -dumpversion` ||
    AC_MSG_ERROR([Unable to get GNU C++ compiler version])
    case "${gxx_version}" in
     [[03]].*)
	AC_MSG_ERROR([C++ compiler too old (${gxx_version})])
        ;;
     4.1.[[1]]*)
        AC_MSG_ERROR([C++ compiler is buggy])
        ;;
     *)
        AC_MSG_RESULT([ok (${gxx_version})])
    esac

    AC_MSG_CHECKING([for supported OS])
    case "$target_cpu" in
	i?86|amd64|x86_64|powerpc*)
	    case "$target_os" in
		darwin*|freebsd*|kfreebsd*|openbsd*|netbsd*|dragonfly*|linux*|solaris*|win32*|mingw*)
		    AC_MSG_RESULT([ok ($target_cpu-$target_os)])
		    ;;
		*)
                    AC_MSG_ERROR([OS $target_os is not supported, not building LLVM])
                    ;;
	    esac
	    ;;
	alpha*|arm*)
	    AC_MSG_ERROR([CPU support is untested, not building LLVM])
	    ;;
	*)
	    AC_MSG_ERROR([Unsupported CPU for JIT: $target_cpu, not building LLVM])
	    ;;
    esac
fi

dnl bb #1971 - doesn't work with older libstdc++ version at link/runtime
AC_MSG_CHECKING([for working libstdc++])
AC_LANG_PUSH([C++])
AC_RUN_IFELSE(
    [AC_LANG_SOURCE([
	#include <iostream>
	int main()
	{
	    // this causes an @GLIBCXX_3.4.9 symbol to be linked in -O2 mode
	    std::cout << "test";
	    return 0;
    }
    ])],[AC_MSG_RESULT([yes])],
    [AC_MSG_FAILURE([failed])],
[AC_LINK_IFELSE(
    [AC_LANG_SOURCE([
	#include <iostream>
	int main()
	{
	    // this causes an @GLIBCXX_3.4.9 symbol to be linked in -O2 mode
	    std::cout << "test";
	    return 0;
	}
    ])], [AC_MSG_RESULT([yes])],
    [AC_MSG_FAILURE([failed])]
)])
AC_LANG_POP([C++])

build_x86=no
build_ppc=no
case "$target_cpu" in
    i?86|amd64|x86_64)
	    build_x86=yes
	    ;;
    powerpc*)
	    build_ppc=yes
	    ;;
esac

# FreeBSD is only one which needs something else than -pthread,
# according to the logic in ClamAV's main configure.in.
case "$target_os" in
freebsd[[45]]*)
    THREAD_LIBS="-pthread -lc_r"
    ;;
freebsd*)
    THREAD_LIBS="-lthr"
    ;;
darwin*)
    # none required
    THREAD_LIBS=
    ;;

*)
    THREAD_LIBS="-pthread"
esac
AC_SUBST([THREAD_LIBS])

if test "$enable_alltargets" = "yes"; then
	build_x86=yes
	build_ppc=yes
fi
if test "$ac_cv_c_bigendian" = "universal"; then
    AC_MSG_NOTICE([Universal build detected])
    build_x86=yes
    build_ppc=yes
fi
AC_MSG_NOTICE([Building X86 backend: $build_x86])
AC_MSG_NOTICE([Building PPC backend: $build_ppc])
AM_CONDITIONAL(BUILD_X86, [test "$build_x86" = "yes"])
AM_CONDITIONAL(BUILD_PPC, [test "$build_ppc" = "yes"])

AC_MSG_CHECKING([optional compiler flags])
CXX_FLAG_CHECK(NO_VARIADIC_MACROS, [-Wno-variadic-macros])
CXX_FLAG_CHECK(NO_MISSING_FIELD_INITIALIZERS, [-Wno-missing-field-initializers])
AC_MSG_RESULT([$NO_VARIADIC_MACROS $NO_MISSING_FIELD_INITIALIZERS])

AM_CONDITIONAL(BUILD_EXTERNAL_LLVM, [test -n "$llvmconfig"])

AC_OUTPUT([
    Makefile
])
