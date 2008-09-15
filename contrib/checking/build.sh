#!/bin/sh
CC=`which gcc`
CFLAGS="-fstack-protector-all -D_FORTIFY_SOURCE=2 -O2 -Wformat -Wformat-security"
LDFLAGS="-Wl,-z,relro"
MAKEFLAGS="-j4"
# disable valgrind & friends, we are testing with mudflap
VALGRIND=
LIBEFENCE=no
LIBDUMA=no
test -x "$CC" || { echo "these checks need gcc"; exit 1; }
if test "X$NOMUDFLAP" != "X1"; then
	# You can disable mudflap by setting NOMUDFLAP=1
	CFLAGS="$CFLAGS -fmudflapth -pthread"
	LDFLAGS="$LDFLAGS -lmudflapth"
fi
if test "X$NOPIE" != "X1"; then
	# You can disable PIE by NOPIE = 1
	CFLAGS="$CFLAGS -fPIE"
	LDFLAGS="$LDFLAGS -pie"
	CONF_FLAGS="ac_cv_findlib_CHECK_libs=-lcheck_pic ac_cv_findlib_CHECK_ltlibs=-lcheck_pic"
fi

rm -rf _build
mkdir _build
export CC CFLAGS LDFLAGS MAKEFLAGS VALGRIND LIBEFENCE LIBDUMA
(cd _build &&
../../../configure --disable-static --disable-clamav --enable-check $CONF_FLAGS &&
make &&
make check) &&
rm -rf _build
