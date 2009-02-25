#!/bin/sh
# Run under duma
test "x$RUNDUMA" = "x1" || { echo "*** duma tests skipped by default, use 'make check RUNDUMA=1' to activate (but don't report bugs about timeouts!)"; exit 77; }
LIBDIRS=`../libtool --config | grep sys_lib_search_path_spec | sed -e 's/.*"\(.*\)"/\1/'`
if test -z "$LIBDUMA"; then
	for i in $LIBDIRS; do
		if test -f "$i/libduma.so"; then
			LIBDUMA="$i/libduma.so"
			break;
		fi
	done
fi
test -f "$LIBDUMA" || { echo "*** duma not found, skipping test"; exit 77;}
DUMA_FILL=90
DUMA_MALLOC_0_STRATEGY=1
DUMA_OUTPUT_FILE=duma.log
DUMA_DISABLE_BANNER=1
LIBPRELOAD="$LIBDUMA"
rm -f duma.log
export CK_DEFAULT_TIMEOUT=40
export DUMA_FILL DUMA_MALLOC_0_STRATEGY DUMA_OUTPUT_FILE DUMA_DISABLE_BANNER LIBPRELOAD
echo "--- starting clamd under duma to detect overruns"
CLAMD_WRAPPER=$abs_srcdir/preload_run.sh $abs_srcdir/check_clamd.sh
if test $? -ne 0; then
	echo "*** DUMA has detected errors"
	cat duma.log
	rm -f duma.log duma2.log
	exit 1
fi

echo "--- starting clamd under duma to detect underruns"
DUMA_OUTPUT_FILE=duma2.log
DUMA_PROTECT_BELOW=1
export DUMA_PROTECT_BELOW
rm -f duma2.log
CLAMD_TEST_UNIQ1=3 CLAMD_TEST_UNIQ2=4 CLAMD_WRAPPER=$abs_srcdir/preload_run.sh $abs_srcdir/check_clamd.sh
if test $? -ne 0; then
	echo "*** DUMA has detected errors"
	cat duma2.log
	rm -f duma.log duma2.log
	exit 1
fi
exit 0
