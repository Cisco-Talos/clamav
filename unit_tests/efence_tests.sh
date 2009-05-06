#!/bin/sh
# Run under electric-fence
LIBDIRS=`../libtool --config | grep sys_lib_dlsearch_path_spec | sed -e 's/.*"\(.*\)"/\1/'`
if test -z "$LIBEFENCE"; then
	for i in $LIBDIRS /usr/local/lib; do
		if test -f "$i/libefence.so"; then
			LIBEFENCE="$i/libefence.so"
			break;
		fi
	done
fi
test -f "$LIBEFENCE" || { echo "*** electric-fence not found, skipping test"; exit 77;}

# use the default EF_ALIGNMENT only for x86/x86_64, and set it to 8 for other
# platforms. ia64 needs this for example.
(../libtool --config | grep host=x86) || { EF_ALIGNMENT=8; export EF_ALIGNMENT; }
EF_DISABLE_BANNER=1
EF_FREE_WIPES=1
LIBPRELOAD="$LIBEFENCE"
export EF_FREE_WIPES LIBPRELOAD EF_DISABLE_BANNER
VALGRIND=`which ${VALGRIND-valgrind}`
if test ! -n "$VALGRIND" || test ! -x "$VALGRIND"; then
	# run check_clamav under efence only if we don't have valgrind installed
	echo "--- Running check_clamav under electric-fence"
	CK_FORK=no ../libtool --mode=execute $abs_srcdir/preload_run.sh ./check_clamav
	if test $? -ne 0; then
		echo "*** Electric-fence has detected errors"
		exit 1
	fi
fi
# we don't run clamd under electric-fence, it always crashes in free(),
# probably doesn't work well with libpthread.
echo "--- running clamscan under electric-fence to detect overruns"
CLAMSCAN_WRAPPER=$abs_srcdir/preload_run.sh $abs_srcdir/check_clamscan.sh
if test $? -ne 0; then
	echo "*** Electric-fence has detected errors"
	exit 2
fi
EF_PROTECT_BELOW=1
export EF_PROTECT_BELOW
echo "--- running clamscan under electric-fence to detect underruns"
CLAMSCAN_WRAPPER=$abs_srcdir/preload_run.sh $abs_srcdir/check_clamscan.sh
if test $? -ne 0; then
	echo "*** Electric-fence has detected errors"
	exit 3
fi
