#!/bin/sh
# Run under duma
for i in $LIBDUMA /usr/lib/libduma.so /usr/local/lib/libduma.so; do
	if test -f "$i"; then
		LIBDUMA="$i"
		break;
	fi
done
test -f "$LIBDUMA" || { echo "*** duma not found, skipping test"; exit 77;}
DUMA_FILL=90
DUMA_MALLOC_0_STRATEGY=1
DUMA_OUTPUT_FILE=duma.log
DUMA_DISABLE_BANNER=1
LIBPRELOAD="$LIBDUMA"
rm -f duma.log
export DUMA_FILL DUMA_MALLOC_0_STRATEGY DUMA_OUTPUT_FILE DUMA_DISABLE_BANNER LIBPRELOAD
echo "--- running clamd under duma to detect underruns"
CLAMD_WRAPPER=$srcdir/preload_run.sh $srcdir/check_clamd.sh
if test ! $?; then
	echo "*** DUMA has detected errors"
	cat duma.log
	exit 3
fi
DUMA_PROTECT_BELOW=1
export DUMA_PROTECT_BELOW
echo "--- running clamd under duma to detect underruns"
rm -f duma.log
CLAMD_WRAPPER=$srcdir/preload_run.sh $srcdir/check_clamd.sh
if test ! $?; then
	echo "*** DUMA has detected errors"
	cat duma.log
	exit 3
fi
rm -f duma.log

