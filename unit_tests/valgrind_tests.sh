#!/bin/sh
# 
# We don't look for 'still reachable' blocks, since clamd fork()s after loading
# the DB. The parent exits without freeing the memory (but they are freed
# anyway due to the exit).
# To test for DB load leaks, we issue a RELOAD command, which should cause
# leaks to be reported by valgrind if there are any.
# 

test "x$VG" = "x1" || { echo "*** valgrind tests skipped by default, use 'make check VG=1' to activate"; exit 77; }
VALGRIND=`which ${VALGRIND-valgrind}`
test -n "$VALGRIND" || { echo "*** valgrind not found, skipping test"; exit 77; }
test -x "$VALGRIND" || { echo "*** valgrind not executable, skipping test"; exit 77; }

parse_valgrindlog()
{
	if test ! -f $1; then
		echo "*** Logfile $1 not found. Valgrind failed to run?"
	fi
	NRUNS=`grep "ERROR SUMMARY" $1 | wc -l`
	if test $NRUNS -eq `grep "ERROR SUMMARY: 0 errors" $1 | wc -l` && test `grep "FATAL:" $1|wc -l ` -eq 0; then
		if test "$1" = "valgrind-race.log" || 
			test $NRUNS -eq `grep "no leaks are possible" $1 | wc -l` ||
			test `grep "lost:" $1 | grep -v "0 bytes" | wc -l` -eq 0; then 
			if test -z "$GENSUPP"; then
				rm -f $1;
			fi
			return
		else
			echo "*** Valgrind test FAILED, memory LEAKS detected ***"
			grep "lost:" $1 | grep -v "0 bytes"
		fi
	else
		if test "$1" = "valgrind-race.log" ; then
			echo "*** Valgrind test FAILED, DATA RACES detected ****"
		else
			echo "*** Valgrind test FAILED, memory ERRORS detected ****"
		fi
		grep "ERROR SUMMARY" $1 | grep -v "0 errors"
		sed -rn '
			/^[=0-9]+ +at/ {
				# save current line in hold buffer
				x
				# print hold buffer
				p
				# get original line back and print
				x
				p
			}
			# store it in hold buffer
			h
		' <$1 | grep -Ev "Thread.+was created" | grep -v "Open"
	fi
	echo "***"
	echo "*** Please submit $1 to http://bugs.clamav.net"
	echo "***"
}

if test "X$VALGRIND_GENSUPP" = "X1"; then
	GENSUPP="--gen-suppressions=all"
else
	GENSUPP=
fi

VALGRIND_COMMON_FLAGS="-v --trace-children=yes --suppressions=$abs_srcdir/valgrind.supp $GENSUPP"
VALGRIND_FLAGS="$VALGRIND_COMMON_FLAGS --track-fds=yes --leak-check=full"
VALGRIND_FLAGS_RACE="$VALGRIND_COMMON_FLAGS --tool=helgrind"
export CK_DEFAULT_TIMEOUT=40
echo "--- Starting check_clamav under valgrind/memcheck"
rm -f valgrind-check.log valgrind-clamd.log valgrind-race.log
CK_FORK=no ../libtool --mode=execute $VALGRIND $VALGRIND_FLAGS ./check_clamav >valgrind-check.log 2>&1 &
pid1=$!

echo "--- Starting clamd under valgrind/memcheck"
CLAMD_WRAPPER="$VALGRIND $VALGRIND_FLAGS" $abs_srcdir/check_clamd.sh >valgrind-clamd.log 2>&1 &
pid2=$!

echo "--- Starting clamd under valgrind/helgrind"
CLAMD_TEST_UNIQ1=3 CLAMD_TEST_UNIQ2=4 CLAMD_WRAPPER="$VALGRIND $VALGRIND_FLAGS_RACE" $abs_srcdir/check_clamd.sh >valgrind-race.log 2>&1 &
pid3=$!

wait $pid1 $pid2 $pid3
parse_valgrindlog valgrind-check.log
parse_valgrindlog valgrind-clamd.log
parse_valgrindlog valgrind-race.log

if test -f valgrind-check.log || test -f valgrind-race.log || test -f valgrind-clamd.log; then
	exit 1;
fi
exit 0
