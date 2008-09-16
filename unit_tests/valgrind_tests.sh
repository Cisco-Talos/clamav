#!/bin/sh
# 
# We don't look for 'still reachable' blocks, since clamd fork()s after loading
# the DB. The parent exits without freeing the memory (but they are freed
# anyway due to the exit).
# To test for DB load leaks, we issue a RELOAD command, which should cause
# leaks to be reported by valgrind if there are any.
# 

VALGRIND=`which ${VALGRIND-valgrind}`
test -n "$VALGRIND" || { echo "*** valgrind not found, skipping test"; exit 77; }
test -x "$VALGRIND" || { echo "*** valgrind not executable, skipping test"; exit 77; }

parse_valgrindlog()
{
	if test ! -f $1; then
		echo "*** Logfile $1 not found. Valgrind failed to run?"
	fi
	NRUNS=`grep "ERROR SUMMARY" $1 | wc -l`
	if test $NRUNS -eq `grep "ERROR SUMMARY: 0 errors" $1 | wc -l`; then
		if test "$1" = "valgrind-race.log" || 
			test $NRUNS -eq `grep "no leaks are possible" $1 | wc -l` ||
			test `grep "lost:" $1 | grep -v "0 bytes" | wc -l` -ne 0; then 
			rm -f $1;
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
				# get original line back
				x
			}
			# store it in hold buffer
			h
			/^[=0-9]+ FILE DESC/ {
				q
			}
		' <$1 | grep -v "Thread.+was created"
	fi
	echo "***"
	echo "*** Please submit $1 to http://bugs.clamav.net"
	echo "***"
}


VALGRIND_FLAGS="-v --trace-children=yes --track-fds=yes --leak-check=full --suppressions=$srcdir/valgrind.supp"
VALGRIND_FLAGS_RACE="-v --tool=helgrind --trace-children=yes --suppressions=$srcdir/valgrind.supp"

echo "--- Starting check_clamav under valgrind/memcheck"
rm -f valgrind-check.log valgrind-clamd.log valgrind-race.log
CK_FORK=no ../libtool --mode=execute $VALGRIND $VALGRIND_FLAGS ./check_clamav >valgrind-check.log 2>&1 &
pid=$!
echo "--- Starting clamd under valgrind/memcheck"
CLAMD_WRAPPER="$VALGRIND $VALGRIND_FLAGS" $srcdir/check_clamd.sh >valgrind-clamd.log 2>&1

echo "--- Starting clamd under valgrind/helgrind"
CLAMD_WRAPPER="$VALGRIND $VALGRIND_FLAGS_RACE" $srcdir/check_clamd.sh >valgrind-race.log 2>&1

wait $pid
parse_valgrindlog valgrind-check.log
parse_valgrindlog valgrind-clamd.log
parse_valgrindlog valgrind-race.log

if test -f valgrind-check.log -o -f valgrind-race.log -o -f valgrind-clamd.log; then
	exit 1;
fi
exit 0
