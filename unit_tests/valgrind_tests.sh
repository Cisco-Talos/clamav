#!/bin/sh
VALGRIND=`which ${VALGRIND-valgrind}`
VALGRIND_FLAGS="--trace-children=yes --track-fds=yes --leak-check=full --show-reachable=yes --suppressions=$srcdir/valgrind.supp"
test -n "$VALGRIND" || { echo "*** valgrind not found, skipping test"; exit 77; }
test -x "$VALGRIND" || { echo "*** valgrind not executable, skipping test"; exit 77; }

echo "Running valgrind"
CK_FORK=no ../libtool --mode=execute $VALGRIND $VALGRIND_FLAGS ./check_clamav 2>&1 | cat >valgrind.log
if grep "ERROR SUMMARY: 0 errors" valgrind.log >/dev/null; then
	if grep "no leaks are possible" valgrind.log >/dev/null; then
		echo "Valgrind tests successful"
		exit 0;
	fi
	echo "*** Valgrind test FAILED, memory LEAKS detected ***"
else
	echo "*** Valgrind test FAILED, memory ERRORS detected ****"
fi
echo 
grep "ERROR SUMMARY" valgrind.log
echo `grep "Invalid read" valgrind.log| wc -l` "invalid reads"
echo `grep "Invalid write" valgrind.log| wc -l` "invalid writes"
echo `grep "Invalid free" valgrind.log| wc -l` "invalid frees"
echo `grep "uninitialised value" valgrind.log|wc -l` "uses of uninitialized values"
grep " lost:" valgrind.log
grep "still reachable:" valgrind.log
grep "FILE DESCRIPTORS" valgrind.log
echo 
exit 1;
