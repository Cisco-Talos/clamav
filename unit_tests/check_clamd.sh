#!/bin/sh 
#set -x
killclamd() {
	test -f /tmp/clamd-test.pid || return
	pid=`cat /tmp/clamd-test.pid`
	kill -0 $pid && kill $pid
	pippo=0
	while test -f /tmp/clamd-test.pid; do
		sleep 1
		pippo=`expr $pippo + 1`
		if test $pippo -gt 9; then
			kill -KILL $pid
			rm /tmp/clamd-test.pid
		fi
	done
}
die() {
	killclamd
	rm -rf test-db test-clamd-viraction.conf test-clamd.log	test-clamd-heur-pred.conf clamd-test.socket
	exit $1
}
run_clamd_test() {
	conf_file=$1
	shift
	rm -f clamdscan.log
	../clamd/clamd -c $conf_file || { echo "Failed to start clamd!" >&2; die 1;}
	../clamdscan/clamdscan --version --config-file $conf_file 2>&1|grep "^ClamAV" >/dev/null || { echo "clamdscan can't get version of clamd!" >&2; die 2;}
	../clamdscan/clamdscan --quiet --config-file $conf_file $* --log=clamdscan.log
	if test $? = 2; then 
		echo "Failed to run clamdscan!" >&2;
		die 3;	
	fi
	killclamd
}

run_clamd_fdpass_test() {
	conf_file=$1
	shift
	rm -f clamdscan.log
	../clamd/clamd -c $conf_file || { echo "Failed to start clamd!" >&2; die 1;}
	../clamdscan/clamdscan --quiet --fdpass --config-file $conf_file - <$1 --log=clamdscan.log
	if test $? = 2; then
		echo "Failed to run clamdscan!" >&2;
		die 3;
	fi
	killclamd
}

mkdir -p test-db
cat <<EOF >test-db/test.hdb
aa15bcf478d165efd2065190eb473bcb:544:ClamAV-Test-File
EOF
cp $srcdir/input/daily.ftm test-db/
cp $srcdir/input/daily.pdb test-db/

# Test that all testfiles are detected
FILES=../test/clam*
run_clamd_test $srcdir/test-clamd.conf $FILES
NFILES=`ls -1 $FILES | wc -l`
NINFECTED=`grep "Infected files" clamdscan.log | cut -f2 -d:|sed -e 's/ //g'`
if test "$NFILES" -ne "0$NINFECTED"; then
	echo "clamd did not detect all testfiles correctly!" >&2;
	grep OK clamdscan.log >&2;
	die 4;
fi

# Test VirusEvent feature
cat <$srcdir/test-clamd.conf >test-clamd-viraction.conf
echo "VirusEvent `pwd`/$srcdir/virusaction-test.sh `pwd` \"Virus found: %v\"" >>test-clamd-viraction.conf
rm -f test-clamd.log
run_clamd_test test-clamd-viraction.conf ../test/clam.exe
grep "Virus found: ClamAV-Test-File.UNOFFICIAL" test-clamd.log >/dev/null 2>/dev/null; 
if test ! $? ; then
	echo "Virusaction test failed!" 
	cat test-clamd.log
	die 5;
fi

# Test HeuristicScanPrecedence feature
cat <$srcdir/test-clamd.conf >test-clamd-heur-pred.conf
run_clamd_test test-clamd-heur-pred.conf clam-phish-exe
grep "ClamAV-Test-File" clamdscan.log >/dev/null 2>/dev/null;
if test ! $?; then
	echo "HeuristicScanPrecedence off test failed!" >&2;
	cat clamdscan.log;
	die 6;
fi
echo "HeuristicScanPrecedence yes" >>test-clamd-heur-pred.conf
run_clamd_test test-clamd-heur-pred.conf clam-phish-exe
grep "Phishing.Heuristics.Email.SpoofedDomain" clamdscan.log >/dev/null 2>/dev/null;
if test ! $?; then
	echo "HeuristicScanPrecedence on test failed!" >&2;
	cat clamdscan.log;
	die 6;
fi

if grep "^#define HAVE_FD_PASSING 1" ../clamav-config.h >/dev/null; then
	run_clamd_fdpass_test $srcdir/test-clamd.conf ../test/clam.exe
	grep "ClamAV-Test-File" clamdscan.log >/dev/null 2>/dev/null;
	if test ! $?; then
		echo "FDpassing test failed!" >&2;
		cat clamdscan.log;
		die 7;
	fi
else
	echo "No FD passing support, skipping test"
fi
die 0;
