#!/bin/sh 
CLAMD_WRAPPER=${CLAMD_WRAPPER-}
CLAMD_TEST_UNIQ1=${CLAMD_TEST_UNIQ1-1}
CLAMD_TEST_UNIQ2=${CLAMD_TEST_UNIQ2-2}
TOP="../.."
LTEXEC="$TOP/libtool --mode=execute"
killclamd() {
	test -f clamd-test.pid || return
	pid=`cat clamd-test.pid 2>/dev/null`
	if test "X$pid" = "X"; then
		# file can be removed between the 'test' and 'cat',
		# it happened a few times for me
		return
	fi
	kill -0 $pid 2>/dev/null || return
	kill $pid
	pippo=0
	while kill -0 $pid 2>/dev/null; do
		sleep 1
		pippo=`expr $pippo + 1`
		if test $pippo -gt 9; then
			kill -KILL $pid
			echo "Clamd didn't quit";
			rm -f clamd-test.pid
			exit 4;
		fi
	done
	rm -f clamd-test.pid
}

die()
{
	killclamd
	exit $1
}

error()
{
	echo >&2
	echo "***" >&2
	echo "*** $1" >&2
	echo "***" >&2
}

scan_failed() {
	if test "X$unrar_disabled" = "X1" && test `grep -v '\.rar' $1 | grep OK | wc -l` -eq 0
	then
		error "UNRAR is disabled, won't be able to detect unrar files!";
	else
		error  $2;
		die 2;
	fi
}

start_clamd()
{
	rm -f clamd-test.log ../clamd-test1.log ../clamd-test2.log
	$LTEXEC $CLAMD_WRAPPER $TOP/clamd/clamd -c $1 --help >clamd-test.log 2>&1 || 
		{ error "Failed to start clamd --help!"; cat clamd-test.log; die 1; }
	grep "Clam AntiVirus Daemon" clamd-test.log >/dev/null ||
		{ error "Wrong --help reply from clamd!"; die 1; }
	$LTEXEC $CLAMD_WRAPPER $TOP/clamd/clamd -c $1 >clamd-test.log 2>&1 || 
		{ error "Failed to start clamd!"; cat clamd-test.log; die 1; }
}

run_clamdscan_fileonly() {
	rm -f clamdscan.log clamdscan-multiscan.log
	$TOP/clamdscan/clamdscan --version --config-file=test-clamd.conf 2>&1|grep "^ClamAV" >/dev/null || 
		{ error "clamdscan can't get version of clamd!"; die 1;}
	$TOP/clamdscan/clamdscan --quiet --config-file=test-clamd.conf $* --log=clamdscan.log
	if test $? = 2; then 
		error "Failed to run clamdscan!"
		cat clamdscan.log
		die 1
	fi
	$TOP/clamdscan/clamdscan --quiet --config-file=test-clamd.conf $* -m --log=clamdscan-multiscan.log
	if test $? = 2; then 
		error "Failed to run clamdscan (multiscan)!"
		cat clamdscan-multiscan.log
		die 1
	fi
}

run_clamdscan() {
	run_clamdscan_fileonly $*
	rm -f clamdscan-fdpass.log clamdscan-multiscan-fdpass.log
	$TOP/clamdscan/clamdscan --quiet --config-file=test-clamd.conf $* --fdpass --log=clamdscan-fdpass.log
	if test $? = 2; then 
		error "Failed to run clamdscan (fdpass)!"
		cat clamdscan-fdpass.log
		die 1
	fi
	$TOP/clamdscan/clamdscan --quiet --config-file=test-clamd.conf $* -m --fdpass --log=clamdscan-multiscan-fdpass.log
	if test $? = 2; then 
		error "Failed to run clamdscan (fdpass + multiscan)!"
		cat clamdscan-multiscan-fdpass.log
		die 1
	fi
	$TOP/clamdscan/clamdscan --quiet --config-file=test-clamd.conf $* --stream --log=clamdscan-stream.log
	if test $? = 2; then 
		error "Failed to run clamdscan (instream)!"
		cat clamdscan-stream.log
		die 1
	fi
	$TOP/clamdscan/clamdscan --quiet --config-file=test-clamd.conf $* -m --stream --log=clamdscan-multiscan-stream.log
	if test $? = 2; then 
		error "Failed to run clamdscan (instream + multiscan)!"
		cat clamdscan-multiscan-stream.log
		die 1
	fi
}

run_reload_test()
{
	rm -f reload-testfile
	echo "ClamAV-RELOAD-Test" >reload-testfile
	run_clamdscan reload-testfile
	grep "ClamAV-RELOAD-TestFile" clamdscan.log >/dev/null 2>/dev/null;
	if test $? -eq 0; then
		# it is not supposed to detect until we actually put the
		# signature there and reload!
		error "RELOAD test failed!"
		cat clamdscan.log
		die 10
	fi
	echo "ClamAV-RELOAD-TestFile:0:0:436c616d41562d52454c4f41442d54657374" >test-db/new.ndb
	$TOP/clamdscan/clamdscan --reload --config-file=test-clamd.conf
	if test $? -ne 0; then
		error "clamdscan says reload failed!"
		die 11
	fi
	run_clamdscan reload-testfile
	grep "ClamAV-RELOAD-TestFile" clamdscan.log >/dev/null 2>/dev/null;
	failed=0
	if test $? -ne 0; then
		error "RELOAD test failed! (after reload)"
		cat clamdscan.log
		failed=1
	fi
	grep "ClamAV-RELOAD-TestFile" clamdscan-multiscan.log >/dev/null 2>/dev/null;
	if test $? -ne 0; then
		error "RELOAD test failed! (after reload, multiscan)"
		cat clamdscan-multiscan.log
		failed=1
	fi
	if test "$failed" = "1"; then
		echo "RELOAD tests failed!"
		die 12
	fi
	rm -f reload-testfile
}

run_clamdscan_fdpass() {
	rm -f clamdscan.log
	$TOP/clamdscan/clamdscan --quiet --fdpass --config-file=test-clamd.conf - <$1 --log=clamdscan.log
	if test $? = 2; then
		error "Failed to run clamdscan (fdpass)!"
		cat clamdscan.log
		die 14
	fi
}

# We run multiple clamd tests in parallel, each in its own directory
prepare_clamd()
{
	cd clamdtest$1 
	# Set up test DBdir
	rm -rf test-db
	mkdir -p test-db
	cat <<EOF >test-db/test.hdb
aa15bcf478d165efd2065190eb473bcb:544:ClamAV-Test-File
EOF
	cp $abs_srcdir/input/daily.ftm test-db/
	cp $abs_srcdir/input/daily.pdb test-db/
	$AWK "{ sub(/X/,\"$1\"); sub(/CWD/,\"`pwd`\"); print }" $abs_srcdir/test-clamd.conf >test-clamd.conf
}

rm -rf clamdtest$CLAMD_TEST_UNIQ1 clamdtest$CLAMD_TEST_UNIQ2
mkdir clamdtest$CLAMD_TEST_UNIQ1 clamdtest$CLAMD_TEST_UNIQ2 || 
	{ echo "Unable to create temporary directories!"; exit 1; }

# Prepare configuration for clamd #1 and #2
(prepare_clamd $CLAMD_TEST_UNIQ1)
(prepare_clamd $CLAMD_TEST_UNIQ2)
# Add clamd #2 specific configuration
echo "VirusEvent $abs_srcdir/virusaction-test.sh `pwd`/clamdtest$CLAMD_TEST_UNIQ2 \"Virus found: %v\"" >>clamdtest$CLAMD_TEST_UNIQ2/test-clamd.conf
echo "HeuristicScanPrecedence yes" >>clamdtest$CLAMD_TEST_UNIQ2/test-clamd.conf
grep -v LogFile clamdtest$CLAMD_TEST_UNIQ2/test-clamd.conf >tmp__
mv tmp__ clamdtest$CLAMD_TEST_UNIQ2/test-clamd.conf

# Start clamd #1 tests
(cd clamdtest$CLAMD_TEST_UNIQ1 
start_clamd test-clamd.conf

# Test that all testfiles are detected
FILES=$TOP/test/clam*
run_clamdscan $FILES
NFILES=`ls -1 $FILES | wc -l`
NINFECTED=`grep "Infected files" clamdscan.log | cut -f2 -d:|sed -e 's/ //g'`
NINFECTED_MULTI=`grep "Infected files" clamdscan-multiscan.log | cut -f2 -d:|sed -e 's/ //g'`
NINFECTED_FDPASS=`grep "Infected files" clamdscan-fdpass.log | cut -f2 -d:|sed -e 's/ //g'`
NINFECTED_MULTI_FDPASS=`grep "Infected files" clamdscan-multiscan-fdpass.log | cut -f2 -d:|sed -e 's/ //g'`
NINFECTED_STREAM=`grep "Infected files" clamdscan-stream.log | cut -f2 -d:|sed -e 's/ //g'`
NINFECTED_MULTI_STREAM=`grep "Infected files" clamdscan-multiscan-stream.log | cut -f2 -d:|sed -e 's/ //g'`
if test "$NFILES" -ne "0$NINFECTED"; then
	grep OK clamdscan.log
	scan_failed clamdscan.log "clamd did not detect all testfiles correctly!"
fi
if test "$NFILES" -ne "0$NINFECTED_MULTI"; then
	grep OK clamdscan-multiscan.log
	scan_failed clamdscan-multiscan.log "clamd did not detect all testfiles correctly in multiscan mode!"
fi
if test "$NFILES" -ne "0$NINFECTED_FDPASS"; then
	grep OK clamdscan-fdpass.log
	scan_failed clamdscan-multiscan.log "clamd did not detect all testfiles correctly in fdpass mode!"
fi
if test "$NFILES" -ne "0$NINFECTED_MULTI_FDPASS"; then
	grep OK clamdscan-multiscan-fdpass.log
	scan_failed clamdscan-multiscan.log "clamd did not detect all testfiles correctly in fdpass+multiscan mode!"
fi

$TOP/unit_tests/check_clamd
ecode=$?
if test $ecode -ne 77 && test $ecode -ne 0; then
    error "Failed clamd protocol test!"
    die 1
fi
# Test HeuristicScanPrecedence off feature
run_clamdscan ../clam-phish-exe
grep "ClamAV-Test-File" clamdscan.log >/dev/null 2>/dev/null;
if test $? -ne 0; then
	error "HeuristicScanPrecedence off test failed!"
	cat clamdscan.log
	die 4
fi
die 0
)&
pid1=$!

# Start clamd #2 tests
(cd clamdtest$CLAMD_TEST_UNIQ2
start_clamd test-clamd.conf

# Test VirusEvent feature
run_clamdscan_fileonly $TOP/test/clam.exe
grep "Virus found: ClamAV-Test-File.UNOFFICIAL" test-clamd.log >/dev/null 2>/dev/null; 
if test $? -ne 0; then
	error "Virusaction test failed!" 
	cat test-clamd.log
	die 2
fi

# Test HeuristicScanPrecedence feature
run_clamdscan ../clam-phish-exe
grep "Phishing.Heuristics.Email.SpoofedDomain" clamdscan.log >/dev/null 2>/dev/null;
if test $? -ne 0; then
	error "HeuristicScanPrecedence on test failed!"
	cat clamdscan.log
	die 3
fi

if grep "^#define HAVE_FD_PASSING 1" $TOP/clamav-config.h >/dev/null; then
	run_clamdscan_fdpass $TOP/test/clam.exe
	grep "ClamAV-Test-File" clamdscan.log >/dev/null 2>/dev/null;
	if test $? -ne 0; then
		error "FDpassing test failed!"
		cat clamdscan.log;
		die 4
	fi
else
	echo "*** No file descriptor passing support, skipping test"
fi

# Test RELOAD command
run_reload_test

die 0
)&

pid2=$!

wait $pid1
exitcode1=$?
wait $pid2
exitcode2=$?
rm -rf clamdtest$CLAMD_TEST_UNIQ1 clamdtest$CLAMD_TEST_UNIQ2 test-db accdenied
if (test $exitcode1 -ne 0 && test $exitcode1 -ne 127) || (test $exitcode2 -ne 0	&& test $exitcode2 -ne 127); then
	exit 1
fi
exit 0
