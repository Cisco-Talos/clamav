#!/bin/sh

# Solaris's /bin/sh is not a POSIX shell, and
# it quits when cd fails, even if it is followed by a ||
# So enable -e only on POSIX shells
(cd /nonexistentdir 2>/dev/null || true) && set -e

WRAPPER=${WRAPPER-}
TOP=`pwd`/..
CLAMSCAN=$TOP/clamscan/clamscan
CLAMD=$TOP/clamd/clamd
CHECK_CLAMD=$TOP/unit_tests/check_clamd
CLAMDSCAN=$TOP/clamdscan/clamdscan
TESTFILES=$TOP/test/clam*
NFILES=`ls -1 $TESTFILES | wc -l`

killclamd() {
    test -f clamd-test.pid &&
    pid=`cat clamd-test.pid 2>/dev/null` &&
    test -n "$pid" &&
    kill -0 $pid 2>/dev/null &&
    kill $pid 2>/dev/null &&
    kill -0 $pid 2>/dev/null &&
    sleep 1 &&
    kill -0 $pid 2>/dev/null &&
    sleep 9 &&
    kill -0 $pid 2>/dev/null &&
    echo "Killing stuck clamd!" &&
    kill -KILL $pid && exit 109 || true
}

error()
{
	echo >&2
	echo "***" >&2
	echo "*** $1" >&2
	echo "***" >&2
}

die()
{
	error "$1"
	test -f valgrind.log && cat valgrind.log || true
	killclamd
	exit 42
}

# Setup test directory to avoid temporary and output file clashes
test_start() {
    ulimit -t 120; ulimit -d 512000;
    ulimit -v 512000 || true;
    (cd test-$1 2>/dev/null && killclamd || true)
    rm -rf test-$1
    mkdir test-$1
    cd test-$1
    mkdir test-db
    cat <<EOF >test-db/test.hdb
aa15bcf478d165efd2065190eb473bcb:544:ClamAV-Test-File
EOF
    cat <<EOF >test-clamd.conf
LogFile `pwd`/clamd-test.log
LogFileMaxSize 0
LogTime yes
Debug yes
LogClean yes
LogVerbose yes
PidFile `pwd`/clamd-test.pid
DatabaseDirectory `pwd`/test-db
LocalSocket clamd-test.socket
TCPAddr 127.0.0.1
# using different port here to avoid conflicts with system clamd daemon
TCPSocket 331$1
ExitOnOOM yes
DetectPUA yes
ScanPDF yes
CommandReadTimeout 1
MaxQueue 800
MaxConnectionQueueLength 1024
EOF
}

# arg1: expected exitcode
test_run() {
   expected=$1
   shift
   set +e
   $TOP/libtool --mode=execute $WRAPPER $*
   val=$?
   if test $val -ne $expected; then
       error "Failed to run $*, expected $expected exitcode, but was $val" >&2;
       return 0;
   fi
   set -e
   return 1;
}

# Run a test and return its exitcode
test_run_check() {
    set +e
    $TOP/libtool --mode=execute $WRAPPER $*
    val=$?
    set -e
    return $?;
}

# test successfully finished, remove test dir
test_end() {
    killclamd
    cd ..
    rm -rf test-$1
}

scan_failed() {
    if test "X$unrar_disabled" = "X1" && test `grep -v '\.rar' $1 | grep OK | wc -l` -eq 0
    then
	error "UNRAR is disabled, won't be able to detect unrar files!"
    else
	cat $1
    	die "$2";
    fi
}

# ----------- valgrind wrapper 
init_valgrind() {
    test "x$VG" = "x1" || { echo "*** valgrind tests skipped by default, use 'make check VG=1' to activate"; exit 77; }
    VALGRIND=`which ${VALGRIND-valgrind}` || true
    VALGRIND_COMMON_FLAGS="-v --trace-children=yes --suppressions=$abs_srcdir/valgrind.supp --log-file=valgrind.log --error-exitcode=123 $GENSUPP"
    VALGRIND_FLAGS="$VALGRIND_COMMON_FLAGS --track-fds=yes --leak-check=full"
    VALGRIND_FLAGS_RACE="$VALGRIND_COMMON_FLAGS --tool=helgrind"
    export VALGRIND VALGRIND_COMMON_FLAGS VALGRIND_FLAGS VALGRIND_FLAGS_RACE
    test -n "$VALGRIND" || { echo "*** valgrind not found, skipping test"; exit 77; }
    test -x "$VALGRIND" || { echo "*** valgrind not executable, skipping test"; exit 77; }
}

init_helgrind() {
    init_valgrind
}

end_valgrind() {
    NRUNS=`grep -a "ERROR SUMMARY" valgrind.log | wc -l`
    if test $NRUNS -ne `grep -a "ERROR SUMMARY: 0 errors" valgrind.log | wc -l` || 
	test `grep -a "FATAL:" valgrind.log|wc -l` -ne 0; then
	cat valgrind.log
	die "Valgrind tests failed"
    fi
}

# ----------- clamscan tests --------------------------------------------------------
test_clamscan() {
    test_start $1
    if test_run 1 $CLAMSCAN --debug --quiet -dtest-db/test.hdb $TESTFILES --log=clamscan.log; then
	scan_failed clamscan.log "clamscan didn't detect all testfiles correctly"
    fi
    NINFECTED=`grep "Infected files" clamscan.log | cut -f2 -d: | sed -e 's/ //g'`
    if test "$NFILES" -ne "0$NINFECTED"; then
	scan_failed clamscan.log "clamscan didn't detect all testfiles correctly"
    fi

    cat <<EOF >test-db/test.pdb
H:example.com
EOF
    if test_run 0 $CLAMSCAN --quiet -dtest-db $abs_srcdir/input/phish-test-* --log=clamscan2.log; then
	cat clamscan2.log;
	die "Failed to run clamscan (phish-test)";
    fi

    if test_run 1 $CLAMSCAN --quiet --phishing-ssl --phishing-cloak -dtest-db $abs_srcdir/input/phish-test-* --log=clamscan3.log; then
	cat clamscan3.log;
	die "Failed to run clamscan (phish-test2)";
    fi

    grep "phish-test-ssl: Heuristics.Phishing.Email.SSL-Spoof FOUND" clamscan3.log >/dev/null || die "phish-test1 failed";
    grep "phish-test-cloak: Heuristics.Phishing.Email.Cloaked.Null FOUND" clamscan3.log >/dev/null || die "phish-test2 failed";
    test_end $1
}

# ----------- clamd tests --------------------------------------------------------
start_clamd()
{
    cp $abs_srcdir/input/daily.pdb test-db/daily.pdb
    if test_run 0 $CLAMD -c test-clamd.conf --help >clamd-test.log; then
	die "Failed to run clamd --help";
    fi
    grep "Clam AntiVirus Daemon" clamd-test.log >/dev/null || die "Wrong --help reply from clamd!";
    if test_run 0 $CLAMD -c test-clamd.conf >clamd-test.log 2>&1; then
	cat clamd-test.log
	die "Failed to run clamd";
    fi
}

run_clamdscan_fileonly() {
    rm -f clamdscan.log clamdscan-multiscan.log
    $CLAMDSCAN --version --config-file=test-clamd.conf | grep "^ClamAV" >/dev/null || die "clamdscan can't get version of clamd!";
    set +e
    $CLAMDSCAN --quiet --config-file=test-clamd.conf $* --log=clamdscan.log
    if test $? = 2; then
	die "Failed to run clamdscan!"
    fi
    $CLAMDSCAN --quiet --config-file=test-clamd.conf $* -m --log=clamdscan-multiscan.log
    if test $? = 2; then
	die "Failed to run clamdscan (multiscan)!"
    fi
    set -e
}

run_clamdscan() {
    run_clamdscan_fileonly $*
    rm -f clamdscan-fdpass.log clamdscan-multiscan-fdpass.log clamdscan-stream.log clamdscan-multiscan-stream.log
    set +e
    $CLAMDSCAN --quiet --config-file=test-clamd.conf $* --fdpass --log=clamdscan-fdpass.log
    if test $? = 2; then 
	die "Failed to run clamdscan (fdpass)!"
    fi
    $CLAMDSCAN --quiet --config-file=test-clamd.conf $* -m --fdpass --log=clamdscan-multiscan-fdpass.log
    if test $? = 2; then 
        die "Failed to run clamdscan (fdpass + multiscan)!"
    fi
    $CLAMDSCAN --quiet --config-file=test-clamd.conf $* --stream --log=clamdscan-stream.log
    if test $? = 2; then 
    	die "Failed to run clamdscan (instream)!"
    fi
    $CLAMDSCAN --quiet --config-file=test-clamd.conf $* -m --stream --log=clamdscan-multiscan-stream.log
    if test $? = 2; then 
	die "Failed to run clamdscan (instream + multiscan)!"
    fi
    set -e
}

run_reload_test()
{
	echo "ClamAV-RELOAD-Test" >reload-testfile
	run_clamdscan reload-testfile
	# it is not supposed to detect until we actually put the
	# signature there and reload!
	grep "ClamAV-RELOAD-TestFile" clamdscan.log >/dev/null 2>/dev/null && die "RELOAD test(1) failed!"
	echo "ClamAV-RELOAD-TestFile:0:0:436c616d41562d52454c4f41442d54657374" >test-db/new.ndb
	$CLAMDSCAN --reload --config-file=test-clamd.conf || die "clamdscan says reload failed!"
	run_clamdscan reload-testfile
	failed=0
	grep "ClamAV-RELOAD-TestFile" clamdscan.log >/dev/null 2>/dev/null || die "RELOAD test failed! (after reload)"
	grep "ClamAV-RELOAD-TestFile" clamdscan-multiscan.log >/dev/null 2>/dev/null || die "RELOAD test failed! (after reload, multiscan)"
}

run_clamdscan_fdpass() {
    set +e
    $CLAMDSCAN --quiet --fdpass --config-file=test-clamd.conf - <$1 --log=clamdscan.log
    if test $? = 2; then
    	die "Failed to run clamdscan (fdpass)!"
    fi
    set -e
}

test_clamd1() {
    test_start $1
    start_clamd
    # Test that all testfiles are detected
    run_clamdscan $TESTFILES
    NINFECTED=`grep "Infected files" clamdscan.log | cut -f2 -d:|sed -e 's/ //g'`
    NINFECTED_MULTI=`grep "Infected files" clamdscan-multiscan.log | cut -f2 -d:|sed -e 's/ //g'`
    NINFECTED_FDPASS=`grep "Infected files" clamdscan-fdpass.log | cut -f2 -d:|sed -e 's/ //g'`
    NINFECTED_MULTI_FDPASS=`grep "Infected files" clamdscan-multiscan-fdpass.log | cut -f2 -d:|sed -e 's/ //g'`
    NINFECTED_STREAM=`grep "Infected files" clamdscan-stream.log | cut -f2 -d:|sed -e 's/ //g'`
    NINFECTED_MULTI_STREAM=`grep "Infected files" clamdscan-multiscan-stream.log | cut -f2 -d:|sed -e 's/ //g'`
    if test "$NFILES" -ne "0$NINFECTED"; then
	scan_failed clamdscan.log "clamd did not detect all testfiles correctly!"
    fi
    if test "$NFILES" -ne "0$NINFECTED_MULTI"; then
	scan_failed clamdscan-multiscan.log "clamd did not detect all testfiles correctly in multiscan mode!"
    fi
    if test "$NFILES" -ne "0$NINFECTED_FDPASS"; then
	scan_failed clamdscan-fdpass.log "clamd did not detect all testfiles correctly in fdpass mode!"
    fi
    if test "$NFILES" -ne "0$NINFECTED_MULTI_FDPASS"; then
	scan_failed clamdscan-multiscan-fdpass.log "clamd did not detect all testfiles correctly in fdpass+multiscan mode!"
    fi
    if test "$NFILES" -ne "0$NINFECTED_STREAM"; then
	scan_failed clamdscan-stream.log "clamd did not detect all testfiles correctly in stream mode!"
    fi
    if test "$NFILES" -ne "0$NINFECTED_MULTI_STREAM"; then
	scan_failed clamdscan-multiscan-stream.log "clamd did not detect all testfiles correctly in multiscan+stream mode!"
    fi
    # Test HeuristicScanPrecedence off feature
    run_clamdscan ../clam-phish-exe
    grep "ClamAV-Test-File" clamdscan.log >/dev/null 2>/dev/null;
    if test $? -ne 0; then
	cat clamdscan.log
	die "HeuristicScanPrecedence off test failed!"
    fi
    test_end $1
}

test_clamd2() {
    test_start $1
    start_clamd
    # Run clamd test suite
    test_run_check $CHECK_CLAMD
    val=$?

    # Test RELOAD command
    run_reload_test

    test_end $1
    exit $?
}

test_clamd3() {
    test_start $1
    echo "VirusEvent $abs_srcdir/virusaction-test.sh `pwd` \"Virus found: %v\"" >>test-clamd.conf
    echo "HeuristicScanPrecedence yes" >>test-clamd.conf
    start_clamd
    # Test HeuristicScanPrecedence feature
    run_clamdscan ../clam-phish-exe
    grep "Heuristics.Phishing.Email.SpoofedDomain" clamdscan.log >/dev/null 2>/dev/null ||
        { cat clamdscan.log; die "HeuristicScanPrecedence on test failed!"; }

    if grep "^#define HAVE_FD_PASSING 1" $TOP/clamav-config.h >/dev/null; then
	run_clamdscan_fdpass $TOP/test/clam.exe
	grep "ClamAV-Test-File" clamdscan.log >/dev/null 2>/dev/null ||
	{ cat clamdscan.log; die "FDpassing test failed!";}
    else
	echo "*** No file descriptor passing support, skipping test"
    fi

    rm test-clamd.log
    # Test VirusEvent feature
    run_clamdscan_fileonly $TOP/test/clam.exe
    test -f test-clamd.log || sleep 1
    grep "Virus found: ClamAV-Test-File.UNOFFICIAL" test-clamd.log >/dev/null 2>/dev/null ||
	{ cat test-clamd.log || true; die "Virusaction test failed"; }

    test_end $1
}
