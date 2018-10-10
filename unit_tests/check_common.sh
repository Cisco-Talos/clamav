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
#CHECK_FPU_ENDIAN=$TOP/unit_tests/.libs/lt-check_fpu_endian
CHECK_FPU_ENDIAN=$TOP/unit_tests/check_fpu_endian

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
    ulimit -t 120 || true; ulimit -d 1024000 || true;
    ulimit -v 1024000 || true;
    (cd test-$1 2>/dev/null && killclamd || true)
    rm -rf test-$1
    mkdir test-$1
    cd test-$1
    mkdir test-db
    cat <<EOF >test-db/test.hdb
aa15bcf478d165efd2065190eb473bcb:544:ClamAV-Test-File
EOF
    port=331$1
    tries=0
    while nc -z localhost $port 2>/dev/null
	do rand=` ( echo $$ ; time ps 2>&1 ; date ) | cksum | cut -f1 -d" " `
	port=1`expr 100 + \( $rand % 899 \)`$1
	[ $tries -gt 100 ] && echo Giving up, too many ports open && exit 1
	tries=`expr $tries + 1`
    done
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
TCPSocket $port
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
    test -f test-$1/valgrind.log && mv -f test-$1/valgrind.log valgrind$1.log
    rm -rf test-$1
}

scan_failed() {
    cat $1
    die "$2";
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
    VLOG=valgrind$1.log
    NRUNS=`grep -a "ERROR SUMMARY" $VLOG | wc -l`
    if test $NRUNS -ne `grep -a "ERROR SUMMARY: 0 errors" $VLOG | wc -l` || 
	test `grep -a "FATAL:" $VLOG|wc -l` -ne 0; then
	cat $VLOG
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

    if test_run 1 $CLAMSCAN --quiet --alert-phishing-ssl --alert-phishing-cloak -dtest-db $abs_srcdir/input/phish-test-* --log=clamscan3.log; then
	cat clamscan3.log;
	die "Failed to run clamscan (phish-test2)";
    fi

    grep "phish-test-ssl: Heuristics.Phishing.Email.SSL-Spoof FOUND" clamscan3.log >/dev/null || die "phish-test1 failed";
    grep "phish-test-cloak: Heuristics.Phishing.Email.Cloaked.Null FOUND" clamscan3.log >/dev/null || die "phish-test2 failed";

    cat <<EOF >test-db/test.ign2
ClamAV-Test-File
EOF
    cat <<EOF >test-db/test.idb
EA0X-32x32x8:ea0x-grp1:ea0x-grp2:2046f030a42a07153f4120a0031600007000005e1617ef0000d21100cb090674150f880313970b0e7716116d01136216022500002f0a173700081a004a0e
IScab-16x16x8:iscab-grp1:iscab-grp2:107b3000168306015c20a0105b07060be0a0b11c050bea0706cb0a0bbb060b6f00017c06018301068109086b03046705081b000a270a002a000039002b17
EOF
    cat <<EOF >test-db/test.ldb
ClamAV-Test-Icon-EA0X;Engine:52-1000,Target:1,IconGroup1:ea0x-grp1,IconGroup2:*;(0);0:4d5a
ClamAV-Test-Icon-IScab;Engine:52-1000,Target:1,IconGroup2:iscab-grp2;(0);0:4d5a
EOF
    if test_run 1 $CLAMSCAN --quiet -dtest-db $TESTFILES --log=clamscan4.log; then
	scan_failed clamscan4.log "clamscan didn't detect icons correctly"
    fi
    NINFECTED=`grep "Infected files" clamscan4.log | cut -f2 -d: | sed -e 's/ //g'`
    grep "clam.ea05.exe: ClamAV-Test-Icon-EA0X.UNOFFICIAL FOUND" clamscan4.log || die "icon-test1 failed"

    test_run_check $CHECK_FPU_ENDIAN
    if test $? -eq 3; then
        NEXPECT=3
    else
        grep "clam.ea06.exe: ClamAV-Test-Icon-EA0X.UNOFFICIAL FOUND" clamscan4.log || die "icon-test2 failed"
        NEXPECT=4
    fi
    grep "clam_IScab_ext.exe: ClamAV-Test-Icon-IScab.UNOFFICIAL FOUND" clamscan4.log || die "icon-test3 failed"
    grep "clam_IScab_int.exe: ClamAV-Test-Icon-IScab.UNOFFICIAL FOUND" clamscan4.log || die "icon-test4 failed"
    if test "x$NINFECTED" != "x$NEXPECT"; then
	scan_failed clamscan4.log "clamscan has detected spurious icons or whitelisting was not applied properly"
    fi

cat <<EOF >test-db/test.ldb
Clam-VI-Test:Target;Engine:52-255,Target:1;(0&1);VI:43006f006d00700061006e0079004e0061006d0065000000000063006f006d00700061006e007900;VI:500072006f0064007500630074004e0061006d0065000000000063006c0061006d00
EOF
    if test_run 1 $CLAMSCAN --quiet -dtest-db/test.ldb $TESTFILES --log=clamscan5.log; then
	scan_failed clamscan5.log "clamscan didn't detect VI correctly"
    fi
    grep "clam_ISmsi_ext.exe: Clam-VI-Test:Target.UNOFFICIAL FOUND" clamscan5.log || die "VI-test1 failed"
    grep "clam_ISmsi_int.exe: Clam-VI-Test:Target.UNOFFICIAL FOUND" clamscan5.log || die "VI-test2 failed"
    NINFECTED=`grep "Infected files" clamscan5.log | cut -f2 -d: | sed -e 's/ //g'`
    if test "x$NINFECTED" != x2; then
	scan_failed clamscan4.log "clamscan has detected spurious VI's"
    fi

cat <<EOF >test-db/test.yara
rule yara_at_offset {strings: \$tar_magic = { 75 73 74 61 72 } condition: \$tar_magic at 257}
EOF
    if test_run 1 $CLAMSCAN --quiet -dtest-db/test.yara $TESTFILES --log=clamscan6.log; then
	scan_failed clamscan6.log "clamscan YARA at-offset test failed"
    fi
    grep "clam.tar.gz: YARA.yara_at_offset.UNOFFICIAL FOUND" clamscan6.log || die "YARA at-offset test1 failed"
    grep "clam_cache_emax.tgz: YARA.yara_at_offset.UNOFFICIAL FOUND" clamscan6.log || die "YARA at-offset test2 failed"
    NINFECTED=`grep "Infected files" clamscan6.log | cut -f2 -d: | sed -e 's/ //g'`
    if test "x$NINFECTED" != x2; then
	scan_failed clamscan7.log "clamscan: unexpected YARA offset match."
    fi

cat <<EOF >test-db/test.yara
rule yara_in_range {strings: \$tar_magic = { 75 73 74 61 72 } condition: \$tar_magic in (200..300)}
EOF
    if test_run 1 $CLAMSCAN --quiet -dtest-db/test.yara $TESTFILES --log=clamscan7.log; then
	scan_failed clamscan7.log "clamscan YARA in-range test failed"
    fi
    grep "clam.tar.gz: YARA.yara_in_range.UNOFFICIAL FOUND" clamscan7.log || die "YARA in-range test1 failed"
    grep "clam_cache_emax.tgz: YARA.yara_in_range.UNOFFICIAL FOUND" clamscan7.log || die "YARA in-range test2 failed"
    NINFECTED=`grep "Infected files" clamscan7.log | cut -f2 -d: | sed -e 's/ //g'`
    if test "x$NINFECTED" != x2; then
	scan_failed clamscan7.log "clamscan: unexpected YARA range match."
    fi

    test_end $1
}

# ----------- clamd tests --------------------------------------------------------
start_clamd()
{
    cp $abs_srcdir/input/daily.pdb test-db/daily.pdb
    if test_run 0 $CLAMD -c test-clamd.conf --help >clamd-test.log; then
	die "Failed to run clamd --help";
    fi
    grep "Clam AntiVirus: Daemon" clamd-test.log >/dev/null || die "Wrong --help reply from clamd!";
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
