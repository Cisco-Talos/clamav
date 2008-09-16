#!/bin/sh 
CLAMD_WRAPPER=${CLAMD_WRAPPER-}
killclamd() {
	test -f /tmp/clamd-test.pid || return
	pid=`cat /tmp/clamd-test.pid 2>/dev/null`
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
		pippo=$((pippo+1))
		if test $pippo -gt 9; then
			kill -KILL $pid
		fi
	done
	rm -f /tmp/clamd-test.pid
}

die() {
	killclamd
	rm -rf test-db test-clamd1.conf test-clamd2.conf test-clamd.log	clamd-test.socket reload-testfile
	exit $1
}

error()
{
	echo >&2
	echo "***" >&2
	echo "*** $1" >&2
	echo "***" >&2
}

start_clamd()
{
	rm -f /tmp/clamd-test.log
	../libtool --mode=execute $CLAMD_WRAPPER ../clamd/clamd -c $1 || 
		{ error "Failed to start clamd!"; die 1;}
}

run_clamdscan() {
	conf_file=$1
	shift
	rm -f clamdscan.log clamdscan-multiscan.log
	../clamdscan/clamdscan --version --config-file $conf_file 2>&1|grep "^ClamAV" >/dev/null || 
		{ error "clamdscan can't get version of clamd!"; die 2;}
	../clamdscan/clamdscan --quiet --config-file $conf_file $* --log=clamdscan.log
	if test $? = 2; then 
		error "Failed to run clamdscan!"
		cat clamdscan.log
		die 3;	
	fi
	../clamdscan/clamdscan --quiet --config-file $conf_file $* -m --log=clamdscan-multiscan.log
	if test $? = 2; then 
		error "Failed to run clamdscan (multiscan)!"
		die 3;	
	fi
}

run_reload_test()
{
	# TODO consider using clamdscan when it'll have a reload feature
	if test ! -x /bin/nc; then
		echo "*** Netcat (nc) is not installed, skipping reload test"
		return
	fi
	rm -f reload-testfile
	echo "ClamAV-RELOAD-Test" >reload-testfile
	run_clamdscan test-clamd1.conf reload-testfile
	grep "ClamAV-RELOAD-TestFile" clamdscan.log >/dev/null 2>/dev/null;
	if test $? -eq 0; then
		# it is not supposed to detect until we actually put the
		# signature there and reload!
		error "RELOAD test failed!"
		cat clamdscan.log
		die 7;
	fi
	echo "ClamAV-RELOAD-TestFile:0:0:436c616d41562d52454c4f41442d54657374" >test-db/new.ndb
	echo RELOAD | nc -q 0 -n 127.0.0.1 3311
	run_clamdscan test-clamd1.conf reload-testfile
	grep "ClamAV-RELOAD-TestFile" clamdscan.log >/dev/null 2>/dev/null;
	if test $? -ne 0; then
		error "RELOAD test failed! (after reload)"
		cat clamdscan.log
		die 8;
	fi
	grep "ClamAV-RELOAD-TestFile" clamdscan-multiscan.log >/dev/null 2>/dev/null;
	if test $? -ne 0; then
		error "RELOAD test failed! (after reload, multiscan)"
		die 9;
	fi
	rm -f reload-testfile
}

run_clamdscan_fdpass() {
	conf_file=$1
	shift
	rm -f clamdscan.log
	../clamdscan/clamdscan --quiet --fdpass --config-file $conf_file - <$1 --log=clamdscan.log
	if test $? = 2; then
		error "Failed to run clamdscan!"
		die 9;
	fi
}

# Set up test DBdir
rm -rf test-db
mkdir -p test-db
cat <<EOF >test-db/test.hdb
aa15bcf478d165efd2065190eb473bcb:544:ClamAV-Test-File
EOF
cp $srcdir/input/daily.ftm test-db/
cp $srcdir/input/daily.pdb test-db/

# Prepare for clamd #1
cat <$srcdir/test-clamd.conf >test-clamd1.conf
#  Use absolute path to dbdir, so that RELOAD works
echo "DatabaseDirectory `pwd`/test-db" >>test-clamd1.conf

# Start clamd #1
start_clamd test-clamd1.conf

# Test that all testfiles are detected
FILES=../test/clam*
run_clamdscan test-clamd1.conf $FILES
NFILES=`ls -1 $FILES | wc -l`
NINFECTED=`grep "Infected files" clamdscan.log | cut -f2 -d:|sed -e 's/ //g'`
NINFECTED_MULTI=`grep "Infected files" clamdscan-multiscan.log | cut -f2 -d:|sed -e 's/ //g'`
if test "$NFILES" -ne "0$NINFECTED"; then
	error "clamd did not detect all testfiles correctly!"
	grep OK clamdscan.log
	die 4;
fi
if test "$NFILES" -ne "0$NINFECTED_MULTI"; then
	error "clamd did not detect all testfiles correctly in multiscan mode!"
	grep OK clamdscan-multiscan.log
	die 5;
fi

# Test HeuristicScanPrecedence off feature
run_clamdscan test-clamd1.conf clam-phish-exe
grep "ClamAV-Test-File" clamdscan.log >/dev/null 2>/dev/null;
if test $? -ne 0; then
	error "HeuristicScanPrecedence off test failed!"
	cat clamdscan.log
	die 6;
fi

# Test RELOAD command
run_reload_test
killclamd 

# Prepare configuration for clamd #2
cat <test-clamd1.conf >test-clamd2.conf
echo "VirusEvent `pwd`/$srcdir/virusaction-test.sh `pwd` \"Virus found: %v\"" >>test-clamd2.conf
echo "HeuristicScanPrecedence yes" >>test-clamd2.conf

# Start clamd #2
start_clamd test-clamd2.conf

# Test VirusEvent feature
run_clamdscan test-clamd2.conf ../test/clam.exe
grep "Virus found: ClamAV-Test-File.UNOFFICIAL" test-clamd.log >/dev/null 2>/dev/null; 
if test $? -ne 0; then
	error "Virusaction test failed!" 
	cat test-clamd.log
	die 10;
fi

# Test HeuristicScanPrecedence feature
run_clamdscan test-clamd2.conf clam-phish-exe
grep "Phishing.Heuristics.Email.SpoofedDomain" clamdscan.log >/dev/null 2>/dev/null;
if test $? -ne 0; then
	error "HeuristicScanPrecedence on test failed!"
	cat clamdscan.log
	die 11;
fi

if grep "^#define HAVE_FD_PASSING 1" ../clamav-config.h >/dev/null; then
	run_clamdscan_fdpass test-clamd2.conf ../test/clam.exe
	grep "ClamAV-Test-File" clamdscan.log >/dev/null 2>/dev/null;
	if test $? -ne 0; then
		error "FDpassing test failed!"
		cat clamdscan.log;
		die 12;
	fi
else
	echo "*** No file descriptor passing support, skipping test"
fi
die 0;
