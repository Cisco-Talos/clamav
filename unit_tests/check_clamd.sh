#!/bin/sh
function die() {
	test /tmp/clamd-test.pid && kill `cat /tmp/clamd-test.pid` 
	rm -r test-db
	exit $1
}

mkdir -p test-db
cat <<EOF >test-db/test.hdb
aa15bcf478d165efd2065190eb473bcb:544:ClamAV-Test-File
EOF

FILES=../test/clam*
../clamd/clamd -c $srcdir/test-clamd.conf || { echo "Failed to start clamd!" >&2; die 1;}
rm -f clamdscan.log
../clamdscan/clamdscan --version --config-file $srcdir/test-clamd.conf 2>&1|grep "^ClamAV" >/dev/null || { echo "clamdscan can't get version of clamd!" >&2; die 2;}
../clamdscan/clamdscan --quiet --config-file $srcdir/test-clamd.conf $FILES --log=clamdscan.log
if test $? = 2; then 
	echo "Failed to run clamdscan!" >&2;
	die 3;
fi
NFILES=`ls -1 $FILES | wc -l`
NINFECTED=`grep "Infected files" clamdscan.log | cut -f2 -d:`
if test "$NFILES" -ne "$NINFECTED"; then
	echo "clamd did not detect all testfiles correctly!" >&2;
	grep OK clamdscan.log >&2;
	die 4;
fi
die 0;
