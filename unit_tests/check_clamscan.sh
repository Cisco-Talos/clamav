#!/bin/sh
die() {
	rm -rf test-db
	exit $1;
}
mkdir test-db
cat <<EOF >test-db/test.hdb
aa15bcf478d165efd2065190eb473bcb:544:ClamAV-Test-File
EOF
rm -f clamscan.log
../clamscan/clamscan --quiet -dtest-db/test.hdb ../test/clam* --log=clamscan.log
if test $? != 1; then
	echo "Error running clamscan: $?" >&2;
	grep OK clamscan.log >&2;
	die 1;
fi
NFILES=`ls -1 ../test/clam* | wc -l`
NINFECTED=`grep "Infected files" clamscan.log | cut -f2 -d: |sed -e 's/ //g'`
if test "$NFILES" -ne "0$NINFECTED"; then
	echo "clamscan did not detect all testfiles correctly!" >&2;
	grep OK clamscan.log >&2;
	die 2;
fi
die 0;
