#!/bin/sh
mkdir test-db
cat <<EOF >test-db/test.hdb
aa15bcf478d165efd2065190eb473bcb:544:ClamAV-Test-File
EOF
rm clamscan.log
../clamscan/clamscan --quiet -dtest-db/test.hdb ../test/clam* --log=clamscan.log
if test $? != 1; then
	echo "Error running clamscan: $?" >&2;
	grep OK clamscan.log >&2;
	exit 1;
fi
NFILES=`ls -1 ../test/clam* | wc -l`
NINFECTED=`grep "Infected files" clamscan.log | cut -f2 -d:`
if test "$NFILES" -ne "$NINFECTED"; then
	echo "clamscan did not detect all testfiles correctly!" >&2;
	grep OK clamscan.log >&2;
	exit 2;
fi
exit 0;
