#!/bin/sh
mkdir test-db
cat <<EOF >test-db/test.hdb
aa15bcf478d165efd2065190eb473bcb:544:ClamAV-Test-File
EOF
../clamscan/clamscan --quiet -dtest-db/test.hdb ../test/clam* --log=clamscan.log
if test $? != 1; then
	echo "Error running clamscan: $?" >&2;
	grep OK clamscan.log >&2;
	exit 1;
fi
exit 0;
