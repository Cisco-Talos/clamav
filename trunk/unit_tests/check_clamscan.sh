#!/bin/sh 
CLAMSCAN_WRAPPER=${CLAMSCAN_WRAPPER-}
die() {
	rm -rf test-db
	exit $1;
}

scan_failed() {
	if test "X$unrar_disabled" = "X1" && test `grep -v '\.rar' $1 | grep OK | wc -l` -eq 0
	then
		echo "***" >&2;
		echo "*** UNRAR is disabled, won't be able to detect unrar files!" >&2;
		echo "***" >&2;
	else
		echo "clamscan did not detect all testfiles correctly!" >&2;
		die 2;
	fi
}

mkdir test-db
cat <<EOF >test-db/test.hdb
aa15bcf478d165efd2065190eb473bcb:544:ClamAV-Test-File
EOF
rm -f clamscan.log
../libtool --mode=execute $CLAMSCAN_WRAPPER ../clamscan/clamscan --quiet -dtest-db/test.hdb ../test/clam* --log=clamscan.log
if test $? != 1; then
	echo "Error running clamscan: $?" >&2;
	grep OK clamscan.log >&2;
	die 1;
fi
NFILES=`ls -1 ../test/clam* | wc -l`
NINFECTED=`grep "Infected files" clamscan.log | cut -f2 -d: |sed -e 's/ //g'`
if test "$NFILES" -ne "0$NINFECTED"; then
	grep OK clamscan.log >&2;
	scan_failed clamscan.log
fi

cat <<EOF >test-db/test.pdb
H:example.com
EOF
rm -f clamscan2.log
../clamscan/clamscan  -dtest-db $abs_srcdir/input/phish-test-* --log=clamscan2.log --quiet
val=$?
if test $val != 0; then
	if test $val = 1; then
		echo "clamscan detected a file it shouldn't" >&2
		grep FOUND clamscan2.log
		die 3;
	fi
	echo "Error running clamscan: $val" >&2;
	die 3;
fi

rm -f clamscan2.log
../clamscan/clamscan --phishing-ssl --phishing-cloak -dtest-db $abs_srcdir/input/phish-test-* --log=clamscan2.log --quiet
val=$?
if test $val != 1; then
	echo "Error running clamscan: $val" >&2;
	die 3;
fi
grep "phish-test-ssl: Phishing.Heuristics.Email.SSL-Spoof FOUND" clamscan2.log >/dev/null && grep "phish-test-cloak: Phishing.Heuristics.Email.Cloaked.Null FOUND" clamscan2.log >/dev/null
if test $? -ne 0; then
	echo "Error on ssl/cloak phishing test" >&2;
	die 4;
fi
die 0;
