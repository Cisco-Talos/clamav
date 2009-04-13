#!/bin/bash
# Split an upstream tarball into +dfsg, and libclamunrar.
if test $# -ne 2; then
    echo -e "Usage: $0 <PATH> <VERSION>\n\t<PATH> - directory that contains clamav-<VERSION>.tar.gz";
    exit 1;
fi

test -d $1 || { echo "Directory $1 doesn't exist"; exit 2; }
TARBALL="$PWD/$1/clamav-$2.tar.gz"
test -f $TARBALL || { echo "Tarball $TARBALL doesn't exist"; exit 3; }

TEMP=`mktemp -d __splitXXXXXX` || { echo "Cannot create temporary directory"; exit 2; }
echo "Temporary directory is $TEMP"
cd $TEMP || exit 3;
echo "Extracting $TARBALL";
tar -xzf $TARBALL || { echo "Failed to extract $TARBALL"; exit 4; }

UNRARPKG=libclamunrar_$2.orig.tar.gz
DFSGPKG=clamav_$2+dfsg.orig.tar.gz
UNRARDIR="libclamunrar-$2"
MAKEFLAGS=-j4

set -e

mv clamav-$2 clamav-$2+dfsg
mkdir $UNRARDIR
UNRARDIR="$PWD/$UNRARDIR"
echo "Preparing dfsg package"
cd clamav-$2+dfsg
cp -R libclamunrar_iface $UNRARDIR
mv libclamunrar $UNRARDIR
cp -R m4/ $UNRARDIR
cp -R config/ $UNRARDIR
cp configure.in $UNRARDIR
cp COPYING{,.unrar,.LGPL} $UNRARDIR
cd ../
tar -czf $DFSGPKG clamav-$2+dfsg/
cd $UNRARDIR
echo "Preparing unrar package"
sed -i '/AC_OUTPUT/,/])/ {
/^AC_OUTPUT/p
s/^libclamav\/Makefile/libclamunrar_iface\/Makefile/p
/^Makefile/p
/^])/p
d
}
/LTDL/d
/ltdl/d
s/clamscan\/clamscan.c/libclamunrar_iface\/unrar_iface.c/
' configure.in
cat <<EOF >Makefile.am &&
ACLOCAL_AMFLAGS=-I m4
DISTCLEANFILES = target.h
SUBDIRS = libclamunrar_iface
EOF
autoreconf
cd ..
tar -czf $UNRARPKG libclamunrar-$2/

printf "Test archives?"
read yes
if [ x$yes != xy ] ; then
    echo "Copying tarballs to current directory"
    mv $UNRARPKG ../ &&
    mv $DFSGPKG ../ &&
    echo "Ready (untested): $UNRARPKG $DFSGPKG" &&
    rm -rf $TEMP &&
    echo "Removed temporary directory $TEMP" &&
    exit 0
    exit 30
fi

mkdir testpfx || { echo "Failed to create testpfx"; exit 5; }
TESTPFX="$PWD/testpfx"
mkdir buildtest && cd buildtest
echo "Running build-test for $DFSGPKG"
tar -xzf ../$DFSGPKG && cd clamav-$2+dfsg
echo "Configuring"
./configure --disable-clamav --disable-unrar --enable-milter --prefix=$TESTPFX >makelog
echo "Building"
make $MAKEFLAGS >>makelog
echo "Checking"
make $MAKEFLAGS check >>makelog 2>&1
make $MAKEFLAGS install >>makelog
make $MAKFELAGS installcheck >>makelog
echo "OK"
cd ..
echo "Running build-test for $UNRARPKG"
tar -xzf ../$UNRARPKG && cd libclamunrar-$2
echo "Configuring"
./configure --disable-clamav --prefix=$TESTPFX >makelog
echo "Building"
make $MAKEFLAGS >>makelog
make $MAKEFLAGS install >>makelog
make $MAKEFLAGS installcheck >>makelog
echo "OK"
cd ../..
echo "Testing whether unrar functionality works"
cat <<EOF >test.hdb
aa15bcf478d165efd2065190eb473bcb:544:ClamAV-Test-File
EOF

if test $? -ne 0; then
    tail makelog
    echo
    echo "Failed"
    exit 50;
fi
# clamscan will exit with exitcode 1 on success (virus found)
set +e
$TESTPFX/bin/clamscan buildtest/clamav-$2+dfsg/test/clam-v*.rar -dtest.hdb >clamscanlog
if test $? -ne 1; then
    echo "Test failed";
    cat clamscanlog
    exit 10;
fi
NDET=`grep FOUND clamscanlog | wc -l`
if test "0$NDET" -eq "2"; then
    echo "All testfiles detected"
    echo "Copying tarballs to current directory"
    mv $UNRARPKG ../ &&
    mv $DFSGPKG ../ &&
    echo "Ready: $UNRARPKG $DFSGPKG" &&
    rm -rf $TEMP &&
    echo "Removed temporary directory $TEMP" &&
    exit 0
    exit 30
fi
echo "Test failed"
cat clamscanlog
exit 100
