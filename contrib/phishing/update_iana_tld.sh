#!/bin/sh
IANA_TLD="http://data.iana.org/TLD/tlds-alpha-by-domain.txt"
TMP=`tempfile`
OUTFILE=iana_tld.h

echo "Downloading updated tld list from iana.org"
wget $IANA_TLD -O $TMP || exit 2
echo "Download complete, parsing data"
# 174 is the code for |
TLDLIST=$(egrep -v ^# $TMP|tr \\n \\174 )
echo "Parse complete, removing tmpfile"
rm $TMP
echo "Generating $OUTFILE"
cat >$OUTFILE <<EOF
#ifndef IANA_TLD_H
#define IANA_TLD_H
EOF
echo -n "#define iana_tld \"(" >>$OUTFILE
echo -n $TLDLIST >>$OUTFILE
echo ")\"" >>$OUTFILE
echo "#endif" >>$OUTFILE
echo "Finished succesfully"

