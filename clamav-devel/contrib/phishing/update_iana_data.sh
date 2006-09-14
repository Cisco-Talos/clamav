#!/bin/sh
IANA_TLD="http://data.iana.org/TLD/tlds-alpha-by-domain.txt"
IANA_CCTLD="http://www.iana.org/cctld/cctld-whois.htm";
TMP=`tempfile`
OUTFILE=iana_tld.h

echo "Downloading updated tld list from iana.org"
wget $IANA_TLD -O $TMP || exit 2
echo "Download complete, parsing data"
# 174 is the code for |
TLDLIST=$(egrep -v ^# $TMP | tr \\n \\174 | sed 's/[^a-zA-Z]$//')
echo "Parse complete, removing tmpfile"
rm $TMP
echo "Generating tld list in $OUTFILE"
cat >$OUTFILE <<EOF
#ifndef IANA_TLD_H
#define IANA_TLD_H
EOF
echo -n "#define iana_tld \"(" >>$OUTFILE
echo -n $TLDLIST >>$OUTFILE
echo ")\"" >>$OUTFILE

echo "Downloading updated country-code list from iana.org"
wget $IANA_CCTLD -O $TMP || exit 2
echo "Download complete, parsing data"
CCTLDLIST=$(cat $TMP | egrep -oi "<a href=[^>]+>\\.([a-z]+).+</a>" | egrep -o ">.[a-z]+" | colrm 1 2 | tr \\n \\174 | sed 's/[^a-zA-Z]$//')
echo "Parse complete, removing tmpfile"
rm $TMP
echo "Generating cctld list in $OUTFILE"
echo -n "#define iana_cctld \"(" >>$OUTFILE
echo -n $CCTLDLIST >>$OUTFILE
echo ")\"" >>$OUTFILE


echo "#endif" >>$OUTFILE
echo "Finished succesfully"
