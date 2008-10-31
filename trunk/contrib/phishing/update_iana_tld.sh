#!/bin/sh
#
#  Phishing detection automated testing & tools.
#  Copyright (C) 2006 Torok Edvin <edwintorok@gmail.com>
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.
#
IANA_TLD="http://data.iana.org/TLD/tlds-alpha-by-domain.txt"
TMP=`tempfile`
OUTFILE=iana_tld.h

echo "Downloading updated tld list from iana.org"
wget $IANA_TLD -O $TMP || exit 2
echo "Download complete, parsing data"
# 174 is the code for |
grep -Ev ^# $TMP | tr [A-Z] [a-z] | gperf -C -H tld_hash -N in_tld_set -l|grep -v '^#line' | sed -e 's/^const struct/static const struct/' -e 's/register //g'
