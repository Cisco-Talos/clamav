#!/bin/sh
# CVS-ID: $Id$

echo ""
echo "-----------------------------------"
echo " Refreshing tables, please wait..."
echo "-----------------------------------"
echo ""

sh ./mk_fallbacks.sh
sh ./mk_encodings.sh

echo "  * removing temporary files..."

rm -f Fallbacks UnicodeChars

echo "
  * copying tables to src/common/unictabl.inc..."
  
mv -f unictabl.inc ../../src/common/unictabl.inc

echo "
  DONE
"
