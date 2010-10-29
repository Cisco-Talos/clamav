#!/bin/sh
# CVS-ID: $Id$


add_fallback()
{
    echo "      - for $3..."
    cat _tmp3 | grep "$1" | while read i ; do
        code=`echo $i | cut -c1-6`
        echo "$code	$2" >> _tmp5
    done
}


echo "  * getting list of needed unicode characters..."

cat mappings/*.TXT | sed -n '/^0x../p' | \
    cut -f2,4 | sort | uniq | sed -n '/^0x/p' > _tmp1
cat _tmp1 | cut -f1 | sort | uniq > _tmp2


echo "  * making unique list of unicode characters meanings..."

rm -f _tmp3
cat _tmp2 | while read i ; do
    sed -n "/^$i/p" _tmp1 | (read t ; echo "$t" >> _tmp3)
done

cp _tmp3 UnicodeChars

echo "  * creating one-byte fallback tables..."

rm -f Fallbacks _tmp5

echo "      - for latin capital letters..."

cat _tmp3 | grep 'LATIN CAPITAL LETTER [A-Z]$' > _tmp6
cat _tmp3 | grep 'LATIN CAPITAL LETTER [A-Z] WITH' >> _tmp6
cat _tmp6 | sort +2 > _tmp4

cat _tmp4 | while read i ; do
    code=`echo $i | cut -c1-6`
    fallb=`echo $i | cut -c8-29`
    cat _tmp4 | fgrep "$fallb" | cut -c1-6 | (read i ; 
        echo "$code	$i" >> _tmp5)
done


echo "      - for latin small letters..."

cat _tmp3 | grep 'LATIN SMALL LETTER [A-Z]$' > _tmp6
cat _tmp3 | grep 'LATIN SMALL LETTER [A-Z] WITH' >> _tmp6
cat _tmp6 | sort +2 > _tmp4

cat _tmp4 | while read i ; do
    code=`echo $i | cut -c1-6`
    fallb=`echo $i | cut -c8-27`
    cat _tmp4 | fgrep "$fallb" | cut -c1-6 | (read i ; 
        echo "$code	$i" >> _tmp5)
done


add_fallback "DOUBLE .*QUOTATION MARK" "0x0022" "double quotations"
add_fallback "SINGLE .*QUOTATION MARK" "0x0027" "single quotations"
add_fallback "DASH" "0x002D" "dashes"



echo "  * removing infinite loops from fallback tables..."

cat _tmp5 | grep -v '\(0x....\)	\1' | sort > Fallbacks

rm -f _tmp1 _tmp2 _tmp3 _tmp4 _tmp5 _tmp6

