#!/bin/sh
mkdir -p llvm/Release/bin
mkdir -p llvm/Debug/bin
cp lli llc llvm-as not count FileCheck tblgen llvm-dis llvm/Release/bin/
cp lli llc llvm-as not count FileCheck tblgen llvm-dis llvm/Debug/bin/
$GMAKE -v || { echo "GNU make not found, skipping LLVM tests"; exit 77; }
python -V || { echo "Python not found, skipping LLVM tests"; exit 77; }
python <<EOF
import sys
if sys.hexversion < 0x2050000: sys.exit(1)
EOF
test $? -eq 0 || { echo "Python version older than 2.5, skipping LLVM tests"; exit 77; }
exec $GMAKE -C llvm check-lit TESTSUITE="CodeGen ExecutionEngine Integer Verifier"
