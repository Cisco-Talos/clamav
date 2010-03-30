#!/bin/sh
mkdir -p llvm/Release/bin
mkdir -p llvm/Debug/bin
cp lli llc llvm-as not count FileCheck llvm-dis llvm/Release/bin/
cp lli llc llvm-as not count FileCheck llvm-dis llvm/Debug/bin/
$GMAKE -v || { echo "GNU make not found, skipping LLVM tests"; exit 77; }
python -V || { echo "Python not found, skipping LLVM tests"; exit 77; }
python <<EOF
import sys
if sys.hexversion < 0x2040000: sys.exit(1)
EOF
test $? -eq 0 || { echo "Python version older than 2.4, skipping LLVM tests"; exit 77; }
exec $GMAKE -C llvm check-lit TESTSUITE="--no-tcl-as-sh CodeGen ExecutionEngine Integer Verifier"
