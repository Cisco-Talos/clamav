#!/bin/sh
mkdir -p llvm/Release/bin
mkdir -p llvm/Debug/bin
cp lli llc llvm-as not count FileCheck tblgen llvm-dis llvm/Release/bin/
cp lli llc llvm-as not count FileCheck tblgen llvm-dis llvm/Debug/bin/
$GMAKE -v || { echo "GNU make not found, skipping LLVM tests"; exit 77; }
python -V || { echo "Python not found, skipping LLVM tests"; exit 77; }
exec $GMAKE -C llvm check-lit TESTSUITE="CodeGen ExecutionEngine Integer Verifier"
