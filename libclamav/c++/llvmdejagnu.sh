#!/bin/bash
mkdir -p llvm/Release/bin
mkdir -p llvm/Debug/bin
cp lli llc llvm-as not count FileCheck tblgen llvm-dis llvm/Release/bin/
cp lli llc llvm-as not count FileCheck tblgen llvm-dis llvm/Debug/bin/

exec $GMAKE -C llvm check-lit TESTSUITE="CodeGen ExecutionEngine Integer TableGen Verifier"
