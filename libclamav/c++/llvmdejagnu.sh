#!/bin/bash
mkdir -p llvm/Release/bin
mkdir -p llvm/Debug/bin
cp lli llc llvm-as llvm/Release/bin/
cp lli llc llvm-as llvm/Debug/bin/

failed=
$GMAKE -C llvm/test TESTSUITE=CodeGen || failed=CodeGen
$GMAKE -C llvm/test TESTSUITE=ExecutionEngine || failed="$failed ExecutionEngine"
$GMAKE -C llvm/test TESTSUITE=Integer || failed="$failed Integer"
$GMAKE -C llvm/test TESTSUITE=TableGen || failed="$failed TableGen"
$GMAKE -C llvm/test TESTSUITE=Verifier || failed="$failed Verifier"

test -z "$failed" && exit 0
echo "LLVM dejagnu tests failed: $failed"
exit 1
