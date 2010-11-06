#!/bin/sh
# Remove directories we don't use

for i in llvm/bindings/ llvm/examples/ llvm/projects/ llvm/runtime/\
    llvm/website llvm/win32 llvm/Xcode llvm/lib/Archive\
    llvm/lib/CompilerDriver/ llvm/lib/Debugger/ llvm/lib/Linker/\
    llvm/lib/AsmParser llvm/lib/Bitcode\
    llvm/lib/CodeGen/AsmPrinter\
    llvm/lib/ExecutionEngine/Interpreter\
    llvm/lib/MC/MCDisassembler llvm/lib/MC/MCParser/\
    llvm/lib/Target/PowerPC/AsmPrinter llvm/lib/Target/X86/AsmPrinter\
    llvm/lib/Target/X86/Disassembler/ llvm/lib/Target/X86/AsmParser\
    llvm/lib/Transforms/InstCombine/\
    llvm/lib/Target/Alpha/ llvm/lib/Target/ARM/ llvm/lib/Target/Blackfin/ llvm/lib/Target/CBackend/\
    llvm/lib/Target/CellSPU/ llvm/lib/Target/CppBackend/ llvm/lib/Target/Mips\
    llvm/lib/Target/MSIL llvm/lib/Target/MSP430/ llvm/lib/Target/PIC16\
    llvm/lib/Target/Sparc/ llvm/lib/Target/SystemZ llvm/lib/Target/XCore\
    llvm/lib/Target/MBlaze/ llvm/lib/Target/PIC16/ llvm/lib/Target/MSP430\
    llvm/test/  llvm/tools llvm/unittests llvm/utils/FileCheck\
    llvm/utils/FileUpdate llvm/utils/fpcmp llvm/utils/not\
    llvm/utils/PerfectShuffle llvm/utils/unittest\
    llvm/docs
    do
	git rm -rf $i; git rm -f $i;
done
# config.status needs these
mkdir -p llvm/docs/doxygen
touch llvm/docs/doxygen.cfg.in
git add llvm/docs/doxygen.cfg.in
