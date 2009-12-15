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

LLVM_INCLUDES=-I$(top_srcdir)/llvm/include -I$(top_builddir)/llvm/include
# TODO: _DEBUG should be defined for --enable-debug, and NDEBUG otherwise, but
# keep it like this while I'm testing LLVM
# TODO: HP-UX should have -D_REENTRANT -D_HPUX_SOURCE
LLVM_DEFS=-D__STDC_LIMIT_MACROS -D__STDC_CONSTANT_MACROS -D_DEBUG -D_GNU_SOURCE
AM_CPPFLAGS = -I$(top_srcdir)/../.. -I$(top_srcdir)/.. -I$(top_builddir)/../../ $(LLVM_INCLUDES) $(LLVM_DEFS)
AM_CXXFLAGS = $(LLVM_CXXFLAGS) -fno-exceptions
ACLOCAL_AMFLAGS=-I m4
if DEBUG_BUILD
LLVM_CONFIG=llvm/Debug/bin/llvm-config
else
LLVM_CONFIG=llvm/Release/bin/llvm-config
endif

#$(LLVM_CONFIG): build-llvm
# we know this will be built with GNU make, so its safe to use GNU make specific
# $(shell ...)
#LLVM_DEPS=$(shell $(LLVM_CONFIG) --libfiles jit nativecodegen)
#libclamavcxx_la_CPPFLAGS = $(AM_CPPFLAGS) `$(LLVM_CONFIG) --cppflags`
#libclamavcxx_la_DEPENDENCIES = $(LLVM_DEPS)
#libclamavcxx_la_LDFLAGS = `$(LLVM_CONFIG) --ldflags --libs jit nativecodegen`
#libclamavcxx_la_CPPFLAGS = $(AM_CPPFLAGS) $(LLVM_INCLUDES) $(LLVM_DEFS)
#libclamavcxx_la_DEPENDENCIES = $(LLVM_DEPS)

noinst_LTLIBRARIES = libclamavcxx.la libllvmsupport.la libllvmsystem.la\
		     libllvmcodegen.la libllvmjit.la

libclamavcxx_la_LIBADD=libllvmjit.la libllvmcodegen.la libllvmsystem.la
libclamavcxx_la_DEPENDENCIES=libllvmjit.la libllvmcodegen.la libllvmsystem.la
libclamavcxx_la_LDFLAGS=-no-undefined
libclamavcxx_la_CXXFLAGS = $(LLVM_CXXFLAGS)
libclamavcxx_la_SOURCES = bytecode2llvm.cpp
if BUILD_X86
libclamavcxx_la_LIBADD+=libllvmx86codegen.la
libclamavcxx_la_DEPENDENCIES+=libllvmx86codegen.la
noinst_LTLIBRARIES+=libllvmx86codegen.la
endif
if BUILD_PPC
libclamavcxx_la_LIBADD+=libllvmpowerpccodegen.la
libclamavcxx_la_DEPENDENCIES+=libllvmpowerpccodegen.la
noinst_LTLIBRARIES+=libllvmpowerpccodegen.la
endif
if BUILD_ARM
libclamavcxx_la_LIBADD+=libllvmarmcodegen.la
libclamavcxx_la_DEPENDENCIES+=libllvmarmcodegen.la
noinst_LTLIBRARIES+=libllvmarmcodegen.la
endif


LLVM_CXXFLAGS=-Woverloaded-virtual -pedantic -Wno-long-long -Wall -W -Wno-unused-parameter -Wwrite-strings

EXTRA_DIST=$(top_srcdir)/llvm llvmdejagnu.sh

libllvmsystem_la_LDFLAGS=-pthread
libllvmsystem_la_LIBADD=-ldl
libllvmsystem_la_SOURCES=\
	llvm/lib/System/Alarm.cpp\
	llvm/lib/System/Atomic.cpp\
	llvm/lib/System/Disassembler.cpp\
	llvm/lib/System/DynamicLibrary.cpp\
	llvm/lib/System/Errno.cpp\
	llvm/lib/System/Host.cpp\
	llvm/lib/System/IncludeFile.cpp\
	llvm/lib/System/Memory.cpp\
	llvm/lib/System/Mutex.cpp\
	llvm/lib/System/Path.cpp\
	llvm/lib/System/Process.cpp\
	llvm/lib/System/Program.cpp\
	llvm/lib/System/RWMutex.cpp\
	llvm/lib/System/Signals.cpp\
	llvm/lib/System/ThreadLocal.cpp\
	llvm/lib/System/Threading.cpp\
	llvm/lib/System/TimeValue.cpp

libllvmsupport_la_SOURCES=\
	llvm/lib/Support/APFloat.cpp\
	llvm/lib/Support/APInt.cpp\
	llvm/lib/Support/APSInt.cpp\
	llvm/lib/Support/Allocator.cpp\
	llvm/lib/Support/CommandLine.cpp\
	llvm/lib/Support/ConstantRange.cpp\
	llvm/lib/Support/Debug.cpp\
	llvm/lib/Support/DeltaAlgorithm.cpp\
	llvm/lib/Support/Dwarf.cpp\
	llvm/lib/Support/ErrorHandling.cpp\
	llvm/lib/Support/FileUtilities.cpp\
	llvm/lib/Support/FoldingSet.cpp\
	llvm/lib/Support/FormattedStream.cpp\
	llvm/lib/Support/GraphWriter.cpp\
	llvm/lib/Support/IsInf.cpp\
	llvm/lib/Support/IsNAN.cpp\
	llvm/lib/Support/ManagedStatic.cpp\
	llvm/lib/Support/MemoryBuffer.cpp\
	llvm/lib/Support/MemoryObject.cpp\
	llvm/lib/Support/PluginLoader.cpp\
	llvm/lib/Support/PrettyStackTrace.cpp\
	llvm/lib/Support/Regex.cpp\
	llvm/lib/Support/SlowOperationInformer.cpp\
	llvm/lib/Support/SmallPtrSet.cpp\
	llvm/lib/Support/SourceMgr.cpp\
	llvm/lib/Support/Statistic.cpp\
	llvm/lib/Support/StringExtras.cpp\
	llvm/lib/Support/StringMap.cpp\
	llvm/lib/Support/StringPool.cpp\
	llvm/lib/Support/StringRef.cpp\
	llvm/lib/Support/SystemUtils.cpp\
	llvm/lib/Support/TargetRegistry.cpp\
	llvm/lib/Support/Timer.cpp\
	llvm/lib/Support/Triple.cpp\
	llvm/lib/Support/Twine.cpp\
	llvm/lib/Support/raw_os_ostream.cpp\
	llvm/lib/Support/raw_ostream.cpp\
	llvm/lib/Support/regcomp.c\
	llvm/lib/Support/regerror.c\
	llvm/lib/Support/regexec.c\
	llvm/lib/Support/regfree.c\
	llvm/lib/Support/regstrlcpy.c

tblgen_CXXFLAGS=$(LLVM_CXXFLAGS)
tblgen_LDADD=libllvmsupport.la libllvmsystem.la
#TODO: if VERSIONSCRIPT
tblgen_LDFLAGS= -Wl,--version-script,@top_srcdir@/llvm/autoconf/ExportMap.map
tblgen_SOURCES=\
  llvm/utils/TableGen/AsmMatcherEmitter.cpp\
  llvm/utils/TableGen/AsmWriterEmitter.cpp\
  llvm/utils/TableGen/CallingConvEmitter.cpp\
  llvm/utils/TableGen/ClangDiagnosticsEmitter.cpp\
  llvm/utils/TableGen/CodeEmitterGen.cpp\
  llvm/utils/TableGen/CodeGenDAGPatterns.cpp\
  llvm/utils/TableGen/CodeGenInstruction.cpp\
  llvm/utils/TableGen/CodeGenTarget.cpp\
  llvm/utils/TableGen/DisassemblerEmitter.cpp\
  llvm/utils/TableGen/DAGISelEmitter.cpp\
  llvm/utils/TableGen/FastISelEmitter.cpp\
  llvm/utils/TableGen/InstrEnumEmitter.cpp\
  llvm/utils/TableGen/InstrInfoEmitter.cpp\
  llvm/utils/TableGen/IntrinsicEmitter.cpp\
  llvm/utils/TableGen/LLVMCConfigurationEmitter.cpp\
  llvm/utils/TableGen/OptParserEmitter.cpp\
  llvm/utils/TableGen/Record.cpp\
  llvm/utils/TableGen/RegisterInfoEmitter.cpp\
  llvm/utils/TableGen/SubtargetEmitter.cpp\
  llvm/utils/TableGen/TGLexer.cpp\
  llvm/utils/TableGen/TGParser.cpp\
  llvm/utils/TableGen/TGValueTypes.cpp\
  llvm/utils/TableGen/TableGen.cpp\
  llvm/utils/TableGen/TableGenBackend.cpp

TBLGEN=$(top_builddir)/tblgen
TBLGEN_V=$(AM_V_GEN)$(TBLGEN)
TBLGEN_FLAGS=-I$(top_srcdir)/llvm/include -I$(top_srcdir)/llvm/lib/Target

BUILT_SOURCES=llvm/include/llvm/Intrinsics.gen
llvm/include/llvm/Intrinsics.gen: llvm/include/llvm/Intrinsics.td $(TBLGEN)
	$(TBLGEN_V) $(TBLGEN_FLAGS) -gen-intrinsic -o $@ $<

# X86 Target
if BUILD_X86
TBLGEN_FLAGS_X86= $(TBLGEN_FLAGS) -I$(top_srcdir)/llvm/lib/Target/X86
X86GenRegisterInfo.h.inc: llvm/lib/Target/X86/X86.td $(TBLGEN)
	$(TBLGEN_V) $(TBLGEN_FLAGS_X86) -gen-register-desc-header -o $@ $<

X86GenRegisterNames.inc: llvm/lib/Target/X86/X86.td $(TBLGEN)
	$(TBLGEN_V) $(TBLGEN_FLAGS_X86) -gen-register-enums -o $@ $<

X86GenRegisterInfo.inc: llvm/lib/Target/X86/X86.td $(TBLGEN)
	$(TBLGEN_V) $(TBLGEN_FLAGS_X86) -gen-register-desc -o $@ $<

X86GenInstrNames.inc: llvm/lib/Target/X86/X86.td $(TBLGEN)
	$(TBLGEN_V) $(TBLGEN_FLAGS_X86) -gen-instr-enums -o $@ $<

X86GenInstrInfo.inc: llvm/lib/Target/X86/X86.td $(TBLGEN)
	$(TBLGEN_V) $(TBLGEN_FLAGS_X86) -gen-instr-desc -o $@ $<

X86GenAsmWriter.inc: llvm/lib/Target/X86/X86.td $(TBLGEN)
	$(TBLGEN_V) $(TBLGEN_FLAGS_X86) -gen-asm-writer -o $@ $<

X86GenAsmWriter1.inc: llvm/lib/Target/X86/X86.td $(TBLGEN)
	$(TBLGEN_V) $(TBLGEN_FLAGS_X86) -gen-asm-writer -asmwriternum=1 -o $@ $<

X86GenAsmMatcher.inc: llvm/lib/Target/X86/X86.td $(TBLGEN)
	$(TBLGEN_V) $(TBLGEN_FLAGS_X86) -gen-asm-matcher -o $@ $<

X86GenDAGISel.inc: llvm/lib/Target/X86/X86.td $(TBLGEN)
	$(TBLGEN_V) $(TBLGEN_FLAGS_X86) -gen-dag-isel -o $@ $<

X86GenFastISel.inc: llvm/lib/Target/X86/X86.td $(TBLGEN)
	$(TBLGEN_V) $(TBLGEN_FLAGS_X86) -gen-fast-isel -o $@ $<

X86GenCallingConv.inc: llvm/lib/Target/X86/X86.td $(TBLGEN)
	$(TBLGEN_V) $(TBLGEN_FLAGS_X86) -gen-callingconv -o $@ $<

X86GenSubtarget.inc: llvm/lib/Target/X86/X86.td $(TBLGEN)
	$(TBLGEN_V) $(TBLGEN_FLAGS_X86) -gen-subtarget -o $@ $<

libllvmx86codegen_la_CPPFLAGS=$(LLVM_INCLUDES) $(LLVM_DEFS) -I$(top_builddir) -I$(top_srcdir)/llvm/lib/Target/X86
BUILT_SOURCES+=X86GenRegisterInfo.h.inc X86GenRegisterNames.inc X86GenRegisterInfo.inc X86GenInstrNames.inc X86GenInstrInfo.inc\
	      X86GenAsmWriter.inc X86GenAsmWriter1.inc X86GenAsmMatcher.inc X86GenDAGISel.inc X86GenFastISel.inc X86GenCallingConv.inc\
	      X86GenSubtarget.inc

libllvmx86codegen_la_SOURCES=\
	llvm/lib/CodeGen/DeadMachineInstructionElim.cpp\
	llvm/lib/CodeGen/MachineDominators.cpp\
	llvm/lib/CodeGen/MachineLoopInfo.cpp\
	llvm/lib/CodeGen/MachineModuleInfoImpls.cpp\
	llvm/lib/CodeGen/SelectionDAG/FastISel.cpp\
	llvm/lib/MC/MCAsmInfoCOFF.cpp\
	llvm/lib/MC/MCCodeEmitter.cpp\
	llvm/lib/MC/MCContext.cpp\
	llvm/lib/MC/MCExpr.cpp\
	llvm/lib/MC/MCInst.cpp\
	llvm/lib/Target/TargetELFWriterInfo.cpp\
	llvm/lib/Target/X86/TargetInfo/X86TargetInfo.cpp\
	llvm/lib/Target/X86/X86COFFMachineModuleInfo.cpp\
	llvm/lib/Target/X86/X86CodeEmitter.cpp\
	llvm/lib/Target/X86/X86ELFWriterInfo.cpp\
	llvm/lib/Target/X86/X86FastISel.cpp\
	llvm/lib/Target/X86/X86FloatingPoint.cpp\
	llvm/lib/Target/X86/X86FloatingPointRegKill.cpp\
	llvm/lib/Target/X86/X86ISelDAGToDAG.cpp\
	llvm/lib/Target/X86/X86ISelLowering.cpp\
	llvm/lib/Target/X86/X86InstrInfo.cpp\
	llvm/lib/Target/X86/X86JITInfo.cpp\
	llvm/lib/Target/X86/X86MCAsmInfo.cpp\
	llvm/lib/Target/X86/X86RegisterInfo.cpp\
	llvm/lib/Target/X86/X86Subtarget.cpp\
	llvm/lib/Target/X86/X86TargetMachine.cpp\
	llvm/lib/Target/X86/X86TargetObjectFile.cpp
endif

if BUILD_PPC
# PPC Target
TBLGEN_FLAGS_PPC= $(TBLGEN_FLAGS) -I$(top_srcdir)/llvm/lib/Target/PowerPC
PPCGenInstrNames.inc: llvm/lib/Target/PowerPC/PPC.td $(TBLGEN)
	$(TBLGEN_V) $(TBLGEN_FLAGS_PPC) -gen-instr-enums -o $@ $<

PPCGenRegisterNames.inc: llvm/lib/Target/PowerPC/PPC.td $(TBLGEN)
	$(TBLGEN_V) $(TBLGEN_FLAGS_PPC) -gen-register-enums -o $@ $<

PPCGenAsmWriter.inc: llvm/lib/Target/PowerPC/PPC.td $(TBLGEN)
	$(TBLGEN_V) $(TBLGEN_FLAGS_PPC) -gen-asm-writer -o $@ $<

PPCGenCodeEmitter.inc: llvm/lib/Target/PowerPC/PPC.td $(TBLGEN)
	$(TBLGEN_V) $(TBLGEN_FLAGS_PPC) -gen-emitter -o $@ $<

PPCRegisterInfo.h.inc: llvm/lib/Target/PowerPC/PPC.td $(TBLGEN)
	$(TBLGEN_V) $(TBLGEN_FLAGS_PPC) -gen-register-desc-header -o $@ $<

PPCGenRegisterInfo.inc: llvm/lib/Target/PowerPC/PPC.td $(TBLGEN)
	$(TBLGEN_V) $(TBLGEN_FLAGS_PPC) -gen-register-desc -o $@ $<

PPCGenRegisterInfo.h.inc: llvm/lib/Target/PowerPC/PPC.td $(TBLGEN)
	$(TBLGEN_V) $(TBLGEN_FLAGS_PPC) -gen-register-desc-header -o $@ $<

PPCGenInstrInfo.inc: llvm/lib/Target/PowerPC/PPC.td $(TBLGEN)
	$(TBLGEN_V) $(TBLGEN_FLAGS_PPC) -gen-instr-desc -o $@ $<

PPCGenDAGISel.inc: llvm/lib/Target/PowerPC/PPC.td $(TBLGEN)
	$(TBLGEN_V) $(TBLGEN_FLAGS_PPC) -gen-dag-isel -o $@ $<

PPCGenCallingConv.inc: llvm/lib/Target/PowerPC/PPC.td $(TBLGEN)
	$(TBLGEN_V) $(TBLGEN_FLAGS_PPC) -gen-callingconv -o $@ $<

PPCGenSubtarget.inc: llvm/lib/Target/PowerPC/PPC.td $(TBLGEN)
	$(TBLGEN_V) $(TBLGEN_FLAGS_PPC) -gen-subtarget -o $@ $<

libllvmpowerpccodegen_la_CPPFLAGS=$(LLVM_INCLUDES) $(LLVM_DEFS) -I$(top_builddir) -I$(top_srcdir)/llvm/lib/Target/PowerPC
BUILT_SOURCES += PPCGenInstrNames.inc PPCGenRegisterNames.inc PPCGenAsmWriter.inc PPCGenCodeEmitter.inc PPCGenRegisterInfo.h.inc PPCGenRegisterInfo.inc\
    PPCGenInstrInfo.inc PPCGenDAGISel.inc PPCGenCallingConv.inc PPCGenSubtarget.inc

libllvmpowerpccodegen_la_SOURCES=\
	llvm/lib/CodeGen/ScheduleDAG.cpp\
	llvm/lib/Target/PowerPC/PPCBranchSelector.cpp\
	llvm/lib/Target/PowerPC/PPCCodeEmitter.cpp\
	llvm/lib/Target/PowerPC/PPCHazardRecognizers.cpp\
	llvm/lib/Target/PowerPC/PPCISelDAGToDAG.cpp\
	llvm/lib/Target/PowerPC/PPCISelLowering.cpp\
	llvm/lib/Target/PowerPC/PPCInstrInfo.cpp\
	llvm/lib/Target/PowerPC/PPCJITInfo.cpp\
	llvm/lib/Target/PowerPC/PPCMCAsmInfo.cpp\
	llvm/lib/Target/PowerPC/PPCMachOWriterInfo.cpp\
	llvm/lib/Target/PowerPC/PPCPredicates.cpp\
	llvm/lib/Target/PowerPC/PPCRegisterInfo.cpp\
	llvm/lib/Target/PowerPC/PPCSubtarget.cpp\
	llvm/lib/Target/PowerPC/PPCTargetMachine.cpp\
	llvm/lib/Target/PowerPC/TargetInfo/PowerPCTargetInfo.cpp\
	llvm/lib/Target/TargetMachOWriterInfo.cpp

endif

if BUILD_ARM
# ARM Target
TBLGEN_FLAGS_ARM= $(TBLGEN_FLAGS) -I$(top_srcdir)/llvm/lib/Target/ARM
ARMGenRegisterInfo.h.inc: llvm/lib/Target/ARM/ARM.td $(TBLGEN)
	$(TBLGEN_V) $(TBLGEN_FLAGS_ARM) -gen-register-desc-header -o $@ $<

ARMGenRegisterNames.inc: llvm/lib/Target/ARM/ARM.td $(TBLGEN)
	$(TBLGEN_V) $(TBLGEN_FLAGS_ARM) -gen-register-enums -o $@ $<

ARMGenRegisterInfo.inc: llvm/lib/Target/ARM/ARM.td $(TBLGEN)
	$(TBLGEN_V) $(TBLGEN_FLAGS_ARM) -gen-register-desc -o $@ $<

ARMGenInstrNames.inc: llvm/lib/Target/ARM/ARM.td $(TBLGEN)
	$(TBLGEN_V) $(TBLGEN_FLAGS_ARM) -gen-instr-enums -o $@ $<

ARMGenInstrInfo.inc: llvm/lib/Target/ARM/ARM.td $(TBLGEN)
	$(TBLGEN_V) $(TBLGEN_FLAGS_ARM) -gen-instr-desc -o $@ $<

ARMGenCodeEmitter.inc: llvm/lib/Target/ARM/ARM.td $(TBLGEN)
	$(TBLGEN_V) $(TBLGEN_FLAGS_ARM) -gen-emitter -o $@ $<

ARMGenAsmWriter.inc: llvm/lib/Target/ARM/ARM.td $(TBLGEN)
	$(TBLGEN_V) $(TBLGEN_FLAGS_ARM) -gen-asm-writer -o $@ $<

ARMGenDAGISel.inc: llvm/lib/Target/ARM/ARM.td $(TBLGEN)
	$(TBLGEN_V) $(TBLGEN_FLAGS_ARM) -gen-dag-isel -o $@ $<

ARMGenCallingConv.inc: llvm/lib/Target/ARM/ARM.td $(TBLGEN)
	$(TBLGEN_V) $(TBLGEN_FLAGS_ARM) -gen-callingconv -o $@ $<

ARMGenSubtarget.inc: llvm/lib/Target/ARM/ARM.td $(TBLGEN)
	$(TBLGEN_V) $(TBLGEN_FLAGS_ARM) -gen-subtarget -o $@ $<

libllvmarmcodegen_la_CPPFLAGS=$(LLVM_INCLUDES) $(LLVM_DEFS) -I$(top_builddir) -I$(top_srcdir)/llvm/lib/Target/ARM
BUILT_SOURCES += ARMGenRegisterInfo.h.inc ARMGenRegisterNames.inc ARMGenRegisterInfo.inc ARMGenInstrNames.inc ARMGenInstrInfo.inc ARMGenCodeEmitter.inc\
    ARMGenAsmWriter.inc ARMGenDAGISel.inc ARMGenCallingConv.inc ARMGenSubtarget.inc

libllvmarmcodegen_la_SOURCES=\
	llvm/lib/CodeGen/IfConversion.cpp\
	llvm/lib/Target/ARM/ARMBaseInstrInfo.cpp\
	llvm/lib/Target/ARM/ARMBaseRegisterInfo.cpp\
	llvm/lib/Target/ARM/ARMCodeEmitter.cpp\
	llvm/lib/Target/ARM/ARMConstantIslandPass.cpp\
	llvm/lib/Target/ARM/ARMConstantPoolValue.cpp\
	llvm/lib/Target/ARM/ARMExpandPseudoInsts.cpp\
	llvm/lib/Target/ARM/ARMISelDAGToDAG.cpp\
	llvm/lib/Target/ARM/ARMISelLowering.cpp\
	llvm/lib/Target/ARM/ARMInstrInfo.cpp\
	llvm/lib/Target/ARM/ARMJITInfo.cpp\
	llvm/lib/Target/ARM/ARMLoadStoreOptimizer.cpp\
	llvm/lib/Target/ARM/ARMMCAsmInfo.cpp\
	llvm/lib/Target/ARM/ARMRegisterInfo.cpp\
	llvm/lib/Target/ARM/ARMSubtarget.cpp\
	llvm/lib/Target/ARM/ARMTargetMachine.cpp\
	llvm/lib/Target/ARM/NEONMoveFix.cpp\
	llvm/lib/Target/ARM/NEONPreAllocPass.cpp\
	llvm/lib/Target/ARM/TargetInfo/ARMTargetInfo.cpp\
	llvm/lib/Target/ARM/Thumb1InstrInfo.cpp\
	llvm/lib/Target/ARM/Thumb1RegisterInfo.cpp\
	llvm/lib/Target/ARM/Thumb2ITBlockPass.cpp\
	llvm/lib/Target/ARM/Thumb2InstrInfo.cpp\
	llvm/lib/Target/ARM/Thumb2RegisterInfo.cpp\
	llvm/lib/Target/ARM/Thumb2SizeReduction.cpp
endif

# End of Targets

libllvmjit_la_SOURCES=\
	llvm/lib/CodeGen/ELFWriter.cpp\
	llvm/lib/CodeGen/MachineFunction.cpp\
	llvm/lib/CodeGen/MachineInstr.cpp\
	llvm/lib/CodeGen/MachineModuleInfo.cpp\
	llvm/lib/ExecutionEngine/ExecutionEngine.cpp\
	llvm/lib/ExecutionEngine/JIT/Intercept.cpp\
	llvm/lib/ExecutionEngine/JIT/JIT.cpp\
	llvm/lib/ExecutionEngine/JIT/JITDebugRegisterer.cpp\
	llvm/lib/ExecutionEngine/JIT/JITDwarfEmitter.cpp\
	llvm/lib/ExecutionEngine/JIT/JITEmitter.cpp\
	llvm/lib/ExecutionEngine/JIT/JITMemoryManager.cpp\
	llvm/lib/ExecutionEngine/JIT/OProfileJITEventListener.cpp\
	llvm/lib/ExecutionEngine/JIT/TargetSelect.cpp\
	llvm/lib/MC/MCAsmInfo.cpp\
	llvm/lib/Support/APFloat.cpp\
	llvm/lib/Support/APInt.cpp\
	llvm/lib/Support/Allocator.cpp\
	llvm/lib/Support/CommandLine.cpp\
	llvm/lib/Support/ConstantRange.cpp\
	llvm/lib/Support/Debug.cpp\
	llvm/lib/Support/Dwarf.cpp\
	llvm/lib/Support/ErrorHandling.cpp\
	llvm/lib/Support/FoldingSet.cpp\
	llvm/lib/Support/FormattedStream.cpp\
	llvm/lib/Support/ManagedStatic.cpp\
	llvm/lib/Support/MemoryBuffer.cpp\
	llvm/lib/Support/PrettyStackTrace.cpp\
	llvm/lib/Support/SmallPtrSet.cpp\
	llvm/lib/Support/Statistic.cpp\
	llvm/lib/Support/StringExtras.cpp\
	llvm/lib/Support/StringMap.cpp\
	llvm/lib/Support/StringPool.cpp\
	llvm/lib/Support/TargetRegistry.cpp\
	llvm/lib/Support/Timer.cpp\
	llvm/lib/Support/Triple.cpp\
	llvm/lib/Support/Twine.cpp\
	llvm/lib/Support/raw_ostream.cpp\
	llvm/lib/Target/SubtargetFeature.cpp\
	llvm/lib/Target/TargetData.cpp\
	llvm/lib/Target/TargetMachine.cpp\
	llvm/lib/VMCore/AsmWriter.cpp\
	llvm/lib/VMCore/Attributes.cpp\
	llvm/lib/VMCore/AutoUpgrade.cpp\
	llvm/lib/VMCore/BasicBlock.cpp\
	llvm/lib/VMCore/ConstantFold.cpp\
	llvm/lib/VMCore/Constants.cpp\
	llvm/lib/VMCore/Core.cpp\
	llvm/lib/VMCore/Dominators.cpp\
	llvm/lib/VMCore/Function.cpp\
	llvm/lib/VMCore/Globals.cpp\
	llvm/lib/VMCore/InlineAsm.cpp\
	llvm/lib/VMCore/Instruction.cpp\
	llvm/lib/VMCore/Instructions.cpp\
	llvm/lib/VMCore/IntrinsicInst.cpp\
	llvm/lib/VMCore/LLVMContext.cpp\
	llvm/lib/VMCore/LeakDetector.cpp\
	llvm/lib/VMCore/Mangler.cpp\
	llvm/lib/VMCore/Metadata.cpp\
	llvm/lib/VMCore/Module.cpp\
	llvm/lib/VMCore/ModuleProvider.cpp\
	llvm/lib/VMCore/Pass.cpp\
	llvm/lib/VMCore/PassManager.cpp\
	llvm/lib/VMCore/PrintModulePass.cpp\
	llvm/lib/VMCore/Type.cpp\
	llvm/lib/VMCore/TypeSymbolTable.cpp\
	llvm/lib/VMCore/Use.cpp\
	llvm/lib/VMCore/Value.cpp\
	llvm/lib/VMCore/ValueSymbolTable.cpp\
	llvm/lib/VMCore/ValueTypes.cpp\
	llvm/lib/VMCore/Verifier.cpp

libllvmcodegen_la_SOURCES=\
	llvm/lib/CodeGen/LLVMTargetMachine.cpp\
	llvm/lib/CodeGen/LiveVariables.cpp\
	llvm/lib/CodeGen/MachineBasicBlock.cpp\
	llvm/lib/CodeGen/MachineFunctionPass.cpp\
	llvm/lib/CodeGen/MachineRegisterInfo.cpp\
	llvm/lib/CodeGen/MaxStackAlignment.cpp\
	llvm/lib/CodeGen/ObjectCodeEmitter.cpp\
	llvm/lib/CodeGen/PseudoSourceValue.cpp\
	llvm/lib/CodeGen/RegisterScavenging.cpp\
	llvm/lib/CodeGen/SelectionDAG/CallingConvLower.cpp\
	llvm/lib/CodeGen/SelectionDAG/DAGCombiner.cpp\
	llvm/lib/CodeGen/SelectionDAG/SelectionDAG.cpp\
	llvm/lib/CodeGen/SelectionDAG/SelectionDAGBuilder.cpp\
	llvm/lib/CodeGen/SelectionDAG/SelectionDAGISel.cpp\
	llvm/lib/CodeGen/SelectionDAG/TargetLowering.cpp\
	llvm/lib/CodeGen/TargetInstrInfoImpl.cpp\
	llvm/lib/MC/MCAsmInfoDarwin.cpp\
	llvm/lib/Support/StringRef.cpp\
	llvm/lib/Target/TargetFrameInfo.cpp\
	llvm/lib/Target/TargetInstrInfo.cpp\
	llvm/lib/Target/TargetLoweringObjectFile.cpp\
	llvm/lib/Target/TargetRegisterInfo.cpp\
	llvm/lib/Target/TargetSubtarget.cpp



# Used only by make check

libllvmbitreader_la_SOURCES=\
 llvm/lib/Bitcode/Reader/BitReader.cpp\
 llvm/lib/Bitcode/Reader/BitcodeReader.cpp\
 llvm/lib/Bitcode/Reader/Deserialize.cpp\
 llvm/lib/Bitcode/Reader/DeserializeAPFloat.cpp\
 llvm/lib/Bitcode/Reader/DeserializeAPInt.cpp

libllvmbitwriter_la_SOURCES=\
 llvm/lib/Bitcode/Writer/BitWriter.cpp\
 llvm/lib/Bitcode/Writer/BitcodeWriter.cpp\
 llvm/lib/Bitcode/Writer/BitcodeWriterPass.cpp\
 llvm/lib/Bitcode/Writer/Serialize.cpp\
 llvm/lib/Bitcode/Writer/SerializeAPFloat.cpp\
 llvm/lib/Bitcode/Writer/SerializeAPInt.cpp\
 llvm/lib/Bitcode/Writer/ValueEnumerator.cpp

libllvmasmparser_la_SOURCES=\
 llvm/lib/AsmParser/LLLexer.cpp\
 llvm/lib/AsmParser/LLParser.cpp\
 llvm/lib/AsmParser/Parser.cpp

#TODO: configure check -Wno-missing-field-initializers -Wno-variadic-macros
libllvminterpreter_la_SOURCES=\
    llvm/lib/ExecutionEngine/Interpreter/Execution.cpp\
    llvm/lib/ExecutionEngine/Interpreter/ExternalFunctions.cpp\
    llvm/lib/ExecutionEngine/Interpreter/Interpreter.cpp

# -Wno-missing-field-initializers -Wno-variadic-macros
libgoogletest_la_SOURCES=\
    llvm/utils/unittest/googletest/gtest-death-test.cc\
    llvm/utils/unittest/googletest/gtest-filepath.cc\
    llvm/utils/unittest/googletest/gtest-port.cc\
    llvm/utils/unittest/googletest/gtest-test-part.cc\
    llvm/utils/unittest/googletest/gtest-typed-test.cc\
    llvm/utils/unittest/googletest/gtest.cc\
    llvm/utils/unittest/UnitTestMain/TestMain.cpp

#-Wno-variadic-macros
llvmunittest_ADT_LDADD=libgoogletest.la libllvmcore.la libllvmsupport.la libllvmsystem.la
llvmunittest_ADT_SOURCES=\
    llvm/unittests/ADT/APFloatTest.cpp\
    llvm/unittests/ADT/APIntTest.cpp\
    llvm/unittests/ADT/DenseMapTest.cpp\
    llvm/unittests/ADT/DenseSetTest.cpp\
    llvm/unittests/ADT/ImmutableSetTest.cpp\
    llvm/unittests/ADT/SmallStringTest.cpp\
    llvm/unittests/ADT/SmallVectorTest.cpp\
    llvm/unittests/ADT/SparseBitVectorTest.cpp\
    llvm/unittests/ADT/StringMapTest.cpp\
    llvm/unittests/ADT/StringRefTest.cpp\
    llvm/unittests/ADT/TripleTest.cpp\
    llvm/unittests/ADT/TwineTest.cpp

llvmunittest_Support_CPPFLAGS=$(LLVM_INCLUDES) $(LLVM_DEFS) -I$(top_srcdir)/llvm/utils/unittest/googletest/include
#-Wno-variadic-macros
llvmunittest_Support_LDADD=libgoogletest.la libllvmcore.la libllvmsupport.la libllvmsystem.la
llvmunittest_Support_SOURCES=\
    llvm/unittests/Support/AllocatorTest.cpp\
    llvm/unittests/Support/ConstantRangeTest.cpp\
    llvm/unittests/Support/MathExtrasTest.cpp\
    llvm/unittests/Support/RegexTest.cpp\
    llvm/unittests/Support/TypeBuilderTest.cpp\
    llvm/unittests/Support/ValueHandleTest.cpp\
    llvm/unittests/Support/raw_ostream_test.cpp

llvmunittest_VMCore_CPPFLAGS=$(LLVM_INCLUDES) $(LLVM_DEFS) -I$(top_srcdir)/llvm/utils/unittest/googletest/include
#-Wno-variadic-macros
llvmunittest_VMCore_LDADD=libgoogletest.la libllvmtarget.la libllvmipa.la libllvmcore.la libllvmsupport.la libllvmsystem.la
llvmunittest_VMCore_SOURCES=\
    llvm/lib/Analysis/IPA/CallGraphSCCPass.cpp\
    llvm/unittests/VMCore/ConstantsTest.cpp\
    llvm/unittests/VMCore/MetadataTest.cpp\
    llvm/unittests/VMCore/PassManagerTest.cpp

llvmunittest_JIT_CPPFLAGS=$(LLVM_INCLUDES) $(LLVM_DEFS) -I$(top_srcdir)/llvm/utils/unittest/googletest/include
#-Wno-variadic-macros
llvmunittest_JIT_LDADD=libgoogletest.la libllvmasmparser.la $(libclamavcxx_la_LIBADD)
llvmunittest_JIT_SOURCES=\
    llvm/unittests/ExecutionEngine/JIT/JITEventListenerTest.cpp\
    llvm/unittests/ExecutionEngine/JIT/JITMemoryManagerTest.cpp\
    llvm/unittests/ExecutionEngine/JIT/JITTest.cpp

llvmunittest_ExecutionEngine_CPPFLAGS=$(LLVM_INCLUDES) $(LLVM_DEFS) -I$(top_srcdir)/llvm/utils/unittest/googletest/include
#-Wno-variadic-macros
llvmunittest_ExecutionEngine_LDADD=libgoogletest.la libllvminterpreter.la $(libclamavcxx_la_LIBADD)
llvmunittest_ExecutionEngine_SOURCES=\
    llvm/unittests/ExecutionEngine/ExecutionEngineTest.cpp

count_CPPFLAGS=$(LLVM_INCLUDES) $(LLVM_DEFS)
count_SOURCES=llvm/utils/count/count.c
count_LDADD=libllvmsystem.la
not_CPPFLAGS=$(LLVM_INCLUDES) $(LLVM_DEFS)
not_CXXFLAGS=$(LLVM_CXXFLAGS)
not_SOURCES=llvm/utils/not/not.cpp
not_LDADD=libllvmsystem.la

FileCheck_CPPFLAGS=$(LLVM_INCLUDES) $(LLVM_DEFS)
FileCheck_CXXFLAGS=$(LLVM_CXXFLAGS)
FileCheck_LDADD=libllvmsupport.la libllvmsystem.la 
FileCheck_SOURCES=llvm/utils/FileCheck/FileCheck.cpp

check_LTLIBRARIES=libllvmbitreader.la libllvmasmprinter.la libllvmbitwriter.la libllvmasmparser.la libgoogletest.la libllvminterpreter.la
check_PROGRAMS=count not lli llc llvm-as llvm-dis llvmunittest_ADT llvmunittest_Support llvmunittest_VMCore llvmunittest_ExecutionEngine llvmunittest_JIT FileCheck
check_SCRIPTS=llvmdejagnu.sh
TESTS_ENVIRONMENT=export GMAKE=@GMAKE@;
TESTS=llvmunittest_ADT llvmunittest_Support llvmunittest_VMCore llvmunittest_ExecutionEngine llvmunittest_JIT
# Disable LLVM make check for now, there are some things to fix first:
#   - check python version (2.4 doesn't work, needs 2.5+)
#   - run llvm's make check after clamav's was run
#   - have a way to run only clamav's make check and not llvm's
#@ifGNUmake@ TESTS+=llvmdejagnu.sh

libllvmasmprinter_la_CPPFLAGS=$(LLVM_INCLUDES) $(LLVM_DEFS) -I$(top_srcdir)/llvm/lib/Target/X86 \
			      -I$(top_srcdir)/llvm/lib/Target/PowerPC -I$(top_srcdir)/llvm/lib/Target/ARM
libllvmasmprinter_la_SOURCES=\
    llvm/lib/CodeGen/AsmPrinter/OcamlGCPrinter.cpp\
    llvm/lib/CodeGen/ELFCodeEmitter.cpp\
    llvm/lib/CodeGen/ELFWriter.cpp\
    llvm/lib/CodeGen/MachOCodeEmitter.cpp\
    llvm/lib/CodeGen/MachOWriter.cpp

if BUILD_X86
libllvmasmprinter_la_SOURCES+=llvm/lib/Target/X86/AsmPrinter/X86AsmPrinter.cpp\
    llvm/lib/Target/X86/AsmPrinter/X86ATTInstPrinter.cpp\
    llvm/lib/Target/X86/AsmPrinter/X86IntelInstPrinter.cpp\
    llvm/lib/Target/X86/AsmPrinter/X86AsmPrinter.cpp\
    llvm/lib/Target/X86/AsmPrinter/X86MCInstLower.cpp\
    llvm/lib/Target/X86/X86COFFMachineModuleInfo.cpp
endif

if BUILD_PPC
libllvmasmprinter_la_SOURCES+= llvm/lib/Target/PowerPC/AsmPrinter/PPCAsmPrinter.cpp
endif

if BUILD_ARM
libllvmasmprinter_la_SOURCES+= llvm/lib/Target/ARM/AsmPrinter/ARMAsmPrinter.cpp \
    llvm/lib/Target/ARM/AsmPrinter/ARMInstPrinter.cpp\
    llvm/lib/Target/ARM/AsmPrinter/ARMMCInstLower.cpp
endif

lli_CPPFLAGS=$(LLVM_INCLUDES) $(LLVM_DEFS)
lli_CXXFLAGS=$(LLVM_CXXFLAGS)
lli_LDADD=libllvmbitreader.la libllvminterpreter.la $(libclamavcxx_la_LIBADD)
lli_SOURCES=\
    llvm/lib/ExecutionEngine/JIT/OProfileJITEventListener.cpp\
    llvm/tools/lli/lli.cpp

llc_CPPFLAGS=$(LLVM_INCLUDES) $(LLVM_DEFS)
llc_CXXFLAGS=$(LLVM_CXXFLAGS)
llc_LDADD=libllvmbitreader.la libllvmasmparser.la libllvmasmprinter.la $(libclamavcxx_la_LIBADD)
llc_SOURCES=\
    llvm/lib/MC/MCInstPrinter.cpp\
    llvm/tools/llc/llc.cpp

llvm_as_CPPFLAGS=$(LLVM_INCLUDES) $(LLVM_DEFS)
llvm_as_CXXFLAGS=$(LLVM_CXXFLAGS)
llvm_as_LDADD=libllvmasmparser.la libllvmbitwriter.la libllvmcore.la libllvmsupport.la libllvmsystem.la
llvm_as_SOURCES=\
    llvm/tools/llvm-as/llvm-as.cpp

llvm_dis_CPPFLAGS=$(LLVM_INCLUDES) $(LLVM_DEFS)
llvm_dis_CXXFLAGS=$(LLVM_CXXFLAGS)
llvm_dis_LDADD=libllvmasmparser.la libllvmbitreader.la libllvmcore.la libllvmsupport.la libllvmsystem.la
llvm_dis_SOURCES=\
    llvm/tools/llvm-dis/llvm-dis.cpp

noinst_PROGRAMS = tblgen
#bytecode2llvm.cpp: build-llvm

build-llvm:
	+$(GMAKE) -C llvm OPTIMIZE_OPTION=-O2 libs-only

build-llvm-for-check:
	+$(GMAKE) -C llvm OPTIMIZE_OPTION=-O2 tools-only

# Don't use make -C here, otherwise there's a racecondition between distclean
# and clean (distclean removes all Makefiles in llvm/)
clean-local:
	rm -rf `find llvm/test -name Output -type d -print`
	rm -rf llvm/Release llvm/Debug
	rm -f *.inc
	rm -f llvm/include/llvm/Intrinsics.gen
	rm -f llvm/test/site.exp llvm/test/site.bak llvm/test/*.out llvm/test/*.sum llvm/test/*.log

distclean-local:
	rm -f llvm/lib/Makefile llvm/docs/doxygen.cfg llvm/test/Unit/.dir llvm/test/Unit/lit.site.cfg
	rm -f llvm/test/Makefile llvm/test/lit.site.cfg llvm/test/Makefile.tests llvm/Makefile llvm/config.status
	rm -f llvm/mklib llvm/tools/Makefile llvm/tools/llvmc/llvm-config.in llvm/utils/Makefile
	rm -f llvm/Makefile.common llvm/Makefile.config llvm/config.log llvm/unittests/Makefile
	rm -f llvm/llvm.spec llvm/include/llvm/Config/AsmPrinters.def llvm/include/llvm/Config/config.h
	rm -f llvm/include/llvm/Config/Disassemblers.def
	rm -f llvm/include/llvm/System/DataTypes.h llvm/include/llvm/Config/Targets.def
	rm -f llvm/tools/llvmc/plugins/Base/Base.td llvm/tools/llvm-config/llvm-config.in
	rm -f llvm/include/llvm/Config/AsmParsers.def

check-llvm: build-llvm-for-check
	+$(GMAKE) -C llvm check
	+$(GMAKE) -C llvm unittests

CONFIG_STATUS_DEPENDENCIES = $(top_builddir)/llvm/config.status
# config.status needs to be run twice, once without recheck so that it has a
# chance to create configure generated files.
$(top_builddir)/llvm/config.status: llvm/configure
	cd llvm; ./config.status --recheck; ./config.status

# rm configure generated files
dist-hook:
	make -C llvm dist-hook
	rm -f $(distdir)/llvm/include/llvm/Config/*.h $(distdir)/llvm/include/llvm/Config/*.def $(distdir)/llvm/Makefile.config $(distdir)/llvm/llvm.spec
	rm -f $(distdir)/llvm/docs/doxygen.cfg $(distdir)/llvm/tools/llvmc/plugins/Base/Base.td $(distdir)/llvm/tools/llvm-config/llvm-config.in
	rm -f $(distdir)/llvm/include/llvm/Intrinsics.gen
	rm -f $(distdir)/llvm/include/llvm/Support/DataTypes.h $(distdir)/llvm/config.log $(distdir)/llvm/config.status

