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
AM_CPPFLAGS = @SSL_CPPFLAGS@ -I$(top_srcdir)/../.. -I$(top_srcdir)/.. -I$(top_builddir)/../../
AM_CXXFLAGS = $(LLVM_CXXFLAGS) -fno-exceptions
ACLOCAL_AMFLAGS=-I m4

libclamavcxx_la_SOURCES = bytecode2llvm.cpp\
			  ClamBCRTChecks.cpp\
			  ClamBCModule.h\
			  ClamBCDiagnostics.h\
			  detect.cpp\
			  llvm30_compat.h
if BUILD_EXTERNAL_LLVM
#$(LLVM_CONFIG): build-llvm
# we know this will be built with GNU make, so its safe to use GNU make specific
# $(shell ...)
#LLVM_DEPS=$(shell $(LLVM_CONFIG) --libfiles jit nativecodegen)
libclamavcxx_la_CXXFLAGS = $(AM_CPPFLAGS) @LLVMCONFIG_CXXFLAGS@ -fexceptions -DLLVM_VERSION=${LLVM_VERSION}
libclamavcxx_la_LDFLAGS = @LLVMCONFIG_LDFLAGS@ @LLVMCONFIG_LIBS@ @LLVMCONFIG_LDFLAGS@
libclamavcxx_la_DEPENDENCIES = @LLVMCONFIG_LIBFILES@
noinst_LTLIBRARIES = libclamavcxx.la
libclamavcxx_la_SOURCES += PointerTracking.cpp
libclamavcxx_la_SOURCES += PointerTracking.h

else
AM_CPPFLAGS += $(LLVM_INCLUDES) $(LLVM_DEFS)
noinst_LTLIBRARIES = libclamavcxx.la libllvmsystem.la\
		     libllvmcodegen.la libllvmjit.la
libclamavcxx_la_LIBADD = libllvmjit.la
libclamavcxx_la_DEPENDENCIES = libllvmjit.la libllvmcodegen.la libllvmsystem.la
libclamavcxx_la_LDFLAGS = $(AM_LDFLAGS) -no-undefined
libclamavcxx_la_CXXFLAGS = $(LLVM_CXXFLAGS) -DLLVM_VERSION=${LLVM_VERSION}


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

libclamavcxx_la_LIBADD+=libllvmcodegen.la libllvmsystem.la

# crdaviso@cisco.com - Removed -pedantic from the following line to allow
# building on CentOS 5 (g++ 4.1.2). An openssl header file is included that
# includes a comma at the end of an enumerator list, which is valid in C99 but
# not C++98, so -pedantic produces an error and the build fails.
LLVM_CXXFLAGS=-Woverloaded-virtual -Wno-long-long -Wall -W -Wno-unused-parameter -Wwrite-strings
unittest_CXXFLAGS=@NO_VARIADIC_MACROS@ @NO_MISSING_FIELD_INITIALIZERS@ -DGTEST_HAS_TR1_TUPLE=0

TBLGENFILES=llvm/include/llvm/Intrinsics.gen X86GenRegisterInfo.h.inc X86GenRegisterNames.inc X86GenRegisterInfo.inc X86GenInstrNames.inc X86GenInstrInfo.inc\
    X86GenDAGISel.inc X86GenFastISel.inc X86GenCallingConv.inc\
    X86GenSubtarget.inc PPCGenInstrNames.inc PPCGenRegisterNames.inc PPCGenCodeEmitter.inc PPCGenRegisterInfo.h.inc PPCGenRegisterInfo.inc\
    PPCGenInstrInfo.inc PPCGenDAGISel.inc PPCGenCallingConv.inc PPCGenSubtarget.inc

BUILT_SOURCES=
EXTRA_DIST=$(top_srcdir)/llvm llvmcheck.sh $(TBLGENFILES)

libllvmsystem_la_LDFLAGS=@THREAD_LIBS@
libllvmsystem_la_LIBADD=
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
	llvm/lib/System/TimeValue.cpp\
	llvm/lib/System/Valgrind.cpp

if MAINTAINER_MODE
BUILT_SOURCES+=$(TBLGENFILES)
noinst_PROGRAMS = tblgen
tblgen_CXXFLAGS=$(LLVM_CXXFLAGS)
tblgen_CFLAGS=
#TODO: if VERSIONSCRIPT
tblgen_LDFLAGS=@THREAD_LIBS@ -Wl,--version-script,@top_srcdir@/llvm/autoconf/ExportMap.map
# tblgen needs rtti (for now), and we build everything else with -fno-rtti
# since tblgen is only a maintainer-mode tool, build these files twice (once for
# libllvmsupport.la -fno-rtti, and once here, with defaults (rtti)).
tblgen_SOURCES=\
    llvm/utils/TableGen/ARMDecoderEmitter.cpp\
    llvm/utils/TableGen/AsmMatcherEmitter.cpp\
    llvm/utils/TableGen/AsmWriterInst.cpp\
    llvm/utils/TableGen/CallingConvEmitter.cpp\
    llvm/utils/TableGen/ClangASTNodesEmitter.cpp\
    llvm/utils/TableGen/ClangAttrEmitter.cpp\
    llvm/utils/TableGen/ClangDiagnosticsEmitter.cpp\
    llvm/utils/TableGen/CodeEmitterGen.cpp\
    llvm/utils/TableGen/CodeGenDAGPatterns.cpp\
    llvm/utils/TableGen/CodeGenInstruction.cpp\
    llvm/utils/TableGen/CodeGenTarget.cpp\
    llvm/utils/TableGen/DAGISelEmitter.cpp\
    llvm/utils/TableGen/DAGISelMatcher.cpp\
    llvm/utils/TableGen/DAGISelMatcherEmitter.cpp\
    llvm/utils/TableGen/DAGISelMatcherGen.cpp\
    llvm/utils/TableGen/DAGISelMatcherOpt.cpp\
    llvm/utils/TableGen/EDEmitter.cpp\
    llvm/utils/TableGen/FastISelEmitter.cpp\
    llvm/utils/TableGen/InstrEnumEmitter.cpp\
    llvm/utils/TableGen/InstrInfoEmitter.cpp\
    llvm/utils/TableGen/IntrinsicEmitter.cpp\
    llvm/utils/TableGen/LLVMCConfigurationEmitter.cpp\
    llvm/utils/TableGen/NeonEmitter.cpp\
    llvm/utils/TableGen/OptParserEmitter.cpp\
    llvm/utils/TableGen/Record.cpp\
    llvm/utils/TableGen/RegisterInfoEmitter.cpp\
    llvm/utils/TableGen/SubtargetEmitter.cpp\
    llvm/utils/TableGen/TableGenBackend.cpp\
    llvm/utils/TableGen/TableGen.cpp\
    llvm/utils/TableGen/TGLexer.cpp\
    llvm/utils/TableGen/TGParser.cpp\
    llvm/utils/TableGen/TGValueTypes.cpp\
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
  llvm/lib/System/TimeValue.cpp\
  llvm/lib/System/Valgrind.cpp\
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
  llvm/lib/Support/SmallPtrSet.cpp\
  llvm/lib/Support/SmallVector.cpp\
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
  llvm/lib/Support/circular_raw_ostream.cpp\
  llvm/lib/Support/raw_os_ostream.cpp\
  llvm/lib/Support/raw_ostream.cpp\
  llvm/lib/Support/regcomp.c\
  llvm/lib/Support/regerror.c\
  llvm/lib/Support/regexec.c\
  llvm/lib/Support/regfree.c\
  llvm/lib/Support/regstrlcpy.c

TBLGEN=$(top_builddir)/tblgen
TBLGEN_V=$(AM_V_GEN)$(TBLGEN)
TBLGEN_FLAGS=-I$(top_srcdir)/llvm/include -I$(top_srcdir)/llvm/lib/Target -omit-comments

llvm/include/llvm/Intrinsics.gen: llvm/include/llvm/Intrinsics.td $(TBLGEN)
	$(TBLGEN_V) $(TBLGEN_FLAGS) -gen-intrinsic -o $@ $<

# X86 Target
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

X86GenDAGISel.inc: llvm/lib/Target/X86/X86.td $(TBLGEN)
	$(TBLGEN_V) $(TBLGEN_FLAGS_X86) -gen-dag-isel -o $@ $<

X86GenFastISel.inc: llvm/lib/Target/X86/X86.td $(TBLGEN)
	$(TBLGEN_V) $(TBLGEN_FLAGS_X86) -gen-fast-isel -o $@ $<

X86GenCallingConv.inc: llvm/lib/Target/X86/X86.td $(TBLGEN)
	$(TBLGEN_V) $(TBLGEN_FLAGS_X86) -gen-callingconv -o $@ $<

X86GenSubtarget.inc: llvm/lib/Target/X86/X86.td $(TBLGEN)
	$(TBLGEN_V) $(TBLGEN_FLAGS_X86) -gen-subtarget -o $@ $<

# PPC Target
TBLGEN_FLAGS_PPC= $(TBLGEN_FLAGS) -I$(top_srcdir)/llvm/lib/Target/PowerPC
PPCGenInstrNames.inc: llvm/lib/Target/PowerPC/PPC.td $(TBLGEN)
	$(TBLGEN_V) $(TBLGEN_FLAGS_PPC) -gen-instr-enums -o $@ $<

PPCGenRegisterNames.inc: llvm/lib/Target/PowerPC/PPC.td $(TBLGEN)
	$(TBLGEN_V) $(TBLGEN_FLAGS_PPC) -gen-register-enums -o $@ $<

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

endif

if BUILD_X86
libllvmx86codegen_la_CPPFLAGS=$(LLVM_INCLUDES) $(LLVM_DEFS) -I$(top_builddir) -I$(top_srcdir)/llvm/lib/Target/X86
libllvmx86codegen_la_SOURCES=\
	llvm/lib/MC/ELFObjectWriter.cpp\
	llvm/lib/MC/MCAsmInfoCOFF.cpp\
	llvm/lib/MC/MCCodeEmitter.cpp\
	llvm/lib/MC/MCELFStreamer.cpp\
	llvm/lib/MC/MCMachOStreamer.cpp\
	llvm/lib/MC/MCObjectStreamer.cpp\
	llvm/lib/MC/MCObjectWriter.cpp\
	llvm/lib/MC/MachObjectWriter.cpp\
	llvm/lib/MC/TargetAsmBackend.cpp\
	llvm/lib/MC/WinCOFFObjectWriter.cpp\
	llvm/lib/MC/WinCOFFStreamer.cpp\
	llvm/lib/Target/TargetELFWriterInfo.cpp\
	llvm/lib/Target/X86/SSEDomainFix.cpp\
	llvm/lib/Target/X86/TargetInfo/X86TargetInfo.cpp\
	llvm/lib/Target/X86/X86AsmBackend.cpp\
	llvm/lib/Target/X86/X86COFFMachineModuleInfo.cpp\
	llvm/lib/Target/X86/X86CodeEmitter.cpp\
	llvm/lib/Target/X86/X86ELFWriterInfo.cpp\
	llvm/lib/Target/X86/X86FastISel.cpp\
	llvm/lib/Target/X86/X86FloatingPoint.cpp\
	llvm/lib/Target/X86/X86ISelDAGToDAG.cpp\
	llvm/lib/Target/X86/X86ISelLowering.cpp\
	llvm/lib/Target/X86/X86InstrInfo.cpp\
	llvm/lib/Target/X86/X86JITInfo.cpp\
	llvm/lib/Target/X86/X86MCAsmInfo.cpp\
	llvm/lib/Target/X86/X86MCCodeEmitter.cpp\
	llvm/lib/Target/X86/X86RegisterInfo.cpp\
	llvm/lib/Target/X86/X86SelectionDAGInfo.cpp\
	llvm/lib/Target/X86/X86Subtarget.cpp\
	llvm/lib/Target/X86/X86TargetMachine.cpp\
	llvm/lib/Target/X86/X86TargetObjectFile.cpp
endif

if BUILD_PPC
libllvmpowerpccodegen_la_CPPFLAGS=$(LLVM_INCLUDES) $(LLVM_DEFS) -I$(top_builddir) -I$(top_srcdir)/llvm/lib/Target/PowerPC
libllvmpowerpccodegen_la_SOURCES=\
	llvm/lib/Target/PowerPC/PPCBranchSelector.cpp\
	llvm/lib/Target/PowerPC/PPCCodeEmitter.cpp\
	llvm/lib/Target/PowerPC/PPCHazardRecognizers.cpp\
	llvm/lib/Target/PowerPC/PPCISelDAGToDAG.cpp\
	llvm/lib/Target/PowerPC/PPCISelLowering.cpp\
	llvm/lib/Target/PowerPC/PPCInstrInfo.cpp\
	llvm/lib/Target/PowerPC/PPCJITInfo.cpp\
	llvm/lib/Target/PowerPC/PPCMCAsmInfo.cpp\
	llvm/lib/Target/PowerPC/PPCPredicates.cpp\
	llvm/lib/Target/PowerPC/PPCRegisterInfo.cpp\
	llvm/lib/Target/PowerPC/PPCSelectionDAGInfo.cpp\
	llvm/lib/Target/PowerPC/PPCSubtarget.cpp\
	llvm/lib/Target/PowerPC/PPCTargetMachine.cpp\
	llvm/lib/Target/PowerPC/TargetInfo/PowerPCTargetInfo.cpp
endif

# End of Targets

libllvmjit_la_SOURCES=\
	llvm/lib/Analysis/AliasAnalysis.cpp\
	llvm/lib/Analysis/AliasSetTracker.cpp\
	llvm/lib/Analysis/BasicAliasAnalysis.cpp\
	llvm/lib/Analysis/CaptureTracking.cpp\
	llvm/lib/Analysis/DebugInfo.cpp\
	llvm/lib/Analysis/IPA/CallGraph.cpp\
	llvm/lib/Analysis/MemoryBuiltins.cpp\
	llvm/lib/Analysis/PointerTracking.cpp\
	llvm/lib/Analysis/ProfileInfo.cpp\
	llvm/lib/Analysis/ValueTracking.cpp\
	llvm/lib/CodeGen/ELFCodeEmitter.cpp\
	llvm/lib/CodeGen/ELFWriter.cpp\
	llvm/lib/CodeGen/LiveVariables.cpp\
	llvm/lib/CodeGen/MachineBasicBlock.cpp\
	llvm/lib/CodeGen/MachineDominators.cpp\
	llvm/lib/CodeGen/MachineFunction.cpp\
	llvm/lib/CodeGen/MachineFunctionAnalysis.cpp\
	llvm/lib/CodeGen/MachineFunctionPass.cpp\
	llvm/lib/CodeGen/MachineFunctionPrinterPass.cpp\
	llvm/lib/CodeGen/MachineInstr.cpp\
	llvm/lib/CodeGen/MachineLoopInfo.cpp\
	llvm/lib/CodeGen/MachineModuleInfo.cpp\
	llvm/lib/CodeGen/MachineRegisterInfo.cpp\
	llvm/lib/CodeGen/ObjectCodeEmitter.cpp\
	llvm/lib/CodeGen/PostRAHazardRecognizer.cpp\
	llvm/lib/CodeGen/PseudoSourceValue.cpp\
	llvm/lib/CodeGen/ScheduleDAG.cpp\
	llvm/lib/CodeGen/TargetInstrInfoImpl.cpp\
	llvm/lib/CodeGen/UnreachableBlockElim.cpp\
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
	llvm/lib/MC/MCAssembler.cpp\
	llvm/lib/MC/MCContext.cpp\
	llvm/lib/MC/MCExpr.cpp\
	llvm/lib/MC/MCInst.cpp\
	llvm/lib/MC/MCSection.cpp\
	llvm/lib/MC/MCSectionCOFF.cpp\
	llvm/lib/MC/MCSectionELF.cpp\
	llvm/lib/MC/MCSectionMachO.cpp\
	llvm/lib/MC/MCSymbol.cpp\
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
	llvm/lib/Support/SmallVector.cpp\
	llvm/lib/Support/SourceMgr.cpp\
	llvm/lib/Support/Statistic.cpp\
	llvm/lib/Support/StringExtras.cpp\
	llvm/lib/Support/StringMap.cpp\
	llvm/lib/Support/StringPool.cpp\
	llvm/lib/Support/StringRef.cpp\
	llvm/lib/Support/TargetRegistry.cpp\
	llvm/lib/Support/Timer.cpp\
	llvm/lib/Support/Triple.cpp\
	llvm/lib/Support/Twine.cpp\
	llvm/lib/Support/raw_ostream.cpp\
	llvm/lib/Support/circular_raw_ostream.cpp\
	llvm/lib/Target/Mangler.cpp\
	llvm/lib/Target/SubtargetFeature.cpp\
	llvm/lib/Target/TargetData.cpp\
	llvm/lib/Target/TargetInstrInfo.cpp\
	llvm/lib/Target/TargetLoweringObjectFile.cpp\
	llvm/lib/Target/TargetMachine.cpp\
	llvm/lib/Target/TargetRegisterInfo.cpp\
	llvm/lib/Transforms/Scalar/DCE.cpp\
	llvm/lib/Transforms/Scalar/SimplifyCFGPass.cpp\
	llvm/lib/VMCore/AsmWriter.cpp\
	llvm/lib/VMCore/Attributes.cpp\
	llvm/lib/VMCore/AutoUpgrade.cpp\
	llvm/lib/VMCore/BasicBlock.cpp\
	llvm/lib/VMCore/ConstantFold.cpp\
	llvm/lib/VMCore/Constants.cpp\
	llvm/lib/VMCore/Core.cpp\
	llvm/lib/VMCore/DebugLoc.cpp\
	llvm/lib/VMCore/Dominators.cpp\
	llvm/lib/VMCore/Function.cpp\
	llvm/lib/VMCore/GVMaterializer.cpp\
	llvm/lib/VMCore/Globals.cpp\
	llvm/lib/VMCore/IRBuilder.cpp\
	llvm/lib/VMCore/InlineAsm.cpp\
	llvm/lib/VMCore/Instruction.cpp\
	llvm/lib/VMCore/Instructions.cpp\
	llvm/lib/VMCore/IntrinsicInst.cpp\
	llvm/lib/VMCore/LLVMContext.cpp\
	llvm/lib/VMCore/LLVMContextImpl.cpp\
	llvm/lib/VMCore/LeakDetector.cpp\
	llvm/lib/VMCore/Metadata.cpp\
	llvm/lib/VMCore/Module.cpp\
	llvm/lib/VMCore/Pass.cpp\
	llvm/lib/VMCore/PassManager.cpp\
	llvm/lib/VMCore/PassRegistry.cpp\
	llvm/lib/VMCore/PrintModulePass.cpp\
	llvm/lib/VMCore/Type.cpp\
	llvm/lib/VMCore/TypeSymbolTable.cpp\
	llvm/lib/VMCore/Use.cpp\
	llvm/lib/VMCore/Value.cpp\
	llvm/lib/VMCore/ValueSymbolTable.cpp\
	llvm/lib/VMCore/ValueTypes.cpp\
	llvm/lib/VMCore/Verifier.cpp

libllvmcodegen_la_SOURCES=\
	llvm/lib/Analysis/ConstantFolding.cpp\
	llvm/lib/Analysis/IVUsers.cpp\
	llvm/lib/Analysis/InstructionSimplify.cpp\
	llvm/lib/Analysis/Loads.cpp\
	llvm/lib/Analysis/LoopInfo.cpp\
	llvm/lib/Analysis/LoopPass.cpp\
	llvm/lib/Analysis/MemoryDependenceAnalysis.cpp\
	llvm/lib/Analysis/PHITransAddr.cpp\
	llvm/lib/Analysis/ScalarEvolution.cpp\
	llvm/lib/Analysis/ScalarEvolutionExpander.cpp\
	llvm/lib/Analysis/ScalarEvolutionNormalization.cpp\
	llvm/lib/CodeGen/AggressiveAntiDepBreaker.cpp\
	llvm/lib/CodeGen/Analysis.cpp\
	llvm/lib/CodeGen/BranchFolding.cpp\
	llvm/lib/CodeGen/CalcSpillWeights.cpp\
	llvm/lib/CodeGen/CallingConvLower.cpp\
	llvm/lib/CodeGen/CodePlacementOpt.cpp\
	llvm/lib/CodeGen/CriticalAntiDepBreaker.cpp\
	llvm/lib/CodeGen/DeadMachineInstructionElim.cpp\
	llvm/lib/CodeGen/DwarfEHPrepare.cpp\
	llvm/lib/CodeGen/GCMetadata.cpp\
	llvm/lib/CodeGen/GCStrategy.cpp\
	llvm/lib/CodeGen/InlineSpiller.cpp\
	llvm/lib/CodeGen/LLVMTargetMachine.cpp\
	llvm/lib/CodeGen/LatencyPriorityQueue.cpp\
	llvm/lib/CodeGen/LiveInterval.cpp\
	llvm/lib/CodeGen/LiveIntervalAnalysis.cpp\
	llvm/lib/CodeGen/LiveStackAnalysis.cpp\
	llvm/lib/CodeGen/LocalStackSlotAllocation.cpp\
	llvm/lib/CodeGen/LowerSubregs.cpp\
	llvm/lib/CodeGen/MachineCSE.cpp\
	llvm/lib/CodeGen/MachineLICM.cpp\
	llvm/lib/CodeGen/MachineModuleInfoImpls.cpp\
	llvm/lib/CodeGen/MachinePassRegistry.cpp\
	llvm/lib/CodeGen/MachineSSAUpdater.cpp\
	llvm/lib/CodeGen/MachineSink.cpp\
	llvm/lib/CodeGen/MachineVerifier.cpp\
	llvm/lib/CodeGen/OptimizePHIs.cpp\
	llvm/lib/CodeGen/PHIElimination.cpp\
	llvm/lib/CodeGen/Passes.cpp\
	llvm/lib/CodeGen/PeepholeOptimizer.cpp\
	llvm/lib/CodeGen/PostRASchedulerList.cpp\
	llvm/lib/CodeGen/PreAllocSplitting.cpp\
	llvm/lib/CodeGen/ProcessImplicitDefs.cpp\
	llvm/lib/CodeGen/PrologEpilogInserter.cpp\
	llvm/lib/CodeGen/RegAllocFast.cpp\
	llvm/lib/CodeGen/RegAllocLinearScan.cpp\
	llvm/lib/CodeGen/RegisterCoalescer.cpp\
	llvm/lib/CodeGen/RegisterScavenging.cpp\
	llvm/lib/CodeGen/ScheduleDAGEmit.cpp\
	llvm/lib/CodeGen/ScheduleDAGInstrs.cpp\
	llvm/lib/CodeGen/SelectionDAG/DAGCombiner.cpp\
	llvm/lib/CodeGen/SelectionDAG/FastISel.cpp\
	llvm/lib/CodeGen/SelectionDAG/FunctionLoweringInfo.cpp\
	llvm/lib/CodeGen/SelectionDAG/InstrEmitter.cpp\
	llvm/lib/CodeGen/SelectionDAG/LegalizeDAG.cpp\
	llvm/lib/CodeGen/SelectionDAG/LegalizeFloatTypes.cpp\
	llvm/lib/CodeGen/SelectionDAG/LegalizeIntegerTypes.cpp\
	llvm/lib/CodeGen/SelectionDAG/LegalizeTypes.cpp\
	llvm/lib/CodeGen/SelectionDAG/LegalizeTypesGeneric.cpp\
	llvm/lib/CodeGen/SelectionDAG/LegalizeVectorOps.cpp\
	llvm/lib/CodeGen/SelectionDAG/LegalizeVectorTypes.cpp\
	llvm/lib/CodeGen/SelectionDAG/ScheduleDAGList.cpp\
	llvm/lib/CodeGen/SelectionDAG/ScheduleDAGRRList.cpp\
	llvm/lib/CodeGen/SelectionDAG/ScheduleDAGSDNodes.cpp\
	llvm/lib/CodeGen/SelectionDAG/SelectionDAG.cpp\
	llvm/lib/CodeGen/SelectionDAG/SelectionDAGBuilder.cpp\
	llvm/lib/CodeGen/SelectionDAG/SelectionDAGISel.cpp\
	llvm/lib/CodeGen/SelectionDAG/SelectionDAGPrinter.cpp\
	llvm/lib/CodeGen/SelectionDAG/TargetLowering.cpp\
	llvm/lib/CodeGen/SelectionDAG/TargetSelectionDAGInfo.cpp\
	llvm/lib/CodeGen/ScheduleDAGPrinter.cpp\
	llvm/lib/CodeGen/ShrinkWrapping.cpp\
	llvm/lib/CodeGen/SimpleRegisterCoalescing.cpp\
	llvm/lib/CodeGen/SjLjEHPrepare.cpp\
	llvm/lib/CodeGen/SlotIndexes.cpp\
	llvm/lib/CodeGen/Spiller.cpp\
	llvm/lib/CodeGen/SplitKit.cpp\
	llvm/lib/CodeGen/StackProtector.cpp\
	llvm/lib/CodeGen/StackSlotColoring.cpp\
	llvm/lib/CodeGen/StrongPHIElimination.cpp\
	llvm/lib/CodeGen/TailDuplication.cpp\
	llvm/lib/CodeGen/TargetLoweringObjectFileImpl.cpp\
	llvm/lib/CodeGen/TwoAddressInstructionPass.cpp\
	llvm/lib/CodeGen/VirtRegMap.cpp\
	llvm/lib/CodeGen/VirtRegRewriter.cpp\
	llvm/lib/MC/MCAsmInfoDarwin.cpp\
	llvm/lib/MC/MCAsmStreamer.cpp\
	llvm/lib/MC/MCInstPrinter.cpp\
	llvm/lib/MC/MCLoggingStreamer.cpp\
	llvm/lib/MC/MCNullStreamer.cpp\
	llvm/lib/MC/MCStreamer.cpp\
	llvm/lib/Support/GraphWriter.cpp\
	llvm/lib/Target/TargetFrameInfo.cpp\
	llvm/lib/Target/TargetSubtarget.cpp\
	llvm/lib/Transforms/IPO/ConstantMerge.cpp\
	llvm/lib/Transforms/IPO/GlobalOpt.cpp\
	llvm/lib/Transforms/Scalar/CodeGenPrepare.cpp\
	llvm/lib/Transforms/Scalar/GEPSplitter.cpp\
	llvm/lib/Transforms/Scalar/GVN.cpp\
	llvm/lib/Transforms/Scalar/LoopStrengthReduce.cpp\
	llvm/lib/Transforms/Scalar/SCCP.cpp\
	llvm/lib/Transforms/Utils/AddrModeMatcher.cpp\
	llvm/lib/Transforms/Utils/BasicBlockUtils.cpp\
	llvm/lib/Transforms/Utils/BreakCriticalEdges.cpp\
	llvm/lib/Transforms/Utils/BuildLibCalls.cpp\
	llvm/lib/Transforms/Utils/DemoteRegToStack.cpp\
	llvm/lib/Transforms/Utils/LCSSA.cpp\
	llvm/lib/Transforms/Utils/Local.cpp\
	llvm/lib/Transforms/Utils/LoopSimplify.cpp\
	llvm/lib/Transforms/Utils/LowerInvoke.cpp\
	llvm/lib/Transforms/Utils/LowerSwitch.cpp\
	llvm/lib/Transforms/Utils/Mem2Reg.cpp\
	llvm/lib/Transforms/Utils/PromoteMemoryToRegister.cpp\
	llvm/lib/Transforms/Utils/SSAUpdater.cpp\
	llvm/lib/Transforms/Utils/SimplifyCFG.cpp\
	llvm/lib/Transforms/Utils/UnifyFunctionExitNodes.cpp

# Don't use make -C here, otherwise there's a racecondition between distclean
# and clean (distclean removes all Makefiles in llvm/)
clean-local:
	rm -rf `find llvm/test -name Output -type d -print`
	rm -rf llvm/Release llvm/Debug
if MAINTAINER_MODE
	rm -f *.inc
	rm -f llvm/include/llvm/Intrinsics.gen
endif
	rm -f llvm/test/site.exp llvm/test/site.bak llvm/test/*.out llvm/test/*.sum llvm/test/*.log
	rm -f $(top_srcdir)/llvm/utils/lit/lit/*.pyc

distclean-local:
	rm -f llvm/docs/doxygen.cfg llvm/test/Unit/.dir llvm/test/Unit/lit.site.cfg
	rm -f llvm/test/lit.site.cfg llvm/config.status
	rm -f llvm/mklib llvm/tools/llvmc/llvm-config.in
	rm -f llvm/Makefile.config llvm/config.log
	rm -f llvm/llvm.spec llvm/include/llvm/Config/AsmPrinters.def llvm/include/llvm/Config/config.h
	rm -f llvm/include/llvm/Config/Disassemblers.def llvm/include/llvm/Config/llvm-config.h
	rm -f llvm/include/llvm/System/DataTypes.h llvm/include/llvm/Config/Targets.def
	rm -f llvm/tools/llvmc/plugins/Base/Base.td llvm/tools/llvm-config/llvm-config.in
	rm -f llvm/include/llvm/Config/AsmParsers.def
	if test $(abs_srcdir) != $(abs_builddir); then\
	    rm -f llvm/Makefile llvm/lib/Makefile llvm/test/Makefile\
	    llvm/test/Makefile.tests llvm/tools/Makefile llvm/utils/Makefile\
	    llvm/Makefile.common llvm/unittests/Makefile;\
	fi

# Rule to rerun LLVM's configure if it changed, before building anything else
# LLVM
BUILT_SOURCES += llvm/config.status
libllvmsystem_la_SOURCES += llvm/config.status
$(top_builddir)/llvm/config.status: llvm/configure
	(cd llvm; ./config.status --recheck; ./config.status)

endif
# rm configure generated files
dist-hook: clean-local
	$(MAKE) -C llvm dist-hook
	rm -f $(distdir)/llvm/include/llvm/Config/*.h $(distdir)/llvm/include/llvm/Config/*.def $(distdir)/llvm/Makefile.config $(distdir)/llvm/llvm.spec
	rm -f $(distdir)/llvm/docs/doxygen.cfg $(distdir)/llvm/tools/llvmc/plugins/Base/Base.td $(distdir)/llvm/tools/llvm-config/llvm-config.in
	rm -f $(distdir)/llvm/include/llvm/System/DataTypes.h $(distdir)/llvm/config.log $(distdir)/llvm/config.status
