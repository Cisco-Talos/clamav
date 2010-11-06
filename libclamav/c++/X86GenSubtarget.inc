//===- TableGen'erated file -------------------------------------*- C++ -*-===//
//
// Subtarget Enumeration Source Fragment
//
// Automatically generated file, do not edit!
//
//===----------------------------------------------------------------------===//

#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Target/SubtargetFeature.h"
#include "llvm/Target/TargetInstrItineraries.h"

enum {
  Feature3DNow =  1 << 0,
  Feature3DNowA =  1 << 1,
  Feature64Bit =  1 << 2,
  FeatureAES =  1 << 3,
  FeatureAVX =  1 << 4,
  FeatureCLMUL =  1 << 5,
  FeatureCMOV =  1 << 6,
  FeatureFMA3 =  1 << 7,
  FeatureFMA4 =  1 << 8,
  FeatureFastUAMem =  1 << 9,
  FeatureMMX =  1 << 10,
  FeatureSSE1 =  1 << 11,
  FeatureSSE2 =  1 << 12,
  FeatureSSE3 =  1 << 13,
  FeatureSSE41 =  1 << 14,
  FeatureSSE42 =  1 << 15,
  FeatureSSE4A =  1 << 16,
  FeatureSSSE3 =  1 << 17,
  FeatureSlowBTMem =  1 << 18,
  FeatureVectorUAMem =  1 << 19
};

// Sorted (by key) array of values for CPU features.
static const llvm::SubtargetFeatureKV FeatureKV[] = {
  { "3dnow", "Enable 3DNow! instructions", Feature3DNow, 0 },
  { "3dnowa", "Enable 3DNow! Athlon instructions", Feature3DNowA, Feature3DNow },
  { "64bit", "Support 64-bit instructions", Feature64Bit, FeatureCMOV },
  { "aes", "Enable AES instructions", FeatureAES, 0 },
  { "avx", "Enable AVX instructions", FeatureAVX, 0 },
  { "clmul", "Enable carry-less multiplication instructions", FeatureCLMUL, 0 },
  { "cmov", "Enable conditional move instructions", FeatureCMOV, 0 },
  { "fast-unaligned-mem", "Fast unaligned memory access", FeatureFastUAMem, 0 },
  { "fma3", "Enable three-operand fused multiple-add", FeatureFMA3, 0 },
  { "fma4", "Enable four-operand fused multiple-add", FeatureFMA4, 0 },
  { "mmx", "Enable MMX instructions", FeatureMMX, 0 },
  { "slow-bt-mem", "Bit testing of memory is slow", FeatureSlowBTMem, 0 },
  { "sse", "Enable SSE instructions", FeatureSSE1, FeatureMMX | FeatureCMOV },
  { "sse2", "Enable SSE2 instructions", FeatureSSE2, FeatureSSE1 },
  { "sse3", "Enable SSE3 instructions", FeatureSSE3, FeatureSSE2 },
  { "sse41", "Enable SSE 4.1 instructions", FeatureSSE41, FeatureSSSE3 },
  { "sse42", "Enable SSE 4.2 instructions", FeatureSSE42, FeatureSSE41 },
  { "sse4a", "Support SSE 4a instructions", FeatureSSE4A, 0 },
  { "ssse3", "Enable SSSE3 instructions", FeatureSSSE3, FeatureSSE3 },
  { "vector-unaligned-mem", "Allow unaligned memory operands on vector/SIMD instructions", FeatureVectorUAMem, 0 }
};

enum {
  FeatureKVSize = sizeof(FeatureKV)/sizeof(llvm::SubtargetFeatureKV)
};

// Sorted (by key) array of values for CPU subtype.
static const llvm::SubtargetFeatureKV SubTypeKV[] = {
  { "amdfam10", "Select the amdfam10 processor", FeatureSSE3 | FeatureSSE4A | Feature3DNowA | Feature64Bit | FeatureSlowBTMem, 0 },
  { "athlon", "Select the athlon processor", FeatureMMX | Feature3DNowA | FeatureSlowBTMem, 0 },
  { "athlon-4", "Select the athlon-4 processor", FeatureSSE1 | Feature3DNowA | FeatureSlowBTMem, 0 },
  { "athlon-fx", "Select the athlon-fx processor", FeatureSSE2 | Feature3DNowA | Feature64Bit | FeatureSlowBTMem, 0 },
  { "athlon-mp", "Select the athlon-mp processor", FeatureSSE1 | Feature3DNowA | FeatureSlowBTMem, 0 },
  { "athlon-tbird", "Select the athlon-tbird processor", FeatureMMX | Feature3DNowA | FeatureSlowBTMem, 0 },
  { "athlon-xp", "Select the athlon-xp processor", FeatureSSE1 | Feature3DNowA | FeatureSlowBTMem, 0 },
  { "athlon64", "Select the athlon64 processor", FeatureSSE2 | Feature3DNowA | Feature64Bit | FeatureSlowBTMem, 0 },
  { "athlon64-sse3", "Select the athlon64-sse3 processor", FeatureSSE3 | Feature3DNowA | Feature64Bit | FeatureSlowBTMem, 0 },
  { "atom", "Select the atom processor", FeatureSSE3 | Feature64Bit | FeatureSlowBTMem, 0 },
  { "barcelona", "Select the barcelona processor", FeatureSSE3 | FeatureSSE4A | Feature3DNowA | Feature64Bit | FeatureSlowBTMem, 0 },
  { "c3", "Select the c3 processor", FeatureMMX | Feature3DNow, 0 },
  { "c3-2", "Select the c3-2 processor", FeatureSSE1, 0 },
  { "core2", "Select the core2 processor", FeatureSSSE3 | Feature64Bit | FeatureSlowBTMem, 0 },
  { "corei7", "Select the corei7 processor", FeatureSSE42 | Feature64Bit | FeatureSlowBTMem | FeatureFastUAMem | FeatureAES, 0 },
  { "generic", "Select the generic processor", 0, 0 },
  { "i386", "Select the i386 processor", 0, 0 },
  { "i486", "Select the i486 processor", 0, 0 },
  { "i586", "Select the i586 processor", 0, 0 },
  { "i686", "Select the i686 processor", 0, 0 },
  { "istanbul", "Select the istanbul processor", Feature3DNowA | Feature64Bit | FeatureSSE4A | Feature3DNowA, 0 },
  { "k6", "Select the k6 processor", FeatureMMX, 0 },
  { "k6-2", "Select the k6-2 processor", FeatureMMX | Feature3DNow, 0 },
  { "k6-3", "Select the k6-3 processor", FeatureMMX | Feature3DNow, 0 },
  { "k8", "Select the k8 processor", FeatureSSE2 | Feature3DNowA | Feature64Bit | FeatureSlowBTMem, 0 },
  { "k8-sse3", "Select the k8-sse3 processor", FeatureSSE3 | Feature3DNowA | Feature64Bit | FeatureSlowBTMem, 0 },
  { "nehalem", "Select the nehalem processor", FeatureSSE42 | Feature64Bit | FeatureSlowBTMem | FeatureFastUAMem, 0 },
  { "nocona", "Select the nocona processor", FeatureSSE3 | Feature64Bit | FeatureSlowBTMem, 0 },
  { "opteron", "Select the opteron processor", FeatureSSE2 | Feature3DNowA | Feature64Bit | FeatureSlowBTMem, 0 },
  { "opteron-sse3", "Select the opteron-sse3 processor", FeatureSSE3 | Feature3DNowA | Feature64Bit | FeatureSlowBTMem, 0 },
  { "penryn", "Select the penryn processor", FeatureSSE41 | Feature64Bit | FeatureSlowBTMem, 0 },
  { "pentium", "Select the pentium processor", 0, 0 },
  { "pentium-m", "Select the pentium-m processor", FeatureSSE2 | FeatureSlowBTMem, 0 },
  { "pentium-mmx", "Select the pentium-mmx processor", FeatureMMX, 0 },
  { "pentium2", "Select the pentium2 processor", FeatureMMX | FeatureCMOV, 0 },
  { "pentium3", "Select the pentium3 processor", FeatureSSE1, 0 },
  { "pentium4", "Select the pentium4 processor", FeatureSSE2, 0 },
  { "pentiumpro", "Select the pentiumpro processor", FeatureCMOV, 0 },
  { "prescott", "Select the prescott processor", FeatureSSE3 | FeatureSlowBTMem, 0 },
  { "sandybridge", "Select the sandybridge processor", FeatureSSE42 | FeatureAVX | Feature64Bit, 0 },
  { "shanghai", "Select the shanghai processor", Feature3DNowA | Feature64Bit | FeatureSSE4A | Feature3DNowA, 0 },
  { "westmere", "Select the westmere processor", FeatureSSE42 | Feature64Bit | FeatureSlowBTMem | FeatureFastUAMem | FeatureAES, 0 },
  { "winchip-c6", "Select the winchip-c6 processor", FeatureMMX, 0 },
  { "winchip2", "Select the winchip2 processor", FeatureMMX | Feature3DNow, 0 },
  { "x86-64", "Select the x86-64 processor", FeatureSSE2 | Feature64Bit | FeatureSlowBTMem, 0 },
  { "yonah", "Select the yonah processor", FeatureSSE3 | FeatureSlowBTMem, 0 }
};

enum {
  SubTypeKVSize = sizeof(SubTypeKV)/sizeof(llvm::SubtargetFeatureKV)
};


enum {
  ItinClassesSize = 1
};

// ParseSubtargetFeatures - Parses features string setting specified
// subtarget options.
std::string llvm::X86Subtarget::ParseSubtargetFeatures(const std::string &FS,
                                  const std::string &CPU) {
  DEBUG(dbgs() << "\nFeatures:" << FS);
  DEBUG(dbgs() << "\nCPU:" << CPU);
  SubtargetFeatures Features(FS);
  Features.setCPUIfNone(CPU);
  uint32_t Bits =  Features.getBits(SubTypeKV, SubTypeKVSize,
                                    FeatureKV, FeatureKVSize);
  if ((Bits & Feature3DNow) != 0 && X863DNowLevel < ThreeDNow) X863DNowLevel = ThreeDNow;
  if ((Bits & Feature3DNowA) != 0 && X863DNowLevel < ThreeDNowA) X863DNowLevel = ThreeDNowA;
  if ((Bits & Feature64Bit) != 0) HasX86_64 = true;
  if ((Bits & FeatureAES) != 0) HasAES = true;
  if ((Bits & FeatureAVX) != 0) HasAVX = true;
  if ((Bits & FeatureCLMUL) != 0) HasCLMUL = true;
  if ((Bits & FeatureCMOV) != 0) HasCMov = true;
  if ((Bits & FeatureFMA3) != 0) HasFMA3 = true;
  if ((Bits & FeatureFMA4) != 0) HasFMA4 = true;
  if ((Bits & FeatureFastUAMem) != 0) IsUAMemFast = true;
  if ((Bits & FeatureMMX) != 0 && X86SSELevel < MMX) X86SSELevel = MMX;
  if ((Bits & FeatureSSE1) != 0 && X86SSELevel < SSE1) X86SSELevel = SSE1;
  if ((Bits & FeatureSSE2) != 0 && X86SSELevel < SSE2) X86SSELevel = SSE2;
  if ((Bits & FeatureSSE3) != 0 && X86SSELevel < SSE3) X86SSELevel = SSE3;
  if ((Bits & FeatureSSE41) != 0 && X86SSELevel < SSE41) X86SSELevel = SSE41;
  if ((Bits & FeatureSSE42) != 0 && X86SSELevel < SSE42) X86SSELevel = SSE42;
  if ((Bits & FeatureSSE4A) != 0) HasSSE4A = true;
  if ((Bits & FeatureSSSE3) != 0 && X86SSELevel < SSSE3) X86SSELevel = SSSE3;
  if ((Bits & FeatureSlowBTMem) != 0) IsBTMemSlow = true;
  if ((Bits & FeatureVectorUAMem) != 0) HasVectorUAMem = true;
  return Features.getCPU();
}
