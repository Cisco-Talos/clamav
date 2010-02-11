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
  BPU =  1 << 0,
  FPU1 =  1 << 1,
  FPU2 =  1 << 2,
  IU1 =  1 << 3,
  IU2 =  1 << 4,
  IU3 =  1 << 5,
  IU4 =  1 << 6,
  SLU =  1 << 7,
  SRU =  1 << 8,
  VFPU =  1 << 9,
  VIU1 =  1 << 10,
  VIU2 =  1 << 11,
  VPU =  1 << 12
};

enum {
  Directive32 =  1 << 0,
  Directive601 =  1 << 1,
  Directive602 =  1 << 2,
  Directive603 =  1 << 3,
  Directive604 =  1 << 4,
  Directive620 =  1 << 5,
  Directive64 =  1 << 6,
  Directive7400 =  1 << 7,
  Directive750 =  1 << 8,
  Directive970 =  1 << 9,
  Feature64Bit =  1 << 10,
  Feature64BitRegs =  1 << 11,
  FeatureAltivec =  1 << 12,
  FeatureFSqrt =  1 << 13,
  FeatureGPUL =  1 << 14,
  FeatureSTFIWX =  1 << 15
};

// Sorted (by key) array of values for CPU features.
static const llvm::SubtargetFeatureKV FeatureKV[] = {
  { "64bit", "Enable 64-bit instructions", Feature64Bit, 0 },
  { "64bitregs", "Enable 64-bit registers usage for ppc32 [beta]", Feature64BitRegs, 0 },
  { "altivec", "Enable Altivec instructions", FeatureAltivec, 0 },
  { "fsqrt", "Enable the fsqrt instruction", FeatureFSqrt, 0 },
  { "gpul", "Enable GPUL instructions", FeatureGPUL, 0 },
  { "stfiwx", "Enable the stfiwx instruction", FeatureSTFIWX, 0 }
};

enum {
  FeatureKVSize = sizeof(FeatureKV)/sizeof(llvm::SubtargetFeatureKV)
};

// Sorted (by key) array of values for CPU subtype.
static const llvm::SubtargetFeatureKV SubTypeKV[] = {
  { "601", "Select the 601 processor", Directive601, 0 },
  { "602", "Select the 602 processor", Directive602, 0 },
  { "603", "Select the 603 processor", Directive603, 0 },
  { "603e", "Select the 603e processor", Directive603, 0 },
  { "603ev", "Select the 603ev processor", Directive603, 0 },
  { "604", "Select the 604 processor", Directive604, 0 },
  { "604e", "Select the 604e processor", Directive604, 0 },
  { "620", "Select the 620 processor", Directive620, 0 },
  { "7400", "Select the 7400 processor", Directive7400 | FeatureAltivec, 0 },
  { "7450", "Select the 7450 processor", Directive7400 | FeatureAltivec, 0 },
  { "750", "Select the 750 processor", Directive750 | FeatureAltivec, 0 },
  { "970", "Select the 970 processor", Directive970 | FeatureAltivec | FeatureGPUL | FeatureFSqrt | FeatureSTFIWX | Feature64Bit, 0 },
  { "g3", "Select the g3 processor", Directive7400, 0 },
  { "g4", "Select the g4 processor", Directive7400 | FeatureAltivec, 0 },
  { "g4+", "Select the g4+ processor", Directive750 | FeatureAltivec, 0 },
  { "g5", "Select the g5 processor", Directive970 | FeatureAltivec | FeatureGPUL | FeatureFSqrt | FeatureSTFIWX | Feature64Bit, 0 },
  { "generic", "Select the generic processor", Directive32, 0 },
  { "ppc", "Select the ppc processor", Directive32, 0 },
  { "ppc64", "Select the ppc64 processor", Directive64 | FeatureAltivec | FeatureGPUL | FeatureFSqrt | FeatureSTFIWX | Feature64Bit, 0 }
};

enum {
  SubTypeKVSize = sizeof(SubTypeKV)/sizeof(llvm::SubtargetFeatureKV)
};


enum {
  ItinClassesSize = 74
};
static const llvm::InstrStage Stages[] = {
  { 0, 0, 0 }, // No itinerary
  { 1, IU1 | IU2, -1 }, // 1
  { 19, IU1, -1 }, // 2
  { 1, FPU1, -1 }, // 3
  { 3, FPU1, -1 }, // 4
  { 5, IU1, -1 }, // 5
  { 6, IU1, -1 }, // 6
  { 3, IU1, -1 }, // 7
  { 2, IU1 | IU2, -1 }, // 8
  { 1, BPU, -1 }, // 9
  { 1, SRU, -1 }, // 10
  { 2, SLU, -1 }, // 11
  { 3, SLU, -1 }, // 12
  { 34, SLU, -1 }, // 13
  { 8, SLU, -1 }, // 14
  { 2, SRU, -1 }, // 15
  { 3, SRU, -1 }, // 16
  { 31, FPU1, -1 }, // 17
  { 17, FPU1, -1 }, // 18
  { 2, FPU1, -1 }, // 19
  { 10, FPU1, -1 }, // 20
  { 1, VIU1, -1 }, // 21
  { 5, SLU, -1 }, // 22
  { 8, SRU, -1 }, // 23
  { 4, VFPU, -1 }, // 24
  { 3, VIU2, -1 }, // 25
  { 1, VPU, -1 }, // 26
  { 1, IU1 | IU2 | IU3 | IU4, -1 }, // 27
  { 23, IU2, -1 }, // 28
  { 5, FPU1, -1 }, // 29
  { 2, VFPU, -1 }, // 30
  { 4, IU2, -1 }, // 31
  { 3, IU2, -1 }, // 32
  { 2, IU1 | IU2 | IU3 | IU4, -1 }, // 33
  { 2, IU2, -1 }, // 34
  { 4, SLU, -1 }, // 35
  { 37, SLU, -1 }, // 36
  { 35, SLU, -1 }, // 37
  { 0, IU1 | IU2 | IU3 | IU4, -1 }, // 38
  { 5, IU2, -1 }, // 39
  { 35, FPU1, -1 }, // 40
  { 21, FPU1, -1 }, // 41
  { 14, FPU1, -1 }, // 42
  { 4, VIU2, -1 }, // 43
  { 2, VPU, -1 }, // 44
  { 4, VIU1, -1 }, // 45
  { 3, IU1 | IU2, -1 }, // 46
  { 68, IU1, -1 }, // 47
  { 36, IU1, -1 }, // 48
  { 6, IU2, -1 }, // 49
  { 1, VFPU, -1 }, // 50
  { 6, FPU1 | FPU2, -1 }, // 51
  { 7, IU1 | IU2, -1 }, // 52
  { 5, IU1 | IU2, -1 }, // 53
  { 4, IU1 | IU2, -1 }, // 54
  { 1, IU2, -1 }, // 55
  { 4, BPU, -1 }, // 56
  { 2, BPU, -1 }, // 57
  { 3, BPU, -1 }, // 58
  { 10, SLU, -1 }, // 59
  { 40, SLU, -1 }, // 60
  { 11, SLU, -1 }, // 61
  { 64, SLU, -1 }, // 62
  { 10, IU2, -1 }, // 63
  { 8, IU2, -1 }, // 64
  { 8, FPU1 | FPU2, -1 }, // 65
  { 33, FPU1 | FPU2, -1 }, // 66
  { 40, FPU1 | FPU2, -1 }, // 67
  { 2, VIU1, -1 }, // 68
  { 8, VFPU, -1 }, // 69
  { 5, VIU2, -1 }, // 70
  { 3, VPU, -1 }, // 71
  { 0, 0, 0 } // End itinerary
};
static const unsigned OperandCycles[] = {
  0, // No itinerary
  0 // End itinerary
};

enum {
  StagesSize = sizeof(Stages)/sizeof(llvm::InstrStage),
  OperandCyclesSize = sizeof(OperandCycles)/sizeof(unsigned)
};

static const llvm::InstrItinerary G3Itineraries[] = {
  { 9, 10, 0, 0 }, // 0
  { 10, 11, 0, 0 }, // 1
  { 10, 11, 0, 0 }, // 2
  { 10, 11, 0, 0 }, // 3
  { 3, 4, 0, 0 }, // 4
  { 17, 18, 0, 0 }, // 5
  { 18, 19, 0, 0 }, // 6
  { 19, 20, 0, 0 }, // 7
  { 3, 4, 0, 0 }, // 8
  { 20, 21, 0, 0 }, // 9
  { 0, 0, 0, 0 }, // 10
  { 1, 2, 0, 0 }, // 11
  { 0, 0, 0, 0 }, // 12
  { 2, 3, 0, 0 }, // 13
  { 1, 2, 0, 0 }, // 14
  { 3, 4, 0, 0 }, // 15
  { 0, 0, 0, 0 }, // 16
  { 4, 5, 0, 0 }, // 17
  { 0, 0, 0, 0 }, // 18
  { 0, 0, 0, 0 }, // 19
  { 5, 6, 0, 0 }, // 20
  { 6, 7, 0, 0 }, // 21
  { 7, 8, 0, 0 }, // 22
  { 0, 0, 0, 0 }, // 23
  { 1, 2, 0, 0 }, // 24
  { 0, 0, 0, 0 }, // 25
  { 1, 2, 0, 0 }, // 26
  { 0, 0, 0, 0 }, // 27
  { 8, 9, 0, 0 }, // 28
  { 11, 12, 0, 0 }, // 29
  { 12, 13, 0, 0 }, // 30
  { 12, 13, 0, 0 }, // 31
  { 0, 0, 0, 0 }, // 32
  { 11, 12, 0, 0 }, // 33
  { 12, 13, 0, 0 }, // 34
  { 0, 0, 0, 0 }, // 35
  { 0, 0, 0, 0 }, // 36
  { 11, 12, 0, 0 }, // 37
  { 11, 12, 0, 0 }, // 38
  { 11, 12, 0, 0 }, // 39
  { 13, 14, 0, 0 }, // 40
  { 0, 0, 0, 0 }, // 41
  { 0, 0, 0, 0 }, // 42
  { 12, 13, 0, 0 }, // 43
  { 0, 0, 0, 0 }, // 44
  { 0, 0, 0, 0 }, // 45
  { 0, 0, 0, 0 }, // 46
  { 0, 0, 0, 0 }, // 47
  { 0, 0, 0, 0 }, // 48
  { 14, 15, 0, 0 }, // 49
  { 12, 13, 0, 0 }, // 50
  { 11, 12, 0, 0 }, // 51
  { 0, 0, 0, 0 }, // 52
  { 15, 16, 0, 0 }, // 53
  { 10, 11, 0, 0 }, // 54
  { 10, 11, 0, 0 }, // 55
  { 16, 17, 0, 0 }, // 56
  { 16, 17, 0, 0 }, // 57
  { 16, 17, 0, 0 }, // 58
  { 10, 11, 0, 0 }, // 59
  { 15, 16, 0, 0 }, // 60
  { 15, 16, 0, 0 }, // 61
  { 15, 16, 0, 0 }, // 62
  { 15, 16, 0, 0 }, // 63
  { 15, 16, 0, 0 }, // 64
  { 16, 17, 0, 0 }, // 65
  { 0, 0, 0, 0 }, // 66
  { 0, 0, 0, 0 }, // 67
  { 0, 0, 0, 0 }, // 68
  { 0, 0, 0, 0 }, // 69
  { 0, 0, 0, 0 }, // 70
  { 0, 0, 0, 0 }, // 71
  { 0, 0, 0, 0 }, // 72
  { 0, 0, 0, 0 }, // 73
  { ~0U, ~0U, ~0U, ~0U } // end marker
};

static const llvm::InstrItinerary G4Itineraries[] = {
  { 9, 10, 0, 0 }, // 0
  { 10, 11, 0, 0 }, // 1
  { 10, 11, 0, 0 }, // 2
  { 10, 11, 0, 0 }, // 3
  { 3, 4, 0, 0 }, // 4
  { 17, 18, 0, 0 }, // 5
  { 18, 19, 0, 0 }, // 6
  { 3, 4, 0, 0 }, // 7
  { 3, 4, 0, 0 }, // 8
  { 20, 21, 0, 0 }, // 9
  { 0, 0, 0, 0 }, // 10
  { 1, 2, 0, 0 }, // 11
  { 0, 0, 0, 0 }, // 12
  { 2, 3, 0, 0 }, // 13
  { 1, 2, 0, 0 }, // 14
  { 4, 5, 0, 0 }, // 15
  { 21, 22, 0, 0 }, // 16
  { 4, 5, 0, 0 }, // 17
  { 0, 0, 0, 0 }, // 18
  { 0, 0, 0, 0 }, // 19
  { 5, 6, 0, 0 }, // 20
  { 6, 7, 0, 0 }, // 21
  { 7, 8, 0, 0 }, // 22
  { 0, 0, 0, 0 }, // 23
  { 1, 2, 0, 0 }, // 24
  { 0, 0, 0, 0 }, // 25
  { 1, 2, 0, 0 }, // 26
  { 0, 0, 0, 0 }, // 27
  { 8, 9, 0, 0 }, // 28
  { 0, 0, 0, 0 }, // 29
  { 11, 12, 0, 0 }, // 30
  { 11, 12, 0, 0 }, // 31
  { 11, 12, 0, 0 }, // 32
  { 11, 12, 0, 0 }, // 33
  { 11, 12, 0, 0 }, // 34
  { 0, 0, 0, 0 }, // 35
  { 0, 0, 0, 0 }, // 36
  { 11, 12, 0, 0 }, // 37
  { 11, 12, 0, 0 }, // 38
  { 11, 12, 0, 0 }, // 39
  { 13, 14, 0, 0 }, // 40
  { 11, 12, 0, 0 }, // 41
  { 0, 0, 0, 0 }, // 42
  { 12, 13, 0, 0 }, // 43
  { 0, 0, 0, 0 }, // 44
  { 0, 0, 0, 0 }, // 45
  { 0, 0, 0, 0 }, // 46
  { 0, 0, 0, 0 }, // 47
  { 11, 12, 0, 0 }, // 48
  { 22, 23, 0, 0 }, // 49
  { 14, 15, 0, 0 }, // 50
  { 11, 12, 0, 0 }, // 51
  { 0, 0, 0, 0 }, // 52
  { 15, 16, 0, 0 }, // 53
  { 10, 11, 0, 0 }, // 54
  { 10, 11, 0, 0 }, // 55
  { 16, 17, 0, 0 }, // 56
  { 16, 17, 0, 0 }, // 57
  { 10, 11, 0, 0 }, // 58
  { 10, 11, 0, 0 }, // 59
  { 15, 16, 0, 0 }, // 60
  { 15, 16, 0, 0 }, // 61
  { 15, 16, 0, 0 }, // 62
  { 15, 16, 0, 0 }, // 63
  { 15, 16, 0, 0 }, // 64
  { 23, 24, 0, 0 }, // 65
  { 25, 26, 0, 0 }, // 66
  { 24, 25, 0, 0 }, // 67
  { 21, 22, 0, 0 }, // 68
  { 24, 25, 0, 0 }, // 69
  { 21, 22, 0, 0 }, // 70
  { 26, 27, 0, 0 }, // 71
  { 21, 22, 0, 0 }, // 72
  { 21, 22, 0, 0 }, // 73
  { ~0U, ~0U, ~0U, ~0U } // end marker
};

static const llvm::InstrItinerary G4PlusItineraries[] = {
  { 9, 10, 0, 0 }, // 0
  { 34, 35, 0, 0 }, // 1
  { 34, 35, 0, 0 }, // 2
  { 34, 35, 0, 0 }, // 3
  { 29, 30, 0, 0 }, // 4
  { 40, 41, 0, 0 }, // 5
  { 41, 42, 0, 0 }, // 6
  { 29, 30, 0, 0 }, // 7
  { 29, 30, 0, 0 }, // 8
  { 42, 43, 0, 0 }, // 9
  { 0, 0, 0, 0 }, // 10
  { 27, 28, 0, 0 }, // 11
  { 0, 0, 0, 0 }, // 12
  { 28, 29, 0, 0 }, // 13
  { 27, 28, 0, 0 }, // 14
  { 29, 30, 0, 0 }, // 15
  { 30, 31, 0, 0 }, // 16
  { 29, 30, 0, 0 }, // 17
  { 0, 0, 0, 0 }, // 18
  { 0, 0, 0, 0 }, // 19
  { 31, 32, 0, 0 }, // 20
  { 31, 32, 0, 0 }, // 21
  { 32, 33, 0, 0 }, // 22
  { 0, 0, 0, 0 }, // 23
  { 27, 28, 0, 0 }, // 24
  { 0, 0, 0, 0 }, // 25
  { 33, 34, 0, 0 }, // 26
  { 0, 0, 0, 0 }, // 27
  { 33, 34, 0, 0 }, // 28
  { 0, 0, 0, 0 }, // 29
  { 12, 13, 0, 0 }, // 30
  { 12, 13, 0, 0 }, // 31
  { 12, 13, 0, 0 }, // 32
  { 12, 13, 0, 0 }, // 33
  { 32, 33, 0, 0 }, // 34
  { 0, 0, 0, 0 }, // 35
  { 0, 0, 0, 0 }, // 36
  { 35, 36, 0, 0 }, // 37
  { 35, 36, 0, 0 }, // 38
  { 12, 13, 0, 0 }, // 39
  { 36, 37, 0, 0 }, // 40
  { 12, 13, 0, 0 }, // 41
  { 12, 13, 0, 0 }, // 42
  { 12, 13, 0, 0 }, // 43
  { 0, 0, 0, 0 }, // 44
  { 0, 0, 0, 0 }, // 45
  { 12, 13, 0, 0 }, // 46
  { 12, 13, 0, 0 }, // 47
  { 12, 13, 0, 0 }, // 48
  { 12, 13, 0, 0 }, // 49
  { 37, 38, 0, 0 }, // 50
  { 12, 13, 0, 0 }, // 51
  { 0, 0, 0, 0 }, // 52
  { 38, 39, 0, 0 }, // 53
  { 34, 35, 0, 0 }, // 54
  { 32, 33, 0, 0 }, // 55
  { 31, 32, 0, 0 }, // 56
  { 31, 32, 0, 0 }, // 57
  { 39, 40, 0, 0 }, // 58
  { 34, 35, 0, 0 }, // 59
  { 34, 35, 0, 0 }, // 60
  { 34, 35, 0, 0 }, // 61
  { 34, 35, 0, 0 }, // 62
  { 27, 28, 0, 0 }, // 63
  { 38, 39, 0, 0 }, // 64
  { 12, 13, 0, 0 }, // 65
  { 43, 44, 0, 0 }, // 66
  { 24, 25, 0, 0 }, // 67
  { 30, 31, 0, 0 }, // 68
  { 45, 46, 0, 0 }, // 69
  { 21, 22, 0, 0 }, // 70
  { 44, 45, 0, 0 }, // 71
  { 44, 45, 0, 0 }, // 72
  { 44, 45, 0, 0 }, // 73
  { ~0U, ~0U, ~0U, ~0U } // end marker
};

static const llvm::InstrItinerary G5Itineraries[] = {
  { 9, 10, 0, 0 }, // 0
  { 56, 57, 0, 0 }, // 1
  { 57, 58, 0, 0 }, // 2
  { 58, 59, 0, 0 }, // 3
  { 65, 66, 0, 0 }, // 4
  { 66, 67, 0, 0 }, // 5
  { 66, 67, 0, 0 }, // 6
  { 51, 52, 0, 0 }, // 7
  { 51, 52, 0, 0 }, // 8
  { 51, 52, 0, 0 }, // 9
  { 67, 68, 0, 0 }, // 10
  { 46, 47, 0, 0 }, // 11
  { 47, 48, 0, 0 }, // 12
  { 48, 49, 0, 0 }, // 13
  { 8, 9, 0, 0 }, // 14
  { 49, 50, 0, 0 }, // 15
  { 50, 51, 0, 0 }, // 16
  { 51, 52, 0, 0 }, // 17
  { 0, 0, 0, 0 }, // 18
  { 52, 53, 0, 0 }, // 19
  { 53, 54, 0, 0 }, // 20
  { 53, 54, 0, 0 }, // 21
  { 54, 55, 0, 0 }, // 22
  { 55, 56, 0, 0 }, // 23
  { 54, 55, 0, 0 }, // 24
  { 8, 9, 0, 0 }, // 25
  { 8, 9, 0, 0 }, // 26
  { 1, 2, 0, 0 }, // 27
  { 1, 2, 0, 0 }, // 28
  { 0, 0, 0, 0 }, // 29
  { 12, 13, 0, 0 }, // 30
  { 0, 0, 0, 0 }, // 31
  { 59, 60, 0, 0 }, // 32
  { 12, 13, 0, 0 }, // 33
  { 60, 61, 0, 0 }, // 34
  { 12, 13, 0, 0 }, // 35
  { 61, 62, 0, 0 }, // 36
  { 12, 13, 0, 0 }, // 37
  { 22, 23, 0, 0 }, // 38
  { 22, 23, 0, 0 }, // 39
  { 62, 63, 0, 0 }, // 40
  { 12, 13, 0, 0 }, // 41
  { 22, 23, 0, 0 }, // 42
  { 61, 62, 0, 0 }, // 43
  { 60, 61, 0, 0 }, // 44
  { 11, 12, 0, 0 }, // 45
  { 12, 13, 0, 0 }, // 46
  { 61, 62, 0, 0 }, // 47
  { 22, 23, 0, 0 }, // 48
  { 61, 62, 0, 0 }, // 49
  { 37, 38, 0, 0 }, // 50
  { 35, 36, 0, 0 }, // 51
  { 0, 0, 0, 0 }, // 52
  { 60, 61, 0, 0 }, // 53
  { 34, 35, 0, 0 }, // 54
  { 32, 33, 0, 0 }, // 55
  { 32, 33, 0, 0 }, // 56
  { 12, 13, 0, 0 }, // 57
  { 63, 64, 0, 0 }, // 58
  { 12, 13, 0, 0 }, // 59
  { 64, 65, 0, 0 }, // 60
  { 12, 13, 0, 0 }, // 61
  { 0, 0, 0, 0 }, // 62
  { 0, 0, 0, 0 }, // 63
  { 55, 56, 0, 0 }, // 64
  { 12, 13, 0, 0 }, // 65
  { 70, 71, 0, 0 }, // 66
  { 69, 70, 0, 0 }, // 67
  { 30, 31, 0, 0 }, // 68
  { 69, 70, 0, 0 }, // 69
  { 68, 69, 0, 0 }, // 70
  { 71, 72, 0, 0 }, // 71
  { 68, 69, 0, 0 }, // 72
  { 71, 72, 0, 0 }, // 73
  { ~0U, ~0U, ~0U, ~0U } // end marker
};

// Sorted (by key) array of itineraries for CPU subtype.
static const llvm::SubtargetInfoKV ProcItinKV[] = {
  { "601", (void *)&G3Itineraries },
  { "602", (void *)&G3Itineraries },
  { "603", (void *)&G3Itineraries },
  { "603e", (void *)&G3Itineraries },
  { "603ev", (void *)&G3Itineraries },
  { "604", (void *)&G3Itineraries },
  { "604e", (void *)&G3Itineraries },
  { "620", (void *)&G3Itineraries },
  { "7400", (void *)&G4Itineraries },
  { "7450", (void *)&G4PlusItineraries },
  { "750", (void *)&G4Itineraries },
  { "970", (void *)&G5Itineraries },
  { "g3", (void *)&G3Itineraries },
  { "g4", (void *)&G4Itineraries },
  { "g4+", (void *)&G4PlusItineraries },
  { "g5", (void *)&G5Itineraries },
  { "generic", (void *)&G3Itineraries },
  { "ppc", (void *)&G3Itineraries },
  { "ppc64", (void *)&G5Itineraries }
};

enum {
  ProcItinKVSize = sizeof(ProcItinKV)/sizeof(llvm::SubtargetInfoKV)
};

// ParseSubtargetFeatures - Parses features string setting specified
// subtarget options.
std::string llvm::PPCSubtarget::ParseSubtargetFeatures(const std::string &FS,
                                  const std::string &CPU) {
  DEBUG(dbgs() << "\nFeatures:" << FS);
  DEBUG(dbgs() << "\nCPU:" << CPU);
  SubtargetFeatures Features(FS);
  Features.setCPUIfNone(CPU);
  uint32_t Bits =  Features.getBits(SubTypeKV, SubTypeKVSize,
                                    FeatureKV, FeatureKVSize);
  if ((Bits & Directive32) != 0 && DarwinDirective < PPC::DIR_32) DarwinDirective = PPC::DIR_32;
  if ((Bits & Directive601) != 0 && DarwinDirective < PPC::DIR_601) DarwinDirective = PPC::DIR_601;
  if ((Bits & Directive602) != 0 && DarwinDirective < PPC::DIR_602) DarwinDirective = PPC::DIR_602;
  if ((Bits & Directive603) != 0 && DarwinDirective < PPC::DIR_603) DarwinDirective = PPC::DIR_603;
  if ((Bits & Directive604) != 0 && DarwinDirective < PPC::DIR_603) DarwinDirective = PPC::DIR_603;
  if ((Bits & Directive620) != 0 && DarwinDirective < PPC::DIR_603) DarwinDirective = PPC::DIR_603;
  if ((Bits & Directive64) != 0 && DarwinDirective < PPC::DIR_64) DarwinDirective = PPC::DIR_64;
  if ((Bits & Directive7400) != 0 && DarwinDirective < PPC::DIR_7400) DarwinDirective = PPC::DIR_7400;
  if ((Bits & Directive750) != 0 && DarwinDirective < PPC::DIR_750) DarwinDirective = PPC::DIR_750;
  if ((Bits & Directive970) != 0 && DarwinDirective < PPC::DIR_970) DarwinDirective = PPC::DIR_970;
  if ((Bits & Feature64Bit) != 0) Has64BitSupport = true;
  if ((Bits & Feature64BitRegs) != 0) Use64BitRegs = true;
  if ((Bits & FeatureAltivec) != 0) HasAltivec = true;
  if ((Bits & FeatureFSqrt) != 0) HasFSQRT = true;
  if ((Bits & FeatureGPUL) != 0) IsGigaProcessor = true;
  if ((Bits & FeatureSTFIWX) != 0) HasSTFIWX = true;

  InstrItinerary *Itinerary = (InstrItinerary *)Features.getInfo(ProcItinKV, ProcItinKVSize);
  InstrItins = InstrItineraryData(Stages, OperandCycles, Itinerary);
  return Features.getCPU();
}
