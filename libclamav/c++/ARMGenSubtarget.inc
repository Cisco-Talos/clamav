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
  FU_Issue =  1 << 0,
  FU_LdSt0 =  1 << 1,
  FU_LdSt1 =  1 << 2,
  FU_NLSPipe =  1 << 3,
  FU_NPipe =  1 << 4,
  FU_Pipe0 =  1 << 5,
  FU_Pipe1 =  1 << 6
};

enum {
  ArchV4T =  1 << 0,
  ArchV5T =  1 << 1,
  ArchV5TE =  1 << 2,
  ArchV6 =  1 << 3,
  ArchV6T2 =  1 << 4,
  ArchV7A =  1 << 5,
  FeatureNEON =  1 << 6,
  FeatureThumb2 =  1 << 7,
  FeatureVFP2 =  1 << 8,
  FeatureVFP3 =  1 << 9
};

// Sorted (by key) array of values for CPU features.
static const llvm::SubtargetFeatureKV FeatureKV[] = {
  { "neon", "Enable NEON instructions", FeatureNEON, 0 },
  { "thumb2", "Enable Thumb2 instructions", FeatureThumb2, 0 },
  { "v4t", "ARM v4T", ArchV4T, 0 },
  { "v5t", "ARM v5T", ArchV5T, 0 },
  { "v5te", "ARM v5TE, v5TEj, v5TExp", ArchV5TE, 0 },
  { "v6", "ARM v6", ArchV6, 0 },
  { "v6t2", "ARM v6t2", ArchV6T2, 0 },
  { "v7a", "ARM v7A", ArchV7A, 0 },
  { "vfp2", "Enable VFP2 instructions", FeatureVFP2, 0 },
  { "vfp3", "Enable VFP3 instructions", FeatureVFP3, 0 }
};

enum {
  FeatureKVSize = sizeof(FeatureKV)/sizeof(llvm::SubtargetFeatureKV)
};

// Sorted (by key) array of values for CPU subtype.
static const llvm::SubtargetFeatureKV SubTypeKV[] = {
  { "arm1020e", "Select the arm1020e processor", ArchV5TE, 0 },
  { "arm1020t", "Select the arm1020t processor", ArchV5T, 0 },
  { "arm1022e", "Select the arm1022e processor", ArchV5TE, 0 },
  { "arm10e", "Select the arm10e processor", ArchV5TE, 0 },
  { "arm10tdmi", "Select the arm10tdmi processor", ArchV5T, 0 },
  { "arm1136j-s", "Select the arm1136j-s processor", ArchV6, 0 },
  { "arm1136jf-s", "Select the arm1136jf-s processor", ArchV6 | FeatureVFP2, 0 },
  { "arm1156t2-s", "Select the arm1156t2-s processor", ArchV6T2 | FeatureThumb2, 0 },
  { "arm1156t2f-s", "Select the arm1156t2f-s processor", ArchV6T2 | FeatureThumb2 | FeatureVFP2, 0 },
  { "arm1176jz-s", "Select the arm1176jz-s processor", ArchV6, 0 },
  { "arm1176jzf-s", "Select the arm1176jzf-s processor", ArchV6 | FeatureVFP2, 0 },
  { "arm710t", "Select the arm710t processor", ArchV4T, 0 },
  { "arm720t", "Select the arm720t processor", ArchV4T, 0 },
  { "arm7tdmi", "Select the arm7tdmi processor", ArchV4T, 0 },
  { "arm7tdmi-s", "Select the arm7tdmi-s processor", ArchV4T, 0 },
  { "arm8", "Select the arm8 processor", 0, 0 },
  { "arm810", "Select the arm810 processor", 0, 0 },
  { "arm9", "Select the arm9 processor", ArchV4T, 0 },
  { "arm920", "Select the arm920 processor", ArchV4T, 0 },
  { "arm920t", "Select the arm920t processor", ArchV4T, 0 },
  { "arm922t", "Select the arm922t processor", ArchV4T, 0 },
  { "arm926ej-s", "Select the arm926ej-s processor", ArchV5TE, 0 },
  { "arm940t", "Select the arm940t processor", ArchV4T, 0 },
  { "arm946e-s", "Select the arm946e-s processor", ArchV5TE, 0 },
  { "arm966e-s", "Select the arm966e-s processor", ArchV5TE, 0 },
  { "arm968e-s", "Select the arm968e-s processor", ArchV5TE, 0 },
  { "arm9e", "Select the arm9e processor", ArchV5TE, 0 },
  { "arm9tdmi", "Select the arm9tdmi processor", ArchV4T, 0 },
  { "cortex-a8", "Select the cortex-a8 processor", ArchV7A | FeatureThumb2 | FeatureNEON, 0 },
  { "cortex-a9", "Select the cortex-a9 processor", ArchV7A | FeatureThumb2 | FeatureNEON, 0 },
  { "ep9312", "Select the ep9312 processor", ArchV4T, 0 },
  { "generic", "Select the generic processor", 0, 0 },
  { "iwmmxt", "Select the iwmmxt processor", ArchV5TE, 0 },
  { "mpcore", "Select the mpcore processor", ArchV6 | FeatureVFP2, 0 },
  { "mpcorenovfp", "Select the mpcorenovfp processor", ArchV6, 0 },
  { "strongarm", "Select the strongarm processor", 0, 0 },
  { "strongarm110", "Select the strongarm110 processor", 0, 0 },
  { "strongarm1100", "Select the strongarm1100 processor", 0, 0 },
  { "strongarm1110", "Select the strongarm1110 processor", 0, 0 },
  { "xscale", "Select the xscale processor", ArchV5TE, 0 }
};

enum {
  SubTypeKVSize = sizeof(SubTypeKV)/sizeof(llvm::SubtargetFeatureKV)
};


enum {
  ItinClassesSize = 129
};
static const llvm::InstrStage Stages[] = {
  { 0, 0, 0 }, // No itinerary
  { 1, FU_Pipe0, -1 }, // 1
  { 2, FU_Pipe0, -1 }, // 2
  { 3, FU_Pipe0, -1 }, // 3
  { 15, FU_Pipe0, -1 }, // 4
  { 29, FU_Pipe0, -1 }, // 5
  { 1, FU_Pipe0 | FU_Pipe1, -1 }, // 6
  { 1, FU_Pipe1, 0 },   { 2, FU_Pipe0, -1 }, // 7
  { 2, FU_Pipe1, 0 },   { 3, FU_Pipe0, -1 }, // 8
  { 1, FU_Issue, 0 },   { 1, FU_Pipe0 | FU_Pipe1, -1 },   { 1, FU_LdSt0, -1 }, // 9
  { 2, FU_Issue, 0 },   { 1, FU_Pipe0, 0 },   { 1, FU_Pipe1, -1 },   { 1, FU_Pipe0 | FU_Pipe1, -1 },   { 1, FU_LdSt0, -1 }, // 10
  { 2, FU_Issue, 0 },   { 2, FU_Pipe0, 0 },   { 2, FU_Pipe1, -1 },   { 1, FU_Pipe0 | FU_Pipe1, -1 },   { 1, FU_LdSt0, -1 }, // 11
  { 1, FU_Pipe0 | FU_Pipe1, -1 },   { 1, FU_NLSPipe, -1 }, // 12
  { 1, FU_Pipe0 | FU_Pipe1, -1 },   { 1, FU_NPipe, -1 }, // 13
  { 1, FU_Pipe0 | FU_Pipe1, -1 },   { 4, FU_NPipe, 0 },   { 4, FU_NLSPipe, -1 }, // 14
  { 1, FU_Pipe0 | FU_Pipe1, -1 },   { 7, FU_NPipe, 0 },   { 7, FU_NLSPipe, -1 }, // 15
  { 1, FU_Pipe0 | FU_Pipe1, -1 },   { 5, FU_NPipe, 0 },   { 5, FU_NLSPipe, -1 }, // 16
  { 1, FU_Pipe0 | FU_Pipe1, -1 },   { 8, FU_NPipe, 0 },   { 8, FU_NLSPipe, -1 }, // 17
  { 1, FU_Pipe0 | FU_Pipe1, -1 },   { 9, FU_NPipe, 0 },   { 9, FU_NLSPipe, -1 }, // 18
  { 1, FU_Pipe0 | FU_Pipe1, -1 },   { 11, FU_NPipe, 0 },   { 11, FU_NLSPipe, -1 }, // 19
  { 1, FU_Pipe0 | FU_Pipe1, -1 },   { 19, FU_NPipe, 0 },   { 19, FU_NLSPipe, -1 }, // 20
  { 1, FU_Pipe0 | FU_Pipe1, -1 },   { 20, FU_NPipe, 0 },   { 20, FU_NLSPipe, -1 }, // 21
  { 1, FU_Pipe0 | FU_Pipe1, -1 },   { 29, FU_NPipe, 0 },   { 29, FU_NLSPipe, -1 }, // 22
  { 1, FU_Issue, 0 },   { 1, FU_Pipe0 | FU_Pipe1, -1 },   { 1, FU_LdSt0, 0 },   { 1, FU_NLSPipe, -1 }, // 23
  { 2, FU_Issue, 0 },   { 1, FU_Pipe0, 0 },   { 1, FU_Pipe1, -1 },   { 1, FU_Pipe0 | FU_Pipe1, -1 },   { 1, FU_LdSt0, 0 },   { 1, FU_NLSPipe, -1 }, // 24
  { 3, FU_Issue, 0 },   { 2, FU_Pipe0, 0 },   { 2, FU_Pipe1, -1 },   { 1, FU_Pipe0 | FU_Pipe1, -1 },   { 1, FU_LdSt0, 0 },   { 1, FU_NLSPipe, -1 }, // 25
  { 1, FU_Pipe0 | FU_Pipe1, -1 },   { 2, FU_NPipe, -1 }, // 26
  { 1, FU_Pipe0 | FU_Pipe1, -1 },   { 2, FU_NLSPipe, -1 }, // 27
  { 1, FU_Pipe0 | FU_Pipe1, -1 },   { 1, FU_NLSPipe, -1 },   { 1, FU_NPipe, 0 },   { 2, FU_NLSPipe, -1 }, // 28
  { 1, FU_Pipe0 | FU_Pipe1, -1 },   { 1, FU_NPipe, -1 },   { 2, FU_NLSPipe, 0 },   { 3, FU_NPipe, -1 }, // 29
  { 0, 0, 0 } // End itinerary
};
static const unsigned OperandCycles[] = {
  0, // No itinerary
  2,   2, // 1
  2,   2,   2, // 2
  2,   2,   1, // 3
  3,   3,   2,   1, // 4
  2,   1, // 5
  3,   2,   1, // 6
  2, // 7
  3, // 8
  3,   2, // 9
  3,   1, // 10
  4,   2,   1, // 11
  4,   1,   1, // 12
  4,   1,   1,   2, // 13
  5,   1,   1, // 14
  5,   1,   1,   2, // 15
  6,   1,   1, // 16
  6,   1,   1,   2, // 17
  4,   1, // 18
  5,   2,   1, // 19
  4,   2,   1,   1, // 20
  5,   2,   2,   1, // 21
  2,   1,   1, // 22
  2,   2,   1,   1, // 23
  2,   2,   2,   1, // 24
  5,   2, // 25
  9,   2, // 26
  9,   2,   2, // 27
  9,   2,   2,   2, // 28
  20,   2,   2, // 29
  34,   2,   2, // 30
  5,   2,   2, // 31
  1, // 32
  1,   1, // 33
  1,   1,   1, // 34
  6,   1,   1,   4, // 35
  6,   6,   1,   1, // 36
  3,   1,   1, // 37
  3,   2,   1,   1, // 38
  4,   3,   1,   1, // 39
  2,   3,   1, // 40
  2,   3,   1,   1, // 41
  3,   3,   1,   1, // 42
  7,   1, // 43
  5,   1, // 44
  8,   1, // 45
  7,   1,   1, // 46
  9,   1,   1, // 47
  11,   1,   1, // 48
  7,   2,   1,   1, // 49
  19,   2,   1,   1, // 50
  20,   1,   1, // 51
  29,   1,   1, // 52
  19,   1, // 53
  29,   1, // 54
  2,   2,   2,   2,   1, // 55
  6,   2, // 56
  6,   2,   2, // 57
  20,   1, // 58
  20,   20,   1, // 59
  4,   4,   1,   1, // 60
  9,   2,   2,   3, // 61
  10,   2,   2,   3, // 62
  10,   2,   2, // 63
  3,   2,   2, // 64
  4,   2,   2, // 65
  4,   2, // 66
  6,   3,   2,   1, // 67
  7,   3,   2,   1, // 68
  7,   2,   1, // 69
  7,   2,   2, // 70
  9,   2,   1, // 71
  6,   2,   2,   3, // 72
  7,   2,   1,   3, // 73
  7,   2,   2,   3, // 74
  9,   2,   1,   3, // 75
  3,   2,   2,   1, // 76
  4,   2,   2,   3,   1, // 77
  4,   2,   2,   3,   3,   1, // 78
  3,   1,   2,   1, // 79
  3,   1,   2,   2,   1, // 80
  4,   1,   2,   2,   3,   1, // 81
  4,   1,   2,   2,   3,   3,   1, // 82
  0 // End itinerary
};

enum {
  StagesSize = sizeof(Stages)/sizeof(llvm::InstrStage),
  OperandCyclesSize = sizeof(OperandCycles)/sizeof(unsigned)
};

static const llvm::InstrItinerary ARMV6Itineraries[] = {
  { 1, 2, 0, 0 }, // 0
  { 0, 0, 0, 0 }, // 1
  { 0, 0, 0, 0 }, // 2
  { 0, 0, 0, 0 }, // 3
  { 0, 0, 0, 0 }, // 4
  { 0, 0, 0, 0 }, // 5
  { 0, 0, 0, 0 }, // 6
  { 0, 0, 0, 0 }, // 7
  { 0, 0, 0, 0 }, // 8
  { 0, 0, 0, 0 }, // 9
  { 0, 0, 0, 0 }, // 10
  { 0, 0, 0, 0 }, // 11
  { 0, 0, 0, 0 }, // 12
  { 0, 0, 0, 0 }, // 13
  { 0, 0, 0, 0 }, // 14
  { 0, 0, 0, 0 }, // 15
  { 0, 0, 0, 0 }, // 16
  { 0, 0, 0, 0 }, // 17
  { 0, 0, 0, 0 }, // 18
  { 0, 0, 0, 0 }, // 19
  { 0, 0, 0, 0 }, // 20
  { 0, 0, 0, 0 }, // 21
  { 0, 0, 0, 0 }, // 22
  { 0, 0, 0, 0 }, // 23
  { 0, 0, 0, 0 }, // 24
  { 0, 0, 0, 0 }, // 25
  { 0, 0, 0, 0 }, // 26
  { 0, 0, 0, 0 }, // 27
  { 0, 0, 0, 0 }, // 28
  { 0, 0, 0, 0 }, // 29
  { 0, 0, 0, 0 }, // 30
  { 0, 0, 0, 0 }, // 31
  { 0, 0, 0, 0 }, // 32
  { 0, 0, 0, 0 }, // 33
  { 0, 0, 0, 0 }, // 34
  { 0, 0, 0, 0 }, // 35
  { 0, 0, 0, 0 }, // 36
  { 0, 0, 0, 0 }, // 37
  { 0, 0, 0, 0 }, // 38
  { 0, 0, 0, 0 }, // 39
  { 0, 0, 0, 0 }, // 40
  { 0, 0, 0, 0 }, // 41
  { 0, 0, 0, 0 }, // 42
  { 0, 0, 0, 0 }, // 43
  { 0, 0, 0, 0 }, // 44
  { 0, 0, 0, 0 }, // 45
  { 0, 0, 0, 0 }, // 46
  { 0, 0, 0, 0 }, // 47
  { 0, 0, 0, 0 }, // 48
  { 0, 0, 0, 0 }, // 49
  { 0, 0, 0, 0 }, // 50
  { 0, 0, 0, 0 }, // 51
  { 0, 0, 0, 0 }, // 52
  { 0, 0, 0, 0 }, // 53
  { 0, 0, 0, 0 }, // 54
  { 0, 0, 0, 0 }, // 55
  { 0, 0, 0, 0 }, // 56
  { 0, 0, 0, 0 }, // 57
  { 0, 0, 0, 0 }, // 58
  { 0, 0, 0, 0 }, // 59
  { 0, 0, 0, 0 }, // 60
  { 1, 2, 76, 79 }, // 61
  { 1, 2, 76, 79 }, // 62
  { 1, 2, 1, 3 }, // 63
  { 1, 2, 1, 3 }, // 64
  { 1, 2, 74, 76 }, // 65
  { 1, 2, 72, 74 }, // 66
  { 1, 2, 74, 76 }, // 67
  { 1, 2, 74, 76 }, // 68
  { 1, 2, 72, 74 }, // 69
  { 1, 2, 74, 76 }, // 70
  { 4, 5, 83, 86 }, // 71
  { 5, 6, 86, 89 }, // 72
  { 1, 2, 89, 92 }, // 73
  { 1, 2, 89, 92 }, // 74
  { 3, 4, 0, 0 }, // 75
  { 1, 2, 79, 83 }, // 76
  { 2, 3, 79, 83 }, // 77
  { 1, 2, 76, 79 }, // 78
  { 2, 3, 76, 79 }, // 79
  { 4, 5, 83, 86 }, // 80
  { 5, 6, 86, 89 }, // 81
  { 1, 2, 19, 20 }, // 82
  { 1, 2, 3, 6 }, // 83
  { 1, 2, 3, 6 }, // 84
  { 3, 4, 0, 0 }, // 85
  { 1, 2, 72, 74 }, // 86
  { 1, 2, 72, 74 }, // 87
  { 1, 2, 1, 3 }, // 88
  { 1, 2, 3, 6 }, // 89
  { 1, 2, 6, 9 }, // 90
  { 2, 3, 9, 13 }, // 91
  { 1, 2, 0, 0 }, // 92
  { 1, 2, 19, 20 }, // 93
  { 1, 2, 20, 22 }, // 94
  { 1, 2, 22, 24 }, // 95
  { 1, 2, 24, 27 }, // 96
  { 1, 2, 18, 19 }, // 97
  { 1, 2, 1, 3 }, // 98
  { 1, 2, 13, 15 }, // 99
  { 2, 3, 15, 18 }, // 100
  { 1, 2, 48, 50 }, // 101
  { 1, 2, 24, 27 }, // 102
  { 3, 4, 0, 0 }, // 103
  { 1, 2, 27, 30 }, // 104
  { 1, 2, 53, 57 }, // 105
  { 2, 3, 50, 53 }, // 106
  { 2, 3, 57, 61 }, // 107
  { 1, 2, 30, 34 }, // 108
  { 2, 3, 37, 41 }, // 109
  { 3, 4, 44, 48 }, // 110
  { 1, 2, 18, 19 }, // 111
  { 1, 2, 1, 3 }, // 112
  { 1, 2, 13, 15 }, // 113
  { 2, 3, 15, 18 }, // 114
  { 1, 2, 27, 30 }, // 115
  { 2, 3, 34, 37 }, // 116
  { 3, 4, 41, 44 }, // 117
  { 1, 2, 13, 15 }, // 118
  { 1, 2, 6, 9 }, // 119
  { 3, 4, 0, 0 }, // 120
  { 1, 2, 61, 64 }, // 121
  { 1, 2, 64, 68 }, // 122
  { 2, 3, 6, 9 }, // 123
  { 2, 3, 68, 72 }, // 124
  { 1, 2, 1, 3 }, // 125
  { 1, 2, 13, 15 }, // 126
  { 2, 3, 15, 18 }, // 127
  { 0, 0, 0, 0 }, // 128
  { ~0U, ~0U, ~0U, ~0U } // end marker
};

static const llvm::InstrItinerary CortexA8Itineraries[] = {
  { 6, 7, 0, 0 }, // 0
  { 26, 28, 89, 92 }, // 1
  { 71, 73, 168, 171 }, // 2
  { 26, 28, 24, 27 }, // 3
  { 26, 28, 24, 27 }, // 4
  { 26, 28, 191, 194 }, // 5
  { 26, 28, 191, 194 }, // 6
  { 26, 28, 191, 194 }, // 7
  { 71, 73, 194, 197 }, // 8
  { 24, 26, 61, 64 }, // 9
  { 73, 75, 106, 109 }, // 10
  { 55, 59, 0, 0 }, // 11
  { 55, 59, 6, 9 }, // 12
  { 55, 59, 68, 72 }, // 13
  { 55, 59, 161, 166 }, // 14
  { 26, 28, 180, 184 }, // 15
  { 71, 73, 184, 188 }, // 16
  { 26, 28, 216, 220 }, // 17
  { 71, 73, 224, 228 }, // 18
  { 71, 73, 220, 224 }, // 19
  { 79, 83, 228, 232 }, // 20
  { 24, 26, 13, 15 }, // 21
  { 24, 26, 173, 176 }, // 22
  { 24, 26, 61, 64 }, // 23
  { 24, 26, 13, 15 }, // 24
  { 73, 75, 106, 109 }, // 25
  { 26, 28, 19, 20 }, // 26
  { 73, 75, 22, 24 }, // 27
  { 24, 26, 171, 173 }, // 28
  { 26, 28, 168, 171 }, // 29
  { 71, 73, 210, 213 }, // 30
  { 71, 73, 207, 210 }, // 31
  { 79, 83, 213, 216 }, // 32
  { 26, 28, 199, 203 }, // 33
  { 71, 73, 203, 207 }, // 34
  { 24, 26, 64, 68 }, // 35
  { 73, 75, 124, 128 }, // 36
  { 75, 79, 176, 180 }, // 37
  { 26, 28, 48, 50 }, // 38
  { 26, 28, 48, 50 }, // 39
  { 26, 28, 76, 79 }, // 40
  { 71, 73, 188, 191 }, // 41
  { 26, 28, 27, 30 }, // 42
  { 71, 73, 34, 37 }, // 43
  { 26, 28, 106, 109 }, // 44
  { 71, 73, 27, 30 }, // 45
  { 55, 59, 0, 0 }, // 46
  { 26, 28, 15, 18 }, // 47
  { 26, 28, 15, 18 }, // 48
  { 73, 75, 15, 18 }, // 49
  { 73, 75, 232, 236 }, // 50
  { 75, 79, 236, 241 }, // 51
  { 75, 79, 241, 247 }, // 52
  { 73, 75, 247, 251 }, // 53
  { 73, 75, 251, 256 }, // 54
  { 75, 79, 256, 262 }, // 55
  { 75, 79, 262, 269 }, // 56
  { 26, 28, 72, 74 }, // 57
  { 71, 73, 166, 168 }, // 58
  { 26, 28, 197, 199 }, // 59
  { 26, 28, 197, 199 }, // 60
  { 26, 28, 134, 137 }, // 61
  { 40, 43, 137, 140 }, // 62
  { 26, 28, 93, 95 }, // 63
  { 28, 31, 48, 50 }, // 64
  { 37, 40, 132, 134 }, // 65
  { 34, 37, 130, 132 }, // 66
  { 37, 40, 132, 134 }, // 67
  { 26, 28, 128, 130 }, // 68
  { 31, 34, 128, 130 }, // 69
  { 26, 28, 128, 130 }, // 70
  { 49, 52, 151, 154 }, // 71
  { 52, 55, 154, 157 }, // 72
  { 55, 59, 0, 0 }, // 73
  { 59, 65, 0, 0 }, // 74
  { 65, 71, 0, 0 }, // 75
  { 26, 28, 143, 147 }, // 76
  { 46, 49, 147, 151 }, // 77
  { 26, 28, 134, 137 }, // 78
  { 43, 46, 140, 143 }, // 79
  { 46, 49, 157, 159 }, // 80
  { 52, 55, 159, 161 }, // 81
  { 24, 26, 0, 0 }, // 82
  { 55, 59, 0, 0 }, // 83
  { 59, 65, 0, 0 }, // 84
  { 65, 71, 0, 0 }, // 85
  { 26, 28, 128, 130 }, // 86
  { 28, 31, 48, 50 }, // 87
  { 6, 7, 1, 3 }, // 88
  { 6, 7, 3, 6 }, // 89
  { 6, 7, 6, 9 }, // 90
  { 6, 7, 64, 68 }, // 91
  { 6, 7, 0, 0 }, // 92
  { 6, 7, 18, 19 }, // 93
  { 6, 7, 13, 15 }, // 94
  { 6, 7, 13, 15 }, // 95
  { 6, 7, 61, 64 }, // 96
  { 6, 7, 18, 19 }, // 97
  { 6, 7, 1, 3 }, // 98
  { 6, 7, 13, 15 }, // 99
  { 6, 7, 61, 64 }, // 100
  { 11, 14, 22, 24 }, // 101
  { 11, 14, 15, 18 }, // 102
  { 19, 24, 0, 0 }, // 103
  { 11, 14, 106, 109 }, // 104
  { 11, 14, 109, 113 }, // 105
  { 14, 19, 27, 30 }, // 106
  { 14, 19, 113, 117 }, // 107
  { 7, 9, 98, 102 }, // 108
  { 7, 9, 98, 102 }, // 109
  { 9, 11, 102, 106 }, // 110
  { 6, 7, 92, 93 }, // 111
  { 6, 7, 93, 95 }, // 112
  { 6, 7, 93, 95 }, // 113
  { 6, 7, 95, 98 }, // 114
  { 1, 2, 34, 37 }, // 115
  { 7, 9, 41, 44 }, // 116
  { 9, 11, 102, 106 }, // 117
  { 11, 14, 22, 24 }, // 118
  { 11, 14, 117, 120 }, // 119
  { 19, 24, 0, 0 }, // 120
  { 11, 14, 106, 109 }, // 121
  { 11, 14, 120, 124 }, // 122
  { 14, 19, 106, 109 }, // 123
  { 14, 19, 124, 128 }, // 124
  { 6, 7, 1, 3 }, // 125
  { 6, 7, 13, 15 }, // 126
  { 6, 7, 61, 64 }, // 127
  { 0, 0, 0, 0 }, // 128
  { ~0U, ~0U, ~0U, ~0U } // end marker
};

static const llvm::InstrItinerary GenericItineraries[] = {
  { 0, 0, 0, 0 }, // 0
  { 0, 0, 0, 0 }, // 1
  { 0, 0, 0, 0 }, // 2
  { 0, 0, 0, 0 }, // 3
  { 0, 0, 0, 0 }, // 4
  { 0, 0, 0, 0 }, // 5
  { 0, 0, 0, 0 }, // 6
  { 0, 0, 0, 0 }, // 7
  { 0, 0, 0, 0 }, // 8
  { 0, 0, 0, 0 }, // 9
  { 0, 0, 0, 0 }, // 10
  { 0, 0, 0, 0 }, // 11
  { 0, 0, 0, 0 }, // 12
  { 0, 0, 0, 0 }, // 13
  { 0, 0, 0, 0 }, // 14
  { 0, 0, 0, 0 }, // 15
  { 0, 0, 0, 0 }, // 16
  { 0, 0, 0, 0 }, // 17
  { 0, 0, 0, 0 }, // 18
  { 0, 0, 0, 0 }, // 19
  { 0, 0, 0, 0 }, // 20
  { 0, 0, 0, 0 }, // 21
  { 0, 0, 0, 0 }, // 22
  { 0, 0, 0, 0 }, // 23
  { 0, 0, 0, 0 }, // 24
  { 0, 0, 0, 0 }, // 25
  { 0, 0, 0, 0 }, // 26
  { 0, 0, 0, 0 }, // 27
  { 0, 0, 0, 0 }, // 28
  { 0, 0, 0, 0 }, // 29
  { 0, 0, 0, 0 }, // 30
  { 0, 0, 0, 0 }, // 31
  { 0, 0, 0, 0 }, // 32
  { 0, 0, 0, 0 }, // 33
  { 0, 0, 0, 0 }, // 34
  { 0, 0, 0, 0 }, // 35
  { 0, 0, 0, 0 }, // 36
  { 0, 0, 0, 0 }, // 37
  { 0, 0, 0, 0 }, // 38
  { 0, 0, 0, 0 }, // 39
  { 0, 0, 0, 0 }, // 40
  { 0, 0, 0, 0 }, // 41
  { 0, 0, 0, 0 }, // 42
  { 0, 0, 0, 0 }, // 43
  { 0, 0, 0, 0 }, // 44
  { 0, 0, 0, 0 }, // 45
  { 0, 0, 0, 0 }, // 46
  { 0, 0, 0, 0 }, // 47
  { 0, 0, 0, 0 }, // 48
  { 0, 0, 0, 0 }, // 49
  { 0, 0, 0, 0 }, // 50
  { 0, 0, 0, 0 }, // 51
  { 0, 0, 0, 0 }, // 52
  { 0, 0, 0, 0 }, // 53
  { 0, 0, 0, 0 }, // 54
  { 0, 0, 0, 0 }, // 55
  { 0, 0, 0, 0 }, // 56
  { 0, 0, 0, 0 }, // 57
  { 0, 0, 0, 0 }, // 58
  { 0, 0, 0, 0 }, // 59
  { 0, 0, 0, 0 }, // 60
  { 0, 0, 0, 0 }, // 61
  { 0, 0, 0, 0 }, // 62
  { 0, 0, 0, 0 }, // 63
  { 0, 0, 0, 0 }, // 64
  { 0, 0, 0, 0 }, // 65
  { 0, 0, 0, 0 }, // 66
  { 0, 0, 0, 0 }, // 67
  { 0, 0, 0, 0 }, // 68
  { 0, 0, 0, 0 }, // 69
  { 0, 0, 0, 0 }, // 70
  { 0, 0, 0, 0 }, // 71
  { 0, 0, 0, 0 }, // 72
  { 0, 0, 0, 0 }, // 73
  { 0, 0, 0, 0 }, // 74
  { 0, 0, 0, 0 }, // 75
  { 0, 0, 0, 0 }, // 76
  { 0, 0, 0, 0 }, // 77
  { 0, 0, 0, 0 }, // 78
  { 0, 0, 0, 0 }, // 79
  { 0, 0, 0, 0 }, // 80
  { 0, 0, 0, 0 }, // 81
  { 0, 0, 0, 0 }, // 82
  { 0, 0, 0, 0 }, // 83
  { 0, 0, 0, 0 }, // 84
  { 0, 0, 0, 0 }, // 85
  { 0, 0, 0, 0 }, // 86
  { 0, 0, 0, 0 }, // 87
  { 0, 0, 0, 0 }, // 88
  { 0, 0, 0, 0 }, // 89
  { 0, 0, 0, 0 }, // 90
  { 0, 0, 0, 0 }, // 91
  { 0, 0, 0, 0 }, // 92
  { 0, 0, 0, 0 }, // 93
  { 0, 0, 0, 0 }, // 94
  { 0, 0, 0, 0 }, // 95
  { 0, 0, 0, 0 }, // 96
  { 0, 0, 0, 0 }, // 97
  { 0, 0, 0, 0 }, // 98
  { 0, 0, 0, 0 }, // 99
  { 0, 0, 0, 0 }, // 100
  { 0, 0, 0, 0 }, // 101
  { 0, 0, 0, 0 }, // 102
  { 0, 0, 0, 0 }, // 103
  { 0, 0, 0, 0 }, // 104
  { 0, 0, 0, 0 }, // 105
  { 0, 0, 0, 0 }, // 106
  { 0, 0, 0, 0 }, // 107
  { 0, 0, 0, 0 }, // 108
  { 0, 0, 0, 0 }, // 109
  { 0, 0, 0, 0 }, // 110
  { 0, 0, 0, 0 }, // 111
  { 0, 0, 0, 0 }, // 112
  { 0, 0, 0, 0 }, // 113
  { 0, 0, 0, 0 }, // 114
  { 0, 0, 0, 0 }, // 115
  { 0, 0, 0, 0 }, // 116
  { 0, 0, 0, 0 }, // 117
  { 0, 0, 0, 0 }, // 118
  { 0, 0, 0, 0 }, // 119
  { 0, 0, 0, 0 }, // 120
  { 0, 0, 0, 0 }, // 121
  { 0, 0, 0, 0 }, // 122
  { 0, 0, 0, 0 }, // 123
  { 0, 0, 0, 0 }, // 124
  { 0, 0, 0, 0 }, // 125
  { 0, 0, 0, 0 }, // 126
  { 0, 0, 0, 0 }, // 127
  { 0, 0, 0, 0 }, // 128
  { ~0U, ~0U, ~0U, ~0U } // end marker
};

// Sorted (by key) array of itineraries for CPU subtype.
static const llvm::SubtargetInfoKV ProcItinKV[] = {
  { "arm1020e", (void *)&GenericItineraries },
  { "arm1020t", (void *)&GenericItineraries },
  { "arm1022e", (void *)&GenericItineraries },
  { "arm10e", (void *)&GenericItineraries },
  { "arm10tdmi", (void *)&GenericItineraries },
  { "arm1136j-s", (void *)&ARMV6Itineraries },
  { "arm1136jf-s", (void *)&ARMV6Itineraries },
  { "arm1156t2-s", (void *)&ARMV6Itineraries },
  { "arm1156t2f-s", (void *)&ARMV6Itineraries },
  { "arm1176jz-s", (void *)&ARMV6Itineraries },
  { "arm1176jzf-s", (void *)&ARMV6Itineraries },
  { "arm710t", (void *)&GenericItineraries },
  { "arm720t", (void *)&GenericItineraries },
  { "arm7tdmi", (void *)&GenericItineraries },
  { "arm7tdmi-s", (void *)&GenericItineraries },
  { "arm8", (void *)&GenericItineraries },
  { "arm810", (void *)&GenericItineraries },
  { "arm9", (void *)&GenericItineraries },
  { "arm920", (void *)&GenericItineraries },
  { "arm920t", (void *)&GenericItineraries },
  { "arm922t", (void *)&GenericItineraries },
  { "arm926ej-s", (void *)&GenericItineraries },
  { "arm940t", (void *)&GenericItineraries },
  { "arm946e-s", (void *)&GenericItineraries },
  { "arm966e-s", (void *)&GenericItineraries },
  { "arm968e-s", (void *)&GenericItineraries },
  { "arm9e", (void *)&GenericItineraries },
  { "arm9tdmi", (void *)&GenericItineraries },
  { "cortex-a8", (void *)&CortexA8Itineraries },
  { "cortex-a9", (void *)&GenericItineraries },
  { "ep9312", (void *)&GenericItineraries },
  { "generic", (void *)&GenericItineraries },
  { "iwmmxt", (void *)&GenericItineraries },
  { "mpcore", (void *)&ARMV6Itineraries },
  { "mpcorenovfp", (void *)&ARMV6Itineraries },
  { "strongarm", (void *)&GenericItineraries },
  { "strongarm110", (void *)&GenericItineraries },
  { "strongarm1100", (void *)&GenericItineraries },
  { "strongarm1110", (void *)&GenericItineraries },
  { "xscale", (void *)&GenericItineraries }
};

enum {
  ProcItinKVSize = sizeof(ProcItinKV)/sizeof(llvm::SubtargetInfoKV)
};

// ParseSubtargetFeatures - Parses features string setting specified
// subtarget options.
std::string llvm::ARMSubtarget::ParseSubtargetFeatures(const std::string &FS,
                                  const std::string &CPU) {
  DEBUG(dbgs() << "\nFeatures:" << FS);
  DEBUG(dbgs() << "\nCPU:" << CPU);
  SubtargetFeatures Features(FS);
  Features.setCPUIfNone(CPU);
  uint32_t Bits =  Features.getBits(SubTypeKV, SubTypeKVSize,
                                    FeatureKV, FeatureKVSize);
  if ((Bits & ArchV4T) != 0 && ARMArchVersion < V4T) ARMArchVersion = V4T;
  if ((Bits & ArchV5T) != 0 && ARMArchVersion < V5T) ARMArchVersion = V5T;
  if ((Bits & ArchV5TE) != 0 && ARMArchVersion < V5TE) ARMArchVersion = V5TE;
  if ((Bits & ArchV6) != 0 && ARMArchVersion < V6) ARMArchVersion = V6;
  if ((Bits & ArchV6T2) != 0 && ARMArchVersion < V6T2) ARMArchVersion = V6T2;
  if ((Bits & ArchV7A) != 0 && ARMArchVersion < V7A) ARMArchVersion = V7A;
  if ((Bits & FeatureNEON) != 0 && ARMFPUType < NEON) ARMFPUType = NEON;
  if ((Bits & FeatureThumb2) != 0 && ThumbMode < Thumb2) ThumbMode = Thumb2;
  if ((Bits & FeatureVFP2) != 0 && ARMFPUType < VFPv2) ARMFPUType = VFPv2;
  if ((Bits & FeatureVFP3) != 0 && ARMFPUType < VFPv3) ARMFPUType = VFPv3;

  InstrItinerary *Itinerary = (InstrItinerary *)Features.getInfo(ProcItinKV, ProcItinKVSize);
  InstrItins = InstrItineraryData(Stages, OperandCycles, Itinerary);
  return Features.getCPU();
}
