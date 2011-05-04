//===- TableGen'erated file -------------------------------------*- C++ -*-===//
//
// "Fast" Instruction Selector for the X86 target
//
// Automatically generated file, do not edit!
//
//===----------------------------------------------------------------------===//

// FastEmit functions for ISD::Constant.

unsigned FastEmit_ISD_Constant_MVT_i8_i(MVT RetVT, uint64_t imm0) {
  if (RetVT.SimpleTy != MVT::i8)
    return 0;
  return FastEmitInst_i(X86::MOV8ri, X86::GR8RegisterClass, imm0);
}

unsigned FastEmit_ISD_Constant_MVT_i16_i(MVT RetVT, uint64_t imm0) {
  if (RetVT.SimpleTy != MVT::i16)
    return 0;
  return FastEmitInst_i(X86::MOV16ri, X86::GR16RegisterClass, imm0);
}

unsigned FastEmit_ISD_Constant_MVT_i32_i(MVT RetVT, uint64_t imm0) {
  if (RetVT.SimpleTy != MVT::i32)
    return 0;
  return FastEmitInst_i(X86::MOV32ri, X86::GR32RegisterClass, imm0);
}

unsigned FastEmit_ISD_Constant_MVT_i64_i(MVT RetVT, uint64_t imm0) {
  if (RetVT.SimpleTy != MVT::i64)
    return 0;
  return FastEmitInst_i(X86::MOV64ri, X86::GR64RegisterClass, imm0);
}

unsigned FastEmit_ISD_Constant_i(MVT VT, MVT RetVT, uint64_t imm0) {
  switch (VT.SimpleTy) {
  case MVT::i8: return FastEmit_ISD_Constant_MVT_i8_i(RetVT, imm0);
  case MVT::i16: return FastEmit_ISD_Constant_MVT_i16_i(RetVT, imm0);
  case MVT::i32: return FastEmit_ISD_Constant_MVT_i32_i(RetVT, imm0);
  case MVT::i64: return FastEmit_ISD_Constant_MVT_i64_i(RetVT, imm0);
  default: return 0;
  }
}

// Top-level FastEmit function.

unsigned FastEmit_i(MVT VT, MVT RetVT, unsigned Opcode, uint64_t imm0) {
  switch (Opcode) {
  case ISD::Constant: return FastEmit_ISD_Constant_i(VT, RetVT, imm0);
  default: return 0;
  }
}

// FastEmit functions for ISD::ANY_EXTEND.

unsigned FastEmit_ISD_ANY_EXTEND_MVT_i8_MVT_i16_r(unsigned Op0, bool Op0IsKill) {
  return FastEmitInst_r(X86::MOVZX16rr8, X86::GR16RegisterClass, Op0, Op0IsKill);
}

unsigned FastEmit_ISD_ANY_EXTEND_MVT_i8_MVT_i32_r(unsigned Op0, bool Op0IsKill) {
  return FastEmitInst_r(X86::MOVZX32rr8, X86::GR32RegisterClass, Op0, Op0IsKill);
}

unsigned FastEmit_ISD_ANY_EXTEND_MVT_i8_MVT_i64_r(unsigned Op0, bool Op0IsKill) {
  return FastEmitInst_r(X86::MOVZX64rr8, X86::GR64RegisterClass, Op0, Op0IsKill);
}

unsigned FastEmit_ISD_ANY_EXTEND_MVT_i8_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
switch (RetVT.SimpleTy) {
  case MVT::i16: return FastEmit_ISD_ANY_EXTEND_MVT_i8_MVT_i16_r(Op0, Op0IsKill);
  case MVT::i32: return FastEmit_ISD_ANY_EXTEND_MVT_i8_MVT_i32_r(Op0, Op0IsKill);
  case MVT::i64: return FastEmit_ISD_ANY_EXTEND_MVT_i8_MVT_i64_r(Op0, Op0IsKill);
  default: return 0;
}
}

unsigned FastEmit_ISD_ANY_EXTEND_MVT_i16_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
  if (RetVT.SimpleTy != MVT::i64)
    return 0;
  return FastEmitInst_r(X86::MOVZX64rr16, X86::GR64RegisterClass, Op0, Op0IsKill);
}

unsigned FastEmit_ISD_ANY_EXTEND_r(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill) {
  switch (VT.SimpleTy) {
  case MVT::i8: return FastEmit_ISD_ANY_EXTEND_MVT_i8_r(RetVT, Op0, Op0IsKill);
  case MVT::i16: return FastEmit_ISD_ANY_EXTEND_MVT_i16_r(RetVT, Op0, Op0IsKill);
  default: return 0;
  }
}

// FastEmit functions for ISD::BIT_CONVERT.

unsigned FastEmit_ISD_BIT_CONVERT_MVT_i32_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
  if (RetVT.SimpleTy != MVT::f32)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_r(X86::VMOVDI2SSrr, X86::FR32RegisterClass, Op0, Op0IsKill);
  }
  if ((Subtarget->hasSSE2())) {
    return FastEmitInst_r(X86::MOVDI2SSrr, X86::FR32RegisterClass, Op0, Op0IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_BIT_CONVERT_MVT_i64_MVT_f64_r(unsigned Op0, bool Op0IsKill) {
  if ((Subtarget->hasSSE2())) {
    return FastEmitInst_r(X86::MOV64toSDrr, X86::FR64RegisterClass, Op0, Op0IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_BIT_CONVERT_MVT_i64_MVT_v8i8_r(unsigned Op0, bool Op0IsKill) {
  return FastEmitInst_r(X86::MMX_MOVD64to64rr, X86::VR64RegisterClass, Op0, Op0IsKill);
}

unsigned FastEmit_ISD_BIT_CONVERT_MVT_i64_MVT_v4i16_r(unsigned Op0, bool Op0IsKill) {
  return FastEmitInst_r(X86::MMX_MOVD64to64rr, X86::VR64RegisterClass, Op0, Op0IsKill);
}

unsigned FastEmit_ISD_BIT_CONVERT_MVT_i64_MVT_v2i32_r(unsigned Op0, bool Op0IsKill) {
  return FastEmitInst_r(X86::MMX_MOVD64to64rr, X86::VR64RegisterClass, Op0, Op0IsKill);
}

unsigned FastEmit_ISD_BIT_CONVERT_MVT_i64_MVT_v1i64_r(unsigned Op0, bool Op0IsKill) {
  return FastEmitInst_r(X86::MMX_MOVD64to64rr, X86::VR64RegisterClass, Op0, Op0IsKill);
}

unsigned FastEmit_ISD_BIT_CONVERT_MVT_i64_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
switch (RetVT.SimpleTy) {
  case MVT::f64: return FastEmit_ISD_BIT_CONVERT_MVT_i64_MVT_f64_r(Op0, Op0IsKill);
  case MVT::v8i8: return FastEmit_ISD_BIT_CONVERT_MVT_i64_MVT_v8i8_r(Op0, Op0IsKill);
  case MVT::v4i16: return FastEmit_ISD_BIT_CONVERT_MVT_i64_MVT_v4i16_r(Op0, Op0IsKill);
  case MVT::v2i32: return FastEmit_ISD_BIT_CONVERT_MVT_i64_MVT_v2i32_r(Op0, Op0IsKill);
  case MVT::v1i64: return FastEmit_ISD_BIT_CONVERT_MVT_i64_MVT_v1i64_r(Op0, Op0IsKill);
  default: return 0;
}
}

unsigned FastEmit_ISD_BIT_CONVERT_MVT_f32_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
  if (RetVT.SimpleTy != MVT::i32)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_r(X86::VMOVSS2DIrr, X86::GR32RegisterClass, Op0, Op0IsKill);
  }
  if ((Subtarget->hasSSE2())) {
    return FastEmitInst_r(X86::MOVSS2DIrr, X86::GR32RegisterClass, Op0, Op0IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_BIT_CONVERT_MVT_f64_MVT_i64_r(unsigned Op0, bool Op0IsKill) {
  if ((Subtarget->hasSSE2())) {
    return FastEmitInst_r(X86::MOVSDto64rr, X86::GR64RegisterClass, Op0, Op0IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_BIT_CONVERT_MVT_f64_MVT_v8i8_r(unsigned Op0, bool Op0IsKill) {
  return FastEmitInst_r(X86::MMX_MOVFR642Qrr, X86::VR64RegisterClass, Op0, Op0IsKill);
}

unsigned FastEmit_ISD_BIT_CONVERT_MVT_f64_MVT_v4i16_r(unsigned Op0, bool Op0IsKill) {
  return FastEmitInst_r(X86::MMX_MOVFR642Qrr, X86::VR64RegisterClass, Op0, Op0IsKill);
}

unsigned FastEmit_ISD_BIT_CONVERT_MVT_f64_MVT_v2i32_r(unsigned Op0, bool Op0IsKill) {
  return FastEmitInst_r(X86::MMX_MOVFR642Qrr, X86::VR64RegisterClass, Op0, Op0IsKill);
}

unsigned FastEmit_ISD_BIT_CONVERT_MVT_f64_MVT_v1i64_r(unsigned Op0, bool Op0IsKill) {
  return FastEmitInst_r(X86::MMX_MOVFR642Qrr, X86::VR64RegisterClass, Op0, Op0IsKill);
}

unsigned FastEmit_ISD_BIT_CONVERT_MVT_f64_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
switch (RetVT.SimpleTy) {
  case MVT::i64: return FastEmit_ISD_BIT_CONVERT_MVT_f64_MVT_i64_r(Op0, Op0IsKill);
  case MVT::v8i8: return FastEmit_ISD_BIT_CONVERT_MVT_f64_MVT_v8i8_r(Op0, Op0IsKill);
  case MVT::v4i16: return FastEmit_ISD_BIT_CONVERT_MVT_f64_MVT_v4i16_r(Op0, Op0IsKill);
  case MVT::v2i32: return FastEmit_ISD_BIT_CONVERT_MVT_f64_MVT_v2i32_r(Op0, Op0IsKill);
  case MVT::v1i64: return FastEmit_ISD_BIT_CONVERT_MVT_f64_MVT_v1i64_r(Op0, Op0IsKill);
  default: return 0;
}
}

unsigned FastEmit_ISD_BIT_CONVERT_MVT_v8i8_MVT_i64_r(unsigned Op0, bool Op0IsKill) {
  return FastEmitInst_r(X86::MMX_MOVD64from64rr, X86::GR64RegisterClass, Op0, Op0IsKill);
}

unsigned FastEmit_ISD_BIT_CONVERT_MVT_v8i8_MVT_f64_r(unsigned Op0, bool Op0IsKill) {
  return FastEmitInst_r(X86::MMX_MOVQ2FR64rr, X86::FR64RegisterClass, Op0, Op0IsKill);
}

unsigned FastEmit_ISD_BIT_CONVERT_MVT_v8i8_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
switch (RetVT.SimpleTy) {
  case MVT::i64: return FastEmit_ISD_BIT_CONVERT_MVT_v8i8_MVT_i64_r(Op0, Op0IsKill);
  case MVT::f64: return FastEmit_ISD_BIT_CONVERT_MVT_v8i8_MVT_f64_r(Op0, Op0IsKill);
  default: return 0;
}
}

unsigned FastEmit_ISD_BIT_CONVERT_MVT_v4i16_MVT_i64_r(unsigned Op0, bool Op0IsKill) {
  return FastEmitInst_r(X86::MMX_MOVD64from64rr, X86::GR64RegisterClass, Op0, Op0IsKill);
}

unsigned FastEmit_ISD_BIT_CONVERT_MVT_v4i16_MVT_f64_r(unsigned Op0, bool Op0IsKill) {
  return FastEmitInst_r(X86::MMX_MOVQ2FR64rr, X86::FR64RegisterClass, Op0, Op0IsKill);
}

unsigned FastEmit_ISD_BIT_CONVERT_MVT_v4i16_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
switch (RetVT.SimpleTy) {
  case MVT::i64: return FastEmit_ISD_BIT_CONVERT_MVT_v4i16_MVT_i64_r(Op0, Op0IsKill);
  case MVT::f64: return FastEmit_ISD_BIT_CONVERT_MVT_v4i16_MVT_f64_r(Op0, Op0IsKill);
  default: return 0;
}
}

unsigned FastEmit_ISD_BIT_CONVERT_MVT_v2i32_MVT_i64_r(unsigned Op0, bool Op0IsKill) {
  return FastEmitInst_r(X86::MMX_MOVD64from64rr, X86::GR64RegisterClass, Op0, Op0IsKill);
}

unsigned FastEmit_ISD_BIT_CONVERT_MVT_v2i32_MVT_f64_r(unsigned Op0, bool Op0IsKill) {
  return FastEmitInst_r(X86::MMX_MOVQ2FR64rr, X86::FR64RegisterClass, Op0, Op0IsKill);
}

unsigned FastEmit_ISD_BIT_CONVERT_MVT_v2i32_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
switch (RetVT.SimpleTy) {
  case MVT::i64: return FastEmit_ISD_BIT_CONVERT_MVT_v2i32_MVT_i64_r(Op0, Op0IsKill);
  case MVT::f64: return FastEmit_ISD_BIT_CONVERT_MVT_v2i32_MVT_f64_r(Op0, Op0IsKill);
  default: return 0;
}
}

unsigned FastEmit_ISD_BIT_CONVERT_MVT_v1i64_MVT_i64_r(unsigned Op0, bool Op0IsKill) {
  return FastEmitInst_r(X86::MMX_MOVD64from64rr, X86::GR64RegisterClass, Op0, Op0IsKill);
}

unsigned FastEmit_ISD_BIT_CONVERT_MVT_v1i64_MVT_f64_r(unsigned Op0, bool Op0IsKill) {
  return FastEmitInst_r(X86::MMX_MOVQ2FR64rr, X86::FR64RegisterClass, Op0, Op0IsKill);
}

unsigned FastEmit_ISD_BIT_CONVERT_MVT_v1i64_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
switch (RetVT.SimpleTy) {
  case MVT::i64: return FastEmit_ISD_BIT_CONVERT_MVT_v1i64_MVT_i64_r(Op0, Op0IsKill);
  case MVT::f64: return FastEmit_ISD_BIT_CONVERT_MVT_v1i64_MVT_f64_r(Op0, Op0IsKill);
  default: return 0;
}
}

unsigned FastEmit_ISD_BIT_CONVERT_r(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill) {
  switch (VT.SimpleTy) {
  case MVT::i32: return FastEmit_ISD_BIT_CONVERT_MVT_i32_r(RetVT, Op0, Op0IsKill);
  case MVT::i64: return FastEmit_ISD_BIT_CONVERT_MVT_i64_r(RetVT, Op0, Op0IsKill);
  case MVT::f32: return FastEmit_ISD_BIT_CONVERT_MVT_f32_r(RetVT, Op0, Op0IsKill);
  case MVT::f64: return FastEmit_ISD_BIT_CONVERT_MVT_f64_r(RetVT, Op0, Op0IsKill);
  case MVT::v8i8: return FastEmit_ISD_BIT_CONVERT_MVT_v8i8_r(RetVT, Op0, Op0IsKill);
  case MVT::v4i16: return FastEmit_ISD_BIT_CONVERT_MVT_v4i16_r(RetVT, Op0, Op0IsKill);
  case MVT::v2i32: return FastEmit_ISD_BIT_CONVERT_MVT_v2i32_r(RetVT, Op0, Op0IsKill);
  case MVT::v1i64: return FastEmit_ISD_BIT_CONVERT_MVT_v1i64_r(RetVT, Op0, Op0IsKill);
  default: return 0;
  }
}

// FastEmit functions for ISD::BRIND.

unsigned FastEmit_ISD_BRIND_MVT_i32_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
  if (RetVT.SimpleTy != MVT::isVoid)
    return 0;
  if ((!Subtarget->is64Bit())) {
    return FastEmitInst_r(X86::JMP32r, X86::GR32RegisterClass, Op0, Op0IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_BRIND_MVT_i64_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
  if (RetVT.SimpleTy != MVT::isVoid)
    return 0;
  if ((Subtarget->is64Bit())) {
    return FastEmitInst_r(X86::JMP64r, X86::GR64RegisterClass, Op0, Op0IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_BRIND_r(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill) {
  switch (VT.SimpleTy) {
  case MVT::i32: return FastEmit_ISD_BRIND_MVT_i32_r(RetVT, Op0, Op0IsKill);
  case MVT::i64: return FastEmit_ISD_BRIND_MVT_i64_r(RetVT, Op0, Op0IsKill);
  default: return 0;
  }
}

// FastEmit functions for ISD::BSWAP.

unsigned FastEmit_ISD_BSWAP_MVT_i32_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
  if (RetVT.SimpleTy != MVT::i32)
    return 0;
  return FastEmitInst_r(X86::BSWAP32r, X86::GR32RegisterClass, Op0, Op0IsKill);
}

unsigned FastEmit_ISD_BSWAP_MVT_i64_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
  if (RetVT.SimpleTy != MVT::i64)
    return 0;
  return FastEmitInst_r(X86::BSWAP64r, X86::GR64RegisterClass, Op0, Op0IsKill);
}

unsigned FastEmit_ISD_BSWAP_r(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill) {
  switch (VT.SimpleTy) {
  case MVT::i32: return FastEmit_ISD_BSWAP_MVT_i32_r(RetVT, Op0, Op0IsKill);
  case MVT::i64: return FastEmit_ISD_BSWAP_MVT_i64_r(RetVT, Op0, Op0IsKill);
  default: return 0;
  }
}

// FastEmit functions for ISD::FABS.

unsigned FastEmit_ISD_FABS_MVT_f32_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
  if (RetVT.SimpleTy != MVT::f32)
    return 0;
  if ((!Subtarget->hasSSE1())) {
    return FastEmitInst_r(X86::ABS_Fp32, X86::RFP32RegisterClass, Op0, Op0IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_FABS_MVT_f64_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
  if (RetVT.SimpleTy != MVT::f64)
    return 0;
  if ((!Subtarget->hasSSE2())) {
    return FastEmitInst_r(X86::ABS_Fp64, X86::RFP64RegisterClass, Op0, Op0IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_FABS_MVT_f80_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
  if (RetVT.SimpleTy != MVT::f80)
    return 0;
  return FastEmitInst_r(X86::ABS_Fp80, X86::RFP80RegisterClass, Op0, Op0IsKill);
}

unsigned FastEmit_ISD_FABS_r(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill) {
  switch (VT.SimpleTy) {
  case MVT::f32: return FastEmit_ISD_FABS_MVT_f32_r(RetVT, Op0, Op0IsKill);
  case MVT::f64: return FastEmit_ISD_FABS_MVT_f64_r(RetVT, Op0, Op0IsKill);
  case MVT::f80: return FastEmit_ISD_FABS_MVT_f80_r(RetVT, Op0, Op0IsKill);
  default: return 0;
  }
}

// FastEmit functions for ISD::FCOS.

unsigned FastEmit_ISD_FCOS_MVT_f32_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
  if (RetVT.SimpleTy != MVT::f32)
    return 0;
  if ((!Subtarget->hasSSE1())) {
    return FastEmitInst_r(X86::COS_Fp32, X86::RFP32RegisterClass, Op0, Op0IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_FCOS_MVT_f64_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
  if (RetVT.SimpleTy != MVT::f64)
    return 0;
  if ((!Subtarget->hasSSE2())) {
    return FastEmitInst_r(X86::COS_Fp64, X86::RFP64RegisterClass, Op0, Op0IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_FCOS_MVT_f80_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
  if (RetVT.SimpleTy != MVT::f80)
    return 0;
  return FastEmitInst_r(X86::COS_Fp80, X86::RFP80RegisterClass, Op0, Op0IsKill);
}

unsigned FastEmit_ISD_FCOS_r(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill) {
  switch (VT.SimpleTy) {
  case MVT::f32: return FastEmit_ISD_FCOS_MVT_f32_r(RetVT, Op0, Op0IsKill);
  case MVT::f64: return FastEmit_ISD_FCOS_MVT_f64_r(RetVT, Op0, Op0IsKill);
  case MVT::f80: return FastEmit_ISD_FCOS_MVT_f80_r(RetVT, Op0, Op0IsKill);
  default: return 0;
  }
}

// FastEmit functions for ISD::FNEG.

unsigned FastEmit_ISD_FNEG_MVT_f32_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
  if (RetVT.SimpleTy != MVT::f32)
    return 0;
  if ((!Subtarget->hasSSE1())) {
    return FastEmitInst_r(X86::CHS_Fp32, X86::RFP32RegisterClass, Op0, Op0IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_FNEG_MVT_f64_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
  if (RetVT.SimpleTy != MVT::f64)
    return 0;
  if ((!Subtarget->hasSSE2())) {
    return FastEmitInst_r(X86::CHS_Fp64, X86::RFP64RegisterClass, Op0, Op0IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_FNEG_MVT_f80_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
  if (RetVT.SimpleTy != MVT::f80)
    return 0;
  return FastEmitInst_r(X86::CHS_Fp80, X86::RFP80RegisterClass, Op0, Op0IsKill);
}

unsigned FastEmit_ISD_FNEG_r(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill) {
  switch (VT.SimpleTy) {
  case MVT::f32: return FastEmit_ISD_FNEG_MVT_f32_r(RetVT, Op0, Op0IsKill);
  case MVT::f64: return FastEmit_ISD_FNEG_MVT_f64_r(RetVT, Op0, Op0IsKill);
  case MVT::f80: return FastEmit_ISD_FNEG_MVT_f80_r(RetVT, Op0, Op0IsKill);
  default: return 0;
  }
}

// FastEmit functions for ISD::FP_EXTEND.

unsigned FastEmit_ISD_FP_EXTEND_MVT_f32_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
  if (RetVT.SimpleTy != MVT::f64)
    return 0;
  if ((Subtarget->hasSSE2())) {
    return FastEmitInst_r(X86::CVTSS2SDrr, X86::FR64RegisterClass, Op0, Op0IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_FP_EXTEND_r(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill) {
  switch (VT.SimpleTy) {
  case MVT::f32: return FastEmit_ISD_FP_EXTEND_MVT_f32_r(RetVT, Op0, Op0IsKill);
  default: return 0;
  }
}

// FastEmit functions for ISD::FP_ROUND.

unsigned FastEmit_ISD_FP_ROUND_MVT_f64_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
  if (RetVT.SimpleTy != MVT::f32)
    return 0;
  if ((Subtarget->hasSSE2())) {
    return FastEmitInst_r(X86::CVTSD2SSrr, X86::FR32RegisterClass, Op0, Op0IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_FP_ROUND_r(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill) {
  switch (VT.SimpleTy) {
  case MVT::f64: return FastEmit_ISD_FP_ROUND_MVT_f64_r(RetVT, Op0, Op0IsKill);
  default: return 0;
  }
}

// FastEmit functions for ISD::FP_TO_SINT.

unsigned FastEmit_ISD_FP_TO_SINT_MVT_f32_MVT_i32_r(unsigned Op0, bool Op0IsKill) {
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_r(X86::VCVTTSS2SIrr, X86::GR32RegisterClass, Op0, Op0IsKill);
  }
  if ((Subtarget->hasSSE1())) {
    return FastEmitInst_r(X86::CVTTSS2SIrr, X86::GR32RegisterClass, Op0, Op0IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_FP_TO_SINT_MVT_f32_MVT_i64_r(unsigned Op0, bool Op0IsKill) {
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_r(X86::VCVTTSS2SI64rr, X86::GR64RegisterClass, Op0, Op0IsKill);
  }
  if ((Subtarget->hasSSE1())) {
    return FastEmitInst_r(X86::CVTTSS2SI64rr, X86::GR64RegisterClass, Op0, Op0IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_FP_TO_SINT_MVT_f32_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
switch (RetVT.SimpleTy) {
  case MVT::i32: return FastEmit_ISD_FP_TO_SINT_MVT_f32_MVT_i32_r(Op0, Op0IsKill);
  case MVT::i64: return FastEmit_ISD_FP_TO_SINT_MVT_f32_MVT_i64_r(Op0, Op0IsKill);
  default: return 0;
}
}

unsigned FastEmit_ISD_FP_TO_SINT_MVT_f64_MVT_i32_r(unsigned Op0, bool Op0IsKill) {
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_r(X86::VCVTTSD2SIrr, X86::GR32RegisterClass, Op0, Op0IsKill);
  }
  if ((Subtarget->hasSSE2())) {
    return FastEmitInst_r(X86::CVTTSD2SIrr, X86::GR32RegisterClass, Op0, Op0IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_FP_TO_SINT_MVT_f64_MVT_i64_r(unsigned Op0, bool Op0IsKill) {
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_r(X86::VCVTTSD2SI64rr, X86::GR64RegisterClass, Op0, Op0IsKill);
  }
  if ((Subtarget->hasSSE2())) {
    return FastEmitInst_r(X86::CVTTSD2SI64rr, X86::GR64RegisterClass, Op0, Op0IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_FP_TO_SINT_MVT_f64_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
switch (RetVT.SimpleTy) {
  case MVT::i32: return FastEmit_ISD_FP_TO_SINT_MVT_f64_MVT_i32_r(Op0, Op0IsKill);
  case MVT::i64: return FastEmit_ISD_FP_TO_SINT_MVT_f64_MVT_i64_r(Op0, Op0IsKill);
  default: return 0;
}
}

unsigned FastEmit_ISD_FP_TO_SINT_MVT_v4f32_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
  if (RetVT.SimpleTy != MVT::v4i32)
    return 0;
  if ((Subtarget->hasSSE2())) {
    return FastEmitInst_r(X86::Int_CVTTPS2DQrr, X86::VR128RegisterClass, Op0, Op0IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_FP_TO_SINT_MVT_v2f64_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
  if (RetVT.SimpleTy != MVT::v2i32)
    return 0;
  if ((Subtarget->hasSSE2())) {
    return FastEmitInst_r(X86::Int_CVTTPD2PIrr, X86::VR64RegisterClass, Op0, Op0IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_FP_TO_SINT_r(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill) {
  switch (VT.SimpleTy) {
  case MVT::f32: return FastEmit_ISD_FP_TO_SINT_MVT_f32_r(RetVT, Op0, Op0IsKill);
  case MVT::f64: return FastEmit_ISD_FP_TO_SINT_MVT_f64_r(RetVT, Op0, Op0IsKill);
  case MVT::v4f32: return FastEmit_ISD_FP_TO_SINT_MVT_v4f32_r(RetVT, Op0, Op0IsKill);
  case MVT::v2f64: return FastEmit_ISD_FP_TO_SINT_MVT_v2f64_r(RetVT, Op0, Op0IsKill);
  default: return 0;
  }
}

// FastEmit functions for ISD::FSIN.

unsigned FastEmit_ISD_FSIN_MVT_f32_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
  if (RetVT.SimpleTy != MVT::f32)
    return 0;
  if ((!Subtarget->hasSSE1())) {
    return FastEmitInst_r(X86::SIN_Fp32, X86::RFP32RegisterClass, Op0, Op0IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_FSIN_MVT_f64_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
  if (RetVT.SimpleTy != MVT::f64)
    return 0;
  if ((!Subtarget->hasSSE2())) {
    return FastEmitInst_r(X86::SIN_Fp64, X86::RFP64RegisterClass, Op0, Op0IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_FSIN_MVT_f80_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
  if (RetVT.SimpleTy != MVT::f80)
    return 0;
  return FastEmitInst_r(X86::SIN_Fp80, X86::RFP80RegisterClass, Op0, Op0IsKill);
}

unsigned FastEmit_ISD_FSIN_r(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill) {
  switch (VT.SimpleTy) {
  case MVT::f32: return FastEmit_ISD_FSIN_MVT_f32_r(RetVT, Op0, Op0IsKill);
  case MVT::f64: return FastEmit_ISD_FSIN_MVT_f64_r(RetVT, Op0, Op0IsKill);
  case MVT::f80: return FastEmit_ISD_FSIN_MVT_f80_r(RetVT, Op0, Op0IsKill);
  default: return 0;
  }
}

// FastEmit functions for ISD::FSQRT.

unsigned FastEmit_ISD_FSQRT_MVT_f32_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
  if (RetVT.SimpleTy != MVT::f32)
    return 0;
  if ((!Subtarget->hasSSE1())) {
    return FastEmitInst_r(X86::SQRT_Fp32, X86::RFP32RegisterClass, Op0, Op0IsKill);
  }
  if ((Subtarget->hasSSE1())) {
    return FastEmitInst_r(X86::SQRTSSr, X86::FR32RegisterClass, Op0, Op0IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_FSQRT_MVT_f64_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
  if (RetVT.SimpleTy != MVT::f64)
    return 0;
  if ((!Subtarget->hasSSE2())) {
    return FastEmitInst_r(X86::SQRT_Fp64, X86::RFP64RegisterClass, Op0, Op0IsKill);
  }
  if ((Subtarget->hasSSE2())) {
    return FastEmitInst_r(X86::SQRTSDr, X86::FR64RegisterClass, Op0, Op0IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_FSQRT_MVT_f80_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
  if (RetVT.SimpleTy != MVT::f80)
    return 0;
  return FastEmitInst_r(X86::SQRT_Fp80, X86::RFP80RegisterClass, Op0, Op0IsKill);
}

unsigned FastEmit_ISD_FSQRT_MVT_v4f32_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
  if (RetVT.SimpleTy != MVT::v4f32)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_r(X86::VSQRTPSr, X86::VR128RegisterClass, Op0, Op0IsKill);
  }
  if ((Subtarget->hasSSE1())) {
    return FastEmitInst_r(X86::SQRTPSr, X86::VR128RegisterClass, Op0, Op0IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_FSQRT_MVT_v8f32_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
  if (RetVT.SimpleTy != MVT::v8f32)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_r(X86::VSQRTPSYr, X86::VR256RegisterClass, Op0, Op0IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_FSQRT_MVT_v2f64_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
  if (RetVT.SimpleTy != MVT::v2f64)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_r(X86::VSQRTPDr, X86::VR128RegisterClass, Op0, Op0IsKill);
  }
  if ((Subtarget->hasSSE2())) {
    return FastEmitInst_r(X86::SQRTPDr, X86::VR128RegisterClass, Op0, Op0IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_FSQRT_MVT_v4f64_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
  if (RetVT.SimpleTy != MVT::v4f64)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_r(X86::VSQRTPDYr, X86::VR256RegisterClass, Op0, Op0IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_FSQRT_r(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill) {
  switch (VT.SimpleTy) {
  case MVT::f32: return FastEmit_ISD_FSQRT_MVT_f32_r(RetVT, Op0, Op0IsKill);
  case MVT::f64: return FastEmit_ISD_FSQRT_MVT_f64_r(RetVT, Op0, Op0IsKill);
  case MVT::f80: return FastEmit_ISD_FSQRT_MVT_f80_r(RetVT, Op0, Op0IsKill);
  case MVT::v4f32: return FastEmit_ISD_FSQRT_MVT_v4f32_r(RetVT, Op0, Op0IsKill);
  case MVT::v8f32: return FastEmit_ISD_FSQRT_MVT_v8f32_r(RetVT, Op0, Op0IsKill);
  case MVT::v2f64: return FastEmit_ISD_FSQRT_MVT_v2f64_r(RetVT, Op0, Op0IsKill);
  case MVT::v4f64: return FastEmit_ISD_FSQRT_MVT_v4f64_r(RetVT, Op0, Op0IsKill);
  default: return 0;
  }
}

// FastEmit functions for ISD::SCALAR_TO_VECTOR.

unsigned FastEmit_ISD_SCALAR_TO_VECTOR_MVT_i32_MVT_v2i32_r(unsigned Op0, bool Op0IsKill) {
  if ((Subtarget->hasMMX() && !Subtarget->hasAVX())) {
    return FastEmitInst_r(X86::MMX_MOVD64rr, X86::VR64RegisterClass, Op0, Op0IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_SCALAR_TO_VECTOR_MVT_i32_MVT_v4i32_r(unsigned Op0, bool Op0IsKill) {
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_r(X86::VMOVDI2PDIrr, X86::VR128RegisterClass, Op0, Op0IsKill);
  }
  if ((Subtarget->hasSSE2())) {
    return FastEmitInst_r(X86::MOVDI2PDIrr, X86::VR128RegisterClass, Op0, Op0IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_SCALAR_TO_VECTOR_MVT_i32_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
switch (RetVT.SimpleTy) {
  case MVT::v2i32: return FastEmit_ISD_SCALAR_TO_VECTOR_MVT_i32_MVT_v2i32_r(Op0, Op0IsKill);
  case MVT::v4i32: return FastEmit_ISD_SCALAR_TO_VECTOR_MVT_i32_MVT_v4i32_r(Op0, Op0IsKill);
  default: return 0;
}
}

unsigned FastEmit_ISD_SCALAR_TO_VECTOR_MVT_i64_MVT_v1i64_r(unsigned Op0, bool Op0IsKill) {
  if ((Subtarget->hasMMX() && !Subtarget->hasAVX())) {
    return FastEmitInst_r(X86::MMX_MOVD64rrv164, X86::VR64RegisterClass, Op0, Op0IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_SCALAR_TO_VECTOR_MVT_i64_MVT_v2i64_r(unsigned Op0, bool Op0IsKill) {
  if ((Subtarget->hasSSE2())) {
    return FastEmitInst_r(X86::MOV64toPQIrr, X86::VR128RegisterClass, Op0, Op0IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_SCALAR_TO_VECTOR_MVT_i64_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
switch (RetVT.SimpleTy) {
  case MVT::v1i64: return FastEmit_ISD_SCALAR_TO_VECTOR_MVT_i64_MVT_v1i64_r(Op0, Op0IsKill);
  case MVT::v2i64: return FastEmit_ISD_SCALAR_TO_VECTOR_MVT_i64_MVT_v2i64_r(Op0, Op0IsKill);
  default: return 0;
}
}

unsigned FastEmit_ISD_SCALAR_TO_VECTOR_r(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill) {
  switch (VT.SimpleTy) {
  case MVT::i32: return FastEmit_ISD_SCALAR_TO_VECTOR_MVT_i32_r(RetVT, Op0, Op0IsKill);
  case MVT::i64: return FastEmit_ISD_SCALAR_TO_VECTOR_MVT_i64_r(RetVT, Op0, Op0IsKill);
  default: return 0;
  }
}

// FastEmit functions for ISD::SIGN_EXTEND.

unsigned FastEmit_ISD_SIGN_EXTEND_MVT_i8_MVT_i16_r(unsigned Op0, bool Op0IsKill) {
  return FastEmitInst_r(X86::MOVSX16rr8, X86::GR16RegisterClass, Op0, Op0IsKill);
}

unsigned FastEmit_ISD_SIGN_EXTEND_MVT_i8_MVT_i32_r(unsigned Op0, bool Op0IsKill) {
  return FastEmitInst_r(X86::MOVSX32rr8, X86::GR32RegisterClass, Op0, Op0IsKill);
}

unsigned FastEmit_ISD_SIGN_EXTEND_MVT_i8_MVT_i64_r(unsigned Op0, bool Op0IsKill) {
  return FastEmitInst_r(X86::MOVSX64rr8, X86::GR64RegisterClass, Op0, Op0IsKill);
}

unsigned FastEmit_ISD_SIGN_EXTEND_MVT_i8_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
switch (RetVT.SimpleTy) {
  case MVT::i16: return FastEmit_ISD_SIGN_EXTEND_MVT_i8_MVT_i16_r(Op0, Op0IsKill);
  case MVT::i32: return FastEmit_ISD_SIGN_EXTEND_MVT_i8_MVT_i32_r(Op0, Op0IsKill);
  case MVT::i64: return FastEmit_ISD_SIGN_EXTEND_MVT_i8_MVT_i64_r(Op0, Op0IsKill);
  default: return 0;
}
}

unsigned FastEmit_ISD_SIGN_EXTEND_MVT_i16_MVT_i32_r(unsigned Op0, bool Op0IsKill) {
  return FastEmitInst_r(X86::MOVSX32rr16, X86::GR32RegisterClass, Op0, Op0IsKill);
}

unsigned FastEmit_ISD_SIGN_EXTEND_MVT_i16_MVT_i64_r(unsigned Op0, bool Op0IsKill) {
  return FastEmitInst_r(X86::MOVSX64rr16, X86::GR64RegisterClass, Op0, Op0IsKill);
}

unsigned FastEmit_ISD_SIGN_EXTEND_MVT_i16_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
switch (RetVT.SimpleTy) {
  case MVT::i32: return FastEmit_ISD_SIGN_EXTEND_MVT_i16_MVT_i32_r(Op0, Op0IsKill);
  case MVT::i64: return FastEmit_ISD_SIGN_EXTEND_MVT_i16_MVT_i64_r(Op0, Op0IsKill);
  default: return 0;
}
}

unsigned FastEmit_ISD_SIGN_EXTEND_MVT_i32_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
  if (RetVT.SimpleTy != MVT::i64)
    return 0;
  return FastEmitInst_r(X86::MOVSX64rr32, X86::GR64RegisterClass, Op0, Op0IsKill);
}

unsigned FastEmit_ISD_SIGN_EXTEND_r(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill) {
  switch (VT.SimpleTy) {
  case MVT::i8: return FastEmit_ISD_SIGN_EXTEND_MVT_i8_r(RetVT, Op0, Op0IsKill);
  case MVT::i16: return FastEmit_ISD_SIGN_EXTEND_MVT_i16_r(RetVT, Op0, Op0IsKill);
  case MVT::i32: return FastEmit_ISD_SIGN_EXTEND_MVT_i32_r(RetVT, Op0, Op0IsKill);
  default: return 0;
  }
}

// FastEmit functions for ISD::SINT_TO_FP.

unsigned FastEmit_ISD_SINT_TO_FP_MVT_i32_MVT_f32_r(unsigned Op0, bool Op0IsKill) {
  if ((Subtarget->hasSSE1())) {
    return FastEmitInst_r(X86::CVTSI2SSrr, X86::FR32RegisterClass, Op0, Op0IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_SINT_TO_FP_MVT_i32_MVT_f64_r(unsigned Op0, bool Op0IsKill) {
  if ((Subtarget->hasSSE2())) {
    return FastEmitInst_r(X86::CVTSI2SDrr, X86::FR64RegisterClass, Op0, Op0IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_SINT_TO_FP_MVT_i32_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
switch (RetVT.SimpleTy) {
  case MVT::f32: return FastEmit_ISD_SINT_TO_FP_MVT_i32_MVT_f32_r(Op0, Op0IsKill);
  case MVT::f64: return FastEmit_ISD_SINT_TO_FP_MVT_i32_MVT_f64_r(Op0, Op0IsKill);
  default: return 0;
}
}

unsigned FastEmit_ISD_SINT_TO_FP_MVT_i64_MVT_f32_r(unsigned Op0, bool Op0IsKill) {
  if ((Subtarget->hasSSE1())) {
    return FastEmitInst_r(X86::CVTSI2SS64rr, X86::FR32RegisterClass, Op0, Op0IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_SINT_TO_FP_MVT_i64_MVT_f64_r(unsigned Op0, bool Op0IsKill) {
  if ((Subtarget->hasSSE2())) {
    return FastEmitInst_r(X86::CVTSI2SD64rr, X86::FR64RegisterClass, Op0, Op0IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_SINT_TO_FP_MVT_i64_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
switch (RetVT.SimpleTy) {
  case MVT::f32: return FastEmit_ISD_SINT_TO_FP_MVT_i64_MVT_f32_r(Op0, Op0IsKill);
  case MVT::f64: return FastEmit_ISD_SINT_TO_FP_MVT_i64_MVT_f64_r(Op0, Op0IsKill);
  default: return 0;
}
}

unsigned FastEmit_ISD_SINT_TO_FP_MVT_v2i32_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
  if (RetVT.SimpleTy != MVT::v2f64)
    return 0;
  if ((Subtarget->hasSSE2())) {
    return FastEmitInst_r(X86::Int_CVTPI2PDrr, X86::VR128RegisterClass, Op0, Op0IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_SINT_TO_FP_MVT_v4i32_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
  if (RetVT.SimpleTy != MVT::v4f32)
    return 0;
  if ((Subtarget->hasSSE2())) {
    return FastEmitInst_r(X86::Int_CVTDQ2PSrr, X86::VR128RegisterClass, Op0, Op0IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_SINT_TO_FP_r(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill) {
  switch (VT.SimpleTy) {
  case MVT::i32: return FastEmit_ISD_SINT_TO_FP_MVT_i32_r(RetVT, Op0, Op0IsKill);
  case MVT::i64: return FastEmit_ISD_SINT_TO_FP_MVT_i64_r(RetVT, Op0, Op0IsKill);
  case MVT::v2i32: return FastEmit_ISD_SINT_TO_FP_MVT_v2i32_r(RetVT, Op0, Op0IsKill);
  case MVT::v4i32: return FastEmit_ISD_SINT_TO_FP_MVT_v4i32_r(RetVT, Op0, Op0IsKill);
  default: return 0;
  }
}

// FastEmit functions for ISD::TRUNCATE.

unsigned FastEmit_ISD_TRUNCATE_MVT_i16_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
  if (RetVT.SimpleTy != MVT::i8)
    return 0;
  if ((Subtarget->is64Bit())) {
    return FastEmitInst_extractsubreg(RetVT, Op0, Op0IsKill, X86::sub_8bit);
  }
  return 0;
}

unsigned FastEmit_ISD_TRUNCATE_MVT_i32_MVT_i8_r(unsigned Op0, bool Op0IsKill) {
  if ((Subtarget->is64Bit())) {
    return FastEmitInst_extractsubreg(MVT::i8, Op0, Op0IsKill, X86::sub_8bit);
  }
  return 0;
}

unsigned FastEmit_ISD_TRUNCATE_MVT_i32_MVT_i16_r(unsigned Op0, bool Op0IsKill) {
  return FastEmitInst_extractsubreg(MVT::i16, Op0, Op0IsKill, X86::sub_16bit);
}

unsigned FastEmit_ISD_TRUNCATE_MVT_i32_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
switch (RetVT.SimpleTy) {
  case MVT::i8: return FastEmit_ISD_TRUNCATE_MVT_i32_MVT_i8_r(Op0, Op0IsKill);
  case MVT::i16: return FastEmit_ISD_TRUNCATE_MVT_i32_MVT_i16_r(Op0, Op0IsKill);
  default: return 0;
}
}

unsigned FastEmit_ISD_TRUNCATE_MVT_i64_MVT_i8_r(unsigned Op0, bool Op0IsKill) {
  return FastEmitInst_extractsubreg(MVT::i8, Op0, Op0IsKill, X86::sub_8bit);
}

unsigned FastEmit_ISD_TRUNCATE_MVT_i64_MVT_i16_r(unsigned Op0, bool Op0IsKill) {
  return FastEmitInst_extractsubreg(MVT::i16, Op0, Op0IsKill, X86::sub_16bit);
}

unsigned FastEmit_ISD_TRUNCATE_MVT_i64_MVT_i32_r(unsigned Op0, bool Op0IsKill) {
  return FastEmitInst_extractsubreg(MVT::i32, Op0, Op0IsKill, X86::sub_32bit);
}

unsigned FastEmit_ISD_TRUNCATE_MVT_i64_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
switch (RetVT.SimpleTy) {
  case MVT::i8: return FastEmit_ISD_TRUNCATE_MVT_i64_MVT_i8_r(Op0, Op0IsKill);
  case MVT::i16: return FastEmit_ISD_TRUNCATE_MVT_i64_MVT_i16_r(Op0, Op0IsKill);
  case MVT::i32: return FastEmit_ISD_TRUNCATE_MVT_i64_MVT_i32_r(Op0, Op0IsKill);
  default: return 0;
}
}

unsigned FastEmit_ISD_TRUNCATE_r(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill) {
  switch (VT.SimpleTy) {
  case MVT::i16: return FastEmit_ISD_TRUNCATE_MVT_i16_r(RetVT, Op0, Op0IsKill);
  case MVT::i32: return FastEmit_ISD_TRUNCATE_MVT_i32_r(RetVT, Op0, Op0IsKill);
  case MVT::i64: return FastEmit_ISD_TRUNCATE_MVT_i64_r(RetVT, Op0, Op0IsKill);
  default: return 0;
  }
}

// FastEmit functions for ISD::ZERO_EXTEND.

unsigned FastEmit_ISD_ZERO_EXTEND_MVT_i8_MVT_i16_r(unsigned Op0, bool Op0IsKill) {
  return FastEmitInst_r(X86::MOVZX16rr8, X86::GR16RegisterClass, Op0, Op0IsKill);
}

unsigned FastEmit_ISD_ZERO_EXTEND_MVT_i8_MVT_i32_r(unsigned Op0, bool Op0IsKill) {
  return FastEmitInst_r(X86::MOVZX32rr8, X86::GR32RegisterClass, Op0, Op0IsKill);
}

unsigned FastEmit_ISD_ZERO_EXTEND_MVT_i8_MVT_i64_r(unsigned Op0, bool Op0IsKill) {
  return FastEmitInst_r(X86::MOVZX64rr8, X86::GR64RegisterClass, Op0, Op0IsKill);
}

unsigned FastEmit_ISD_ZERO_EXTEND_MVT_i8_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
switch (RetVT.SimpleTy) {
  case MVT::i16: return FastEmit_ISD_ZERO_EXTEND_MVT_i8_MVT_i16_r(Op0, Op0IsKill);
  case MVT::i32: return FastEmit_ISD_ZERO_EXTEND_MVT_i8_MVT_i32_r(Op0, Op0IsKill);
  case MVT::i64: return FastEmit_ISD_ZERO_EXTEND_MVT_i8_MVT_i64_r(Op0, Op0IsKill);
  default: return 0;
}
}

unsigned FastEmit_ISD_ZERO_EXTEND_MVT_i16_MVT_i32_r(unsigned Op0, bool Op0IsKill) {
  return FastEmitInst_r(X86::MOVZX32rr16, X86::GR32RegisterClass, Op0, Op0IsKill);
}

unsigned FastEmit_ISD_ZERO_EXTEND_MVT_i16_MVT_i64_r(unsigned Op0, bool Op0IsKill) {
  return FastEmitInst_r(X86::MOVZX64rr16, X86::GR64RegisterClass, Op0, Op0IsKill);
}

unsigned FastEmit_ISD_ZERO_EXTEND_MVT_i16_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
switch (RetVT.SimpleTy) {
  case MVT::i32: return FastEmit_ISD_ZERO_EXTEND_MVT_i16_MVT_i32_r(Op0, Op0IsKill);
  case MVT::i64: return FastEmit_ISD_ZERO_EXTEND_MVT_i16_MVT_i64_r(Op0, Op0IsKill);
  default: return 0;
}
}

unsigned FastEmit_ISD_ZERO_EXTEND_MVT_i32_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
  if (RetVT.SimpleTy != MVT::i64)
    return 0;
  return FastEmitInst_r(X86::MOVZX64rr32, X86::GR64RegisterClass, Op0, Op0IsKill);
}

unsigned FastEmit_ISD_ZERO_EXTEND_r(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill) {
  switch (VT.SimpleTy) {
  case MVT::i8: return FastEmit_ISD_ZERO_EXTEND_MVT_i8_r(RetVT, Op0, Op0IsKill);
  case MVT::i16: return FastEmit_ISD_ZERO_EXTEND_MVT_i16_r(RetVT, Op0, Op0IsKill);
  case MVT::i32: return FastEmit_ISD_ZERO_EXTEND_MVT_i32_r(RetVT, Op0, Op0IsKill);
  default: return 0;
  }
}

// FastEmit functions for X86ISD::CALL.

unsigned FastEmit_X86ISD_CALL_MVT_i32_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
  if (RetVT.SimpleTy != MVT::isVoid)
    return 0;
  return FastEmitInst_r(X86::CALL32r, X86::GR32RegisterClass, Op0, Op0IsKill);
}

unsigned FastEmit_X86ISD_CALL_MVT_i64_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
  if (RetVT.SimpleTy != MVT::isVoid)
    return 0;
  if ((!Subtarget->isTargetWin64())) {
    return FastEmitInst_r(X86::CALL64r, X86::GR64RegisterClass, Op0, Op0IsKill);
  }
  if ((Subtarget->isTargetWin64())) {
    return FastEmitInst_r(X86::WINCALL64r, X86::GR64RegisterClass, Op0, Op0IsKill);
  }
  return 0;
}

unsigned FastEmit_X86ISD_CALL_r(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill) {
  switch (VT.SimpleTy) {
  case MVT::i32: return FastEmit_X86ISD_CALL_MVT_i32_r(RetVT, Op0, Op0IsKill);
  case MVT::i64: return FastEmit_X86ISD_CALL_MVT_i64_r(RetVT, Op0, Op0IsKill);
  default: return 0;
  }
}

// FastEmit functions for X86ISD::EH_RETURN.

unsigned FastEmit_X86ISD_EH_RETURN_MVT_i32_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
  if (RetVT.SimpleTy != MVT::isVoid)
    return 0;
  return FastEmitInst_r(X86::EH_RETURN, X86::GR32RegisterClass, Op0, Op0IsKill);
}

unsigned FastEmit_X86ISD_EH_RETURN_MVT_i64_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
  if (RetVT.SimpleTy != MVT::isVoid)
    return 0;
  return FastEmitInst_r(X86::EH_RETURN64, X86::GR64RegisterClass, Op0, Op0IsKill);
}

unsigned FastEmit_X86ISD_EH_RETURN_r(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill) {
  switch (VT.SimpleTy) {
  case MVT::i32: return FastEmit_X86ISD_EH_RETURN_MVT_i32_r(RetVT, Op0, Op0IsKill);
  case MVT::i64: return FastEmit_X86ISD_EH_RETURN_MVT_i64_r(RetVT, Op0, Op0IsKill);
  default: return 0;
  }
}

// FastEmit functions for X86ISD::FRCP.

unsigned FastEmit_X86ISD_FRCP_MVT_f32_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
  if (RetVT.SimpleTy != MVT::f32)
    return 0;
  if ((Subtarget->hasSSE1())) {
    return FastEmitInst_r(X86::RCPSSr, X86::FR32RegisterClass, Op0, Op0IsKill);
  }
  return 0;
}

unsigned FastEmit_X86ISD_FRCP_MVT_v4f32_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
  if (RetVT.SimpleTy != MVT::v4f32)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_r(X86::VRCPPSr, X86::VR128RegisterClass, Op0, Op0IsKill);
  }
  if ((Subtarget->hasSSE1())) {
    return FastEmitInst_r(X86::RCPPSr, X86::VR128RegisterClass, Op0, Op0IsKill);
  }
  return 0;
}

unsigned FastEmit_X86ISD_FRCP_MVT_v8f32_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
  if (RetVT.SimpleTy != MVT::v8f32)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_r(X86::VRCPPSYr, X86::VR256RegisterClass, Op0, Op0IsKill);
  }
  return 0;
}

unsigned FastEmit_X86ISD_FRCP_r(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill) {
  switch (VT.SimpleTy) {
  case MVT::f32: return FastEmit_X86ISD_FRCP_MVT_f32_r(RetVT, Op0, Op0IsKill);
  case MVT::v4f32: return FastEmit_X86ISD_FRCP_MVT_v4f32_r(RetVT, Op0, Op0IsKill);
  case MVT::v8f32: return FastEmit_X86ISD_FRCP_MVT_v8f32_r(RetVT, Op0, Op0IsKill);
  default: return 0;
  }
}

// FastEmit functions for X86ISD::FRSQRT.

unsigned FastEmit_X86ISD_FRSQRT_MVT_f32_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
  if (RetVT.SimpleTy != MVT::f32)
    return 0;
  if ((Subtarget->hasSSE1())) {
    return FastEmitInst_r(X86::RSQRTSSr, X86::FR32RegisterClass, Op0, Op0IsKill);
  }
  return 0;
}

unsigned FastEmit_X86ISD_FRSQRT_MVT_v4f32_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
  if (RetVT.SimpleTy != MVT::v4f32)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_r(X86::VRSQRTPSr, X86::VR128RegisterClass, Op0, Op0IsKill);
  }
  if ((Subtarget->hasSSE1())) {
    return FastEmitInst_r(X86::RSQRTPSr, X86::VR128RegisterClass, Op0, Op0IsKill);
  }
  return 0;
}

unsigned FastEmit_X86ISD_FRSQRT_MVT_v8f32_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
  if (RetVT.SimpleTy != MVT::v8f32)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_r(X86::VRSQRTPSYr, X86::VR256RegisterClass, Op0, Op0IsKill);
  }
  return 0;
}

unsigned FastEmit_X86ISD_FRSQRT_r(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill) {
  switch (VT.SimpleTy) {
  case MVT::f32: return FastEmit_X86ISD_FRSQRT_MVT_f32_r(RetVT, Op0, Op0IsKill);
  case MVT::v4f32: return FastEmit_X86ISD_FRSQRT_MVT_v4f32_r(RetVT, Op0, Op0IsKill);
  case MVT::v8f32: return FastEmit_X86ISD_FRSQRT_MVT_v8f32_r(RetVT, Op0, Op0IsKill);
  default: return 0;
  }
}

// FastEmit functions for X86ISD::MEMBARRIER.

unsigned FastEmit_X86ISD_MEMBARRIER_MVT_i64_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
  if (RetVT.SimpleTy != MVT::isVoid)
    return 0;
  if ((Subtarget->is64Bit())) {
    return FastEmitInst_r(X86::Int_MemBarrierNoSSE64, X86::GR64RegisterClass, Op0, Op0IsKill);
  }
  return 0;
}

unsigned FastEmit_X86ISD_MEMBARRIER_r(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill) {
  switch (VT.SimpleTy) {
  case MVT::i64: return FastEmit_X86ISD_MEMBARRIER_MVT_i64_r(RetVT, Op0, Op0IsKill);
  default: return 0;
  }
}

// FastEmit functions for X86ISD::MOVQ2DQ.

unsigned FastEmit_X86ISD_MOVQ2DQ_MVT_v1i64_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
  if (RetVT.SimpleTy != MVT::v2i64)
    return 0;
  return FastEmitInst_r(X86::MMX_MOVQ2DQrr, X86::VR128RegisterClass, Op0, Op0IsKill);
}

unsigned FastEmit_X86ISD_MOVQ2DQ_r(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill) {
  switch (VT.SimpleTy) {
  case MVT::v1i64: return FastEmit_X86ISD_MOVQ2DQ_MVT_v1i64_r(RetVT, Op0, Op0IsKill);
  default: return 0;
  }
}

// FastEmit functions for X86ISD::MOVSHDUP.

unsigned FastEmit_X86ISD_MOVSHDUP_MVT_v4i32_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
  if (RetVT.SimpleTy != MVT::v4i32)
    return 0;
  return FastEmitInst_r(X86::MOVSHDUPrr, X86::VR128RegisterClass, Op0, Op0IsKill);
}

unsigned FastEmit_X86ISD_MOVSHDUP_MVT_v4f32_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
  if (RetVT.SimpleTy != MVT::v4f32)
    return 0;
  return FastEmitInst_r(X86::MOVSHDUPrr, X86::VR128RegisterClass, Op0, Op0IsKill);
}

unsigned FastEmit_X86ISD_MOVSHDUP_r(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill) {
  switch (VT.SimpleTy) {
  case MVT::v4i32: return FastEmit_X86ISD_MOVSHDUP_MVT_v4i32_r(RetVT, Op0, Op0IsKill);
  case MVT::v4f32: return FastEmit_X86ISD_MOVSHDUP_MVT_v4f32_r(RetVT, Op0, Op0IsKill);
  default: return 0;
  }
}

// FastEmit functions for X86ISD::MOVSLDUP.

unsigned FastEmit_X86ISD_MOVSLDUP_MVT_v4i32_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
  if (RetVT.SimpleTy != MVT::v4i32)
    return 0;
  return FastEmitInst_r(X86::MOVSLDUPrr, X86::VR128RegisterClass, Op0, Op0IsKill);
}

unsigned FastEmit_X86ISD_MOVSLDUP_MVT_v4f32_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
  if (RetVT.SimpleTy != MVT::v4f32)
    return 0;
  return FastEmitInst_r(X86::MOVSLDUPrr, X86::VR128RegisterClass, Op0, Op0IsKill);
}

unsigned FastEmit_X86ISD_MOVSLDUP_r(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill) {
  switch (VT.SimpleTy) {
  case MVT::v4i32: return FastEmit_X86ISD_MOVSLDUP_MVT_v4i32_r(RetVT, Op0, Op0IsKill);
  case MVT::v4f32: return FastEmit_X86ISD_MOVSLDUP_MVT_v4f32_r(RetVT, Op0, Op0IsKill);
  default: return 0;
  }
}

// FastEmit functions for X86ISD::VZEXT_MOVL.

unsigned FastEmit_X86ISD_VZEXT_MOVL_MVT_v2i64_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
  if (RetVT.SimpleTy != MVT::v2i64)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_r(X86::VMOVZPQILo2PQIrr, X86::VR128RegisterClass, Op0, Op0IsKill);
  }
  if ((Subtarget->hasSSE2())) {
    return FastEmitInst_r(X86::MOVZPQILo2PQIrr, X86::VR128RegisterClass, Op0, Op0IsKill);
  }
  return 0;
}

unsigned FastEmit_X86ISD_VZEXT_MOVL_MVT_v2f64_r(MVT RetVT, unsigned Op0, bool Op0IsKill) {
  if (RetVT.SimpleTy != MVT::v2f64)
    return 0;
  if ((Subtarget->hasSSE2())) {
    return FastEmitInst_r(X86::MOVZPQILo2PQIrr, X86::VR128RegisterClass, Op0, Op0IsKill);
  }
  return 0;
}

unsigned FastEmit_X86ISD_VZEXT_MOVL_r(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill) {
  switch (VT.SimpleTy) {
  case MVT::v2i64: return FastEmit_X86ISD_VZEXT_MOVL_MVT_v2i64_r(RetVT, Op0, Op0IsKill);
  case MVT::v2f64: return FastEmit_X86ISD_VZEXT_MOVL_MVT_v2f64_r(RetVT, Op0, Op0IsKill);
  default: return 0;
  }
}

// Top-level FastEmit function.

unsigned FastEmit_r(MVT VT, MVT RetVT, unsigned Opcode, unsigned Op0, bool Op0IsKill) {
  switch (Opcode) {
  case ISD::ANY_EXTEND: return FastEmit_ISD_ANY_EXTEND_r(VT, RetVT, Op0, Op0IsKill);
  case ISD::BIT_CONVERT: return FastEmit_ISD_BIT_CONVERT_r(VT, RetVT, Op0, Op0IsKill);
  case ISD::BRIND: return FastEmit_ISD_BRIND_r(VT, RetVT, Op0, Op0IsKill);
  case ISD::BSWAP: return FastEmit_ISD_BSWAP_r(VT, RetVT, Op0, Op0IsKill);
  case ISD::FABS: return FastEmit_ISD_FABS_r(VT, RetVT, Op0, Op0IsKill);
  case ISD::FCOS: return FastEmit_ISD_FCOS_r(VT, RetVT, Op0, Op0IsKill);
  case ISD::FNEG: return FastEmit_ISD_FNEG_r(VT, RetVT, Op0, Op0IsKill);
  case ISD::FP_EXTEND: return FastEmit_ISD_FP_EXTEND_r(VT, RetVT, Op0, Op0IsKill);
  case ISD::FP_ROUND: return FastEmit_ISD_FP_ROUND_r(VT, RetVT, Op0, Op0IsKill);
  case ISD::FP_TO_SINT: return FastEmit_ISD_FP_TO_SINT_r(VT, RetVT, Op0, Op0IsKill);
  case ISD::FSIN: return FastEmit_ISD_FSIN_r(VT, RetVT, Op0, Op0IsKill);
  case ISD::FSQRT: return FastEmit_ISD_FSQRT_r(VT, RetVT, Op0, Op0IsKill);
  case ISD::SCALAR_TO_VECTOR: return FastEmit_ISD_SCALAR_TO_VECTOR_r(VT, RetVT, Op0, Op0IsKill);
  case ISD::SIGN_EXTEND: return FastEmit_ISD_SIGN_EXTEND_r(VT, RetVT, Op0, Op0IsKill);
  case ISD::SINT_TO_FP: return FastEmit_ISD_SINT_TO_FP_r(VT, RetVT, Op0, Op0IsKill);
  case ISD::TRUNCATE: return FastEmit_ISD_TRUNCATE_r(VT, RetVT, Op0, Op0IsKill);
  case ISD::ZERO_EXTEND: return FastEmit_ISD_ZERO_EXTEND_r(VT, RetVT, Op0, Op0IsKill);
  case X86ISD::CALL: return FastEmit_X86ISD_CALL_r(VT, RetVT, Op0, Op0IsKill);
  case X86ISD::EH_RETURN: return FastEmit_X86ISD_EH_RETURN_r(VT, RetVT, Op0, Op0IsKill);
  case X86ISD::FRCP: return FastEmit_X86ISD_FRCP_r(VT, RetVT, Op0, Op0IsKill);
  case X86ISD::FRSQRT: return FastEmit_X86ISD_FRSQRT_r(VT, RetVT, Op0, Op0IsKill);
  case X86ISD::MEMBARRIER: return FastEmit_X86ISD_MEMBARRIER_r(VT, RetVT, Op0, Op0IsKill);
  case X86ISD::MOVQ2DQ: return FastEmit_X86ISD_MOVQ2DQ_r(VT, RetVT, Op0, Op0IsKill);
  case X86ISD::MOVSHDUP: return FastEmit_X86ISD_MOVSHDUP_r(VT, RetVT, Op0, Op0IsKill);
  case X86ISD::MOVSLDUP: return FastEmit_X86ISD_MOVSLDUP_r(VT, RetVT, Op0, Op0IsKill);
  case X86ISD::VZEXT_MOVL: return FastEmit_X86ISD_VZEXT_MOVL_r(VT, RetVT, Op0, Op0IsKill);
  default: return 0;
  }
}

// FastEmit functions for ISD::ADD.

unsigned FastEmit_ISD_ADD_MVT_i8_ri(MVT RetVT, unsigned Op0, bool Op0IsKill, uint64_t imm1) {
  if (RetVT.SimpleTy != MVT::i8)
    return 0;
  return FastEmitInst_ri(X86::ADD8ri, X86::GR8RegisterClass, Op0, Op0IsKill, imm1);
}

unsigned FastEmit_ISD_ADD_MVT_i16_ri(MVT RetVT, unsigned Op0, bool Op0IsKill, uint64_t imm1) {
  if (RetVT.SimpleTy != MVT::i16)
    return 0;
  return FastEmitInst_ri(X86::ADD16ri, X86::GR16RegisterClass, Op0, Op0IsKill, imm1);
}

unsigned FastEmit_ISD_ADD_MVT_i32_ri(MVT RetVT, unsigned Op0, bool Op0IsKill, uint64_t imm1) {
  if (RetVT.SimpleTy != MVT::i32)
    return 0;
  return FastEmitInst_ri(X86::ADD32ri, X86::GR32RegisterClass, Op0, Op0IsKill, imm1);
}

unsigned FastEmit_ISD_ADD_ri(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, uint64_t imm1) {
  switch (VT.SimpleTy) {
  case MVT::i8: return FastEmit_ISD_ADD_MVT_i8_ri(RetVT, Op0, Op0IsKill, imm1);
  case MVT::i16: return FastEmit_ISD_ADD_MVT_i16_ri(RetVT, Op0, Op0IsKill, imm1);
  case MVT::i32: return FastEmit_ISD_ADD_MVT_i32_ri(RetVT, Op0, Op0IsKill, imm1);
  default: return 0;
  }
}

// FastEmit functions for ISD::ADDC.

unsigned FastEmit_ISD_ADDC_MVT_i32_ri(MVT RetVT, unsigned Op0, bool Op0IsKill, uint64_t imm1) {
  if (RetVT.SimpleTy != MVT::i32)
    return 0;
  return FastEmitInst_ri(X86::ADD32ri, X86::GR32RegisterClass, Op0, Op0IsKill, imm1);
}

unsigned FastEmit_ISD_ADDC_ri(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, uint64_t imm1) {
  switch (VT.SimpleTy) {
  case MVT::i32: return FastEmit_ISD_ADDC_MVT_i32_ri(RetVT, Op0, Op0IsKill, imm1);
  default: return 0;
  }
}

// FastEmit functions for ISD::ADDE.

unsigned FastEmit_ISD_ADDE_MVT_i8_ri(MVT RetVT, unsigned Op0, bool Op0IsKill, uint64_t imm1) {
  if (RetVT.SimpleTy != MVT::i8)
    return 0;
  return FastEmitInst_ri(X86::ADC8ri, X86::GR8RegisterClass, Op0, Op0IsKill, imm1);
}

unsigned FastEmit_ISD_ADDE_MVT_i16_ri(MVT RetVT, unsigned Op0, bool Op0IsKill, uint64_t imm1) {
  if (RetVT.SimpleTy != MVT::i16)
    return 0;
  return FastEmitInst_ri(X86::ADC16ri, X86::GR16RegisterClass, Op0, Op0IsKill, imm1);
}

unsigned FastEmit_ISD_ADDE_MVT_i32_ri(MVT RetVT, unsigned Op0, bool Op0IsKill, uint64_t imm1) {
  if (RetVT.SimpleTy != MVT::i32)
    return 0;
  return FastEmitInst_ri(X86::ADC32ri, X86::GR32RegisterClass, Op0, Op0IsKill, imm1);
}

unsigned FastEmit_ISD_ADDE_ri(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, uint64_t imm1) {
  switch (VT.SimpleTy) {
  case MVT::i8: return FastEmit_ISD_ADDE_MVT_i8_ri(RetVT, Op0, Op0IsKill, imm1);
  case MVT::i16: return FastEmit_ISD_ADDE_MVT_i16_ri(RetVT, Op0, Op0IsKill, imm1);
  case MVT::i32: return FastEmit_ISD_ADDE_MVT_i32_ri(RetVT, Op0, Op0IsKill, imm1);
  default: return 0;
  }
}

// FastEmit functions for ISD::AND.

unsigned FastEmit_ISD_AND_MVT_i8_ri(MVT RetVT, unsigned Op0, bool Op0IsKill, uint64_t imm1) {
  if (RetVT.SimpleTy != MVT::i8)
    return 0;
  return FastEmitInst_ri(X86::AND8ri, X86::GR8RegisterClass, Op0, Op0IsKill, imm1);
}

unsigned FastEmit_ISD_AND_MVT_i16_ri(MVT RetVT, unsigned Op0, bool Op0IsKill, uint64_t imm1) {
  if (RetVT.SimpleTy != MVT::i16)
    return 0;
  return FastEmitInst_ri(X86::AND16ri, X86::GR16RegisterClass, Op0, Op0IsKill, imm1);
}

unsigned FastEmit_ISD_AND_MVT_i32_ri(MVT RetVT, unsigned Op0, bool Op0IsKill, uint64_t imm1) {
  if (RetVT.SimpleTy != MVT::i32)
    return 0;
  return FastEmitInst_ri(X86::AND32ri, X86::GR32RegisterClass, Op0, Op0IsKill, imm1);
}

unsigned FastEmit_ISD_AND_ri(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, uint64_t imm1) {
  switch (VT.SimpleTy) {
  case MVT::i8: return FastEmit_ISD_AND_MVT_i8_ri(RetVT, Op0, Op0IsKill, imm1);
  case MVT::i16: return FastEmit_ISD_AND_MVT_i16_ri(RetVT, Op0, Op0IsKill, imm1);
  case MVT::i32: return FastEmit_ISD_AND_MVT_i32_ri(RetVT, Op0, Op0IsKill, imm1);
  default: return 0;
  }
}

// FastEmit functions for ISD::MUL.

unsigned FastEmit_ISD_MUL_MVT_i16_ri(MVT RetVT, unsigned Op0, bool Op0IsKill, uint64_t imm1) {
  if (RetVT.SimpleTy != MVT::i16)
    return 0;
  return FastEmitInst_ri(X86::IMUL16rri, X86::GR16RegisterClass, Op0, Op0IsKill, imm1);
}

unsigned FastEmit_ISD_MUL_MVT_i32_ri(MVT RetVT, unsigned Op0, bool Op0IsKill, uint64_t imm1) {
  if (RetVT.SimpleTy != MVT::i32)
    return 0;
  return FastEmitInst_ri(X86::IMUL32rri, X86::GR32RegisterClass, Op0, Op0IsKill, imm1);
}

unsigned FastEmit_ISD_MUL_ri(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, uint64_t imm1) {
  switch (VT.SimpleTy) {
  case MVT::i16: return FastEmit_ISD_MUL_MVT_i16_ri(RetVT, Op0, Op0IsKill, imm1);
  case MVT::i32: return FastEmit_ISD_MUL_MVT_i32_ri(RetVT, Op0, Op0IsKill, imm1);
  default: return 0;
  }
}

// FastEmit functions for ISD::OR.

unsigned FastEmit_ISD_OR_MVT_i8_ri(MVT RetVT, unsigned Op0, bool Op0IsKill, uint64_t imm1) {
  if (RetVT.SimpleTy != MVT::i8)
    return 0;
  return FastEmitInst_ri(X86::OR8ri, X86::GR8RegisterClass, Op0, Op0IsKill, imm1);
}

unsigned FastEmit_ISD_OR_MVT_i16_ri(MVT RetVT, unsigned Op0, bool Op0IsKill, uint64_t imm1) {
  if (RetVT.SimpleTy != MVT::i16)
    return 0;
  return FastEmitInst_ri(X86::OR16ri, X86::GR16RegisterClass, Op0, Op0IsKill, imm1);
}

unsigned FastEmit_ISD_OR_MVT_i32_ri(MVT RetVT, unsigned Op0, bool Op0IsKill, uint64_t imm1) {
  if (RetVT.SimpleTy != MVT::i32)
    return 0;
  return FastEmitInst_ri(X86::OR32ri, X86::GR32RegisterClass, Op0, Op0IsKill, imm1);
}

unsigned FastEmit_ISD_OR_ri(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, uint64_t imm1) {
  switch (VT.SimpleTy) {
  case MVT::i8: return FastEmit_ISD_OR_MVT_i8_ri(RetVT, Op0, Op0IsKill, imm1);
  case MVT::i16: return FastEmit_ISD_OR_MVT_i16_ri(RetVT, Op0, Op0IsKill, imm1);
  case MVT::i32: return FastEmit_ISD_OR_MVT_i32_ri(RetVT, Op0, Op0IsKill, imm1);
  default: return 0;
  }
}

// FastEmit functions for ISD::ROTL.

unsigned FastEmit_ISD_ROTL_MVT_i8_ri(MVT RetVT, unsigned Op0, bool Op0IsKill, uint64_t imm1) {
  if (RetVT.SimpleTy != MVT::i8)
    return 0;
  return FastEmitInst_ri(X86::ROL8ri, X86::GR8RegisterClass, Op0, Op0IsKill, imm1);
}

unsigned FastEmit_ISD_ROTL_ri(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, uint64_t imm1) {
  switch (VT.SimpleTy) {
  case MVT::i8: return FastEmit_ISD_ROTL_MVT_i8_ri(RetVT, Op0, Op0IsKill, imm1);
  default: return 0;
  }
}

// FastEmit functions for ISD::ROTR.

unsigned FastEmit_ISD_ROTR_MVT_i8_ri(MVT RetVT, unsigned Op0, bool Op0IsKill, uint64_t imm1) {
  if (RetVT.SimpleTy != MVT::i8)
    return 0;
  return FastEmitInst_ri(X86::ROR8ri, X86::GR8RegisterClass, Op0, Op0IsKill, imm1);
}

unsigned FastEmit_ISD_ROTR_ri(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, uint64_t imm1) {
  switch (VT.SimpleTy) {
  case MVT::i8: return FastEmit_ISD_ROTR_MVT_i8_ri(RetVT, Op0, Op0IsKill, imm1);
  default: return 0;
  }
}

// FastEmit functions for ISD::SHL.

unsigned FastEmit_ISD_SHL_MVT_i8_ri(MVT RetVT, unsigned Op0, bool Op0IsKill, uint64_t imm1) {
  if (RetVT.SimpleTy != MVT::i8)
    return 0;
  return FastEmitInst_ri(X86::SHL8ri, X86::GR8RegisterClass, Op0, Op0IsKill, imm1);
}

unsigned FastEmit_ISD_SHL_ri(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, uint64_t imm1) {
  switch (VT.SimpleTy) {
  case MVT::i8: return FastEmit_ISD_SHL_MVT_i8_ri(RetVT, Op0, Op0IsKill, imm1);
  default: return 0;
  }
}

// FastEmit functions for ISD::SRA.

unsigned FastEmit_ISD_SRA_MVT_i8_ri(MVT RetVT, unsigned Op0, bool Op0IsKill, uint64_t imm1) {
  if (RetVT.SimpleTy != MVT::i8)
    return 0;
  return FastEmitInst_ri(X86::SAR8ri, X86::GR8RegisterClass, Op0, Op0IsKill, imm1);
}

unsigned FastEmit_ISD_SRA_ri(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, uint64_t imm1) {
  switch (VT.SimpleTy) {
  case MVT::i8: return FastEmit_ISD_SRA_MVT_i8_ri(RetVT, Op0, Op0IsKill, imm1);
  default: return 0;
  }
}

// FastEmit functions for ISD::SRL.

unsigned FastEmit_ISD_SRL_MVT_i8_ri(MVT RetVT, unsigned Op0, bool Op0IsKill, uint64_t imm1) {
  if (RetVT.SimpleTy != MVT::i8)
    return 0;
  return FastEmitInst_ri(X86::SHR8ri, X86::GR8RegisterClass, Op0, Op0IsKill, imm1);
}

unsigned FastEmit_ISD_SRL_ri(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, uint64_t imm1) {
  switch (VT.SimpleTy) {
  case MVT::i8: return FastEmit_ISD_SRL_MVT_i8_ri(RetVT, Op0, Op0IsKill, imm1);
  default: return 0;
  }
}

// FastEmit functions for ISD::SUB.

unsigned FastEmit_ISD_SUB_MVT_i8_ri(MVT RetVT, unsigned Op0, bool Op0IsKill, uint64_t imm1) {
  if (RetVT.SimpleTy != MVT::i8)
    return 0;
  return FastEmitInst_ri(X86::SUB8ri, X86::GR8RegisterClass, Op0, Op0IsKill, imm1);
}

unsigned FastEmit_ISD_SUB_MVT_i16_ri(MVT RetVT, unsigned Op0, bool Op0IsKill, uint64_t imm1) {
  if (RetVT.SimpleTy != MVT::i16)
    return 0;
  return FastEmitInst_ri(X86::SUB16ri, X86::GR16RegisterClass, Op0, Op0IsKill, imm1);
}

unsigned FastEmit_ISD_SUB_MVT_i32_ri(MVT RetVT, unsigned Op0, bool Op0IsKill, uint64_t imm1) {
  if (RetVT.SimpleTy != MVT::i32)
    return 0;
  return FastEmitInst_ri(X86::SUB32ri, X86::GR32RegisterClass, Op0, Op0IsKill, imm1);
}

unsigned FastEmit_ISD_SUB_ri(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, uint64_t imm1) {
  switch (VT.SimpleTy) {
  case MVT::i8: return FastEmit_ISD_SUB_MVT_i8_ri(RetVT, Op0, Op0IsKill, imm1);
  case MVT::i16: return FastEmit_ISD_SUB_MVT_i16_ri(RetVT, Op0, Op0IsKill, imm1);
  case MVT::i32: return FastEmit_ISD_SUB_MVT_i32_ri(RetVT, Op0, Op0IsKill, imm1);
  default: return 0;
  }
}

// FastEmit functions for ISD::SUBC.

unsigned FastEmit_ISD_SUBC_MVT_i32_ri(MVT RetVT, unsigned Op0, bool Op0IsKill, uint64_t imm1) {
  if (RetVT.SimpleTy != MVT::i32)
    return 0;
  return FastEmitInst_ri(X86::SUB32ri, X86::GR32RegisterClass, Op0, Op0IsKill, imm1);
}

unsigned FastEmit_ISD_SUBC_MVT_i64_ri(MVT RetVT, unsigned Op0, bool Op0IsKill, uint64_t imm1) {
  if (RetVT.SimpleTy != MVT::i64)
    return 0;
  return FastEmitInst_ri(X86::SUB64ri32, X86::GR64RegisterClass, Op0, Op0IsKill, imm1);
}

unsigned FastEmit_ISD_SUBC_ri(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, uint64_t imm1) {
  switch (VT.SimpleTy) {
  case MVT::i32: return FastEmit_ISD_SUBC_MVT_i32_ri(RetVT, Op0, Op0IsKill, imm1);
  case MVT::i64: return FastEmit_ISD_SUBC_MVT_i64_ri(RetVT, Op0, Op0IsKill, imm1);
  default: return 0;
  }
}

// FastEmit functions for ISD::SUBE.

unsigned FastEmit_ISD_SUBE_MVT_i8_ri(MVT RetVT, unsigned Op0, bool Op0IsKill, uint64_t imm1) {
  if (RetVT.SimpleTy != MVT::i8)
    return 0;
  return FastEmitInst_ri(X86::SBB8ri, X86::GR8RegisterClass, Op0, Op0IsKill, imm1);
}

unsigned FastEmit_ISD_SUBE_MVT_i16_ri(MVT RetVT, unsigned Op0, bool Op0IsKill, uint64_t imm1) {
  if (RetVT.SimpleTy != MVT::i16)
    return 0;
  return FastEmitInst_ri(X86::SBB16ri, X86::GR16RegisterClass, Op0, Op0IsKill, imm1);
}

unsigned FastEmit_ISD_SUBE_MVT_i32_ri(MVT RetVT, unsigned Op0, bool Op0IsKill, uint64_t imm1) {
  if (RetVT.SimpleTy != MVT::i32)
    return 0;
  return FastEmitInst_ri(X86::SBB32ri, X86::GR32RegisterClass, Op0, Op0IsKill, imm1);
}

unsigned FastEmit_ISD_SUBE_ri(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, uint64_t imm1) {
  switch (VT.SimpleTy) {
  case MVT::i8: return FastEmit_ISD_SUBE_MVT_i8_ri(RetVT, Op0, Op0IsKill, imm1);
  case MVT::i16: return FastEmit_ISD_SUBE_MVT_i16_ri(RetVT, Op0, Op0IsKill, imm1);
  case MVT::i32: return FastEmit_ISD_SUBE_MVT_i32_ri(RetVT, Op0, Op0IsKill, imm1);
  default: return 0;
  }
}

// FastEmit functions for ISD::XOR.

unsigned FastEmit_ISD_XOR_MVT_i8_ri(MVT RetVT, unsigned Op0, bool Op0IsKill, uint64_t imm1) {
  if (RetVT.SimpleTy != MVT::i8)
    return 0;
  return FastEmitInst_ri(X86::XOR8ri, X86::GR8RegisterClass, Op0, Op0IsKill, imm1);
}

unsigned FastEmit_ISD_XOR_MVT_i16_ri(MVT RetVT, unsigned Op0, bool Op0IsKill, uint64_t imm1) {
  if (RetVT.SimpleTy != MVT::i16)
    return 0;
  return FastEmitInst_ri(X86::XOR16ri, X86::GR16RegisterClass, Op0, Op0IsKill, imm1);
}

unsigned FastEmit_ISD_XOR_MVT_i32_ri(MVT RetVT, unsigned Op0, bool Op0IsKill, uint64_t imm1) {
  if (RetVT.SimpleTy != MVT::i32)
    return 0;
  return FastEmitInst_ri(X86::XOR32ri, X86::GR32RegisterClass, Op0, Op0IsKill, imm1);
}

unsigned FastEmit_ISD_XOR_ri(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, uint64_t imm1) {
  switch (VT.SimpleTy) {
  case MVT::i8: return FastEmit_ISD_XOR_MVT_i8_ri(RetVT, Op0, Op0IsKill, imm1);
  case MVT::i16: return FastEmit_ISD_XOR_MVT_i16_ri(RetVT, Op0, Op0IsKill, imm1);
  case MVT::i32: return FastEmit_ISD_XOR_MVT_i32_ri(RetVT, Op0, Op0IsKill, imm1);
  default: return 0;
  }
}

// FastEmit functions for X86ISD::CMP.

unsigned FastEmit_X86ISD_CMP_MVT_i8_ri(MVT RetVT, unsigned Op0, bool Op0IsKill, uint64_t imm1) {
  if (RetVT.SimpleTy != MVT::i32)
    return 0;
  return FastEmitInst_ri(X86::CMP8ri, X86::GR8RegisterClass, Op0, Op0IsKill, imm1);
}

unsigned FastEmit_X86ISD_CMP_MVT_i16_ri(MVT RetVT, unsigned Op0, bool Op0IsKill, uint64_t imm1) {
  if (RetVT.SimpleTy != MVT::i32)
    return 0;
  return FastEmitInst_ri(X86::CMP16ri, X86::GR16RegisterClass, Op0, Op0IsKill, imm1);
}

unsigned FastEmit_X86ISD_CMP_MVT_i32_ri(MVT RetVT, unsigned Op0, bool Op0IsKill, uint64_t imm1) {
  if (RetVT.SimpleTy != MVT::i32)
    return 0;
  return FastEmitInst_ri(X86::CMP32ri, X86::GR32RegisterClass, Op0, Op0IsKill, imm1);
}

unsigned FastEmit_X86ISD_CMP_ri(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, uint64_t imm1) {
  switch (VT.SimpleTy) {
  case MVT::i8: return FastEmit_X86ISD_CMP_MVT_i8_ri(RetVT, Op0, Op0IsKill, imm1);
  case MVT::i16: return FastEmit_X86ISD_CMP_MVT_i16_ri(RetVT, Op0, Op0IsKill, imm1);
  case MVT::i32: return FastEmit_X86ISD_CMP_MVT_i32_ri(RetVT, Op0, Op0IsKill, imm1);
  default: return 0;
  }
}

// FastEmit functions for X86ISD::TC_RETURN.

unsigned FastEmit_X86ISD_TC_RETURN_MVT_i32_ri(MVT RetVT, unsigned Op0, bool Op0IsKill, uint64_t imm1) {
  if (RetVT.SimpleTy != MVT::isVoid)
    return 0;
  if ((!Subtarget->is64Bit())) {
    return FastEmitInst_ri(X86::TCRETURNri, X86::GR32_TCRegisterClass, Op0, Op0IsKill, imm1);
  }
  return 0;
}

unsigned FastEmit_X86ISD_TC_RETURN_ri(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, uint64_t imm1) {
  switch (VT.SimpleTy) {
  case MVT::i32: return FastEmit_X86ISD_TC_RETURN_MVT_i32_ri(RetVT, Op0, Op0IsKill, imm1);
  default: return 0;
  }
}

// Top-level FastEmit function.

unsigned FastEmit_ri(MVT VT, MVT RetVT, unsigned Opcode, unsigned Op0, bool Op0IsKill, uint64_t imm1) {
  switch (Opcode) {
  case ISD::ADD: return FastEmit_ISD_ADD_ri(VT, RetVT, Op0, Op0IsKill, imm1);
  case ISD::ADDC: return FastEmit_ISD_ADDC_ri(VT, RetVT, Op0, Op0IsKill, imm1);
  case ISD::ADDE: return FastEmit_ISD_ADDE_ri(VT, RetVT, Op0, Op0IsKill, imm1);
  case ISD::AND: return FastEmit_ISD_AND_ri(VT, RetVT, Op0, Op0IsKill, imm1);
  case ISD::MUL: return FastEmit_ISD_MUL_ri(VT, RetVT, Op0, Op0IsKill, imm1);
  case ISD::OR: return FastEmit_ISD_OR_ri(VT, RetVT, Op0, Op0IsKill, imm1);
  case ISD::ROTL: return FastEmit_ISD_ROTL_ri(VT, RetVT, Op0, Op0IsKill, imm1);
  case ISD::ROTR: return FastEmit_ISD_ROTR_ri(VT, RetVT, Op0, Op0IsKill, imm1);
  case ISD::SHL: return FastEmit_ISD_SHL_ri(VT, RetVT, Op0, Op0IsKill, imm1);
  case ISD::SRA: return FastEmit_ISD_SRA_ri(VT, RetVT, Op0, Op0IsKill, imm1);
  case ISD::SRL: return FastEmit_ISD_SRL_ri(VT, RetVT, Op0, Op0IsKill, imm1);
  case ISD::SUB: return FastEmit_ISD_SUB_ri(VT, RetVT, Op0, Op0IsKill, imm1);
  case ISD::SUBC: return FastEmit_ISD_SUBC_ri(VT, RetVT, Op0, Op0IsKill, imm1);
  case ISD::SUBE: return FastEmit_ISD_SUBE_ri(VT, RetVT, Op0, Op0IsKill, imm1);
  case ISD::XOR: return FastEmit_ISD_XOR_ri(VT, RetVT, Op0, Op0IsKill, imm1);
  case X86ISD::CMP: return FastEmit_X86ISD_CMP_ri(VT, RetVT, Op0, Op0IsKill, imm1);
  case X86ISD::TC_RETURN: return FastEmit_X86ISD_TC_RETURN_ri(VT, RetVT, Op0, Op0IsKill, imm1);
  default: return 0;
  }
}

// FastEmit functions for ISD::ADD.

unsigned FastEmit_ISD_ADD_MVT_i8_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::i8)
    return 0;
  return FastEmitInst_rr(X86::ADD8rr, X86::GR8RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_ISD_ADD_MVT_i16_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::i16)
    return 0;
  return FastEmitInst_rr(X86::ADD16rr, X86::GR16RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_ISD_ADD_MVT_i32_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::i32)
    return 0;
  return FastEmitInst_rr(X86::ADD32rr, X86::GR32RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_ISD_ADD_MVT_i64_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::i64)
    return 0;
  return FastEmitInst_rr(X86::ADD64rr, X86::GR64RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_ISD_ADD_MVT_v8i8_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v8i8)
    return 0;
  if ((Subtarget->hasMMX() && !Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::MMX_PADDBrr, X86::VR64RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_ADD_MVT_v16i8_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v16i8)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VPADDBrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  if ((Subtarget->hasSSE2())) {
    return FastEmitInst_rr(X86::PADDBrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_ADD_MVT_v4i16_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v4i16)
    return 0;
  if ((Subtarget->hasMMX() && !Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::MMX_PADDWrr, X86::VR64RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_ADD_MVT_v8i16_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v8i16)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VPADDWrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  if ((Subtarget->hasSSE2())) {
    return FastEmitInst_rr(X86::PADDWrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_ADD_MVT_v2i32_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v2i32)
    return 0;
  if ((Subtarget->hasMMX() && !Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::MMX_PADDDrr, X86::VR64RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_ADD_MVT_v4i32_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v4i32)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VPADDDrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  if ((Subtarget->hasSSE2())) {
    return FastEmitInst_rr(X86::PADDDrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_ADD_MVT_v1i64_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v1i64)
    return 0;
  if ((Subtarget->hasMMX() && !Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::MMX_PADDQrr, X86::VR64RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_ADD_MVT_v2i64_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v2i64)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VPADDQrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  if ((Subtarget->hasSSE2())) {
    return FastEmitInst_rr(X86::PADDQrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_ADD_rr(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  switch (VT.SimpleTy) {
  case MVT::i8: return FastEmit_ISD_ADD_MVT_i8_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::i16: return FastEmit_ISD_ADD_MVT_i16_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::i32: return FastEmit_ISD_ADD_MVT_i32_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::i64: return FastEmit_ISD_ADD_MVT_i64_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::v8i8: return FastEmit_ISD_ADD_MVT_v8i8_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::v16i8: return FastEmit_ISD_ADD_MVT_v16i8_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::v4i16: return FastEmit_ISD_ADD_MVT_v4i16_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::v8i16: return FastEmit_ISD_ADD_MVT_v8i16_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::v2i32: return FastEmit_ISD_ADD_MVT_v2i32_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::v4i32: return FastEmit_ISD_ADD_MVT_v4i32_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::v1i64: return FastEmit_ISD_ADD_MVT_v1i64_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::v2i64: return FastEmit_ISD_ADD_MVT_v2i64_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  default: return 0;
  }
}

// FastEmit functions for ISD::ADDC.

unsigned FastEmit_ISD_ADDC_MVT_i32_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::i32)
    return 0;
  return FastEmitInst_rr(X86::ADD32rr, X86::GR32RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_ISD_ADDC_MVT_i64_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::i64)
    return 0;
  return FastEmitInst_rr(X86::ADD64rr, X86::GR64RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_ISD_ADDC_rr(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  switch (VT.SimpleTy) {
  case MVT::i32: return FastEmit_ISD_ADDC_MVT_i32_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::i64: return FastEmit_ISD_ADDC_MVT_i64_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  default: return 0;
  }
}

// FastEmit functions for ISD::ADDE.

unsigned FastEmit_ISD_ADDE_MVT_i8_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::i8)
    return 0;
  return FastEmitInst_rr(X86::ADC8rr, X86::GR8RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_ISD_ADDE_MVT_i16_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::i16)
    return 0;
  return FastEmitInst_rr(X86::ADC16rr, X86::GR16RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_ISD_ADDE_MVT_i32_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::i32)
    return 0;
  return FastEmitInst_rr(X86::ADC32rr, X86::GR32RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_ISD_ADDE_MVT_i64_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::i64)
    return 0;
  return FastEmitInst_rr(X86::ADC64rr, X86::GR64RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_ISD_ADDE_rr(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  switch (VT.SimpleTy) {
  case MVT::i8: return FastEmit_ISD_ADDE_MVT_i8_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::i16: return FastEmit_ISD_ADDE_MVT_i16_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::i32: return FastEmit_ISD_ADDE_MVT_i32_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::i64: return FastEmit_ISD_ADDE_MVT_i64_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  default: return 0;
  }
}

// FastEmit functions for ISD::AND.

unsigned FastEmit_ISD_AND_MVT_i8_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::i8)
    return 0;
  return FastEmitInst_rr(X86::AND8rr, X86::GR8RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_ISD_AND_MVT_i16_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::i16)
    return 0;
  return FastEmitInst_rr(X86::AND16rr, X86::GR16RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_ISD_AND_MVT_i32_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::i32)
    return 0;
  return FastEmitInst_rr(X86::AND32rr, X86::GR32RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_ISD_AND_MVT_i64_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::i64)
    return 0;
  return FastEmitInst_rr(X86::AND64rr, X86::GR64RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_ISD_AND_MVT_v1i64_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v1i64)
    return 0;
  if ((Subtarget->hasMMX() && !Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::MMX_PANDrr, X86::VR64RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_AND_MVT_v2i64_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v2i64)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VPANDrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  if ((Subtarget->hasSSE1())) {
    return FastEmitInst_rr(X86::ANDPSrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  if ((Subtarget->hasSSE2())) {
    return FastEmitInst_rr(X86::PANDrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_AND_rr(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  switch (VT.SimpleTy) {
  case MVT::i8: return FastEmit_ISD_AND_MVT_i8_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::i16: return FastEmit_ISD_AND_MVT_i16_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::i32: return FastEmit_ISD_AND_MVT_i32_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::i64: return FastEmit_ISD_AND_MVT_i64_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::v1i64: return FastEmit_ISD_AND_MVT_v1i64_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::v2i64: return FastEmit_ISD_AND_MVT_v2i64_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  default: return 0;
  }
}

// FastEmit functions for ISD::FADD.

unsigned FastEmit_ISD_FADD_MVT_f32_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::f32)
    return 0;
  if ((!Subtarget->hasSSE1())) {
    return FastEmitInst_rr(X86::ADD_Fp32, X86::RFP32RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VADDSSrr, X86::FR32RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  if ((Subtarget->hasSSE1())) {
    return FastEmitInst_rr(X86::ADDSSrr, X86::FR32RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_FADD_MVT_f64_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::f64)
    return 0;
  if ((!Subtarget->hasSSE2())) {
    return FastEmitInst_rr(X86::ADD_Fp64, X86::RFP64RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VADDSDrr, X86::FR64RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  if ((Subtarget->hasSSE2())) {
    return FastEmitInst_rr(X86::ADDSDrr, X86::FR64RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_FADD_MVT_f80_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::f80)
    return 0;
  return FastEmitInst_rr(X86::ADD_Fp80, X86::RFP80RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_ISD_FADD_MVT_v4f32_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v4f32)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VADDPSrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  if ((Subtarget->hasSSE1())) {
    return FastEmitInst_rr(X86::ADDPSrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_FADD_MVT_v8f32_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v8f32)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VADDPSYrr, X86::VR256RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_FADD_MVT_v2f64_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v2f64)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VADDPDrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  if ((Subtarget->hasSSE2())) {
    return FastEmitInst_rr(X86::ADDPDrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_FADD_MVT_v4f64_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v4f64)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VADDPDYrr, X86::VR256RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_FADD_rr(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  switch (VT.SimpleTy) {
  case MVT::f32: return FastEmit_ISD_FADD_MVT_f32_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::f64: return FastEmit_ISD_FADD_MVT_f64_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::f80: return FastEmit_ISD_FADD_MVT_f80_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::v4f32: return FastEmit_ISD_FADD_MVT_v4f32_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::v8f32: return FastEmit_ISD_FADD_MVT_v8f32_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::v2f64: return FastEmit_ISD_FADD_MVT_v2f64_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::v4f64: return FastEmit_ISD_FADD_MVT_v4f64_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  default: return 0;
  }
}

// FastEmit functions for ISD::FDIV.

unsigned FastEmit_ISD_FDIV_MVT_f32_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::f32)
    return 0;
  if ((!Subtarget->hasSSE1())) {
    return FastEmitInst_rr(X86::DIV_Fp32, X86::RFP32RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VDIVSSrr, X86::FR32RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  if ((Subtarget->hasSSE1())) {
    return FastEmitInst_rr(X86::DIVSSrr, X86::FR32RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_FDIV_MVT_f64_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::f64)
    return 0;
  if ((!Subtarget->hasSSE2())) {
    return FastEmitInst_rr(X86::DIV_Fp64, X86::RFP64RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VDIVSDrr, X86::FR64RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  if ((Subtarget->hasSSE2())) {
    return FastEmitInst_rr(X86::DIVSDrr, X86::FR64RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_FDIV_MVT_f80_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::f80)
    return 0;
  return FastEmitInst_rr(X86::DIV_Fp80, X86::RFP80RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_ISD_FDIV_MVT_v4f32_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v4f32)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VDIVPSrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  if ((Subtarget->hasSSE1())) {
    return FastEmitInst_rr(X86::DIVPSrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_FDIV_MVT_v8f32_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v8f32)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VDIVPSYrr, X86::VR256RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_FDIV_MVT_v2f64_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v2f64)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VDIVPDrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  if ((Subtarget->hasSSE2())) {
    return FastEmitInst_rr(X86::DIVPDrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_FDIV_MVT_v4f64_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v4f64)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VDIVPDYrr, X86::VR256RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_FDIV_rr(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  switch (VT.SimpleTy) {
  case MVT::f32: return FastEmit_ISD_FDIV_MVT_f32_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::f64: return FastEmit_ISD_FDIV_MVT_f64_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::f80: return FastEmit_ISD_FDIV_MVT_f80_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::v4f32: return FastEmit_ISD_FDIV_MVT_v4f32_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::v8f32: return FastEmit_ISD_FDIV_MVT_v8f32_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::v2f64: return FastEmit_ISD_FDIV_MVT_v2f64_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::v4f64: return FastEmit_ISD_FDIV_MVT_v4f64_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  default: return 0;
  }
}

// FastEmit functions for ISD::FMUL.

unsigned FastEmit_ISD_FMUL_MVT_f32_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::f32)
    return 0;
  if ((!Subtarget->hasSSE1())) {
    return FastEmitInst_rr(X86::MUL_Fp32, X86::RFP32RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VMULSSrr, X86::FR32RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  if ((Subtarget->hasSSE1())) {
    return FastEmitInst_rr(X86::MULSSrr, X86::FR32RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_FMUL_MVT_f64_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::f64)
    return 0;
  if ((!Subtarget->hasSSE2())) {
    return FastEmitInst_rr(X86::MUL_Fp64, X86::RFP64RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VMULSDrr, X86::FR64RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  if ((Subtarget->hasSSE2())) {
    return FastEmitInst_rr(X86::MULSDrr, X86::FR64RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_FMUL_MVT_f80_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::f80)
    return 0;
  return FastEmitInst_rr(X86::MUL_Fp80, X86::RFP80RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_ISD_FMUL_MVT_v4f32_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v4f32)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VMULPSrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  if ((Subtarget->hasSSE1())) {
    return FastEmitInst_rr(X86::MULPSrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_FMUL_MVT_v8f32_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v8f32)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VMULPSYrr, X86::VR256RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_FMUL_MVT_v2f64_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v2f64)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VMULPDrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  if ((Subtarget->hasSSE2())) {
    return FastEmitInst_rr(X86::MULPDrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_FMUL_MVT_v4f64_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v4f64)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VMULPDYrr, X86::VR256RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_FMUL_rr(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  switch (VT.SimpleTy) {
  case MVT::f32: return FastEmit_ISD_FMUL_MVT_f32_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::f64: return FastEmit_ISD_FMUL_MVT_f64_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::f80: return FastEmit_ISD_FMUL_MVT_f80_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::v4f32: return FastEmit_ISD_FMUL_MVT_v4f32_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::v8f32: return FastEmit_ISD_FMUL_MVT_v8f32_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::v2f64: return FastEmit_ISD_FMUL_MVT_v2f64_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::v4f64: return FastEmit_ISD_FMUL_MVT_v4f64_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  default: return 0;
  }
}

// FastEmit functions for ISD::FSUB.

unsigned FastEmit_ISD_FSUB_MVT_f32_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::f32)
    return 0;
  if ((!Subtarget->hasSSE1())) {
    return FastEmitInst_rr(X86::SUB_Fp32, X86::RFP32RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VSUBSSrr, X86::FR32RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  if ((Subtarget->hasSSE1())) {
    return FastEmitInst_rr(X86::SUBSSrr, X86::FR32RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_FSUB_MVT_f64_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::f64)
    return 0;
  if ((!Subtarget->hasSSE2())) {
    return FastEmitInst_rr(X86::SUB_Fp64, X86::RFP64RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VSUBSDrr, X86::FR64RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  if ((Subtarget->hasSSE2())) {
    return FastEmitInst_rr(X86::SUBSDrr, X86::FR64RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_FSUB_MVT_f80_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::f80)
    return 0;
  return FastEmitInst_rr(X86::SUB_Fp80, X86::RFP80RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_ISD_FSUB_MVT_v4f32_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v4f32)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VSUBPSrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  if ((Subtarget->hasSSE1())) {
    return FastEmitInst_rr(X86::SUBPSrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_FSUB_MVT_v8f32_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v8f32)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VSUBPSYrr, X86::VR256RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_FSUB_MVT_v2f64_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v2f64)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VSUBPDrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  if ((Subtarget->hasSSE2())) {
    return FastEmitInst_rr(X86::SUBPDrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_FSUB_MVT_v4f64_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v4f64)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VSUBPDYrr, X86::VR256RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_FSUB_rr(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  switch (VT.SimpleTy) {
  case MVT::f32: return FastEmit_ISD_FSUB_MVT_f32_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::f64: return FastEmit_ISD_FSUB_MVT_f64_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::f80: return FastEmit_ISD_FSUB_MVT_f80_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::v4f32: return FastEmit_ISD_FSUB_MVT_v4f32_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::v8f32: return FastEmit_ISD_FSUB_MVT_v8f32_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::v2f64: return FastEmit_ISD_FSUB_MVT_v2f64_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::v4f64: return FastEmit_ISD_FSUB_MVT_v4f64_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  default: return 0;
  }
}

// FastEmit functions for ISD::MUL.

unsigned FastEmit_ISD_MUL_MVT_i8_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::i8)
    return 0;
  BuildMI(*FuncInfo.MBB, FuncInfo.InsertPt, DL, TII.get(TargetOpcode::COPY), X86::AL).addReg(Op0);
  return FastEmitInst_r(X86::MUL8r, X86::GR8RegisterClass, Op1, Op1IsKill);
}

unsigned FastEmit_ISD_MUL_MVT_i16_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::i16)
    return 0;
  return FastEmitInst_rr(X86::IMUL16rr, X86::GR16RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_ISD_MUL_MVT_i32_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::i32)
    return 0;
  return FastEmitInst_rr(X86::IMUL32rr, X86::GR32RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_ISD_MUL_MVT_i64_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::i64)
    return 0;
  return FastEmitInst_rr(X86::IMUL64rr, X86::GR64RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_ISD_MUL_MVT_v4i16_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v4i16)
    return 0;
  if ((Subtarget->hasMMX() && !Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::MMX_PMULLWrr, X86::VR64RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_MUL_MVT_v8i16_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v8i16)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VPMULLWrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  if ((Subtarget->hasSSE2())) {
    return FastEmitInst_rr(X86::PMULLWrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_MUL_MVT_v4i32_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v4i32)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VPMULLDrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  if ((Subtarget->hasSSE41())) {
    return FastEmitInst_rr(X86::PMULLDrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_MUL_rr(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  switch (VT.SimpleTy) {
  case MVT::i8: return FastEmit_ISD_MUL_MVT_i8_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::i16: return FastEmit_ISD_MUL_MVT_i16_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::i32: return FastEmit_ISD_MUL_MVT_i32_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::i64: return FastEmit_ISD_MUL_MVT_i64_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::v4i16: return FastEmit_ISD_MUL_MVT_v4i16_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::v8i16: return FastEmit_ISD_MUL_MVT_v8i16_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::v4i32: return FastEmit_ISD_MUL_MVT_v4i32_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  default: return 0;
  }
}

// FastEmit functions for ISD::OR.

unsigned FastEmit_ISD_OR_MVT_i8_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::i8)
    return 0;
  return FastEmitInst_rr(X86::OR8rr, X86::GR8RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_ISD_OR_MVT_i16_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::i16)
    return 0;
  return FastEmitInst_rr(X86::OR16rr, X86::GR16RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_ISD_OR_MVT_i32_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::i32)
    return 0;
  return FastEmitInst_rr(X86::OR32rr, X86::GR32RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_ISD_OR_MVT_i64_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::i64)
    return 0;
  return FastEmitInst_rr(X86::OR64rr, X86::GR64RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_ISD_OR_MVT_v1i64_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v1i64)
    return 0;
  if ((Subtarget->hasMMX() && !Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::MMX_PORrr, X86::VR64RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_OR_MVT_v2i64_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v2i64)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VPORrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  if ((Subtarget->hasSSE1())) {
    return FastEmitInst_rr(X86::ORPSrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  if ((Subtarget->hasSSE2())) {
    return FastEmitInst_rr(X86::PORrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_OR_rr(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  switch (VT.SimpleTy) {
  case MVT::i8: return FastEmit_ISD_OR_MVT_i8_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::i16: return FastEmit_ISD_OR_MVT_i16_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::i32: return FastEmit_ISD_OR_MVT_i32_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::i64: return FastEmit_ISD_OR_MVT_i64_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::v1i64: return FastEmit_ISD_OR_MVT_v1i64_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::v2i64: return FastEmit_ISD_OR_MVT_v2i64_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  default: return 0;
  }
}

// FastEmit functions for ISD::ROTL.

unsigned FastEmit_ISD_ROTL_MVT_i8_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::i8)
    return 0;
  BuildMI(*FuncInfo.MBB, FuncInfo.InsertPt, DL, TII.get(TargetOpcode::COPY), X86::CL).addReg(Op1);
  return FastEmitInst_r(X86::ROL8rCL, X86::GR8RegisterClass, Op0, Op0IsKill);
}

unsigned FastEmit_ISD_ROTL_rr(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  switch (VT.SimpleTy) {
  case MVT::i8: return FastEmit_ISD_ROTL_MVT_i8_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  default: return 0;
  }
}

// FastEmit functions for ISD::ROTR.

unsigned FastEmit_ISD_ROTR_MVT_i8_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::i8)
    return 0;
  BuildMI(*FuncInfo.MBB, FuncInfo.InsertPt, DL, TII.get(TargetOpcode::COPY), X86::CL).addReg(Op1);
  return FastEmitInst_r(X86::ROR8rCL, X86::GR8RegisterClass, Op0, Op0IsKill);
}

unsigned FastEmit_ISD_ROTR_rr(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  switch (VT.SimpleTy) {
  case MVT::i8: return FastEmit_ISD_ROTR_MVT_i8_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  default: return 0;
  }
}

// FastEmit functions for ISD::SHL.

unsigned FastEmit_ISD_SHL_MVT_i8_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::i8)
    return 0;
  BuildMI(*FuncInfo.MBB, FuncInfo.InsertPt, DL, TII.get(TargetOpcode::COPY), X86::CL).addReg(Op1);
  return FastEmitInst_r(X86::SHL8rCL, X86::GR8RegisterClass, Op0, Op0IsKill);
}

unsigned FastEmit_ISD_SHL_rr(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  switch (VT.SimpleTy) {
  case MVT::i8: return FastEmit_ISD_SHL_MVT_i8_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  default: return 0;
  }
}

// FastEmit functions for ISD::SRA.

unsigned FastEmit_ISD_SRA_MVT_i8_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::i8)
    return 0;
  BuildMI(*FuncInfo.MBB, FuncInfo.InsertPt, DL, TII.get(TargetOpcode::COPY), X86::CL).addReg(Op1);
  return FastEmitInst_r(X86::SAR8rCL, X86::GR8RegisterClass, Op0, Op0IsKill);
}

unsigned FastEmit_ISD_SRA_rr(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  switch (VT.SimpleTy) {
  case MVT::i8: return FastEmit_ISD_SRA_MVT_i8_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  default: return 0;
  }
}

// FastEmit functions for ISD::SRL.

unsigned FastEmit_ISD_SRL_MVT_i8_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::i8)
    return 0;
  BuildMI(*FuncInfo.MBB, FuncInfo.InsertPt, DL, TII.get(TargetOpcode::COPY), X86::CL).addReg(Op1);
  return FastEmitInst_r(X86::SHR8rCL, X86::GR8RegisterClass, Op0, Op0IsKill);
}

unsigned FastEmit_ISD_SRL_rr(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  switch (VT.SimpleTy) {
  case MVT::i8: return FastEmit_ISD_SRL_MVT_i8_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  default: return 0;
  }
}

// FastEmit functions for ISD::SUB.

unsigned FastEmit_ISD_SUB_MVT_i8_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::i8)
    return 0;
  return FastEmitInst_rr(X86::SUB8rr, X86::GR8RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_ISD_SUB_MVT_i16_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::i16)
    return 0;
  return FastEmitInst_rr(X86::SUB16rr, X86::GR16RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_ISD_SUB_MVT_i32_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::i32)
    return 0;
  return FastEmitInst_rr(X86::SUB32rr, X86::GR32RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_ISD_SUB_MVT_i64_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::i64)
    return 0;
  return FastEmitInst_rr(X86::SUB64rr, X86::GR64RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_ISD_SUB_MVT_v8i8_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v8i8)
    return 0;
  if ((Subtarget->hasMMX() && !Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::MMX_PSUBBrr, X86::VR64RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_SUB_MVT_v16i8_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v16i8)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VPSUBBrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  if ((Subtarget->hasSSE2())) {
    return FastEmitInst_rr(X86::PSUBBrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_SUB_MVT_v4i16_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v4i16)
    return 0;
  if ((Subtarget->hasMMX() && !Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::MMX_PSUBWrr, X86::VR64RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_SUB_MVT_v8i16_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v8i16)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VPSUBWrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  if ((Subtarget->hasSSE2())) {
    return FastEmitInst_rr(X86::PSUBWrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_SUB_MVT_v2i32_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v2i32)
    return 0;
  if ((Subtarget->hasMMX() && !Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::MMX_PSUBDrr, X86::VR64RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_SUB_MVT_v4i32_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v4i32)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VPSUBDrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  if ((Subtarget->hasSSE2())) {
    return FastEmitInst_rr(X86::PSUBDrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_SUB_MVT_v1i64_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v1i64)
    return 0;
  if ((Subtarget->hasMMX() && !Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::MMX_PSUBQrr, X86::VR64RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_SUB_MVT_v2i64_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v2i64)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VPSUBQrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  if ((Subtarget->hasSSE2())) {
    return FastEmitInst_rr(X86::PSUBQrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_SUB_rr(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  switch (VT.SimpleTy) {
  case MVT::i8: return FastEmit_ISD_SUB_MVT_i8_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::i16: return FastEmit_ISD_SUB_MVT_i16_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::i32: return FastEmit_ISD_SUB_MVT_i32_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::i64: return FastEmit_ISD_SUB_MVT_i64_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::v8i8: return FastEmit_ISD_SUB_MVT_v8i8_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::v16i8: return FastEmit_ISD_SUB_MVT_v16i8_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::v4i16: return FastEmit_ISD_SUB_MVT_v4i16_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::v8i16: return FastEmit_ISD_SUB_MVT_v8i16_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::v2i32: return FastEmit_ISD_SUB_MVT_v2i32_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::v4i32: return FastEmit_ISD_SUB_MVT_v4i32_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::v1i64: return FastEmit_ISD_SUB_MVT_v1i64_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::v2i64: return FastEmit_ISD_SUB_MVT_v2i64_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  default: return 0;
  }
}

// FastEmit functions for ISD::SUBC.

unsigned FastEmit_ISD_SUBC_MVT_i32_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::i32)
    return 0;
  return FastEmitInst_rr(X86::SUB32rr, X86::GR32RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_ISD_SUBC_MVT_i64_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::i64)
    return 0;
  return FastEmitInst_rr(X86::SUB64rr, X86::GR64RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_ISD_SUBC_rr(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  switch (VT.SimpleTy) {
  case MVT::i32: return FastEmit_ISD_SUBC_MVT_i32_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::i64: return FastEmit_ISD_SUBC_MVT_i64_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  default: return 0;
  }
}

// FastEmit functions for ISD::SUBE.

unsigned FastEmit_ISD_SUBE_MVT_i8_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::i8)
    return 0;
  return FastEmitInst_rr(X86::SBB8rr, X86::GR8RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_ISD_SUBE_MVT_i16_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::i16)
    return 0;
  return FastEmitInst_rr(X86::SBB16rr, X86::GR16RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_ISD_SUBE_MVT_i32_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::i32)
    return 0;
  return FastEmitInst_rr(X86::SBB32rr, X86::GR32RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_ISD_SUBE_MVT_i64_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::i64)
    return 0;
  return FastEmitInst_rr(X86::SBB64rr, X86::GR64RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_ISD_SUBE_rr(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  switch (VT.SimpleTy) {
  case MVT::i8: return FastEmit_ISD_SUBE_MVT_i8_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::i16: return FastEmit_ISD_SUBE_MVT_i16_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::i32: return FastEmit_ISD_SUBE_MVT_i32_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::i64: return FastEmit_ISD_SUBE_MVT_i64_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  default: return 0;
  }
}

// FastEmit functions for ISD::XOR.

unsigned FastEmit_ISD_XOR_MVT_i8_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::i8)
    return 0;
  return FastEmitInst_rr(X86::XOR8rr, X86::GR8RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_ISD_XOR_MVT_i16_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::i16)
    return 0;
  return FastEmitInst_rr(X86::XOR16rr, X86::GR16RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_ISD_XOR_MVT_i32_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::i32)
    return 0;
  return FastEmitInst_rr(X86::XOR32rr, X86::GR32RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_ISD_XOR_MVT_i64_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::i64)
    return 0;
  return FastEmitInst_rr(X86::XOR64rr, X86::GR64RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_ISD_XOR_MVT_v1i64_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v1i64)
    return 0;
  if ((Subtarget->hasMMX() && !Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::MMX_PXORrr, X86::VR64RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_XOR_MVT_v2i64_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v2i64)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VPXORrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  if ((Subtarget->hasSSE1())) {
    return FastEmitInst_rr(X86::XORPSrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  if ((Subtarget->hasSSE2())) {
    return FastEmitInst_rr(X86::PXORrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_ISD_XOR_rr(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  switch (VT.SimpleTy) {
  case MVT::i8: return FastEmit_ISD_XOR_MVT_i8_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::i16: return FastEmit_ISD_XOR_MVT_i16_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::i32: return FastEmit_ISD_XOR_MVT_i32_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::i64: return FastEmit_ISD_XOR_MVT_i64_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::v1i64: return FastEmit_ISD_XOR_MVT_v1i64_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::v2i64: return FastEmit_ISD_XOR_MVT_v2i64_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  default: return 0;
  }
}

// FastEmit functions for X86ISD::BT.

unsigned FastEmit_X86ISD_BT_MVT_i16_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::i32)
    return 0;
  return FastEmitInst_rr(X86::BT16rr, X86::GR16RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_X86ISD_BT_MVT_i32_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::i32)
    return 0;
  return FastEmitInst_rr(X86::BT32rr, X86::GR32RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_X86ISD_BT_MVT_i64_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::i32)
    return 0;
  return FastEmitInst_rr(X86::BT64rr, X86::GR64RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_X86ISD_BT_rr(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  switch (VT.SimpleTy) {
  case MVT::i16: return FastEmit_X86ISD_BT_MVT_i16_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::i32: return FastEmit_X86ISD_BT_MVT_i32_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::i64: return FastEmit_X86ISD_BT_MVT_i64_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  default: return 0;
  }
}

// FastEmit functions for X86ISD::CMP.

unsigned FastEmit_X86ISD_CMP_MVT_i8_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::i32)
    return 0;
  return FastEmitInst_rr(X86::CMP8rr, X86::GR8RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_X86ISD_CMP_MVT_i16_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::i32)
    return 0;
  return FastEmitInst_rr(X86::CMP16rr, X86::GR16RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_X86ISD_CMP_MVT_i32_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::i32)
    return 0;
  return FastEmitInst_rr(X86::CMP32rr, X86::GR32RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_X86ISD_CMP_MVT_i64_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::i32)
    return 0;
  return FastEmitInst_rr(X86::CMP64rr, X86::GR64RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_X86ISD_CMP_MVT_f32_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::i32)
    return 0;
  if ((!Subtarget->hasSSE1())) {
    return FastEmitInst_rr(X86::UCOM_FpIr32, X86::RFP32RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VUCOMISSrr, X86::FR32RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  if ((Subtarget->hasSSE1())) {
    return FastEmitInst_rr(X86::UCOMISSrr, X86::FR32RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_X86ISD_CMP_MVT_f64_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::i32)
    return 0;
  if ((!Subtarget->hasSSE2())) {
    return FastEmitInst_rr(X86::UCOM_FpIr64, X86::RFP64RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VUCOMISDrr, X86::FR64RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  if ((Subtarget->hasSSE2())) {
    return FastEmitInst_rr(X86::UCOMISDrr, X86::FR64RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_X86ISD_CMP_MVT_f80_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::i32)
    return 0;
  return FastEmitInst_rr(X86::UCOM_FpIr80, X86::RFP80RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_X86ISD_CMP_rr(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  switch (VT.SimpleTy) {
  case MVT::i8: return FastEmit_X86ISD_CMP_MVT_i8_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::i16: return FastEmit_X86ISD_CMP_MVT_i16_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::i32: return FastEmit_X86ISD_CMP_MVT_i32_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::i64: return FastEmit_X86ISD_CMP_MVT_i64_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::f32: return FastEmit_X86ISD_CMP_MVT_f32_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::f64: return FastEmit_X86ISD_CMP_MVT_f64_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::f80: return FastEmit_X86ISD_CMP_MVT_f80_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  default: return 0;
  }
}

// FastEmit functions for X86ISD::COMI.

unsigned FastEmit_X86ISD_COMI_MVT_v4f32_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::i32)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::Int_VCOMISSrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  if ((Subtarget->hasSSE1())) {
    return FastEmitInst_rr(X86::Int_COMISSrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_X86ISD_COMI_MVT_v2f64_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::i32)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::Int_VCOMISDrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  if ((Subtarget->hasSSE2())) {
    return FastEmitInst_rr(X86::Int_COMISDrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_X86ISD_COMI_rr(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  switch (VT.SimpleTy) {
  case MVT::v4f32: return FastEmit_X86ISD_COMI_MVT_v4f32_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::v2f64: return FastEmit_X86ISD_COMI_MVT_v2f64_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  default: return 0;
  }
}

// FastEmit functions for X86ISD::FAND.

unsigned FastEmit_X86ISD_FAND_MVT_f32_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::f32)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VFsANDPSrr, X86::FR32RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  if ((Subtarget->hasSSE1())) {
    return FastEmitInst_rr(X86::FsANDPSrr, X86::FR32RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_X86ISD_FAND_MVT_f64_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::f64)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VFsANDPDrr, X86::FR64RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  if ((Subtarget->hasSSE2())) {
    return FastEmitInst_rr(X86::FsANDPDrr, X86::FR64RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_X86ISD_FAND_rr(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  switch (VT.SimpleTy) {
  case MVT::f32: return FastEmit_X86ISD_FAND_MVT_f32_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::f64: return FastEmit_X86ISD_FAND_MVT_f64_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  default: return 0;
  }
}

// FastEmit functions for X86ISD::FMAX.

unsigned FastEmit_X86ISD_FMAX_MVT_f32_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::f32)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VMAXSSrr, X86::FR32RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  if ((Subtarget->hasSSE1())) {
    return FastEmitInst_rr(X86::MAXSSrr, X86::FR32RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_X86ISD_FMAX_MVT_f64_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::f64)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VMAXSDrr, X86::FR64RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  if ((Subtarget->hasSSE2())) {
    return FastEmitInst_rr(X86::MAXSDrr, X86::FR64RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_X86ISD_FMAX_MVT_v4f32_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v4f32)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VMAXPSrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  if ((Subtarget->hasSSE1())) {
    return FastEmitInst_rr(X86::MAXPSrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_X86ISD_FMAX_MVT_v8f32_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v8f32)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VMAXPSYrr, X86::VR256RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_X86ISD_FMAX_MVT_v2f64_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v2f64)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VMAXPDrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  if ((Subtarget->hasSSE2())) {
    return FastEmitInst_rr(X86::MAXPDrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_X86ISD_FMAX_MVT_v4f64_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v4f64)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VMAXPDYrr, X86::VR256RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_X86ISD_FMAX_rr(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  switch (VT.SimpleTy) {
  case MVT::f32: return FastEmit_X86ISD_FMAX_MVT_f32_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::f64: return FastEmit_X86ISD_FMAX_MVT_f64_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::v4f32: return FastEmit_X86ISD_FMAX_MVT_v4f32_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::v8f32: return FastEmit_X86ISD_FMAX_MVT_v8f32_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::v2f64: return FastEmit_X86ISD_FMAX_MVT_v2f64_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::v4f64: return FastEmit_X86ISD_FMAX_MVT_v4f64_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  default: return 0;
  }
}

// FastEmit functions for X86ISD::FMIN.

unsigned FastEmit_X86ISD_FMIN_MVT_f32_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::f32)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VMINSSrr, X86::FR32RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  if ((Subtarget->hasSSE1())) {
    return FastEmitInst_rr(X86::MINSSrr, X86::FR32RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_X86ISD_FMIN_MVT_f64_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::f64)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VMINSDrr, X86::FR64RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  if ((Subtarget->hasSSE2())) {
    return FastEmitInst_rr(X86::MINSDrr, X86::FR64RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_X86ISD_FMIN_MVT_v4f32_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v4f32)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VMINPSrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  if ((Subtarget->hasSSE1())) {
    return FastEmitInst_rr(X86::MINPSrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_X86ISD_FMIN_MVT_v8f32_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v8f32)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VMINPSYrr, X86::VR256RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_X86ISD_FMIN_MVT_v2f64_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v2f64)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VMINPDrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  if ((Subtarget->hasSSE2())) {
    return FastEmitInst_rr(X86::MINPDrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_X86ISD_FMIN_MVT_v4f64_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v4f64)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VMINPDYrr, X86::VR256RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_X86ISD_FMIN_rr(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  switch (VT.SimpleTy) {
  case MVT::f32: return FastEmit_X86ISD_FMIN_MVT_f32_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::f64: return FastEmit_X86ISD_FMIN_MVT_f64_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::v4f32: return FastEmit_X86ISD_FMIN_MVT_v4f32_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::v8f32: return FastEmit_X86ISD_FMIN_MVT_v8f32_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::v2f64: return FastEmit_X86ISD_FMIN_MVT_v2f64_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::v4f64: return FastEmit_X86ISD_FMIN_MVT_v4f64_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  default: return 0;
  }
}

// FastEmit functions for X86ISD::FOR.

unsigned FastEmit_X86ISD_FOR_MVT_f32_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::f32)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VFsORPSrr, X86::FR32RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  if ((Subtarget->hasSSE1())) {
    return FastEmitInst_rr(X86::FsORPSrr, X86::FR32RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_X86ISD_FOR_MVT_f64_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::f64)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VFsORPDrr, X86::FR64RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  if ((Subtarget->hasSSE2())) {
    return FastEmitInst_rr(X86::FsORPDrr, X86::FR64RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_X86ISD_FOR_rr(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  switch (VT.SimpleTy) {
  case MVT::f32: return FastEmit_X86ISD_FOR_MVT_f32_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::f64: return FastEmit_X86ISD_FOR_MVT_f64_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  default: return 0;
  }
}

// FastEmit functions for X86ISD::FXOR.

unsigned FastEmit_X86ISD_FXOR_MVT_f32_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::f32)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VFsXORPSrr, X86::FR32RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  if ((Subtarget->hasSSE1())) {
    return FastEmitInst_rr(X86::FsXORPSrr, X86::FR32RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_X86ISD_FXOR_MVT_f64_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::f64)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VFsXORPDrr, X86::FR64RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  if ((Subtarget->hasSSE2())) {
    return FastEmitInst_rr(X86::FsXORPDrr, X86::FR64RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_X86ISD_FXOR_rr(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  switch (VT.SimpleTy) {
  case MVT::f32: return FastEmit_X86ISD_FXOR_MVT_f32_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::f64: return FastEmit_X86ISD_FXOR_MVT_f64_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  default: return 0;
  }
}

// FastEmit functions for X86ISD::MOVHLPS.

unsigned FastEmit_X86ISD_MOVHLPS_MVT_v4i32_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v4i32)
    return 0;
  return FastEmitInst_rr(X86::MOVHLPSrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_X86ISD_MOVHLPS_MVT_v4f32_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v4f32)
    return 0;
  return FastEmitInst_rr(X86::MOVHLPSrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_X86ISD_MOVHLPS_rr(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  switch (VT.SimpleTy) {
  case MVT::v4i32: return FastEmit_X86ISD_MOVHLPS_MVT_v4i32_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::v4f32: return FastEmit_X86ISD_MOVHLPS_MVT_v4f32_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  default: return 0;
  }
}

// FastEmit functions for X86ISD::MOVLHPS.

unsigned FastEmit_X86ISD_MOVLHPS_MVT_v4i32_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v4i32)
    return 0;
  return FastEmitInst_rr(X86::MOVLHPSrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_X86ISD_MOVLHPS_MVT_v2i64_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v2i64)
    return 0;
  return FastEmitInst_rr(X86::MOVLHPSrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_X86ISD_MOVLHPS_MVT_v4f32_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v4f32)
    return 0;
  return FastEmitInst_rr(X86::MOVLHPSrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_X86ISD_MOVLHPS_rr(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  switch (VT.SimpleTy) {
  case MVT::v4i32: return FastEmit_X86ISD_MOVLHPS_MVT_v4i32_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::v2i64: return FastEmit_X86ISD_MOVLHPS_MVT_v2i64_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::v4f32: return FastEmit_X86ISD_MOVLHPS_MVT_v4f32_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  default: return 0;
  }
}

// FastEmit functions for X86ISD::PCMPEQB.

unsigned FastEmit_X86ISD_PCMPEQB_MVT_v8i8_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v8i8)
    return 0;
  return FastEmitInst_rr(X86::MMX_PCMPEQBrr, X86::VR64RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_X86ISD_PCMPEQB_MVT_v16i8_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v16i8)
    return 0;
  return FastEmitInst_rr(X86::PCMPEQBrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_X86ISD_PCMPEQB_rr(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  switch (VT.SimpleTy) {
  case MVT::v8i8: return FastEmit_X86ISD_PCMPEQB_MVT_v8i8_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::v16i8: return FastEmit_X86ISD_PCMPEQB_MVT_v16i8_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  default: return 0;
  }
}

// FastEmit functions for X86ISD::PCMPEQD.

unsigned FastEmit_X86ISD_PCMPEQD_MVT_v2i32_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v2i32)
    return 0;
  return FastEmitInst_rr(X86::MMX_PCMPEQDrr, X86::VR64RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_X86ISD_PCMPEQD_MVT_v4i32_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v4i32)
    return 0;
  return FastEmitInst_rr(X86::PCMPEQDrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_X86ISD_PCMPEQD_rr(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  switch (VT.SimpleTy) {
  case MVT::v2i32: return FastEmit_X86ISD_PCMPEQD_MVT_v2i32_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::v4i32: return FastEmit_X86ISD_PCMPEQD_MVT_v4i32_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  default: return 0;
  }
}

// FastEmit functions for X86ISD::PCMPEQQ.

unsigned FastEmit_X86ISD_PCMPEQQ_MVT_v2i64_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v2i64)
    return 0;
  return FastEmitInst_rr(X86::PCMPEQQrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_X86ISD_PCMPEQQ_rr(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  switch (VT.SimpleTy) {
  case MVT::v2i64: return FastEmit_X86ISD_PCMPEQQ_MVT_v2i64_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  default: return 0;
  }
}

// FastEmit functions for X86ISD::PCMPEQW.

unsigned FastEmit_X86ISD_PCMPEQW_MVT_v4i16_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v4i16)
    return 0;
  return FastEmitInst_rr(X86::MMX_PCMPEQWrr, X86::VR64RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_X86ISD_PCMPEQW_MVT_v8i16_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v8i16)
    return 0;
  return FastEmitInst_rr(X86::PCMPEQWrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_X86ISD_PCMPEQW_rr(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  switch (VT.SimpleTy) {
  case MVT::v4i16: return FastEmit_X86ISD_PCMPEQW_MVT_v4i16_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::v8i16: return FastEmit_X86ISD_PCMPEQW_MVT_v8i16_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  default: return 0;
  }
}

// FastEmit functions for X86ISD::PCMPGTB.

unsigned FastEmit_X86ISD_PCMPGTB_MVT_v8i8_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v8i8)
    return 0;
  return FastEmitInst_rr(X86::MMX_PCMPGTBrr, X86::VR64RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_X86ISD_PCMPGTB_MVT_v16i8_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v16i8)
    return 0;
  return FastEmitInst_rr(X86::PCMPGTBrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_X86ISD_PCMPGTB_rr(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  switch (VT.SimpleTy) {
  case MVT::v8i8: return FastEmit_X86ISD_PCMPGTB_MVT_v8i8_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::v16i8: return FastEmit_X86ISD_PCMPGTB_MVT_v16i8_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  default: return 0;
  }
}

// FastEmit functions for X86ISD::PCMPGTD.

unsigned FastEmit_X86ISD_PCMPGTD_MVT_v2i32_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v2i32)
    return 0;
  return FastEmitInst_rr(X86::MMX_PCMPGTDrr, X86::VR64RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_X86ISD_PCMPGTD_MVT_v4i32_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v4i32)
    return 0;
  return FastEmitInst_rr(X86::PCMPGTDrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_X86ISD_PCMPGTD_rr(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  switch (VT.SimpleTy) {
  case MVT::v2i32: return FastEmit_X86ISD_PCMPGTD_MVT_v2i32_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::v4i32: return FastEmit_X86ISD_PCMPGTD_MVT_v4i32_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  default: return 0;
  }
}

// FastEmit functions for X86ISD::PCMPGTQ.

unsigned FastEmit_X86ISD_PCMPGTQ_MVT_v2i64_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v2i64)
    return 0;
  return FastEmitInst_rr(X86::PCMPGTQrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_X86ISD_PCMPGTQ_rr(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  switch (VT.SimpleTy) {
  case MVT::v2i64: return FastEmit_X86ISD_PCMPGTQ_MVT_v2i64_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  default: return 0;
  }
}

// FastEmit functions for X86ISD::PCMPGTW.

unsigned FastEmit_X86ISD_PCMPGTW_MVT_v4i16_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v4i16)
    return 0;
  return FastEmitInst_rr(X86::MMX_PCMPGTWrr, X86::VR64RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_X86ISD_PCMPGTW_MVT_v8i16_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v8i16)
    return 0;
  return FastEmitInst_rr(X86::PCMPGTWrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_X86ISD_PCMPGTW_rr(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  switch (VT.SimpleTy) {
  case MVT::v4i16: return FastEmit_X86ISD_PCMPGTW_MVT_v4i16_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::v8i16: return FastEmit_X86ISD_PCMPGTW_MVT_v8i16_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  default: return 0;
  }
}

// FastEmit functions for X86ISD::PSHUFB.

unsigned FastEmit_X86ISD_PSHUFB_MVT_v16i8_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v16i8)
    return 0;
  if ((Subtarget->hasSSSE3())) {
    return FastEmitInst_rr(X86::PSHUFBrr128, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_X86ISD_PSHUFB_rr(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  switch (VT.SimpleTy) {
  case MVT::v16i8: return FastEmit_X86ISD_PSHUFB_MVT_v16i8_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  default: return 0;
  }
}

// FastEmit functions for X86ISD::PTEST.

unsigned FastEmit_X86ISD_PTEST_MVT_v4i64_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::i32)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VPTESTYrr, X86::VR256RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_X86ISD_PTEST_MVT_v4f32_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::i32)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VPTESTrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  if ((Subtarget->hasSSE41())) {
    return FastEmitInst_rr(X86::PTESTrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_X86ISD_PTEST_rr(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  switch (VT.SimpleTy) {
  case MVT::v4i64: return FastEmit_X86ISD_PTEST_MVT_v4i64_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::v4f32: return FastEmit_X86ISD_PTEST_MVT_v4f32_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  default: return 0;
  }
}

// FastEmit functions for X86ISD::PUNPCKHBW.

unsigned FastEmit_X86ISD_PUNPCKHBW_MVT_v16i8_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v16i8)
    return 0;
  return FastEmitInst_rr(X86::PUNPCKHBWrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_X86ISD_PUNPCKHBW_rr(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  switch (VT.SimpleTy) {
  case MVT::v16i8: return FastEmit_X86ISD_PUNPCKHBW_MVT_v16i8_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  default: return 0;
  }
}

// FastEmit functions for X86ISD::PUNPCKHDQ.

unsigned FastEmit_X86ISD_PUNPCKHDQ_MVT_v4i32_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v4i32)
    return 0;
  return FastEmitInst_rr(X86::PUNPCKHDQrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_X86ISD_PUNPCKHDQ_rr(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  switch (VT.SimpleTy) {
  case MVT::v4i32: return FastEmit_X86ISD_PUNPCKHDQ_MVT_v4i32_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  default: return 0;
  }
}

// FastEmit functions for X86ISD::PUNPCKHQDQ.

unsigned FastEmit_X86ISD_PUNPCKHQDQ_MVT_v2i64_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v2i64)
    return 0;
  return FastEmitInst_rr(X86::PUNPCKHQDQrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_X86ISD_PUNPCKHQDQ_rr(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  switch (VT.SimpleTy) {
  case MVT::v2i64: return FastEmit_X86ISD_PUNPCKHQDQ_MVT_v2i64_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  default: return 0;
  }
}

// FastEmit functions for X86ISD::PUNPCKHWD.

unsigned FastEmit_X86ISD_PUNPCKHWD_MVT_v8i16_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v8i16)
    return 0;
  return FastEmitInst_rr(X86::PUNPCKHWDrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_X86ISD_PUNPCKHWD_rr(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  switch (VT.SimpleTy) {
  case MVT::v8i16: return FastEmit_X86ISD_PUNPCKHWD_MVT_v8i16_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  default: return 0;
  }
}

// FastEmit functions for X86ISD::PUNPCKLBW.

unsigned FastEmit_X86ISD_PUNPCKLBW_MVT_v16i8_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v16i8)
    return 0;
  return FastEmitInst_rr(X86::PUNPCKLBWrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_X86ISD_PUNPCKLBW_rr(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  switch (VT.SimpleTy) {
  case MVT::v16i8: return FastEmit_X86ISD_PUNPCKLBW_MVT_v16i8_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  default: return 0;
  }
}

// FastEmit functions for X86ISD::PUNPCKLDQ.

unsigned FastEmit_X86ISD_PUNPCKLDQ_MVT_v4i32_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v4i32)
    return 0;
  return FastEmitInst_rr(X86::PUNPCKLDQrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_X86ISD_PUNPCKLDQ_rr(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  switch (VT.SimpleTy) {
  case MVT::v4i32: return FastEmit_X86ISD_PUNPCKLDQ_MVT_v4i32_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  default: return 0;
  }
}

// FastEmit functions for X86ISD::PUNPCKLQDQ.

unsigned FastEmit_X86ISD_PUNPCKLQDQ_MVT_v2i64_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v2i64)
    return 0;
  return FastEmitInst_rr(X86::PUNPCKLQDQrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_X86ISD_PUNPCKLQDQ_rr(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  switch (VT.SimpleTy) {
  case MVT::v2i64: return FastEmit_X86ISD_PUNPCKLQDQ_MVT_v2i64_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  default: return 0;
  }
}

// FastEmit functions for X86ISD::PUNPCKLWD.

unsigned FastEmit_X86ISD_PUNPCKLWD_MVT_v8i16_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v8i16)
    return 0;
  return FastEmitInst_rr(X86::PUNPCKLWDrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
}

unsigned FastEmit_X86ISD_PUNPCKLWD_rr(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  switch (VT.SimpleTy) {
  case MVT::v8i16: return FastEmit_X86ISD_PUNPCKLWD_MVT_v8i16_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  default: return 0;
  }
}

// FastEmit functions for X86ISD::TESTP.

unsigned FastEmit_X86ISD_TESTP_MVT_v4f32_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::i32)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VTESTPSrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_X86ISD_TESTP_MVT_v8f32_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::i32)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VTESTPSYrr, X86::VR256RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_X86ISD_TESTP_MVT_v2f64_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::i32)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VTESTPDrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_X86ISD_TESTP_MVT_v4f64_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::i32)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VTESTPDYrr, X86::VR256RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_X86ISD_TESTP_rr(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  switch (VT.SimpleTy) {
  case MVT::v4f32: return FastEmit_X86ISD_TESTP_MVT_v4f32_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::v8f32: return FastEmit_X86ISD_TESTP_MVT_v8f32_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::v2f64: return FastEmit_X86ISD_TESTP_MVT_v2f64_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::v4f64: return FastEmit_X86ISD_TESTP_MVT_v4f64_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  default: return 0;
  }
}

// FastEmit functions for X86ISD::UCOMI.

unsigned FastEmit_X86ISD_UCOMI_MVT_v4f32_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::i32)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::Int_VUCOMISSrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  if ((Subtarget->hasSSE1())) {
    return FastEmitInst_rr(X86::Int_UCOMISSrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_X86ISD_UCOMI_MVT_v2f64_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::i32)
    return 0;
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::Int_VUCOMISDrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  if ((Subtarget->hasSSE2())) {
    return FastEmitInst_rr(X86::Int_UCOMISDrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_X86ISD_UCOMI_rr(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  switch (VT.SimpleTy) {
  case MVT::v4f32: return FastEmit_X86ISD_UCOMI_MVT_v4f32_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case MVT::v2f64: return FastEmit_X86ISD_UCOMI_MVT_v2f64_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  default: return 0;
  }
}

// FastEmit functions for X86ISD::UNPCKHPD.

unsigned FastEmit_X86ISD_UNPCKHPD_MVT_v2f64_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v2f64)
    return 0;
  return FastEmitInst_rr(X86::UNPCKHPDrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VUNPCKHPDrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_X86ISD_UNPCKHPD_rr(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  switch (VT.SimpleTy) {
  case MVT::v2f64: return FastEmit_X86ISD_UNPCKHPD_MVT_v2f64_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  default: return 0;
  }
}

// FastEmit functions for X86ISD::UNPCKHPS.

unsigned FastEmit_X86ISD_UNPCKHPS_MVT_v4f32_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v4f32)
    return 0;
  return FastEmitInst_rr(X86::UNPCKHPSrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VUNPCKHPSrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_X86ISD_UNPCKHPS_rr(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  switch (VT.SimpleTy) {
  case MVT::v4f32: return FastEmit_X86ISD_UNPCKHPS_MVT_v4f32_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  default: return 0;
  }
}

// FastEmit functions for X86ISD::UNPCKLPD.

unsigned FastEmit_X86ISD_UNPCKLPD_MVT_v2f64_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v2f64)
    return 0;
  return FastEmitInst_rr(X86::UNPCKLPDrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VUNPCKLPDrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_X86ISD_UNPCKLPD_rr(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  switch (VT.SimpleTy) {
  case MVT::v2f64: return FastEmit_X86ISD_UNPCKLPD_MVT_v2f64_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  default: return 0;
  }
}

// FastEmit functions for X86ISD::UNPCKLPS.

unsigned FastEmit_X86ISD_UNPCKLPS_MVT_v4f32_rr(MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  if (RetVT.SimpleTy != MVT::v4f32)
    return 0;
  return FastEmitInst_rr(X86::UNPCKLPSrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  if ((Subtarget->hasAVX())) {
    return FastEmitInst_rr(X86::VUNPCKLPSrr, X86::VR128RegisterClass, Op0, Op0IsKill, Op1, Op1IsKill);
  }
  return 0;
}

unsigned FastEmit_X86ISD_UNPCKLPS_rr(MVT VT, MVT RetVT, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  switch (VT.SimpleTy) {
  case MVT::v4f32: return FastEmit_X86ISD_UNPCKLPS_MVT_v4f32_rr(RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  default: return 0;
  }
}

// Top-level FastEmit function.

unsigned FastEmit_rr(MVT VT, MVT RetVT, unsigned Opcode, unsigned Op0, bool Op0IsKill, unsigned Op1, bool Op1IsKill) {
  switch (Opcode) {
  case ISD::ADD: return FastEmit_ISD_ADD_rr(VT, RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case ISD::ADDC: return FastEmit_ISD_ADDC_rr(VT, RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case ISD::ADDE: return FastEmit_ISD_ADDE_rr(VT, RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case ISD::AND: return FastEmit_ISD_AND_rr(VT, RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case ISD::FADD: return FastEmit_ISD_FADD_rr(VT, RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case ISD::FDIV: return FastEmit_ISD_FDIV_rr(VT, RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case ISD::FMUL: return FastEmit_ISD_FMUL_rr(VT, RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case ISD::FSUB: return FastEmit_ISD_FSUB_rr(VT, RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case ISD::MUL: return FastEmit_ISD_MUL_rr(VT, RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case ISD::OR: return FastEmit_ISD_OR_rr(VT, RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case ISD::ROTL: return FastEmit_ISD_ROTL_rr(VT, RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case ISD::ROTR: return FastEmit_ISD_ROTR_rr(VT, RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case ISD::SHL: return FastEmit_ISD_SHL_rr(VT, RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case ISD::SRA: return FastEmit_ISD_SRA_rr(VT, RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case ISD::SRL: return FastEmit_ISD_SRL_rr(VT, RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case ISD::SUB: return FastEmit_ISD_SUB_rr(VT, RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case ISD::SUBC: return FastEmit_ISD_SUBC_rr(VT, RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case ISD::SUBE: return FastEmit_ISD_SUBE_rr(VT, RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case ISD::XOR: return FastEmit_ISD_XOR_rr(VT, RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case X86ISD::BT: return FastEmit_X86ISD_BT_rr(VT, RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case X86ISD::CMP: return FastEmit_X86ISD_CMP_rr(VT, RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case X86ISD::COMI: return FastEmit_X86ISD_COMI_rr(VT, RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case X86ISD::FAND: return FastEmit_X86ISD_FAND_rr(VT, RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case X86ISD::FMAX: return FastEmit_X86ISD_FMAX_rr(VT, RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case X86ISD::FMIN: return FastEmit_X86ISD_FMIN_rr(VT, RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case X86ISD::FOR: return FastEmit_X86ISD_FOR_rr(VT, RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case X86ISD::FXOR: return FastEmit_X86ISD_FXOR_rr(VT, RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case X86ISD::MOVHLPS: return FastEmit_X86ISD_MOVHLPS_rr(VT, RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case X86ISD::MOVLHPS: return FastEmit_X86ISD_MOVLHPS_rr(VT, RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case X86ISD::PCMPEQB: return FastEmit_X86ISD_PCMPEQB_rr(VT, RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case X86ISD::PCMPEQD: return FastEmit_X86ISD_PCMPEQD_rr(VT, RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case X86ISD::PCMPEQQ: return FastEmit_X86ISD_PCMPEQQ_rr(VT, RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case X86ISD::PCMPEQW: return FastEmit_X86ISD_PCMPEQW_rr(VT, RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case X86ISD::PCMPGTB: return FastEmit_X86ISD_PCMPGTB_rr(VT, RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case X86ISD::PCMPGTD: return FastEmit_X86ISD_PCMPGTD_rr(VT, RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case X86ISD::PCMPGTQ: return FastEmit_X86ISD_PCMPGTQ_rr(VT, RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case X86ISD::PCMPGTW: return FastEmit_X86ISD_PCMPGTW_rr(VT, RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case X86ISD::PSHUFB: return FastEmit_X86ISD_PSHUFB_rr(VT, RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case X86ISD::PTEST: return FastEmit_X86ISD_PTEST_rr(VT, RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case X86ISD::PUNPCKHBW: return FastEmit_X86ISD_PUNPCKHBW_rr(VT, RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case X86ISD::PUNPCKHDQ: return FastEmit_X86ISD_PUNPCKHDQ_rr(VT, RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case X86ISD::PUNPCKHQDQ: return FastEmit_X86ISD_PUNPCKHQDQ_rr(VT, RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case X86ISD::PUNPCKHWD: return FastEmit_X86ISD_PUNPCKHWD_rr(VT, RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case X86ISD::PUNPCKLBW: return FastEmit_X86ISD_PUNPCKLBW_rr(VT, RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case X86ISD::PUNPCKLDQ: return FastEmit_X86ISD_PUNPCKLDQ_rr(VT, RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case X86ISD::PUNPCKLQDQ: return FastEmit_X86ISD_PUNPCKLQDQ_rr(VT, RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case X86ISD::PUNPCKLWD: return FastEmit_X86ISD_PUNPCKLWD_rr(VT, RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case X86ISD::TESTP: return FastEmit_X86ISD_TESTP_rr(VT, RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case X86ISD::UCOMI: return FastEmit_X86ISD_UCOMI_rr(VT, RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case X86ISD::UNPCKHPD: return FastEmit_X86ISD_UNPCKHPD_rr(VT, RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case X86ISD::UNPCKHPS: return FastEmit_X86ISD_UNPCKHPS_rr(VT, RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case X86ISD::UNPCKLPD: return FastEmit_X86ISD_UNPCKLPD_rr(VT, RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  case X86ISD::UNPCKLPS: return FastEmit_X86ISD_UNPCKLPS_rr(VT, RetVT, Op0, Op0IsKill, Op1, Op1IsKill);
  default: return 0;
  }
}

