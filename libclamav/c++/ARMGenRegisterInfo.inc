//===- TableGen'erated file -------------------------------------*- C++ -*-===//
//
// Register Information Source Fragment
//
// Automatically generated file, do not edit!
//
//===----------------------------------------------------------------------===//

namespace llvm {

namespace {     // Register classes...
  // CCR Register Class...
  static const unsigned CCR[] = {
    ARM::CPSR, 
  };

  // DPR Register Class...
  static const unsigned DPR[] = {
    ARM::D0, ARM::D1, ARM::D2, ARM::D3, ARM::D4, ARM::D5, ARM::D6, ARM::D7, ARM::D8, ARM::D9, ARM::D10, ARM::D11, ARM::D12, ARM::D13, ARM::D14, ARM::D15, ARM::D16, ARM::D17, ARM::D18, ARM::D19, ARM::D20, ARM::D21, ARM::D22, ARM::D23, ARM::D24, ARM::D25, ARM::D26, ARM::D27, ARM::D28, ARM::D29, ARM::D30, ARM::D31, 
  };

  // DPR_8 Register Class...
  static const unsigned DPR_8[] = {
    ARM::D0, ARM::D1, ARM::D2, ARM::D3, ARM::D4, ARM::D5, ARM::D6, ARM::D7, 
  };

  // DPR_VFP2 Register Class...
  static const unsigned DPR_VFP2[] = {
    ARM::D0, ARM::D1, ARM::D2, ARM::D3, ARM::D4, ARM::D5, ARM::D6, ARM::D7, ARM::D8, ARM::D9, ARM::D10, ARM::D11, ARM::D12, ARM::D13, ARM::D14, ARM::D15, 
  };

  // GPR Register Class...
  static const unsigned GPR[] = {
    ARM::R0, ARM::R1, ARM::R2, ARM::R3, ARM::R4, ARM::R5, ARM::R6, ARM::R7, ARM::R8, ARM::R9, ARM::R10, ARM::R11, ARM::R12, ARM::SP, ARM::LR, ARM::PC, 
  };

  // QPR Register Class...
  static const unsigned QPR[] = {
    ARM::Q0, ARM::Q1, ARM::Q2, ARM::Q3, ARM::Q4, ARM::Q5, ARM::Q6, ARM::Q7, ARM::Q8, ARM::Q9, ARM::Q10, ARM::Q11, ARM::Q12, ARM::Q13, ARM::Q14, ARM::Q15, 
  };

  // QPR_8 Register Class...
  static const unsigned QPR_8[] = {
    ARM::Q0, ARM::Q1, ARM::Q2, ARM::Q3, 
  };

  // QPR_VFP2 Register Class...
  static const unsigned QPR_VFP2[] = {
    ARM::Q0, ARM::Q1, ARM::Q2, ARM::Q3, ARM::Q4, ARM::Q5, ARM::Q6, ARM::Q7, 
  };

  // SPR Register Class...
  static const unsigned SPR[] = {
    ARM::S0, ARM::S1, ARM::S2, ARM::S3, ARM::S4, ARM::S5, ARM::S6, ARM::S7, ARM::S8, ARM::S9, ARM::S10, ARM::S11, ARM::S12, ARM::S13, ARM::S14, ARM::S15, ARM::S16, ARM::S17, ARM::S18, ARM::S19, ARM::S20, ARM::S21, ARM::S22, ARM::S23, ARM::S24, ARM::S25, ARM::S26, ARM::S27, ARM::S28, ARM::S29, ARM::S30, ARM::S31, 
  };

  // SPR_8 Register Class...
  static const unsigned SPR_8[] = {
    ARM::S0, ARM::S1, ARM::S2, ARM::S3, ARM::S4, ARM::S5, ARM::S6, ARM::S7, ARM::S8, ARM::S9, ARM::S10, ARM::S11, ARM::S12, ARM::S13, ARM::S14, ARM::S15, 
  };

  // SPR_INVALID Register Class...
  static const unsigned SPR_INVALID[] = {
    ARM::SDummy, 
  };

  // tGPR Register Class...
  static const unsigned tGPR[] = {
    ARM::R0, ARM::R1, ARM::R2, ARM::R3, ARM::R4, ARM::R5, ARM::R6, ARM::R7, 
  };

  // CCRVTs Register Class Value Types...
  static const EVT CCRVTs[] = {
    MVT::i32, MVT::Other
  };

  // DPRVTs Register Class Value Types...
  static const EVT DPRVTs[] = {
    MVT::f64, MVT::v8i8, MVT::v4i16, MVT::v2i32, MVT::v1i64, MVT::v2f32, MVT::Other
  };

  // DPR_8VTs Register Class Value Types...
  static const EVT DPR_8VTs[] = {
    MVT::f64, MVT::v8i8, MVT::v4i16, MVT::v2i32, MVT::v1i64, MVT::v2f32, MVT::Other
  };

  // DPR_VFP2VTs Register Class Value Types...
  static const EVT DPR_VFP2VTs[] = {
    MVT::f64, MVT::v8i8, MVT::v4i16, MVT::v2i32, MVT::v1i64, MVT::v2f32, MVT::Other
  };

  // GPRVTs Register Class Value Types...
  static const EVT GPRVTs[] = {
    MVT::i32, MVT::Other
  };

  // QPRVTs Register Class Value Types...
  static const EVT QPRVTs[] = {
    MVT::v16i8, MVT::v8i16, MVT::v4i32, MVT::v2i64, MVT::v4f32, MVT::v2f64, MVT::Other
  };

  // QPR_8VTs Register Class Value Types...
  static const EVT QPR_8VTs[] = {
    MVT::v16i8, MVT::v8i16, MVT::v4i32, MVT::v2i64, MVT::v4f32, MVT::v2f64, MVT::Other
  };

  // QPR_VFP2VTs Register Class Value Types...
  static const EVT QPR_VFP2VTs[] = {
    MVT::v16i8, MVT::v8i16, MVT::v4i32, MVT::v2i64, MVT::v4f32, MVT::v2f64, MVT::Other
  };

  // SPRVTs Register Class Value Types...
  static const EVT SPRVTs[] = {
    MVT::f32, MVT::Other
  };

  // SPR_8VTs Register Class Value Types...
  static const EVT SPR_8VTs[] = {
    MVT::f32, MVT::Other
  };

  // SPR_INVALIDVTs Register Class Value Types...
  static const EVT SPR_INVALIDVTs[] = {
    MVT::f32, MVT::Other
  };

  // tGPRVTs Register Class Value Types...
  static const EVT tGPRVTs[] = {
    MVT::i32, MVT::Other
  };

}  // end anonymous namespace

namespace ARM {   // Register class instances
  CCRClass	CCRRegClass;
  DPRClass	DPRRegClass;
  DPR_8Class	DPR_8RegClass;
  DPR_VFP2Class	DPR_VFP2RegClass;
  GPRClass	GPRRegClass;
  QPRClass	QPRRegClass;
  QPR_8Class	QPR_8RegClass;
  QPR_VFP2Class	QPR_VFP2RegClass;
  SPRClass	SPRRegClass;
  SPR_8Class	SPR_8RegClass;
  SPR_INVALIDClass	SPR_INVALIDRegClass;
  tGPRClass	tGPRRegClass;

  // CCR Sub-register Classes...
  static const TargetRegisterClass* const CCRSubRegClasses[] = {
    NULL
  };

  // DPR Sub-register Classes...
  static const TargetRegisterClass* const DPRSubRegClasses[] = {
    &ARM::SPR_INVALIDRegClass, &ARM::SPR_INVALIDRegClass, NULL
  };

  // DPR_8 Sub-register Classes...
  static const TargetRegisterClass* const DPR_8SubRegClasses[] = {
    &ARM::SPR_8RegClass, &ARM::SPR_8RegClass, NULL
  };

  // DPR_VFP2 Sub-register Classes...
  static const TargetRegisterClass* const DPR_VFP2SubRegClasses[] = {
    &ARM::SPRRegClass, &ARM::SPRRegClass, NULL
  };

  // GPR Sub-register Classes...
  static const TargetRegisterClass* const GPRSubRegClasses[] = {
    NULL
  };

  // QPR Sub-register Classes...
  static const TargetRegisterClass* const QPRSubRegClasses[] = {
    &ARM::SPR_INVALIDRegClass, &ARM::SPR_INVALIDRegClass, &ARM::SPR_INVALIDRegClass, &ARM::SPR_INVALIDRegClass, &ARM::DPRRegClass, &ARM::DPRRegClass, NULL
  };

  // QPR_8 Sub-register Classes...
  static const TargetRegisterClass* const QPR_8SubRegClasses[] = {
    &ARM::SPR_8RegClass, &ARM::SPR_8RegClass, &ARM::SPR_8RegClass, &ARM::SPR_8RegClass, &ARM::DPR_8RegClass, &ARM::DPR_8RegClass, NULL
  };

  // QPR_VFP2 Sub-register Classes...
  static const TargetRegisterClass* const QPR_VFP2SubRegClasses[] = {
    &ARM::SPRRegClass, &ARM::SPRRegClass, &ARM::SPRRegClass, &ARM::SPRRegClass, &ARM::DPR_VFP2RegClass, &ARM::DPR_VFP2RegClass, NULL
  };

  // SPR Sub-register Classes...
  static const TargetRegisterClass* const SPRSubRegClasses[] = {
    NULL
  };

  // SPR_8 Sub-register Classes...
  static const TargetRegisterClass* const SPR_8SubRegClasses[] = {
    NULL
  };

  // SPR_INVALID Sub-register Classes...
  static const TargetRegisterClass* const SPR_INVALIDSubRegClasses[] = {
    NULL
  };

  // tGPR Sub-register Classes...
  static const TargetRegisterClass* const tGPRSubRegClasses[] = {
    NULL
  };

  // CCR Super-register Classes...
  static const TargetRegisterClass* const CCRSuperRegClasses[] = {
    NULL
  };

  // DPR Super-register Classes...
  static const TargetRegisterClass* const DPRSuperRegClasses[] = {
    &ARM::QPRRegClass, NULL
  };

  // DPR_8 Super-register Classes...
  static const TargetRegisterClass* const DPR_8SuperRegClasses[] = {
    &ARM::QPR_8RegClass, NULL
  };

  // DPR_VFP2 Super-register Classes...
  static const TargetRegisterClass* const DPR_VFP2SuperRegClasses[] = {
    &ARM::QPR_VFP2RegClass, NULL
  };

  // GPR Super-register Classes...
  static const TargetRegisterClass* const GPRSuperRegClasses[] = {
    NULL
  };

  // QPR Super-register Classes...
  static const TargetRegisterClass* const QPRSuperRegClasses[] = {
    NULL
  };

  // QPR_8 Super-register Classes...
  static const TargetRegisterClass* const QPR_8SuperRegClasses[] = {
    NULL
  };

  // QPR_VFP2 Super-register Classes...
  static const TargetRegisterClass* const QPR_VFP2SuperRegClasses[] = {
    NULL
  };

  // SPR Super-register Classes...
  static const TargetRegisterClass* const SPRSuperRegClasses[] = {
    &ARM::DPR_VFP2RegClass, &ARM::QPR_VFP2RegClass, NULL
  };

  // SPR_8 Super-register Classes...
  static const TargetRegisterClass* const SPR_8SuperRegClasses[] = {
    &ARM::DPR_8RegClass, &ARM::QPR_8RegClass, NULL
  };

  // SPR_INVALID Super-register Classes...
  static const TargetRegisterClass* const SPR_INVALIDSuperRegClasses[] = {
    &ARM::DPRRegClass, &ARM::QPRRegClass, NULL
  };

  // tGPR Super-register Classes...
  static const TargetRegisterClass* const tGPRSuperRegClasses[] = {
    NULL
  };

  // CCR Register Class sub-classes...
  static const TargetRegisterClass* const CCRSubclasses[] = {
    NULL
  };

  // DPR Register Class sub-classes...
  static const TargetRegisterClass* const DPRSubclasses[] = {
    &ARM::DPR_8RegClass, &ARM::DPR_VFP2RegClass, NULL
  };

  // DPR_8 Register Class sub-classes...
  static const TargetRegisterClass* const DPR_8Subclasses[] = {
    NULL
  };

  // DPR_VFP2 Register Class sub-classes...
  static const TargetRegisterClass* const DPR_VFP2Subclasses[] = {
    &ARM::DPR_8RegClass, NULL
  };

  // GPR Register Class sub-classes...
  static const TargetRegisterClass* const GPRSubclasses[] = {
    &ARM::tGPRRegClass, NULL
  };

  // QPR Register Class sub-classes...
  static const TargetRegisterClass* const QPRSubclasses[] = {
    &ARM::QPR_8RegClass, &ARM::QPR_VFP2RegClass, NULL
  };

  // QPR_8 Register Class sub-classes...
  static const TargetRegisterClass* const QPR_8Subclasses[] = {
    NULL
  };

  // QPR_VFP2 Register Class sub-classes...
  static const TargetRegisterClass* const QPR_VFP2Subclasses[] = {
    &ARM::QPR_8RegClass, NULL
  };

  // SPR Register Class sub-classes...
  static const TargetRegisterClass* const SPRSubclasses[] = {
    &ARM::SPR_8RegClass, NULL
  };

  // SPR_8 Register Class sub-classes...
  static const TargetRegisterClass* const SPR_8Subclasses[] = {
    NULL
  };

  // SPR_INVALID Register Class sub-classes...
  static const TargetRegisterClass* const SPR_INVALIDSubclasses[] = {
    NULL
  };

  // tGPR Register Class sub-classes...
  static const TargetRegisterClass* const tGPRSubclasses[] = {
    NULL
  };

  // CCR Register Class super-classes...
  static const TargetRegisterClass* const CCRSuperclasses[] = {
    NULL
  };

  // DPR Register Class super-classes...
  static const TargetRegisterClass* const DPRSuperclasses[] = {
    NULL
  };

  // DPR_8 Register Class super-classes...
  static const TargetRegisterClass* const DPR_8Superclasses[] = {
    &ARM::DPRRegClass, &ARM::DPR_VFP2RegClass, NULL
  };

  // DPR_VFP2 Register Class super-classes...
  static const TargetRegisterClass* const DPR_VFP2Superclasses[] = {
    &ARM::DPRRegClass, NULL
  };

  // GPR Register Class super-classes...
  static const TargetRegisterClass* const GPRSuperclasses[] = {
    NULL
  };

  // QPR Register Class super-classes...
  static const TargetRegisterClass* const QPRSuperclasses[] = {
    NULL
  };

  // QPR_8 Register Class super-classes...
  static const TargetRegisterClass* const QPR_8Superclasses[] = {
    &ARM::QPRRegClass, &ARM::QPR_VFP2RegClass, NULL
  };

  // QPR_VFP2 Register Class super-classes...
  static const TargetRegisterClass* const QPR_VFP2Superclasses[] = {
    &ARM::QPRRegClass, NULL
  };

  // SPR Register Class super-classes...
  static const TargetRegisterClass* const SPRSuperclasses[] = {
    NULL
  };

  // SPR_8 Register Class super-classes...
  static const TargetRegisterClass* const SPR_8Superclasses[] = {
    &ARM::SPRRegClass, NULL
  };

  // SPR_INVALID Register Class super-classes...
  static const TargetRegisterClass* const SPR_INVALIDSuperclasses[] = {
    NULL
  };

  // tGPR Register Class super-classes...
  static const TargetRegisterClass* const tGPRSuperclasses[] = {
    &ARM::GPRRegClass, NULL
  };


CCRClass::CCRClass()  : TargetRegisterClass(CCRRegClassID, "CCR", CCRVTs, CCRSubclasses, CCRSuperclasses, CCRSubRegClasses, CCRSuperRegClasses, 4, 4, 1, CCR, CCR + 1) {}

    // VFP2
    static const unsigned ARM_DPR_VFP2[] = {
      ARM::D0,  ARM::D1,  ARM::D2,  ARM::D3,
      ARM::D4,  ARM::D5,  ARM::D6,  ARM::D7,
      ARM::D8,  ARM::D9,  ARM::D10, ARM::D11,
      ARM::D12, ARM::D13, ARM::D14, ARM::D15 };
    // VFP3
    static const unsigned ARM_DPR_VFP3[] = {
      ARM::D0,  ARM::D1,  ARM::D2,  ARM::D3,
      ARM::D4,  ARM::D5,  ARM::D6,  ARM::D7,
      ARM::D8,  ARM::D9,  ARM::D10, ARM::D11,
      ARM::D12, ARM::D13, ARM::D14, ARM::D15,
      ARM::D16, ARM::D17, ARM::D18, ARM::D19,
      ARM::D20, ARM::D21, ARM::D22, ARM::D23,
      ARM::D24, ARM::D25, ARM::D26, ARM::D27,
      ARM::D28, ARM::D29, ARM::D30, ARM::D31 };
    DPRClass::iterator
    DPRClass::allocation_order_begin(const MachineFunction &MF) const {
      const TargetMachine &TM = MF.getTarget();
      const ARMSubtarget &Subtarget = TM.getSubtarget<ARMSubtarget>();
      if (Subtarget.hasVFP3())
        return ARM_DPR_VFP3;
      return ARM_DPR_VFP2;
    }

    DPRClass::iterator
    DPRClass::allocation_order_end(const MachineFunction &MF) const {
      const TargetMachine &TM = MF.getTarget();
      const ARMSubtarget &Subtarget = TM.getSubtarget<ARMSubtarget>();
      if (Subtarget.hasVFP3())
        return ARM_DPR_VFP3 + (sizeof(ARM_DPR_VFP3)/sizeof(unsigned));
      else
        return ARM_DPR_VFP2 + (sizeof(ARM_DPR_VFP2)/sizeof(unsigned));
    }
  
DPRClass::DPRClass()  : TargetRegisterClass(DPRRegClassID, "DPR", DPRVTs, DPRSubclasses, DPRSuperclasses, DPRSubRegClasses, DPRSuperRegClasses, 8, 8, 1, DPR, DPR + 32) {}

DPR_8Class::DPR_8Class()  : TargetRegisterClass(DPR_8RegClassID, "DPR_8", DPR_8VTs, DPR_8Subclasses, DPR_8Superclasses, DPR_8SubRegClasses, DPR_8SuperRegClasses, 8, 8, 1, DPR_8, DPR_8 + 8) {}

DPR_VFP2Class::DPR_VFP2Class()  : TargetRegisterClass(DPR_VFP2RegClassID, "DPR_VFP2", DPR_VFP2VTs, DPR_VFP2Subclasses, DPR_VFP2Superclasses, DPR_VFP2SubRegClasses, DPR_VFP2SuperRegClasses, 8, 8, 1, DPR_VFP2, DPR_VFP2 + 16) {}

    // FP is R11, R9 is available.
    static const unsigned ARM_GPR_AO_1[] = {
      ARM::R0, ARM::R1, ARM::R2, ARM::R3,
      ARM::R12,ARM::LR,
      ARM::R4, ARM::R5, ARM::R6, ARM::R7,
      ARM::R8, ARM::R9, ARM::R10,
      ARM::R11 };
    // FP is R11, R9 is not available.
    static const unsigned ARM_GPR_AO_2[] = {
      ARM::R0, ARM::R1, ARM::R2, ARM::R3,
      ARM::R12,ARM::LR,
      ARM::R4, ARM::R5, ARM::R6, ARM::R7,
      ARM::R8, ARM::R10,
      ARM::R11 };
    // FP is R7, R9 is available as non-callee-saved register.
    // This is used by Darwin.
    static const unsigned ARM_GPR_AO_3[] = {
      ARM::R0, ARM::R1, ARM::R2, ARM::R3,
      ARM::R9, ARM::R12,ARM::LR,
      ARM::R4, ARM::R5, ARM::R6,
      ARM::R8, ARM::R10,ARM::R11,ARM::R7 };
    // FP is R7, R9 is not available.
    static const unsigned ARM_GPR_AO_4[] = {
      ARM::R0, ARM::R1, ARM::R2, ARM::R3,
      ARM::R12,ARM::LR,
      ARM::R4, ARM::R5, ARM::R6,
      ARM::R8, ARM::R10,ARM::R11,
      ARM::R7 };
    // FP is R7, R9 is available as callee-saved register.
    // This is used by non-Darwin platform in Thumb mode.
    static const unsigned ARM_GPR_AO_5[] = {
      ARM::R0, ARM::R1, ARM::R2, ARM::R3,
      ARM::R12,ARM::LR,
      ARM::R4, ARM::R5, ARM::R6,
      ARM::R8, ARM::R9, ARM::R10,ARM::R11,ARM::R7 };

    // For Thumb1 mode, we don't want to allocate hi regs at all, as we
    // don't know how to spill them. If we make our prologue/epilogue code
    // smarter at some point, we can go back to using the above allocation
    // orders for the Thumb1 instructions that know how to use hi regs.
    static const unsigned THUMB_GPR_AO[] = {
      ARM::R0, ARM::R1, ARM::R2, ARM::R3,
      ARM::R4, ARM::R5, ARM::R6, ARM::R7 };

    GPRClass::iterator
    GPRClass::allocation_order_begin(const MachineFunction &MF) const {
      const TargetMachine &TM = MF.getTarget();
      const ARMSubtarget &Subtarget = TM.getSubtarget<ARMSubtarget>();
      if (Subtarget.isThumb1Only())
        return THUMB_GPR_AO;
      if (Subtarget.isTargetDarwin()) {
        if (Subtarget.isR9Reserved())
          return ARM_GPR_AO_4;
        else
          return ARM_GPR_AO_3;
      } else {
        if (Subtarget.isR9Reserved())
          return ARM_GPR_AO_2;
        else if (Subtarget.isThumb())
          return ARM_GPR_AO_5;
        else
          return ARM_GPR_AO_1;
      }
    }

    GPRClass::iterator
    GPRClass::allocation_order_end(const MachineFunction &MF) const {
      const TargetMachine &TM = MF.getTarget();
      const TargetRegisterInfo *RI = TM.getRegisterInfo();
      const ARMSubtarget &Subtarget = TM.getSubtarget<ARMSubtarget>();
      GPRClass::iterator I;

      if (Subtarget.isThumb1Only()) {
        I = THUMB_GPR_AO + (sizeof(THUMB_GPR_AO)/sizeof(unsigned));
        // Mac OS X requires FP not to be clobbered for backtracing purpose.
        return (Subtarget.isTargetDarwin() || RI->hasFP(MF)) ? I-1 : I;
      }

      if (Subtarget.isTargetDarwin()) {
        if (Subtarget.isR9Reserved())
          I = ARM_GPR_AO_4 + (sizeof(ARM_GPR_AO_4)/sizeof(unsigned));
        else
          I = ARM_GPR_AO_3 + (sizeof(ARM_GPR_AO_3)/sizeof(unsigned));
      } else {
        if (Subtarget.isR9Reserved())
          I = ARM_GPR_AO_2 + (sizeof(ARM_GPR_AO_2)/sizeof(unsigned));
        else if (Subtarget.isThumb())
          I = ARM_GPR_AO_5 + (sizeof(ARM_GPR_AO_5)/sizeof(unsigned));
        else
          I = ARM_GPR_AO_1 + (sizeof(ARM_GPR_AO_1)/sizeof(unsigned));
      }

      // Mac OS X requires FP not to be clobbered for backtracing purpose.
      return (Subtarget.isTargetDarwin() || RI->hasFP(MF)) ? I-1 : I;
    }
  
GPRClass::GPRClass()  : TargetRegisterClass(GPRRegClassID, "GPR", GPRVTs, GPRSubclasses, GPRSuperclasses, GPRSubRegClasses, GPRSuperRegClasses, 4, 4, 1, GPR, GPR + 16) {}

QPRClass::QPRClass()  : TargetRegisterClass(QPRRegClassID, "QPR", QPRVTs, QPRSubclasses, QPRSuperclasses, QPRSubRegClasses, QPRSuperRegClasses, 16, 16, 1, QPR, QPR + 16) {}

QPR_8Class::QPR_8Class()  : TargetRegisterClass(QPR_8RegClassID, "QPR_8", QPR_8VTs, QPR_8Subclasses, QPR_8Superclasses, QPR_8SubRegClasses, QPR_8SuperRegClasses, 16, 16, 1, QPR_8, QPR_8 + 4) {}

QPR_VFP2Class::QPR_VFP2Class()  : TargetRegisterClass(QPR_VFP2RegClassID, "QPR_VFP2", QPR_VFP2VTs, QPR_VFP2Subclasses, QPR_VFP2Superclasses, QPR_VFP2SubRegClasses, QPR_VFP2SuperRegClasses, 16, 16, 1, QPR_VFP2, QPR_VFP2 + 8) {}

SPRClass::SPRClass()  : TargetRegisterClass(SPRRegClassID, "SPR", SPRVTs, SPRSubclasses, SPRSuperclasses, SPRSubRegClasses, SPRSuperRegClasses, 4, 4, 1, SPR, SPR + 32) {}

SPR_8Class::SPR_8Class()  : TargetRegisterClass(SPR_8RegClassID, "SPR_8", SPR_8VTs, SPR_8Subclasses, SPR_8Superclasses, SPR_8SubRegClasses, SPR_8SuperRegClasses, 4, 4, 1, SPR_8, SPR_8 + 16) {}

SPR_INVALIDClass::SPR_INVALIDClass()  : TargetRegisterClass(SPR_INVALIDRegClassID, "SPR_INVALID", SPR_INVALIDVTs, SPR_INVALIDSubclasses, SPR_INVALIDSuperclasses, SPR_INVALIDSubRegClasses, SPR_INVALIDSuperRegClasses, 4, 4, -1, SPR_INVALID, SPR_INVALID + 1) {}

    static const unsigned THUMB_tGPR_AO[] = {
      ARM::R0, ARM::R1, ARM::R2, ARM::R3,
      ARM::R4, ARM::R5, ARM::R6, ARM::R7 };

    // FP is R7, only low registers available.
    tGPRClass::iterator
    tGPRClass::allocation_order_begin(const MachineFunction &MF) const {
      return THUMB_tGPR_AO;
    }

    tGPRClass::iterator
    tGPRClass::allocation_order_end(const MachineFunction &MF) const {
      const TargetMachine &TM = MF.getTarget();
      const TargetRegisterInfo *RI = TM.getRegisterInfo();
      const ARMSubtarget &Subtarget = TM.getSubtarget<ARMSubtarget>();
      tGPRClass::iterator I =
        THUMB_tGPR_AO + (sizeof(THUMB_tGPR_AO)/sizeof(unsigned));
      // Mac OS X requires FP not to be clobbered for backtracing purpose.
      return (Subtarget.isTargetDarwin() || RI->hasFP(MF)) ? I-1 : I;
    }
  
tGPRClass::tGPRClass()  : TargetRegisterClass(tGPRRegClassID, "tGPR", tGPRVTs, tGPRSubclasses, tGPRSuperclasses, tGPRSubRegClasses, tGPRSuperRegClasses, 4, 4, 1, tGPR, tGPR + 8) {}
}

namespace {
  const TargetRegisterClass* const RegisterClasses[] = {
    &ARM::CCRRegClass,
    &ARM::DPRRegClass,
    &ARM::DPR_8RegClass,
    &ARM::DPR_VFP2RegClass,
    &ARM::GPRRegClass,
    &ARM::QPRRegClass,
    &ARM::QPR_8RegClass,
    &ARM::QPR_VFP2RegClass,
    &ARM::SPRRegClass,
    &ARM::SPR_8RegClass,
    &ARM::SPR_INVALIDRegClass,
    &ARM::tGPRRegClass,
  };


  // Number of hash collisions: 6
  const unsigned SubregHashTable[] = { ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q2, ARM::S10, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D12, ARM::S24, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q5, ARM::S23, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q2, ARM::S8, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q15, ARM::D31, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q9, ARM::D19, 
                                       ARM::D5, ARM::S11, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D4, ARM::S9, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q2, ARM::S11, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D12, ARM::S25, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q1, ARM::D2, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q6, ARM::S24, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q2, ARM::S9, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q2, ARM::D4, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D6, ARM::S12, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q3, ARM::S12, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D13, ARM::S26, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q10, ARM::D20, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q6, ARM::S25, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q2, ARM::D5, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D6, ARM::S13, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q0, ARM::D0, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q3, ARM::S13, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D13, ARM::S27, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q10, ARM::D21, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q6, ARM::S26, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q3, ARM::D6, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D7, ARM::S14, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q0, ARM::D1, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q3, ARM::S14, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D14, ARM::S28, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q11, ARM::D22, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q6, ARM::S27, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q3, ARM::D7, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D7, ARM::S15, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q3, ARM::S15, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D14, ARM::S29, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q11, ARM::D23, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q5, ARM::D10, 
                                       ARM::Q7, ARM::S28, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q4, ARM::D8, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D8, ARM::S16, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D1, ARM::S3, 
                                       ARM::Q4, ARM::S16, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q12, ARM::D24, 
                                       ARM::Q5, ARM::D11, 
                                       ARM::Q7, ARM::S29, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q4, ARM::D9, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D8, ARM::S17, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q0, ARM::S3, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q4, ARM::S17, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D15, ARM::S30, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q12, ARM::D25, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q6, ARM::D12, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D9, ARM::S18, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q4, ARM::S18, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D15, ARM::S31, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q13, ARM::D26, 
                                       ARM::Q6, ARM::D13, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q7, ARM::S30, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D9, ARM::S19, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D1, ARM::S2, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q4, ARM::S19, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q13, ARM::D27, 
                                       ARM::Q7, ARM::S31, 
                                       ARM::D2, ARM::S4, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q7, ARM::D14, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q0, ARM::S2, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D10, ARM::S20, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q1, ARM::S4, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q14, ARM::D28, 
                                       ARM::D2, ARM::S5, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q7, ARM::D15, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D0, ARM::S0, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D10, ARM::S21, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q1, ARM::S5, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q5, ARM::S20, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q14, ARM::D29, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q8, ARM::D16, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D3, ARM::S6, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D0, ARM::S1, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q0, ARM::S0, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D11, ARM::S22, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q1, ARM::S6, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q5, ARM::S21, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q1, ARM::D3, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q8, ARM::D17, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D3, ARM::S7, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q0, ARM::S1, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D11, ARM::S23, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q1, ARM::S7, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q5, ARM::S22, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q15, ARM::D30, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q9, ARM::D18, 
                                       ARM::D5, ARM::S10, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D4, ARM::S8, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
ARM::NoRegister, ARM::NoRegister };
  const unsigned SubregHashTableSize = 512;


  // Number of hash collisions: 18
  const unsigned SuperregHashTable[] = { ARM::D24, ARM::Q12, 
                                       ARM::D25, ARM::Q12, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D26, ARM::Q13, 
                                       ARM::D27, ARM::Q13, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D28, ARM::Q14, 
                                       ARM::D29, ARM::Q14, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::S4, ARM::D2, 
                                       ARM::S5, ARM::D2, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::S8, ARM::D4, 
                                       ARM::S9, ARM::D4, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::S10, ARM::D5, 
                                       ARM::D30, ARM::Q15, 
                                       ARM::D31, ARM::Q15, 
                                       ARM::S11, ARM::D5, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::S0, ARM::D0, 
                                       ARM::S1, ARM::D0, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::S12, ARM::D6, 
                                       ARM::D4, ARM::Q2, 
                                       ARM::D5, ARM::Q2, 
                                       ARM::S13, ARM::D6, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::S2, ARM::D1, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::S14, ARM::D7, 
                                       ARM::D6, ARM::Q3, 
                                       ARM::D7, ARM::Q3, 
                                       ARM::S11, ARM::Q2, 
                                       ARM::S10, ARM::Q2, 
                                       ARM::S3, ARM::D1, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::S15, ARM::D7, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::S8, ARM::Q2, 
                                       ARM::S9, ARM::Q2, 
                                       ARM::S20, ARM::D10, 
                                       ARM::S21, ARM::D10, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::S16, ARM::D8, 
                                       ARM::D8, ARM::Q4, 
                                       ARM::D9, ARM::Q4, 
                                       ARM::S13, ARM::Q3, 
                                       ARM::S12, ARM::Q3, 
                                       ARM::S15, ARM::Q3, 
                                       ARM::S14, ARM::Q3, 
                                       ARM::S17, ARM::D8, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D10, ARM::Q5, 
                                       ARM::D11, ARM::Q5, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::S22, ARM::D11, 
                                       ARM::S23, ARM::D11, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::S18, ARM::D9, 
                                       ARM::S19, ARM::D9, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::S16, ARM::Q4, 
                                       ARM::S17, ARM::Q4, 
                                       ARM::S18, ARM::Q4, 
                                       ARM::S19, ARM::Q4, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D12, ARM::Q6, 
                                       ARM::D13, ARM::Q6, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::S24, ARM::D12, 
                                       ARM::S25, ARM::D12, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::S20, ARM::Q5, 
                                       ARM::S21, ARM::Q5, 
                                       ARM::S22, ARM::Q5, 
                                       ARM::D14, ARM::Q7, 
                                       ARM::D15, ARM::Q7, 
                                       ARM::S23, ARM::Q5, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::S26, ARM::D13, 
                                       ARM::S27, ARM::D13, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D0, ARM::Q0, 
                                       ARM::D1, ARM::Q0, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::S24, ARM::Q6, 
                                       ARM::D16, ARM::Q8, 
                                       ARM::D17, ARM::Q8, 
                                       ARM::S25, ARM::Q6, 
                                       ARM::S26, ARM::Q6, 
                                       ARM::S27, ARM::Q6, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::S28, ARM::D14, 
                                       ARM::S29, ARM::D14, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D2, ARM::Q1, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D18, ARM::Q9, 
                                       ARM::D19, ARM::Q9, 
                                       ARM::S29, ARM::Q7, 
                                       ARM::S28, ARM::Q7, 
                                       ARM::S30, ARM::Q7, 
                                       ARM::S31, ARM::Q7, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D3, ARM::Q1, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::S0, ARM::Q0, 
                                       ARM::S1, ARM::Q0, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::S2, ARM::Q0, 
                                       ARM::S31, ARM::D15, 
                                       ARM::S30, ARM::D15, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D20, ARM::Q10, 
                                       ARM::D21, ARM::Q10, 
                                       ARM::S3, ARM::Q0, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D22, ARM::Q11, 
                                       ARM::D23, ARM::Q11, 
                                       ARM::S5, ARM::Q1, 
                                       ARM::S4, ARM::Q1, 
                                       ARM::S7, ARM::Q1, 
                                       ARM::S6, ARM::Q1, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::S6, ARM::D3, 
                                       ARM::S7, ARM::D3, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
ARM::NoRegister, ARM::NoRegister };
  const unsigned SuperregHashTableSize = 512;


  // Number of hash collisions: 38
  const unsigned AliasesHashTable[] = { ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D12, ARM::S24, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q5, ARM::S23, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q15, ARM::D31, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D12, ARM::S25, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q6, ARM::S24, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q2, ARM::D4, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D13, ARM::S26, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q6, ARM::S25, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q2, ARM::D5, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::S8, ARM::D4, 
                                       ARM::S9, ARM::D4, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q0, ARM::D0, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D13, ARM::S27, 
                                       ARM::S11, ARM::D5, 
                                       ARM::S10, ARM::D5, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q6, ARM::S26, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q3, ARM::D6, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::S0, ARM::D0, 
                                       ARM::S1, ARM::D0, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q0, ARM::D1, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D14, ARM::S28, 
                                       ARM::S12, ARM::D6, 
                                       ARM::S13, ARM::D6, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q6, ARM::S27, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q3, ARM::D7, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::S2, ARM::D1, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D14, ARM::S29, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::S14, ARM::D7, 
                                       ARM::Q5, ARM::D10, 
                                       ARM::Q7, ARM::S28, 
                                       ARM::S15, ARM::D7, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::S3, ARM::D1, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q4, ARM::D8, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D1, ARM::S3, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::S20, ARM::D10, 
                                       ARM::S21, ARM::D10, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q5, ARM::D11, 
                                       ARM::Q7, ARM::S29, 
                                       ARM::S17, ARM::D8, 
                                       ARM::S16, ARM::D8, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q4, ARM::D9, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q0, ARM::S3, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::S22, ARM::D11, 
                                       ARM::D15, ARM::S30, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::S23, ARM::D11, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q6, ARM::D12, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::S18, ARM::D9, 
                                       ARM::S19, ARM::D9, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D15, ARM::S31, 
                                       ARM::S24, ARM::D12, 
                                       ARM::S25, ARM::D12, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q6, ARM::D13, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q7, ARM::S30, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::S26, ARM::D13, 
                                       ARM::Q7, ARM::S31, 
                                       ARM::D2, ARM::S4, 
                                       ARM::D0, ARM::Q0, 
                                       ARM::D1, ARM::Q0, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::S27, ARM::D13, 
                                       ARM::Q7, ARM::D14, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q1, ARM::S4, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D2, ARM::S5, 
                                       ARM::S29, ARM::D14, 
                                       ARM::Q7, ARM::D15, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::S28, ARM::D14, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D0, ARM::S0, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D2, ARM::Q1, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D3, ARM::Q1, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q1, ARM::S5, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::S0, ARM::Q0, 
                                       ARM::S1, ARM::Q0, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q8, ARM::D16, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::S2, ARM::Q0, 
                                       ARM::S31, ARM::D15, 
                                       ARM::S30, ARM::D15, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D3, ARM::S6, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D0, ARM::S1, 
                                       ARM::D20, ARM::Q10, 
                                       ARM::D21, ARM::Q10, 
                                       ARM::S3, ARM::Q0, 
                                       ARM::Q0, ARM::S0, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q1, ARM::S6, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q8, ARM::D17, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D3, ARM::S7, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q0, ARM::S1, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D22, ARM::Q11, 
                                       ARM::D23, ARM::Q11, 
                                       ARM::S5, ARM::Q1, 
                                       ARM::S4, ARM::Q1, 
                                       ARM::S7, ARM::Q1, 
                                       ARM::S6, ARM::Q1, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q1, ARM::S7, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q9, ARM::D18, 
                                       ARM::D5, ARM::S10, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D4, ARM::S8, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D24, ARM::Q12, 
                                       ARM::D25, ARM::Q12, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q2, ARM::S10, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q2, ARM::S8, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q9, ARM::D19, 
                                       ARM::D5, ARM::S11, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D4, ARM::S9, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q2, ARM::S11, 
                                       ARM::D26, ARM::Q13, 
                                       ARM::D27, ARM::Q13, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q1, ARM::D2, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q2, ARM::S9, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D6, ARM::S12, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q3, ARM::S12, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D28, ARM::Q14, 
                                       ARM::D29, ARM::Q14, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q10, ARM::D20, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D6, ARM::S13, 
                                       ARM::S4, ARM::D2, 
                                       ARM::S5, ARM::D2, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q3, ARM::S13, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D30, ARM::Q15, 
                                       ARM::D31, ARM::Q15, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q10, ARM::D21, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D7, ARM::S14, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q3, ARM::S14, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D4, ARM::Q2, 
                                       ARM::D5, ARM::Q2, 
                                       ARM::Q11, ARM::D22, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D7, ARM::S15, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q3, ARM::S15, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q11, ARM::D23, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D6, ARM::Q3, 
                                       ARM::D7, ARM::Q3, 
                                       ARM::S11, ARM::Q2, 
                                       ARM::S10, ARM::Q2, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D8, ARM::S16, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q4, ARM::S16, 
                                       ARM::S9, ARM::Q2, 
                                       ARM::S8, ARM::Q2, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q12, ARM::D24, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D8, ARM::Q4, 
                                       ARM::D9, ARM::Q4, 
                                       ARM::S13, ARM::Q3, 
                                       ARM::S12, ARM::Q3, 
                                       ARM::S15, ARM::Q3, 
                                       ARM::S14, ARM::Q3, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D10, ARM::Q5, 
                                       ARM::D11, ARM::Q5, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D8, ARM::S17, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q4, ARM::S17, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q12, ARM::D25, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::S16, ARM::Q4, 
                                       ARM::S17, ARM::Q4, 
                                       ARM::S18, ARM::Q4, 
                                       ARM::S19, ARM::Q4, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D12, ARM::Q6, 
                                       ARM::D13, ARM::Q6, 
                                       ARM::D9, ARM::S18, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q4, ARM::S18, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q13, ARM::D26, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::S20, ARM::Q5, 
                                       ARM::S21, ARM::Q5, 
                                       ARM::S22, ARM::Q5, 
                                       ARM::D14, ARM::Q7, 
                                       ARM::D15, ARM::Q7, 
                                       ARM::D9, ARM::S19, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::S23, ARM::Q5, 
                                       ARM::D1, ARM::S2, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q4, ARM::S19, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q13, ARM::D27, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::S24, ARM::Q6, 
                                       ARM::D16, ARM::Q8, 
                                       ARM::D17, ARM::Q8, 
                                       ARM::Q0, ARM::S2, 
                                       ARM::S26, ARM::Q6, 
                                       ARM::S27, ARM::Q6, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D10, ARM::S20, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::S25, ARM::Q6, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q14, ARM::D28, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D18, ARM::Q9, 
                                       ARM::D19, ARM::Q9, 
                                       ARM::S29, ARM::Q7, 
                                       ARM::S28, ARM::Q7, 
                                       ARM::D10, ARM::S21, 
                                       ARM::S31, ARM::Q7, 
                                       ARM::S30, ARM::Q7, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q5, ARM::S20, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q14, ARM::D29, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D11, ARM::S22, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q5, ARM::S21, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q1, ARM::D3, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::D11, ARM::S23, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q5, ARM::S22, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::Q15, ARM::D30, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::S6, ARM::D3, 
                                       ARM::S7, ARM::D3, 
                                       ARM::NoRegister, ARM::NoRegister, 
                                       ARM::NoRegister, ARM::NoRegister, 
ARM::NoRegister, ARM::NoRegister };
  const unsigned AliasesHashTableSize = 1024;


  // Register Alias Sets...
  const unsigned Empty_AliasSet[] = { 0 };
  const unsigned CPSR_AliasSet[] = { 0 };
  const unsigned D0_AliasSet[] = { ARM::S0, ARM::S1, ARM::Q0, 0 };
  const unsigned D1_AliasSet[] = { ARM::S2, ARM::S3, ARM::Q0, 0 };
  const unsigned D10_AliasSet[] = { ARM::S20, ARM::S21, ARM::Q5, 0 };
  const unsigned D11_AliasSet[] = { ARM::S22, ARM::S23, ARM::Q5, 0 };
  const unsigned D12_AliasSet[] = { ARM::S24, ARM::S25, ARM::Q6, 0 };
  const unsigned D13_AliasSet[] = { ARM::S26, ARM::S27, ARM::Q6, 0 };
  const unsigned D14_AliasSet[] = { ARM::S28, ARM::S29, ARM::Q7, 0 };
  const unsigned D15_AliasSet[] = { ARM::S30, ARM::S31, ARM::Q7, 0 };
  const unsigned D16_AliasSet[] = { ARM::Q8, 0 };
  const unsigned D17_AliasSet[] = { ARM::Q8, 0 };
  const unsigned D18_AliasSet[] = { ARM::Q9, 0 };
  const unsigned D19_AliasSet[] = { ARM::Q9, 0 };
  const unsigned D2_AliasSet[] = { ARM::S4, ARM::S5, ARM::Q1, 0 };
  const unsigned D20_AliasSet[] = { ARM::Q10, 0 };
  const unsigned D21_AliasSet[] = { ARM::Q10, 0 };
  const unsigned D22_AliasSet[] = { ARM::Q11, 0 };
  const unsigned D23_AliasSet[] = { ARM::Q11, 0 };
  const unsigned D24_AliasSet[] = { ARM::Q12, 0 };
  const unsigned D25_AliasSet[] = { ARM::Q12, 0 };
  const unsigned D26_AliasSet[] = { ARM::Q13, 0 };
  const unsigned D27_AliasSet[] = { ARM::Q13, 0 };
  const unsigned D28_AliasSet[] = { ARM::Q14, 0 };
  const unsigned D29_AliasSet[] = { ARM::Q14, 0 };
  const unsigned D3_AliasSet[] = { ARM::S6, ARM::S7, ARM::Q1, 0 };
  const unsigned D30_AliasSet[] = { ARM::Q15, 0 };
  const unsigned D31_AliasSet[] = { ARM::Q15, 0 };
  const unsigned D4_AliasSet[] = { ARM::S8, ARM::S9, ARM::Q2, 0 };
  const unsigned D5_AliasSet[] = { ARM::S10, ARM::S11, ARM::Q2, 0 };
  const unsigned D6_AliasSet[] = { ARM::S12, ARM::S13, ARM::Q3, 0 };
  const unsigned D7_AliasSet[] = { ARM::S14, ARM::S15, ARM::Q3, 0 };
  const unsigned D8_AliasSet[] = { ARM::S16, ARM::S17, ARM::Q4, 0 };
  const unsigned D9_AliasSet[] = { ARM::S18, ARM::S19, ARM::Q4, 0 };
  const unsigned FPSCR_AliasSet[] = { 0 };
  const unsigned LR_AliasSet[] = { 0 };
  const unsigned PC_AliasSet[] = { 0 };
  const unsigned Q0_AliasSet[] = { ARM::S0, ARM::S1, ARM::S2, ARM::S3, ARM::D0, ARM::D1, 0 };
  const unsigned Q1_AliasSet[] = { ARM::S4, ARM::S5, ARM::S6, ARM::S7, ARM::D2, ARM::D3, 0 };
  const unsigned Q10_AliasSet[] = { ARM::D20, ARM::D21, 0 };
  const unsigned Q11_AliasSet[] = { ARM::D22, ARM::D23, 0 };
  const unsigned Q12_AliasSet[] = { ARM::D24, ARM::D25, 0 };
  const unsigned Q13_AliasSet[] = { ARM::D26, ARM::D27, 0 };
  const unsigned Q14_AliasSet[] = { ARM::D28, ARM::D29, 0 };
  const unsigned Q15_AliasSet[] = { ARM::D30, ARM::D31, 0 };
  const unsigned Q2_AliasSet[] = { ARM::S8, ARM::S9, ARM::S10, ARM::S11, ARM::D4, ARM::D5, 0 };
  const unsigned Q3_AliasSet[] = { ARM::S12, ARM::S13, ARM::S14, ARM::S15, ARM::D6, ARM::D7, 0 };
  const unsigned Q4_AliasSet[] = { ARM::S16, ARM::S17, ARM::S18, ARM::S19, ARM::D8, ARM::D9, 0 };
  const unsigned Q5_AliasSet[] = { ARM::S20, ARM::S21, ARM::S22, ARM::S23, ARM::D10, ARM::D11, 0 };
  const unsigned Q6_AliasSet[] = { ARM::S24, ARM::S25, ARM::S26, ARM::S27, ARM::D12, ARM::D13, 0 };
  const unsigned Q7_AliasSet[] = { ARM::S28, ARM::S29, ARM::S30, ARM::S31, ARM::D14, ARM::D15, 0 };
  const unsigned Q8_AliasSet[] = { ARM::D16, ARM::D17, 0 };
  const unsigned Q9_AliasSet[] = { ARM::D18, ARM::D19, 0 };
  const unsigned R0_AliasSet[] = { 0 };
  const unsigned R1_AliasSet[] = { 0 };
  const unsigned R10_AliasSet[] = { 0 };
  const unsigned R11_AliasSet[] = { 0 };
  const unsigned R12_AliasSet[] = { 0 };
  const unsigned R2_AliasSet[] = { 0 };
  const unsigned R3_AliasSet[] = { 0 };
  const unsigned R4_AliasSet[] = { 0 };
  const unsigned R5_AliasSet[] = { 0 };
  const unsigned R6_AliasSet[] = { 0 };
  const unsigned R7_AliasSet[] = { 0 };
  const unsigned R8_AliasSet[] = { 0 };
  const unsigned R9_AliasSet[] = { 0 };
  const unsigned S0_AliasSet[] = { ARM::D0, ARM::Q0, 0 };
  const unsigned S1_AliasSet[] = { ARM::D0, ARM::Q0, 0 };
  const unsigned S10_AliasSet[] = { ARM::D5, ARM::Q2, 0 };
  const unsigned S11_AliasSet[] = { ARM::D5, ARM::Q2, 0 };
  const unsigned S12_AliasSet[] = { ARM::D6, ARM::Q3, 0 };
  const unsigned S13_AliasSet[] = { ARM::D6, ARM::Q3, 0 };
  const unsigned S14_AliasSet[] = { ARM::D7, ARM::Q3, 0 };
  const unsigned S15_AliasSet[] = { ARM::D7, ARM::Q3, 0 };
  const unsigned S16_AliasSet[] = { ARM::D8, ARM::Q4, 0 };
  const unsigned S17_AliasSet[] = { ARM::D8, ARM::Q4, 0 };
  const unsigned S18_AliasSet[] = { ARM::D9, ARM::Q4, 0 };
  const unsigned S19_AliasSet[] = { ARM::D9, ARM::Q4, 0 };
  const unsigned S2_AliasSet[] = { ARM::D1, ARM::Q0, 0 };
  const unsigned S20_AliasSet[] = { ARM::D10, ARM::Q5, 0 };
  const unsigned S21_AliasSet[] = { ARM::D10, ARM::Q5, 0 };
  const unsigned S22_AliasSet[] = { ARM::D11, ARM::Q5, 0 };
  const unsigned S23_AliasSet[] = { ARM::D11, ARM::Q5, 0 };
  const unsigned S24_AliasSet[] = { ARM::D12, ARM::Q6, 0 };
  const unsigned S25_AliasSet[] = { ARM::D12, ARM::Q6, 0 };
  const unsigned S26_AliasSet[] = { ARM::D13, ARM::Q6, 0 };
  const unsigned S27_AliasSet[] = { ARM::D13, ARM::Q6, 0 };
  const unsigned S28_AliasSet[] = { ARM::D14, ARM::Q7, 0 };
  const unsigned S29_AliasSet[] = { ARM::D14, ARM::Q7, 0 };
  const unsigned S3_AliasSet[] = { ARM::D1, ARM::Q0, 0 };
  const unsigned S30_AliasSet[] = { ARM::D15, ARM::Q7, 0 };
  const unsigned S31_AliasSet[] = { ARM::D15, ARM::Q7, 0 };
  const unsigned S4_AliasSet[] = { ARM::D2, ARM::Q1, 0 };
  const unsigned S5_AliasSet[] = { ARM::D2, ARM::Q1, 0 };
  const unsigned S6_AliasSet[] = { ARM::D3, ARM::Q1, 0 };
  const unsigned S7_AliasSet[] = { ARM::D3, ARM::Q1, 0 };
  const unsigned S8_AliasSet[] = { ARM::D4, ARM::Q2, 0 };
  const unsigned S9_AliasSet[] = { ARM::D4, ARM::Q2, 0 };
  const unsigned SDummy_AliasSet[] = { 0 };
  const unsigned SP_AliasSet[] = { 0 };


  // Register Sub-registers Sets...
  const unsigned Empty_SubRegsSet[] = { 0 };
  const unsigned CPSR_SubRegsSet[] = { 0 };
  const unsigned D0_SubRegsSet[] = { ARM::S0, ARM::S1, 0 };
  const unsigned D1_SubRegsSet[] = { ARM::S2, ARM::S3, 0 };
  const unsigned D10_SubRegsSet[] = { ARM::S20, ARM::S21, 0 };
  const unsigned D11_SubRegsSet[] = { ARM::S22, ARM::S23, 0 };
  const unsigned D12_SubRegsSet[] = { ARM::S24, ARM::S25, 0 };
  const unsigned D13_SubRegsSet[] = { ARM::S26, ARM::S27, 0 };
  const unsigned D14_SubRegsSet[] = { ARM::S28, ARM::S29, 0 };
  const unsigned D15_SubRegsSet[] = { ARM::S30, ARM::S31, 0 };
  const unsigned D16_SubRegsSet[] = { 0 };
  const unsigned D17_SubRegsSet[] = { 0 };
  const unsigned D18_SubRegsSet[] = { 0 };
  const unsigned D19_SubRegsSet[] = { 0 };
  const unsigned D2_SubRegsSet[] = { ARM::S4, ARM::S5, 0 };
  const unsigned D20_SubRegsSet[] = { 0 };
  const unsigned D21_SubRegsSet[] = { 0 };
  const unsigned D22_SubRegsSet[] = { 0 };
  const unsigned D23_SubRegsSet[] = { 0 };
  const unsigned D24_SubRegsSet[] = { 0 };
  const unsigned D25_SubRegsSet[] = { 0 };
  const unsigned D26_SubRegsSet[] = { 0 };
  const unsigned D27_SubRegsSet[] = { 0 };
  const unsigned D28_SubRegsSet[] = { 0 };
  const unsigned D29_SubRegsSet[] = { 0 };
  const unsigned D3_SubRegsSet[] = { ARM::S6, ARM::S7, 0 };
  const unsigned D30_SubRegsSet[] = { 0 };
  const unsigned D31_SubRegsSet[] = { 0 };
  const unsigned D4_SubRegsSet[] = { ARM::S8, ARM::S9, 0 };
  const unsigned D5_SubRegsSet[] = { ARM::S10, ARM::S11, 0 };
  const unsigned D6_SubRegsSet[] = { ARM::S12, ARM::S13, 0 };
  const unsigned D7_SubRegsSet[] = { ARM::S14, ARM::S15, 0 };
  const unsigned D8_SubRegsSet[] = { ARM::S16, ARM::S17, 0 };
  const unsigned D9_SubRegsSet[] = { ARM::S18, ARM::S19, 0 };
  const unsigned FPSCR_SubRegsSet[] = { 0 };
  const unsigned LR_SubRegsSet[] = { 0 };
  const unsigned PC_SubRegsSet[] = { 0 };
  const unsigned Q0_SubRegsSet[] = { ARM::S0, ARM::S1, ARM::D1, ARM::S2, ARM::S3, ARM::D0, 0 };
  const unsigned Q1_SubRegsSet[] = { ARM::S4, ARM::S5, ARM::D3, ARM::S6, ARM::S7, ARM::D2, 0 };
  const unsigned Q10_SubRegsSet[] = { ARM::D20, ARM::D21, 0 };
  const unsigned Q11_SubRegsSet[] = { ARM::D22, ARM::D23, 0 };
  const unsigned Q12_SubRegsSet[] = { ARM::D24, ARM::D25, 0 };
  const unsigned Q13_SubRegsSet[] = { ARM::D26, ARM::D27, 0 };
  const unsigned Q14_SubRegsSet[] = { ARM::D28, ARM::D29, 0 };
  const unsigned Q15_SubRegsSet[] = { ARM::D30, ARM::D31, 0 };
  const unsigned Q2_SubRegsSet[] = { ARM::S8, ARM::S9, ARM::D5, ARM::S10, ARM::S11, ARM::D4, 0 };
  const unsigned Q3_SubRegsSet[] = { ARM::S12, ARM::S13, ARM::D7, ARM::S14, ARM::S15, ARM::D6, 0 };
  const unsigned Q4_SubRegsSet[] = { ARM::S16, ARM::S17, ARM::D9, ARM::S18, ARM::S19, ARM::D8, 0 };
  const unsigned Q5_SubRegsSet[] = { ARM::S20, ARM::S21, ARM::D11, ARM::S22, ARM::S23, ARM::D10, 0 };
  const unsigned Q6_SubRegsSet[] = { ARM::S24, ARM::S25, ARM::D13, ARM::S26, ARM::S27, ARM::D12, 0 };
  const unsigned Q7_SubRegsSet[] = { ARM::S28, ARM::S29, ARM::D15, ARM::S30, ARM::S31, ARM::D14, 0 };
  const unsigned Q8_SubRegsSet[] = { ARM::D16, ARM::D17, 0 };
  const unsigned Q9_SubRegsSet[] = { ARM::D18, ARM::D19, 0 };
  const unsigned R0_SubRegsSet[] = { 0 };
  const unsigned R1_SubRegsSet[] = { 0 };
  const unsigned R10_SubRegsSet[] = { 0 };
  const unsigned R11_SubRegsSet[] = { 0 };
  const unsigned R12_SubRegsSet[] = { 0 };
  const unsigned R2_SubRegsSet[] = { 0 };
  const unsigned R3_SubRegsSet[] = { 0 };
  const unsigned R4_SubRegsSet[] = { 0 };
  const unsigned R5_SubRegsSet[] = { 0 };
  const unsigned R6_SubRegsSet[] = { 0 };
  const unsigned R7_SubRegsSet[] = { 0 };
  const unsigned R8_SubRegsSet[] = { 0 };
  const unsigned R9_SubRegsSet[] = { 0 };
  const unsigned S0_SubRegsSet[] = { 0 };
  const unsigned S1_SubRegsSet[] = { 0 };
  const unsigned S10_SubRegsSet[] = { 0 };
  const unsigned S11_SubRegsSet[] = { 0 };
  const unsigned S12_SubRegsSet[] = { 0 };
  const unsigned S13_SubRegsSet[] = { 0 };
  const unsigned S14_SubRegsSet[] = { 0 };
  const unsigned S15_SubRegsSet[] = { 0 };
  const unsigned S16_SubRegsSet[] = { 0 };
  const unsigned S17_SubRegsSet[] = { 0 };
  const unsigned S18_SubRegsSet[] = { 0 };
  const unsigned S19_SubRegsSet[] = { 0 };
  const unsigned S2_SubRegsSet[] = { 0 };
  const unsigned S20_SubRegsSet[] = { 0 };
  const unsigned S21_SubRegsSet[] = { 0 };
  const unsigned S22_SubRegsSet[] = { 0 };
  const unsigned S23_SubRegsSet[] = { 0 };
  const unsigned S24_SubRegsSet[] = { 0 };
  const unsigned S25_SubRegsSet[] = { 0 };
  const unsigned S26_SubRegsSet[] = { 0 };
  const unsigned S27_SubRegsSet[] = { 0 };
  const unsigned S28_SubRegsSet[] = { 0 };
  const unsigned S29_SubRegsSet[] = { 0 };
  const unsigned S3_SubRegsSet[] = { 0 };
  const unsigned S30_SubRegsSet[] = { 0 };
  const unsigned S31_SubRegsSet[] = { 0 };
  const unsigned S4_SubRegsSet[] = { 0 };
  const unsigned S5_SubRegsSet[] = { 0 };
  const unsigned S6_SubRegsSet[] = { 0 };
  const unsigned S7_SubRegsSet[] = { 0 };
  const unsigned S8_SubRegsSet[] = { 0 };
  const unsigned S9_SubRegsSet[] = { 0 };
  const unsigned SDummy_SubRegsSet[] = { 0 };
  const unsigned SP_SubRegsSet[] = { 0 };


  // Register Super-registers Sets...
  const unsigned Empty_SuperRegsSet[] = { 0 };
  const unsigned CPSR_SuperRegsSet[] = { 0 };
  const unsigned D0_SuperRegsSet[] = { ARM::Q0, 0 };
  const unsigned D1_SuperRegsSet[] = { ARM::Q0, 0 };
  const unsigned D10_SuperRegsSet[] = { ARM::Q5, 0 };
  const unsigned D11_SuperRegsSet[] = { ARM::Q5, 0 };
  const unsigned D12_SuperRegsSet[] = { ARM::Q6, 0 };
  const unsigned D13_SuperRegsSet[] = { ARM::Q6, 0 };
  const unsigned D14_SuperRegsSet[] = { ARM::Q7, 0 };
  const unsigned D15_SuperRegsSet[] = { ARM::Q7, 0 };
  const unsigned D16_SuperRegsSet[] = { ARM::Q8, 0 };
  const unsigned D17_SuperRegsSet[] = { ARM::Q8, 0 };
  const unsigned D18_SuperRegsSet[] = { ARM::Q9, 0 };
  const unsigned D19_SuperRegsSet[] = { ARM::Q9, 0 };
  const unsigned D2_SuperRegsSet[] = { ARM::Q1, 0 };
  const unsigned D20_SuperRegsSet[] = { ARM::Q10, 0 };
  const unsigned D21_SuperRegsSet[] = { ARM::Q10, 0 };
  const unsigned D22_SuperRegsSet[] = { ARM::Q11, 0 };
  const unsigned D23_SuperRegsSet[] = { ARM::Q11, 0 };
  const unsigned D24_SuperRegsSet[] = { ARM::Q12, 0 };
  const unsigned D25_SuperRegsSet[] = { ARM::Q12, 0 };
  const unsigned D26_SuperRegsSet[] = { ARM::Q13, 0 };
  const unsigned D27_SuperRegsSet[] = { ARM::Q13, 0 };
  const unsigned D28_SuperRegsSet[] = { ARM::Q14, 0 };
  const unsigned D29_SuperRegsSet[] = { ARM::Q14, 0 };
  const unsigned D3_SuperRegsSet[] = { ARM::Q1, 0 };
  const unsigned D30_SuperRegsSet[] = { ARM::Q15, 0 };
  const unsigned D31_SuperRegsSet[] = { ARM::Q15, 0 };
  const unsigned D4_SuperRegsSet[] = { ARM::Q2, 0 };
  const unsigned D5_SuperRegsSet[] = { ARM::Q2, 0 };
  const unsigned D6_SuperRegsSet[] = { ARM::Q3, 0 };
  const unsigned D7_SuperRegsSet[] = { ARM::Q3, 0 };
  const unsigned D8_SuperRegsSet[] = { ARM::Q4, 0 };
  const unsigned D9_SuperRegsSet[] = { ARM::Q4, 0 };
  const unsigned FPSCR_SuperRegsSet[] = { 0 };
  const unsigned LR_SuperRegsSet[] = { 0 };
  const unsigned PC_SuperRegsSet[] = { 0 };
  const unsigned Q0_SuperRegsSet[] = { 0 };
  const unsigned Q1_SuperRegsSet[] = { 0 };
  const unsigned Q10_SuperRegsSet[] = { 0 };
  const unsigned Q11_SuperRegsSet[] = { 0 };
  const unsigned Q12_SuperRegsSet[] = { 0 };
  const unsigned Q13_SuperRegsSet[] = { 0 };
  const unsigned Q14_SuperRegsSet[] = { 0 };
  const unsigned Q15_SuperRegsSet[] = { 0 };
  const unsigned Q2_SuperRegsSet[] = { 0 };
  const unsigned Q3_SuperRegsSet[] = { 0 };
  const unsigned Q4_SuperRegsSet[] = { 0 };
  const unsigned Q5_SuperRegsSet[] = { 0 };
  const unsigned Q6_SuperRegsSet[] = { 0 };
  const unsigned Q7_SuperRegsSet[] = { 0 };
  const unsigned Q8_SuperRegsSet[] = { 0 };
  const unsigned Q9_SuperRegsSet[] = { 0 };
  const unsigned R0_SuperRegsSet[] = { 0 };
  const unsigned R1_SuperRegsSet[] = { 0 };
  const unsigned R10_SuperRegsSet[] = { 0 };
  const unsigned R11_SuperRegsSet[] = { 0 };
  const unsigned R12_SuperRegsSet[] = { 0 };
  const unsigned R2_SuperRegsSet[] = { 0 };
  const unsigned R3_SuperRegsSet[] = { 0 };
  const unsigned R4_SuperRegsSet[] = { 0 };
  const unsigned R5_SuperRegsSet[] = { 0 };
  const unsigned R6_SuperRegsSet[] = { 0 };
  const unsigned R7_SuperRegsSet[] = { 0 };
  const unsigned R8_SuperRegsSet[] = { 0 };
  const unsigned R9_SuperRegsSet[] = { 0 };
  const unsigned S0_SuperRegsSet[] = { ARM::Q0, ARM::D0, 0 };
  const unsigned S1_SuperRegsSet[] = { ARM::Q0, ARM::D0, 0 };
  const unsigned S10_SuperRegsSet[] = { ARM::Q2, ARM::D5, 0 };
  const unsigned S11_SuperRegsSet[] = { ARM::Q2, ARM::D5, 0 };
  const unsigned S12_SuperRegsSet[] = { ARM::Q3, ARM::D6, 0 };
  const unsigned S13_SuperRegsSet[] = { ARM::Q3, ARM::D6, 0 };
  const unsigned S14_SuperRegsSet[] = { ARM::Q3, ARM::D7, 0 };
  const unsigned S15_SuperRegsSet[] = { ARM::Q3, ARM::D7, 0 };
  const unsigned S16_SuperRegsSet[] = { ARM::Q4, ARM::D8, 0 };
  const unsigned S17_SuperRegsSet[] = { ARM::Q4, ARM::D8, 0 };
  const unsigned S18_SuperRegsSet[] = { ARM::Q4, ARM::D9, 0 };
  const unsigned S19_SuperRegsSet[] = { ARM::Q4, ARM::D9, 0 };
  const unsigned S2_SuperRegsSet[] = { ARM::Q0, ARM::D1, 0 };
  const unsigned S20_SuperRegsSet[] = { ARM::Q5, ARM::D10, 0 };
  const unsigned S21_SuperRegsSet[] = { ARM::Q5, ARM::D10, 0 };
  const unsigned S22_SuperRegsSet[] = { ARM::Q5, ARM::D11, 0 };
  const unsigned S23_SuperRegsSet[] = { ARM::Q5, ARM::D11, 0 };
  const unsigned S24_SuperRegsSet[] = { ARM::Q6, ARM::D12, 0 };
  const unsigned S25_SuperRegsSet[] = { ARM::Q6, ARM::D12, 0 };
  const unsigned S26_SuperRegsSet[] = { ARM::Q6, ARM::D13, 0 };
  const unsigned S27_SuperRegsSet[] = { ARM::Q6, ARM::D13, 0 };
  const unsigned S28_SuperRegsSet[] = { ARM::Q7, ARM::D14, 0 };
  const unsigned S29_SuperRegsSet[] = { ARM::Q7, ARM::D14, 0 };
  const unsigned S3_SuperRegsSet[] = { ARM::Q0, ARM::D1, 0 };
  const unsigned S30_SuperRegsSet[] = { ARM::Q7, ARM::D15, 0 };
  const unsigned S31_SuperRegsSet[] = { ARM::Q7, ARM::D15, 0 };
  const unsigned S4_SuperRegsSet[] = { ARM::Q1, ARM::D2, 0 };
  const unsigned S5_SuperRegsSet[] = { ARM::Q1, ARM::D2, 0 };
  const unsigned S6_SuperRegsSet[] = { ARM::Q1, ARM::D3, 0 };
  const unsigned S7_SuperRegsSet[] = { ARM::Q1, ARM::D3, 0 };
  const unsigned S8_SuperRegsSet[] = { ARM::Q2, ARM::D4, 0 };
  const unsigned S9_SuperRegsSet[] = { ARM::Q2, ARM::D4, 0 };
  const unsigned SDummy_SuperRegsSet[] = { 0 };
  const unsigned SP_SuperRegsSet[] = { 0 };

  const TargetRegisterDesc RegisterDescriptors[] = { // Descriptors
    { "NOREG",	0,	0,	0 },
    { "CPSR",	CPSR_AliasSet,	CPSR_SubRegsSet,	CPSR_SuperRegsSet },
    { "D0",	D0_AliasSet,	D0_SubRegsSet,	D0_SuperRegsSet },
    { "D1",	D1_AliasSet,	D1_SubRegsSet,	D1_SuperRegsSet },
    { "D10",	D10_AliasSet,	D10_SubRegsSet,	D10_SuperRegsSet },
    { "D11",	D11_AliasSet,	D11_SubRegsSet,	D11_SuperRegsSet },
    { "D12",	D12_AliasSet,	D12_SubRegsSet,	D12_SuperRegsSet },
    { "D13",	D13_AliasSet,	D13_SubRegsSet,	D13_SuperRegsSet },
    { "D14",	D14_AliasSet,	D14_SubRegsSet,	D14_SuperRegsSet },
    { "D15",	D15_AliasSet,	D15_SubRegsSet,	D15_SuperRegsSet },
    { "D16",	D16_AliasSet,	D16_SubRegsSet,	D16_SuperRegsSet },
    { "D17",	D17_AliasSet,	D17_SubRegsSet,	D17_SuperRegsSet },
    { "D18",	D18_AliasSet,	D18_SubRegsSet,	D18_SuperRegsSet },
    { "D19",	D19_AliasSet,	D19_SubRegsSet,	D19_SuperRegsSet },
    { "D2",	D2_AliasSet,	D2_SubRegsSet,	D2_SuperRegsSet },
    { "D20",	D20_AliasSet,	D20_SubRegsSet,	D20_SuperRegsSet },
    { "D21",	D21_AliasSet,	D21_SubRegsSet,	D21_SuperRegsSet },
    { "D22",	D22_AliasSet,	D22_SubRegsSet,	D22_SuperRegsSet },
    { "D23",	D23_AliasSet,	D23_SubRegsSet,	D23_SuperRegsSet },
    { "D24",	D24_AliasSet,	D24_SubRegsSet,	D24_SuperRegsSet },
    { "D25",	D25_AliasSet,	D25_SubRegsSet,	D25_SuperRegsSet },
    { "D26",	D26_AliasSet,	D26_SubRegsSet,	D26_SuperRegsSet },
    { "D27",	D27_AliasSet,	D27_SubRegsSet,	D27_SuperRegsSet },
    { "D28",	D28_AliasSet,	D28_SubRegsSet,	D28_SuperRegsSet },
    { "D29",	D29_AliasSet,	D29_SubRegsSet,	D29_SuperRegsSet },
    { "D3",	D3_AliasSet,	D3_SubRegsSet,	D3_SuperRegsSet },
    { "D30",	D30_AliasSet,	D30_SubRegsSet,	D30_SuperRegsSet },
    { "D31",	D31_AliasSet,	D31_SubRegsSet,	D31_SuperRegsSet },
    { "D4",	D4_AliasSet,	D4_SubRegsSet,	D4_SuperRegsSet },
    { "D5",	D5_AliasSet,	D5_SubRegsSet,	D5_SuperRegsSet },
    { "D6",	D6_AliasSet,	D6_SubRegsSet,	D6_SuperRegsSet },
    { "D7",	D7_AliasSet,	D7_SubRegsSet,	D7_SuperRegsSet },
    { "D8",	D8_AliasSet,	D8_SubRegsSet,	D8_SuperRegsSet },
    { "D9",	D9_AliasSet,	D9_SubRegsSet,	D9_SuperRegsSet },
    { "FPSCR",	FPSCR_AliasSet,	FPSCR_SubRegsSet,	FPSCR_SuperRegsSet },
    { "LR",	LR_AliasSet,	LR_SubRegsSet,	LR_SuperRegsSet },
    { "PC",	PC_AliasSet,	PC_SubRegsSet,	PC_SuperRegsSet },
    { "Q0",	Q0_AliasSet,	Q0_SubRegsSet,	Q0_SuperRegsSet },
    { "Q1",	Q1_AliasSet,	Q1_SubRegsSet,	Q1_SuperRegsSet },
    { "Q10",	Q10_AliasSet,	Q10_SubRegsSet,	Q10_SuperRegsSet },
    { "Q11",	Q11_AliasSet,	Q11_SubRegsSet,	Q11_SuperRegsSet },
    { "Q12",	Q12_AliasSet,	Q12_SubRegsSet,	Q12_SuperRegsSet },
    { "Q13",	Q13_AliasSet,	Q13_SubRegsSet,	Q13_SuperRegsSet },
    { "Q14",	Q14_AliasSet,	Q14_SubRegsSet,	Q14_SuperRegsSet },
    { "Q15",	Q15_AliasSet,	Q15_SubRegsSet,	Q15_SuperRegsSet },
    { "Q2",	Q2_AliasSet,	Q2_SubRegsSet,	Q2_SuperRegsSet },
    { "Q3",	Q3_AliasSet,	Q3_SubRegsSet,	Q3_SuperRegsSet },
    { "Q4",	Q4_AliasSet,	Q4_SubRegsSet,	Q4_SuperRegsSet },
    { "Q5",	Q5_AliasSet,	Q5_SubRegsSet,	Q5_SuperRegsSet },
    { "Q6",	Q6_AliasSet,	Q6_SubRegsSet,	Q6_SuperRegsSet },
    { "Q7",	Q7_AliasSet,	Q7_SubRegsSet,	Q7_SuperRegsSet },
    { "Q8",	Q8_AliasSet,	Q8_SubRegsSet,	Q8_SuperRegsSet },
    { "Q9",	Q9_AliasSet,	Q9_SubRegsSet,	Q9_SuperRegsSet },
    { "R0",	R0_AliasSet,	R0_SubRegsSet,	R0_SuperRegsSet },
    { "R1",	R1_AliasSet,	R1_SubRegsSet,	R1_SuperRegsSet },
    { "R10",	R10_AliasSet,	R10_SubRegsSet,	R10_SuperRegsSet },
    { "R11",	R11_AliasSet,	R11_SubRegsSet,	R11_SuperRegsSet },
    { "R12",	R12_AliasSet,	R12_SubRegsSet,	R12_SuperRegsSet },
    { "R2",	R2_AliasSet,	R2_SubRegsSet,	R2_SuperRegsSet },
    { "R3",	R3_AliasSet,	R3_SubRegsSet,	R3_SuperRegsSet },
    { "R4",	R4_AliasSet,	R4_SubRegsSet,	R4_SuperRegsSet },
    { "R5",	R5_AliasSet,	R5_SubRegsSet,	R5_SuperRegsSet },
    { "R6",	R6_AliasSet,	R6_SubRegsSet,	R6_SuperRegsSet },
    { "R7",	R7_AliasSet,	R7_SubRegsSet,	R7_SuperRegsSet },
    { "R8",	R8_AliasSet,	R8_SubRegsSet,	R8_SuperRegsSet },
    { "R9",	R9_AliasSet,	R9_SubRegsSet,	R9_SuperRegsSet },
    { "S0",	S0_AliasSet,	S0_SubRegsSet,	S0_SuperRegsSet },
    { "S1",	S1_AliasSet,	S1_SubRegsSet,	S1_SuperRegsSet },
    { "S10",	S10_AliasSet,	S10_SubRegsSet,	S10_SuperRegsSet },
    { "S11",	S11_AliasSet,	S11_SubRegsSet,	S11_SuperRegsSet },
    { "S12",	S12_AliasSet,	S12_SubRegsSet,	S12_SuperRegsSet },
    { "S13",	S13_AliasSet,	S13_SubRegsSet,	S13_SuperRegsSet },
    { "S14",	S14_AliasSet,	S14_SubRegsSet,	S14_SuperRegsSet },
    { "S15",	S15_AliasSet,	S15_SubRegsSet,	S15_SuperRegsSet },
    { "S16",	S16_AliasSet,	S16_SubRegsSet,	S16_SuperRegsSet },
    { "S17",	S17_AliasSet,	S17_SubRegsSet,	S17_SuperRegsSet },
    { "S18",	S18_AliasSet,	S18_SubRegsSet,	S18_SuperRegsSet },
    { "S19",	S19_AliasSet,	S19_SubRegsSet,	S19_SuperRegsSet },
    { "S2",	S2_AliasSet,	S2_SubRegsSet,	S2_SuperRegsSet },
    { "S20",	S20_AliasSet,	S20_SubRegsSet,	S20_SuperRegsSet },
    { "S21",	S21_AliasSet,	S21_SubRegsSet,	S21_SuperRegsSet },
    { "S22",	S22_AliasSet,	S22_SubRegsSet,	S22_SuperRegsSet },
    { "S23",	S23_AliasSet,	S23_SubRegsSet,	S23_SuperRegsSet },
    { "S24",	S24_AliasSet,	S24_SubRegsSet,	S24_SuperRegsSet },
    { "S25",	S25_AliasSet,	S25_SubRegsSet,	S25_SuperRegsSet },
    { "S26",	S26_AliasSet,	S26_SubRegsSet,	S26_SuperRegsSet },
    { "S27",	S27_AliasSet,	S27_SubRegsSet,	S27_SuperRegsSet },
    { "S28",	S28_AliasSet,	S28_SubRegsSet,	S28_SuperRegsSet },
    { "S29",	S29_AliasSet,	S29_SubRegsSet,	S29_SuperRegsSet },
    { "S3",	S3_AliasSet,	S3_SubRegsSet,	S3_SuperRegsSet },
    { "S30",	S30_AliasSet,	S30_SubRegsSet,	S30_SuperRegsSet },
    { "S31",	S31_AliasSet,	S31_SubRegsSet,	S31_SuperRegsSet },
    { "S4",	S4_AliasSet,	S4_SubRegsSet,	S4_SuperRegsSet },
    { "S5",	S5_AliasSet,	S5_SubRegsSet,	S5_SuperRegsSet },
    { "S6",	S6_AliasSet,	S6_SubRegsSet,	S6_SuperRegsSet },
    { "S7",	S7_AliasSet,	S7_SubRegsSet,	S7_SuperRegsSet },
    { "S8",	S8_AliasSet,	S8_SubRegsSet,	S8_SuperRegsSet },
    { "S9",	S9_AliasSet,	S9_SubRegsSet,	S9_SuperRegsSet },
    { "SDummy",	SDummy_AliasSet,	SDummy_SubRegsSet,	SDummy_SuperRegsSet },
    { "SP",	SP_AliasSet,	SP_SubRegsSet,	SP_SuperRegsSet },
  };
}

unsigned ARMGenRegisterInfo::getSubReg(unsigned RegNo, unsigned Index) const {
  switch (RegNo) {
  default:
    return 0;
  case ARM::D0:
    switch (Index) {
    default: return 0;
    case 1: return ARM::S0;
    case 2: return ARM::S1;
    };
    break;
  case ARM::D1:
    switch (Index) {
    default: return 0;
    case 1: return ARM::S2;
    case 2: return ARM::S3;
    };
    break;
  case ARM::D2:
    switch (Index) {
    default: return 0;
    case 1: return ARM::S4;
    case 2: return ARM::S5;
    };
    break;
  case ARM::D3:
    switch (Index) {
    default: return 0;
    case 1: return ARM::S6;
    case 2: return ARM::S7;
    };
    break;
  case ARM::D4:
    switch (Index) {
    default: return 0;
    case 1: return ARM::S8;
    case 2: return ARM::S9;
    };
    break;
  case ARM::D5:
    switch (Index) {
    default: return 0;
    case 1: return ARM::S10;
    case 2: return ARM::S11;
    };
    break;
  case ARM::D6:
    switch (Index) {
    default: return 0;
    case 1: return ARM::S12;
    case 2: return ARM::S13;
    };
    break;
  case ARM::D7:
    switch (Index) {
    default: return 0;
    case 1: return ARM::S14;
    case 2: return ARM::S15;
    };
    break;
  case ARM::D8:
    switch (Index) {
    default: return 0;
    case 1: return ARM::S16;
    case 2: return ARM::S17;
    };
    break;
  case ARM::D9:
    switch (Index) {
    default: return 0;
    case 1: return ARM::S18;
    case 2: return ARM::S19;
    };
    break;
  case ARM::D10:
    switch (Index) {
    default: return 0;
    case 1: return ARM::S20;
    case 2: return ARM::S21;
    };
    break;
  case ARM::D11:
    switch (Index) {
    default: return 0;
    case 1: return ARM::S22;
    case 2: return ARM::S23;
    };
    break;
  case ARM::D12:
    switch (Index) {
    default: return 0;
    case 1: return ARM::S24;
    case 2: return ARM::S25;
    };
    break;
  case ARM::D13:
    switch (Index) {
    default: return 0;
    case 1: return ARM::S26;
    case 2: return ARM::S27;
    };
    break;
  case ARM::D14:
    switch (Index) {
    default: return 0;
    case 1: return ARM::S28;
    case 2: return ARM::S29;
    };
    break;
  case ARM::D15:
    switch (Index) {
    default: return 0;
    case 1: return ARM::S30;
    case 2: return ARM::S31;
    };
    break;
  case ARM::Q0:
    switch (Index) {
    default: return 0;
    case 1: return ARM::S0;
    case 2: return ARM::S1;
    case 3: return ARM::S2;
    case 4: return ARM::S3;
    case 5: return ARM::D0;
    case 6: return ARM::D1;
    };
    break;
  case ARM::Q1:
    switch (Index) {
    default: return 0;
    case 1: return ARM::S4;
    case 2: return ARM::S5;
    case 3: return ARM::S6;
    case 4: return ARM::S7;
    case 5: return ARM::D2;
    case 6: return ARM::D3;
    };
    break;
  case ARM::Q2:
    switch (Index) {
    default: return 0;
    case 1: return ARM::S8;
    case 2: return ARM::S9;
    case 3: return ARM::S10;
    case 4: return ARM::S11;
    case 5: return ARM::D4;
    case 6: return ARM::D5;
    };
    break;
  case ARM::Q3:
    switch (Index) {
    default: return 0;
    case 1: return ARM::S12;
    case 2: return ARM::S13;
    case 3: return ARM::S14;
    case 4: return ARM::S15;
    case 5: return ARM::D6;
    case 6: return ARM::D7;
    };
    break;
  case ARM::Q4:
    switch (Index) {
    default: return 0;
    case 1: return ARM::S16;
    case 2: return ARM::S17;
    case 3: return ARM::S18;
    case 4: return ARM::S19;
    case 5: return ARM::D8;
    case 6: return ARM::D9;
    };
    break;
  case ARM::Q5:
    switch (Index) {
    default: return 0;
    case 1: return ARM::S20;
    case 2: return ARM::S21;
    case 3: return ARM::S22;
    case 4: return ARM::S23;
    case 5: return ARM::D10;
    case 6: return ARM::D11;
    };
    break;
  case ARM::Q6:
    switch (Index) {
    default: return 0;
    case 1: return ARM::S24;
    case 2: return ARM::S25;
    case 3: return ARM::S26;
    case 4: return ARM::S27;
    case 5: return ARM::D12;
    case 6: return ARM::D13;
    };
    break;
  case ARM::Q7:
    switch (Index) {
    default: return 0;
    case 1: return ARM::S28;
    case 2: return ARM::S29;
    case 3: return ARM::S30;
    case 4: return ARM::S31;
    case 5: return ARM::D14;
    case 6: return ARM::D15;
    };
    break;
  case ARM::Q8:
    switch (Index) {
    default: return 0;
    case 5: return ARM::D16;
    case 6: return ARM::D17;
    };
    break;
  case ARM::Q9:
    switch (Index) {
    default: return 0;
    case 5: return ARM::D18;
    case 6: return ARM::D19;
    };
    break;
  case ARM::Q10:
    switch (Index) {
    default: return 0;
    case 5: return ARM::D20;
    case 6: return ARM::D21;
    };
    break;
  case ARM::Q11:
    switch (Index) {
    default: return 0;
    case 5: return ARM::D22;
    case 6: return ARM::D23;
    };
    break;
  case ARM::Q12:
    switch (Index) {
    default: return 0;
    case 5: return ARM::D24;
    case 6: return ARM::D25;
    };
    break;
  case ARM::Q13:
    switch (Index) {
    default: return 0;
    case 5: return ARM::D26;
    case 6: return ARM::D27;
    };
    break;
  case ARM::Q14:
    switch (Index) {
    default: return 0;
    case 5: return ARM::D28;
    case 6: return ARM::D29;
    };
    break;
  case ARM::Q15:
    switch (Index) {
    default: return 0;
    case 5: return ARM::D30;
    case 6: return ARM::D31;
    };
    break;
  };
  return 0;
}

unsigned ARMGenRegisterInfo::getSubRegIndex(unsigned RegNo, unsigned SubRegNo) const {
  switch (RegNo) {
  default:
    return 0;
  case ARM::D0:
    if (SubRegNo == ARM::S0)  return 1;
    if (SubRegNo == ARM::S1)  return 2;
    return 0;
  case ARM::D1:
    if (SubRegNo == ARM::S2)  return 1;
    if (SubRegNo == ARM::S3)  return 2;
    return 0;
  case ARM::D2:
    if (SubRegNo == ARM::S4)  return 1;
    if (SubRegNo == ARM::S5)  return 2;
    return 0;
  case ARM::D3:
    if (SubRegNo == ARM::S6)  return 1;
    if (SubRegNo == ARM::S7)  return 2;
    return 0;
  case ARM::D4:
    if (SubRegNo == ARM::S8)  return 1;
    if (SubRegNo == ARM::S9)  return 2;
    return 0;
  case ARM::D5:
    if (SubRegNo == ARM::S10)  return 1;
    if (SubRegNo == ARM::S11)  return 2;
    return 0;
  case ARM::D6:
    if (SubRegNo == ARM::S12)  return 1;
    if (SubRegNo == ARM::S13)  return 2;
    return 0;
  case ARM::D7:
    if (SubRegNo == ARM::S14)  return 1;
    if (SubRegNo == ARM::S15)  return 2;
    return 0;
  case ARM::D8:
    if (SubRegNo == ARM::S16)  return 1;
    if (SubRegNo == ARM::S17)  return 2;
    return 0;
  case ARM::D9:
    if (SubRegNo == ARM::S18)  return 1;
    if (SubRegNo == ARM::S19)  return 2;
    return 0;
  case ARM::D10:
    if (SubRegNo == ARM::S20)  return 1;
    if (SubRegNo == ARM::S21)  return 2;
    return 0;
  case ARM::D11:
    if (SubRegNo == ARM::S22)  return 1;
    if (SubRegNo == ARM::S23)  return 2;
    return 0;
  case ARM::D12:
    if (SubRegNo == ARM::S24)  return 1;
    if (SubRegNo == ARM::S25)  return 2;
    return 0;
  case ARM::D13:
    if (SubRegNo == ARM::S26)  return 1;
    if (SubRegNo == ARM::S27)  return 2;
    return 0;
  case ARM::D14:
    if (SubRegNo == ARM::S28)  return 1;
    if (SubRegNo == ARM::S29)  return 2;
    return 0;
  case ARM::D15:
    if (SubRegNo == ARM::S30)  return 1;
    if (SubRegNo == ARM::S31)  return 2;
    return 0;
  case ARM::Q0:
    if (SubRegNo == ARM::S0)  return 1;
    if (SubRegNo == ARM::S1)  return 2;
    if (SubRegNo == ARM::S2)  return 3;
    if (SubRegNo == ARM::S3)  return 4;
    if (SubRegNo == ARM::D0)  return 5;
    if (SubRegNo == ARM::D1)  return 6;
    return 0;
  case ARM::Q1:
    if (SubRegNo == ARM::S4)  return 1;
    if (SubRegNo == ARM::S5)  return 2;
    if (SubRegNo == ARM::S6)  return 3;
    if (SubRegNo == ARM::S7)  return 4;
    if (SubRegNo == ARM::D2)  return 5;
    if (SubRegNo == ARM::D3)  return 6;
    return 0;
  case ARM::Q2:
    if (SubRegNo == ARM::S8)  return 1;
    if (SubRegNo == ARM::S9)  return 2;
    if (SubRegNo == ARM::S10)  return 3;
    if (SubRegNo == ARM::S11)  return 4;
    if (SubRegNo == ARM::D4)  return 5;
    if (SubRegNo == ARM::D5)  return 6;
    return 0;
  case ARM::Q3:
    if (SubRegNo == ARM::S12)  return 1;
    if (SubRegNo == ARM::S13)  return 2;
    if (SubRegNo == ARM::S14)  return 3;
    if (SubRegNo == ARM::S15)  return 4;
    if (SubRegNo == ARM::D6)  return 5;
    if (SubRegNo == ARM::D7)  return 6;
    return 0;
  case ARM::Q4:
    if (SubRegNo == ARM::S16)  return 1;
    if (SubRegNo == ARM::S17)  return 2;
    if (SubRegNo == ARM::S18)  return 3;
    if (SubRegNo == ARM::S19)  return 4;
    if (SubRegNo == ARM::D8)  return 5;
    if (SubRegNo == ARM::D9)  return 6;
    return 0;
  case ARM::Q5:
    if (SubRegNo == ARM::S20)  return 1;
    if (SubRegNo == ARM::S21)  return 2;
    if (SubRegNo == ARM::S22)  return 3;
    if (SubRegNo == ARM::S23)  return 4;
    if (SubRegNo == ARM::D10)  return 5;
    if (SubRegNo == ARM::D11)  return 6;
    return 0;
  case ARM::Q6:
    if (SubRegNo == ARM::S24)  return 1;
    if (SubRegNo == ARM::S25)  return 2;
    if (SubRegNo == ARM::S26)  return 3;
    if (SubRegNo == ARM::S27)  return 4;
    if (SubRegNo == ARM::D12)  return 5;
    if (SubRegNo == ARM::D13)  return 6;
    return 0;
  case ARM::Q7:
    if (SubRegNo == ARM::S28)  return 1;
    if (SubRegNo == ARM::S29)  return 2;
    if (SubRegNo == ARM::S30)  return 3;
    if (SubRegNo == ARM::S31)  return 4;
    if (SubRegNo == ARM::D14)  return 5;
    if (SubRegNo == ARM::D15)  return 6;
    return 0;
  case ARM::Q8:
    if (SubRegNo == ARM::D16)  return 5;
    if (SubRegNo == ARM::D17)  return 6;
    return 0;
  case ARM::Q9:
    if (SubRegNo == ARM::D18)  return 5;
    if (SubRegNo == ARM::D19)  return 6;
    return 0;
  case ARM::Q10:
    if (SubRegNo == ARM::D20)  return 5;
    if (SubRegNo == ARM::D21)  return 6;
    return 0;
  case ARM::Q11:
    if (SubRegNo == ARM::D22)  return 5;
    if (SubRegNo == ARM::D23)  return 6;
    return 0;
  case ARM::Q12:
    if (SubRegNo == ARM::D24)  return 5;
    if (SubRegNo == ARM::D25)  return 6;
    return 0;
  case ARM::Q13:
    if (SubRegNo == ARM::D26)  return 5;
    if (SubRegNo == ARM::D27)  return 6;
    return 0;
  case ARM::Q14:
    if (SubRegNo == ARM::D28)  return 5;
    if (SubRegNo == ARM::D29)  return 6;
    return 0;
  case ARM::Q15:
    if (SubRegNo == ARM::D30)  return 5;
    if (SubRegNo == ARM::D31)  return 6;
    return 0;
  };
  return 0;
}

ARMGenRegisterInfo::ARMGenRegisterInfo(int CallFrameSetupOpcode, int CallFrameDestroyOpcode)
  : TargetRegisterInfo(RegisterDescriptors, 100, RegisterClasses, RegisterClasses+12,
                  CallFrameSetupOpcode, CallFrameDestroyOpcode,
                 SubregHashTable, SubregHashTableSize,
                 SuperregHashTable, SuperregHashTableSize,
                 AliasesHashTable, AliasesHashTableSize) {
}

int ARMGenRegisterInfo::getDwarfRegNumFull(unsigned RegNum, unsigned Flavour) const {
  switch (Flavour) {
  default:
    assert(0 && "Unknown DWARF flavour");
    return -1;
  case 0:
    switch (RegNum) {
    default:
      assert(0 && "Invalid RegNum");
      return -1;
    case ARM::CPSR:
      return -1;
    case ARM::D0:
      return -1;
    case ARM::D1:
      return -1;
    case ARM::D10:
      return -1;
    case ARM::D11:
      return -1;
    case ARM::D12:
      return -1;
    case ARM::D13:
      return -1;
    case ARM::D14:
      return -1;
    case ARM::D15:
      return -1;
    case ARM::D16:
      return -1;
    case ARM::D17:
      return -1;
    case ARM::D18:
      return -1;
    case ARM::D19:
      return -1;
    case ARM::D2:
      return -1;
    case ARM::D20:
      return -1;
    case ARM::D21:
      return -1;
    case ARM::D22:
      return -1;
    case ARM::D23:
      return -1;
    case ARM::D24:
      return -1;
    case ARM::D25:
      return -1;
    case ARM::D26:
      return -1;
    case ARM::D27:
      return -1;
    case ARM::D28:
      return -1;
    case ARM::D29:
      return -1;
    case ARM::D3:
      return -1;
    case ARM::D30:
      return -1;
    case ARM::D31:
      return -1;
    case ARM::D4:
      return -1;
    case ARM::D5:
      return -1;
    case ARM::D6:
      return -1;
    case ARM::D7:
      return -1;
    case ARM::D8:
      return -1;
    case ARM::D9:
      return -1;
    case ARM::FPSCR:
      return -1;
    case ARM::LR:
      return 14;
    case ARM::PC:
      return 15;
    case ARM::Q0:
      return -1;
    case ARM::Q1:
      return -1;
    case ARM::Q10:
      return -1;
    case ARM::Q11:
      return -1;
    case ARM::Q12:
      return -1;
    case ARM::Q13:
      return -1;
    case ARM::Q14:
      return -1;
    case ARM::Q15:
      return -1;
    case ARM::Q2:
      return -1;
    case ARM::Q3:
      return -1;
    case ARM::Q4:
      return -1;
    case ARM::Q5:
      return -1;
    case ARM::Q6:
      return -1;
    case ARM::Q7:
      return -1;
    case ARM::Q8:
      return -1;
    case ARM::Q9:
      return -1;
    case ARM::R0:
      return 0;
    case ARM::R1:
      return 1;
    case ARM::R10:
      return 10;
    case ARM::R11:
      return 11;
    case ARM::R12:
      return 12;
    case ARM::R2:
      return 2;
    case ARM::R3:
      return 3;
    case ARM::R4:
      return 4;
    case ARM::R5:
      return 5;
    case ARM::R6:
      return 6;
    case ARM::R7:
      return 7;
    case ARM::R8:
      return 8;
    case ARM::R9:
      return 9;
    case ARM::S0:
      return -1;
    case ARM::S1:
      return -1;
    case ARM::S10:
      return -1;
    case ARM::S11:
      return -1;
    case ARM::S12:
      return -1;
    case ARM::S13:
      return -1;
    case ARM::S14:
      return -1;
    case ARM::S15:
      return -1;
    case ARM::S16:
      return -1;
    case ARM::S17:
      return -1;
    case ARM::S18:
      return -1;
    case ARM::S19:
      return -1;
    case ARM::S2:
      return -1;
    case ARM::S20:
      return -1;
    case ARM::S21:
      return -1;
    case ARM::S22:
      return -1;
    case ARM::S23:
      return -1;
    case ARM::S24:
      return -1;
    case ARM::S25:
      return -1;
    case ARM::S26:
      return -1;
    case ARM::S27:
      return -1;
    case ARM::S28:
      return -1;
    case ARM::S29:
      return -1;
    case ARM::S3:
      return -1;
    case ARM::S30:
      return -1;
    case ARM::S31:
      return -1;
    case ARM::S4:
      return -1;
    case ARM::S5:
      return -1;
    case ARM::S6:
      return -1;
    case ARM::S7:
      return -1;
    case ARM::S8:
      return -1;
    case ARM::S9:
      return -1;
    case ARM::SDummy:
      return -1;
    case ARM::SP:
      return 13;
    };
  };
}

} // End llvm namespace 
