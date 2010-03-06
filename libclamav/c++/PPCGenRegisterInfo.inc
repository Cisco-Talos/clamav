//===- TableGen'erated file -------------------------------------*- C++ -*-===//
//
// Register Information Source Fragment
//
// Automatically generated file, do not edit!
//
//===----------------------------------------------------------------------===//

namespace llvm {

namespace {     // Register classes...
  // CARRYRC Register Class...
  static const unsigned CARRYRC[] = {
    PPC::CARRY, 
  };

  // CRBITRC Register Class...
  static const unsigned CRBITRC[] = {
    PPC::CR0LT, PPC::CR0GT, PPC::CR0EQ, PPC::CR0UN, PPC::CR1LT, PPC::CR1GT, PPC::CR1EQ, PPC::CR1UN, PPC::CR2LT, PPC::CR2GT, PPC::CR2EQ, PPC::CR2UN, PPC::CR3LT, PPC::CR3GT, PPC::CR3EQ, PPC::CR3UN, PPC::CR4LT, PPC::CR4GT, PPC::CR4EQ, PPC::CR4UN, PPC::CR5LT, PPC::CR5GT, PPC::CR5EQ, PPC::CR5UN, PPC::CR6LT, PPC::CR6GT, PPC::CR6EQ, PPC::CR6UN, PPC::CR7LT, PPC::CR7GT, PPC::CR7EQ, PPC::CR7UN, 
  };

  // CRRC Register Class...
  static const unsigned CRRC[] = {
    PPC::CR0, PPC::CR1, PPC::CR5, PPC::CR6, PPC::CR7, PPC::CR2, PPC::CR3, PPC::CR4, 
  };

  // CTRRC Register Class...
  static const unsigned CTRRC[] = {
    PPC::CTR, 
  };

  // CTRRC8 Register Class...
  static const unsigned CTRRC8[] = {
    PPC::CTR8, 
  };

  // F4RC Register Class...
  static const unsigned F4RC[] = {
    PPC::F0, PPC::F1, PPC::F2, PPC::F3, PPC::F4, PPC::F5, PPC::F6, PPC::F7, PPC::F8, PPC::F9, PPC::F10, PPC::F11, PPC::F12, PPC::F13, PPC::F31, PPC::F30, PPC::F29, PPC::F28, PPC::F27, PPC::F26, PPC::F25, PPC::F24, PPC::F23, PPC::F22, PPC::F21, PPC::F20, PPC::F19, PPC::F18, PPC::F17, PPC::F16, PPC::F15, PPC::F14, 
  };

  // F8RC Register Class...
  static const unsigned F8RC[] = {
    PPC::F0, PPC::F1, PPC::F2, PPC::F3, PPC::F4, PPC::F5, PPC::F6, PPC::F7, PPC::F8, PPC::F9, PPC::F10, PPC::F11, PPC::F12, PPC::F13, PPC::F31, PPC::F30, PPC::F29, PPC::F28, PPC::F27, PPC::F26, PPC::F25, PPC::F24, PPC::F23, PPC::F22, PPC::F21, PPC::F20, PPC::F19, PPC::F18, PPC::F17, PPC::F16, PPC::F15, PPC::F14, 
  };

  // G8RC Register Class...
  static const unsigned G8RC[] = {
    PPC::X2, PPC::X3, PPC::X4, PPC::X5, PPC::X6, PPC::X7, PPC::X8, PPC::X9, PPC::X10, PPC::X11, PPC::X12, PPC::X30, PPC::X29, PPC::X28, PPC::X27, PPC::X26, PPC::X25, PPC::X24, PPC::X23, PPC::X22, PPC::X21, PPC::X20, PPC::X19, PPC::X18, PPC::X17, PPC::X16, PPC::X15, PPC::X14, PPC::X31, PPC::X13, PPC::X0, PPC::X1, PPC::LR8, 
  };

  // GPRC Register Class...
  static const unsigned GPRC[] = {
    PPC::R2, PPC::R3, PPC::R4, PPC::R5, PPC::R6, PPC::R7, PPC::R8, PPC::R9, PPC::R10, PPC::R11, PPC::R12, PPC::R30, PPC::R29, PPC::R28, PPC::R27, PPC::R26, PPC::R25, PPC::R24, PPC::R23, PPC::R22, PPC::R21, PPC::R20, PPC::R19, PPC::R18, PPC::R17, PPC::R16, PPC::R15, PPC::R14, PPC::R13, PPC::R31, PPC::R0, PPC::R1, PPC::LR, 
  };

  // VRRC Register Class...
  static const unsigned VRRC[] = {
    PPC::V2, PPC::V3, PPC::V4, PPC::V5, PPC::V0, PPC::V1, PPC::V6, PPC::V7, PPC::V8, PPC::V9, PPC::V10, PPC::V11, PPC::V12, PPC::V13, PPC::V14, PPC::V15, PPC::V16, PPC::V17, PPC::V18, PPC::V19, PPC::V31, PPC::V30, PPC::V29, PPC::V28, PPC::V27, PPC::V26, PPC::V25, PPC::V24, PPC::V23, PPC::V22, PPC::V21, PPC::V20, 
  };

  // VRSAVERC Register Class...
  static const unsigned VRSAVERC[] = {
    PPC::VRSAVE, 
  };

  // CARRYRCVTs Register Class Value Types...
  static const EVT CARRYRCVTs[] = {
    MVT::i32, MVT::Other
  };

  // CRBITRCVTs Register Class Value Types...
  static const EVT CRBITRCVTs[] = {
    MVT::i32, MVT::Other
  };

  // CRRCVTs Register Class Value Types...
  static const EVT CRRCVTs[] = {
    MVT::i32, MVT::Other
  };

  // CTRRCVTs Register Class Value Types...
  static const EVT CTRRCVTs[] = {
    MVT::i32, MVT::Other
  };

  // CTRRC8VTs Register Class Value Types...
  static const EVT CTRRC8VTs[] = {
    MVT::i64, MVT::Other
  };

  // F4RCVTs Register Class Value Types...
  static const EVT F4RCVTs[] = {
    MVT::f32, MVT::Other
  };

  // F8RCVTs Register Class Value Types...
  static const EVT F8RCVTs[] = {
    MVT::f64, MVT::Other
  };

  // G8RCVTs Register Class Value Types...
  static const EVT G8RCVTs[] = {
    MVT::i64, MVT::Other
  };

  // GPRCVTs Register Class Value Types...
  static const EVT GPRCVTs[] = {
    MVT::i32, MVT::Other
  };

  // VRRCVTs Register Class Value Types...
  static const EVT VRRCVTs[] = {
    MVT::v16i8, MVT::v8i16, MVT::v4i32, MVT::v4f32, MVT::Other
  };

  // VRSAVERCVTs Register Class Value Types...
  static const EVT VRSAVERCVTs[] = {
    MVT::i32, MVT::Other
  };

}  // end anonymous namespace

namespace PPC {   // Register class instances
  CARRYRCClass	CARRYRCRegClass;
  CRBITRCClass	CRBITRCRegClass;
  CRRCClass	CRRCRegClass;
  CTRRCClass	CTRRCRegClass;
  CTRRC8Class	CTRRC8RegClass;
  F4RCClass	F4RCRegClass;
  F8RCClass	F8RCRegClass;
  G8RCClass	G8RCRegClass;
  GPRCClass	GPRCRegClass;
  VRRCClass	VRRCRegClass;
  VRSAVERCClass	VRSAVERCRegClass;

  // CARRYRC Sub-register Classes...
  static const TargetRegisterClass* const CARRYRCSubRegClasses[] = {
    NULL
  };

  // CRBITRC Sub-register Classes...
  static const TargetRegisterClass* const CRBITRCSubRegClasses[] = {
    NULL
  };

  // CRRC Sub-register Classes...
  static const TargetRegisterClass* const CRRCSubRegClasses[] = {
    &PPC::CRBITRCRegClass, &PPC::CRBITRCRegClass, &PPC::CRBITRCRegClass, &PPC::CRBITRCRegClass, NULL
  };

  // CTRRC Sub-register Classes...
  static const TargetRegisterClass* const CTRRCSubRegClasses[] = {
    NULL
  };

  // CTRRC8 Sub-register Classes...
  static const TargetRegisterClass* const CTRRC8SubRegClasses[] = {
    NULL
  };

  // F4RC Sub-register Classes...
  static const TargetRegisterClass* const F4RCSubRegClasses[] = {
    NULL
  };

  // F8RC Sub-register Classes...
  static const TargetRegisterClass* const F8RCSubRegClasses[] = {
    NULL
  };

  // G8RC Sub-register Classes...
  static const TargetRegisterClass* const G8RCSubRegClasses[] = {
    NULL
  };

  // GPRC Sub-register Classes...
  static const TargetRegisterClass* const GPRCSubRegClasses[] = {
    NULL
  };

  // VRRC Sub-register Classes...
  static const TargetRegisterClass* const VRRCSubRegClasses[] = {
    NULL
  };

  // VRSAVERC Sub-register Classes...
  static const TargetRegisterClass* const VRSAVERCSubRegClasses[] = {
    NULL
  };

  // CARRYRC Super-register Classes...
  static const TargetRegisterClass* const CARRYRCSuperRegClasses[] = {
    NULL
  };

  // CRBITRC Super-register Classes...
  static const TargetRegisterClass* const CRBITRCSuperRegClasses[] = {
    &PPC::CRRCRegClass, NULL
  };

  // CRRC Super-register Classes...
  static const TargetRegisterClass* const CRRCSuperRegClasses[] = {
    NULL
  };

  // CTRRC Super-register Classes...
  static const TargetRegisterClass* const CTRRCSuperRegClasses[] = {
    NULL
  };

  // CTRRC8 Super-register Classes...
  static const TargetRegisterClass* const CTRRC8SuperRegClasses[] = {
    NULL
  };

  // F4RC Super-register Classes...
  static const TargetRegisterClass* const F4RCSuperRegClasses[] = {
    NULL
  };

  // F8RC Super-register Classes...
  static const TargetRegisterClass* const F8RCSuperRegClasses[] = {
    NULL
  };

  // G8RC Super-register Classes...
  static const TargetRegisterClass* const G8RCSuperRegClasses[] = {
    NULL
  };

  // GPRC Super-register Classes...
  static const TargetRegisterClass* const GPRCSuperRegClasses[] = {
    NULL
  };

  // VRRC Super-register Classes...
  static const TargetRegisterClass* const VRRCSuperRegClasses[] = {
    NULL
  };

  // VRSAVERC Super-register Classes...
  static const TargetRegisterClass* const VRSAVERCSuperRegClasses[] = {
    NULL
  };

  // CARRYRC Register Class sub-classes...
  static const TargetRegisterClass* const CARRYRCSubclasses[] = {
    NULL
  };

  // CRBITRC Register Class sub-classes...
  static const TargetRegisterClass* const CRBITRCSubclasses[] = {
    NULL
  };

  // CRRC Register Class sub-classes...
  static const TargetRegisterClass* const CRRCSubclasses[] = {
    NULL
  };

  // CTRRC Register Class sub-classes...
  static const TargetRegisterClass* const CTRRCSubclasses[] = {
    NULL
  };

  // CTRRC8 Register Class sub-classes...
  static const TargetRegisterClass* const CTRRC8Subclasses[] = {
    NULL
  };

  // F4RC Register Class sub-classes...
  static const TargetRegisterClass* const F4RCSubclasses[] = {
    &PPC::F8RCRegClass, NULL
  };

  // F8RC Register Class sub-classes...
  static const TargetRegisterClass* const F8RCSubclasses[] = {
    NULL
  };

  // G8RC Register Class sub-classes...
  static const TargetRegisterClass* const G8RCSubclasses[] = {
    NULL
  };

  // GPRC Register Class sub-classes...
  static const TargetRegisterClass* const GPRCSubclasses[] = {
    NULL
  };

  // VRRC Register Class sub-classes...
  static const TargetRegisterClass* const VRRCSubclasses[] = {
    NULL
  };

  // VRSAVERC Register Class sub-classes...
  static const TargetRegisterClass* const VRSAVERCSubclasses[] = {
    NULL
  };

  // CARRYRC Register Class super-classes...
  static const TargetRegisterClass* const CARRYRCSuperclasses[] = {
    NULL
  };

  // CRBITRC Register Class super-classes...
  static const TargetRegisterClass* const CRBITRCSuperclasses[] = {
    NULL
  };

  // CRRC Register Class super-classes...
  static const TargetRegisterClass* const CRRCSuperclasses[] = {
    NULL
  };

  // CTRRC Register Class super-classes...
  static const TargetRegisterClass* const CTRRCSuperclasses[] = {
    NULL
  };

  // CTRRC8 Register Class super-classes...
  static const TargetRegisterClass* const CTRRC8Superclasses[] = {
    NULL
  };

  // F4RC Register Class super-classes...
  static const TargetRegisterClass* const F4RCSuperclasses[] = {
    NULL
  };

  // F8RC Register Class super-classes...
  static const TargetRegisterClass* const F8RCSuperclasses[] = {
    &PPC::F4RCRegClass, NULL
  };

  // G8RC Register Class super-classes...
  static const TargetRegisterClass* const G8RCSuperclasses[] = {
    NULL
  };

  // GPRC Register Class super-classes...
  static const TargetRegisterClass* const GPRCSuperclasses[] = {
    NULL
  };

  // VRRC Register Class super-classes...
  static const TargetRegisterClass* const VRRCSuperclasses[] = {
    NULL
  };

  // VRSAVERC Register Class super-classes...
  static const TargetRegisterClass* const VRSAVERCSuperclasses[] = {
    NULL
  };


CARRYRCClass::CARRYRCClass()  : TargetRegisterClass(CARRYRCRegClassID, "CARRYRC", CARRYRCVTs, CARRYRCSubclasses, CARRYRCSuperclasses, CARRYRCSubRegClasses, CARRYRCSuperRegClasses, 4, 4, -1, CARRYRC, CARRYRC + 1) {}

CRBITRCClass::CRBITRCClass()  : TargetRegisterClass(CRBITRCRegClassID, "CRBITRC", CRBITRCVTs, CRBITRCSubclasses, CRBITRCSuperclasses, CRBITRCSubRegClasses, CRBITRCSuperRegClasses, 4, 4, -1, CRBITRC, CRBITRC + 32) {}

CRRCClass::CRRCClass()  : TargetRegisterClass(CRRCRegClassID, "CRRC", CRRCVTs, CRRCSubclasses, CRRCSuperclasses, CRRCSubRegClasses, CRRCSuperRegClasses, 4, 4, 1, CRRC, CRRC + 8) {}

CTRRCClass::CTRRCClass()  : TargetRegisterClass(CTRRCRegClassID, "CTRRC", CTRRCVTs, CTRRCSubclasses, CTRRCSuperclasses, CTRRCSubRegClasses, CTRRCSuperRegClasses, 4, 4, 1, CTRRC, CTRRC + 1) {}

CTRRC8Class::CTRRC8Class()  : TargetRegisterClass(CTRRC8RegClassID, "CTRRC8", CTRRC8VTs, CTRRC8Subclasses, CTRRC8Superclasses, CTRRC8SubRegClasses, CTRRC8SuperRegClasses, 8, 8, 1, CTRRC8, CTRRC8 + 1) {}

F4RCClass::F4RCClass()  : TargetRegisterClass(F4RCRegClassID, "F4RC", F4RCVTs, F4RCSubclasses, F4RCSuperclasses, F4RCSubRegClasses, F4RCSuperRegClasses, 4, 4, 1, F4RC, F4RC + 32) {}

F8RCClass::F8RCClass()  : TargetRegisterClass(F8RCRegClassID, "F8RC", F8RCVTs, F8RCSubclasses, F8RCSuperclasses, F8RCSubRegClasses, F8RCSuperRegClasses, 8, 8, 1, F8RC, F8RC + 32) {}

    G8RCClass::iterator
    G8RCClass::allocation_order_begin(const MachineFunction &MF) const {
      // 64-bit SVR4 ABI: r2 is reserved for the TOC pointer.
      // Darwin: r2 is reserved for CR save/restore sequence.
      return begin()+1;
    }
    G8RCClass::iterator
    G8RCClass::allocation_order_end(const MachineFunction &MF) const {
      if (needsFP(MF))
        return end()-5;
      else
        return end()-4;
    }
  
G8RCClass::G8RCClass()  : TargetRegisterClass(G8RCRegClassID, "G8RC", G8RCVTs, G8RCSubclasses, G8RCSuperclasses, G8RCSubRegClasses, G8RCSuperRegClasses, 8, 8, 1, G8RC, G8RC + 33) {}

    GPRCClass::iterator
    GPRCClass::allocation_order_begin(const MachineFunction &MF) const {
      // 32-bit SVR4 ABI: r2 is reserved for the OS.
      // 64-bit SVR4 ABI: r2 is reserved for the TOC pointer.
      // Darwin: R2 is reserved for CR save/restore sequence.
      return begin()+1;
    }
    GPRCClass::iterator
    GPRCClass::allocation_order_end(const MachineFunction &MF) const {
      // On PPC64, r13 is the thread pointer.  Never allocate this register.
      // Note that this is overconservative, as it also prevents allocation of
      // R31 when the FP is not needed.
      // When using the 32-bit SVR4 ABI, r13 is reserved for the Small Data Area
      // pointer.
      const PPCSubtarget &Subtarget
        = MF.getTarget().getSubtarget<PPCSubtarget>();
         
      if (Subtarget.isPPC64() || Subtarget.isSVR4ABI())
        return end()-5;  // don't allocate R13, R31, R0, R1, LR
        
      if (needsFP(MF))
        return end()-4;  // don't allocate R31, R0, R1, LR
      else
        return end()-3;  // don't allocate R0, R1, LR
    }
  
GPRCClass::GPRCClass()  : TargetRegisterClass(GPRCRegClassID, "GPRC", GPRCVTs, GPRCSubclasses, GPRCSuperclasses, GPRCSubRegClasses, GPRCSuperRegClasses, 4, 4, 1, GPRC, GPRC + 33) {}

VRRCClass::VRRCClass()  : TargetRegisterClass(VRRCRegClassID, "VRRC", VRRCVTs, VRRCSubclasses, VRRCSuperclasses, VRRCSubRegClasses, VRRCSuperRegClasses, 16, 16, 1, VRRC, VRRC + 32) {}

VRSAVERCClass::VRSAVERCClass()  : TargetRegisterClass(VRSAVERCRegClassID, "VRSAVERC", VRSAVERCVTs, VRSAVERCSubclasses, VRSAVERCSuperclasses, VRSAVERCSubRegClasses, VRSAVERCSuperRegClasses, 4, 4, 1, VRSAVERC, VRSAVERC + 1) {}
}

namespace {
  const TargetRegisterClass* const RegisterClasses[] = {
    &PPC::CARRYRCRegClass,
    &PPC::CRBITRCRegClass,
    &PPC::CRRCRegClass,
    &PPC::CTRRCRegClass,
    &PPC::CTRRC8RegClass,
    &PPC::F4RCRegClass,
    &PPC::F8RCRegClass,
    &PPC::G8RCRegClass,
    &PPC::GPRCRegClass,
    &PPC::VRRCRegClass,
    &PPC::VRSAVERCRegClass,
  };


  // Number of hash collisions: 11
  const unsigned SubregHashTable[] = { PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::X22, PPC::R22, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::CR2, PPC::CR2GT, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::CR7, PPC::CR7UN, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::X10, PPC::R10, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::X7, PPC::R7, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::CR5, PPC::CR5EQ, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::X23, PPC::R23, 
                                       PPC::CR2, PPC::CR2LT, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::X11, PPC::R11, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::X8, PPC::R8, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::CR5, PPC::CR5GT, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::CR2, PPC::CR2UN, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::X24, PPC::R24, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::X12, PPC::R12, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::X9, PPC::R9, 
                                       PPC::CR0, PPC::CR0EQ, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::CR5, PPC::CR5LT, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::X25, PPC::R25, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::X13, PPC::R13, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::CR0, PPC::CR0GT, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::CR5, PPC::CR5UN, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::X26, PPC::R26, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::CR3, PPC::CR3EQ, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::X14, PPC::R14, 
                                       PPC::CR0, PPC::CR0LT, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::X27, PPC::R27, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::CR3, PPC::CR3GT, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::CR0, PPC::CR0UN, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::X15, PPC::R15, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::CR6, PPC::CR6EQ, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::X28, PPC::R28, 
                                       PPC::CR3, PPC::CR3LT, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::X16, PPC::R16, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::CR6, PPC::CR6GT, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::CR3, PPC::CR3UN, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::X29, PPC::R29, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::X17, PPC::R17, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::CR1, PPC::CR1EQ, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::CR6, PPC::CR6LT, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::X3, PPC::R3, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::X18, PPC::R18, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::CR1, PPC::CR1GT, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::CR6, PPC::CR6UN, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::X30, PPC::R30, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::CR4, PPC::CR4EQ, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::X19, PPC::R19, 
                                       PPC::CR1, PPC::CR1LT, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::X31, PPC::R31, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::CR4, PPC::CR4GT, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::CR1, PPC::CR1UN, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::X2, PPC::R2, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::CR7, PPC::CR7EQ, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::X4, PPC::R4, 
                                       PPC::CR4, PPC::CR4LT, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::X20, PPC::R20, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::CR7, PPC::CR7GT, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::X0, PPC::R0, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::CR4, PPC::CR4UN, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::X5, PPC::R5, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::X21, PPC::R21, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::CR2, PPC::CR2EQ, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::CR7, PPC::CR7LT, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::X1, PPC::R1, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::X6, PPC::R6, 
PPC::NoRegister, PPC::NoRegister };
  const unsigned SubregHashTableSize = 512;


  // Number of hash collisions: 10
  const unsigned SuperregHashTable[] = { PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::R14, PPC::X14, 
                                       PPC::CR5EQ, PPC::CR5, 
                                       PPC::CR5GT, PPC::CR5, 
                                       PPC::CR5LT, PPC::CR5, 
                                       PPC::CR5UN, PPC::CR5, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::R27, PPC::X27, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::R15, PPC::X15, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::R28, PPC::X28, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::CR0EQ, PPC::CR0, 
                                       PPC::CR0GT, PPC::CR0, 
                                       PPC::CR0LT, PPC::CR0, 
                                       PPC::CR0UN, PPC::CR0, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::R16, PPC::X16, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::R29, PPC::X29, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::R17, PPC::X17, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::CR3EQ, PPC::CR3, 
                                       PPC::CR3GT, PPC::CR3, 
                                       PPC::CR3LT, PPC::CR3, 
                                       PPC::CR3UN, PPC::CR3, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::R3, PPC::X3, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::R18, PPC::X18, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::R30, PPC::X30, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::R19, PPC::X19, 
                                       PPC::CR6EQ, PPC::CR6, 
                                       PPC::CR6GT, PPC::CR6, 
                                       PPC::CR6LT, PPC::CR6, 
                                       PPC::CR6UN, PPC::CR6, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::R31, PPC::X31, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::R2, PPC::X2, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::R4, PPC::X4, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::CR1EQ, PPC::CR1, 
                                       PPC::CR1GT, PPC::CR1, 
                                       PPC::CR1LT, PPC::CR1, 
                                       PPC::CR1UN, PPC::CR1, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::R20, PPC::X20, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::R0, PPC::X0, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::R5, PPC::X5, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::R21, PPC::X21, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::R1, PPC::X1, 
                                       PPC::CR4EQ, PPC::CR4, 
                                       PPC::CR4GT, PPC::CR4, 
                                       PPC::CR4LT, PPC::CR4, 
                                       PPC::CR4UN, PPC::CR4, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::R6, PPC::X6, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::R22, PPC::X22, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::R10, PPC::X10, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::R7, PPC::X7, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::R23, PPC::X23, 
                                       PPC::CR7EQ, PPC::CR7, 
                                       PPC::CR7GT, PPC::CR7, 
                                       PPC::CR7LT, PPC::CR7, 
                                       PPC::CR7UN, PPC::CR7, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::R11, PPC::X11, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::R8, PPC::X8, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::R24, PPC::X24, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::R12, PPC::X12, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::R9, PPC::X9, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::CR2EQ, PPC::CR2, 
                                       PPC::CR2GT, PPC::CR2, 
                                       PPC::CR2LT, PPC::CR2, 
                                       PPC::CR2UN, PPC::CR2, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::R25, PPC::X25, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::R13, PPC::X13, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::R26, PPC::X26, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
PPC::NoRegister, PPC::NoRegister };
  const unsigned SuperregHashTableSize = 512;


  // Number of hash collisions: 11
  const unsigned AliasesHashTable[] = { PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::CR5EQ, PPC::CR5, 
                                       PPC::CR5GT, PPC::CR5, 
                                       PPC::CR5LT, PPC::CR5, 
                                       PPC::CR5UN, PPC::CR5, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::R27, PPC::X27, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::X10, PPC::R10, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::X7, PPC::R7, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::CR5, PPC::CR5EQ, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::R28, PPC::X28, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::X11, PPC::R11, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::X8, PPC::R8, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::CR5, PPC::CR5GT, 
                                       PPC::CR0EQ, PPC::CR0, 
                                       PPC::CR0GT, PPC::CR0, 
                                       PPC::CR0LT, PPC::CR0, 
                                       PPC::CR0UN, PPC::CR0, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::R29, PPC::X29, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::X12, PPC::R12, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::X9, PPC::R9, 
                                       PPC::CR0, PPC::CR0EQ, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::CR5, PPC::CR5LT, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::R3, PPC::X3, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::X13, PPC::R13, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::CR0, PPC::CR0GT, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::CR5, PPC::CR5UN, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::R30, PPC::X30, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::X14, PPC::R14, 
                                       PPC::CR0, PPC::CR0LT, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::CR6EQ, PPC::CR6, 
                                       PPC::CR6GT, PPC::CR6, 
                                       PPC::CR6LT, PPC::CR6, 
                                       PPC::CR6UN, PPC::CR6, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::R31, PPC::X31, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::CR0, PPC::CR0UN, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::X15, PPC::R15, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::CR6, PPC::CR6EQ, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::R4, PPC::X4, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::X16, PPC::R16, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::CR6, PPC::CR6GT, 
                                       PPC::CR1EQ, PPC::CR1, 
                                       PPC::CR1GT, PPC::CR1, 
                                       PPC::CR1LT, PPC::CR1, 
                                       PPC::CR1UN, PPC::CR1, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::R0, PPC::X0, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::R5, PPC::X5, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::X17, PPC::R17, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::CR1, PPC::CR1EQ, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::CR6, PPC::CR6LT, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::R1, PPC::X1, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::R6, PPC::X6, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::X18, PPC::R18, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::CR1, PPC::CR1GT, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::CR6, PPC::CR6UN, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::R10, PPC::X10, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::R7, PPC::X7, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::X19, PPC::R19, 
                                       PPC::CR1, PPC::CR1LT, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::CR7EQ, PPC::CR7, 
                                       PPC::CR7GT, PPC::CR7, 
                                       PPC::CR7LT, PPC::CR7, 
                                       PPC::CR7UN, PPC::CR7, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::R11, PPC::X11, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::R8, PPC::X8, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::CR1, PPC::CR1UN, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::X2, PPC::R2, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::CR7, PPC::CR7EQ, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::R12, PPC::X12, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::R9, PPC::X9, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::X20, PPC::R20, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::CR7, PPC::CR7GT, 
                                       PPC::CR2EQ, PPC::CR2, 
                                       PPC::CR2GT, PPC::CR2, 
                                       PPC::CR2LT, PPC::CR2, 
                                       PPC::CR2UN, PPC::CR2, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::R13, PPC::X13, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::X21, PPC::R21, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::CR2, PPC::CR2EQ, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::CR7, PPC::CR7LT, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::R14, PPC::X14, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::X22, PPC::R22, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::CR2, PPC::CR2GT, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::CR7, PPC::CR7UN, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::R15, PPC::X15, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::X23, PPC::R23, 
                                       PPC::CR2, PPC::CR2LT, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::R16, PPC::X16, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::CR2, PPC::CR2UN, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::X24, PPC::R24, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::R17, PPC::X17, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::X25, PPC::R25, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::CR3EQ, PPC::CR3, 
                                       PPC::CR3GT, PPC::CR3, 
                                       PPC::CR3LT, PPC::CR3, 
                                       PPC::CR3UN, PPC::CR3, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::R18, PPC::X18, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::X26, PPC::R26, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::CR3, PPC::CR3EQ, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::R19, PPC::X19, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::X27, PPC::R27, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::CR3, PPC::CR3GT, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::R2, PPC::X2, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::X28, PPC::R28, 
                                       PPC::CR3, PPC::CR3LT, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::R20, PPC::X20, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::CR3, PPC::CR3UN, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::X29, PPC::R29, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::R21, PPC::X21, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::X3, PPC::R3, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::CR4EQ, PPC::CR4, 
                                       PPC::CR4GT, PPC::CR4, 
                                       PPC::CR4LT, PPC::CR4, 
                                       PPC::CR4UN, PPC::CR4, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::R22, PPC::X22, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::X30, PPC::R30, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::CR4, PPC::CR4EQ, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::R23, PPC::X23, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::X31, PPC::R31, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::CR4, PPC::CR4GT, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::R24, PPC::X24, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::X4, PPC::R4, 
                                       PPC::CR4, PPC::CR4LT, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::R25, PPC::X25, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::X0, PPC::R0, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::CR4, PPC::CR4UN, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::X5, PPC::R5, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::R26, PPC::X26, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::X1, PPC::R1, 
                                       PPC::NoRegister, PPC::NoRegister, 
                                       PPC::X6, PPC::R6, 
PPC::NoRegister, PPC::NoRegister };
  const unsigned AliasesHashTableSize = 1024;


  // Register Alias Sets...
  const unsigned Empty_AliasSet[] = { 0 };
  const unsigned CARRY_AliasSet[] = { 0 };
  const unsigned CR0_AliasSet[] = { PPC::CR0LT, PPC::CR0GT, PPC::CR0EQ, PPC::CR0UN, 0 };
  const unsigned CR0EQ_AliasSet[] = { PPC::CR0, 0 };
  const unsigned CR0GT_AliasSet[] = { PPC::CR0, 0 };
  const unsigned CR0LT_AliasSet[] = { PPC::CR0, 0 };
  const unsigned CR0UN_AliasSet[] = { PPC::CR0, 0 };
  const unsigned CR1_AliasSet[] = { PPC::CR1LT, PPC::CR1GT, PPC::CR1EQ, PPC::CR1UN, 0 };
  const unsigned CR1EQ_AliasSet[] = { PPC::CR1, 0 };
  const unsigned CR1GT_AliasSet[] = { PPC::CR1, 0 };
  const unsigned CR1LT_AliasSet[] = { PPC::CR1, 0 };
  const unsigned CR1UN_AliasSet[] = { PPC::CR1, 0 };
  const unsigned CR2_AliasSet[] = { PPC::CR2LT, PPC::CR2GT, PPC::CR2EQ, PPC::CR2UN, 0 };
  const unsigned CR2EQ_AliasSet[] = { PPC::CR2, 0 };
  const unsigned CR2GT_AliasSet[] = { PPC::CR2, 0 };
  const unsigned CR2LT_AliasSet[] = { PPC::CR2, 0 };
  const unsigned CR2UN_AliasSet[] = { PPC::CR2, 0 };
  const unsigned CR3_AliasSet[] = { PPC::CR3LT, PPC::CR3GT, PPC::CR3EQ, PPC::CR3UN, 0 };
  const unsigned CR3EQ_AliasSet[] = { PPC::CR3, 0 };
  const unsigned CR3GT_AliasSet[] = { PPC::CR3, 0 };
  const unsigned CR3LT_AliasSet[] = { PPC::CR3, 0 };
  const unsigned CR3UN_AliasSet[] = { PPC::CR3, 0 };
  const unsigned CR4_AliasSet[] = { PPC::CR4LT, PPC::CR4GT, PPC::CR4EQ, PPC::CR4UN, 0 };
  const unsigned CR4EQ_AliasSet[] = { PPC::CR4, 0 };
  const unsigned CR4GT_AliasSet[] = { PPC::CR4, 0 };
  const unsigned CR4LT_AliasSet[] = { PPC::CR4, 0 };
  const unsigned CR4UN_AliasSet[] = { PPC::CR4, 0 };
  const unsigned CR5_AliasSet[] = { PPC::CR5LT, PPC::CR5GT, PPC::CR5EQ, PPC::CR5UN, 0 };
  const unsigned CR5EQ_AliasSet[] = { PPC::CR5, 0 };
  const unsigned CR5GT_AliasSet[] = { PPC::CR5, 0 };
  const unsigned CR5LT_AliasSet[] = { PPC::CR5, 0 };
  const unsigned CR5UN_AliasSet[] = { PPC::CR5, 0 };
  const unsigned CR6_AliasSet[] = { PPC::CR6LT, PPC::CR6GT, PPC::CR6EQ, PPC::CR6UN, 0 };
  const unsigned CR6EQ_AliasSet[] = { PPC::CR6, 0 };
  const unsigned CR6GT_AliasSet[] = { PPC::CR6, 0 };
  const unsigned CR6LT_AliasSet[] = { PPC::CR6, 0 };
  const unsigned CR6UN_AliasSet[] = { PPC::CR6, 0 };
  const unsigned CR7_AliasSet[] = { PPC::CR7LT, PPC::CR7GT, PPC::CR7EQ, PPC::CR7UN, 0 };
  const unsigned CR7EQ_AliasSet[] = { PPC::CR7, 0 };
  const unsigned CR7GT_AliasSet[] = { PPC::CR7, 0 };
  const unsigned CR7LT_AliasSet[] = { PPC::CR7, 0 };
  const unsigned CR7UN_AliasSet[] = { PPC::CR7, 0 };
  const unsigned CTR_AliasSet[] = { 0 };
  const unsigned CTR8_AliasSet[] = { 0 };
  const unsigned F0_AliasSet[] = { 0 };
  const unsigned F1_AliasSet[] = { 0 };
  const unsigned F10_AliasSet[] = { 0 };
  const unsigned F11_AliasSet[] = { 0 };
  const unsigned F12_AliasSet[] = { 0 };
  const unsigned F13_AliasSet[] = { 0 };
  const unsigned F14_AliasSet[] = { 0 };
  const unsigned F15_AliasSet[] = { 0 };
  const unsigned F16_AliasSet[] = { 0 };
  const unsigned F17_AliasSet[] = { 0 };
  const unsigned F18_AliasSet[] = { 0 };
  const unsigned F19_AliasSet[] = { 0 };
  const unsigned F2_AliasSet[] = { 0 };
  const unsigned F20_AliasSet[] = { 0 };
  const unsigned F21_AliasSet[] = { 0 };
  const unsigned F22_AliasSet[] = { 0 };
  const unsigned F23_AliasSet[] = { 0 };
  const unsigned F24_AliasSet[] = { 0 };
  const unsigned F25_AliasSet[] = { 0 };
  const unsigned F26_AliasSet[] = { 0 };
  const unsigned F27_AliasSet[] = { 0 };
  const unsigned F28_AliasSet[] = { 0 };
  const unsigned F29_AliasSet[] = { 0 };
  const unsigned F3_AliasSet[] = { 0 };
  const unsigned F30_AliasSet[] = { 0 };
  const unsigned F31_AliasSet[] = { 0 };
  const unsigned F4_AliasSet[] = { 0 };
  const unsigned F5_AliasSet[] = { 0 };
  const unsigned F6_AliasSet[] = { 0 };
  const unsigned F7_AliasSet[] = { 0 };
  const unsigned F8_AliasSet[] = { 0 };
  const unsigned F9_AliasSet[] = { 0 };
  const unsigned LR_AliasSet[] = { 0 };
  const unsigned LR8_AliasSet[] = { 0 };
  const unsigned R0_AliasSet[] = { PPC::X0, 0 };
  const unsigned R1_AliasSet[] = { PPC::X1, 0 };
  const unsigned R10_AliasSet[] = { PPC::X10, 0 };
  const unsigned R11_AliasSet[] = { PPC::X11, 0 };
  const unsigned R12_AliasSet[] = { PPC::X12, 0 };
  const unsigned R13_AliasSet[] = { PPC::X13, 0 };
  const unsigned R14_AliasSet[] = { PPC::X14, 0 };
  const unsigned R15_AliasSet[] = { PPC::X15, 0 };
  const unsigned R16_AliasSet[] = { PPC::X16, 0 };
  const unsigned R17_AliasSet[] = { PPC::X17, 0 };
  const unsigned R18_AliasSet[] = { PPC::X18, 0 };
  const unsigned R19_AliasSet[] = { PPC::X19, 0 };
  const unsigned R2_AliasSet[] = { PPC::X2, 0 };
  const unsigned R20_AliasSet[] = { PPC::X20, 0 };
  const unsigned R21_AliasSet[] = { PPC::X21, 0 };
  const unsigned R22_AliasSet[] = { PPC::X22, 0 };
  const unsigned R23_AliasSet[] = { PPC::X23, 0 };
  const unsigned R24_AliasSet[] = { PPC::X24, 0 };
  const unsigned R25_AliasSet[] = { PPC::X25, 0 };
  const unsigned R26_AliasSet[] = { PPC::X26, 0 };
  const unsigned R27_AliasSet[] = { PPC::X27, 0 };
  const unsigned R28_AliasSet[] = { PPC::X28, 0 };
  const unsigned R29_AliasSet[] = { PPC::X29, 0 };
  const unsigned R3_AliasSet[] = { PPC::X3, 0 };
  const unsigned R30_AliasSet[] = { PPC::X30, 0 };
  const unsigned R31_AliasSet[] = { PPC::X31, 0 };
  const unsigned R4_AliasSet[] = { PPC::X4, 0 };
  const unsigned R5_AliasSet[] = { PPC::X5, 0 };
  const unsigned R6_AliasSet[] = { PPC::X6, 0 };
  const unsigned R7_AliasSet[] = { PPC::X7, 0 };
  const unsigned R8_AliasSet[] = { PPC::X8, 0 };
  const unsigned R9_AliasSet[] = { PPC::X9, 0 };
  const unsigned RM_AliasSet[] = { 0 };
  const unsigned V0_AliasSet[] = { 0 };
  const unsigned V1_AliasSet[] = { 0 };
  const unsigned V10_AliasSet[] = { 0 };
  const unsigned V11_AliasSet[] = { 0 };
  const unsigned V12_AliasSet[] = { 0 };
  const unsigned V13_AliasSet[] = { 0 };
  const unsigned V14_AliasSet[] = { 0 };
  const unsigned V15_AliasSet[] = { 0 };
  const unsigned V16_AliasSet[] = { 0 };
  const unsigned V17_AliasSet[] = { 0 };
  const unsigned V18_AliasSet[] = { 0 };
  const unsigned V19_AliasSet[] = { 0 };
  const unsigned V2_AliasSet[] = { 0 };
  const unsigned V20_AliasSet[] = { 0 };
  const unsigned V21_AliasSet[] = { 0 };
  const unsigned V22_AliasSet[] = { 0 };
  const unsigned V23_AliasSet[] = { 0 };
  const unsigned V24_AliasSet[] = { 0 };
  const unsigned V25_AliasSet[] = { 0 };
  const unsigned V26_AliasSet[] = { 0 };
  const unsigned V27_AliasSet[] = { 0 };
  const unsigned V28_AliasSet[] = { 0 };
  const unsigned V29_AliasSet[] = { 0 };
  const unsigned V3_AliasSet[] = { 0 };
  const unsigned V30_AliasSet[] = { 0 };
  const unsigned V31_AliasSet[] = { 0 };
  const unsigned V4_AliasSet[] = { 0 };
  const unsigned V5_AliasSet[] = { 0 };
  const unsigned V6_AliasSet[] = { 0 };
  const unsigned V7_AliasSet[] = { 0 };
  const unsigned V8_AliasSet[] = { 0 };
  const unsigned V9_AliasSet[] = { 0 };
  const unsigned VRSAVE_AliasSet[] = { 0 };
  const unsigned X0_AliasSet[] = { PPC::R0, 0 };
  const unsigned X1_AliasSet[] = { PPC::R1, 0 };
  const unsigned X10_AliasSet[] = { PPC::R10, 0 };
  const unsigned X11_AliasSet[] = { PPC::R11, 0 };
  const unsigned X12_AliasSet[] = { PPC::R12, 0 };
  const unsigned X13_AliasSet[] = { PPC::R13, 0 };
  const unsigned X14_AliasSet[] = { PPC::R14, 0 };
  const unsigned X15_AliasSet[] = { PPC::R15, 0 };
  const unsigned X16_AliasSet[] = { PPC::R16, 0 };
  const unsigned X17_AliasSet[] = { PPC::R17, 0 };
  const unsigned X18_AliasSet[] = { PPC::R18, 0 };
  const unsigned X19_AliasSet[] = { PPC::R19, 0 };
  const unsigned X2_AliasSet[] = { PPC::R2, 0 };
  const unsigned X20_AliasSet[] = { PPC::R20, 0 };
  const unsigned X21_AliasSet[] = { PPC::R21, 0 };
  const unsigned X22_AliasSet[] = { PPC::R22, 0 };
  const unsigned X23_AliasSet[] = { PPC::R23, 0 };
  const unsigned X24_AliasSet[] = { PPC::R24, 0 };
  const unsigned X25_AliasSet[] = { PPC::R25, 0 };
  const unsigned X26_AliasSet[] = { PPC::R26, 0 };
  const unsigned X27_AliasSet[] = { PPC::R27, 0 };
  const unsigned X28_AliasSet[] = { PPC::R28, 0 };
  const unsigned X29_AliasSet[] = { PPC::R29, 0 };
  const unsigned X3_AliasSet[] = { PPC::R3, 0 };
  const unsigned X30_AliasSet[] = { PPC::R30, 0 };
  const unsigned X31_AliasSet[] = { PPC::R31, 0 };
  const unsigned X4_AliasSet[] = { PPC::R4, 0 };
  const unsigned X5_AliasSet[] = { PPC::R5, 0 };
  const unsigned X6_AliasSet[] = { PPC::R6, 0 };
  const unsigned X7_AliasSet[] = { PPC::R7, 0 };
  const unsigned X8_AliasSet[] = { PPC::R8, 0 };
  const unsigned X9_AliasSet[] = { PPC::R9, 0 };


  // Register Sub-registers Sets...
  const unsigned Empty_SubRegsSet[] = { 0 };
  const unsigned CARRY_SubRegsSet[] = { 0 };
  const unsigned CR0_SubRegsSet[] = { PPC::CR0LT, PPC::CR0GT, PPC::CR0EQ, PPC::CR0UN, 0 };
  const unsigned CR0EQ_SubRegsSet[] = { 0 };
  const unsigned CR0GT_SubRegsSet[] = { 0 };
  const unsigned CR0LT_SubRegsSet[] = { 0 };
  const unsigned CR0UN_SubRegsSet[] = { 0 };
  const unsigned CR1_SubRegsSet[] = { PPC::CR1LT, PPC::CR1GT, PPC::CR1EQ, PPC::CR1UN, 0 };
  const unsigned CR1EQ_SubRegsSet[] = { 0 };
  const unsigned CR1GT_SubRegsSet[] = { 0 };
  const unsigned CR1LT_SubRegsSet[] = { 0 };
  const unsigned CR1UN_SubRegsSet[] = { 0 };
  const unsigned CR2_SubRegsSet[] = { PPC::CR2LT, PPC::CR2GT, PPC::CR2EQ, PPC::CR2UN, 0 };
  const unsigned CR2EQ_SubRegsSet[] = { 0 };
  const unsigned CR2GT_SubRegsSet[] = { 0 };
  const unsigned CR2LT_SubRegsSet[] = { 0 };
  const unsigned CR2UN_SubRegsSet[] = { 0 };
  const unsigned CR3_SubRegsSet[] = { PPC::CR3LT, PPC::CR3GT, PPC::CR3EQ, PPC::CR3UN, 0 };
  const unsigned CR3EQ_SubRegsSet[] = { 0 };
  const unsigned CR3GT_SubRegsSet[] = { 0 };
  const unsigned CR3LT_SubRegsSet[] = { 0 };
  const unsigned CR3UN_SubRegsSet[] = { 0 };
  const unsigned CR4_SubRegsSet[] = { PPC::CR4LT, PPC::CR4GT, PPC::CR4EQ, PPC::CR4UN, 0 };
  const unsigned CR4EQ_SubRegsSet[] = { 0 };
  const unsigned CR4GT_SubRegsSet[] = { 0 };
  const unsigned CR4LT_SubRegsSet[] = { 0 };
  const unsigned CR4UN_SubRegsSet[] = { 0 };
  const unsigned CR5_SubRegsSet[] = { PPC::CR5LT, PPC::CR5GT, PPC::CR5EQ, PPC::CR5UN, 0 };
  const unsigned CR5EQ_SubRegsSet[] = { 0 };
  const unsigned CR5GT_SubRegsSet[] = { 0 };
  const unsigned CR5LT_SubRegsSet[] = { 0 };
  const unsigned CR5UN_SubRegsSet[] = { 0 };
  const unsigned CR6_SubRegsSet[] = { PPC::CR6LT, PPC::CR6GT, PPC::CR6EQ, PPC::CR6UN, 0 };
  const unsigned CR6EQ_SubRegsSet[] = { 0 };
  const unsigned CR6GT_SubRegsSet[] = { 0 };
  const unsigned CR6LT_SubRegsSet[] = { 0 };
  const unsigned CR6UN_SubRegsSet[] = { 0 };
  const unsigned CR7_SubRegsSet[] = { PPC::CR7LT, PPC::CR7GT, PPC::CR7EQ, PPC::CR7UN, 0 };
  const unsigned CR7EQ_SubRegsSet[] = { 0 };
  const unsigned CR7GT_SubRegsSet[] = { 0 };
  const unsigned CR7LT_SubRegsSet[] = { 0 };
  const unsigned CR7UN_SubRegsSet[] = { 0 };
  const unsigned CTR_SubRegsSet[] = { 0 };
  const unsigned CTR8_SubRegsSet[] = { 0 };
  const unsigned F0_SubRegsSet[] = { 0 };
  const unsigned F1_SubRegsSet[] = { 0 };
  const unsigned F10_SubRegsSet[] = { 0 };
  const unsigned F11_SubRegsSet[] = { 0 };
  const unsigned F12_SubRegsSet[] = { 0 };
  const unsigned F13_SubRegsSet[] = { 0 };
  const unsigned F14_SubRegsSet[] = { 0 };
  const unsigned F15_SubRegsSet[] = { 0 };
  const unsigned F16_SubRegsSet[] = { 0 };
  const unsigned F17_SubRegsSet[] = { 0 };
  const unsigned F18_SubRegsSet[] = { 0 };
  const unsigned F19_SubRegsSet[] = { 0 };
  const unsigned F2_SubRegsSet[] = { 0 };
  const unsigned F20_SubRegsSet[] = { 0 };
  const unsigned F21_SubRegsSet[] = { 0 };
  const unsigned F22_SubRegsSet[] = { 0 };
  const unsigned F23_SubRegsSet[] = { 0 };
  const unsigned F24_SubRegsSet[] = { 0 };
  const unsigned F25_SubRegsSet[] = { 0 };
  const unsigned F26_SubRegsSet[] = { 0 };
  const unsigned F27_SubRegsSet[] = { 0 };
  const unsigned F28_SubRegsSet[] = { 0 };
  const unsigned F29_SubRegsSet[] = { 0 };
  const unsigned F3_SubRegsSet[] = { 0 };
  const unsigned F30_SubRegsSet[] = { 0 };
  const unsigned F31_SubRegsSet[] = { 0 };
  const unsigned F4_SubRegsSet[] = { 0 };
  const unsigned F5_SubRegsSet[] = { 0 };
  const unsigned F6_SubRegsSet[] = { 0 };
  const unsigned F7_SubRegsSet[] = { 0 };
  const unsigned F8_SubRegsSet[] = { 0 };
  const unsigned F9_SubRegsSet[] = { 0 };
  const unsigned LR_SubRegsSet[] = { 0 };
  const unsigned LR8_SubRegsSet[] = { 0 };
  const unsigned R0_SubRegsSet[] = { 0 };
  const unsigned R1_SubRegsSet[] = { 0 };
  const unsigned R10_SubRegsSet[] = { 0 };
  const unsigned R11_SubRegsSet[] = { 0 };
  const unsigned R12_SubRegsSet[] = { 0 };
  const unsigned R13_SubRegsSet[] = { 0 };
  const unsigned R14_SubRegsSet[] = { 0 };
  const unsigned R15_SubRegsSet[] = { 0 };
  const unsigned R16_SubRegsSet[] = { 0 };
  const unsigned R17_SubRegsSet[] = { 0 };
  const unsigned R18_SubRegsSet[] = { 0 };
  const unsigned R19_SubRegsSet[] = { 0 };
  const unsigned R2_SubRegsSet[] = { 0 };
  const unsigned R20_SubRegsSet[] = { 0 };
  const unsigned R21_SubRegsSet[] = { 0 };
  const unsigned R22_SubRegsSet[] = { 0 };
  const unsigned R23_SubRegsSet[] = { 0 };
  const unsigned R24_SubRegsSet[] = { 0 };
  const unsigned R25_SubRegsSet[] = { 0 };
  const unsigned R26_SubRegsSet[] = { 0 };
  const unsigned R27_SubRegsSet[] = { 0 };
  const unsigned R28_SubRegsSet[] = { 0 };
  const unsigned R29_SubRegsSet[] = { 0 };
  const unsigned R3_SubRegsSet[] = { 0 };
  const unsigned R30_SubRegsSet[] = { 0 };
  const unsigned R31_SubRegsSet[] = { 0 };
  const unsigned R4_SubRegsSet[] = { 0 };
  const unsigned R5_SubRegsSet[] = { 0 };
  const unsigned R6_SubRegsSet[] = { 0 };
  const unsigned R7_SubRegsSet[] = { 0 };
  const unsigned R8_SubRegsSet[] = { 0 };
  const unsigned R9_SubRegsSet[] = { 0 };
  const unsigned RM_SubRegsSet[] = { 0 };
  const unsigned V0_SubRegsSet[] = { 0 };
  const unsigned V1_SubRegsSet[] = { 0 };
  const unsigned V10_SubRegsSet[] = { 0 };
  const unsigned V11_SubRegsSet[] = { 0 };
  const unsigned V12_SubRegsSet[] = { 0 };
  const unsigned V13_SubRegsSet[] = { 0 };
  const unsigned V14_SubRegsSet[] = { 0 };
  const unsigned V15_SubRegsSet[] = { 0 };
  const unsigned V16_SubRegsSet[] = { 0 };
  const unsigned V17_SubRegsSet[] = { 0 };
  const unsigned V18_SubRegsSet[] = { 0 };
  const unsigned V19_SubRegsSet[] = { 0 };
  const unsigned V2_SubRegsSet[] = { 0 };
  const unsigned V20_SubRegsSet[] = { 0 };
  const unsigned V21_SubRegsSet[] = { 0 };
  const unsigned V22_SubRegsSet[] = { 0 };
  const unsigned V23_SubRegsSet[] = { 0 };
  const unsigned V24_SubRegsSet[] = { 0 };
  const unsigned V25_SubRegsSet[] = { 0 };
  const unsigned V26_SubRegsSet[] = { 0 };
  const unsigned V27_SubRegsSet[] = { 0 };
  const unsigned V28_SubRegsSet[] = { 0 };
  const unsigned V29_SubRegsSet[] = { 0 };
  const unsigned V3_SubRegsSet[] = { 0 };
  const unsigned V30_SubRegsSet[] = { 0 };
  const unsigned V31_SubRegsSet[] = { 0 };
  const unsigned V4_SubRegsSet[] = { 0 };
  const unsigned V5_SubRegsSet[] = { 0 };
  const unsigned V6_SubRegsSet[] = { 0 };
  const unsigned V7_SubRegsSet[] = { 0 };
  const unsigned V8_SubRegsSet[] = { 0 };
  const unsigned V9_SubRegsSet[] = { 0 };
  const unsigned VRSAVE_SubRegsSet[] = { 0 };
  const unsigned X0_SubRegsSet[] = { PPC::R0, 0 };
  const unsigned X1_SubRegsSet[] = { PPC::R1, 0 };
  const unsigned X10_SubRegsSet[] = { PPC::R10, 0 };
  const unsigned X11_SubRegsSet[] = { PPC::R11, 0 };
  const unsigned X12_SubRegsSet[] = { PPC::R12, 0 };
  const unsigned X13_SubRegsSet[] = { PPC::R13, 0 };
  const unsigned X14_SubRegsSet[] = { PPC::R14, 0 };
  const unsigned X15_SubRegsSet[] = { PPC::R15, 0 };
  const unsigned X16_SubRegsSet[] = { PPC::R16, 0 };
  const unsigned X17_SubRegsSet[] = { PPC::R17, 0 };
  const unsigned X18_SubRegsSet[] = { PPC::R18, 0 };
  const unsigned X19_SubRegsSet[] = { PPC::R19, 0 };
  const unsigned X2_SubRegsSet[] = { PPC::R2, 0 };
  const unsigned X20_SubRegsSet[] = { PPC::R20, 0 };
  const unsigned X21_SubRegsSet[] = { PPC::R21, 0 };
  const unsigned X22_SubRegsSet[] = { PPC::R22, 0 };
  const unsigned X23_SubRegsSet[] = { PPC::R23, 0 };
  const unsigned X24_SubRegsSet[] = { PPC::R24, 0 };
  const unsigned X25_SubRegsSet[] = { PPC::R25, 0 };
  const unsigned X26_SubRegsSet[] = { PPC::R26, 0 };
  const unsigned X27_SubRegsSet[] = { PPC::R27, 0 };
  const unsigned X28_SubRegsSet[] = { PPC::R28, 0 };
  const unsigned X29_SubRegsSet[] = { PPC::R29, 0 };
  const unsigned X3_SubRegsSet[] = { PPC::R3, 0 };
  const unsigned X30_SubRegsSet[] = { PPC::R30, 0 };
  const unsigned X31_SubRegsSet[] = { PPC::R31, 0 };
  const unsigned X4_SubRegsSet[] = { PPC::R4, 0 };
  const unsigned X5_SubRegsSet[] = { PPC::R5, 0 };
  const unsigned X6_SubRegsSet[] = { PPC::R6, 0 };
  const unsigned X7_SubRegsSet[] = { PPC::R7, 0 };
  const unsigned X8_SubRegsSet[] = { PPC::R8, 0 };
  const unsigned X9_SubRegsSet[] = { PPC::R9, 0 };


  // Register Super-registers Sets...
  const unsigned Empty_SuperRegsSet[] = { 0 };
  const unsigned CARRY_SuperRegsSet[] = { 0 };
  const unsigned CR0_SuperRegsSet[] = { 0 };
  const unsigned CR0EQ_SuperRegsSet[] = { PPC::CR0, 0 };
  const unsigned CR0GT_SuperRegsSet[] = { PPC::CR0, 0 };
  const unsigned CR0LT_SuperRegsSet[] = { PPC::CR0, 0 };
  const unsigned CR0UN_SuperRegsSet[] = { PPC::CR0, 0 };
  const unsigned CR1_SuperRegsSet[] = { 0 };
  const unsigned CR1EQ_SuperRegsSet[] = { PPC::CR1, 0 };
  const unsigned CR1GT_SuperRegsSet[] = { PPC::CR1, 0 };
  const unsigned CR1LT_SuperRegsSet[] = { PPC::CR1, 0 };
  const unsigned CR1UN_SuperRegsSet[] = { PPC::CR1, 0 };
  const unsigned CR2_SuperRegsSet[] = { 0 };
  const unsigned CR2EQ_SuperRegsSet[] = { PPC::CR2, 0 };
  const unsigned CR2GT_SuperRegsSet[] = { PPC::CR2, 0 };
  const unsigned CR2LT_SuperRegsSet[] = { PPC::CR2, 0 };
  const unsigned CR2UN_SuperRegsSet[] = { PPC::CR2, 0 };
  const unsigned CR3_SuperRegsSet[] = { 0 };
  const unsigned CR3EQ_SuperRegsSet[] = { PPC::CR3, 0 };
  const unsigned CR3GT_SuperRegsSet[] = { PPC::CR3, 0 };
  const unsigned CR3LT_SuperRegsSet[] = { PPC::CR3, 0 };
  const unsigned CR3UN_SuperRegsSet[] = { PPC::CR3, 0 };
  const unsigned CR4_SuperRegsSet[] = { 0 };
  const unsigned CR4EQ_SuperRegsSet[] = { PPC::CR4, 0 };
  const unsigned CR4GT_SuperRegsSet[] = { PPC::CR4, 0 };
  const unsigned CR4LT_SuperRegsSet[] = { PPC::CR4, 0 };
  const unsigned CR4UN_SuperRegsSet[] = { PPC::CR4, 0 };
  const unsigned CR5_SuperRegsSet[] = { 0 };
  const unsigned CR5EQ_SuperRegsSet[] = { PPC::CR5, 0 };
  const unsigned CR5GT_SuperRegsSet[] = { PPC::CR5, 0 };
  const unsigned CR5LT_SuperRegsSet[] = { PPC::CR5, 0 };
  const unsigned CR5UN_SuperRegsSet[] = { PPC::CR5, 0 };
  const unsigned CR6_SuperRegsSet[] = { 0 };
  const unsigned CR6EQ_SuperRegsSet[] = { PPC::CR6, 0 };
  const unsigned CR6GT_SuperRegsSet[] = { PPC::CR6, 0 };
  const unsigned CR6LT_SuperRegsSet[] = { PPC::CR6, 0 };
  const unsigned CR6UN_SuperRegsSet[] = { PPC::CR6, 0 };
  const unsigned CR7_SuperRegsSet[] = { 0 };
  const unsigned CR7EQ_SuperRegsSet[] = { PPC::CR7, 0 };
  const unsigned CR7GT_SuperRegsSet[] = { PPC::CR7, 0 };
  const unsigned CR7LT_SuperRegsSet[] = { PPC::CR7, 0 };
  const unsigned CR7UN_SuperRegsSet[] = { PPC::CR7, 0 };
  const unsigned CTR_SuperRegsSet[] = { 0 };
  const unsigned CTR8_SuperRegsSet[] = { 0 };
  const unsigned F0_SuperRegsSet[] = { 0 };
  const unsigned F1_SuperRegsSet[] = { 0 };
  const unsigned F10_SuperRegsSet[] = { 0 };
  const unsigned F11_SuperRegsSet[] = { 0 };
  const unsigned F12_SuperRegsSet[] = { 0 };
  const unsigned F13_SuperRegsSet[] = { 0 };
  const unsigned F14_SuperRegsSet[] = { 0 };
  const unsigned F15_SuperRegsSet[] = { 0 };
  const unsigned F16_SuperRegsSet[] = { 0 };
  const unsigned F17_SuperRegsSet[] = { 0 };
  const unsigned F18_SuperRegsSet[] = { 0 };
  const unsigned F19_SuperRegsSet[] = { 0 };
  const unsigned F2_SuperRegsSet[] = { 0 };
  const unsigned F20_SuperRegsSet[] = { 0 };
  const unsigned F21_SuperRegsSet[] = { 0 };
  const unsigned F22_SuperRegsSet[] = { 0 };
  const unsigned F23_SuperRegsSet[] = { 0 };
  const unsigned F24_SuperRegsSet[] = { 0 };
  const unsigned F25_SuperRegsSet[] = { 0 };
  const unsigned F26_SuperRegsSet[] = { 0 };
  const unsigned F27_SuperRegsSet[] = { 0 };
  const unsigned F28_SuperRegsSet[] = { 0 };
  const unsigned F29_SuperRegsSet[] = { 0 };
  const unsigned F3_SuperRegsSet[] = { 0 };
  const unsigned F30_SuperRegsSet[] = { 0 };
  const unsigned F31_SuperRegsSet[] = { 0 };
  const unsigned F4_SuperRegsSet[] = { 0 };
  const unsigned F5_SuperRegsSet[] = { 0 };
  const unsigned F6_SuperRegsSet[] = { 0 };
  const unsigned F7_SuperRegsSet[] = { 0 };
  const unsigned F8_SuperRegsSet[] = { 0 };
  const unsigned F9_SuperRegsSet[] = { 0 };
  const unsigned LR_SuperRegsSet[] = { 0 };
  const unsigned LR8_SuperRegsSet[] = { 0 };
  const unsigned R0_SuperRegsSet[] = { PPC::X0, 0 };
  const unsigned R1_SuperRegsSet[] = { PPC::X1, 0 };
  const unsigned R10_SuperRegsSet[] = { PPC::X10, 0 };
  const unsigned R11_SuperRegsSet[] = { PPC::X11, 0 };
  const unsigned R12_SuperRegsSet[] = { PPC::X12, 0 };
  const unsigned R13_SuperRegsSet[] = { PPC::X13, 0 };
  const unsigned R14_SuperRegsSet[] = { PPC::X14, 0 };
  const unsigned R15_SuperRegsSet[] = { PPC::X15, 0 };
  const unsigned R16_SuperRegsSet[] = { PPC::X16, 0 };
  const unsigned R17_SuperRegsSet[] = { PPC::X17, 0 };
  const unsigned R18_SuperRegsSet[] = { PPC::X18, 0 };
  const unsigned R19_SuperRegsSet[] = { PPC::X19, 0 };
  const unsigned R2_SuperRegsSet[] = { PPC::X2, 0 };
  const unsigned R20_SuperRegsSet[] = { PPC::X20, 0 };
  const unsigned R21_SuperRegsSet[] = { PPC::X21, 0 };
  const unsigned R22_SuperRegsSet[] = { PPC::X22, 0 };
  const unsigned R23_SuperRegsSet[] = { PPC::X23, 0 };
  const unsigned R24_SuperRegsSet[] = { PPC::X24, 0 };
  const unsigned R25_SuperRegsSet[] = { PPC::X25, 0 };
  const unsigned R26_SuperRegsSet[] = { PPC::X26, 0 };
  const unsigned R27_SuperRegsSet[] = { PPC::X27, 0 };
  const unsigned R28_SuperRegsSet[] = { PPC::X28, 0 };
  const unsigned R29_SuperRegsSet[] = { PPC::X29, 0 };
  const unsigned R3_SuperRegsSet[] = { PPC::X3, 0 };
  const unsigned R30_SuperRegsSet[] = { PPC::X30, 0 };
  const unsigned R31_SuperRegsSet[] = { PPC::X31, 0 };
  const unsigned R4_SuperRegsSet[] = { PPC::X4, 0 };
  const unsigned R5_SuperRegsSet[] = { PPC::X5, 0 };
  const unsigned R6_SuperRegsSet[] = { PPC::X6, 0 };
  const unsigned R7_SuperRegsSet[] = { PPC::X7, 0 };
  const unsigned R8_SuperRegsSet[] = { PPC::X8, 0 };
  const unsigned R9_SuperRegsSet[] = { PPC::X9, 0 };
  const unsigned RM_SuperRegsSet[] = { 0 };
  const unsigned V0_SuperRegsSet[] = { 0 };
  const unsigned V1_SuperRegsSet[] = { 0 };
  const unsigned V10_SuperRegsSet[] = { 0 };
  const unsigned V11_SuperRegsSet[] = { 0 };
  const unsigned V12_SuperRegsSet[] = { 0 };
  const unsigned V13_SuperRegsSet[] = { 0 };
  const unsigned V14_SuperRegsSet[] = { 0 };
  const unsigned V15_SuperRegsSet[] = { 0 };
  const unsigned V16_SuperRegsSet[] = { 0 };
  const unsigned V17_SuperRegsSet[] = { 0 };
  const unsigned V18_SuperRegsSet[] = { 0 };
  const unsigned V19_SuperRegsSet[] = { 0 };
  const unsigned V2_SuperRegsSet[] = { 0 };
  const unsigned V20_SuperRegsSet[] = { 0 };
  const unsigned V21_SuperRegsSet[] = { 0 };
  const unsigned V22_SuperRegsSet[] = { 0 };
  const unsigned V23_SuperRegsSet[] = { 0 };
  const unsigned V24_SuperRegsSet[] = { 0 };
  const unsigned V25_SuperRegsSet[] = { 0 };
  const unsigned V26_SuperRegsSet[] = { 0 };
  const unsigned V27_SuperRegsSet[] = { 0 };
  const unsigned V28_SuperRegsSet[] = { 0 };
  const unsigned V29_SuperRegsSet[] = { 0 };
  const unsigned V3_SuperRegsSet[] = { 0 };
  const unsigned V30_SuperRegsSet[] = { 0 };
  const unsigned V31_SuperRegsSet[] = { 0 };
  const unsigned V4_SuperRegsSet[] = { 0 };
  const unsigned V5_SuperRegsSet[] = { 0 };
  const unsigned V6_SuperRegsSet[] = { 0 };
  const unsigned V7_SuperRegsSet[] = { 0 };
  const unsigned V8_SuperRegsSet[] = { 0 };
  const unsigned V9_SuperRegsSet[] = { 0 };
  const unsigned VRSAVE_SuperRegsSet[] = { 0 };
  const unsigned X0_SuperRegsSet[] = { 0 };
  const unsigned X1_SuperRegsSet[] = { 0 };
  const unsigned X10_SuperRegsSet[] = { 0 };
  const unsigned X11_SuperRegsSet[] = { 0 };
  const unsigned X12_SuperRegsSet[] = { 0 };
  const unsigned X13_SuperRegsSet[] = { 0 };
  const unsigned X14_SuperRegsSet[] = { 0 };
  const unsigned X15_SuperRegsSet[] = { 0 };
  const unsigned X16_SuperRegsSet[] = { 0 };
  const unsigned X17_SuperRegsSet[] = { 0 };
  const unsigned X18_SuperRegsSet[] = { 0 };
  const unsigned X19_SuperRegsSet[] = { 0 };
  const unsigned X2_SuperRegsSet[] = { 0 };
  const unsigned X20_SuperRegsSet[] = { 0 };
  const unsigned X21_SuperRegsSet[] = { 0 };
  const unsigned X22_SuperRegsSet[] = { 0 };
  const unsigned X23_SuperRegsSet[] = { 0 };
  const unsigned X24_SuperRegsSet[] = { 0 };
  const unsigned X25_SuperRegsSet[] = { 0 };
  const unsigned X26_SuperRegsSet[] = { 0 };
  const unsigned X27_SuperRegsSet[] = { 0 };
  const unsigned X28_SuperRegsSet[] = { 0 };
  const unsigned X29_SuperRegsSet[] = { 0 };
  const unsigned X3_SuperRegsSet[] = { 0 };
  const unsigned X30_SuperRegsSet[] = { 0 };
  const unsigned X31_SuperRegsSet[] = { 0 };
  const unsigned X4_SuperRegsSet[] = { 0 };
  const unsigned X5_SuperRegsSet[] = { 0 };
  const unsigned X6_SuperRegsSet[] = { 0 };
  const unsigned X7_SuperRegsSet[] = { 0 };
  const unsigned X8_SuperRegsSet[] = { 0 };
  const unsigned X9_SuperRegsSet[] = { 0 };

  const TargetRegisterDesc RegisterDescriptors[] = { // Descriptors
    { "NOREG",	0,	0,	0 },
    { "CARRY",	CARRY_AliasSet,	CARRY_SubRegsSet,	CARRY_SuperRegsSet },
    { "CR0",	CR0_AliasSet,	CR0_SubRegsSet,	CR0_SuperRegsSet },
    { "CR0EQ",	CR0EQ_AliasSet,	CR0EQ_SubRegsSet,	CR0EQ_SuperRegsSet },
    { "CR0GT",	CR0GT_AliasSet,	CR0GT_SubRegsSet,	CR0GT_SuperRegsSet },
    { "CR0LT",	CR0LT_AliasSet,	CR0LT_SubRegsSet,	CR0LT_SuperRegsSet },
    { "CR0UN",	CR0UN_AliasSet,	CR0UN_SubRegsSet,	CR0UN_SuperRegsSet },
    { "CR1",	CR1_AliasSet,	CR1_SubRegsSet,	CR1_SuperRegsSet },
    { "CR1EQ",	CR1EQ_AliasSet,	CR1EQ_SubRegsSet,	CR1EQ_SuperRegsSet },
    { "CR1GT",	CR1GT_AliasSet,	CR1GT_SubRegsSet,	CR1GT_SuperRegsSet },
    { "CR1LT",	CR1LT_AliasSet,	CR1LT_SubRegsSet,	CR1LT_SuperRegsSet },
    { "CR1UN",	CR1UN_AliasSet,	CR1UN_SubRegsSet,	CR1UN_SuperRegsSet },
    { "CR2",	CR2_AliasSet,	CR2_SubRegsSet,	CR2_SuperRegsSet },
    { "CR2EQ",	CR2EQ_AliasSet,	CR2EQ_SubRegsSet,	CR2EQ_SuperRegsSet },
    { "CR2GT",	CR2GT_AliasSet,	CR2GT_SubRegsSet,	CR2GT_SuperRegsSet },
    { "CR2LT",	CR2LT_AliasSet,	CR2LT_SubRegsSet,	CR2LT_SuperRegsSet },
    { "CR2UN",	CR2UN_AliasSet,	CR2UN_SubRegsSet,	CR2UN_SuperRegsSet },
    { "CR3",	CR3_AliasSet,	CR3_SubRegsSet,	CR3_SuperRegsSet },
    { "CR3EQ",	CR3EQ_AliasSet,	CR3EQ_SubRegsSet,	CR3EQ_SuperRegsSet },
    { "CR3GT",	CR3GT_AliasSet,	CR3GT_SubRegsSet,	CR3GT_SuperRegsSet },
    { "CR3LT",	CR3LT_AliasSet,	CR3LT_SubRegsSet,	CR3LT_SuperRegsSet },
    { "CR3UN",	CR3UN_AliasSet,	CR3UN_SubRegsSet,	CR3UN_SuperRegsSet },
    { "CR4",	CR4_AliasSet,	CR4_SubRegsSet,	CR4_SuperRegsSet },
    { "CR4EQ",	CR4EQ_AliasSet,	CR4EQ_SubRegsSet,	CR4EQ_SuperRegsSet },
    { "CR4GT",	CR4GT_AliasSet,	CR4GT_SubRegsSet,	CR4GT_SuperRegsSet },
    { "CR4LT",	CR4LT_AliasSet,	CR4LT_SubRegsSet,	CR4LT_SuperRegsSet },
    { "CR4UN",	CR4UN_AliasSet,	CR4UN_SubRegsSet,	CR4UN_SuperRegsSet },
    { "CR5",	CR5_AliasSet,	CR5_SubRegsSet,	CR5_SuperRegsSet },
    { "CR5EQ",	CR5EQ_AliasSet,	CR5EQ_SubRegsSet,	CR5EQ_SuperRegsSet },
    { "CR5GT",	CR5GT_AliasSet,	CR5GT_SubRegsSet,	CR5GT_SuperRegsSet },
    { "CR5LT",	CR5LT_AliasSet,	CR5LT_SubRegsSet,	CR5LT_SuperRegsSet },
    { "CR5UN",	CR5UN_AliasSet,	CR5UN_SubRegsSet,	CR5UN_SuperRegsSet },
    { "CR6",	CR6_AliasSet,	CR6_SubRegsSet,	CR6_SuperRegsSet },
    { "CR6EQ",	CR6EQ_AliasSet,	CR6EQ_SubRegsSet,	CR6EQ_SuperRegsSet },
    { "CR6GT",	CR6GT_AliasSet,	CR6GT_SubRegsSet,	CR6GT_SuperRegsSet },
    { "CR6LT",	CR6LT_AliasSet,	CR6LT_SubRegsSet,	CR6LT_SuperRegsSet },
    { "CR6UN",	CR6UN_AliasSet,	CR6UN_SubRegsSet,	CR6UN_SuperRegsSet },
    { "CR7",	CR7_AliasSet,	CR7_SubRegsSet,	CR7_SuperRegsSet },
    { "CR7EQ",	CR7EQ_AliasSet,	CR7EQ_SubRegsSet,	CR7EQ_SuperRegsSet },
    { "CR7GT",	CR7GT_AliasSet,	CR7GT_SubRegsSet,	CR7GT_SuperRegsSet },
    { "CR7LT",	CR7LT_AliasSet,	CR7LT_SubRegsSet,	CR7LT_SuperRegsSet },
    { "CR7UN",	CR7UN_AliasSet,	CR7UN_SubRegsSet,	CR7UN_SuperRegsSet },
    { "CTR",	CTR_AliasSet,	CTR_SubRegsSet,	CTR_SuperRegsSet },
    { "CTR8",	CTR8_AliasSet,	CTR8_SubRegsSet,	CTR8_SuperRegsSet },
    { "F0",	F0_AliasSet,	F0_SubRegsSet,	F0_SuperRegsSet },
    { "F1",	F1_AliasSet,	F1_SubRegsSet,	F1_SuperRegsSet },
    { "F10",	F10_AliasSet,	F10_SubRegsSet,	F10_SuperRegsSet },
    { "F11",	F11_AliasSet,	F11_SubRegsSet,	F11_SuperRegsSet },
    { "F12",	F12_AliasSet,	F12_SubRegsSet,	F12_SuperRegsSet },
    { "F13",	F13_AliasSet,	F13_SubRegsSet,	F13_SuperRegsSet },
    { "F14",	F14_AliasSet,	F14_SubRegsSet,	F14_SuperRegsSet },
    { "F15",	F15_AliasSet,	F15_SubRegsSet,	F15_SuperRegsSet },
    { "F16",	F16_AliasSet,	F16_SubRegsSet,	F16_SuperRegsSet },
    { "F17",	F17_AliasSet,	F17_SubRegsSet,	F17_SuperRegsSet },
    { "F18",	F18_AliasSet,	F18_SubRegsSet,	F18_SuperRegsSet },
    { "F19",	F19_AliasSet,	F19_SubRegsSet,	F19_SuperRegsSet },
    { "F2",	F2_AliasSet,	F2_SubRegsSet,	F2_SuperRegsSet },
    { "F20",	F20_AliasSet,	F20_SubRegsSet,	F20_SuperRegsSet },
    { "F21",	F21_AliasSet,	F21_SubRegsSet,	F21_SuperRegsSet },
    { "F22",	F22_AliasSet,	F22_SubRegsSet,	F22_SuperRegsSet },
    { "F23",	F23_AliasSet,	F23_SubRegsSet,	F23_SuperRegsSet },
    { "F24",	F24_AliasSet,	F24_SubRegsSet,	F24_SuperRegsSet },
    { "F25",	F25_AliasSet,	F25_SubRegsSet,	F25_SuperRegsSet },
    { "F26",	F26_AliasSet,	F26_SubRegsSet,	F26_SuperRegsSet },
    { "F27",	F27_AliasSet,	F27_SubRegsSet,	F27_SuperRegsSet },
    { "F28",	F28_AliasSet,	F28_SubRegsSet,	F28_SuperRegsSet },
    { "F29",	F29_AliasSet,	F29_SubRegsSet,	F29_SuperRegsSet },
    { "F3",	F3_AliasSet,	F3_SubRegsSet,	F3_SuperRegsSet },
    { "F30",	F30_AliasSet,	F30_SubRegsSet,	F30_SuperRegsSet },
    { "F31",	F31_AliasSet,	F31_SubRegsSet,	F31_SuperRegsSet },
    { "F4",	F4_AliasSet,	F4_SubRegsSet,	F4_SuperRegsSet },
    { "F5",	F5_AliasSet,	F5_SubRegsSet,	F5_SuperRegsSet },
    { "F6",	F6_AliasSet,	F6_SubRegsSet,	F6_SuperRegsSet },
    { "F7",	F7_AliasSet,	F7_SubRegsSet,	F7_SuperRegsSet },
    { "F8",	F8_AliasSet,	F8_SubRegsSet,	F8_SuperRegsSet },
    { "F9",	F9_AliasSet,	F9_SubRegsSet,	F9_SuperRegsSet },
    { "LR",	LR_AliasSet,	LR_SubRegsSet,	LR_SuperRegsSet },
    { "LR8",	LR8_AliasSet,	LR8_SubRegsSet,	LR8_SuperRegsSet },
    { "R0",	R0_AliasSet,	R0_SubRegsSet,	R0_SuperRegsSet },
    { "R1",	R1_AliasSet,	R1_SubRegsSet,	R1_SuperRegsSet },
    { "R10",	R10_AliasSet,	R10_SubRegsSet,	R10_SuperRegsSet },
    { "R11",	R11_AliasSet,	R11_SubRegsSet,	R11_SuperRegsSet },
    { "R12",	R12_AliasSet,	R12_SubRegsSet,	R12_SuperRegsSet },
    { "R13",	R13_AliasSet,	R13_SubRegsSet,	R13_SuperRegsSet },
    { "R14",	R14_AliasSet,	R14_SubRegsSet,	R14_SuperRegsSet },
    { "R15",	R15_AliasSet,	R15_SubRegsSet,	R15_SuperRegsSet },
    { "R16",	R16_AliasSet,	R16_SubRegsSet,	R16_SuperRegsSet },
    { "R17",	R17_AliasSet,	R17_SubRegsSet,	R17_SuperRegsSet },
    { "R18",	R18_AliasSet,	R18_SubRegsSet,	R18_SuperRegsSet },
    { "R19",	R19_AliasSet,	R19_SubRegsSet,	R19_SuperRegsSet },
    { "R2",	R2_AliasSet,	R2_SubRegsSet,	R2_SuperRegsSet },
    { "R20",	R20_AliasSet,	R20_SubRegsSet,	R20_SuperRegsSet },
    { "R21",	R21_AliasSet,	R21_SubRegsSet,	R21_SuperRegsSet },
    { "R22",	R22_AliasSet,	R22_SubRegsSet,	R22_SuperRegsSet },
    { "R23",	R23_AliasSet,	R23_SubRegsSet,	R23_SuperRegsSet },
    { "R24",	R24_AliasSet,	R24_SubRegsSet,	R24_SuperRegsSet },
    { "R25",	R25_AliasSet,	R25_SubRegsSet,	R25_SuperRegsSet },
    { "R26",	R26_AliasSet,	R26_SubRegsSet,	R26_SuperRegsSet },
    { "R27",	R27_AliasSet,	R27_SubRegsSet,	R27_SuperRegsSet },
    { "R28",	R28_AliasSet,	R28_SubRegsSet,	R28_SuperRegsSet },
    { "R29",	R29_AliasSet,	R29_SubRegsSet,	R29_SuperRegsSet },
    { "R3",	R3_AliasSet,	R3_SubRegsSet,	R3_SuperRegsSet },
    { "R30",	R30_AliasSet,	R30_SubRegsSet,	R30_SuperRegsSet },
    { "R31",	R31_AliasSet,	R31_SubRegsSet,	R31_SuperRegsSet },
    { "R4",	R4_AliasSet,	R4_SubRegsSet,	R4_SuperRegsSet },
    { "R5",	R5_AliasSet,	R5_SubRegsSet,	R5_SuperRegsSet },
    { "R6",	R6_AliasSet,	R6_SubRegsSet,	R6_SuperRegsSet },
    { "R7",	R7_AliasSet,	R7_SubRegsSet,	R7_SuperRegsSet },
    { "R8",	R8_AliasSet,	R8_SubRegsSet,	R8_SuperRegsSet },
    { "R9",	R9_AliasSet,	R9_SubRegsSet,	R9_SuperRegsSet },
    { "RM",	RM_AliasSet,	RM_SubRegsSet,	RM_SuperRegsSet },
    { "V0",	V0_AliasSet,	V0_SubRegsSet,	V0_SuperRegsSet },
    { "V1",	V1_AliasSet,	V1_SubRegsSet,	V1_SuperRegsSet },
    { "V10",	V10_AliasSet,	V10_SubRegsSet,	V10_SuperRegsSet },
    { "V11",	V11_AliasSet,	V11_SubRegsSet,	V11_SuperRegsSet },
    { "V12",	V12_AliasSet,	V12_SubRegsSet,	V12_SuperRegsSet },
    { "V13",	V13_AliasSet,	V13_SubRegsSet,	V13_SuperRegsSet },
    { "V14",	V14_AliasSet,	V14_SubRegsSet,	V14_SuperRegsSet },
    { "V15",	V15_AliasSet,	V15_SubRegsSet,	V15_SuperRegsSet },
    { "V16",	V16_AliasSet,	V16_SubRegsSet,	V16_SuperRegsSet },
    { "V17",	V17_AliasSet,	V17_SubRegsSet,	V17_SuperRegsSet },
    { "V18",	V18_AliasSet,	V18_SubRegsSet,	V18_SuperRegsSet },
    { "V19",	V19_AliasSet,	V19_SubRegsSet,	V19_SuperRegsSet },
    { "V2",	V2_AliasSet,	V2_SubRegsSet,	V2_SuperRegsSet },
    { "V20",	V20_AliasSet,	V20_SubRegsSet,	V20_SuperRegsSet },
    { "V21",	V21_AliasSet,	V21_SubRegsSet,	V21_SuperRegsSet },
    { "V22",	V22_AliasSet,	V22_SubRegsSet,	V22_SuperRegsSet },
    { "V23",	V23_AliasSet,	V23_SubRegsSet,	V23_SuperRegsSet },
    { "V24",	V24_AliasSet,	V24_SubRegsSet,	V24_SuperRegsSet },
    { "V25",	V25_AliasSet,	V25_SubRegsSet,	V25_SuperRegsSet },
    { "V26",	V26_AliasSet,	V26_SubRegsSet,	V26_SuperRegsSet },
    { "V27",	V27_AliasSet,	V27_SubRegsSet,	V27_SuperRegsSet },
    { "V28",	V28_AliasSet,	V28_SubRegsSet,	V28_SuperRegsSet },
    { "V29",	V29_AliasSet,	V29_SubRegsSet,	V29_SuperRegsSet },
    { "V3",	V3_AliasSet,	V3_SubRegsSet,	V3_SuperRegsSet },
    { "V30",	V30_AliasSet,	V30_SubRegsSet,	V30_SuperRegsSet },
    { "V31",	V31_AliasSet,	V31_SubRegsSet,	V31_SuperRegsSet },
    { "V4",	V4_AliasSet,	V4_SubRegsSet,	V4_SuperRegsSet },
    { "V5",	V5_AliasSet,	V5_SubRegsSet,	V5_SuperRegsSet },
    { "V6",	V6_AliasSet,	V6_SubRegsSet,	V6_SuperRegsSet },
    { "V7",	V7_AliasSet,	V7_SubRegsSet,	V7_SuperRegsSet },
    { "V8",	V8_AliasSet,	V8_SubRegsSet,	V8_SuperRegsSet },
    { "V9",	V9_AliasSet,	V9_SubRegsSet,	V9_SuperRegsSet },
    { "VRSAVE",	VRSAVE_AliasSet,	VRSAVE_SubRegsSet,	VRSAVE_SuperRegsSet },
    { "X0",	X0_AliasSet,	X0_SubRegsSet,	X0_SuperRegsSet },
    { "X1",	X1_AliasSet,	X1_SubRegsSet,	X1_SuperRegsSet },
    { "X10",	X10_AliasSet,	X10_SubRegsSet,	X10_SuperRegsSet },
    { "X11",	X11_AliasSet,	X11_SubRegsSet,	X11_SuperRegsSet },
    { "X12",	X12_AliasSet,	X12_SubRegsSet,	X12_SuperRegsSet },
    { "X13",	X13_AliasSet,	X13_SubRegsSet,	X13_SuperRegsSet },
    { "X14",	X14_AliasSet,	X14_SubRegsSet,	X14_SuperRegsSet },
    { "X15",	X15_AliasSet,	X15_SubRegsSet,	X15_SuperRegsSet },
    { "X16",	X16_AliasSet,	X16_SubRegsSet,	X16_SuperRegsSet },
    { "X17",	X17_AliasSet,	X17_SubRegsSet,	X17_SuperRegsSet },
    { "X18",	X18_AliasSet,	X18_SubRegsSet,	X18_SuperRegsSet },
    { "X19",	X19_AliasSet,	X19_SubRegsSet,	X19_SuperRegsSet },
    { "X2",	X2_AliasSet,	X2_SubRegsSet,	X2_SuperRegsSet },
    { "X20",	X20_AliasSet,	X20_SubRegsSet,	X20_SuperRegsSet },
    { "X21",	X21_AliasSet,	X21_SubRegsSet,	X21_SuperRegsSet },
    { "X22",	X22_AliasSet,	X22_SubRegsSet,	X22_SuperRegsSet },
    { "X23",	X23_AliasSet,	X23_SubRegsSet,	X23_SuperRegsSet },
    { "X24",	X24_AliasSet,	X24_SubRegsSet,	X24_SuperRegsSet },
    { "X25",	X25_AliasSet,	X25_SubRegsSet,	X25_SuperRegsSet },
    { "X26",	X26_AliasSet,	X26_SubRegsSet,	X26_SuperRegsSet },
    { "X27",	X27_AliasSet,	X27_SubRegsSet,	X27_SuperRegsSet },
    { "X28",	X28_AliasSet,	X28_SubRegsSet,	X28_SuperRegsSet },
    { "X29",	X29_AliasSet,	X29_SubRegsSet,	X29_SuperRegsSet },
    { "X3",	X3_AliasSet,	X3_SubRegsSet,	X3_SuperRegsSet },
    { "X30",	X30_AliasSet,	X30_SubRegsSet,	X30_SuperRegsSet },
    { "X31",	X31_AliasSet,	X31_SubRegsSet,	X31_SuperRegsSet },
    { "X4",	X4_AliasSet,	X4_SubRegsSet,	X4_SuperRegsSet },
    { "X5",	X5_AliasSet,	X5_SubRegsSet,	X5_SuperRegsSet },
    { "X6",	X6_AliasSet,	X6_SubRegsSet,	X6_SuperRegsSet },
    { "X7",	X7_AliasSet,	X7_SubRegsSet,	X7_SuperRegsSet },
    { "X8",	X8_AliasSet,	X8_SubRegsSet,	X8_SuperRegsSet },
    { "X9",	X9_AliasSet,	X9_SubRegsSet,	X9_SuperRegsSet },
  };
}

unsigned PPCGenRegisterInfo::getSubReg(unsigned RegNo, unsigned Index) const {
  switch (RegNo) {
  default:
    return 0;
  case PPC::CR0:
    switch (Index) {
    default: return 0;
    case 1: return PPC::CR0LT;
    case 2: return PPC::CR0GT;
    case 3: return PPC::CR0EQ;
    case 4: return PPC::CR0UN;
    };
    break;
  case PPC::CR1:
    switch (Index) {
    default: return 0;
    case 1: return PPC::CR1LT;
    case 2: return PPC::CR1GT;
    case 3: return PPC::CR1EQ;
    case 4: return PPC::CR1UN;
    };
    break;
  case PPC::CR2:
    switch (Index) {
    default: return 0;
    case 1: return PPC::CR2LT;
    case 2: return PPC::CR2GT;
    case 3: return PPC::CR2EQ;
    case 4: return PPC::CR2UN;
    };
    break;
  case PPC::CR3:
    switch (Index) {
    default: return 0;
    case 1: return PPC::CR3LT;
    case 2: return PPC::CR3GT;
    case 3: return PPC::CR3EQ;
    case 4: return PPC::CR3UN;
    };
    break;
  case PPC::CR4:
    switch (Index) {
    default: return 0;
    case 1: return PPC::CR4LT;
    case 2: return PPC::CR4GT;
    case 3: return PPC::CR4EQ;
    case 4: return PPC::CR4UN;
    };
    break;
  case PPC::CR5:
    switch (Index) {
    default: return 0;
    case 1: return PPC::CR5LT;
    case 2: return PPC::CR5GT;
    case 3: return PPC::CR5EQ;
    case 4: return PPC::CR5UN;
    };
    break;
  case PPC::CR6:
    switch (Index) {
    default: return 0;
    case 1: return PPC::CR6LT;
    case 2: return PPC::CR6GT;
    case 3: return PPC::CR6EQ;
    case 4: return PPC::CR6UN;
    };
    break;
  case PPC::CR7:
    switch (Index) {
    default: return 0;
    case 1: return PPC::CR7LT;
    case 2: return PPC::CR7GT;
    case 3: return PPC::CR7EQ;
    case 4: return PPC::CR7UN;
    };
    break;
  };
  return 0;
}

unsigned PPCGenRegisterInfo::getSubRegIndex(unsigned RegNo, unsigned SubRegNo) const {
  switch (RegNo) {
  default:
    return 0;
  case PPC::CR0:
    if (SubRegNo == PPC::CR0LT)  return 1;
    if (SubRegNo == PPC::CR0GT)  return 2;
    if (SubRegNo == PPC::CR0EQ)  return 3;
    if (SubRegNo == PPC::CR0UN)  return 4;
    return 0;
  case PPC::CR1:
    if (SubRegNo == PPC::CR1LT)  return 1;
    if (SubRegNo == PPC::CR1GT)  return 2;
    if (SubRegNo == PPC::CR1EQ)  return 3;
    if (SubRegNo == PPC::CR1UN)  return 4;
    return 0;
  case PPC::CR2:
    if (SubRegNo == PPC::CR2LT)  return 1;
    if (SubRegNo == PPC::CR2GT)  return 2;
    if (SubRegNo == PPC::CR2EQ)  return 3;
    if (SubRegNo == PPC::CR2UN)  return 4;
    return 0;
  case PPC::CR3:
    if (SubRegNo == PPC::CR3LT)  return 1;
    if (SubRegNo == PPC::CR3GT)  return 2;
    if (SubRegNo == PPC::CR3EQ)  return 3;
    if (SubRegNo == PPC::CR3UN)  return 4;
    return 0;
  case PPC::CR4:
    if (SubRegNo == PPC::CR4LT)  return 1;
    if (SubRegNo == PPC::CR4GT)  return 2;
    if (SubRegNo == PPC::CR4EQ)  return 3;
    if (SubRegNo == PPC::CR4UN)  return 4;
    return 0;
  case PPC::CR5:
    if (SubRegNo == PPC::CR5LT)  return 1;
    if (SubRegNo == PPC::CR5GT)  return 2;
    if (SubRegNo == PPC::CR5EQ)  return 3;
    if (SubRegNo == PPC::CR5UN)  return 4;
    return 0;
  case PPC::CR6:
    if (SubRegNo == PPC::CR6LT)  return 1;
    if (SubRegNo == PPC::CR6GT)  return 2;
    if (SubRegNo == PPC::CR6EQ)  return 3;
    if (SubRegNo == PPC::CR6UN)  return 4;
    return 0;
  case PPC::CR7:
    if (SubRegNo == PPC::CR7LT)  return 1;
    if (SubRegNo == PPC::CR7GT)  return 2;
    if (SubRegNo == PPC::CR7EQ)  return 3;
    if (SubRegNo == PPC::CR7UN)  return 4;
    return 0;
  };
  return 0;
}

PPCGenRegisterInfo::PPCGenRegisterInfo(int CallFrameSetupOpcode, int CallFrameDestroyOpcode)
  : TargetRegisterInfo(RegisterDescriptors, 176, RegisterClasses, RegisterClasses+11,
                  CallFrameSetupOpcode, CallFrameDestroyOpcode,
                 SubregHashTable, SubregHashTableSize,
                 SuperregHashTable, SuperregHashTableSize,
                 AliasesHashTable, AliasesHashTableSize) {
}

int PPCGenRegisterInfo::getDwarfRegNumFull(unsigned RegNum, unsigned Flavour) const {
  switch (Flavour) {
  default:
    assert(0 && "Unknown DWARF flavour");
    return -1;
  case 0:
    switch (RegNum) {
    default:
      assert(0 && "Invalid RegNum");
      return -1;
    case PPC::CARRY:
      return 0;
    case PPC::CR0:
      return 68;
    case PPC::CR0EQ:
      return 0;
    case PPC::CR0GT:
      return 0;
    case PPC::CR0LT:
      return 0;
    case PPC::CR0UN:
      return 0;
    case PPC::CR1:
      return 69;
    case PPC::CR1EQ:
      return 0;
    case PPC::CR1GT:
      return 0;
    case PPC::CR1LT:
      return 0;
    case PPC::CR1UN:
      return 0;
    case PPC::CR2:
      return 70;
    case PPC::CR2EQ:
      return 0;
    case PPC::CR2GT:
      return 0;
    case PPC::CR2LT:
      return 0;
    case PPC::CR2UN:
      return 0;
    case PPC::CR3:
      return 71;
    case PPC::CR3EQ:
      return 0;
    case PPC::CR3GT:
      return 0;
    case PPC::CR3LT:
      return 0;
    case PPC::CR3UN:
      return 0;
    case PPC::CR4:
      return 72;
    case PPC::CR4EQ:
      return 0;
    case PPC::CR4GT:
      return 0;
    case PPC::CR4LT:
      return 0;
    case PPC::CR4UN:
      return 0;
    case PPC::CR5:
      return 73;
    case PPC::CR5EQ:
      return 0;
    case PPC::CR5GT:
      return 0;
    case PPC::CR5LT:
      return 0;
    case PPC::CR5UN:
      return 0;
    case PPC::CR6:
      return 74;
    case PPC::CR6EQ:
      return 0;
    case PPC::CR6GT:
      return 0;
    case PPC::CR6LT:
      return 0;
    case PPC::CR6UN:
      return 0;
    case PPC::CR7:
      return 75;
    case PPC::CR7EQ:
      return 0;
    case PPC::CR7GT:
      return 0;
    case PPC::CR7LT:
      return 0;
    case PPC::CR7UN:
      return 0;
    case PPC::CTR:
      return 66;
    case PPC::CTR8:
      return 66;
    case PPC::F0:
      return 32;
    case PPC::F1:
      return 33;
    case PPC::F10:
      return 42;
    case PPC::F11:
      return 43;
    case PPC::F12:
      return 44;
    case PPC::F13:
      return 45;
    case PPC::F14:
      return 46;
    case PPC::F15:
      return 47;
    case PPC::F16:
      return 48;
    case PPC::F17:
      return 49;
    case PPC::F18:
      return 50;
    case PPC::F19:
      return 51;
    case PPC::F2:
      return 34;
    case PPC::F20:
      return 52;
    case PPC::F21:
      return 53;
    case PPC::F22:
      return 54;
    case PPC::F23:
      return 55;
    case PPC::F24:
      return 56;
    case PPC::F25:
      return 57;
    case PPC::F26:
      return 58;
    case PPC::F27:
      return 59;
    case PPC::F28:
      return 60;
    case PPC::F29:
      return 61;
    case PPC::F3:
      return 35;
    case PPC::F30:
      return 62;
    case PPC::F31:
      return 63;
    case PPC::F4:
      return 36;
    case PPC::F5:
      return 37;
    case PPC::F6:
      return 38;
    case PPC::F7:
      return 39;
    case PPC::F8:
      return 40;
    case PPC::F9:
      return 41;
    case PPC::LR:
      return 65;
    case PPC::LR8:
      return 65;
    case PPC::R0:
      return 0;
    case PPC::R1:
      return 1;
    case PPC::R10:
      return 10;
    case PPC::R11:
      return 11;
    case PPC::R12:
      return 12;
    case PPC::R13:
      return 13;
    case PPC::R14:
      return 14;
    case PPC::R15:
      return 15;
    case PPC::R16:
      return 16;
    case PPC::R17:
      return 17;
    case PPC::R18:
      return 18;
    case PPC::R19:
      return 19;
    case PPC::R2:
      return 2;
    case PPC::R20:
      return 20;
    case PPC::R21:
      return 21;
    case PPC::R22:
      return 22;
    case PPC::R23:
      return 23;
    case PPC::R24:
      return 24;
    case PPC::R25:
      return 25;
    case PPC::R26:
      return 26;
    case PPC::R27:
      return 27;
    case PPC::R28:
      return 28;
    case PPC::R29:
      return 29;
    case PPC::R3:
      return 3;
    case PPC::R30:
      return 30;
    case PPC::R31:
      return 31;
    case PPC::R4:
      return 4;
    case PPC::R5:
      return 5;
    case PPC::R6:
      return 6;
    case PPC::R7:
      return 7;
    case PPC::R8:
      return 8;
    case PPC::R9:
      return 9;
    case PPC::RM:
      return 0;
    case PPC::V0:
      return 77;
    case PPC::V1:
      return 78;
    case PPC::V10:
      return 87;
    case PPC::V11:
      return 88;
    case PPC::V12:
      return 89;
    case PPC::V13:
      return 90;
    case PPC::V14:
      return 91;
    case PPC::V15:
      return 92;
    case PPC::V16:
      return 93;
    case PPC::V17:
      return 94;
    case PPC::V18:
      return 95;
    case PPC::V19:
      return 96;
    case PPC::V2:
      return 79;
    case PPC::V20:
      return 97;
    case PPC::V21:
      return 98;
    case PPC::V22:
      return 99;
    case PPC::V23:
      return 100;
    case PPC::V24:
      return 101;
    case PPC::V25:
      return 102;
    case PPC::V26:
      return 103;
    case PPC::V27:
      return 104;
    case PPC::V28:
      return 105;
    case PPC::V29:
      return 106;
    case PPC::V3:
      return 80;
    case PPC::V30:
      return 107;
    case PPC::V31:
      return 108;
    case PPC::V4:
      return 81;
    case PPC::V5:
      return 82;
    case PPC::V6:
      return 83;
    case PPC::V7:
      return 84;
    case PPC::V8:
      return 85;
    case PPC::V9:
      return 86;
    case PPC::VRSAVE:
      return 107;
    case PPC::X0:
      return 0;
    case PPC::X1:
      return 1;
    case PPC::X10:
      return 10;
    case PPC::X11:
      return 11;
    case PPC::X12:
      return 12;
    case PPC::X13:
      return 13;
    case PPC::X14:
      return 14;
    case PPC::X15:
      return 15;
    case PPC::X16:
      return 16;
    case PPC::X17:
      return 17;
    case PPC::X18:
      return 18;
    case PPC::X19:
      return 19;
    case PPC::X2:
      return 2;
    case PPC::X20:
      return 20;
    case PPC::X21:
      return 21;
    case PPC::X22:
      return 22;
    case PPC::X23:
      return 23;
    case PPC::X24:
      return 24;
    case PPC::X25:
      return 25;
    case PPC::X26:
      return 26;
    case PPC::X27:
      return 27;
    case PPC::X28:
      return 28;
    case PPC::X29:
      return 29;
    case PPC::X3:
      return 3;
    case PPC::X30:
      return 30;
    case PPC::X31:
      return 31;
    case PPC::X4:
      return 4;
    case PPC::X5:
      return 5;
    case PPC::X6:
      return 6;
    case PPC::X7:
      return 7;
    case PPC::X8:
      return 8;
    case PPC::X9:
      return 9;
    };
  };
}

} // End llvm namespace 
