//===- TableGen'erated file -------------------------------------*- C++ -*-===//
//
// Register Information Header Fragment
//
// Automatically generated file, do not edit!
//
//===----------------------------------------------------------------------===//

#include "llvm/Target/TargetRegisterInfo.h"
#include <string>

namespace llvm {

struct PPCGenRegisterInfo : public TargetRegisterInfo {
  explicit PPCGenRegisterInfo(int CallFrameSetupOpcode = -1, int CallFrameDestroyOpcode = -1);
  virtual int getDwarfRegNumFull(unsigned RegNum, unsigned Flavour) const;
  virtual int getDwarfRegNum(unsigned RegNum, bool isEH) const = 0;
  virtual bool needsStackRealignment(const MachineFunction &) const
     { return false; }
  unsigned getSubReg(unsigned RegNo, unsigned Index) const;
  unsigned getSubRegIndex(unsigned RegNo, unsigned SubRegNo) const;
  unsigned composeSubRegIndices(unsigned, unsigned) const;
};

namespace PPC { // Register classes
  enum {
    CARRYRCRegClassID = 0,
    CRBITRCRegClassID = 1,
    CRRCRegClassID = 2,
    CTRRCRegClassID = 3,
    CTRRC8RegClassID = 4,
    F4RCRegClassID = 5,
    F8RCRegClassID = 6,
    G8RCRegClassID = 7,
    GPRCRegClassID = 8,
    VRRCRegClassID = 9,
    VRSAVERCRegClassID = 10
  };

  struct CARRYRCClass : public TargetRegisterClass {
    CARRYRCClass();
  };
  extern CARRYRCClass	CARRYRCRegClass;
  static TargetRegisterClass * const CARRYRCRegisterClass = &CARRYRCRegClass;
  struct CRBITRCClass : public TargetRegisterClass {
    CRBITRCClass();
  };
  extern CRBITRCClass	CRBITRCRegClass;
  static TargetRegisterClass * const CRBITRCRegisterClass = &CRBITRCRegClass;
  struct CRRCClass : public TargetRegisterClass {
    CRRCClass();
  };
  extern CRRCClass	CRRCRegClass;
  static TargetRegisterClass * const CRRCRegisterClass = &CRRCRegClass;
  struct CTRRCClass : public TargetRegisterClass {
    CTRRCClass();
  };
  extern CTRRCClass	CTRRCRegClass;
  static TargetRegisterClass * const CTRRCRegisterClass = &CTRRCRegClass;
  struct CTRRC8Class : public TargetRegisterClass {
    CTRRC8Class();
  };
  extern CTRRC8Class	CTRRC8RegClass;
  static TargetRegisterClass * const CTRRC8RegisterClass = &CTRRC8RegClass;
  struct F4RCClass : public TargetRegisterClass {
    F4RCClass();
  };
  extern F4RCClass	F4RCRegClass;
  static TargetRegisterClass * const F4RCRegisterClass = &F4RCRegClass;
  struct F8RCClass : public TargetRegisterClass {
    F8RCClass();
  };
  extern F8RCClass	F8RCRegClass;
  static TargetRegisterClass * const F8RCRegisterClass = &F8RCRegClass;
  struct G8RCClass : public TargetRegisterClass {
    G8RCClass();

    iterator allocation_order_begin(const MachineFunction &MF) const;
    iterator allocation_order_end(const MachineFunction &MF) const;
    };
  extern G8RCClass	G8RCRegClass;
  static TargetRegisterClass * const G8RCRegisterClass = &G8RCRegClass;
  struct GPRCClass : public TargetRegisterClass {
    GPRCClass();

    iterator allocation_order_begin(const MachineFunction &MF) const;
    iterator allocation_order_end(const MachineFunction &MF) const;
    };
  extern GPRCClass	GPRCRegClass;
  static TargetRegisterClass * const GPRCRegisterClass = &GPRCRegClass;
  struct VRRCClass : public TargetRegisterClass {
    VRRCClass();
  };
  extern VRRCClass	VRRCRegClass;
  static TargetRegisterClass * const VRRCRegisterClass = &VRRCRegClass;
  struct VRSAVERCClass : public TargetRegisterClass {
    VRSAVERCClass();
  };
  extern VRSAVERCClass	VRSAVERCRegClass;
  static TargetRegisterClass * const VRSAVERCRegisterClass = &VRSAVERCRegClass;
} // end of namespace PPC

} // End llvm namespace 
