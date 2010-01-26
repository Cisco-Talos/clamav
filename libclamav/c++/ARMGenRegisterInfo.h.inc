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

struct ARMGenRegisterInfo : public TargetRegisterInfo {
  explicit ARMGenRegisterInfo(int CallFrameSetupOpcode = -1, int CallFrameDestroyOpcode = -1);
  virtual int getDwarfRegNumFull(unsigned RegNum, unsigned Flavour) const;
  virtual int getDwarfRegNum(unsigned RegNum, bool isEH) const = 0;
  virtual bool needsStackRealignment(const MachineFunction &) const
     { return false; }
  unsigned getSubReg(unsigned RegNo, unsigned Index) const;
  unsigned getSubRegIndex(unsigned RegNo, unsigned SubRegNo) const;
};

namespace ARM { // Register classes
  enum {
    CCRRegClassID = 1,
    DPRRegClassID = 2,
    DPR_8RegClassID = 3,
    DPR_VFP2RegClassID = 4,
    GPRRegClassID = 5,
    QPRRegClassID = 6,
    QPR_8RegClassID = 7,
    QPR_VFP2RegClassID = 8,
    SPRRegClassID = 9,
    SPR_8RegClassID = 10,
    SPR_INVALIDRegClassID = 11,
    tGPRRegClassID = 12
  };

  struct CCRClass : public TargetRegisterClass {
    CCRClass();
  };
  extern CCRClass	CCRRegClass;
  static TargetRegisterClass * const CCRRegisterClass = &CCRRegClass;
  struct DPRClass : public TargetRegisterClass {
    DPRClass();

    iterator allocation_order_begin(const MachineFunction &MF) const;
    iterator allocation_order_end(const MachineFunction &MF) const;
    };
  extern DPRClass	DPRRegClass;
  static TargetRegisterClass * const DPRRegisterClass = &DPRRegClass;
  struct DPR_8Class : public TargetRegisterClass {
    DPR_8Class();
  };
  extern DPR_8Class	DPR_8RegClass;
  static TargetRegisterClass * const DPR_8RegisterClass = &DPR_8RegClass;
  struct DPR_VFP2Class : public TargetRegisterClass {
    DPR_VFP2Class();
  };
  extern DPR_VFP2Class	DPR_VFP2RegClass;
  static TargetRegisterClass * const DPR_VFP2RegisterClass = &DPR_VFP2RegClass;
  struct GPRClass : public TargetRegisterClass {
    GPRClass();

    iterator allocation_order_begin(const MachineFunction &MF) const;
    iterator allocation_order_end(const MachineFunction &MF) const;
    };
  extern GPRClass	GPRRegClass;
  static TargetRegisterClass * const GPRRegisterClass = &GPRRegClass;
  struct QPRClass : public TargetRegisterClass {
    QPRClass();
  };
  extern QPRClass	QPRRegClass;
  static TargetRegisterClass * const QPRRegisterClass = &QPRRegClass;
  struct QPR_8Class : public TargetRegisterClass {
    QPR_8Class();
  };
  extern QPR_8Class	QPR_8RegClass;
  static TargetRegisterClass * const QPR_8RegisterClass = &QPR_8RegClass;
  struct QPR_VFP2Class : public TargetRegisterClass {
    QPR_VFP2Class();
  };
  extern QPR_VFP2Class	QPR_VFP2RegClass;
  static TargetRegisterClass * const QPR_VFP2RegisterClass = &QPR_VFP2RegClass;
  struct SPRClass : public TargetRegisterClass {
    SPRClass();
  };
  extern SPRClass	SPRRegClass;
  static TargetRegisterClass * const SPRRegisterClass = &SPRRegClass;
  struct SPR_8Class : public TargetRegisterClass {
    SPR_8Class();
  };
  extern SPR_8Class	SPR_8RegClass;
  static TargetRegisterClass * const SPR_8RegisterClass = &SPR_8RegClass;
  struct SPR_INVALIDClass : public TargetRegisterClass {
    SPR_INVALIDClass();
  };
  extern SPR_INVALIDClass	SPR_INVALIDRegClass;
  static TargetRegisterClass * const SPR_INVALIDRegisterClass = &SPR_INVALIDRegClass;
  struct tGPRClass : public TargetRegisterClass {
    tGPRClass();

    iterator allocation_order_begin(const MachineFunction &MF) const;
    iterator allocation_order_end(const MachineFunction &MF) const;
    };
  extern tGPRClass	tGPRRegClass;
  static TargetRegisterClass * const tGPRRegisterClass = &tGPRRegClass;
} // end of namespace ARM

} // End llvm namespace 
