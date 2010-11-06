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

struct X86GenRegisterInfo : public TargetRegisterInfo {
  explicit X86GenRegisterInfo(int CallFrameSetupOpcode = -1, int CallFrameDestroyOpcode = -1);
  virtual int getDwarfRegNumFull(unsigned RegNum, unsigned Flavour) const;
  virtual int getDwarfRegNum(unsigned RegNum, bool isEH) const = 0;
  virtual bool needsStackRealignment(const MachineFunction &) const
     { return false; }
  unsigned getSubReg(unsigned RegNo, unsigned Index) const;
  unsigned getSubRegIndex(unsigned RegNo, unsigned SubRegNo) const;
  unsigned composeSubRegIndices(unsigned, unsigned) const;
};

namespace X86 { // Register classes
  enum {
    CCRRegClassID = 0,
    CONTROL_REGRegClassID = 1,
    DEBUG_REGRegClassID = 2,
    FR32RegClassID = 3,
    FR64RegClassID = 4,
    GR16RegClassID = 5,
    GR16_ABCDRegClassID = 6,
    GR16_NOREXRegClassID = 7,
    GR32RegClassID = 8,
    GR32_ABCDRegClassID = 9,
    GR32_ADRegClassID = 10,
    GR32_NOREXRegClassID = 11,
    GR32_NOSPRegClassID = 12,
    GR32_TCRegClassID = 13,
    GR64RegClassID = 14,
    GR64_ABCDRegClassID = 15,
    GR64_NOREXRegClassID = 16,
    GR64_NOREX_NOSPRegClassID = 17,
    GR64_NOSPRegClassID = 18,
    GR64_TCRegClassID = 19,
    GR8RegClassID = 20,
    GR8_ABCD_HRegClassID = 21,
    GR8_ABCD_LRegClassID = 22,
    GR8_NOREXRegClassID = 23,
    RFP32RegClassID = 24,
    RFP64RegClassID = 25,
    RFP80RegClassID = 26,
    RSTRegClassID = 27,
    SEGMENT_REGRegClassID = 28,
    VR128RegClassID = 29,
    VR256RegClassID = 30,
    VR64RegClassID = 31
  };

  struct CCRClass : public TargetRegisterClass {
    CCRClass();

    iterator allocation_order_end(const MachineFunction &MF) const;
    };
  extern CCRClass	CCRRegClass;
  static TargetRegisterClass * const CCRRegisterClass = &CCRRegClass;
  struct CONTROL_REGClass : public TargetRegisterClass {
    CONTROL_REGClass();
  };
  extern CONTROL_REGClass	CONTROL_REGRegClass;
  static TargetRegisterClass * const CONTROL_REGRegisterClass = &CONTROL_REGRegClass;
  struct DEBUG_REGClass : public TargetRegisterClass {
    DEBUG_REGClass();
  };
  extern DEBUG_REGClass	DEBUG_REGRegClass;
  static TargetRegisterClass * const DEBUG_REGRegisterClass = &DEBUG_REGRegClass;
  struct FR32Class : public TargetRegisterClass {
    FR32Class();

    iterator allocation_order_end(const MachineFunction &MF) const;
    };
  extern FR32Class	FR32RegClass;
  static TargetRegisterClass * const FR32RegisterClass = &FR32RegClass;
  struct FR64Class : public TargetRegisterClass {
    FR64Class();

    iterator allocation_order_end(const MachineFunction &MF) const;
    };
  extern FR64Class	FR64RegClass;
  static TargetRegisterClass * const FR64RegisterClass = &FR64RegClass;
  struct GR16Class : public TargetRegisterClass {
    GR16Class();

    iterator allocation_order_begin(const MachineFunction &MF) const;
    iterator allocation_order_end(const MachineFunction &MF) const;
    };
  extern GR16Class	GR16RegClass;
  static TargetRegisterClass * const GR16RegisterClass = &GR16RegClass;
  struct GR16_ABCDClass : public TargetRegisterClass {
    GR16_ABCDClass();
  };
  extern GR16_ABCDClass	GR16_ABCDRegClass;
  static TargetRegisterClass * const GR16_ABCDRegisterClass = &GR16_ABCDRegClass;
  struct GR16_NOREXClass : public TargetRegisterClass {
    GR16_NOREXClass();

    iterator allocation_order_end(const MachineFunction &MF) const;
    };
  extern GR16_NOREXClass	GR16_NOREXRegClass;
  static TargetRegisterClass * const GR16_NOREXRegisterClass = &GR16_NOREXRegClass;
  struct GR32Class : public TargetRegisterClass {
    GR32Class();

    iterator allocation_order_begin(const MachineFunction &MF) const;
    iterator allocation_order_end(const MachineFunction &MF) const;
    };
  extern GR32Class	GR32RegClass;
  static TargetRegisterClass * const GR32RegisterClass = &GR32RegClass;
  struct GR32_ABCDClass : public TargetRegisterClass {
    GR32_ABCDClass();
  };
  extern GR32_ABCDClass	GR32_ABCDRegClass;
  static TargetRegisterClass * const GR32_ABCDRegisterClass = &GR32_ABCDRegClass;
  struct GR32_ADClass : public TargetRegisterClass {
    GR32_ADClass();
  };
  extern GR32_ADClass	GR32_ADRegClass;
  static TargetRegisterClass * const GR32_ADRegisterClass = &GR32_ADRegClass;
  struct GR32_NOREXClass : public TargetRegisterClass {
    GR32_NOREXClass();

    iterator allocation_order_end(const MachineFunction &MF) const;
    };
  extern GR32_NOREXClass	GR32_NOREXRegClass;
  static TargetRegisterClass * const GR32_NOREXRegisterClass = &GR32_NOREXRegClass;
  struct GR32_NOSPClass : public TargetRegisterClass {
    GR32_NOSPClass();

    iterator allocation_order_begin(const MachineFunction &MF) const;
    iterator allocation_order_end(const MachineFunction &MF) const;
    };
  extern GR32_NOSPClass	GR32_NOSPRegClass;
  static TargetRegisterClass * const GR32_NOSPRegisterClass = &GR32_NOSPRegClass;
  struct GR32_TCClass : public TargetRegisterClass {
    GR32_TCClass();
  };
  extern GR32_TCClass	GR32_TCRegClass;
  static TargetRegisterClass * const GR32_TCRegisterClass = &GR32_TCRegClass;
  struct GR64Class : public TargetRegisterClass {
    GR64Class();

    iterator allocation_order_end(const MachineFunction &MF) const;
    };
  extern GR64Class	GR64RegClass;
  static TargetRegisterClass * const GR64RegisterClass = &GR64RegClass;
  struct GR64_ABCDClass : public TargetRegisterClass {
    GR64_ABCDClass();
  };
  extern GR64_ABCDClass	GR64_ABCDRegClass;
  static TargetRegisterClass * const GR64_ABCDRegisterClass = &GR64_ABCDRegClass;
  struct GR64_NOREXClass : public TargetRegisterClass {
    GR64_NOREXClass();

    iterator allocation_order_end(const MachineFunction &MF) const;
    };
  extern GR64_NOREXClass	GR64_NOREXRegClass;
  static TargetRegisterClass * const GR64_NOREXRegisterClass = &GR64_NOREXRegClass;
  struct GR64_NOREX_NOSPClass : public TargetRegisterClass {
    GR64_NOREX_NOSPClass();

    iterator allocation_order_end(const MachineFunction &MF) const;
    };
  extern GR64_NOREX_NOSPClass	GR64_NOREX_NOSPRegClass;
  static TargetRegisterClass * const GR64_NOREX_NOSPRegisterClass = &GR64_NOREX_NOSPRegClass;
  struct GR64_NOSPClass : public TargetRegisterClass {
    GR64_NOSPClass();

    iterator allocation_order_end(const MachineFunction &MF) const;
    };
  extern GR64_NOSPClass	GR64_NOSPRegClass;
  static TargetRegisterClass * const GR64_NOSPRegisterClass = &GR64_NOSPRegClass;
  struct GR64_TCClass : public TargetRegisterClass {
    GR64_TCClass();
  };
  extern GR64_TCClass	GR64_TCRegClass;
  static TargetRegisterClass * const GR64_TCRegisterClass = &GR64_TCRegClass;
  struct GR8Class : public TargetRegisterClass {
    GR8Class();

    iterator allocation_order_begin(const MachineFunction &MF) const;
    iterator allocation_order_end(const MachineFunction &MF) const;
    };
  extern GR8Class	GR8RegClass;
  static TargetRegisterClass * const GR8RegisterClass = &GR8RegClass;
  struct GR8_ABCD_HClass : public TargetRegisterClass {
    GR8_ABCD_HClass();
  };
  extern GR8_ABCD_HClass	GR8_ABCD_HRegClass;
  static TargetRegisterClass * const GR8_ABCD_HRegisterClass = &GR8_ABCD_HRegClass;
  struct GR8_ABCD_LClass : public TargetRegisterClass {
    GR8_ABCD_LClass();
  };
  extern GR8_ABCD_LClass	GR8_ABCD_LRegClass;
  static TargetRegisterClass * const GR8_ABCD_LRegisterClass = &GR8_ABCD_LRegClass;
  struct GR8_NOREXClass : public TargetRegisterClass {
    GR8_NOREXClass();

    iterator allocation_order_begin(const MachineFunction &MF) const;
    iterator allocation_order_end(const MachineFunction &MF) const;
    };
  extern GR8_NOREXClass	GR8_NOREXRegClass;
  static TargetRegisterClass * const GR8_NOREXRegisterClass = &GR8_NOREXRegClass;
  struct RFP32Class : public TargetRegisterClass {
    RFP32Class();
  };
  extern RFP32Class	RFP32RegClass;
  static TargetRegisterClass * const RFP32RegisterClass = &RFP32RegClass;
  struct RFP64Class : public TargetRegisterClass {
    RFP64Class();
  };
  extern RFP64Class	RFP64RegClass;
  static TargetRegisterClass * const RFP64RegisterClass = &RFP64RegClass;
  struct RFP80Class : public TargetRegisterClass {
    RFP80Class();
  };
  extern RFP80Class	RFP80RegClass;
  static TargetRegisterClass * const RFP80RegisterClass = &RFP80RegClass;
  struct RSTClass : public TargetRegisterClass {
    RSTClass();

    iterator allocation_order_end(const MachineFunction &MF) const;
    };
  extern RSTClass	RSTRegClass;
  static TargetRegisterClass * const RSTRegisterClass = &RSTRegClass;
  struct SEGMENT_REGClass : public TargetRegisterClass {
    SEGMENT_REGClass();
  };
  extern SEGMENT_REGClass	SEGMENT_REGRegClass;
  static TargetRegisterClass * const SEGMENT_REGRegisterClass = &SEGMENT_REGRegClass;
  struct VR128Class : public TargetRegisterClass {
    VR128Class();

    iterator allocation_order_end(const MachineFunction &MF) const;
    };
  extern VR128Class	VR128RegClass;
  static TargetRegisterClass * const VR128RegisterClass = &VR128RegClass;
  struct VR256Class : public TargetRegisterClass {
    VR256Class();

    iterator allocation_order_end(const MachineFunction &MF) const;
    };
  extern VR256Class	VR256RegClass;
  static TargetRegisterClass * const VR256RegisterClass = &VR256RegClass;
  struct VR64Class : public TargetRegisterClass {
    VR64Class();
  };
  extern VR64Class	VR64RegClass;
  static TargetRegisterClass * const VR64RegisterClass = &VR64RegClass;
} // end of namespace X86

} // End llvm namespace 
