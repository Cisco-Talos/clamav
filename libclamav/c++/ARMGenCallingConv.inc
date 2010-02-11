//===- TableGen'erated file -------------------------------------*- C++ -*-===//
//
// Calling Convention Implementation Fragment
//
// Automatically generated file, do not edit!
//
//===----------------------------------------------------------------------===//

static bool CC_ARM_AAPCS(unsigned ValNo, EVT ValVT,
                         EVT LocVT, CCValAssign::LocInfo LocInfo,
                         ISD::ArgFlagsTy ArgFlags, CCState &State);
static bool CC_ARM_AAPCS_Common(unsigned ValNo, EVT ValVT,
                                EVT LocVT, CCValAssign::LocInfo LocInfo,
                                ISD::ArgFlagsTy ArgFlags, CCState &State);
static bool CC_ARM_AAPCS_VFP(unsigned ValNo, EVT ValVT,
                             EVT LocVT, CCValAssign::LocInfo LocInfo,
                             ISD::ArgFlagsTy ArgFlags, CCState &State);
static bool CC_ARM_APCS(unsigned ValNo, EVT ValVT,
                        EVT LocVT, CCValAssign::LocInfo LocInfo,
                        ISD::ArgFlagsTy ArgFlags, CCState &State);
static bool RetCC_ARM_AAPCS(unsigned ValNo, EVT ValVT,
                            EVT LocVT, CCValAssign::LocInfo LocInfo,
                            ISD::ArgFlagsTy ArgFlags, CCState &State);
static bool RetCC_ARM_AAPCS_Common(unsigned ValNo, EVT ValVT,
                                   EVT LocVT, CCValAssign::LocInfo LocInfo,
                                   ISD::ArgFlagsTy ArgFlags, CCState &State);
static bool RetCC_ARM_AAPCS_VFP(unsigned ValNo, EVT ValVT,
                                EVT LocVT, CCValAssign::LocInfo LocInfo,
                                ISD::ArgFlagsTy ArgFlags, CCState &State);
static bool RetCC_ARM_APCS(unsigned ValNo, EVT ValVT,
                           EVT LocVT, CCValAssign::LocInfo LocInfo,
                           ISD::ArgFlagsTy ArgFlags, CCState &State);


static bool CC_ARM_AAPCS(unsigned ValNo, EVT ValVT,
                         EVT LocVT, CCValAssign::LocInfo LocInfo,
                         ISD::ArgFlagsTy ArgFlags, CCState &State) {

  if (LocVT == MVT::v1i64 ||
      LocVT == MVT::v2i32 ||
      LocVT == MVT::v4i16 ||
      LocVT == MVT::v8i8 ||
      LocVT == MVT::v2f32) {
    LocVT = MVT::f64;
    LocInfo = CCValAssign::BCvt;
  }

  if (LocVT == MVT::v2i64 ||
      LocVT == MVT::v4i32 ||
      LocVT == MVT::v8i16 ||
      LocVT == MVT::v16i8 ||
      LocVT == MVT::v4f32) {
    LocVT = MVT::v2f64;
    LocInfo = CCValAssign::BCvt;
  }

  if (LocVT == MVT::f64 ||
      LocVT == MVT::v2f64) {
    if (CC_ARM_AAPCS_Custom_f64(ValNo, ValVT, LocVT, LocInfo, ArgFlags, State))
        return false;
  }

  if (LocVT == MVT::f32) {
    LocVT = MVT::i32;
    LocInfo = CCValAssign::BCvt;
  }

  if (!CC_ARM_AAPCS_Common(ValNo, ValVT, LocVT, LocInfo, ArgFlags, State))
    return false;

  return true;  // CC didn't match.
}


static bool CC_ARM_AAPCS_Common(unsigned ValNo, EVT ValVT,
                                EVT LocVT, CCValAssign::LocInfo LocInfo,
                                ISD::ArgFlagsTy ArgFlags, CCState &State) {

  if (LocVT == MVT::i8 ||
      LocVT == MVT::i16) {
    LocVT = MVT::i32;
    if (ArgFlags.isSExt())
        LocInfo = CCValAssign::SExt;
    else if (ArgFlags.isZExt())
        LocInfo = CCValAssign::ZExt;
    else
        LocInfo = CCValAssign::AExt;
  }

  if (LocVT == MVT::i32) {
    if (ArgFlags.getOrigAlign() == 8) {
      static const unsigned RegList1[] = {
        ARM::R0, ARM::R2
      };
      static const unsigned RegList2[] = {
        ARM::R0, ARM::R1
      };
      if (unsigned Reg = State.AllocateReg(RegList1, RegList2, 2)) {
        State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
        return false;
      }
    }
  }

  if (LocVT == MVT::i32) {
    if (State.getNextStackOffset() == 0 &&ArgFlags.getOrigAlign() != 8) {
      static const unsigned RegList3[] = {
        ARM::R0, ARM::R1, ARM::R2, ARM::R3
      };
      if (unsigned Reg = State.AllocateReg(RegList3, 4)) {
        State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
        return false;
      }
    }
  }

  if (LocVT == MVT::i32) {
    if (ArgFlags.getOrigAlign() == 8) {
      unsigned Offset4 = State.AllocateStack(4, 8);
      State.addLoc(CCValAssign::getMem(ValNo, ValVT, Offset4, LocVT, LocInfo));
      return false;
    }
  }

  if (LocVT == MVT::i32 ||
      LocVT == MVT::f32) {
    unsigned Offset5 = State.AllocateStack(4, 4);
    State.addLoc(CCValAssign::getMem(ValNo, ValVT, Offset5, LocVT, LocInfo));
    return false;
  }

  if (LocVT == MVT::f64) {
    unsigned Offset6 = State.AllocateStack(8, 8);
    State.addLoc(CCValAssign::getMem(ValNo, ValVT, Offset6, LocVT, LocInfo));
    return false;
  }

  if (LocVT == MVT::v2f64) {
    unsigned Offset7 = State.AllocateStack(16, 8);
    State.addLoc(CCValAssign::getMem(ValNo, ValVT, Offset7, LocVT, LocInfo));
    return false;
  }

  return true;  // CC didn't match.
}


static bool CC_ARM_AAPCS_VFP(unsigned ValNo, EVT ValVT,
                             EVT LocVT, CCValAssign::LocInfo LocInfo,
                             ISD::ArgFlagsTy ArgFlags, CCState &State) {

  if (LocVT == MVT::v1i64 ||
      LocVT == MVT::v2i32 ||
      LocVT == MVT::v4i16 ||
      LocVT == MVT::v8i8 ||
      LocVT == MVT::v2f32) {
    LocVT = MVT::f64;
    LocInfo = CCValAssign::BCvt;
  }

  if (LocVT == MVT::v2i64 ||
      LocVT == MVT::v4i32 ||
      LocVT == MVT::v8i16 ||
      LocVT == MVT::v16i8 ||
      LocVT == MVT::v4f32) {
    LocVT = MVT::v2f64;
    LocInfo = CCValAssign::BCvt;
  }

  if (LocVT == MVT::v2f64) {
    static const unsigned RegList1[] = {
      ARM::Q0, ARM::Q1, ARM::Q2, ARM::Q3
    };
    if (unsigned Reg = State.AllocateReg(RegList1, 4)) {
      State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
      return false;
    }
  }

  if (LocVT == MVT::f64) {
    static const unsigned RegList2[] = {
      ARM::D0, ARM::D1, ARM::D2, ARM::D3, ARM::D4, ARM::D5, ARM::D6, ARM::D7
    };
    if (unsigned Reg = State.AllocateReg(RegList2, 8)) {
      State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
      return false;
    }
  }

  if (LocVT == MVT::f32) {
    static const unsigned RegList3[] = {
      ARM::S0, ARM::S1, ARM::S2, ARM::S3, ARM::S4, ARM::S5, ARM::S6, ARM::S7, ARM::S8, ARM::S9, ARM::S10, ARM::S11, ARM::S12, ARM::S13, ARM::S14, ARM::S15
    };
    if (unsigned Reg = State.AllocateReg(RegList3, 16)) {
      State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
      return false;
    }
  }

  if (!CC_ARM_AAPCS_Common(ValNo, ValVT, LocVT, LocInfo, ArgFlags, State))
    return false;

  return true;  // CC didn't match.
}


static bool CC_ARM_APCS(unsigned ValNo, EVT ValVT,
                        EVT LocVT, CCValAssign::LocInfo LocInfo,
                        ISD::ArgFlagsTy ArgFlags, CCState &State) {

  if (LocVT == MVT::i8 ||
      LocVT == MVT::i16) {
    LocVT = MVT::i32;
    if (ArgFlags.isSExt())
        LocInfo = CCValAssign::SExt;
    else if (ArgFlags.isZExt())
        LocInfo = CCValAssign::ZExt;
    else
        LocInfo = CCValAssign::AExt;
  }

  if (LocVT == MVT::v1i64 ||
      LocVT == MVT::v2i32 ||
      LocVT == MVT::v4i16 ||
      LocVT == MVT::v8i8 ||
      LocVT == MVT::v2f32) {
    LocVT = MVT::f64;
    LocInfo = CCValAssign::BCvt;
  }

  if (LocVT == MVT::v2i64 ||
      LocVT == MVT::v4i32 ||
      LocVT == MVT::v8i16 ||
      LocVT == MVT::v16i8 ||
      LocVT == MVT::v4f32) {
    LocVT = MVT::v2f64;
    LocInfo = CCValAssign::BCvt;
  }

  if (LocVT == MVT::f64 ||
      LocVT == MVT::v2f64) {
    if (CC_ARM_APCS_Custom_f64(ValNo, ValVT, LocVT, LocInfo, ArgFlags, State))
        return false;
  }

  if (LocVT == MVT::f32) {
    LocVT = MVT::i32;
    LocInfo = CCValAssign::BCvt;
  }

  if (LocVT == MVT::i32) {
    static const unsigned RegList1[] = {
      ARM::R0, ARM::R1, ARM::R2, ARM::R3
    };
    if (unsigned Reg = State.AllocateReg(RegList1, 4)) {
      State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
      return false;
    }
  }

  if (LocVT == MVT::i32) {
    unsigned Offset2 = State.AllocateStack(4, 4);
    State.addLoc(CCValAssign::getMem(ValNo, ValVT, Offset2, LocVT, LocInfo));
    return false;
  }

  if (LocVT == MVT::f64) {
    unsigned Offset3 = State.AllocateStack(8, 4);
    State.addLoc(CCValAssign::getMem(ValNo, ValVT, Offset3, LocVT, LocInfo));
    return false;
  }

  if (LocVT == MVT::v2f64) {
    unsigned Offset4 = State.AllocateStack(16, 4);
    State.addLoc(CCValAssign::getMem(ValNo, ValVT, Offset4, LocVT, LocInfo));
    return false;
  }

  return true;  // CC didn't match.
}


static bool RetCC_ARM_AAPCS(unsigned ValNo, EVT ValVT,
                            EVT LocVT, CCValAssign::LocInfo LocInfo,
                            ISD::ArgFlagsTy ArgFlags, CCState &State) {

  if (LocVT == MVT::v1i64 ||
      LocVT == MVT::v2i32 ||
      LocVT == MVT::v4i16 ||
      LocVT == MVT::v8i8 ||
      LocVT == MVT::v2f32) {
    LocVT = MVT::f64;
    LocInfo = CCValAssign::BCvt;
  }

  if (LocVT == MVT::v2i64 ||
      LocVT == MVT::v4i32 ||
      LocVT == MVT::v8i16 ||
      LocVT == MVT::v16i8 ||
      LocVT == MVT::v4f32) {
    LocVT = MVT::v2f64;
    LocInfo = CCValAssign::BCvt;
  }

  if (LocVT == MVT::f64 ||
      LocVT == MVT::v2f64) {
    if (RetCC_ARM_AAPCS_Custom_f64(ValNo, ValVT, LocVT, LocInfo, ArgFlags, State))
        return false;
  }

  if (LocVT == MVT::f32) {
    LocVT = MVT::i32;
    LocInfo = CCValAssign::BCvt;
  }

  if (!RetCC_ARM_AAPCS_Common(ValNo, ValVT, LocVT, LocInfo, ArgFlags, State))
    return false;

  return true;  // CC didn't match.
}


static bool RetCC_ARM_AAPCS_Common(unsigned ValNo, EVT ValVT,
                                   EVT LocVT, CCValAssign::LocInfo LocInfo,
                                   ISD::ArgFlagsTy ArgFlags, CCState &State) {

  if (LocVT == MVT::i32) {
    static const unsigned RegList1[] = {
      ARM::R0, ARM::R1, ARM::R2, ARM::R3
    };
    if (unsigned Reg = State.AllocateReg(RegList1, 4)) {
      State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
      return false;
    }
  }

  if (LocVT == MVT::i64) {
    static const unsigned RegList2[] = {
      ARM::R0, ARM::R2
    };
    static const unsigned RegList3[] = {
      ARM::R1, ARM::R3
    };
    if (unsigned Reg = State.AllocateReg(RegList2, RegList3, 2)) {
      State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
      return false;
    }
  }

  return true;  // CC didn't match.
}


static bool RetCC_ARM_AAPCS_VFP(unsigned ValNo, EVT ValVT,
                                EVT LocVT, CCValAssign::LocInfo LocInfo,
                                ISD::ArgFlagsTy ArgFlags, CCState &State) {

  if (LocVT == MVT::v1i64 ||
      LocVT == MVT::v2i32 ||
      LocVT == MVT::v4i16 ||
      LocVT == MVT::v8i8 ||
      LocVT == MVT::v2f32) {
    LocVT = MVT::f64;
    LocInfo = CCValAssign::BCvt;
  }

  if (LocVT == MVT::v2i64 ||
      LocVT == MVT::v4i32 ||
      LocVT == MVT::v8i16 ||
      LocVT == MVT::v16i8 ||
      LocVT == MVT::v4f32) {
    LocVT = MVT::v2f64;
    LocInfo = CCValAssign::BCvt;
  }

  if (LocVT == MVT::v2f64) {
    static const unsigned RegList1[] = {
      ARM::Q0, ARM::Q1, ARM::Q2, ARM::Q3
    };
    if (unsigned Reg = State.AllocateReg(RegList1, 4)) {
      State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
      return false;
    }
  }

  if (LocVT == MVT::f64) {
    static const unsigned RegList2[] = {
      ARM::D0, ARM::D1, ARM::D2, ARM::D3, ARM::D4, ARM::D5, ARM::D6, ARM::D7
    };
    if (unsigned Reg = State.AllocateReg(RegList2, 8)) {
      State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
      return false;
    }
  }

  if (LocVT == MVT::f32) {
    static const unsigned RegList3[] = {
      ARM::S0, ARM::S1, ARM::S2, ARM::S3, ARM::S4, ARM::S5, ARM::S6, ARM::S7, ARM::S8, ARM::S9, ARM::S10, ARM::S11, ARM::S12, ARM::S13, ARM::S14, ARM::S15
    };
    if (unsigned Reg = State.AllocateReg(RegList3, 16)) {
      State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
      return false;
    }
  }

  if (!RetCC_ARM_AAPCS_Common(ValNo, ValVT, LocVT, LocInfo, ArgFlags, State))
    return false;

  return true;  // CC didn't match.
}


static bool RetCC_ARM_APCS(unsigned ValNo, EVT ValVT,
                           EVT LocVT, CCValAssign::LocInfo LocInfo,
                           ISD::ArgFlagsTy ArgFlags, CCState &State) {

  if (LocVT == MVT::f32) {
    LocVT = MVT::i32;
    LocInfo = CCValAssign::BCvt;
  }

  if (LocVT == MVT::v1i64 ||
      LocVT == MVT::v2i32 ||
      LocVT == MVT::v4i16 ||
      LocVT == MVT::v8i8 ||
      LocVT == MVT::v2f32) {
    LocVT = MVT::f64;
    LocInfo = CCValAssign::BCvt;
  }

  if (LocVT == MVT::v2i64 ||
      LocVT == MVT::v4i32 ||
      LocVT == MVT::v8i16 ||
      LocVT == MVT::v16i8 ||
      LocVT == MVT::v4f32) {
    LocVT = MVT::v2f64;
    LocInfo = CCValAssign::BCvt;
  }

  if (LocVT == MVT::f64 ||
      LocVT == MVT::v2f64) {
    if (RetCC_ARM_APCS_Custom_f64(ValNo, ValVT, LocVT, LocInfo, ArgFlags, State))
        return false;
  }

  if (LocVT == MVT::i32) {
    static const unsigned RegList1[] = {
      ARM::R0, ARM::R1, ARM::R2, ARM::R3
    };
    if (unsigned Reg = State.AllocateReg(RegList1, 4)) {
      State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
      return false;
    }
  }

  if (LocVT == MVT::i64) {
    static const unsigned RegList2[] = {
      ARM::R0, ARM::R2
    };
    static const unsigned RegList3[] = {
      ARM::R1, ARM::R3
    };
    if (unsigned Reg = State.AllocateReg(RegList2, RegList3, 2)) {
      State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
      return false;
    }
  }

  return true;  // CC didn't match.
}
