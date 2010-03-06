//===- TableGen'erated file -------------------------------------*- C++ -*-===//
//
// Calling Convention Implementation Fragment
//
// Automatically generated file, do not edit!
//
//===----------------------------------------------------------------------===//

static bool CC_PPC_SVR4(unsigned ValNo, EVT ValVT,
                        EVT LocVT, CCValAssign::LocInfo LocInfo,
                        ISD::ArgFlagsTy ArgFlags, CCState &State);
static bool CC_PPC_SVR4_ByVal(unsigned ValNo, EVT ValVT,
                              EVT LocVT, CCValAssign::LocInfo LocInfo,
                              ISD::ArgFlagsTy ArgFlags, CCState &State);
static bool CC_PPC_SVR4_Common(unsigned ValNo, EVT ValVT,
                               EVT LocVT, CCValAssign::LocInfo LocInfo,
                               ISD::ArgFlagsTy ArgFlags, CCState &State);
static bool CC_PPC_SVR4_VarArg(unsigned ValNo, EVT ValVT,
                               EVT LocVT, CCValAssign::LocInfo LocInfo,
                               ISD::ArgFlagsTy ArgFlags, CCState &State);
static bool RetCC_PPC(unsigned ValNo, EVT ValVT,
                      EVT LocVT, CCValAssign::LocInfo LocInfo,
                      ISD::ArgFlagsTy ArgFlags, CCState &State);


static bool CC_PPC_SVR4(unsigned ValNo, EVT ValVT,
                        EVT LocVT, CCValAssign::LocInfo LocInfo,
                        ISD::ArgFlagsTy ArgFlags, CCState &State) {

  if (LocVT == MVT::v16i8 ||
      LocVT == MVT::v8i16 ||
      LocVT == MVT::v4i32 ||
      LocVT == MVT::v4f32) {
    static const unsigned RegList1[] = {
      PPC::V2, PPC::V3, PPC::V4, PPC::V5, PPC::V6, PPC::V7, PPC::V8, PPC::V9, PPC::V10, PPC::V11, PPC::V12, PPC::V13
    };
    if (unsigned Reg = State.AllocateReg(RegList1, 12)) {
      State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
      return false;
    }
  }

  if (!CC_PPC_SVR4_Common(ValNo, ValVT, LocVT, LocInfo, ArgFlags, State))
    return false;

  return true;  // CC didn't match.
}


static bool CC_PPC_SVR4_ByVal(unsigned ValNo, EVT ValVT,
                              EVT LocVT, CCValAssign::LocInfo LocInfo,
                              ISD::ArgFlagsTy ArgFlags, CCState &State) {

  if (ArgFlags.isByVal()) {
    State.HandleByVal(ValNo, ValVT, LocVT, LocInfo, 4, 4, ArgFlags);
    return false;
  }

  if (CC_PPC_SVR4_Custom_Dummy(ValNo, ValVT, LocVT, LocInfo, ArgFlags, State))
    return false;

  return true;  // CC didn't match.
}


static bool CC_PPC_SVR4_Common(unsigned ValNo, EVT ValVT,
                               EVT LocVT, CCValAssign::LocInfo LocInfo,
                               ISD::ArgFlagsTy ArgFlags, CCState &State) {

  if (LocVT == MVT::i32) {
    if (ArgFlags.isSplit()) {
      if (CC_PPC_SVR4_Custom_AlignArgRegs(ValNo, ValVT, LocVT, LocInfo, ArgFlags, State))
            return false;
    }
  }

  if (LocVT == MVT::i32) {
    static const unsigned RegList1[] = {
      PPC::R3, PPC::R4, PPC::R5, PPC::R6, PPC::R7, PPC::R8, PPC::R9, PPC::R10
    };
    if (unsigned Reg = State.AllocateReg(RegList1, 8)) {
      State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
      return false;
    }
  }

  if (LocVT == MVT::f64) {
    if (ArgFlags.isSplit()) {
      if (CC_PPC_SVR4_Custom_AlignFPArgRegs(ValNo, ValVT, LocVT, LocInfo, ArgFlags, State))
            return false;
    }
  }

  if (LocVT == MVT::f32 ||
      LocVT == MVT::f64) {
    static const unsigned RegList2[] = {
      PPC::F1, PPC::F2, PPC::F3, PPC::F4, PPC::F5, PPC::F6, PPC::F7, PPC::F8
    };
    if (unsigned Reg = State.AllocateReg(RegList2, 8)) {
      State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
      return false;
    }
  }

  if (LocVT == MVT::i32) {
    if (ArgFlags.isSplit()) {
      unsigned Offset3 = State.AllocateStack(4, 8);
      State.addLoc(CCValAssign::getMem(ValNo, ValVT, Offset3, LocVT, LocInfo));
      return false;
    }
  }

  if (LocVT == MVT::i32) {
    unsigned Offset4 = State.AllocateStack(4, 4);
    State.addLoc(CCValAssign::getMem(ValNo, ValVT, Offset4, LocVT, LocInfo));
    return false;
  }

  if (LocVT == MVT::f32 ||
      LocVT == MVT::f64) {
    unsigned Offset5 = State.AllocateStack(8, 8);
    State.addLoc(CCValAssign::getMem(ValNo, ValVT, Offset5, LocVT, LocInfo));
    return false;
  }

  if (LocVT == MVT::v16i8 ||
      LocVT == MVT::v8i16 ||
      LocVT == MVT::v4i32 ||
      LocVT == MVT::v4f32) {
    unsigned Offset6 = State.AllocateStack(16, 16);
    State.addLoc(CCValAssign::getMem(ValNo, ValVT, Offset6, LocVT, LocInfo));
    return false;
  }

  return true;  // CC didn't match.
}


static bool CC_PPC_SVR4_VarArg(unsigned ValNo, EVT ValVT,
                               EVT LocVT, CCValAssign::LocInfo LocInfo,
                               ISD::ArgFlagsTy ArgFlags, CCState &State) {

  if (!CC_PPC_SVR4_Common(ValNo, ValVT, LocVT, LocInfo, ArgFlags, State))
    return false;

  return true;  // CC didn't match.
}


static bool RetCC_PPC(unsigned ValNo, EVT ValVT,
                      EVT LocVT, CCValAssign::LocInfo LocInfo,
                      ISD::ArgFlagsTy ArgFlags, CCState &State) {

  if (LocVT == MVT::i32) {
    static const unsigned RegList1[] = {
      PPC::R3, PPC::R4, PPC::R5, PPC::R6, PPC::R7, PPC::R8, PPC::R9, PPC::R10
    };
    if (unsigned Reg = State.AllocateReg(RegList1, 8)) {
      State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
      return false;
    }
  }

  if (LocVT == MVT::i64) {
    static const unsigned RegList2[] = {
      PPC::X3, PPC::X4, PPC::X5, PPC::X6
    };
    if (unsigned Reg = State.AllocateReg(RegList2, 4)) {
      State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
      return false;
    }
  }

  if (LocVT == MVT::f32) {
    if (unsigned Reg = State.AllocateReg(PPC::F1)) {
      State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
      return false;
    }
  }

  if (LocVT == MVT::f64) {
    static const unsigned RegList3[] = {
      PPC::F1, PPC::F2
    };
    if (unsigned Reg = State.AllocateReg(RegList3, 2)) {
      State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
      return false;
    }
  }

  if (LocVT == MVT::v16i8 ||
      LocVT == MVT::v8i16 ||
      LocVT == MVT::v4i32 ||
      LocVT == MVT::v4f32) {
    if (unsigned Reg = State.AllocateReg(PPC::V2)) {
      State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
      return false;
    }
  }

  return true;  // CC didn't match.
}
