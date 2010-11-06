//===- TableGen'erated file -------------------------------------*- C++ -*-===//
//
// Calling Convention Implementation Fragment
//
// Automatically generated file, do not edit!
//
//===----------------------------------------------------------------------===//

static bool CC_X86_32_C(unsigned ValNo, EVT ValVT,
                        EVT LocVT, CCValAssign::LocInfo LocInfo,
                        ISD::ArgFlagsTy ArgFlags, CCState &State);
static bool CC_X86_32_Common(unsigned ValNo, EVT ValVT,
                             EVT LocVT, CCValAssign::LocInfo LocInfo,
                             ISD::ArgFlagsTy ArgFlags, CCState &State);
static bool CC_X86_32_FastCC(unsigned ValNo, EVT ValVT,
                             EVT LocVT, CCValAssign::LocInfo LocInfo,
                             ISD::ArgFlagsTy ArgFlags, CCState &State);
static bool CC_X86_32_FastCall(unsigned ValNo, EVT ValVT,
                               EVT LocVT, CCValAssign::LocInfo LocInfo,
                               ISD::ArgFlagsTy ArgFlags, CCState &State);
static bool CC_X86_32_GHC(unsigned ValNo, EVT ValVT,
                          EVT LocVT, CCValAssign::LocInfo LocInfo,
                          ISD::ArgFlagsTy ArgFlags, CCState &State);
static bool CC_X86_32_ThisCall(unsigned ValNo, EVT ValVT,
                               EVT LocVT, CCValAssign::LocInfo LocInfo,
                               ISD::ArgFlagsTy ArgFlags, CCState &State);
static bool CC_X86_64_C(unsigned ValNo, EVT ValVT,
                        EVT LocVT, CCValAssign::LocInfo LocInfo,
                        ISD::ArgFlagsTy ArgFlags, CCState &State);
static bool CC_X86_64_GHC(unsigned ValNo, EVT ValVT,
                          EVT LocVT, CCValAssign::LocInfo LocInfo,
                          ISD::ArgFlagsTy ArgFlags, CCState &State);
static bool CC_X86_Win64_C(unsigned ValNo, EVT ValVT,
                           EVT LocVT, CCValAssign::LocInfo LocInfo,
                           ISD::ArgFlagsTy ArgFlags, CCState &State);
static bool RetCC_X86(unsigned ValNo, EVT ValVT,
                      EVT LocVT, CCValAssign::LocInfo LocInfo,
                      ISD::ArgFlagsTy ArgFlags, CCState &State);
static bool RetCC_X86Common(unsigned ValNo, EVT ValVT,
                            EVT LocVT, CCValAssign::LocInfo LocInfo,
                            ISD::ArgFlagsTy ArgFlags, CCState &State);
static bool RetCC_X86_32(unsigned ValNo, EVT ValVT,
                         EVT LocVT, CCValAssign::LocInfo LocInfo,
                         ISD::ArgFlagsTy ArgFlags, CCState &State);
static bool RetCC_X86_32_C(unsigned ValNo, EVT ValVT,
                           EVT LocVT, CCValAssign::LocInfo LocInfo,
                           ISD::ArgFlagsTy ArgFlags, CCState &State);
static bool RetCC_X86_32_Fast(unsigned ValNo, EVT ValVT,
                              EVT LocVT, CCValAssign::LocInfo LocInfo,
                              ISD::ArgFlagsTy ArgFlags, CCState &State);
static bool RetCC_X86_64(unsigned ValNo, EVT ValVT,
                         EVT LocVT, CCValAssign::LocInfo LocInfo,
                         ISD::ArgFlagsTy ArgFlags, CCState &State);
static bool RetCC_X86_64_C(unsigned ValNo, EVT ValVT,
                           EVT LocVT, CCValAssign::LocInfo LocInfo,
                           ISD::ArgFlagsTy ArgFlags, CCState &State);
static bool RetCC_X86_Win64_C(unsigned ValNo, EVT ValVT,
                              EVT LocVT, CCValAssign::LocInfo LocInfo,
                              ISD::ArgFlagsTy ArgFlags, CCState &State);


static bool CC_X86_32_C(unsigned ValNo, EVT ValVT,
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

  if (ArgFlags.isNest()) {
    if (unsigned Reg = State.AllocateReg(X86::ECX)) {
      State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
      return false;
    }
  }

  if (!State.isVarArg()) {
    if (ArgFlags.isInReg()) {
      if (LocVT == MVT::i32) {
        static const unsigned RegList1[] = {
          X86::EAX, X86::EDX, X86::ECX
        };
        if (unsigned Reg = State.AllocateReg(RegList1, 3)) {
          State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
          return false;
        }
      }
    }
  }

  if (!CC_X86_32_Common(ValNo, ValVT, LocVT, LocInfo, ArgFlags, State))
    return false;

  return true;  // CC didn't match.
}


static bool CC_X86_32_Common(unsigned ValNo, EVT ValVT,
                             EVT LocVT, CCValAssign::LocInfo LocInfo,
                             ISD::ArgFlagsTy ArgFlags, CCState &State) {

  if (ArgFlags.isByVal()) {
    State.HandleByVal(ValNo, ValVT, LocVT, LocInfo, 4, 4, ArgFlags);
    return false;
  }

  if (!State.isVarArg()) {
    if (ArgFlags.isInReg()) {
      if (LocVT == MVT::f32 ||
          LocVT == MVT::f64) {
        if (State.getTarget().getSubtarget<X86Subtarget>().hasSSE2()) {
          static const unsigned RegList1[] = {
            X86::XMM0, X86::XMM1, X86::XMM2
          };
          if (unsigned Reg = State.AllocateReg(RegList1, 3)) {
            State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
            return false;
          }
        }
      }
    }
  }

  if (!State.isVarArg()) {
    if (LocVT == MVT::v8i8 ||
        LocVT == MVT::v4i16 ||
        LocVT == MVT::v2i32) {
      static const unsigned RegList2[] = {
        X86::MM0, X86::MM1, X86::MM2
      };
      if (unsigned Reg = State.AllocateReg(RegList2, 3)) {
        State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
        return false;
      }
    }
  }

  if (LocVT == MVT::i32 ||
      LocVT == MVT::f32) {
    unsigned Offset3 = State.AllocateStack(4, 4);
    State.addLoc(CCValAssign::getMem(ValNo, ValVT, Offset3, LocVT, LocInfo));
    return false;
  }

  if (LocVT == MVT::f64) {
    unsigned Offset4 = State.AllocateStack(8, 4);
    State.addLoc(CCValAssign::getMem(ValNo, ValVT, Offset4, LocVT, LocInfo));
    return false;
  }

  if (LocVT == MVT::f80) {
    unsigned Offset5 = State.AllocateStack(
      State.getTarget().getTargetData()->getTypeAllocSize(LocVT.getTypeForEVT(State.getContext())), 4);
    State.addLoc(CCValAssign::getMem(ValNo, ValVT, Offset5, LocVT, LocInfo));
    return false;
  }

  if (!State.isVarArg()) {
    if (LocVT == MVT::v16i8 ||
        LocVT == MVT::v8i16 ||
        LocVT == MVT::v4i32 ||
        LocVT == MVT::v2i64 ||
        LocVT == MVT::v4f32 ||
        LocVT == MVT::v2f64) {
      static const unsigned RegList6[] = {
        X86::XMM0, X86::XMM1, X86::XMM2, X86::XMM3
      };
      if (unsigned Reg = State.AllocateReg(RegList6, 4)) {
        State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
        return false;
      }
    }
  }

  if (!State.isVarArg()) {
    if (LocVT == MVT::v32i8 ||
        LocVT == MVT::v16i16 ||
        LocVT == MVT::v8i32 ||
        LocVT == MVT::v4i64 ||
        LocVT == MVT::v8f32 ||
        LocVT == MVT::v4f64) {
      if (State.getTarget().getSubtarget<X86Subtarget>().hasAVX()) {
        static const unsigned RegList7[] = {
          X86::YMM0, X86::YMM1, X86::YMM2, X86::YMM3
        };
        if (unsigned Reg = State.AllocateReg(RegList7, 4)) {
          State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
          return false;
        }
      }
    }
  }

  if (LocVT == MVT::v16i8 ||
      LocVT == MVT::v8i16 ||
      LocVT == MVT::v4i32 ||
      LocVT == MVT::v2i64 ||
      LocVT == MVT::v4f32 ||
      LocVT == MVT::v2f64) {
    unsigned Offset8 = State.AllocateStack(16, 16);
    State.addLoc(CCValAssign::getMem(ValNo, ValVT, Offset8, LocVT, LocInfo));
    return false;
  }

  if (LocVT == MVT::v32i8 ||
      LocVT == MVT::v16i16 ||
      LocVT == MVT::v8i32 ||
      LocVT == MVT::v4i64 ||
      LocVT == MVT::v8f32 ||
      LocVT == MVT::v4f64) {
    unsigned Offset9 = State.AllocateStack(32, 32);
    State.addLoc(CCValAssign::getMem(ValNo, ValVT, Offset9, LocVT, LocInfo));
    return false;
  }

  if (LocVT == MVT::v8i8 ||
      LocVT == MVT::v4i16 ||
      LocVT == MVT::v2i32 ||
      LocVT == MVT::v1i64) {
    unsigned Offset10 = State.AllocateStack(8, 4);
    State.addLoc(CCValAssign::getMem(ValNo, ValVT, Offset10, LocVT, LocInfo));
    return false;
  }

  return true;  // CC didn't match.
}


static bool CC_X86_32_FastCC(unsigned ValNo, EVT ValVT,
                             EVT LocVT, CCValAssign::LocInfo LocInfo,
                             ISD::ArgFlagsTy ArgFlags, CCState &State) {

  if (ArgFlags.isByVal()) {
    State.HandleByVal(ValNo, ValVT, LocVT, LocInfo, 4, 4, ArgFlags);
    return false;
  }

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

  if (ArgFlags.isNest()) {
    if (unsigned Reg = State.AllocateReg(X86::EAX)) {
      State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
      return false;
    }
  }

  if (LocVT == MVT::i32) {
    static const unsigned RegList1[] = {
      X86::ECX, X86::EDX
    };
    if (unsigned Reg = State.AllocateReg(RegList1, 2)) {
      State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
      return false;
    }
  }

  if (!State.isVarArg()) {
    if (LocVT == MVT::f32 ||
        LocVT == MVT::f64) {
      if (State.getTarget().getSubtarget<X86Subtarget>().hasSSE2()) {
        static const unsigned RegList2[] = {
          X86::XMM0, X86::XMM1, X86::XMM2
        };
        if (unsigned Reg = State.AllocateReg(RegList2, 3)) {
          State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
          return false;
        }
      }
    }
  }

  if (LocVT == MVT::f64) {
    unsigned Offset3 = State.AllocateStack(8, 8);
    State.addLoc(CCValAssign::getMem(ValNo, ValVT, Offset3, LocVT, LocInfo));
    return false;
  }

  if (!CC_X86_32_Common(ValNo, ValVT, LocVT, LocInfo, ArgFlags, State))
    return false;

  return true;  // CC didn't match.
}


static bool CC_X86_32_FastCall(unsigned ValNo, EVT ValVT,
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

  if (ArgFlags.isNest()) {
    if (unsigned Reg = State.AllocateReg(X86::EAX)) {
      State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
      return false;
    }
  }

  if (LocVT == MVT::i32) {
    static const unsigned RegList1[] = {
      X86::ECX, X86::EDX
    };
    if (unsigned Reg = State.AllocateReg(RegList1, 2)) {
      State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
      return false;
    }
  }

  if (!CC_X86_32_Common(ValNo, ValVT, LocVT, LocInfo, ArgFlags, State))
    return false;

  return true;  // CC didn't match.
}


static bool CC_X86_32_GHC(unsigned ValNo, EVT ValVT,
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
    static const unsigned RegList1[] = {
      X86::EBX, X86::EBP, X86::EDI, X86::ESI
    };
    if (unsigned Reg = State.AllocateReg(RegList1, 4)) {
      State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
      return false;
    }
  }

  return true;  // CC didn't match.
}


static bool CC_X86_32_ThisCall(unsigned ValNo, EVT ValVT,
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

  if (ArgFlags.isNest()) {
    if (unsigned Reg = State.AllocateReg(X86::EAX)) {
      State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
      return false;
    }
  }

  if (LocVT == MVT::i32) {
    if (unsigned Reg = State.AllocateReg(X86::ECX)) {
      State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
      return false;
    }
  }

  if (!CC_X86_32_Common(ValNo, ValVT, LocVT, LocInfo, ArgFlags, State))
    return false;

  return true;  // CC didn't match.
}


static bool CC_X86_64_C(unsigned ValNo, EVT ValVT,
                        EVT LocVT, CCValAssign::LocInfo LocInfo,
                        ISD::ArgFlagsTy ArgFlags, CCState &State) {

  if (ArgFlags.isByVal()) {
    State.HandleByVal(ValNo, ValVT, LocVT, LocInfo, 8, 8, ArgFlags);
    return false;
  }

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

  if (ArgFlags.isNest()) {
    if (unsigned Reg = State.AllocateReg(X86::R10)) {
      State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
      return false;
    }
  }

  if (LocVT == MVT::v1i64) {
    if (State.getTarget().getSubtarget<X86Subtarget>().isTargetDarwin()) {
      LocVT = MVT::i64;
      LocInfo = CCValAssign::BCvt;
    }
  }

  if (LocVT == MVT::i32) {
    static const unsigned RegList1[] = {
      X86::EDI, X86::ESI, X86::EDX, X86::ECX, X86::R8D, X86::R9D
    };
    if (unsigned Reg = State.AllocateReg(RegList1, 6)) {
      State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
      return false;
    }
  }

  if (LocVT == MVT::i64) {
    static const unsigned RegList2[] = {
      X86::RDI, X86::RSI, X86::RDX, X86::RCX, X86::R8, X86::R9
    };
    if (unsigned Reg = State.AllocateReg(RegList2, 6)) {
      State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
      return false;
    }
  }

  if (LocVT == MVT::v8i8 ||
      LocVT == MVT::v4i16 ||
      LocVT == MVT::v2i32) {
    if (State.getTarget().getSubtarget<X86Subtarget>().isTargetDarwin()) {
      if (State.getTarget().getSubtarget<X86Subtarget>().hasSSE2()) {
        LocVT = MVT::v2i64;
        if (ArgFlags.isSExt())
                LocInfo = CCValAssign::SExt;
        else if (ArgFlags.isZExt())
                LocInfo = CCValAssign::ZExt;
        else
                LocInfo = CCValAssign::AExt;
      }
    }
  }

  if (LocVT == MVT::f32 ||
      LocVT == MVT::f64 ||
      LocVT == MVT::v16i8 ||
      LocVT == MVT::v8i16 ||
      LocVT == MVT::v4i32 ||
      LocVT == MVT::v2i64 ||
      LocVT == MVT::v4f32 ||
      LocVT == MVT::v2f64) {
    if (State.getTarget().getSubtarget<X86Subtarget>().hasSSE1()) {
      static const unsigned RegList3[] = {
        X86::XMM0, X86::XMM1, X86::XMM2, X86::XMM3, X86::XMM4, X86::XMM5, X86::XMM6, X86::XMM7
      };
      if (unsigned Reg = State.AllocateReg(RegList3, 8)) {
        State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
        return false;
      }
    }
  }

  if (LocVT == MVT::v32i8 ||
      LocVT == MVT::v16i16 ||
      LocVT == MVT::v8i32 ||
      LocVT == MVT::v4i64 ||
      LocVT == MVT::v8f32 ||
      LocVT == MVT::v4f64) {
    if (State.getTarget().getSubtarget<X86Subtarget>().hasAVX()) {
      static const unsigned RegList4[] = {
        X86::YMM0, X86::YMM1, X86::YMM2, X86::YMM3, X86::YMM4, X86::YMM5, X86::YMM6, X86::YMM7
      };
      if (unsigned Reg = State.AllocateReg(RegList4, 8)) {
        State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
        return false;
      }
    }
  }

  if (LocVT == MVT::i32 ||
      LocVT == MVT::i64 ||
      LocVT == MVT::f32 ||
      LocVT == MVT::f64) {
    unsigned Offset5 = State.AllocateStack(8, 8);
    State.addLoc(CCValAssign::getMem(ValNo, ValVT, Offset5, LocVT, LocInfo));
    return false;
  }

  if (LocVT == MVT::f80) {
    unsigned Offset6 = State.AllocateStack(
      State.getTarget().getTargetData()->getTypeAllocSize(LocVT.getTypeForEVT(State.getContext())), 
      State.getTarget().getTargetData()->getABITypeAlignment(LocVT.getTypeForEVT(State.getContext())));
    State.addLoc(CCValAssign::getMem(ValNo, ValVT, Offset6, LocVT, LocInfo));
    return false;
  }

  if (LocVT == MVT::v16i8 ||
      LocVT == MVT::v8i16 ||
      LocVT == MVT::v4i32 ||
      LocVT == MVT::v2i64 ||
      LocVT == MVT::v4f32 ||
      LocVT == MVT::v2f64) {
    unsigned Offset7 = State.AllocateStack(16, 16);
    State.addLoc(CCValAssign::getMem(ValNo, ValVT, Offset7, LocVT, LocInfo));
    return false;
  }

  if (LocVT == MVT::v32i8 ||
      LocVT == MVT::v16i16 ||
      LocVT == MVT::v8i32 ||
      LocVT == MVT::v4i64 ||
      LocVT == MVT::v8f32 ||
      LocVT == MVT::v4f64) {
    unsigned Offset8 = State.AllocateStack(32, 32);
    State.addLoc(CCValAssign::getMem(ValNo, ValVT, Offset8, LocVT, LocInfo));
    return false;
  }

  if (LocVT == MVT::v8i8 ||
      LocVT == MVT::v4i16 ||
      LocVT == MVT::v2i32 ||
      LocVT == MVT::v1i64) {
    unsigned Offset9 = State.AllocateStack(8, 8);
    State.addLoc(CCValAssign::getMem(ValNo, ValVT, Offset9, LocVT, LocInfo));
    return false;
  }

  return true;  // CC didn't match.
}


static bool CC_X86_64_GHC(unsigned ValNo, EVT ValVT,
                          EVT LocVT, CCValAssign::LocInfo LocInfo,
                          ISD::ArgFlagsTy ArgFlags, CCState &State) {

  if (LocVT == MVT::i8 ||
      LocVT == MVT::i16 ||
      LocVT == MVT::i32) {
    LocVT = MVT::i64;
    if (ArgFlags.isSExt())
        LocInfo = CCValAssign::SExt;
    else if (ArgFlags.isZExt())
        LocInfo = CCValAssign::ZExt;
    else
        LocInfo = CCValAssign::AExt;
  }

  if (LocVT == MVT::i64) {
    static const unsigned RegList1[] = {
      X86::R13, X86::RBP, X86::R12, X86::RBX, X86::R14, X86::RSI, X86::RDI, X86::R8, X86::R9, X86::R15
    };
    if (unsigned Reg = State.AllocateReg(RegList1, 10)) {
      State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
      return false;
    }
  }

  if (LocVT == MVT::f32 ||
      LocVT == MVT::f64 ||
      LocVT == MVT::v16i8 ||
      LocVT == MVT::v8i16 ||
      LocVT == MVT::v4i32 ||
      LocVT == MVT::v2i64 ||
      LocVT == MVT::v4f32 ||
      LocVT == MVT::v2f64) {
    if (State.getTarget().getSubtarget<X86Subtarget>().hasSSE1()) {
      static const unsigned RegList2[] = {
        X86::XMM1, X86::XMM2, X86::XMM3, X86::XMM4, X86::XMM5, X86::XMM6
      };
      if (unsigned Reg = State.AllocateReg(RegList2, 6)) {
        State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
        return false;
      }
    }
  }

  return true;  // CC didn't match.
}


static bool CC_X86_Win64_C(unsigned ValNo, EVT ValVT,
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

  if (ArgFlags.isNest()) {
    if (unsigned Reg = State.AllocateReg(X86::R10)) {
      State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
      return false;
    }
  }

  if (LocVT == MVT::v16i8 ||
      LocVT == MVT::v8i16 ||
      LocVT == MVT::v4i32 ||
      LocVT == MVT::v2i64 ||
      LocVT == MVT::v4f32 ||
      LocVT == MVT::v2f64) {
    LocVT = MVT::i64;
    LocInfo = CCValAssign::Indirect;
  }

  if (LocVT == MVT::v8i8 ||
      LocVT == MVT::v4i16 ||
      LocVT == MVT::v2i32 ||
      LocVT == MVT::v1i64) {
    LocVT = MVT::i64;
    LocInfo = CCValAssign::BCvt;
  }

  if (LocVT == MVT::i32) {
    static const unsigned RegList1[] = {
      X86::ECX, X86::EDX, X86::R8D, X86::R9D
    };
    static const unsigned RegList2[] = {
      X86::XMM0, X86::XMM1, X86::XMM2, X86::XMM3
    };
    if (unsigned Reg = State.AllocateReg(RegList1, RegList2, 4)) {
      State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
      return false;
    }
  }

  if (LocVT == MVT::i64) {
    static const unsigned RegList3[] = {
      X86::RCX, X86::RDX, X86::R8, X86::R9
    };
    static const unsigned RegList4[] = {
      X86::XMM0, X86::XMM1, X86::XMM2, X86::XMM3
    };
    if (unsigned Reg = State.AllocateReg(RegList3, RegList4, 4)) {
      State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
      return false;
    }
  }

  if (LocVT == MVT::f32 ||
      LocVT == MVT::f64 ||
      LocVT == MVT::v16i8 ||
      LocVT == MVT::v8i16 ||
      LocVT == MVT::v4i32 ||
      LocVT == MVT::v2i64 ||
      LocVT == MVT::v4f32 ||
      LocVT == MVT::v2f64) {
    static const unsigned RegList5[] = {
      X86::XMM0, X86::XMM1, X86::XMM2, X86::XMM3
    };
    static const unsigned RegList6[] = {
      X86::RCX, X86::RDX, X86::R8, X86::R9
    };
    if (unsigned Reg = State.AllocateReg(RegList5, RegList6, 4)) {
      State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
      return false;
    }
  }

  if (LocVT == MVT::i32 ||
      LocVT == MVT::i64 ||
      LocVT == MVT::f32 ||
      LocVT == MVT::f64) {
    unsigned Offset7 = State.AllocateStack(8, 8);
    State.addLoc(CCValAssign::getMem(ValNo, ValVT, Offset7, LocVT, LocInfo));
    return false;
  }

  if (LocVT == MVT::f80) {
    unsigned Offset8 = State.AllocateStack(
      State.getTarget().getTargetData()->getTypeAllocSize(LocVT.getTypeForEVT(State.getContext())), 
      State.getTarget().getTargetData()->getABITypeAlignment(LocVT.getTypeForEVT(State.getContext())));
    State.addLoc(CCValAssign::getMem(ValNo, ValVT, Offset8, LocVT, LocInfo));
    return false;
  }

  if (LocVT == MVT::v8i8 ||
      LocVT == MVT::v4i16 ||
      LocVT == MVT::v2i32 ||
      LocVT == MVT::v1i64) {
    unsigned Offset9 = State.AllocateStack(8, 8);
    State.addLoc(CCValAssign::getMem(ValNo, ValVT, Offset9, LocVT, LocInfo));
    return false;
  }

  return true;  // CC didn't match.
}


static bool RetCC_X86(unsigned ValNo, EVT ValVT,
                      EVT LocVT, CCValAssign::LocInfo LocInfo,
                      ISD::ArgFlagsTy ArgFlags, CCState &State) {

  if (State.getTarget().getSubtarget<X86Subtarget>().is64Bit()) {
    if (!RetCC_X86_64(ValNo, ValVT, LocVT, LocInfo, ArgFlags, State))
      return false;
  }

  if (!RetCC_X86_32(ValNo, ValVT, LocVT, LocInfo, ArgFlags, State))
    return false;

  return true;  // CC didn't match.
}


static bool RetCC_X86Common(unsigned ValNo, EVT ValVT,
                            EVT LocVT, CCValAssign::LocInfo LocInfo,
                            ISD::ArgFlagsTy ArgFlags, CCState &State) {

  if (LocVT == MVT::i8) {
    static const unsigned RegList1[] = {
      X86::AL, X86::DL
    };
    if (unsigned Reg = State.AllocateReg(RegList1, 2)) {
      State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
      return false;
    }
  }

  if (LocVT == MVT::i16) {
    static const unsigned RegList2[] = {
      X86::AX, X86::DX
    };
    if (unsigned Reg = State.AllocateReg(RegList2, 2)) {
      State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
      return false;
    }
  }

  if (LocVT == MVT::i32) {
    static const unsigned RegList3[] = {
      X86::EAX, X86::EDX
    };
    if (unsigned Reg = State.AllocateReg(RegList3, 2)) {
      State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
      return false;
    }
  }

  if (LocVT == MVT::i64) {
    static const unsigned RegList4[] = {
      X86::RAX, X86::RDX
    };
    if (unsigned Reg = State.AllocateReg(RegList4, 2)) {
      State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
      return false;
    }
  }

  if (LocVT == MVT::v16i8 ||
      LocVT == MVT::v8i16 ||
      LocVT == MVT::v4i32 ||
      LocVT == MVT::v2i64 ||
      LocVT == MVT::v4f32 ||
      LocVT == MVT::v2f64) {
    static const unsigned RegList5[] = {
      X86::XMM0, X86::XMM1, X86::XMM2, X86::XMM3
    };
    if (unsigned Reg = State.AllocateReg(RegList5, 4)) {
      State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
      return false;
    }
  }

  if (LocVT == MVT::v32i8 ||
      LocVT == MVT::v16i16 ||
      LocVT == MVT::v8i32 ||
      LocVT == MVT::v4i64 ||
      LocVT == MVT::v8f32 ||
      LocVT == MVT::v4f64) {
    if (State.getTarget().getSubtarget<X86Subtarget>().hasAVX()) {
      static const unsigned RegList6[] = {
        X86::YMM0, X86::YMM1, X86::YMM2, X86::YMM3
      };
      if (unsigned Reg = State.AllocateReg(RegList6, 4)) {
        State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
        return false;
      }
    }
  }

  if (LocVT == MVT::v8i8 ||
      LocVT == MVT::v4i16 ||
      LocVT == MVT::v2i32 ||
      LocVT == MVT::v1i64) {
    if (unsigned Reg = State.AllocateReg(X86::MM0)) {
      State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
      return false;
    }
  }

  if (LocVT == MVT::f80) {
    static const unsigned RegList7[] = {
      X86::ST0, X86::ST1
    };
    if (unsigned Reg = State.AllocateReg(RegList7, 2)) {
      State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
      return false;
    }
  }

  return true;  // CC didn't match.
}


static bool RetCC_X86_32(unsigned ValNo, EVT ValVT,
                         EVT LocVT, CCValAssign::LocInfo LocInfo,
                         ISD::ArgFlagsTy ArgFlags, CCState &State) {

  if (State.getCallingConv() == CallingConv::Fast) {
    if (!RetCC_X86_32_Fast(ValNo, ValVT, LocVT, LocInfo, ArgFlags, State))
      return false;
  }

  if (!RetCC_X86_32_C(ValNo, ValVT, LocVT, LocInfo, ArgFlags, State))
    return false;

  return true;  // CC didn't match.
}


static bool RetCC_X86_32_C(unsigned ValNo, EVT ValVT,
                           EVT LocVT, CCValAssign::LocInfo LocInfo,
                           ISD::ArgFlagsTy ArgFlags, CCState &State) {

  if (ArgFlags.isInReg()) {
    if (State.getTarget().getSubtarget<X86Subtarget>().hasSSE2()) {
      if (LocVT == MVT::f32 ||
          LocVT == MVT::f64) {
        static const unsigned RegList1[] = {
          X86::XMM0, X86::XMM1, X86::XMM2
        };
        if (unsigned Reg = State.AllocateReg(RegList1, 3)) {
          State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
          return false;
        }
      }
    }
  }

  if (LocVT == MVT::f32 ||
      LocVT == MVT::f64) {
    static const unsigned RegList2[] = {
      X86::ST0, X86::ST1
    };
    if (unsigned Reg = State.AllocateReg(RegList2, 2)) {
      State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
      return false;
    }
  }

  if (!RetCC_X86Common(ValNo, ValVT, LocVT, LocInfo, ArgFlags, State))
    return false;

  return true;  // CC didn't match.
}


static bool RetCC_X86_32_Fast(unsigned ValNo, EVT ValVT,
                              EVT LocVT, CCValAssign::LocInfo LocInfo,
                              ISD::ArgFlagsTy ArgFlags, CCState &State) {

  if (LocVT == MVT::f32) {
    if (State.getTarget().getSubtarget<X86Subtarget>().hasSSE2()) {
      static const unsigned RegList1[] = {
        X86::XMM0, X86::XMM1, X86::XMM2
      };
      if (unsigned Reg = State.AllocateReg(RegList1, 3)) {
        State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
        return false;
      }
    }
  }

  if (LocVT == MVT::f64) {
    if (State.getTarget().getSubtarget<X86Subtarget>().hasSSE2()) {
      static const unsigned RegList2[] = {
        X86::XMM0, X86::XMM1, X86::XMM2
      };
      if (unsigned Reg = State.AllocateReg(RegList2, 3)) {
        State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
        return false;
      }
    }
  }

  if (LocVT == MVT::i8) {
    static const unsigned RegList3[] = {
      X86::AL, X86::DL, X86::CL
    };
    if (unsigned Reg = State.AllocateReg(RegList3, 3)) {
      State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
      return false;
    }
  }

  if (LocVT == MVT::i16) {
    static const unsigned RegList4[] = {
      X86::AX, X86::DX, X86::CX
    };
    if (unsigned Reg = State.AllocateReg(RegList4, 3)) {
      State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
      return false;
    }
  }

  if (LocVT == MVT::i32) {
    static const unsigned RegList5[] = {
      X86::EAX, X86::EDX, X86::ECX
    };
    if (unsigned Reg = State.AllocateReg(RegList5, 3)) {
      State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
      return false;
    }
  }

  if (!RetCC_X86Common(ValNo, ValVT, LocVT, LocInfo, ArgFlags, State))
    return false;

  return true;  // CC didn't match.
}


static bool RetCC_X86_64(unsigned ValNo, EVT ValVT,
                         EVT LocVT, CCValAssign::LocInfo LocInfo,
                         ISD::ArgFlagsTy ArgFlags, CCState &State) {

  if (State.getTarget().getSubtarget<X86Subtarget>().isTargetWin64()) {
    if (!RetCC_X86_Win64_C(ValNo, ValVT, LocVT, LocInfo, ArgFlags, State))
      return false;
  }

  if (!RetCC_X86_64_C(ValNo, ValVT, LocVT, LocInfo, ArgFlags, State))
    return false;

  return true;  // CC didn't match.
}


static bool RetCC_X86_64_C(unsigned ValNo, EVT ValVT,
                           EVT LocVT, CCValAssign::LocInfo LocInfo,
                           ISD::ArgFlagsTy ArgFlags, CCState &State) {

  if (LocVT == MVT::f32) {
    static const unsigned RegList1[] = {
      X86::XMM0, X86::XMM1
    };
    if (unsigned Reg = State.AllocateReg(RegList1, 2)) {
      State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
      return false;
    }
  }

  if (LocVT == MVT::f64) {
    static const unsigned RegList2[] = {
      X86::XMM0, X86::XMM1
    };
    if (unsigned Reg = State.AllocateReg(RegList2, 2)) {
      State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
      return false;
    }
  }

  if (LocVT == MVT::v1i64) {
    if (unsigned Reg = State.AllocateReg(X86::RAX)) {
      State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
      return false;
    }
  }

  if (LocVT == MVT::v8i8 ||
      LocVT == MVT::v4i16 ||
      LocVT == MVT::v2i32) {
    static const unsigned RegList3[] = {
      X86::XMM0, X86::XMM1
    };
    if (unsigned Reg = State.AllocateReg(RegList3, 2)) {
      State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
      return false;
    }
  }

  if (!RetCC_X86Common(ValNo, ValVT, LocVT, LocInfo, ArgFlags, State))
    return false;

  return true;  // CC didn't match.
}


static bool RetCC_X86_Win64_C(unsigned ValNo, EVT ValVT,
                              EVT LocVT, CCValAssign::LocInfo LocInfo,
                              ISD::ArgFlagsTy ArgFlags, CCState &State) {

  if (LocVT == MVT::v8i8 ||
      LocVT == MVT::v4i16 ||
      LocVT == MVT::v2i32 ||
      LocVT == MVT::v1i64) {
    LocVT = MVT::i64;
    LocInfo = CCValAssign::BCvt;
  }

  if (LocVT == MVT::f32) {
    if (unsigned Reg = State.AllocateReg(X86::XMM0)) {
      State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
      return false;
    }
  }

  if (LocVT == MVT::f64) {
    if (unsigned Reg = State.AllocateReg(X86::XMM0)) {
      State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
      return false;
    }
  }

  if (!RetCC_X86_64_C(ValNo, ValVT, LocVT, LocInfo, ArgFlags, State))
    return false;

  return true;  // CC didn't match.
}
