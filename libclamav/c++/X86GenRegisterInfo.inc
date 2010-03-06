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
    X86::EFLAGS, 
  };

  // CONTROL_REG_32 Register Class...
  static const unsigned CONTROL_REG_32[] = {
    X86::ECR0, X86::ECR1, X86::ECR2, X86::ECR3, X86::ECR4, X86::ECR5, X86::ECR6, X86::ECR7, 
  };

  // CONTROL_REG_64 Register Class...
  static const unsigned CONTROL_REG_64[] = {
    X86::RCR0, X86::RCR1, X86::RCR2, X86::RCR3, X86::RCR4, X86::RCR5, X86::RCR6, X86::RCR7, X86::RCR8, 
  };

  // DEBUG_REG Register Class...
  static const unsigned DEBUG_REG[] = {
    X86::DR0, X86::DR1, X86::DR2, X86::DR3, X86::DR4, X86::DR5, X86::DR6, X86::DR7, 
  };

  // FR32 Register Class...
  static const unsigned FR32[] = {
    X86::XMM0, X86::XMM1, X86::XMM2, X86::XMM3, X86::XMM4, X86::XMM5, X86::XMM6, X86::XMM7, X86::XMM8, X86::XMM9, X86::XMM10, X86::XMM11, X86::XMM12, X86::XMM13, X86::XMM14, X86::XMM15, 
  };

  // FR64 Register Class...
  static const unsigned FR64[] = {
    X86::XMM0, X86::XMM1, X86::XMM2, X86::XMM3, X86::XMM4, X86::XMM5, X86::XMM6, X86::XMM7, X86::XMM8, X86::XMM9, X86::XMM10, X86::XMM11, X86::XMM12, X86::XMM13, X86::XMM14, X86::XMM15, 
  };

  // GR16 Register Class...
  static const unsigned GR16[] = {
    X86::AX, X86::CX, X86::DX, X86::SI, X86::DI, X86::BX, X86::BP, X86::SP, X86::R8W, X86::R9W, X86::R10W, X86::R11W, X86::R14W, X86::R15W, X86::R12W, X86::R13W, 
  };

  // GR16_ABCD Register Class...
  static const unsigned GR16_ABCD[] = {
    X86::AX, X86::CX, X86::DX, X86::BX, 
  };

  // GR16_NOREX Register Class...
  static const unsigned GR16_NOREX[] = {
    X86::AX, X86::CX, X86::DX, X86::SI, X86::DI, X86::BX, X86::BP, X86::SP, 
  };

  // GR32 Register Class...
  static const unsigned GR32[] = {
    X86::EAX, X86::ECX, X86::EDX, X86::ESI, X86::EDI, X86::EBX, X86::EBP, X86::ESP, X86::R8D, X86::R9D, X86::R10D, X86::R11D, X86::R14D, X86::R15D, X86::R12D, X86::R13D, 
  };

  // GR32_ABCD Register Class...
  static const unsigned GR32_ABCD[] = {
    X86::EAX, X86::ECX, X86::EDX, X86::EBX, 
  };

  // GR32_AD Register Class...
  static const unsigned GR32_AD[] = {
    X86::EAX, X86::EDX, 
  };

  // GR32_NOREX Register Class...
  static const unsigned GR32_NOREX[] = {
    X86::EAX, X86::ECX, X86::EDX, X86::ESI, X86::EDI, X86::EBX, X86::EBP, X86::ESP, 
  };

  // GR32_NOSP Register Class...
  static const unsigned GR32_NOSP[] = {
    X86::EAX, X86::ECX, X86::EDX, X86::ESI, X86::EDI, X86::EBX, X86::EBP, X86::R8D, X86::R9D, X86::R10D, X86::R11D, X86::R14D, X86::R15D, X86::R12D, X86::R13D, 
  };

  // GR64 Register Class...
  static const unsigned GR64[] = {
    X86::RAX, X86::RCX, X86::RDX, X86::RSI, X86::RDI, X86::R8, X86::R9, X86::R10, X86::R11, X86::RBX, X86::R14, X86::R15, X86::R12, X86::R13, X86::RBP, X86::RSP, X86::RIP, 
  };

  // GR64_ABCD Register Class...
  static const unsigned GR64_ABCD[] = {
    X86::RAX, X86::RCX, X86::RDX, X86::RBX, 
  };

  // GR64_NOREX Register Class...
  static const unsigned GR64_NOREX[] = {
    X86::RAX, X86::RCX, X86::RDX, X86::RSI, X86::RDI, X86::RBX, X86::RBP, X86::RSP, X86::RIP, 
  };

  // GR64_NOREX_NOSP Register Class...
  static const unsigned GR64_NOREX_NOSP[] = {
    X86::RAX, X86::RCX, X86::RDX, X86::RSI, X86::RDI, X86::RBX, X86::RBP, 
  };

  // GR64_NOSP Register Class...
  static const unsigned GR64_NOSP[] = {
    X86::RAX, X86::RCX, X86::RDX, X86::RSI, X86::RDI, X86::R8, X86::R9, X86::R10, X86::R11, X86::RBX, X86::R14, X86::R15, X86::R12, X86::R13, X86::RBP, 
  };

  // GR8 Register Class...
  static const unsigned GR8[] = {
    X86::AL, X86::CL, X86::DL, X86::AH, X86::CH, X86::DH, X86::BL, X86::BH, X86::SIL, X86::DIL, X86::BPL, X86::SPL, X86::R8B, X86::R9B, X86::R10B, X86::R11B, X86::R14B, X86::R15B, X86::R12B, X86::R13B, 
  };

  // GR8_ABCD_H Register Class...
  static const unsigned GR8_ABCD_H[] = {
    X86::AH, X86::CH, X86::DH, X86::BH, 
  };

  // GR8_ABCD_L Register Class...
  static const unsigned GR8_ABCD_L[] = {
    X86::AL, X86::CL, X86::DL, X86::BL, 
  };

  // GR8_NOREX Register Class...
  static const unsigned GR8_NOREX[] = {
    X86::AL, X86::CL, X86::DL, X86::AH, X86::CH, X86::DH, X86::BL, X86::BH, 
  };

  // RFP32 Register Class...
  static const unsigned RFP32[] = {
    X86::FP0, X86::FP1, X86::FP2, X86::FP3, X86::FP4, X86::FP5, X86::FP6, 
  };

  // RFP64 Register Class...
  static const unsigned RFP64[] = {
    X86::FP0, X86::FP1, X86::FP2, X86::FP3, X86::FP4, X86::FP5, X86::FP6, 
  };

  // RFP80 Register Class...
  static const unsigned RFP80[] = {
    X86::FP0, X86::FP1, X86::FP2, X86::FP3, X86::FP4, X86::FP5, X86::FP6, 
  };

  // RST Register Class...
  static const unsigned RST[] = {
    X86::ST0, X86::ST1, X86::ST2, X86::ST3, X86::ST4, X86::ST5, X86::ST6, X86::ST7, 
  };

  // SEGMENT_REG Register Class...
  static const unsigned SEGMENT_REG[] = {
    X86::CS, X86::DS, X86::SS, X86::ES, X86::FS, X86::GS, 
  };

  // VR128 Register Class...
  static const unsigned VR128[] = {
    X86::XMM0, X86::XMM1, X86::XMM2, X86::XMM3, X86::XMM4, X86::XMM5, X86::XMM6, X86::XMM7, X86::XMM8, X86::XMM9, X86::XMM10, X86::XMM11, X86::XMM12, X86::XMM13, X86::XMM14, X86::XMM15, 
  };

  // VR256 Register Class...
  static const unsigned VR256[] = {
    X86::YMM0, X86::YMM1, X86::YMM2, X86::YMM3, X86::YMM4, X86::YMM5, X86::YMM6, X86::YMM7, X86::YMM8, X86::YMM9, X86::YMM10, X86::YMM11, X86::YMM12, X86::YMM13, X86::YMM14, X86::YMM15, 
  };

  // VR64 Register Class...
  static const unsigned VR64[] = {
    X86::MM0, X86::MM1, X86::MM2, X86::MM3, X86::MM4, X86::MM5, X86::MM6, X86::MM7, 
  };

  // CCRVTs Register Class Value Types...
  static const EVT CCRVTs[] = {
    MVT::i32, MVT::Other
  };

  // CONTROL_REG_32VTs Register Class Value Types...
  static const EVT CONTROL_REG_32VTs[] = {
    MVT::i32, MVT::Other
  };

  // CONTROL_REG_64VTs Register Class Value Types...
  static const EVT CONTROL_REG_64VTs[] = {
    MVT::i64, MVT::Other
  };

  // DEBUG_REGVTs Register Class Value Types...
  static const EVT DEBUG_REGVTs[] = {
    MVT::i32, MVT::Other
  };

  // FR32VTs Register Class Value Types...
  static const EVT FR32VTs[] = {
    MVT::f32, MVT::Other
  };

  // FR64VTs Register Class Value Types...
  static const EVT FR64VTs[] = {
    MVT::f64, MVT::Other
  };

  // GR16VTs Register Class Value Types...
  static const EVT GR16VTs[] = {
    MVT::i16, MVT::Other
  };

  // GR16_ABCDVTs Register Class Value Types...
  static const EVT GR16_ABCDVTs[] = {
    MVT::i16, MVT::Other
  };

  // GR16_NOREXVTs Register Class Value Types...
  static const EVT GR16_NOREXVTs[] = {
    MVT::i16, MVT::Other
  };

  // GR32VTs Register Class Value Types...
  static const EVT GR32VTs[] = {
    MVT::i32, MVT::Other
  };

  // GR32_ABCDVTs Register Class Value Types...
  static const EVT GR32_ABCDVTs[] = {
    MVT::i32, MVT::Other
  };

  // GR32_ADVTs Register Class Value Types...
  static const EVT GR32_ADVTs[] = {
    MVT::i32, MVT::Other
  };

  // GR32_NOREXVTs Register Class Value Types...
  static const EVT GR32_NOREXVTs[] = {
    MVT::i32, MVT::Other
  };

  // GR32_NOSPVTs Register Class Value Types...
  static const EVT GR32_NOSPVTs[] = {
    MVT::i32, MVT::Other
  };

  // GR64VTs Register Class Value Types...
  static const EVT GR64VTs[] = {
    MVT::i64, MVT::Other
  };

  // GR64_ABCDVTs Register Class Value Types...
  static const EVT GR64_ABCDVTs[] = {
    MVT::i64, MVT::Other
  };

  // GR64_NOREXVTs Register Class Value Types...
  static const EVT GR64_NOREXVTs[] = {
    MVT::i64, MVT::Other
  };

  // GR64_NOREX_NOSPVTs Register Class Value Types...
  static const EVT GR64_NOREX_NOSPVTs[] = {
    MVT::i64, MVT::Other
  };

  // GR64_NOSPVTs Register Class Value Types...
  static const EVT GR64_NOSPVTs[] = {
    MVT::i64, MVT::Other
  };

  // GR8VTs Register Class Value Types...
  static const EVT GR8VTs[] = {
    MVT::i8, MVT::Other
  };

  // GR8_ABCD_HVTs Register Class Value Types...
  static const EVT GR8_ABCD_HVTs[] = {
    MVT::i8, MVT::Other
  };

  // GR8_ABCD_LVTs Register Class Value Types...
  static const EVT GR8_ABCD_LVTs[] = {
    MVT::i8, MVT::Other
  };

  // GR8_NOREXVTs Register Class Value Types...
  static const EVT GR8_NOREXVTs[] = {
    MVT::i8, MVT::Other
  };

  // RFP32VTs Register Class Value Types...
  static const EVT RFP32VTs[] = {
    MVT::f32, MVT::Other
  };

  // RFP64VTs Register Class Value Types...
  static const EVT RFP64VTs[] = {
    MVT::f64, MVT::Other
  };

  // RFP80VTs Register Class Value Types...
  static const EVT RFP80VTs[] = {
    MVT::f80, MVT::Other
  };

  // RSTVTs Register Class Value Types...
  static const EVT RSTVTs[] = {
    MVT::f80, MVT::f64, MVT::f32, MVT::Other
  };

  // SEGMENT_REGVTs Register Class Value Types...
  static const EVT SEGMENT_REGVTs[] = {
    MVT::i16, MVT::Other
  };

  // VR128VTs Register Class Value Types...
  static const EVT VR128VTs[] = {
    MVT::v16i8, MVT::v8i16, MVT::v4i32, MVT::v2i64, MVT::v4f32, MVT::v2f64, MVT::Other
  };

  // VR256VTs Register Class Value Types...
  static const EVT VR256VTs[] = {
    MVT::v8i32, MVT::v4i64, MVT::v8f32, MVT::v4f64, MVT::Other
  };

  // VR64VTs Register Class Value Types...
  static const EVT VR64VTs[] = {
    MVT::v8i8, MVT::v4i16, MVT::v2i32, MVT::v1i64, MVT::v2f32, MVT::Other
  };

}  // end anonymous namespace

namespace X86 {   // Register class instances
  CCRClass	CCRRegClass;
  CONTROL_REG_32Class	CONTROL_REG_32RegClass;
  CONTROL_REG_64Class	CONTROL_REG_64RegClass;
  DEBUG_REGClass	DEBUG_REGRegClass;
  FR32Class	FR32RegClass;
  FR64Class	FR64RegClass;
  GR16Class	GR16RegClass;
  GR16_ABCDClass	GR16_ABCDRegClass;
  GR16_NOREXClass	GR16_NOREXRegClass;
  GR32Class	GR32RegClass;
  GR32_ABCDClass	GR32_ABCDRegClass;
  GR32_ADClass	GR32_ADRegClass;
  GR32_NOREXClass	GR32_NOREXRegClass;
  GR32_NOSPClass	GR32_NOSPRegClass;
  GR64Class	GR64RegClass;
  GR64_ABCDClass	GR64_ABCDRegClass;
  GR64_NOREXClass	GR64_NOREXRegClass;
  GR64_NOREX_NOSPClass	GR64_NOREX_NOSPRegClass;
  GR64_NOSPClass	GR64_NOSPRegClass;
  GR8Class	GR8RegClass;
  GR8_ABCD_HClass	GR8_ABCD_HRegClass;
  GR8_ABCD_LClass	GR8_ABCD_LRegClass;
  GR8_NOREXClass	GR8_NOREXRegClass;
  RFP32Class	RFP32RegClass;
  RFP64Class	RFP64RegClass;
  RFP80Class	RFP80RegClass;
  RSTClass	RSTRegClass;
  SEGMENT_REGClass	SEGMENT_REGRegClass;
  VR128Class	VR128RegClass;
  VR256Class	VR256RegClass;
  VR64Class	VR64RegClass;

  // CCR Sub-register Classes...
  static const TargetRegisterClass* const CCRSubRegClasses[] = {
    NULL
  };

  // CONTROL_REG_32 Sub-register Classes...
  static const TargetRegisterClass* const CONTROL_REG_32SubRegClasses[] = {
    NULL
  };

  // CONTROL_REG_64 Sub-register Classes...
  static const TargetRegisterClass* const CONTROL_REG_64SubRegClasses[] = {
    NULL
  };

  // DEBUG_REG Sub-register Classes...
  static const TargetRegisterClass* const DEBUG_REGSubRegClasses[] = {
    NULL
  };

  // FR32 Sub-register Classes...
  static const TargetRegisterClass* const FR32SubRegClasses[] = {
    NULL
  };

  // FR64 Sub-register Classes...
  static const TargetRegisterClass* const FR64SubRegClasses[] = {
    NULL
  };

  // GR16 Sub-register Classes...
  static const TargetRegisterClass* const GR16SubRegClasses[] = {
    &X86::GR8RegClass, &X86::GR8RegClass, NULL
  };

  // GR16_ABCD Sub-register Classes...
  static const TargetRegisterClass* const GR16_ABCDSubRegClasses[] = {
    &X86::GR8_ABCD_LRegClass, &X86::GR8_ABCD_HRegClass, NULL
  };

  // GR16_NOREX Sub-register Classes...
  static const TargetRegisterClass* const GR16_NOREXSubRegClasses[] = {
    &X86::GR8_NOREXRegClass, &X86::GR8_NOREXRegClass, NULL
  };

  // GR32 Sub-register Classes...
  static const TargetRegisterClass* const GR32SubRegClasses[] = {
    &X86::GR8RegClass, &X86::GR8RegClass, &X86::GR16RegClass, NULL
  };

  // GR32_ABCD Sub-register Classes...
  static const TargetRegisterClass* const GR32_ABCDSubRegClasses[] = {
    &X86::GR8_ABCD_LRegClass, &X86::GR8_ABCD_HRegClass, &X86::GR16_ABCDRegClass, NULL
  };

  // GR32_AD Sub-register Classes...
  static const TargetRegisterClass* const GR32_ADSubRegClasses[] = {
    &X86::GR8_ABCD_LRegClass, &X86::GR8_ABCD_HRegClass, &X86::GR16_ABCDRegClass, NULL
  };

  // GR32_NOREX Sub-register Classes...
  static const TargetRegisterClass* const GR32_NOREXSubRegClasses[] = {
    &X86::GR8_NOREXRegClass, &X86::GR8_NOREXRegClass, &X86::GR16_NOREXRegClass, NULL
  };

  // GR32_NOSP Sub-register Classes...
  static const TargetRegisterClass* const GR32_NOSPSubRegClasses[] = {
    &X86::GR8RegClass, &X86::GR8RegClass, &X86::GR16RegClass, NULL
  };

  // GR64 Sub-register Classes...
  static const TargetRegisterClass* const GR64SubRegClasses[] = {
    &X86::GR8RegClass, &X86::GR8RegClass, &X86::GR16RegClass, &X86::GR32RegClass, NULL
  };

  // GR64_ABCD Sub-register Classes...
  static const TargetRegisterClass* const GR64_ABCDSubRegClasses[] = {
    &X86::GR8_ABCD_LRegClass, &X86::GR8_ABCD_HRegClass, &X86::GR16_ABCDRegClass, &X86::GR32_ABCDRegClass, NULL
  };

  // GR64_NOREX Sub-register Classes...
  static const TargetRegisterClass* const GR64_NOREXSubRegClasses[] = {
    &X86::GR8_NOREXRegClass, &X86::GR8_NOREXRegClass, &X86::GR16_NOREXRegClass, &X86::GR32_NOREXRegClass, NULL
  };

  // GR64_NOREX_NOSP Sub-register Classes...
  static const TargetRegisterClass* const GR64_NOREX_NOSPSubRegClasses[] = {
    &X86::GR8_NOREXRegClass, &X86::GR8_NOREXRegClass, &X86::GR16_NOREXRegClass, &X86::GR32_NOREXRegClass, NULL
  };

  // GR64_NOSP Sub-register Classes...
  static const TargetRegisterClass* const GR64_NOSPSubRegClasses[] = {
    &X86::GR8RegClass, &X86::GR8RegClass, &X86::GR16RegClass, &X86::GR32_NOSPRegClass, NULL
  };

  // GR8 Sub-register Classes...
  static const TargetRegisterClass* const GR8SubRegClasses[] = {
    NULL
  };

  // GR8_ABCD_H Sub-register Classes...
  static const TargetRegisterClass* const GR8_ABCD_HSubRegClasses[] = {
    NULL
  };

  // GR8_ABCD_L Sub-register Classes...
  static const TargetRegisterClass* const GR8_ABCD_LSubRegClasses[] = {
    NULL
  };

  // GR8_NOREX Sub-register Classes...
  static const TargetRegisterClass* const GR8_NOREXSubRegClasses[] = {
    NULL
  };

  // RFP32 Sub-register Classes...
  static const TargetRegisterClass* const RFP32SubRegClasses[] = {
    NULL
  };

  // RFP64 Sub-register Classes...
  static const TargetRegisterClass* const RFP64SubRegClasses[] = {
    NULL
  };

  // RFP80 Sub-register Classes...
  static const TargetRegisterClass* const RFP80SubRegClasses[] = {
    NULL
  };

  // RST Sub-register Classes...
  static const TargetRegisterClass* const RSTSubRegClasses[] = {
    NULL
  };

  // SEGMENT_REG Sub-register Classes...
  static const TargetRegisterClass* const SEGMENT_REGSubRegClasses[] = {
    NULL
  };

  // VR128 Sub-register Classes...
  static const TargetRegisterClass* const VR128SubRegClasses[] = {
    &X86::FR32RegClass, &X86::FR64RegClass, NULL
  };

  // VR256 Sub-register Classes...
  static const TargetRegisterClass* const VR256SubRegClasses[] = {
    &X86::FR32RegClass, &X86::FR64RegClass, &X86::VR128RegClass, NULL
  };

  // VR64 Sub-register Classes...
  static const TargetRegisterClass* const VR64SubRegClasses[] = {
    NULL
  };

  // CCR Super-register Classes...
  static const TargetRegisterClass* const CCRSuperRegClasses[] = {
    NULL
  };

  // CONTROL_REG_32 Super-register Classes...
  static const TargetRegisterClass* const CONTROL_REG_32SuperRegClasses[] = {
    NULL
  };

  // CONTROL_REG_64 Super-register Classes...
  static const TargetRegisterClass* const CONTROL_REG_64SuperRegClasses[] = {
    NULL
  };

  // DEBUG_REG Super-register Classes...
  static const TargetRegisterClass* const DEBUG_REGSuperRegClasses[] = {
    NULL
  };

  // FR32 Super-register Classes...
  static const TargetRegisterClass* const FR32SuperRegClasses[] = {
    &X86::VR128RegClass, &X86::VR256RegClass, NULL
  };

  // FR64 Super-register Classes...
  static const TargetRegisterClass* const FR64SuperRegClasses[] = {
    &X86::VR128RegClass, &X86::VR256RegClass, NULL
  };

  // GR16 Super-register Classes...
  static const TargetRegisterClass* const GR16SuperRegClasses[] = {
    &X86::GR32RegClass, &X86::GR32_NOSPRegClass, &X86::GR64RegClass, &X86::GR64_NOSPRegClass, NULL
  };

  // GR16_ABCD Super-register Classes...
  static const TargetRegisterClass* const GR16_ABCDSuperRegClasses[] = {
    &X86::GR32_ABCDRegClass, &X86::GR32_ADRegClass, &X86::GR64_ABCDRegClass, NULL
  };

  // GR16_NOREX Super-register Classes...
  static const TargetRegisterClass* const GR16_NOREXSuperRegClasses[] = {
    &X86::GR32_NOREXRegClass, &X86::GR64_NOREXRegClass, &X86::GR64_NOREX_NOSPRegClass, NULL
  };

  // GR32 Super-register Classes...
  static const TargetRegisterClass* const GR32SuperRegClasses[] = {
    &X86::GR64RegClass, NULL
  };

  // GR32_ABCD Super-register Classes...
  static const TargetRegisterClass* const GR32_ABCDSuperRegClasses[] = {
    &X86::GR64_ABCDRegClass, NULL
  };

  // GR32_AD Super-register Classes...
  static const TargetRegisterClass* const GR32_ADSuperRegClasses[] = {
    NULL
  };

  // GR32_NOREX Super-register Classes...
  static const TargetRegisterClass* const GR32_NOREXSuperRegClasses[] = {
    &X86::GR64_NOREXRegClass, &X86::GR64_NOREX_NOSPRegClass, NULL
  };

  // GR32_NOSP Super-register Classes...
  static const TargetRegisterClass* const GR32_NOSPSuperRegClasses[] = {
    &X86::GR64_NOSPRegClass, NULL
  };

  // GR64 Super-register Classes...
  static const TargetRegisterClass* const GR64SuperRegClasses[] = {
    NULL
  };

  // GR64_ABCD Super-register Classes...
  static const TargetRegisterClass* const GR64_ABCDSuperRegClasses[] = {
    NULL
  };

  // GR64_NOREX Super-register Classes...
  static const TargetRegisterClass* const GR64_NOREXSuperRegClasses[] = {
    NULL
  };

  // GR64_NOREX_NOSP Super-register Classes...
  static const TargetRegisterClass* const GR64_NOREX_NOSPSuperRegClasses[] = {
    NULL
  };

  // GR64_NOSP Super-register Classes...
  static const TargetRegisterClass* const GR64_NOSPSuperRegClasses[] = {
    NULL
  };

  // GR8 Super-register Classes...
  static const TargetRegisterClass* const GR8SuperRegClasses[] = {
    &X86::GR16RegClass, &X86::GR32RegClass, &X86::GR32_NOSPRegClass, &X86::GR64RegClass, &X86::GR64_NOSPRegClass, NULL
  };

  // GR8_ABCD_H Super-register Classes...
  static const TargetRegisterClass* const GR8_ABCD_HSuperRegClasses[] = {
    &X86::GR16_ABCDRegClass, &X86::GR32_ABCDRegClass, &X86::GR32_ADRegClass, &X86::GR64_ABCDRegClass, NULL
  };

  // GR8_ABCD_L Super-register Classes...
  static const TargetRegisterClass* const GR8_ABCD_LSuperRegClasses[] = {
    &X86::GR16_ABCDRegClass, &X86::GR32_ABCDRegClass, &X86::GR32_ADRegClass, &X86::GR64_ABCDRegClass, NULL
  };

  // GR8_NOREX Super-register Classes...
  static const TargetRegisterClass* const GR8_NOREXSuperRegClasses[] = {
    &X86::GR16_NOREXRegClass, &X86::GR32_NOREXRegClass, &X86::GR64_NOREXRegClass, &X86::GR64_NOREX_NOSPRegClass, NULL
  };

  // RFP32 Super-register Classes...
  static const TargetRegisterClass* const RFP32SuperRegClasses[] = {
    NULL
  };

  // RFP64 Super-register Classes...
  static const TargetRegisterClass* const RFP64SuperRegClasses[] = {
    NULL
  };

  // RFP80 Super-register Classes...
  static const TargetRegisterClass* const RFP80SuperRegClasses[] = {
    NULL
  };

  // RST Super-register Classes...
  static const TargetRegisterClass* const RSTSuperRegClasses[] = {
    NULL
  };

  // SEGMENT_REG Super-register Classes...
  static const TargetRegisterClass* const SEGMENT_REGSuperRegClasses[] = {
    NULL
  };

  // VR128 Super-register Classes...
  static const TargetRegisterClass* const VR128SuperRegClasses[] = {
    &X86::VR256RegClass, NULL
  };

  // VR256 Super-register Classes...
  static const TargetRegisterClass* const VR256SuperRegClasses[] = {
    NULL
  };

  // VR64 Super-register Classes...
  static const TargetRegisterClass* const VR64SuperRegClasses[] = {
    NULL
  };

  // CCR Register Class sub-classes...
  static const TargetRegisterClass* const CCRSubclasses[] = {
    NULL
  };

  // CONTROL_REG_32 Register Class sub-classes...
  static const TargetRegisterClass* const CONTROL_REG_32Subclasses[] = {
    NULL
  };

  // CONTROL_REG_64 Register Class sub-classes...
  static const TargetRegisterClass* const CONTROL_REG_64Subclasses[] = {
    NULL
  };

  // DEBUG_REG Register Class sub-classes...
  static const TargetRegisterClass* const DEBUG_REGSubclasses[] = {
    NULL
  };

  // FR32 Register Class sub-classes...
  static const TargetRegisterClass* const FR32Subclasses[] = {
    &X86::FR64RegClass, &X86::VR128RegClass, NULL
  };

  // FR64 Register Class sub-classes...
  static const TargetRegisterClass* const FR64Subclasses[] = {
    &X86::VR128RegClass, NULL
  };

  // GR16 Register Class sub-classes...
  static const TargetRegisterClass* const GR16Subclasses[] = {
    &X86::GR16_ABCDRegClass, &X86::GR16_NOREXRegClass, NULL
  };

  // GR16_ABCD Register Class sub-classes...
  static const TargetRegisterClass* const GR16_ABCDSubclasses[] = {
    NULL
  };

  // GR16_NOREX Register Class sub-classes...
  static const TargetRegisterClass* const GR16_NOREXSubclasses[] = {
    &X86::GR16_ABCDRegClass, NULL
  };

  // GR32 Register Class sub-classes...
  static const TargetRegisterClass* const GR32Subclasses[] = {
    &X86::GR32_ABCDRegClass, &X86::GR32_ADRegClass, &X86::GR32_NOREXRegClass, &X86::GR32_NOSPRegClass, NULL
  };

  // GR32_ABCD Register Class sub-classes...
  static const TargetRegisterClass* const GR32_ABCDSubclasses[] = {
    &X86::GR32_ADRegClass, NULL
  };

  // GR32_AD Register Class sub-classes...
  static const TargetRegisterClass* const GR32_ADSubclasses[] = {
    NULL
  };

  // GR32_NOREX Register Class sub-classes...
  static const TargetRegisterClass* const GR32_NOREXSubclasses[] = {
    &X86::GR32_ABCDRegClass, &X86::GR32_ADRegClass, NULL
  };

  // GR32_NOSP Register Class sub-classes...
  static const TargetRegisterClass* const GR32_NOSPSubclasses[] = {
    &X86::GR32_ABCDRegClass, &X86::GR32_ADRegClass, NULL
  };

  // GR64 Register Class sub-classes...
  static const TargetRegisterClass* const GR64Subclasses[] = {
    &X86::GR64_ABCDRegClass, &X86::GR64_NOREXRegClass, &X86::GR64_NOREX_NOSPRegClass, &X86::GR64_NOSPRegClass, NULL
  };

  // GR64_ABCD Register Class sub-classes...
  static const TargetRegisterClass* const GR64_ABCDSubclasses[] = {
    NULL
  };

  // GR64_NOREX Register Class sub-classes...
  static const TargetRegisterClass* const GR64_NOREXSubclasses[] = {
    &X86::GR64_ABCDRegClass, &X86::GR64_NOREX_NOSPRegClass, NULL
  };

  // GR64_NOREX_NOSP Register Class sub-classes...
  static const TargetRegisterClass* const GR64_NOREX_NOSPSubclasses[] = {
    &X86::GR64_ABCDRegClass, NULL
  };

  // GR64_NOSP Register Class sub-classes...
  static const TargetRegisterClass* const GR64_NOSPSubclasses[] = {
    &X86::GR64_ABCDRegClass, &X86::GR64_NOREX_NOSPRegClass, NULL
  };

  // GR8 Register Class sub-classes...
  static const TargetRegisterClass* const GR8Subclasses[] = {
    &X86::GR8_ABCD_HRegClass, &X86::GR8_ABCD_LRegClass, &X86::GR8_NOREXRegClass, NULL
  };

  // GR8_ABCD_H Register Class sub-classes...
  static const TargetRegisterClass* const GR8_ABCD_HSubclasses[] = {
    NULL
  };

  // GR8_ABCD_L Register Class sub-classes...
  static const TargetRegisterClass* const GR8_ABCD_LSubclasses[] = {
    NULL
  };

  // GR8_NOREX Register Class sub-classes...
  static const TargetRegisterClass* const GR8_NOREXSubclasses[] = {
    &X86::GR8_ABCD_HRegClass, &X86::GR8_ABCD_LRegClass, NULL
  };

  // RFP32 Register Class sub-classes...
  static const TargetRegisterClass* const RFP32Subclasses[] = {
    &X86::RFP64RegClass, &X86::RFP80RegClass, NULL
  };

  // RFP64 Register Class sub-classes...
  static const TargetRegisterClass* const RFP64Subclasses[] = {
    &X86::RFP80RegClass, NULL
  };

  // RFP80 Register Class sub-classes...
  static const TargetRegisterClass* const RFP80Subclasses[] = {
    NULL
  };

  // RST Register Class sub-classes...
  static const TargetRegisterClass* const RSTSubclasses[] = {
    NULL
  };

  // SEGMENT_REG Register Class sub-classes...
  static const TargetRegisterClass* const SEGMENT_REGSubclasses[] = {
    NULL
  };

  // VR128 Register Class sub-classes...
  static const TargetRegisterClass* const VR128Subclasses[] = {
    NULL
  };

  // VR256 Register Class sub-classes...
  static const TargetRegisterClass* const VR256Subclasses[] = {
    NULL
  };

  // VR64 Register Class sub-classes...
  static const TargetRegisterClass* const VR64Subclasses[] = {
    NULL
  };

  // CCR Register Class super-classes...
  static const TargetRegisterClass* const CCRSuperclasses[] = {
    NULL
  };

  // CONTROL_REG_32 Register Class super-classes...
  static const TargetRegisterClass* const CONTROL_REG_32Superclasses[] = {
    NULL
  };

  // CONTROL_REG_64 Register Class super-classes...
  static const TargetRegisterClass* const CONTROL_REG_64Superclasses[] = {
    NULL
  };

  // DEBUG_REG Register Class super-classes...
  static const TargetRegisterClass* const DEBUG_REGSuperclasses[] = {
    NULL
  };

  // FR32 Register Class super-classes...
  static const TargetRegisterClass* const FR32Superclasses[] = {
    NULL
  };

  // FR64 Register Class super-classes...
  static const TargetRegisterClass* const FR64Superclasses[] = {
    &X86::FR32RegClass, NULL
  };

  // GR16 Register Class super-classes...
  static const TargetRegisterClass* const GR16Superclasses[] = {
    NULL
  };

  // GR16_ABCD Register Class super-classes...
  static const TargetRegisterClass* const GR16_ABCDSuperclasses[] = {
    &X86::GR16RegClass, &X86::GR16_NOREXRegClass, NULL
  };

  // GR16_NOREX Register Class super-classes...
  static const TargetRegisterClass* const GR16_NOREXSuperclasses[] = {
    &X86::GR16RegClass, NULL
  };

  // GR32 Register Class super-classes...
  static const TargetRegisterClass* const GR32Superclasses[] = {
    NULL
  };

  // GR32_ABCD Register Class super-classes...
  static const TargetRegisterClass* const GR32_ABCDSuperclasses[] = {
    &X86::GR32RegClass, &X86::GR32_NOREXRegClass, &X86::GR32_NOSPRegClass, NULL
  };

  // GR32_AD Register Class super-classes...
  static const TargetRegisterClass* const GR32_ADSuperclasses[] = {
    &X86::GR32RegClass, &X86::GR32_ABCDRegClass, &X86::GR32_NOREXRegClass, &X86::GR32_NOSPRegClass, NULL
  };

  // GR32_NOREX Register Class super-classes...
  static const TargetRegisterClass* const GR32_NOREXSuperclasses[] = {
    &X86::GR32RegClass, NULL
  };

  // GR32_NOSP Register Class super-classes...
  static const TargetRegisterClass* const GR32_NOSPSuperclasses[] = {
    &X86::GR32RegClass, NULL
  };

  // GR64 Register Class super-classes...
  static const TargetRegisterClass* const GR64Superclasses[] = {
    NULL
  };

  // GR64_ABCD Register Class super-classes...
  static const TargetRegisterClass* const GR64_ABCDSuperclasses[] = {
    &X86::GR64RegClass, &X86::GR64_NOREXRegClass, &X86::GR64_NOREX_NOSPRegClass, &X86::GR64_NOSPRegClass, NULL
  };

  // GR64_NOREX Register Class super-classes...
  static const TargetRegisterClass* const GR64_NOREXSuperclasses[] = {
    &X86::GR64RegClass, NULL
  };

  // GR64_NOREX_NOSP Register Class super-classes...
  static const TargetRegisterClass* const GR64_NOREX_NOSPSuperclasses[] = {
    &X86::GR64RegClass, &X86::GR64_NOREXRegClass, &X86::GR64_NOSPRegClass, NULL
  };

  // GR64_NOSP Register Class super-classes...
  static const TargetRegisterClass* const GR64_NOSPSuperclasses[] = {
    &X86::GR64RegClass, NULL
  };

  // GR8 Register Class super-classes...
  static const TargetRegisterClass* const GR8Superclasses[] = {
    NULL
  };

  // GR8_ABCD_H Register Class super-classes...
  static const TargetRegisterClass* const GR8_ABCD_HSuperclasses[] = {
    &X86::GR8RegClass, &X86::GR8_NOREXRegClass, NULL
  };

  // GR8_ABCD_L Register Class super-classes...
  static const TargetRegisterClass* const GR8_ABCD_LSuperclasses[] = {
    &X86::GR8RegClass, &X86::GR8_NOREXRegClass, NULL
  };

  // GR8_NOREX Register Class super-classes...
  static const TargetRegisterClass* const GR8_NOREXSuperclasses[] = {
    &X86::GR8RegClass, NULL
  };

  // RFP32 Register Class super-classes...
  static const TargetRegisterClass* const RFP32Superclasses[] = {
    NULL
  };

  // RFP64 Register Class super-classes...
  static const TargetRegisterClass* const RFP64Superclasses[] = {
    &X86::RFP32RegClass, NULL
  };

  // RFP80 Register Class super-classes...
  static const TargetRegisterClass* const RFP80Superclasses[] = {
    &X86::RFP32RegClass, &X86::RFP64RegClass, NULL
  };

  // RST Register Class super-classes...
  static const TargetRegisterClass* const RSTSuperclasses[] = {
    NULL
  };

  // SEGMENT_REG Register Class super-classes...
  static const TargetRegisterClass* const SEGMENT_REGSuperclasses[] = {
    NULL
  };

  // VR128 Register Class super-classes...
  static const TargetRegisterClass* const VR128Superclasses[] = {
    &X86::FR32RegClass, &X86::FR64RegClass, NULL
  };

  // VR256 Register Class super-classes...
  static const TargetRegisterClass* const VR256Superclasses[] = {
    NULL
  };

  // VR64 Register Class super-classes...
  static const TargetRegisterClass* const VR64Superclasses[] = {
    NULL
  };


CCRClass::CCRClass()  : TargetRegisterClass(CCRRegClassID, "CCR", CCRVTs, CCRSubclasses, CCRSuperclasses, CCRSubRegClasses, CCRSuperRegClasses, 4, 4, -1, CCR, CCR + 1) {}

CONTROL_REG_32Class::CONTROL_REG_32Class()  : TargetRegisterClass(CONTROL_REG_32RegClassID, "CONTROL_REG_32", CONTROL_REG_32VTs, CONTROL_REG_32Subclasses, CONTROL_REG_32Superclasses, CONTROL_REG_32SubRegClasses, CONTROL_REG_32SuperRegClasses, 4, 4, 1, CONTROL_REG_32, CONTROL_REG_32 + 8) {}

CONTROL_REG_64Class::CONTROL_REG_64Class()  : TargetRegisterClass(CONTROL_REG_64RegClassID, "CONTROL_REG_64", CONTROL_REG_64VTs, CONTROL_REG_64Subclasses, CONTROL_REG_64Superclasses, CONTROL_REG_64SubRegClasses, CONTROL_REG_64SuperRegClasses, 8, 8, 1, CONTROL_REG_64, CONTROL_REG_64 + 9) {}

DEBUG_REGClass::DEBUG_REGClass()  : TargetRegisterClass(DEBUG_REGRegClassID, "DEBUG_REG", DEBUG_REGVTs, DEBUG_REGSubclasses, DEBUG_REGSuperclasses, DEBUG_REGSubRegClasses, DEBUG_REGSuperRegClasses, 4, 4, 1, DEBUG_REG, DEBUG_REG + 8) {}

    FR32Class::iterator
    FR32Class::allocation_order_end(const MachineFunction &MF) const {
      const TargetMachine &TM = MF.getTarget();
      const X86Subtarget &Subtarget = TM.getSubtarget<X86Subtarget>();
      if (!Subtarget.is64Bit())
        return end()-8; // Only XMM0 to XMM7 are available in 32-bit mode.
      else
        return end();
    }
  
FR32Class::FR32Class()  : TargetRegisterClass(FR32RegClassID, "FR32", FR32VTs, FR32Subclasses, FR32Superclasses, FR32SubRegClasses, FR32SuperRegClasses, 4, 4, 1, FR32, FR32 + 16) {}

    FR64Class::iterator
    FR64Class::allocation_order_end(const MachineFunction &MF) const {
      const TargetMachine &TM = MF.getTarget();
      const X86Subtarget &Subtarget = TM.getSubtarget<X86Subtarget>();
      if (!Subtarget.is64Bit())
        return end()-8; // Only XMM0 to XMM7 are available in 32-bit mode.
      else
        return end();
    }
  
FR64Class::FR64Class()  : TargetRegisterClass(FR64RegClassID, "FR64", FR64VTs, FR64Subclasses, FR64Superclasses, FR64SubRegClasses, FR64SuperRegClasses, 8, 8, 1, FR64, FR64 + 16) {}

    static const unsigned X86_GR16_AO_64[] = {
      X86::AX,  X86::CX,   X86::DX,   X86::SI,   X86::DI,
      X86::R8W, X86::R9W,  X86::R10W, X86::R11W,
      X86::BX, X86::R14W, X86::R15W,  X86::R12W, X86::R13W, X86::BP
    };

    GR16Class::iterator
    GR16Class::allocation_order_begin(const MachineFunction &MF) const {
      const TargetMachine &TM = MF.getTarget();
      const X86Subtarget &Subtarget = TM.getSubtarget<X86Subtarget>();
      if (Subtarget.is64Bit())
        return X86_GR16_AO_64;
      else
        return begin();
    }

    GR16Class::iterator
    GR16Class::allocation_order_end(const MachineFunction &MF) const {
      const TargetMachine &TM = MF.getTarget();
      const TargetRegisterInfo *RI = TM.getRegisterInfo();
      const X86Subtarget &Subtarget = TM.getSubtarget<X86Subtarget>();
      if (Subtarget.is64Bit()) {
        // Does the function dedicate RBP to being a frame ptr?
        if (RI->hasFP(MF))
          // If so, don't allocate SP or BP.
          return array_endof(X86_GR16_AO_64) - 1;
        else
          // If not, just don't allocate SP.
          return array_endof(X86_GR16_AO_64);
      } else {
        // Does the function dedicate EBP to being a frame ptr?
        if (RI->hasFP(MF))
          // If so, don't allocate SP or BP.
          return begin() + 6;
        else
          // If not, just don't allocate SP.
          return begin() + 7;
      }
    }
  
GR16Class::GR16Class()  : TargetRegisterClass(GR16RegClassID, "GR16", GR16VTs, GR16Subclasses, GR16Superclasses, GR16SubRegClasses, GR16SuperRegClasses, 2, 2, 1, GR16, GR16 + 16) {}

GR16_ABCDClass::GR16_ABCDClass()  : TargetRegisterClass(GR16_ABCDRegClassID, "GR16_ABCD", GR16_ABCDVTs, GR16_ABCDSubclasses, GR16_ABCDSuperclasses, GR16_ABCDSubRegClasses, GR16_ABCDSuperRegClasses, 2, 2, 1, GR16_ABCD, GR16_ABCD + 4) {}

    GR16_NOREXClass::iterator
    GR16_NOREXClass::allocation_order_end(const MachineFunction &MF) const {
      const TargetMachine &TM = MF.getTarget();
      const TargetRegisterInfo *RI = TM.getRegisterInfo();
      // Does the function dedicate RBP / EBP to being a frame ptr?
      if (RI->hasFP(MF))
        // If so, don't allocate SP or BP.
        return end() - 2;
      else
        // If not, just don't allocate SP.
        return end() - 1;
    }
  
GR16_NOREXClass::GR16_NOREXClass()  : TargetRegisterClass(GR16_NOREXRegClassID, "GR16_NOREX", GR16_NOREXVTs, GR16_NOREXSubclasses, GR16_NOREXSuperclasses, GR16_NOREXSubRegClasses, GR16_NOREXSuperRegClasses, 2, 2, 1, GR16_NOREX, GR16_NOREX + 8) {}

    static const unsigned X86_GR32_AO_64[] = {
      X86::EAX, X86::ECX,  X86::EDX,  X86::ESI,  X86::EDI,
      X86::R8D, X86::R9D,  X86::R10D, X86::R11D,
      X86::EBX, X86::R14D, X86::R15D, X86::R12D, X86::R13D, X86::EBP
    };

    GR32Class::iterator
    GR32Class::allocation_order_begin(const MachineFunction &MF) const {
      const TargetMachine &TM = MF.getTarget();
      const X86Subtarget &Subtarget = TM.getSubtarget<X86Subtarget>();
      if (Subtarget.is64Bit())
        return X86_GR32_AO_64;
      else
        return begin();
    }

    GR32Class::iterator
    GR32Class::allocation_order_end(const MachineFunction &MF) const {
      const TargetMachine &TM = MF.getTarget();
      const TargetRegisterInfo *RI = TM.getRegisterInfo();
      const X86Subtarget &Subtarget = TM.getSubtarget<X86Subtarget>();
      if (Subtarget.is64Bit()) {
        // Does the function dedicate RBP to being a frame ptr?
        if (RI->hasFP(MF))
          // If so, don't allocate ESP or EBP.
          return array_endof(X86_GR32_AO_64) - 1;
        else
          // If not, just don't allocate ESP.
          return array_endof(X86_GR32_AO_64);
      } else {
        // Does the function dedicate EBP to being a frame ptr?
        if (RI->hasFP(MF))
          // If so, don't allocate ESP or EBP.
          return begin() + 6;
        else
          // If not, just don't allocate ESP.
          return begin() + 7;
      }
    }
  
GR32Class::GR32Class()  : TargetRegisterClass(GR32RegClassID, "GR32", GR32VTs, GR32Subclasses, GR32Superclasses, GR32SubRegClasses, GR32SuperRegClasses, 4, 4, 1, GR32, GR32 + 16) {}

GR32_ABCDClass::GR32_ABCDClass()  : TargetRegisterClass(GR32_ABCDRegClassID, "GR32_ABCD", GR32_ABCDVTs, GR32_ABCDSubclasses, GR32_ABCDSuperclasses, GR32_ABCDSubRegClasses, GR32_ABCDSuperRegClasses, 4, 4, 1, GR32_ABCD, GR32_ABCD + 4) {}

GR32_ADClass::GR32_ADClass()  : TargetRegisterClass(GR32_ADRegClassID, "GR32_AD", GR32_ADVTs, GR32_ADSubclasses, GR32_ADSuperclasses, GR32_ADSubRegClasses, GR32_ADSuperRegClasses, 4, 4, 1, GR32_AD, GR32_AD + 2) {}

    GR32_NOREXClass::iterator
    GR32_NOREXClass::allocation_order_end(const MachineFunction &MF) const {
      const TargetMachine &TM = MF.getTarget();
      const TargetRegisterInfo *RI = TM.getRegisterInfo();
      // Does the function dedicate RBP / EBP to being a frame ptr?
      if (RI->hasFP(MF))
        // If so, don't allocate ESP or EBP.
        return end() - 2;
      else
        // If not, just don't allocate ESP.
        return end() - 1;
    }
  
GR32_NOREXClass::GR32_NOREXClass()  : TargetRegisterClass(GR32_NOREXRegClassID, "GR32_NOREX", GR32_NOREXVTs, GR32_NOREXSubclasses, GR32_NOREXSuperclasses, GR32_NOREXSubRegClasses, GR32_NOREXSuperRegClasses, 4, 4, 1, GR32_NOREX, GR32_NOREX + 8) {}

    static const unsigned X86_GR32_NOSP_AO_64[] = {
      X86::EAX, X86::ECX,  X86::EDX,  X86::ESI,  X86::EDI,
      X86::R8D, X86::R9D,  X86::R10D, X86::R11D,
      X86::EBX, X86::R14D, X86::R15D, X86::R12D, X86::R13D, X86::EBP
    };

    GR32_NOSPClass::iterator
    GR32_NOSPClass::allocation_order_begin(const MachineFunction &MF) const {
      const TargetMachine &TM = MF.getTarget();
      const X86Subtarget &Subtarget = TM.getSubtarget<X86Subtarget>();
      if (Subtarget.is64Bit())
        return X86_GR32_NOSP_AO_64;
      else
        return begin();
    }

    GR32_NOSPClass::iterator
    GR32_NOSPClass::allocation_order_end(const MachineFunction &MF) const {
      const TargetMachine &TM = MF.getTarget();
      const TargetRegisterInfo *RI = TM.getRegisterInfo();
      const X86Subtarget &Subtarget = TM.getSubtarget<X86Subtarget>();
      if (Subtarget.is64Bit()) {
        // Does the function dedicate RBP to being a frame ptr?
        if (RI->hasFP(MF))
          // If so, don't allocate EBP.
          return array_endof(X86_GR32_NOSP_AO_64) - 1;
        else
          // If not, any reg in this class is ok.
          return array_endof(X86_GR32_NOSP_AO_64);
      } else {
        // Does the function dedicate EBP to being a frame ptr?
        if (RI->hasFP(MF))
          // If so, don't allocate EBP.
          return begin() + 6;
        else
          // If not, any reg in this class is ok.
          return begin() + 7;
      }
    }
  
GR32_NOSPClass::GR32_NOSPClass()  : TargetRegisterClass(GR32_NOSPRegClassID, "GR32_NOSP", GR32_NOSPVTs, GR32_NOSPSubclasses, GR32_NOSPSuperclasses, GR32_NOSPSubRegClasses, GR32_NOSPSuperRegClasses, 4, 4, 1, GR32_NOSP, GR32_NOSP + 15) {}

    GR64Class::iterator
    GR64Class::allocation_order_end(const MachineFunction &MF) const {
      const TargetMachine &TM = MF.getTarget();
      const TargetRegisterInfo *RI = TM.getRegisterInfo();
      const X86Subtarget &Subtarget = TM.getSubtarget<X86Subtarget>();
      if (!Subtarget.is64Bit())
        return begin();  // None of these are allocatable in 32-bit.
      if (RI->hasFP(MF)) // Does the function dedicate RBP to being a frame ptr?
        return end()-3;  // If so, don't allocate RIP, RSP or RBP
      else
        return end()-2;  // If not, just don't allocate RIP or RSP
    }
  
GR64Class::GR64Class()  : TargetRegisterClass(GR64RegClassID, "GR64", GR64VTs, GR64Subclasses, GR64Superclasses, GR64SubRegClasses, GR64SuperRegClasses, 8, 8, 1, GR64, GR64 + 17) {}

GR64_ABCDClass::GR64_ABCDClass()  : TargetRegisterClass(GR64_ABCDRegClassID, "GR64_ABCD", GR64_ABCDVTs, GR64_ABCDSubclasses, GR64_ABCDSuperclasses, GR64_ABCDSubRegClasses, GR64_ABCDSuperRegClasses, 8, 8, 1, GR64_ABCD, GR64_ABCD + 4) {}

    GR64_NOREXClass::iterator
    GR64_NOREXClass::allocation_order_end(const MachineFunction &MF) const {
      const TargetMachine &TM = MF.getTarget();
      const TargetRegisterInfo *RI = TM.getRegisterInfo();
      // Does the function dedicate RBP to being a frame ptr?
      if (RI->hasFP(MF))
        // If so, don't allocate RIP, RSP or RBP.
        return end() - 3;
      else
        // If not, just don't allocate RIP or RSP.
        return end() - 2;
    }
  
GR64_NOREXClass::GR64_NOREXClass()  : TargetRegisterClass(GR64_NOREXRegClassID, "GR64_NOREX", GR64_NOREXVTs, GR64_NOREXSubclasses, GR64_NOREXSuperclasses, GR64_NOREXSubRegClasses, GR64_NOREXSuperRegClasses, 8, 8, 1, GR64_NOREX, GR64_NOREX + 9) {}

    GR64_NOREX_NOSPClass::iterator
    GR64_NOREX_NOSPClass::allocation_order_end(const MachineFunction &MF) const
  {
      const TargetMachine &TM = MF.getTarget();
      const TargetRegisterInfo *RI = TM.getRegisterInfo();
      // Does the function dedicate RBP to being a frame ptr?
      if (RI->hasFP(MF))
        // If so, don't allocate RBP.
        return end() - 1;
      else
        // If not, any reg in this class is ok.
        return end();
    }
  
GR64_NOREX_NOSPClass::GR64_NOREX_NOSPClass()  : TargetRegisterClass(GR64_NOREX_NOSPRegClassID, "GR64_NOREX_NOSP", GR64_NOREX_NOSPVTs, GR64_NOREX_NOSPSubclasses, GR64_NOREX_NOSPSuperclasses, GR64_NOREX_NOSPSubRegClasses, GR64_NOREX_NOSPSuperRegClasses, 8, 8, 1, GR64_NOREX_NOSP, GR64_NOREX_NOSP + 7) {}

    GR64_NOSPClass::iterator
    GR64_NOSPClass::allocation_order_end(const MachineFunction &MF) const {
      const TargetMachine &TM = MF.getTarget();
      const TargetRegisterInfo *RI = TM.getRegisterInfo();
      const X86Subtarget &Subtarget = TM.getSubtarget<X86Subtarget>();
      if (!Subtarget.is64Bit())
        return begin();  // None of these are allocatable in 32-bit.
      if (RI->hasFP(MF)) // Does the function dedicate RBP to being a frame ptr?
        return end()-1;  // If so, don't allocate RBP
      else
        return end();  // If not, any reg in this class is ok.
    }
  
GR64_NOSPClass::GR64_NOSPClass()  : TargetRegisterClass(GR64_NOSPRegClassID, "GR64_NOSP", GR64_NOSPVTs, GR64_NOSPSubclasses, GR64_NOSPSuperclasses, GR64_NOSPSubRegClasses, GR64_NOSPSuperRegClasses, 8, 8, 1, GR64_NOSP, GR64_NOSP + 15) {}

    static const unsigned X86_GR8_AO_64[] = {
      X86::AL,   X86::CL,   X86::DL,   X86::SIL, X86::DIL,
      X86::R8B,  X86::R9B,  X86::R10B, X86::R11B,
      X86::BL,   X86::R14B, X86::R15B, X86::R12B, X86::R13B, X86::BPL
    };

    GR8Class::iterator
    GR8Class::allocation_order_begin(const MachineFunction &MF) const {
      const TargetMachine &TM = MF.getTarget();
      const X86Subtarget &Subtarget = TM.getSubtarget<X86Subtarget>();
      if (Subtarget.is64Bit())
        return X86_GR8_AO_64;
      else
        return begin();
    }

    GR8Class::iterator
    GR8Class::allocation_order_end(const MachineFunction &MF) const {
      const TargetMachine &TM = MF.getTarget();
      const TargetRegisterInfo *RI = TM.getRegisterInfo();
      const X86Subtarget &Subtarget = TM.getSubtarget<X86Subtarget>();
      // Does the function dedicate RBP / EBP to being a frame ptr?
      if (!Subtarget.is64Bit())
        // In 32-mode, none of the 8-bit registers aliases EBP or ESP.
        return begin() + 8;
      else if (RI->hasFP(MF))
        // If so, don't allocate SPL or BPL.
        return array_endof(X86_GR8_AO_64) - 1;
      else
        // If not, just don't allocate SPL.
        return array_endof(X86_GR8_AO_64);
    }
  
GR8Class::GR8Class()  : TargetRegisterClass(GR8RegClassID, "GR8", GR8VTs, GR8Subclasses, GR8Superclasses, GR8SubRegClasses, GR8SuperRegClasses, 1, 1, 1, GR8, GR8 + 20) {}

GR8_ABCD_HClass::GR8_ABCD_HClass()  : TargetRegisterClass(GR8_ABCD_HRegClassID, "GR8_ABCD_H", GR8_ABCD_HVTs, GR8_ABCD_HSubclasses, GR8_ABCD_HSuperclasses, GR8_ABCD_HSubRegClasses, GR8_ABCD_HSuperRegClasses, 1, 1, 1, GR8_ABCD_H, GR8_ABCD_H + 4) {}

GR8_ABCD_LClass::GR8_ABCD_LClass()  : TargetRegisterClass(GR8_ABCD_LRegClassID, "GR8_ABCD_L", GR8_ABCD_LVTs, GR8_ABCD_LSubclasses, GR8_ABCD_LSuperclasses, GR8_ABCD_LSubRegClasses, GR8_ABCD_LSuperRegClasses, 1, 1, 1, GR8_ABCD_L, GR8_ABCD_L + 4) {}

    // In 64-bit mode, it's not safe to blindly allocate H registers.
    static const unsigned X86_GR8_NOREX_AO_64[] = {
      X86::AL, X86::CL, X86::DL, X86::BL
    };

    GR8_NOREXClass::iterator
    GR8_NOREXClass::allocation_order_begin(const MachineFunction &MF) const {
      const TargetMachine &TM = MF.getTarget();
      const X86Subtarget &Subtarget = TM.getSubtarget<X86Subtarget>();
      if (Subtarget.is64Bit())
        return X86_GR8_NOREX_AO_64;
      else
        return begin();
    }

    GR8_NOREXClass::iterator
    GR8_NOREXClass::allocation_order_end(const MachineFunction &MF) const {
      const TargetMachine &TM = MF.getTarget();
      const X86Subtarget &Subtarget = TM.getSubtarget<X86Subtarget>();
      if (Subtarget.is64Bit())
        return array_endof(X86_GR8_NOREX_AO_64);
      else
        return end();
    }
  
GR8_NOREXClass::GR8_NOREXClass()  : TargetRegisterClass(GR8_NOREXRegClassID, "GR8_NOREX", GR8_NOREXVTs, GR8_NOREXSubclasses, GR8_NOREXSuperclasses, GR8_NOREXSubRegClasses, GR8_NOREXSuperRegClasses, 1, 1, 1, GR8_NOREX, GR8_NOREX + 8) {}

RFP32Class::RFP32Class()  : TargetRegisterClass(RFP32RegClassID, "RFP32", RFP32VTs, RFP32Subclasses, RFP32Superclasses, RFP32SubRegClasses, RFP32SuperRegClasses, 4, 4, 1, RFP32, RFP32 + 7) {}

RFP64Class::RFP64Class()  : TargetRegisterClass(RFP64RegClassID, "RFP64", RFP64VTs, RFP64Subclasses, RFP64Superclasses, RFP64SubRegClasses, RFP64SuperRegClasses, 8, 4, 1, RFP64, RFP64 + 7) {}

RFP80Class::RFP80Class()  : TargetRegisterClass(RFP80RegClassID, "RFP80", RFP80VTs, RFP80Subclasses, RFP80Superclasses, RFP80SubRegClasses, RFP80SuperRegClasses, 10, 4, 1, RFP80, RFP80 + 7) {}

    RSTClass::iterator
    RSTClass::allocation_order_end(const MachineFunction &MF) const {
      return begin();
    }
  
RSTClass::RSTClass()  : TargetRegisterClass(RSTRegClassID, "RST", RSTVTs, RSTSubclasses, RSTSuperclasses, RSTSubRegClasses, RSTSuperRegClasses, 10, 4, 1, RST, RST + 8) {}

SEGMENT_REGClass::SEGMENT_REGClass()  : TargetRegisterClass(SEGMENT_REGRegClassID, "SEGMENT_REG", SEGMENT_REGVTs, SEGMENT_REGSubclasses, SEGMENT_REGSuperclasses, SEGMENT_REGSubRegClasses, SEGMENT_REGSuperRegClasses, 2, 2, 1, SEGMENT_REG, SEGMENT_REG + 6) {}

    VR128Class::iterator
    VR128Class::allocation_order_end(const MachineFunction &MF) const {
      const TargetMachine &TM = MF.getTarget();
      const X86Subtarget &Subtarget = TM.getSubtarget<X86Subtarget>();
      if (!Subtarget.is64Bit())
        return end()-8; // Only XMM0 to XMM7 are available in 32-bit mode.
      else
        return end();
    }
  
VR128Class::VR128Class()  : TargetRegisterClass(VR128RegClassID, "VR128", VR128VTs, VR128Subclasses, VR128Superclasses, VR128SubRegClasses, VR128SuperRegClasses, 16, 16, 1, VR128, VR128 + 16) {}

VR256Class::VR256Class()  : TargetRegisterClass(VR256RegClassID, "VR256", VR256VTs, VR256Subclasses, VR256Superclasses, VR256SubRegClasses, VR256SuperRegClasses, 32, 32, 1, VR256, VR256 + 16) {}

VR64Class::VR64Class()  : TargetRegisterClass(VR64RegClassID, "VR64", VR64VTs, VR64Subclasses, VR64Superclasses, VR64SubRegClasses, VR64SuperRegClasses, 8, 8, 1, VR64, VR64 + 8) {}
}

namespace {
  const TargetRegisterClass* const RegisterClasses[] = {
    &X86::CCRRegClass,
    &X86::CONTROL_REG_32RegClass,
    &X86::CONTROL_REG_64RegClass,
    &X86::DEBUG_REGRegClass,
    &X86::FR32RegClass,
    &X86::FR64RegClass,
    &X86::GR16RegClass,
    &X86::GR16_ABCDRegClass,
    &X86::GR16_NOREXRegClass,
    &X86::GR32RegClass,
    &X86::GR32_ABCDRegClass,
    &X86::GR32_ADRegClass,
    &X86::GR32_NOREXRegClass,
    &X86::GR32_NOSPRegClass,
    &X86::GR64RegClass,
    &X86::GR64_ABCDRegClass,
    &X86::GR64_NOREXRegClass,
    &X86::GR64_NOREX_NOSPRegClass,
    &X86::GR64_NOSPRegClass,
    &X86::GR8RegClass,
    &X86::GR8_ABCD_HRegClass,
    &X86::GR8_ABCD_LRegClass,
    &X86::GR8_NOREXRegClass,
    &X86::RFP32RegClass,
    &X86::RFP64RegClass,
    &X86::RFP80RegClass,
    &X86::RSTRegClass,
    &X86::SEGMENT_REGRegClass,
    &X86::VR128RegClass,
    &X86::VR256RegClass,
    &X86::VR64RegClass,
  };


  // Number of hash collisions: 20
  const unsigned SubregHashTable[] = { X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R14, X86::R14B, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R14D, X86::R14B, 
                                       X86::R14W, X86::R14B, 
                                       X86::EDX, X86::DH, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::RDI, X86::EDI, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R9, X86::R9W, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R9D, X86::R9W, 
                                       X86::YMM2, X86::XMM2, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::EIP, X86::IP, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::AX, X86::AH, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R14, X86::R14D, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::EDI, X86::DI, 
                                       X86::RCX, X86::CX, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::RDX, X86::DX, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::RDX, X86::EDX, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::DI, X86::DIL, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R11, X86::R11B, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R11D, X86::R11B, 
                                       X86::EAX, X86::AH, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R11W, X86::R11B, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::YMM3, X86::XMM3, 
                                       X86::RAX, X86::EAX, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::AX, X86::AL, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R14, X86::R14W, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R14D, X86::R14W, 
                                       X86::EDI, X86::DIL, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::RDX, X86::DH, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R11, X86::R11D, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::RIP, X86::IP, 
                                       X86::EAX, X86::AL, 
                                       X86::YMM4, X86::XMM4, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::DX, X86::DL, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::RBP, X86::EBP, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::RDI, X86::DI, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::EDX, X86::DL, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::RIP, X86::EIP, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::RAX, X86::AH, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R11, X86::R11W, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R11D, X86::R11W, 
                                       X86::EAX, X86::AX, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::YMM5, X86::XMM5, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::RBX, X86::EBX, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::RDI, X86::DIL, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::BX, X86::BH, 
                                       X86::R15, X86::R15B, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R15D, X86::R15B, 
                                       X86::R15W, X86::R15B, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::ESI, X86::SI, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::RAX, X86::AL, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::EBX, X86::BH, 
                                       X86::YMM6, X86::XMM6, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::RDX, X86::DL, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::BX, X86::BL, 
                                       X86::R15, X86::R15D, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::ESI, X86::SIL, 
                                       X86::RSI, X86::ESI, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::RAX, X86::AX, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R12, X86::R12B, 
                                       X86::EBX, X86::BL, 
                                       X86::R12D, X86::R12B, 
                                       X86::R12W, X86::R12B, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::YMM7, X86::XMM7, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R15, X86::R15W, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R15D, X86::R15W, 
                                       X86::RSI, X86::SI, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::YMM0, X86::XMM0, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::ESP, X86::SP, 
                                       X86::RSP, X86::ESP, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::RBX, X86::BH, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::EBP, X86::BP, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R12, X86::R12D, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::YMM8, X86::XMM8, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::BP, X86::BPL, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::RSI, X86::SIL, 
                                       X86::YMM1, X86::XMM1, 
                                       X86::SI, X86::SIL, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::ESP, X86::SPL, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::RBX, X86::BL, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::EBP, X86::BPL, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R12, X86::R12W, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R12D, X86::R12W, 
                                       X86::YMM9, X86::XMM9, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R8, X86::R8B, 
                                       X86::YMM10, X86::XMM10, 
                                       X86::R8D, X86::R8B, 
                                       X86::R8W, X86::R8B, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::RSP, X86::SP, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::RBP, X86::BP, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::EBX, X86::BX, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::CX, X86::CH, 
                                       X86::R8, X86::R8D, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::RSP, X86::SPL, 
                                       X86::SP, X86::SPL, 
                                       X86::YMM11, X86::XMM11, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::RBP, X86::BPL, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R13, X86::R13B, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R13D, X86::R13B, 
                                       X86::R13W, X86::R13B, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::ECX, X86::CH, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::CX, X86::CL, 
                                       X86::R8, X86::R8W, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R8D, X86::R8W, 
                                       X86::YMM12, X86::XMM12, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::RBX, X86::BX, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R13, X86::R13D, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::ECX, X86::CL, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R10, X86::R10B, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R10D, X86::R10B, 
                                       X86::R10W, X86::R10B, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::YMM13, X86::XMM13, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R13, X86::R13W, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R13D, X86::R13W, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::RCX, X86::CH, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R10, X86::R10D, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R9, X86::R9B, 
                                       X86::YMM14, X86::XMM14, 
                                       X86::R9D, X86::R9B, 
                                       X86::R9W, X86::R9B, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::RCX, X86::CL, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::ECX, X86::CX, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::EDX, X86::DX, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::RCX, X86::ECX, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R10, X86::R10W, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R10D, X86::R10W, 
                                       X86::R9, X86::R9D, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::YMM15, X86::XMM15, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::DX, X86::DH, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
X86::NoRegister, X86::NoRegister };
  const unsigned SubregHashTableSize = 512;


  // Number of hash collisions: 23
  const unsigned SuperregHashTable[] = { X86::DX, X86::RDX, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::BP, X86::RBP, 
                                       X86::BPL, X86::RBP, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::EDX, X86::RDX, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::XMM14, X86::YMM14, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::BP, X86::EBP, 
                                       X86::BPL, X86::EBP, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::DIL, X86::DI, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R9B, X86::R9W, 
                                       X86::R11B, X86::R11, 
                                       X86::R11D, X86::R11, 
                                       X86::R11W, X86::R11, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::EBP, X86::RBP, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R14D, X86::R14, 
                                       X86::R14B, X86::R14D, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R14W, X86::R14D, 
                                       X86::BH, X86::RBX, 
                                       X86::BL, X86::RBX, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::BX, X86::RBX, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::XMM15, X86::YMM15, 
                                       X86::BH, X86::EBX, 
                                       X86::BL, X86::EBX, 
                                       X86::EIP, X86::RIP, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::BX, X86::EBX, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::IP, X86::RIP, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::EBX, X86::RBX, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::IP, X86::EIP, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R14B, X86::R14W, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::XMM2, X86::YMM2, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::ESI, X86::RSI, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R11B, X86::R11D, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R11W, X86::R11D, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::AH, X86::AX, 
                                       X86::AL, X86::AX, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R15B, X86::R15, 
                                       X86::R15D, X86::R15, 
                                       X86::R15W, X86::R15, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::XMM3, X86::YMM3, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::ESP, X86::RSP, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R11B, X86::R11W, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::SI, X86::RSI, 
                                       X86::SIL, X86::RSI, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::XMM4, X86::YMM4, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R12B, X86::R12, 
                                       X86::R12D, X86::R12, 
                                       X86::R12W, X86::R12, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R15B, X86::R15D, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R15W, X86::R15D, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::SP, X86::RSP, 
                                       X86::SPL, X86::RSP, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::XMM5, X86::YMM5, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::SI, X86::ESI, 
                                       X86::SIL, X86::ESI, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::BPL, X86::BP, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R15B, X86::R15W, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::SIL, X86::SI, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::XMM6, X86::YMM6, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::SP, X86::ESP, 
                                       X86::SPL, X86::ESP, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R12B, X86::R12D, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R12W, X86::R12D, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R8B, X86::R8, 
                                       X86::R8D, X86::R8, 
                                       X86::R8W, X86::R8, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::XMM7, X86::YMM7, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R12B, X86::R12W, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::XMM0, X86::YMM0, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::BH, X86::BX, 
                                       X86::BL, X86::BX, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::SPL, X86::SP, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::XMM8, X86::YMM8, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R13B, X86::R13, 
                                       X86::R13D, X86::R13, 
                                       X86::R13W, X86::R13, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::XMM1, X86::YMM1, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R8B, X86::R8D, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R8W, X86::R8D, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::XMM9, X86::YMM9, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::XMM10, X86::YMM10, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R8B, X86::R8W, 
                                       X86::R10B, X86::R10, 
                                       X86::R10D, X86::R10, 
                                       X86::R10W, X86::R10, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::CH, X86::ECX, 
                                       X86::CL, X86::ECX, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::CX, X86::ECX, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R13B, X86::R13D, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R13W, X86::R13D, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::XMM11, X86::YMM11, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::CH, X86::RCX, 
                                       X86::CL, X86::RCX, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::CX, X86::RCX, 
                                       X86::R9B, X86::R9, 
                                       X86::R9D, X86::R9, 
                                       X86::R9W, X86::R9, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::DI, X86::EDI, 
                                       X86::DIL, X86::EDI, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R13B, X86::R13W, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::ECX, X86::RCX, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::XMM12, X86::YMM12, 
                                       X86::CH, X86::CX, 
                                       X86::CL, X86::CX, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R10B, X86::R10D, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R10W, X86::R10D, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::DH, X86::DX, 
                                       X86::DIL, X86::RDI, 
                                       X86::DI, X86::RDI, 
                                       X86::DL, X86::DX, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::DH, X86::EDX, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::DL, X86::EDX, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::AH, X86::RAX, 
                                       X86::AL, X86::RAX, 
                                       X86::AX, X86::RAX, 
                                       X86::DX, X86::EDX, 
                                       X86::R14W, X86::R14, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R14B, X86::R14, 
                                       X86::AH, X86::EAX, 
                                       X86::AL, X86::EAX, 
                                       X86::AX, X86::EAX, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::EDI, X86::RDI, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R10B, X86::R10W, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::DH, X86::RDX, 
                                       X86::XMM13, X86::YMM13, 
                                       X86::R9B, X86::R9D, 
                                       X86::DL, X86::RDX, 
                                       X86::R9W, X86::R9D, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::EAX, X86::RAX, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
X86::NoRegister, X86::NoRegister };
  const unsigned SuperregHashTableSize = 512;


  // Number of hash collisions: 31
  const unsigned AliasesHashTable[] = { X86::DX, X86::RDX, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R14, X86::R14B, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R14D, X86::R14B, 
                                       X86::R14W, X86::R14B, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::EDX, X86::RDX, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::BP, X86::EBP, 
                                       X86::BPL, X86::EBP, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::YMM2, X86::XMM2, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::EIP, X86::IP, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::AX, X86::AH, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R14, X86::R14D, 
                                       X86::R14B, X86::R14D, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R14W, X86::R14D, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::RDX, X86::DX, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::BH, X86::EBX, 
                                       X86::BL, X86::EBX, 
                                       X86::EIP, X86::RIP, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::BX, X86::EBX, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::EAX, X86::AH, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::IP, X86::RIP, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::YMM3, X86::XMM3, 
                                       X86::RAX, X86::EAX, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::AX, X86::AL, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R14, X86::R14W, 
                                       X86::R14B, X86::R14W, 
                                       X86::R14D, X86::R14W, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::ESI, X86::RSI, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::RIP, X86::IP, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::EAX, X86::AL, 
                                       X86::YMM4, X86::XMM4, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::RBP, X86::EBP, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::AH, X86::AX, 
                                       X86::AL, X86::AX, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R15B, X86::R15, 
                                       X86::R15D, X86::R15, 
                                       X86::R15W, X86::R15, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::ESP, X86::RSP, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::RAX, X86::AH, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::EAX, X86::AX, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::YMM5, X86::XMM5, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::RBX, X86::EBX, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::BX, X86::BH, 
                                       X86::R15, X86::R15B, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R15D, X86::R15B, 
                                       X86::R15W, X86::R15B, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::SI, X86::RSI, 
                                       X86::SIL, X86::RSI, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::ESI, X86::SI, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::RAX, X86::AL, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::EBX, X86::BH, 
                                       X86::YMM6, X86::XMM6, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::BX, X86::BL, 
                                       X86::R15, X86::R15D, 
                                       X86::R15B, X86::R15D, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R15W, X86::R15D, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::SP, X86::RSP, 
                                       X86::SPL, X86::RSP, 
                                       X86::ESI, X86::SIL, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::RAX, X86::AX, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::EBX, X86::BL, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::YMM7, X86::XMM7, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::BPL, X86::BP, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R15, X86::R15W, 
                                       X86::R15B, X86::R15W, 
                                       X86::R15D, X86::R15W, 
                                       X86::RSI, X86::SI, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::SIL, X86::SI, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::ESP, X86::SP, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::RBX, X86::BH, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::EBP, X86::BP, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::YMM8, X86::XMM8, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::BP, X86::BPL, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::RSI, X86::SIL, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R8B, X86::R8, 
                                       X86::R8D, X86::R8, 
                                       X86::R8W, X86::R8, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::ESP, X86::SPL, 
                                       X86::SI, X86::SIL, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::RBX, X86::BL, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::EBP, X86::BPL, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::YMM9, X86::XMM9, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::XMM0, X86::YMM0, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::BH, X86::BX, 
                                       X86::BL, X86::BX, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R8, X86::R8B, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R8D, X86::R8B, 
                                       X86::R8W, X86::R8B, 
                                       X86::SPL, X86::SP, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::RSP, X86::SP, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::RBP, X86::BP, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::EBX, X86::BX, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::XMM1, X86::YMM1, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::CX, X86::CH, 
                                       X86::R8, X86::R8D, 
                                       X86::R8B, X86::R8D, 
                                       X86::RSP, X86::SPL, 
                                       X86::R8W, X86::R8D, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::SP, X86::SPL, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::RBP, X86::BPL, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::ECX, X86::CH, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::XMM10, X86::YMM10, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::CX, X86::CL, 
                                       X86::R8, X86::R8W, 
                                       X86::R8B, X86::R8W, 
                                       X86::R10B, X86::R10, 
                                       X86::R10D, X86::R10, 
                                       X86::R10W, X86::R10, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::CH, X86::ECX, 
                                       X86::CL, X86::ECX, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::CX, X86::ECX, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::RBX, X86::BX, 
                                       X86::R8D, X86::R8W, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::ECX, X86::CL, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::XMM11, X86::YMM11, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R10, X86::R10B, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R10D, X86::R10B, 
                                       X86::R10W, X86::R10B, 
                                       X86::R9B, X86::R9, 
                                       X86::R9D, X86::R9, 
                                       X86::R9W, X86::R9, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::DI, X86::EDI, 
                                       X86::DIL, X86::EDI, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::RCX, X86::CH, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::XMM12, X86::YMM12, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::CH, X86::CX, 
                                       X86::CL, X86::CX, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R10, X86::R10D, 
                                       X86::R10B, X86::R10D, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R10W, X86::R10D, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R9, X86::R9B, 
                                       X86::R9W, X86::R9B, 
                                       X86::R9D, X86::R9B, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::DH, X86::EDX, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::DL, X86::EDX, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::RCX, X86::CL, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::AH, X86::RAX, 
                                       X86::AL, X86::RAX, 
                                       X86::AX, X86::RAX, 
                                       X86::DX, X86::EDX, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::ECX, X86::CX, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::RCX, X86::ECX, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::XMM13, X86::YMM13, 
                                       X86::R10, X86::R10W, 
                                       X86::R10B, X86::R10W, 
                                       X86::R10D, X86::R10W, 
                                       X86::R9, X86::R9D, 
                                       X86::R9B, X86::R9D, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R9W, X86::R9D, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::DX, X86::DH, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::EAX, X86::RAX, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::EDX, X86::DH, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::BP, X86::RBP, 
                                       X86::BPL, X86::RBP, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::XMM14, X86::YMM14, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::RDI, X86::EDI, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::DIL, X86::DI, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R9, X86::R9W, 
                                       X86::R9B, X86::R9W, 
                                       X86::R11B, X86::R11, 
                                       X86::R11D, X86::R11, 
                                       X86::R11W, X86::R11, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R9D, X86::R9W, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::EBP, X86::RBP, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::RCX, X86::CX, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::EDI, X86::DI, 
                                       X86::BH, X86::RBX, 
                                       X86::BL, X86::RBX, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::BX, X86::RBX, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::XMM15, X86::YMM15, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::RDX, X86::EDX, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::DI, X86::DIL, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R11, X86::R11B, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R11D, X86::R11B, 
                                       X86::R11W, X86::R11B, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::EBX, X86::RBX, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::IP, X86::EIP, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::RDX, X86::DH, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::EDI, X86::DIL, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::XMM2, X86::YMM2, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R11, X86::R11D, 
                                       X86::R11B, X86::R11D, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R11W, X86::R11D, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::DX, X86::DL, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::RDI, X86::DI, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::EDX, X86::DL, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::XMM3, X86::YMM3, 
                                       X86::RIP, X86::EIP, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R11, X86::R11W, 
                                       X86::R11B, X86::R11W, 
                                       X86::R11D, X86::R11W, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::RDI, X86::DIL, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::XMM4, X86::YMM4, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R12B, X86::R12, 
                                       X86::R12D, X86::R12, 
                                       X86::R12W, X86::R12, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::RDX, X86::DL, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::RSI, X86::ESI, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::SI, X86::ESI, 
                                       X86::SIL, X86::ESI, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::XMM5, X86::YMM5, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R12, X86::R12B, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R12D, X86::R12B, 
                                       X86::R12W, X86::R12B, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::YMM0, X86::XMM0, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::RSP, X86::ESP, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::XMM6, X86::YMM6, 
                                       X86::SP, X86::ESP, 
                                       X86::SPL, X86::ESP, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R12, X86::R12D, 
                                       X86::R12B, X86::R12D, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R12W, X86::R12D, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::YMM1, X86::XMM1, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::XMM7, X86::YMM7, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R12, X86::R12W, 
                                       X86::R12B, X86::R12W, 
                                       X86::R12D, X86::R12W, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::YMM10, X86::XMM10, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::XMM8, X86::YMM8, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R13B, X86::R13, 
                                       X86::R13D, X86::R13, 
                                       X86::R13W, X86::R13, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::YMM11, X86::XMM11, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::XMM9, X86::YMM9, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R13, X86::R13B, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R13D, X86::R13B, 
                                       X86::R13W, X86::R13B, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::YMM12, X86::XMM12, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R13, X86::R13D, 
                                       X86::R13B, X86::R13D, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R13W, X86::R13D, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::CH, X86::RCX, 
                                       X86::CL, X86::RCX, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::CX, X86::RCX, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::YMM13, X86::XMM13, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R13, X86::R13W, 
                                       X86::R13B, X86::R13W, 
                                       X86::R13D, X86::R13W, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::ECX, X86::RCX, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::YMM14, X86::XMM14, 
                                       X86::DH, X86::DX, 
                                       X86::DIL, X86::RDI, 
                                       X86::DI, X86::RDI, 
                                       X86::DL, X86::DX, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::R14B, X86::R14, 
                                       X86::R14D, X86::R14, 
                                       X86::R14W, X86::R14, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::AH, X86::EAX, 
                                       X86::AL, X86::EAX, 
                                       X86::AX, X86::EAX, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::EDX, X86::DX, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::EDI, X86::RDI, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::DH, X86::RDX, 
                                       X86::YMM15, X86::XMM15, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::DL, X86::RDX, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
                                       X86::NoRegister, X86::NoRegister, 
X86::NoRegister, X86::NoRegister };
  const unsigned AliasesHashTableSize = 1024;


  // Register Alias Sets...
  const unsigned Empty_AliasSet[] = { 0 };
  const unsigned AH_AliasSet[] = { X86::AX, X86::EAX, X86::RAX, 0 };
  const unsigned AL_AliasSet[] = { X86::AX, X86::EAX, X86::RAX, 0 };
  const unsigned AX_AliasSet[] = { X86::AL, X86::AH, X86::EAX, X86::RAX, 0 };
  const unsigned BH_AliasSet[] = { X86::BX, X86::EBX, X86::RBX, 0 };
  const unsigned BL_AliasSet[] = { X86::BX, X86::EBX, X86::RBX, 0 };
  const unsigned BP_AliasSet[] = { X86::BPL, X86::EBP, X86::RBP, 0 };
  const unsigned BPL_AliasSet[] = { X86::BP, X86::EBP, X86::RBP, 0 };
  const unsigned BX_AliasSet[] = { X86::BL, X86::BH, X86::EBX, X86::RBX, 0 };
  const unsigned CH_AliasSet[] = { X86::CX, X86::ECX, X86::RCX, 0 };
  const unsigned CL_AliasSet[] = { X86::CX, X86::ECX, X86::RCX, 0 };
  const unsigned CS_AliasSet[] = { 0 };
  const unsigned CX_AliasSet[] = { X86::CL, X86::CH, X86::ECX, X86::RCX, 0 };
  const unsigned DH_AliasSet[] = { X86::DX, X86::EDX, X86::RDX, 0 };
  const unsigned DI_AliasSet[] = { X86::DIL, X86::EDI, X86::RDI, 0 };
  const unsigned DIL_AliasSet[] = { X86::DI, X86::EDI, X86::RDI, 0 };
  const unsigned DL_AliasSet[] = { X86::DX, X86::EDX, X86::RDX, 0 };
  const unsigned DR0_AliasSet[] = { 0 };
  const unsigned DR1_AliasSet[] = { 0 };
  const unsigned DR2_AliasSet[] = { 0 };
  const unsigned DR3_AliasSet[] = { 0 };
  const unsigned DR4_AliasSet[] = { 0 };
  const unsigned DR5_AliasSet[] = { 0 };
  const unsigned DR6_AliasSet[] = { 0 };
  const unsigned DR7_AliasSet[] = { 0 };
  const unsigned DS_AliasSet[] = { 0 };
  const unsigned DX_AliasSet[] = { X86::DL, X86::DH, X86::EDX, X86::RDX, 0 };
  const unsigned EAX_AliasSet[] = { X86::AL, X86::AH, X86::AX, X86::RAX, 0 };
  const unsigned EBP_AliasSet[] = { X86::BPL, X86::BP, X86::RBP, 0 };
  const unsigned EBX_AliasSet[] = { X86::BL, X86::BH, X86::BX, X86::RBX, 0 };
  const unsigned ECR0_AliasSet[] = { 0 };
  const unsigned ECR1_AliasSet[] = { 0 };
  const unsigned ECR2_AliasSet[] = { 0 };
  const unsigned ECR3_AliasSet[] = { 0 };
  const unsigned ECR4_AliasSet[] = { 0 };
  const unsigned ECR5_AliasSet[] = { 0 };
  const unsigned ECR6_AliasSet[] = { 0 };
  const unsigned ECR7_AliasSet[] = { 0 };
  const unsigned ECX_AliasSet[] = { X86::CL, X86::CH, X86::CX, X86::RCX, 0 };
  const unsigned EDI_AliasSet[] = { X86::DIL, X86::DI, X86::RDI, 0 };
  const unsigned EDX_AliasSet[] = { X86::DL, X86::DH, X86::DX, X86::RDX, 0 };
  const unsigned EFLAGS_AliasSet[] = { 0 };
  const unsigned EIP_AliasSet[] = { X86::IP, X86::RIP, 0 };
  const unsigned ES_AliasSet[] = { 0 };
  const unsigned ESI_AliasSet[] = { X86::SIL, X86::SI, X86::RSI, 0 };
  const unsigned ESP_AliasSet[] = { X86::SPL, X86::SP, X86::RSP, 0 };
  const unsigned FP0_AliasSet[] = { 0 };
  const unsigned FP1_AliasSet[] = { 0 };
  const unsigned FP2_AliasSet[] = { 0 };
  const unsigned FP3_AliasSet[] = { 0 };
  const unsigned FP4_AliasSet[] = { 0 };
  const unsigned FP5_AliasSet[] = { 0 };
  const unsigned FP6_AliasSet[] = { 0 };
  const unsigned FS_AliasSet[] = { 0 };
  const unsigned GS_AliasSet[] = { 0 };
  const unsigned IP_AliasSet[] = { X86::EIP, X86::RIP, 0 };
  const unsigned MM0_AliasSet[] = { 0 };
  const unsigned MM1_AliasSet[] = { 0 };
  const unsigned MM2_AliasSet[] = { 0 };
  const unsigned MM3_AliasSet[] = { 0 };
  const unsigned MM4_AliasSet[] = { 0 };
  const unsigned MM5_AliasSet[] = { 0 };
  const unsigned MM6_AliasSet[] = { 0 };
  const unsigned MM7_AliasSet[] = { 0 };
  const unsigned R10_AliasSet[] = { X86::R10B, X86::R10W, X86::R10D, 0 };
  const unsigned R10B_AliasSet[] = { X86::R10W, X86::R10D, X86::R10, 0 };
  const unsigned R10D_AliasSet[] = { X86::R10B, X86::R10W, X86::R10, 0 };
  const unsigned R10W_AliasSet[] = { X86::R10B, X86::R10D, X86::R10, 0 };
  const unsigned R11_AliasSet[] = { X86::R11B, X86::R11W, X86::R11D, 0 };
  const unsigned R11B_AliasSet[] = { X86::R11W, X86::R11D, X86::R11, 0 };
  const unsigned R11D_AliasSet[] = { X86::R11B, X86::R11W, X86::R11, 0 };
  const unsigned R11W_AliasSet[] = { X86::R11B, X86::R11D, X86::R11, 0 };
  const unsigned R12_AliasSet[] = { X86::R12B, X86::R12W, X86::R12D, 0 };
  const unsigned R12B_AliasSet[] = { X86::R12W, X86::R12D, X86::R12, 0 };
  const unsigned R12D_AliasSet[] = { X86::R12B, X86::R12W, X86::R12, 0 };
  const unsigned R12W_AliasSet[] = { X86::R12B, X86::R12D, X86::R12, 0 };
  const unsigned R13_AliasSet[] = { X86::R13B, X86::R13W, X86::R13D, 0 };
  const unsigned R13B_AliasSet[] = { X86::R13W, X86::R13D, X86::R13, 0 };
  const unsigned R13D_AliasSet[] = { X86::R13B, X86::R13W, X86::R13, 0 };
  const unsigned R13W_AliasSet[] = { X86::R13B, X86::R13D, X86::R13, 0 };
  const unsigned R14_AliasSet[] = { X86::R14B, X86::R14W, X86::R14D, 0 };
  const unsigned R14B_AliasSet[] = { X86::R14W, X86::R14D, X86::R14, 0 };
  const unsigned R14D_AliasSet[] = { X86::R14B, X86::R14W, X86::R14, 0 };
  const unsigned R14W_AliasSet[] = { X86::R14B, X86::R14D, X86::R14, 0 };
  const unsigned R15_AliasSet[] = { X86::R15B, X86::R15W, X86::R15D, 0 };
  const unsigned R15B_AliasSet[] = { X86::R15W, X86::R15D, X86::R15, 0 };
  const unsigned R15D_AliasSet[] = { X86::R15B, X86::R15W, X86::R15, 0 };
  const unsigned R15W_AliasSet[] = { X86::R15B, X86::R15D, X86::R15, 0 };
  const unsigned R8_AliasSet[] = { X86::R8B, X86::R8W, X86::R8D, 0 };
  const unsigned R8B_AliasSet[] = { X86::R8W, X86::R8D, X86::R8, 0 };
  const unsigned R8D_AliasSet[] = { X86::R8B, X86::R8W, X86::R8, 0 };
  const unsigned R8W_AliasSet[] = { X86::R8B, X86::R8D, X86::R8, 0 };
  const unsigned R9_AliasSet[] = { X86::R9B, X86::R9W, X86::R9D, 0 };
  const unsigned R9B_AliasSet[] = { X86::R9W, X86::R9D, X86::R9, 0 };
  const unsigned R9D_AliasSet[] = { X86::R9B, X86::R9W, X86::R9, 0 };
  const unsigned R9W_AliasSet[] = { X86::R9B, X86::R9D, X86::R9, 0 };
  const unsigned RAX_AliasSet[] = { X86::AL, X86::AH, X86::AX, X86::EAX, 0 };
  const unsigned RBP_AliasSet[] = { X86::BPL, X86::BP, X86::EBP, 0 };
  const unsigned RBX_AliasSet[] = { X86::BL, X86::BH, X86::BX, X86::EBX, 0 };
  const unsigned RCR0_AliasSet[] = { 0 };
  const unsigned RCR1_AliasSet[] = { 0 };
  const unsigned RCR2_AliasSet[] = { 0 };
  const unsigned RCR3_AliasSet[] = { 0 };
  const unsigned RCR4_AliasSet[] = { 0 };
  const unsigned RCR5_AliasSet[] = { 0 };
  const unsigned RCR6_AliasSet[] = { 0 };
  const unsigned RCR7_AliasSet[] = { 0 };
  const unsigned RCR8_AliasSet[] = { 0 };
  const unsigned RCX_AliasSet[] = { X86::CL, X86::CH, X86::CX, X86::ECX, 0 };
  const unsigned RDI_AliasSet[] = { X86::DIL, X86::DI, X86::EDI, 0 };
  const unsigned RDX_AliasSet[] = { X86::DL, X86::DH, X86::DX, X86::EDX, 0 };
  const unsigned RIP_AliasSet[] = { X86::IP, X86::EIP, 0 };
  const unsigned RSI_AliasSet[] = { X86::SIL, X86::SI, X86::ESI, 0 };
  const unsigned RSP_AliasSet[] = { X86::SPL, X86::SP, X86::ESP, 0 };
  const unsigned SI_AliasSet[] = { X86::SIL, X86::ESI, X86::RSI, 0 };
  const unsigned SIL_AliasSet[] = { X86::SI, X86::ESI, X86::RSI, 0 };
  const unsigned SP_AliasSet[] = { X86::SPL, X86::ESP, X86::RSP, 0 };
  const unsigned SPL_AliasSet[] = { X86::SP, X86::ESP, X86::RSP, 0 };
  const unsigned SS_AliasSet[] = { 0 };
  const unsigned ST0_AliasSet[] = { 0 };
  const unsigned ST1_AliasSet[] = { 0 };
  const unsigned ST2_AliasSet[] = { 0 };
  const unsigned ST3_AliasSet[] = { 0 };
  const unsigned ST4_AliasSet[] = { 0 };
  const unsigned ST5_AliasSet[] = { 0 };
  const unsigned ST6_AliasSet[] = { 0 };
  const unsigned ST7_AliasSet[] = { 0 };
  const unsigned XMM0_AliasSet[] = { X86::YMM0, 0 };
  const unsigned XMM1_AliasSet[] = { X86::YMM1, 0 };
  const unsigned XMM10_AliasSet[] = { X86::YMM10, 0 };
  const unsigned XMM11_AliasSet[] = { X86::YMM11, 0 };
  const unsigned XMM12_AliasSet[] = { X86::YMM12, 0 };
  const unsigned XMM13_AliasSet[] = { X86::YMM13, 0 };
  const unsigned XMM14_AliasSet[] = { X86::YMM14, 0 };
  const unsigned XMM15_AliasSet[] = { X86::YMM15, 0 };
  const unsigned XMM2_AliasSet[] = { X86::YMM2, 0 };
  const unsigned XMM3_AliasSet[] = { X86::YMM3, 0 };
  const unsigned XMM4_AliasSet[] = { X86::YMM4, 0 };
  const unsigned XMM5_AliasSet[] = { X86::YMM5, 0 };
  const unsigned XMM6_AliasSet[] = { X86::YMM6, 0 };
  const unsigned XMM7_AliasSet[] = { X86::YMM7, 0 };
  const unsigned XMM8_AliasSet[] = { X86::YMM8, 0 };
  const unsigned XMM9_AliasSet[] = { X86::YMM9, 0 };
  const unsigned YMM0_AliasSet[] = { X86::XMM0, 0 };
  const unsigned YMM1_AliasSet[] = { X86::XMM1, 0 };
  const unsigned YMM10_AliasSet[] = { X86::XMM10, 0 };
  const unsigned YMM11_AliasSet[] = { X86::XMM11, 0 };
  const unsigned YMM12_AliasSet[] = { X86::XMM12, 0 };
  const unsigned YMM13_AliasSet[] = { X86::XMM13, 0 };
  const unsigned YMM14_AliasSet[] = { X86::XMM14, 0 };
  const unsigned YMM15_AliasSet[] = { X86::XMM15, 0 };
  const unsigned YMM2_AliasSet[] = { X86::XMM2, 0 };
  const unsigned YMM3_AliasSet[] = { X86::XMM3, 0 };
  const unsigned YMM4_AliasSet[] = { X86::XMM4, 0 };
  const unsigned YMM5_AliasSet[] = { X86::XMM5, 0 };
  const unsigned YMM6_AliasSet[] = { X86::XMM6, 0 };
  const unsigned YMM7_AliasSet[] = { X86::XMM7, 0 };
  const unsigned YMM8_AliasSet[] = { X86::XMM8, 0 };
  const unsigned YMM9_AliasSet[] = { X86::XMM9, 0 };


  // Register Sub-registers Sets...
  const unsigned Empty_SubRegsSet[] = { 0 };
  const unsigned AH_SubRegsSet[] = { 0 };
  const unsigned AL_SubRegsSet[] = { 0 };
  const unsigned AX_SubRegsSet[] = { X86::AL, X86::AH, 0 };
  const unsigned BH_SubRegsSet[] = { 0 };
  const unsigned BL_SubRegsSet[] = { 0 };
  const unsigned BP_SubRegsSet[] = { X86::BPL, 0 };
  const unsigned BPL_SubRegsSet[] = { 0 };
  const unsigned BX_SubRegsSet[] = { X86::BL, X86::BH, 0 };
  const unsigned CH_SubRegsSet[] = { 0 };
  const unsigned CL_SubRegsSet[] = { 0 };
  const unsigned CS_SubRegsSet[] = { 0 };
  const unsigned CX_SubRegsSet[] = { X86::CL, X86::CH, 0 };
  const unsigned DH_SubRegsSet[] = { 0 };
  const unsigned DI_SubRegsSet[] = { X86::DIL, 0 };
  const unsigned DIL_SubRegsSet[] = { 0 };
  const unsigned DL_SubRegsSet[] = { 0 };
  const unsigned DR0_SubRegsSet[] = { 0 };
  const unsigned DR1_SubRegsSet[] = { 0 };
  const unsigned DR2_SubRegsSet[] = { 0 };
  const unsigned DR3_SubRegsSet[] = { 0 };
  const unsigned DR4_SubRegsSet[] = { 0 };
  const unsigned DR5_SubRegsSet[] = { 0 };
  const unsigned DR6_SubRegsSet[] = { 0 };
  const unsigned DR7_SubRegsSet[] = { 0 };
  const unsigned DS_SubRegsSet[] = { 0 };
  const unsigned DX_SubRegsSet[] = { X86::DL, X86::DH, 0 };
  const unsigned EAX_SubRegsSet[] = { X86::AX, X86::AL, X86::AH, 0 };
  const unsigned EBP_SubRegsSet[] = { X86::BP, X86::BPL, 0 };
  const unsigned EBX_SubRegsSet[] = { X86::BX, X86::BL, X86::BH, 0 };
  const unsigned ECR0_SubRegsSet[] = { 0 };
  const unsigned ECR1_SubRegsSet[] = { 0 };
  const unsigned ECR2_SubRegsSet[] = { 0 };
  const unsigned ECR3_SubRegsSet[] = { 0 };
  const unsigned ECR4_SubRegsSet[] = { 0 };
  const unsigned ECR5_SubRegsSet[] = { 0 };
  const unsigned ECR6_SubRegsSet[] = { 0 };
  const unsigned ECR7_SubRegsSet[] = { 0 };
  const unsigned ECX_SubRegsSet[] = { X86::CX, X86::CL, X86::CH, 0 };
  const unsigned EDI_SubRegsSet[] = { X86::DI, X86::DIL, 0 };
  const unsigned EDX_SubRegsSet[] = { X86::DX, X86::DL, X86::DH, 0 };
  const unsigned EFLAGS_SubRegsSet[] = { 0 };
  const unsigned EIP_SubRegsSet[] = { X86::IP, 0 };
  const unsigned ES_SubRegsSet[] = { 0 };
  const unsigned ESI_SubRegsSet[] = { X86::SI, X86::SIL, 0 };
  const unsigned ESP_SubRegsSet[] = { X86::SP, X86::SPL, 0 };
  const unsigned FP0_SubRegsSet[] = { 0 };
  const unsigned FP1_SubRegsSet[] = { 0 };
  const unsigned FP2_SubRegsSet[] = { 0 };
  const unsigned FP3_SubRegsSet[] = { 0 };
  const unsigned FP4_SubRegsSet[] = { 0 };
  const unsigned FP5_SubRegsSet[] = { 0 };
  const unsigned FP6_SubRegsSet[] = { 0 };
  const unsigned FS_SubRegsSet[] = { 0 };
  const unsigned GS_SubRegsSet[] = { 0 };
  const unsigned IP_SubRegsSet[] = { 0 };
  const unsigned MM0_SubRegsSet[] = { 0 };
  const unsigned MM1_SubRegsSet[] = { 0 };
  const unsigned MM2_SubRegsSet[] = { 0 };
  const unsigned MM3_SubRegsSet[] = { 0 };
  const unsigned MM4_SubRegsSet[] = { 0 };
  const unsigned MM5_SubRegsSet[] = { 0 };
  const unsigned MM6_SubRegsSet[] = { 0 };
  const unsigned MM7_SubRegsSet[] = { 0 };
  const unsigned R10_SubRegsSet[] = { X86::R10D, X86::R10W, X86::R10B, 0 };
  const unsigned R10B_SubRegsSet[] = { 0 };
  const unsigned R10D_SubRegsSet[] = { X86::R10W, X86::R10B, 0 };
  const unsigned R10W_SubRegsSet[] = { X86::R10B, 0 };
  const unsigned R11_SubRegsSet[] = { X86::R11D, X86::R11W, X86::R11B, 0 };
  const unsigned R11B_SubRegsSet[] = { 0 };
  const unsigned R11D_SubRegsSet[] = { X86::R11W, X86::R11B, 0 };
  const unsigned R11W_SubRegsSet[] = { X86::R11B, 0 };
  const unsigned R12_SubRegsSet[] = { X86::R12D, X86::R12W, X86::R12B, 0 };
  const unsigned R12B_SubRegsSet[] = { 0 };
  const unsigned R12D_SubRegsSet[] = { X86::R12W, X86::R12B, 0 };
  const unsigned R12W_SubRegsSet[] = { X86::R12B, 0 };
  const unsigned R13_SubRegsSet[] = { X86::R13D, X86::R13W, X86::R13B, 0 };
  const unsigned R13B_SubRegsSet[] = { 0 };
  const unsigned R13D_SubRegsSet[] = { X86::R13W, X86::R13B, 0 };
  const unsigned R13W_SubRegsSet[] = { X86::R13B, 0 };
  const unsigned R14_SubRegsSet[] = { X86::R14D, X86::R14W, X86::R14B, 0 };
  const unsigned R14B_SubRegsSet[] = { 0 };
  const unsigned R14D_SubRegsSet[] = { X86::R14W, X86::R14B, 0 };
  const unsigned R14W_SubRegsSet[] = { X86::R14B, 0 };
  const unsigned R15_SubRegsSet[] = { X86::R15D, X86::R15W, X86::R15B, 0 };
  const unsigned R15B_SubRegsSet[] = { 0 };
  const unsigned R15D_SubRegsSet[] = { X86::R15W, X86::R15B, 0 };
  const unsigned R15W_SubRegsSet[] = { X86::R15B, 0 };
  const unsigned R8_SubRegsSet[] = { X86::R8D, X86::R8W, X86::R8B, 0 };
  const unsigned R8B_SubRegsSet[] = { 0 };
  const unsigned R8D_SubRegsSet[] = { X86::R8W, X86::R8B, 0 };
  const unsigned R8W_SubRegsSet[] = { X86::R8B, 0 };
  const unsigned R9_SubRegsSet[] = { X86::R9D, X86::R9W, X86::R9B, 0 };
  const unsigned R9B_SubRegsSet[] = { 0 };
  const unsigned R9D_SubRegsSet[] = { X86::R9W, X86::R9B, 0 };
  const unsigned R9W_SubRegsSet[] = { X86::R9B, 0 };
  const unsigned RAX_SubRegsSet[] = { X86::EAX, X86::AX, X86::AL, X86::AH, 0 };
  const unsigned RBP_SubRegsSet[] = { X86::EBP, X86::BP, X86::BPL, 0 };
  const unsigned RBX_SubRegsSet[] = { X86::EBX, X86::BX, X86::BL, X86::BH, 0 };
  const unsigned RCR0_SubRegsSet[] = { 0 };
  const unsigned RCR1_SubRegsSet[] = { 0 };
  const unsigned RCR2_SubRegsSet[] = { 0 };
  const unsigned RCR3_SubRegsSet[] = { 0 };
  const unsigned RCR4_SubRegsSet[] = { 0 };
  const unsigned RCR5_SubRegsSet[] = { 0 };
  const unsigned RCR6_SubRegsSet[] = { 0 };
  const unsigned RCR7_SubRegsSet[] = { 0 };
  const unsigned RCR8_SubRegsSet[] = { 0 };
  const unsigned RCX_SubRegsSet[] = { X86::ECX, X86::CX, X86::CL, X86::CH, 0 };
  const unsigned RDI_SubRegsSet[] = { X86::EDI, X86::DI, X86::DIL, 0 };
  const unsigned RDX_SubRegsSet[] = { X86::EDX, X86::DX, X86::DL, X86::DH, 0 };
  const unsigned RIP_SubRegsSet[] = { X86::EIP, X86::IP, 0 };
  const unsigned RSI_SubRegsSet[] = { X86::ESI, X86::SI, X86::SIL, 0 };
  const unsigned RSP_SubRegsSet[] = { X86::ESP, X86::SP, X86::SPL, 0 };
  const unsigned SI_SubRegsSet[] = { X86::SIL, 0 };
  const unsigned SIL_SubRegsSet[] = { 0 };
  const unsigned SP_SubRegsSet[] = { X86::SPL, 0 };
  const unsigned SPL_SubRegsSet[] = { 0 };
  const unsigned SS_SubRegsSet[] = { 0 };
  const unsigned ST0_SubRegsSet[] = { 0 };
  const unsigned ST1_SubRegsSet[] = { 0 };
  const unsigned ST2_SubRegsSet[] = { 0 };
  const unsigned ST3_SubRegsSet[] = { 0 };
  const unsigned ST4_SubRegsSet[] = { 0 };
  const unsigned ST5_SubRegsSet[] = { 0 };
  const unsigned ST6_SubRegsSet[] = { 0 };
  const unsigned ST7_SubRegsSet[] = { 0 };
  const unsigned XMM0_SubRegsSet[] = { 0 };
  const unsigned XMM1_SubRegsSet[] = { 0 };
  const unsigned XMM10_SubRegsSet[] = { 0 };
  const unsigned XMM11_SubRegsSet[] = { 0 };
  const unsigned XMM12_SubRegsSet[] = { 0 };
  const unsigned XMM13_SubRegsSet[] = { 0 };
  const unsigned XMM14_SubRegsSet[] = { 0 };
  const unsigned XMM15_SubRegsSet[] = { 0 };
  const unsigned XMM2_SubRegsSet[] = { 0 };
  const unsigned XMM3_SubRegsSet[] = { 0 };
  const unsigned XMM4_SubRegsSet[] = { 0 };
  const unsigned XMM5_SubRegsSet[] = { 0 };
  const unsigned XMM6_SubRegsSet[] = { 0 };
  const unsigned XMM7_SubRegsSet[] = { 0 };
  const unsigned XMM8_SubRegsSet[] = { 0 };
  const unsigned XMM9_SubRegsSet[] = { 0 };
  const unsigned YMM0_SubRegsSet[] = { X86::XMM0, 0 };
  const unsigned YMM1_SubRegsSet[] = { X86::XMM1, 0 };
  const unsigned YMM10_SubRegsSet[] = { X86::XMM10, 0 };
  const unsigned YMM11_SubRegsSet[] = { X86::XMM11, 0 };
  const unsigned YMM12_SubRegsSet[] = { X86::XMM12, 0 };
  const unsigned YMM13_SubRegsSet[] = { X86::XMM13, 0 };
  const unsigned YMM14_SubRegsSet[] = { X86::XMM14, 0 };
  const unsigned YMM15_SubRegsSet[] = { X86::XMM15, 0 };
  const unsigned YMM2_SubRegsSet[] = { X86::XMM2, 0 };
  const unsigned YMM3_SubRegsSet[] = { X86::XMM3, 0 };
  const unsigned YMM4_SubRegsSet[] = { X86::XMM4, 0 };
  const unsigned YMM5_SubRegsSet[] = { X86::XMM5, 0 };
  const unsigned YMM6_SubRegsSet[] = { X86::XMM6, 0 };
  const unsigned YMM7_SubRegsSet[] = { X86::XMM7, 0 };
  const unsigned YMM8_SubRegsSet[] = { X86::XMM8, 0 };
  const unsigned YMM9_SubRegsSet[] = { X86::XMM9, 0 };


  // Register Super-registers Sets...
  const unsigned Empty_SuperRegsSet[] = { 0 };
  const unsigned AH_SuperRegsSet[] = { X86::RAX, X86::EAX, X86::AX, 0 };
  const unsigned AL_SuperRegsSet[] = { X86::RAX, X86::EAX, X86::AX, 0 };
  const unsigned AX_SuperRegsSet[] = { X86::RAX, X86::EAX, 0 };
  const unsigned BH_SuperRegsSet[] = { X86::RBX, X86::EBX, X86::BX, 0 };
  const unsigned BL_SuperRegsSet[] = { X86::RBX, X86::EBX, X86::BX, 0 };
  const unsigned BP_SuperRegsSet[] = { X86::RBP, X86::EBP, 0 };
  const unsigned BPL_SuperRegsSet[] = { X86::RBP, X86::EBP, X86::BP, 0 };
  const unsigned BX_SuperRegsSet[] = { X86::RBX, X86::EBX, 0 };
  const unsigned CH_SuperRegsSet[] = { X86::RCX, X86::ECX, X86::CX, 0 };
  const unsigned CL_SuperRegsSet[] = { X86::RCX, X86::ECX, X86::CX, 0 };
  const unsigned CS_SuperRegsSet[] = { 0 };
  const unsigned CX_SuperRegsSet[] = { X86::RCX, X86::ECX, 0 };
  const unsigned DH_SuperRegsSet[] = { X86::RDX, X86::EDX, X86::DX, 0 };
  const unsigned DI_SuperRegsSet[] = { X86::RDI, X86::EDI, 0 };
  const unsigned DIL_SuperRegsSet[] = { X86::RDI, X86::EDI, X86::DI, 0 };
  const unsigned DL_SuperRegsSet[] = { X86::RDX, X86::EDX, X86::DX, 0 };
  const unsigned DR0_SuperRegsSet[] = { 0 };
  const unsigned DR1_SuperRegsSet[] = { 0 };
  const unsigned DR2_SuperRegsSet[] = { 0 };
  const unsigned DR3_SuperRegsSet[] = { 0 };
  const unsigned DR4_SuperRegsSet[] = { 0 };
  const unsigned DR5_SuperRegsSet[] = { 0 };
  const unsigned DR6_SuperRegsSet[] = { 0 };
  const unsigned DR7_SuperRegsSet[] = { 0 };
  const unsigned DS_SuperRegsSet[] = { 0 };
  const unsigned DX_SuperRegsSet[] = { X86::RDX, X86::EDX, 0 };
  const unsigned EAX_SuperRegsSet[] = { X86::RAX, 0 };
  const unsigned EBP_SuperRegsSet[] = { X86::RBP, 0 };
  const unsigned EBX_SuperRegsSet[] = { X86::RBX, 0 };
  const unsigned ECR0_SuperRegsSet[] = { 0 };
  const unsigned ECR1_SuperRegsSet[] = { 0 };
  const unsigned ECR2_SuperRegsSet[] = { 0 };
  const unsigned ECR3_SuperRegsSet[] = { 0 };
  const unsigned ECR4_SuperRegsSet[] = { 0 };
  const unsigned ECR5_SuperRegsSet[] = { 0 };
  const unsigned ECR6_SuperRegsSet[] = { 0 };
  const unsigned ECR7_SuperRegsSet[] = { 0 };
  const unsigned ECX_SuperRegsSet[] = { X86::RCX, 0 };
  const unsigned EDI_SuperRegsSet[] = { X86::RDI, 0 };
  const unsigned EDX_SuperRegsSet[] = { X86::RDX, 0 };
  const unsigned EFLAGS_SuperRegsSet[] = { 0 };
  const unsigned EIP_SuperRegsSet[] = { X86::RIP, 0 };
  const unsigned ES_SuperRegsSet[] = { 0 };
  const unsigned ESI_SuperRegsSet[] = { X86::RSI, 0 };
  const unsigned ESP_SuperRegsSet[] = { X86::RSP, 0 };
  const unsigned FP0_SuperRegsSet[] = { 0 };
  const unsigned FP1_SuperRegsSet[] = { 0 };
  const unsigned FP2_SuperRegsSet[] = { 0 };
  const unsigned FP3_SuperRegsSet[] = { 0 };
  const unsigned FP4_SuperRegsSet[] = { 0 };
  const unsigned FP5_SuperRegsSet[] = { 0 };
  const unsigned FP6_SuperRegsSet[] = { 0 };
  const unsigned FS_SuperRegsSet[] = { 0 };
  const unsigned GS_SuperRegsSet[] = { 0 };
  const unsigned IP_SuperRegsSet[] = { X86::RIP, X86::EIP, 0 };
  const unsigned MM0_SuperRegsSet[] = { 0 };
  const unsigned MM1_SuperRegsSet[] = { 0 };
  const unsigned MM2_SuperRegsSet[] = { 0 };
  const unsigned MM3_SuperRegsSet[] = { 0 };
  const unsigned MM4_SuperRegsSet[] = { 0 };
  const unsigned MM5_SuperRegsSet[] = { 0 };
  const unsigned MM6_SuperRegsSet[] = { 0 };
  const unsigned MM7_SuperRegsSet[] = { 0 };
  const unsigned R10_SuperRegsSet[] = { 0 };
  const unsigned R10B_SuperRegsSet[] = { X86::R10, X86::R10D, X86::R10W, 0 };
  const unsigned R10D_SuperRegsSet[] = { X86::R10, 0 };
  const unsigned R10W_SuperRegsSet[] = { X86::R10, X86::R10D, 0 };
  const unsigned R11_SuperRegsSet[] = { 0 };
  const unsigned R11B_SuperRegsSet[] = { X86::R11, X86::R11D, X86::R11W, 0 };
  const unsigned R11D_SuperRegsSet[] = { X86::R11, 0 };
  const unsigned R11W_SuperRegsSet[] = { X86::R11, X86::R11D, 0 };
  const unsigned R12_SuperRegsSet[] = { 0 };
  const unsigned R12B_SuperRegsSet[] = { X86::R12, X86::R12D, X86::R12W, 0 };
  const unsigned R12D_SuperRegsSet[] = { X86::R12, 0 };
  const unsigned R12W_SuperRegsSet[] = { X86::R12, X86::R12D, 0 };
  const unsigned R13_SuperRegsSet[] = { 0 };
  const unsigned R13B_SuperRegsSet[] = { X86::R13, X86::R13D, X86::R13W, 0 };
  const unsigned R13D_SuperRegsSet[] = { X86::R13, 0 };
  const unsigned R13W_SuperRegsSet[] = { X86::R13, X86::R13D, 0 };
  const unsigned R14_SuperRegsSet[] = { 0 };
  const unsigned R14B_SuperRegsSet[] = { X86::R14, X86::R14D, X86::R14W, 0 };
  const unsigned R14D_SuperRegsSet[] = { X86::R14, 0 };
  const unsigned R14W_SuperRegsSet[] = { X86::R14, X86::R14D, 0 };
  const unsigned R15_SuperRegsSet[] = { 0 };
  const unsigned R15B_SuperRegsSet[] = { X86::R15, X86::R15D, X86::R15W, 0 };
  const unsigned R15D_SuperRegsSet[] = { X86::R15, 0 };
  const unsigned R15W_SuperRegsSet[] = { X86::R15, X86::R15D, 0 };
  const unsigned R8_SuperRegsSet[] = { 0 };
  const unsigned R8B_SuperRegsSet[] = { X86::R8, X86::R8D, X86::R8W, 0 };
  const unsigned R8D_SuperRegsSet[] = { X86::R8, 0 };
  const unsigned R8W_SuperRegsSet[] = { X86::R8, X86::R8D, 0 };
  const unsigned R9_SuperRegsSet[] = { 0 };
  const unsigned R9B_SuperRegsSet[] = { X86::R9, X86::R9D, X86::R9W, 0 };
  const unsigned R9D_SuperRegsSet[] = { X86::R9, 0 };
  const unsigned R9W_SuperRegsSet[] = { X86::R9, X86::R9D, 0 };
  const unsigned RAX_SuperRegsSet[] = { 0 };
  const unsigned RBP_SuperRegsSet[] = { 0 };
  const unsigned RBX_SuperRegsSet[] = { 0 };
  const unsigned RCR0_SuperRegsSet[] = { 0 };
  const unsigned RCR1_SuperRegsSet[] = { 0 };
  const unsigned RCR2_SuperRegsSet[] = { 0 };
  const unsigned RCR3_SuperRegsSet[] = { 0 };
  const unsigned RCR4_SuperRegsSet[] = { 0 };
  const unsigned RCR5_SuperRegsSet[] = { 0 };
  const unsigned RCR6_SuperRegsSet[] = { 0 };
  const unsigned RCR7_SuperRegsSet[] = { 0 };
  const unsigned RCR8_SuperRegsSet[] = { 0 };
  const unsigned RCX_SuperRegsSet[] = { 0 };
  const unsigned RDI_SuperRegsSet[] = { 0 };
  const unsigned RDX_SuperRegsSet[] = { 0 };
  const unsigned RIP_SuperRegsSet[] = { 0 };
  const unsigned RSI_SuperRegsSet[] = { 0 };
  const unsigned RSP_SuperRegsSet[] = { 0 };
  const unsigned SI_SuperRegsSet[] = { X86::RSI, X86::ESI, 0 };
  const unsigned SIL_SuperRegsSet[] = { X86::RSI, X86::ESI, X86::SI, 0 };
  const unsigned SP_SuperRegsSet[] = { X86::RSP, X86::ESP, 0 };
  const unsigned SPL_SuperRegsSet[] = { X86::RSP, X86::ESP, X86::SP, 0 };
  const unsigned SS_SuperRegsSet[] = { 0 };
  const unsigned ST0_SuperRegsSet[] = { 0 };
  const unsigned ST1_SuperRegsSet[] = { 0 };
  const unsigned ST2_SuperRegsSet[] = { 0 };
  const unsigned ST3_SuperRegsSet[] = { 0 };
  const unsigned ST4_SuperRegsSet[] = { 0 };
  const unsigned ST5_SuperRegsSet[] = { 0 };
  const unsigned ST6_SuperRegsSet[] = { 0 };
  const unsigned ST7_SuperRegsSet[] = { 0 };
  const unsigned XMM0_SuperRegsSet[] = { X86::YMM0, 0 };
  const unsigned XMM1_SuperRegsSet[] = { X86::YMM1, 0 };
  const unsigned XMM10_SuperRegsSet[] = { X86::YMM10, 0 };
  const unsigned XMM11_SuperRegsSet[] = { X86::YMM11, 0 };
  const unsigned XMM12_SuperRegsSet[] = { X86::YMM12, 0 };
  const unsigned XMM13_SuperRegsSet[] = { X86::YMM13, 0 };
  const unsigned XMM14_SuperRegsSet[] = { X86::YMM14, 0 };
  const unsigned XMM15_SuperRegsSet[] = { X86::YMM15, 0 };
  const unsigned XMM2_SuperRegsSet[] = { X86::YMM2, 0 };
  const unsigned XMM3_SuperRegsSet[] = { X86::YMM3, 0 };
  const unsigned XMM4_SuperRegsSet[] = { X86::YMM4, 0 };
  const unsigned XMM5_SuperRegsSet[] = { X86::YMM5, 0 };
  const unsigned XMM6_SuperRegsSet[] = { X86::YMM6, 0 };
  const unsigned XMM7_SuperRegsSet[] = { X86::YMM7, 0 };
  const unsigned XMM8_SuperRegsSet[] = { X86::YMM8, 0 };
  const unsigned XMM9_SuperRegsSet[] = { X86::YMM9, 0 };
  const unsigned YMM0_SuperRegsSet[] = { 0 };
  const unsigned YMM1_SuperRegsSet[] = { 0 };
  const unsigned YMM10_SuperRegsSet[] = { 0 };
  const unsigned YMM11_SuperRegsSet[] = { 0 };
  const unsigned YMM12_SuperRegsSet[] = { 0 };
  const unsigned YMM13_SuperRegsSet[] = { 0 };
  const unsigned YMM14_SuperRegsSet[] = { 0 };
  const unsigned YMM15_SuperRegsSet[] = { 0 };
  const unsigned YMM2_SuperRegsSet[] = { 0 };
  const unsigned YMM3_SuperRegsSet[] = { 0 };
  const unsigned YMM4_SuperRegsSet[] = { 0 };
  const unsigned YMM5_SuperRegsSet[] = { 0 };
  const unsigned YMM6_SuperRegsSet[] = { 0 };
  const unsigned YMM7_SuperRegsSet[] = { 0 };
  const unsigned YMM8_SuperRegsSet[] = { 0 };
  const unsigned YMM9_SuperRegsSet[] = { 0 };

  const TargetRegisterDesc RegisterDescriptors[] = { // Descriptors
    { "NOREG",	0,	0,	0 },
    { "AH",	AH_AliasSet,	AH_SubRegsSet,	AH_SuperRegsSet },
    { "AL",	AL_AliasSet,	AL_SubRegsSet,	AL_SuperRegsSet },
    { "AX",	AX_AliasSet,	AX_SubRegsSet,	AX_SuperRegsSet },
    { "BH",	BH_AliasSet,	BH_SubRegsSet,	BH_SuperRegsSet },
    { "BL",	BL_AliasSet,	BL_SubRegsSet,	BL_SuperRegsSet },
    { "BP",	BP_AliasSet,	BP_SubRegsSet,	BP_SuperRegsSet },
    { "BPL",	BPL_AliasSet,	BPL_SubRegsSet,	BPL_SuperRegsSet },
    { "BX",	BX_AliasSet,	BX_SubRegsSet,	BX_SuperRegsSet },
    { "CH",	CH_AliasSet,	CH_SubRegsSet,	CH_SuperRegsSet },
    { "CL",	CL_AliasSet,	CL_SubRegsSet,	CL_SuperRegsSet },
    { "CS",	CS_AliasSet,	CS_SubRegsSet,	CS_SuperRegsSet },
    { "CX",	CX_AliasSet,	CX_SubRegsSet,	CX_SuperRegsSet },
    { "DH",	DH_AliasSet,	DH_SubRegsSet,	DH_SuperRegsSet },
    { "DI",	DI_AliasSet,	DI_SubRegsSet,	DI_SuperRegsSet },
    { "DIL",	DIL_AliasSet,	DIL_SubRegsSet,	DIL_SuperRegsSet },
    { "DL",	DL_AliasSet,	DL_SubRegsSet,	DL_SuperRegsSet },
    { "DR0",	DR0_AliasSet,	DR0_SubRegsSet,	DR0_SuperRegsSet },
    { "DR1",	DR1_AliasSet,	DR1_SubRegsSet,	DR1_SuperRegsSet },
    { "DR2",	DR2_AliasSet,	DR2_SubRegsSet,	DR2_SuperRegsSet },
    { "DR3",	DR3_AliasSet,	DR3_SubRegsSet,	DR3_SuperRegsSet },
    { "DR4",	DR4_AliasSet,	DR4_SubRegsSet,	DR4_SuperRegsSet },
    { "DR5",	DR5_AliasSet,	DR5_SubRegsSet,	DR5_SuperRegsSet },
    { "DR6",	DR6_AliasSet,	DR6_SubRegsSet,	DR6_SuperRegsSet },
    { "DR7",	DR7_AliasSet,	DR7_SubRegsSet,	DR7_SuperRegsSet },
    { "DS",	DS_AliasSet,	DS_SubRegsSet,	DS_SuperRegsSet },
    { "DX",	DX_AliasSet,	DX_SubRegsSet,	DX_SuperRegsSet },
    { "EAX",	EAX_AliasSet,	EAX_SubRegsSet,	EAX_SuperRegsSet },
    { "EBP",	EBP_AliasSet,	EBP_SubRegsSet,	EBP_SuperRegsSet },
    { "EBX",	EBX_AliasSet,	EBX_SubRegsSet,	EBX_SuperRegsSet },
    { "ECR0",	ECR0_AliasSet,	ECR0_SubRegsSet,	ECR0_SuperRegsSet },
    { "ECR1",	ECR1_AliasSet,	ECR1_SubRegsSet,	ECR1_SuperRegsSet },
    { "ECR2",	ECR2_AliasSet,	ECR2_SubRegsSet,	ECR2_SuperRegsSet },
    { "ECR3",	ECR3_AliasSet,	ECR3_SubRegsSet,	ECR3_SuperRegsSet },
    { "ECR4",	ECR4_AliasSet,	ECR4_SubRegsSet,	ECR4_SuperRegsSet },
    { "ECR5",	ECR5_AliasSet,	ECR5_SubRegsSet,	ECR5_SuperRegsSet },
    { "ECR6",	ECR6_AliasSet,	ECR6_SubRegsSet,	ECR6_SuperRegsSet },
    { "ECR7",	ECR7_AliasSet,	ECR7_SubRegsSet,	ECR7_SuperRegsSet },
    { "ECX",	ECX_AliasSet,	ECX_SubRegsSet,	ECX_SuperRegsSet },
    { "EDI",	EDI_AliasSet,	EDI_SubRegsSet,	EDI_SuperRegsSet },
    { "EDX",	EDX_AliasSet,	EDX_SubRegsSet,	EDX_SuperRegsSet },
    { "EFLAGS",	EFLAGS_AliasSet,	EFLAGS_SubRegsSet,	EFLAGS_SuperRegsSet },
    { "EIP",	EIP_AliasSet,	EIP_SubRegsSet,	EIP_SuperRegsSet },
    { "ES",	ES_AliasSet,	ES_SubRegsSet,	ES_SuperRegsSet },
    { "ESI",	ESI_AliasSet,	ESI_SubRegsSet,	ESI_SuperRegsSet },
    { "ESP",	ESP_AliasSet,	ESP_SubRegsSet,	ESP_SuperRegsSet },
    { "FP0",	FP0_AliasSet,	FP0_SubRegsSet,	FP0_SuperRegsSet },
    { "FP1",	FP1_AliasSet,	FP1_SubRegsSet,	FP1_SuperRegsSet },
    { "FP2",	FP2_AliasSet,	FP2_SubRegsSet,	FP2_SuperRegsSet },
    { "FP3",	FP3_AliasSet,	FP3_SubRegsSet,	FP3_SuperRegsSet },
    { "FP4",	FP4_AliasSet,	FP4_SubRegsSet,	FP4_SuperRegsSet },
    { "FP5",	FP5_AliasSet,	FP5_SubRegsSet,	FP5_SuperRegsSet },
    { "FP6",	FP6_AliasSet,	FP6_SubRegsSet,	FP6_SuperRegsSet },
    { "FS",	FS_AliasSet,	FS_SubRegsSet,	FS_SuperRegsSet },
    { "GS",	GS_AliasSet,	GS_SubRegsSet,	GS_SuperRegsSet },
    { "IP",	IP_AliasSet,	IP_SubRegsSet,	IP_SuperRegsSet },
    { "MM0",	MM0_AliasSet,	MM0_SubRegsSet,	MM0_SuperRegsSet },
    { "MM1",	MM1_AliasSet,	MM1_SubRegsSet,	MM1_SuperRegsSet },
    { "MM2",	MM2_AliasSet,	MM2_SubRegsSet,	MM2_SuperRegsSet },
    { "MM3",	MM3_AliasSet,	MM3_SubRegsSet,	MM3_SuperRegsSet },
    { "MM4",	MM4_AliasSet,	MM4_SubRegsSet,	MM4_SuperRegsSet },
    { "MM5",	MM5_AliasSet,	MM5_SubRegsSet,	MM5_SuperRegsSet },
    { "MM6",	MM6_AliasSet,	MM6_SubRegsSet,	MM6_SuperRegsSet },
    { "MM7",	MM7_AliasSet,	MM7_SubRegsSet,	MM7_SuperRegsSet },
    { "R10",	R10_AliasSet,	R10_SubRegsSet,	R10_SuperRegsSet },
    { "R10B",	R10B_AliasSet,	R10B_SubRegsSet,	R10B_SuperRegsSet },
    { "R10D",	R10D_AliasSet,	R10D_SubRegsSet,	R10D_SuperRegsSet },
    { "R10W",	R10W_AliasSet,	R10W_SubRegsSet,	R10W_SuperRegsSet },
    { "R11",	R11_AliasSet,	R11_SubRegsSet,	R11_SuperRegsSet },
    { "R11B",	R11B_AliasSet,	R11B_SubRegsSet,	R11B_SuperRegsSet },
    { "R11D",	R11D_AliasSet,	R11D_SubRegsSet,	R11D_SuperRegsSet },
    { "R11W",	R11W_AliasSet,	R11W_SubRegsSet,	R11W_SuperRegsSet },
    { "R12",	R12_AliasSet,	R12_SubRegsSet,	R12_SuperRegsSet },
    { "R12B",	R12B_AliasSet,	R12B_SubRegsSet,	R12B_SuperRegsSet },
    { "R12D",	R12D_AliasSet,	R12D_SubRegsSet,	R12D_SuperRegsSet },
    { "R12W",	R12W_AliasSet,	R12W_SubRegsSet,	R12W_SuperRegsSet },
    { "R13",	R13_AliasSet,	R13_SubRegsSet,	R13_SuperRegsSet },
    { "R13B",	R13B_AliasSet,	R13B_SubRegsSet,	R13B_SuperRegsSet },
    { "R13D",	R13D_AliasSet,	R13D_SubRegsSet,	R13D_SuperRegsSet },
    { "R13W",	R13W_AliasSet,	R13W_SubRegsSet,	R13W_SuperRegsSet },
    { "R14",	R14_AliasSet,	R14_SubRegsSet,	R14_SuperRegsSet },
    { "R14B",	R14B_AliasSet,	R14B_SubRegsSet,	R14B_SuperRegsSet },
    { "R14D",	R14D_AliasSet,	R14D_SubRegsSet,	R14D_SuperRegsSet },
    { "R14W",	R14W_AliasSet,	R14W_SubRegsSet,	R14W_SuperRegsSet },
    { "R15",	R15_AliasSet,	R15_SubRegsSet,	R15_SuperRegsSet },
    { "R15B",	R15B_AliasSet,	R15B_SubRegsSet,	R15B_SuperRegsSet },
    { "R15D",	R15D_AliasSet,	R15D_SubRegsSet,	R15D_SuperRegsSet },
    { "R15W",	R15W_AliasSet,	R15W_SubRegsSet,	R15W_SuperRegsSet },
    { "R8",	R8_AliasSet,	R8_SubRegsSet,	R8_SuperRegsSet },
    { "R8B",	R8B_AliasSet,	R8B_SubRegsSet,	R8B_SuperRegsSet },
    { "R8D",	R8D_AliasSet,	R8D_SubRegsSet,	R8D_SuperRegsSet },
    { "R8W",	R8W_AliasSet,	R8W_SubRegsSet,	R8W_SuperRegsSet },
    { "R9",	R9_AliasSet,	R9_SubRegsSet,	R9_SuperRegsSet },
    { "R9B",	R9B_AliasSet,	R9B_SubRegsSet,	R9B_SuperRegsSet },
    { "R9D",	R9D_AliasSet,	R9D_SubRegsSet,	R9D_SuperRegsSet },
    { "R9W",	R9W_AliasSet,	R9W_SubRegsSet,	R9W_SuperRegsSet },
    { "RAX",	RAX_AliasSet,	RAX_SubRegsSet,	RAX_SuperRegsSet },
    { "RBP",	RBP_AliasSet,	RBP_SubRegsSet,	RBP_SuperRegsSet },
    { "RBX",	RBX_AliasSet,	RBX_SubRegsSet,	RBX_SuperRegsSet },
    { "RCR0",	RCR0_AliasSet,	RCR0_SubRegsSet,	RCR0_SuperRegsSet },
    { "RCR1",	RCR1_AliasSet,	RCR1_SubRegsSet,	RCR1_SuperRegsSet },
    { "RCR2",	RCR2_AliasSet,	RCR2_SubRegsSet,	RCR2_SuperRegsSet },
    { "RCR3",	RCR3_AliasSet,	RCR3_SubRegsSet,	RCR3_SuperRegsSet },
    { "RCR4",	RCR4_AliasSet,	RCR4_SubRegsSet,	RCR4_SuperRegsSet },
    { "RCR5",	RCR5_AliasSet,	RCR5_SubRegsSet,	RCR5_SuperRegsSet },
    { "RCR6",	RCR6_AliasSet,	RCR6_SubRegsSet,	RCR6_SuperRegsSet },
    { "RCR7",	RCR7_AliasSet,	RCR7_SubRegsSet,	RCR7_SuperRegsSet },
    { "RCR8",	RCR8_AliasSet,	RCR8_SubRegsSet,	RCR8_SuperRegsSet },
    { "RCX",	RCX_AliasSet,	RCX_SubRegsSet,	RCX_SuperRegsSet },
    { "RDI",	RDI_AliasSet,	RDI_SubRegsSet,	RDI_SuperRegsSet },
    { "RDX",	RDX_AliasSet,	RDX_SubRegsSet,	RDX_SuperRegsSet },
    { "RIP",	RIP_AliasSet,	RIP_SubRegsSet,	RIP_SuperRegsSet },
    { "RSI",	RSI_AliasSet,	RSI_SubRegsSet,	RSI_SuperRegsSet },
    { "RSP",	RSP_AliasSet,	RSP_SubRegsSet,	RSP_SuperRegsSet },
    { "SI",	SI_AliasSet,	SI_SubRegsSet,	SI_SuperRegsSet },
    { "SIL",	SIL_AliasSet,	SIL_SubRegsSet,	SIL_SuperRegsSet },
    { "SP",	SP_AliasSet,	SP_SubRegsSet,	SP_SuperRegsSet },
    { "SPL",	SPL_AliasSet,	SPL_SubRegsSet,	SPL_SuperRegsSet },
    { "SS",	SS_AliasSet,	SS_SubRegsSet,	SS_SuperRegsSet },
    { "ST0",	ST0_AliasSet,	ST0_SubRegsSet,	ST0_SuperRegsSet },
    { "ST1",	ST1_AliasSet,	ST1_SubRegsSet,	ST1_SuperRegsSet },
    { "ST2",	ST2_AliasSet,	ST2_SubRegsSet,	ST2_SuperRegsSet },
    { "ST3",	ST3_AliasSet,	ST3_SubRegsSet,	ST3_SuperRegsSet },
    { "ST4",	ST4_AliasSet,	ST4_SubRegsSet,	ST4_SuperRegsSet },
    { "ST5",	ST5_AliasSet,	ST5_SubRegsSet,	ST5_SuperRegsSet },
    { "ST6",	ST6_AliasSet,	ST6_SubRegsSet,	ST6_SuperRegsSet },
    { "ST7",	ST7_AliasSet,	ST7_SubRegsSet,	ST7_SuperRegsSet },
    { "XMM0",	XMM0_AliasSet,	XMM0_SubRegsSet,	XMM0_SuperRegsSet },
    { "XMM1",	XMM1_AliasSet,	XMM1_SubRegsSet,	XMM1_SuperRegsSet },
    { "XMM10",	XMM10_AliasSet,	XMM10_SubRegsSet,	XMM10_SuperRegsSet },
    { "XMM11",	XMM11_AliasSet,	XMM11_SubRegsSet,	XMM11_SuperRegsSet },
    { "XMM12",	XMM12_AliasSet,	XMM12_SubRegsSet,	XMM12_SuperRegsSet },
    { "XMM13",	XMM13_AliasSet,	XMM13_SubRegsSet,	XMM13_SuperRegsSet },
    { "XMM14",	XMM14_AliasSet,	XMM14_SubRegsSet,	XMM14_SuperRegsSet },
    { "XMM15",	XMM15_AliasSet,	XMM15_SubRegsSet,	XMM15_SuperRegsSet },
    { "XMM2",	XMM2_AliasSet,	XMM2_SubRegsSet,	XMM2_SuperRegsSet },
    { "XMM3",	XMM3_AliasSet,	XMM3_SubRegsSet,	XMM3_SuperRegsSet },
    { "XMM4",	XMM4_AliasSet,	XMM4_SubRegsSet,	XMM4_SuperRegsSet },
    { "XMM5",	XMM5_AliasSet,	XMM5_SubRegsSet,	XMM5_SuperRegsSet },
    { "XMM6",	XMM6_AliasSet,	XMM6_SubRegsSet,	XMM6_SuperRegsSet },
    { "XMM7",	XMM7_AliasSet,	XMM7_SubRegsSet,	XMM7_SuperRegsSet },
    { "XMM8",	XMM8_AliasSet,	XMM8_SubRegsSet,	XMM8_SuperRegsSet },
    { "XMM9",	XMM9_AliasSet,	XMM9_SubRegsSet,	XMM9_SuperRegsSet },
    { "YMM0",	YMM0_AliasSet,	YMM0_SubRegsSet,	YMM0_SuperRegsSet },
    { "YMM1",	YMM1_AliasSet,	YMM1_SubRegsSet,	YMM1_SuperRegsSet },
    { "YMM10",	YMM10_AliasSet,	YMM10_SubRegsSet,	YMM10_SuperRegsSet },
    { "YMM11",	YMM11_AliasSet,	YMM11_SubRegsSet,	YMM11_SuperRegsSet },
    { "YMM12",	YMM12_AliasSet,	YMM12_SubRegsSet,	YMM12_SuperRegsSet },
    { "YMM13",	YMM13_AliasSet,	YMM13_SubRegsSet,	YMM13_SuperRegsSet },
    { "YMM14",	YMM14_AliasSet,	YMM14_SubRegsSet,	YMM14_SuperRegsSet },
    { "YMM15",	YMM15_AliasSet,	YMM15_SubRegsSet,	YMM15_SuperRegsSet },
    { "YMM2",	YMM2_AliasSet,	YMM2_SubRegsSet,	YMM2_SuperRegsSet },
    { "YMM3",	YMM3_AliasSet,	YMM3_SubRegsSet,	YMM3_SuperRegsSet },
    { "YMM4",	YMM4_AliasSet,	YMM4_SubRegsSet,	YMM4_SuperRegsSet },
    { "YMM5",	YMM5_AliasSet,	YMM5_SubRegsSet,	YMM5_SuperRegsSet },
    { "YMM6",	YMM6_AliasSet,	YMM6_SubRegsSet,	YMM6_SuperRegsSet },
    { "YMM7",	YMM7_AliasSet,	YMM7_SubRegsSet,	YMM7_SuperRegsSet },
    { "YMM8",	YMM8_AliasSet,	YMM8_SubRegsSet,	YMM8_SuperRegsSet },
    { "YMM9",	YMM9_AliasSet,	YMM9_SubRegsSet,	YMM9_SuperRegsSet },
  };
}

unsigned X86GenRegisterInfo::getSubReg(unsigned RegNo, unsigned Index) const {
  switch (RegNo) {
  default:
    return 0;
  case X86::AX:
    switch (Index) {
    default: return 0;
    case 1: return X86::AL;
    case 2: return X86::AH;
    };
    break;
  case X86::DX:
    switch (Index) {
    default: return 0;
    case 1: return X86::DL;
    case 2: return X86::DH;
    };
    break;
  case X86::CX:
    switch (Index) {
    default: return 0;
    case 1: return X86::CL;
    case 2: return X86::CH;
    };
    break;
  case X86::BX:
    switch (Index) {
    default: return 0;
    case 1: return X86::BL;
    case 2: return X86::BH;
    };
    break;
  case X86::SI:
    switch (Index) {
    default: return 0;
    case 1: return X86::SIL;
    };
    break;
  case X86::DI:
    switch (Index) {
    default: return 0;
    case 1: return X86::DIL;
    };
    break;
  case X86::BP:
    switch (Index) {
    default: return 0;
    case 1: return X86::BPL;
    };
    break;
  case X86::SP:
    switch (Index) {
    default: return 0;
    case 1: return X86::SPL;
    };
    break;
  case X86::R8W:
    switch (Index) {
    default: return 0;
    case 1: return X86::R8B;
    };
    break;
  case X86::R9W:
    switch (Index) {
    default: return 0;
    case 1: return X86::R9B;
    };
    break;
  case X86::R10W:
    switch (Index) {
    default: return 0;
    case 1: return X86::R10B;
    };
    break;
  case X86::R11W:
    switch (Index) {
    default: return 0;
    case 1: return X86::R11B;
    };
    break;
  case X86::R12W:
    switch (Index) {
    default: return 0;
    case 1: return X86::R12B;
    };
    break;
  case X86::R13W:
    switch (Index) {
    default: return 0;
    case 1: return X86::R13B;
    };
    break;
  case X86::R14W:
    switch (Index) {
    default: return 0;
    case 1: return X86::R14B;
    };
    break;
  case X86::R15W:
    switch (Index) {
    default: return 0;
    case 1: return X86::R15B;
    };
    break;
  case X86::EAX:
    switch (Index) {
    default: return 0;
    case 1: return X86::AL;
    case 2: return X86::AH;
    case 3: return X86::AX;
    };
    break;
  case X86::EDX:
    switch (Index) {
    default: return 0;
    case 1: return X86::DL;
    case 2: return X86::DH;
    case 3: return X86::DX;
    };
    break;
  case X86::ECX:
    switch (Index) {
    default: return 0;
    case 1: return X86::CL;
    case 2: return X86::CH;
    case 3: return X86::CX;
    };
    break;
  case X86::EBX:
    switch (Index) {
    default: return 0;
    case 1: return X86::BL;
    case 2: return X86::BH;
    case 3: return X86::BX;
    };
    break;
  case X86::ESI:
    switch (Index) {
    default: return 0;
    case 1: return X86::SIL;
    case 3: return X86::SI;
    };
    break;
  case X86::EDI:
    switch (Index) {
    default: return 0;
    case 1: return X86::DIL;
    case 3: return X86::DI;
    };
    break;
  case X86::EBP:
    switch (Index) {
    default: return 0;
    case 1: return X86::BPL;
    case 3: return X86::BP;
    };
    break;
  case X86::ESP:
    switch (Index) {
    default: return 0;
    case 1: return X86::SPL;
    case 3: return X86::SP;
    };
    break;
  case X86::R8D:
    switch (Index) {
    default: return 0;
    case 1: return X86::R8B;
    case 3: return X86::R8W;
    };
    break;
  case X86::R9D:
    switch (Index) {
    default: return 0;
    case 1: return X86::R9B;
    case 3: return X86::R9W;
    };
    break;
  case X86::R10D:
    switch (Index) {
    default: return 0;
    case 1: return X86::R10B;
    case 3: return X86::R10W;
    };
    break;
  case X86::R11D:
    switch (Index) {
    default: return 0;
    case 1: return X86::R11B;
    case 3: return X86::R11W;
    };
    break;
  case X86::R12D:
    switch (Index) {
    default: return 0;
    case 1: return X86::R12B;
    case 3: return X86::R12W;
    };
    break;
  case X86::R13D:
    switch (Index) {
    default: return 0;
    case 1: return X86::R13B;
    case 3: return X86::R13W;
    };
    break;
  case X86::R14D:
    switch (Index) {
    default: return 0;
    case 1: return X86::R14B;
    case 3: return X86::R14W;
    };
    break;
  case X86::R15D:
    switch (Index) {
    default: return 0;
    case 1: return X86::R15B;
    case 3: return X86::R15W;
    };
    break;
  case X86::RAX:
    switch (Index) {
    default: return 0;
    case 1: return X86::AL;
    case 2: return X86::AH;
    case 3: return X86::AX;
    case 4: return X86::EAX;
    };
    break;
  case X86::RDX:
    switch (Index) {
    default: return 0;
    case 1: return X86::DL;
    case 2: return X86::DH;
    case 3: return X86::DX;
    case 4: return X86::EDX;
    };
    break;
  case X86::RCX:
    switch (Index) {
    default: return 0;
    case 1: return X86::CL;
    case 2: return X86::CH;
    case 3: return X86::CX;
    case 4: return X86::ECX;
    };
    break;
  case X86::RBX:
    switch (Index) {
    default: return 0;
    case 1: return X86::BL;
    case 2: return X86::BH;
    case 3: return X86::BX;
    case 4: return X86::EBX;
    };
    break;
  case X86::RSI:
    switch (Index) {
    default: return 0;
    case 1: return X86::SIL;
    case 3: return X86::SI;
    case 4: return X86::ESI;
    };
    break;
  case X86::RDI:
    switch (Index) {
    default: return 0;
    case 1: return X86::DIL;
    case 3: return X86::DI;
    case 4: return X86::EDI;
    };
    break;
  case X86::RBP:
    switch (Index) {
    default: return 0;
    case 1: return X86::BPL;
    case 3: return X86::BP;
    case 4: return X86::EBP;
    };
    break;
  case X86::RSP:
    switch (Index) {
    default: return 0;
    case 1: return X86::SPL;
    case 3: return X86::SP;
    case 4: return X86::ESP;
    };
    break;
  case X86::R8:
    switch (Index) {
    default: return 0;
    case 1: return X86::R8B;
    case 3: return X86::R8W;
    case 4: return X86::R8D;
    };
    break;
  case X86::R9:
    switch (Index) {
    default: return 0;
    case 1: return X86::R9B;
    case 3: return X86::R9W;
    case 4: return X86::R9D;
    };
    break;
  case X86::R10:
    switch (Index) {
    default: return 0;
    case 1: return X86::R10B;
    case 3: return X86::R10W;
    case 4: return X86::R10D;
    };
    break;
  case X86::R11:
    switch (Index) {
    default: return 0;
    case 1: return X86::R11B;
    case 3: return X86::R11W;
    case 4: return X86::R11D;
    };
    break;
  case X86::R12:
    switch (Index) {
    default: return 0;
    case 1: return X86::R12B;
    case 3: return X86::R12W;
    case 4: return X86::R12D;
    };
    break;
  case X86::R13:
    switch (Index) {
    default: return 0;
    case 1: return X86::R13B;
    case 3: return X86::R13W;
    case 4: return X86::R13D;
    };
    break;
  case X86::R14:
    switch (Index) {
    default: return 0;
    case 1: return X86::R14B;
    case 3: return X86::R14W;
    case 4: return X86::R14D;
    };
    break;
  case X86::R15:
    switch (Index) {
    default: return 0;
    case 1: return X86::R15B;
    case 3: return X86::R15W;
    case 4: return X86::R15D;
    };
    break;
  case X86::XMM0:
    switch (Index) {
    default: return 0;
    case 1: return X86::XMM0;
    case 2: return X86::XMM0;
    };
    break;
  case X86::XMM1:
    switch (Index) {
    default: return 0;
    case 1: return X86::XMM1;
    case 2: return X86::XMM1;
    };
    break;
  case X86::XMM2:
    switch (Index) {
    default: return 0;
    case 1: return X86::XMM2;
    case 2: return X86::XMM2;
    };
    break;
  case X86::XMM3:
    switch (Index) {
    default: return 0;
    case 1: return X86::XMM3;
    case 2: return X86::XMM3;
    };
    break;
  case X86::XMM4:
    switch (Index) {
    default: return 0;
    case 1: return X86::XMM4;
    case 2: return X86::XMM4;
    };
    break;
  case X86::XMM5:
    switch (Index) {
    default: return 0;
    case 1: return X86::XMM5;
    case 2: return X86::XMM5;
    };
    break;
  case X86::XMM6:
    switch (Index) {
    default: return 0;
    case 1: return X86::XMM6;
    case 2: return X86::XMM6;
    };
    break;
  case X86::XMM7:
    switch (Index) {
    default: return 0;
    case 1: return X86::XMM7;
    case 2: return X86::XMM7;
    };
    break;
  case X86::XMM8:
    switch (Index) {
    default: return 0;
    case 1: return X86::XMM8;
    case 2: return X86::XMM8;
    };
    break;
  case X86::XMM9:
    switch (Index) {
    default: return 0;
    case 1: return X86::XMM9;
    case 2: return X86::XMM9;
    };
    break;
  case X86::XMM10:
    switch (Index) {
    default: return 0;
    case 1: return X86::XMM10;
    case 2: return X86::XMM10;
    };
    break;
  case X86::XMM11:
    switch (Index) {
    default: return 0;
    case 1: return X86::XMM11;
    case 2: return X86::XMM11;
    };
    break;
  case X86::XMM12:
    switch (Index) {
    default: return 0;
    case 1: return X86::XMM12;
    case 2: return X86::XMM12;
    };
    break;
  case X86::XMM13:
    switch (Index) {
    default: return 0;
    case 1: return X86::XMM13;
    case 2: return X86::XMM13;
    };
    break;
  case X86::XMM14:
    switch (Index) {
    default: return 0;
    case 1: return X86::XMM14;
    case 2: return X86::XMM14;
    };
    break;
  case X86::XMM15:
    switch (Index) {
    default: return 0;
    case 1: return X86::XMM15;
    case 2: return X86::XMM15;
    };
    break;
  case X86::YMM0:
    switch (Index) {
    default: return 0;
    case 1: return X86::XMM0;
    case 2: return X86::XMM0;
    case 3: return X86::XMM0;
    };
    break;
  case X86::YMM1:
    switch (Index) {
    default: return 0;
    case 1: return X86::XMM1;
    case 2: return X86::XMM1;
    case 3: return X86::XMM1;
    };
    break;
  case X86::YMM2:
    switch (Index) {
    default: return 0;
    case 1: return X86::XMM2;
    case 2: return X86::XMM2;
    case 3: return X86::XMM2;
    };
    break;
  case X86::YMM3:
    switch (Index) {
    default: return 0;
    case 1: return X86::XMM3;
    case 2: return X86::XMM3;
    case 3: return X86::XMM3;
    };
    break;
  case X86::YMM4:
    switch (Index) {
    default: return 0;
    case 1: return X86::XMM4;
    case 2: return X86::XMM4;
    case 3: return X86::XMM4;
    };
    break;
  case X86::YMM5:
    switch (Index) {
    default: return 0;
    case 1: return X86::XMM5;
    case 2: return X86::XMM5;
    case 3: return X86::XMM5;
    };
    break;
  case X86::YMM6:
    switch (Index) {
    default: return 0;
    case 1: return X86::XMM6;
    case 2: return X86::XMM6;
    case 3: return X86::XMM6;
    };
    break;
  case X86::YMM7:
    switch (Index) {
    default: return 0;
    case 1: return X86::XMM7;
    case 2: return X86::XMM7;
    case 3: return X86::XMM7;
    };
    break;
  case X86::YMM8:
    switch (Index) {
    default: return 0;
    case 1: return X86::XMM8;
    case 2: return X86::XMM8;
    case 3: return X86::XMM8;
    };
    break;
  case X86::YMM9:
    switch (Index) {
    default: return 0;
    case 1: return X86::XMM9;
    case 2: return X86::XMM9;
    case 3: return X86::XMM9;
    };
    break;
  case X86::YMM10:
    switch (Index) {
    default: return 0;
    case 1: return X86::XMM10;
    case 2: return X86::XMM10;
    case 3: return X86::XMM10;
    };
    break;
  case X86::YMM11:
    switch (Index) {
    default: return 0;
    case 1: return X86::XMM11;
    case 2: return X86::XMM11;
    case 3: return X86::XMM11;
    };
    break;
  case X86::YMM12:
    switch (Index) {
    default: return 0;
    case 1: return X86::XMM12;
    case 2: return X86::XMM12;
    case 3: return X86::XMM12;
    };
    break;
  case X86::YMM13:
    switch (Index) {
    default: return 0;
    case 1: return X86::XMM13;
    case 2: return X86::XMM13;
    case 3: return X86::XMM13;
    };
    break;
  case X86::YMM14:
    switch (Index) {
    default: return 0;
    case 1: return X86::XMM14;
    case 2: return X86::XMM14;
    case 3: return X86::XMM14;
    };
    break;
  case X86::YMM15:
    switch (Index) {
    default: return 0;
    case 1: return X86::XMM15;
    case 2: return X86::XMM15;
    case 3: return X86::XMM15;
    };
    break;
  };
  return 0;
}

unsigned X86GenRegisterInfo::getSubRegIndex(unsigned RegNo, unsigned SubRegNo) const {
  switch (RegNo) {
  default:
    return 0;
  case X86::AX:
    if (SubRegNo == X86::AL)  return 1;
    if (SubRegNo == X86::AH)  return 2;
    return 0;
  case X86::DX:
    if (SubRegNo == X86::DL)  return 1;
    if (SubRegNo == X86::DH)  return 2;
    return 0;
  case X86::CX:
    if (SubRegNo == X86::CL)  return 1;
    if (SubRegNo == X86::CH)  return 2;
    return 0;
  case X86::BX:
    if (SubRegNo == X86::BL)  return 1;
    if (SubRegNo == X86::BH)  return 2;
    return 0;
  case X86::SI:
    if (SubRegNo == X86::SIL)  return 1;
    return 0;
  case X86::DI:
    if (SubRegNo == X86::DIL)  return 1;
    return 0;
  case X86::BP:
    if (SubRegNo == X86::BPL)  return 1;
    return 0;
  case X86::SP:
    if (SubRegNo == X86::SPL)  return 1;
    return 0;
  case X86::R8W:
    if (SubRegNo == X86::R8B)  return 1;
    return 0;
  case X86::R9W:
    if (SubRegNo == X86::R9B)  return 1;
    return 0;
  case X86::R10W:
    if (SubRegNo == X86::R10B)  return 1;
    return 0;
  case X86::R11W:
    if (SubRegNo == X86::R11B)  return 1;
    return 0;
  case X86::R12W:
    if (SubRegNo == X86::R12B)  return 1;
    return 0;
  case X86::R13W:
    if (SubRegNo == X86::R13B)  return 1;
    return 0;
  case X86::R14W:
    if (SubRegNo == X86::R14B)  return 1;
    return 0;
  case X86::R15W:
    if (SubRegNo == X86::R15B)  return 1;
    return 0;
  case X86::EAX:
    if (SubRegNo == X86::AL)  return 1;
    if (SubRegNo == X86::AH)  return 2;
    if (SubRegNo == X86::AX)  return 3;
    return 0;
  case X86::EDX:
    if (SubRegNo == X86::DL)  return 1;
    if (SubRegNo == X86::DH)  return 2;
    if (SubRegNo == X86::DX)  return 3;
    return 0;
  case X86::ECX:
    if (SubRegNo == X86::CL)  return 1;
    if (SubRegNo == X86::CH)  return 2;
    if (SubRegNo == X86::CX)  return 3;
    return 0;
  case X86::EBX:
    if (SubRegNo == X86::BL)  return 1;
    if (SubRegNo == X86::BH)  return 2;
    if (SubRegNo == X86::BX)  return 3;
    return 0;
  case X86::ESI:
    if (SubRegNo == X86::SIL)  return 1;
    if (SubRegNo == X86::SI)  return 3;
    return 0;
  case X86::EDI:
    if (SubRegNo == X86::DIL)  return 1;
    if (SubRegNo == X86::DI)  return 3;
    return 0;
  case X86::EBP:
    if (SubRegNo == X86::BPL)  return 1;
    if (SubRegNo == X86::BP)  return 3;
    return 0;
  case X86::ESP:
    if (SubRegNo == X86::SPL)  return 1;
    if (SubRegNo == X86::SP)  return 3;
    return 0;
  case X86::R8D:
    if (SubRegNo == X86::R8B)  return 1;
    if (SubRegNo == X86::R8W)  return 3;
    return 0;
  case X86::R9D:
    if (SubRegNo == X86::R9B)  return 1;
    if (SubRegNo == X86::R9W)  return 3;
    return 0;
  case X86::R10D:
    if (SubRegNo == X86::R10B)  return 1;
    if (SubRegNo == X86::R10W)  return 3;
    return 0;
  case X86::R11D:
    if (SubRegNo == X86::R11B)  return 1;
    if (SubRegNo == X86::R11W)  return 3;
    return 0;
  case X86::R12D:
    if (SubRegNo == X86::R12B)  return 1;
    if (SubRegNo == X86::R12W)  return 3;
    return 0;
  case X86::R13D:
    if (SubRegNo == X86::R13B)  return 1;
    if (SubRegNo == X86::R13W)  return 3;
    return 0;
  case X86::R14D:
    if (SubRegNo == X86::R14B)  return 1;
    if (SubRegNo == X86::R14W)  return 3;
    return 0;
  case X86::R15D:
    if (SubRegNo == X86::R15B)  return 1;
    if (SubRegNo == X86::R15W)  return 3;
    return 0;
  case X86::RAX:
    if (SubRegNo == X86::AL)  return 1;
    if (SubRegNo == X86::AH)  return 2;
    if (SubRegNo == X86::AX)  return 3;
    if (SubRegNo == X86::EAX)  return 4;
    return 0;
  case X86::RDX:
    if (SubRegNo == X86::DL)  return 1;
    if (SubRegNo == X86::DH)  return 2;
    if (SubRegNo == X86::DX)  return 3;
    if (SubRegNo == X86::EDX)  return 4;
    return 0;
  case X86::RCX:
    if (SubRegNo == X86::CL)  return 1;
    if (SubRegNo == X86::CH)  return 2;
    if (SubRegNo == X86::CX)  return 3;
    if (SubRegNo == X86::ECX)  return 4;
    return 0;
  case X86::RBX:
    if (SubRegNo == X86::BL)  return 1;
    if (SubRegNo == X86::BH)  return 2;
    if (SubRegNo == X86::BX)  return 3;
    if (SubRegNo == X86::EBX)  return 4;
    return 0;
  case X86::RSI:
    if (SubRegNo == X86::SIL)  return 1;
    if (SubRegNo == X86::SI)  return 3;
    if (SubRegNo == X86::ESI)  return 4;
    return 0;
  case X86::RDI:
    if (SubRegNo == X86::DIL)  return 1;
    if (SubRegNo == X86::DI)  return 3;
    if (SubRegNo == X86::EDI)  return 4;
    return 0;
  case X86::RBP:
    if (SubRegNo == X86::BPL)  return 1;
    if (SubRegNo == X86::BP)  return 3;
    if (SubRegNo == X86::EBP)  return 4;
    return 0;
  case X86::RSP:
    if (SubRegNo == X86::SPL)  return 1;
    if (SubRegNo == X86::SP)  return 3;
    if (SubRegNo == X86::ESP)  return 4;
    return 0;
  case X86::R8:
    if (SubRegNo == X86::R8B)  return 1;
    if (SubRegNo == X86::R8W)  return 3;
    if (SubRegNo == X86::R8D)  return 4;
    return 0;
  case X86::R9:
    if (SubRegNo == X86::R9B)  return 1;
    if (SubRegNo == X86::R9W)  return 3;
    if (SubRegNo == X86::R9D)  return 4;
    return 0;
  case X86::R10:
    if (SubRegNo == X86::R10B)  return 1;
    if (SubRegNo == X86::R10W)  return 3;
    if (SubRegNo == X86::R10D)  return 4;
    return 0;
  case X86::R11:
    if (SubRegNo == X86::R11B)  return 1;
    if (SubRegNo == X86::R11W)  return 3;
    if (SubRegNo == X86::R11D)  return 4;
    return 0;
  case X86::R12:
    if (SubRegNo == X86::R12B)  return 1;
    if (SubRegNo == X86::R12W)  return 3;
    if (SubRegNo == X86::R12D)  return 4;
    return 0;
  case X86::R13:
    if (SubRegNo == X86::R13B)  return 1;
    if (SubRegNo == X86::R13W)  return 3;
    if (SubRegNo == X86::R13D)  return 4;
    return 0;
  case X86::R14:
    if (SubRegNo == X86::R14B)  return 1;
    if (SubRegNo == X86::R14W)  return 3;
    if (SubRegNo == X86::R14D)  return 4;
    return 0;
  case X86::R15:
    if (SubRegNo == X86::R15B)  return 1;
    if (SubRegNo == X86::R15W)  return 3;
    if (SubRegNo == X86::R15D)  return 4;
    return 0;
  case X86::XMM0:
    if (SubRegNo == X86::XMM0)  return 1;
    if (SubRegNo == X86::XMM0)  return 2;
    return 0;
  case X86::XMM1:
    if (SubRegNo == X86::XMM1)  return 1;
    if (SubRegNo == X86::XMM1)  return 2;
    return 0;
  case X86::XMM2:
    if (SubRegNo == X86::XMM2)  return 1;
    if (SubRegNo == X86::XMM2)  return 2;
    return 0;
  case X86::XMM3:
    if (SubRegNo == X86::XMM3)  return 1;
    if (SubRegNo == X86::XMM3)  return 2;
    return 0;
  case X86::XMM4:
    if (SubRegNo == X86::XMM4)  return 1;
    if (SubRegNo == X86::XMM4)  return 2;
    return 0;
  case X86::XMM5:
    if (SubRegNo == X86::XMM5)  return 1;
    if (SubRegNo == X86::XMM5)  return 2;
    return 0;
  case X86::XMM6:
    if (SubRegNo == X86::XMM6)  return 1;
    if (SubRegNo == X86::XMM6)  return 2;
    return 0;
  case X86::XMM7:
    if (SubRegNo == X86::XMM7)  return 1;
    if (SubRegNo == X86::XMM7)  return 2;
    return 0;
  case X86::XMM8:
    if (SubRegNo == X86::XMM8)  return 1;
    if (SubRegNo == X86::XMM8)  return 2;
    return 0;
  case X86::XMM9:
    if (SubRegNo == X86::XMM9)  return 1;
    if (SubRegNo == X86::XMM9)  return 2;
    return 0;
  case X86::XMM10:
    if (SubRegNo == X86::XMM10)  return 1;
    if (SubRegNo == X86::XMM10)  return 2;
    return 0;
  case X86::XMM11:
    if (SubRegNo == X86::XMM11)  return 1;
    if (SubRegNo == X86::XMM11)  return 2;
    return 0;
  case X86::XMM12:
    if (SubRegNo == X86::XMM12)  return 1;
    if (SubRegNo == X86::XMM12)  return 2;
    return 0;
  case X86::XMM13:
    if (SubRegNo == X86::XMM13)  return 1;
    if (SubRegNo == X86::XMM13)  return 2;
    return 0;
  case X86::XMM14:
    if (SubRegNo == X86::XMM14)  return 1;
    if (SubRegNo == X86::XMM14)  return 2;
    return 0;
  case X86::XMM15:
    if (SubRegNo == X86::XMM15)  return 1;
    if (SubRegNo == X86::XMM15)  return 2;
    return 0;
  case X86::YMM0:
    if (SubRegNo == X86::XMM0)  return 1;
    if (SubRegNo == X86::XMM0)  return 2;
    if (SubRegNo == X86::XMM0)  return 3;
    return 0;
  case X86::YMM1:
    if (SubRegNo == X86::XMM1)  return 1;
    if (SubRegNo == X86::XMM1)  return 2;
    if (SubRegNo == X86::XMM1)  return 3;
    return 0;
  case X86::YMM2:
    if (SubRegNo == X86::XMM2)  return 1;
    if (SubRegNo == X86::XMM2)  return 2;
    if (SubRegNo == X86::XMM2)  return 3;
    return 0;
  case X86::YMM3:
    if (SubRegNo == X86::XMM3)  return 1;
    if (SubRegNo == X86::XMM3)  return 2;
    if (SubRegNo == X86::XMM3)  return 3;
    return 0;
  case X86::YMM4:
    if (SubRegNo == X86::XMM4)  return 1;
    if (SubRegNo == X86::XMM4)  return 2;
    if (SubRegNo == X86::XMM4)  return 3;
    return 0;
  case X86::YMM5:
    if (SubRegNo == X86::XMM5)  return 1;
    if (SubRegNo == X86::XMM5)  return 2;
    if (SubRegNo == X86::XMM5)  return 3;
    return 0;
  case X86::YMM6:
    if (SubRegNo == X86::XMM6)  return 1;
    if (SubRegNo == X86::XMM6)  return 2;
    if (SubRegNo == X86::XMM6)  return 3;
    return 0;
  case X86::YMM7:
    if (SubRegNo == X86::XMM7)  return 1;
    if (SubRegNo == X86::XMM7)  return 2;
    if (SubRegNo == X86::XMM7)  return 3;
    return 0;
  case X86::YMM8:
    if (SubRegNo == X86::XMM8)  return 1;
    if (SubRegNo == X86::XMM8)  return 2;
    if (SubRegNo == X86::XMM8)  return 3;
    return 0;
  case X86::YMM9:
    if (SubRegNo == X86::XMM9)  return 1;
    if (SubRegNo == X86::XMM9)  return 2;
    if (SubRegNo == X86::XMM9)  return 3;
    return 0;
  case X86::YMM10:
    if (SubRegNo == X86::XMM10)  return 1;
    if (SubRegNo == X86::XMM10)  return 2;
    if (SubRegNo == X86::XMM10)  return 3;
    return 0;
  case X86::YMM11:
    if (SubRegNo == X86::XMM11)  return 1;
    if (SubRegNo == X86::XMM11)  return 2;
    if (SubRegNo == X86::XMM11)  return 3;
    return 0;
  case X86::YMM12:
    if (SubRegNo == X86::XMM12)  return 1;
    if (SubRegNo == X86::XMM12)  return 2;
    if (SubRegNo == X86::XMM12)  return 3;
    return 0;
  case X86::YMM13:
    if (SubRegNo == X86::XMM13)  return 1;
    if (SubRegNo == X86::XMM13)  return 2;
    if (SubRegNo == X86::XMM13)  return 3;
    return 0;
  case X86::YMM14:
    if (SubRegNo == X86::XMM14)  return 1;
    if (SubRegNo == X86::XMM14)  return 2;
    if (SubRegNo == X86::XMM14)  return 3;
    return 0;
  case X86::YMM15:
    if (SubRegNo == X86::XMM15)  return 1;
    if (SubRegNo == X86::XMM15)  return 2;
    if (SubRegNo == X86::XMM15)  return 3;
    return 0;
  };
  return 0;
}

X86GenRegisterInfo::X86GenRegisterInfo(int CallFrameSetupOpcode, int CallFrameDestroyOpcode)
  : TargetRegisterInfo(RegisterDescriptors, 159, RegisterClasses, RegisterClasses+31,
                  CallFrameSetupOpcode, CallFrameDestroyOpcode,
                 SubregHashTable, SubregHashTableSize,
                 SuperregHashTable, SuperregHashTableSize,
                 AliasesHashTable, AliasesHashTableSize) {
}

int X86GenRegisterInfo::getDwarfRegNumFull(unsigned RegNum, unsigned Flavour) const {
  switch (Flavour) {
  default:
    assert(0 && "Unknown DWARF flavour");
    return -1;
  case 0:
    switch (RegNum) {
    default:
      assert(0 && "Invalid RegNum");
      return -1;
    case X86::AH:
      return 0;
    case X86::AL:
      return 0;
    case X86::AX:
      return 0;
    case X86::BH:
      return 3;
    case X86::BL:
      return 3;
    case X86::BP:
      return 6;
    case X86::BPL:
      return 6;
    case X86::BX:
      return 3;
    case X86::CH:
      return 2;
    case X86::CL:
      return 2;
    case X86::CS:
      return -1;
    case X86::CX:
      return 2;
    case X86::DH:
      return 1;
    case X86::DI:
      return 5;
    case X86::DIL:
      return 5;
    case X86::DL:
      return 1;
    case X86::DR0:
      return -1;
    case X86::DR1:
      return -1;
    case X86::DR2:
      return -1;
    case X86::DR3:
      return -1;
    case X86::DR4:
      return -1;
    case X86::DR5:
      return -1;
    case X86::DR6:
      return -1;
    case X86::DR7:
      return -1;
    case X86::DS:
      return -1;
    case X86::DX:
      return 1;
    case X86::EAX:
      return 0;
    case X86::EBP:
      return 6;
    case X86::EBX:
      return 3;
    case X86::ECR0:
      return -1;
    case X86::ECR1:
      return -1;
    case X86::ECR2:
      return -1;
    case X86::ECR3:
      return -1;
    case X86::ECR4:
      return -1;
    case X86::ECR5:
      return -1;
    case X86::ECR6:
      return -1;
    case X86::ECR7:
      return -1;
    case X86::ECX:
      return 2;
    case X86::EDI:
      return 5;
    case X86::EDX:
      return 1;
    case X86::EFLAGS:
      return -1;
    case X86::EIP:
      return 16;
    case X86::ES:
      return -1;
    case X86::ESI:
      return 4;
    case X86::ESP:
      return 7;
    case X86::FP0:
      return -1;
    case X86::FP1:
      return -1;
    case X86::FP2:
      return -1;
    case X86::FP3:
      return -1;
    case X86::FP4:
      return -1;
    case X86::FP5:
      return -1;
    case X86::FP6:
      return -1;
    case X86::FS:
      return -1;
    case X86::GS:
      return -1;
    case X86::IP:
      return 16;
    case X86::MM0:
      return 41;
    case X86::MM1:
      return 42;
    case X86::MM2:
      return 43;
    case X86::MM3:
      return 44;
    case X86::MM4:
      return 45;
    case X86::MM5:
      return 46;
    case X86::MM6:
      return 47;
    case X86::MM7:
      return 48;
    case X86::R10:
      return 10;
    case X86::R10B:
      return 10;
    case X86::R10D:
      return 10;
    case X86::R10W:
      return 10;
    case X86::R11:
      return 11;
    case X86::R11B:
      return 11;
    case X86::R11D:
      return 11;
    case X86::R11W:
      return 11;
    case X86::R12:
      return 12;
    case X86::R12B:
      return 12;
    case X86::R12D:
      return 12;
    case X86::R12W:
      return 12;
    case X86::R13:
      return 13;
    case X86::R13B:
      return 13;
    case X86::R13D:
      return 13;
    case X86::R13W:
      return 13;
    case X86::R14:
      return 14;
    case X86::R14B:
      return 14;
    case X86::R14D:
      return 14;
    case X86::R14W:
      return 14;
    case X86::R15:
      return 15;
    case X86::R15B:
      return 15;
    case X86::R15D:
      return 15;
    case X86::R15W:
      return 15;
    case X86::R8:
      return 8;
    case X86::R8B:
      return 8;
    case X86::R8D:
      return 8;
    case X86::R8W:
      return 8;
    case X86::R9:
      return 9;
    case X86::R9B:
      return 9;
    case X86::R9D:
      return 9;
    case X86::R9W:
      return 9;
    case X86::RAX:
      return 0;
    case X86::RBP:
      return 6;
    case X86::RBX:
      return 3;
    case X86::RCR0:
      return -1;
    case X86::RCR1:
      return -1;
    case X86::RCR2:
      return -1;
    case X86::RCR3:
      return -1;
    case X86::RCR4:
      return -1;
    case X86::RCR5:
      return -1;
    case X86::RCR6:
      return -1;
    case X86::RCR7:
      return -1;
    case X86::RCR8:
      return -1;
    case X86::RCX:
      return 2;
    case X86::RDI:
      return 5;
    case X86::RDX:
      return 1;
    case X86::RIP:
      return 16;
    case X86::RSI:
      return 4;
    case X86::RSP:
      return 7;
    case X86::SI:
      return 4;
    case X86::SIL:
      return 4;
    case X86::SP:
      return 7;
    case X86::SPL:
      return 7;
    case X86::SS:
      return -1;
    case X86::ST0:
      return 33;
    case X86::ST1:
      return 34;
    case X86::ST2:
      return 35;
    case X86::ST3:
      return 36;
    case X86::ST4:
      return 37;
    case X86::ST5:
      return 38;
    case X86::ST6:
      return 39;
    case X86::ST7:
      return 40;
    case X86::XMM0:
      return 17;
    case X86::XMM1:
      return 18;
    case X86::XMM10:
      return 27;
    case X86::XMM11:
      return 28;
    case X86::XMM12:
      return 29;
    case X86::XMM13:
      return 30;
    case X86::XMM14:
      return 31;
    case X86::XMM15:
      return 32;
    case X86::XMM2:
      return 19;
    case X86::XMM3:
      return 20;
    case X86::XMM4:
      return 21;
    case X86::XMM5:
      return 22;
    case X86::XMM6:
      return 23;
    case X86::XMM7:
      return 24;
    case X86::XMM8:
      return 25;
    case X86::XMM9:
      return 26;
    case X86::YMM0:
      return 17;
    case X86::YMM1:
      return 18;
    case X86::YMM10:
      return 27;
    case X86::YMM11:
      return 28;
    case X86::YMM12:
      return 29;
    case X86::YMM13:
      return 30;
    case X86::YMM14:
      return 31;
    case X86::YMM15:
      return 32;
    case X86::YMM2:
      return 19;
    case X86::YMM3:
      return 20;
    case X86::YMM4:
      return 21;
    case X86::YMM5:
      return 22;
    case X86::YMM6:
      return 23;
    case X86::YMM7:
      return 24;
    case X86::YMM8:
      return 25;
    case X86::YMM9:
      return 26;
    };
  case 1:
    switch (RegNum) {
    default:
      assert(0 && "Invalid RegNum");
      return -1;
    case X86::AH:
      return 0;
    case X86::AL:
      return 0;
    case X86::AX:
      return 0;
    case X86::BH:
      return 3;
    case X86::BL:
      return 3;
    case X86::BP:
      return 4;
    case X86::BPL:
      return 4;
    case X86::BX:
      return 3;
    case X86::CH:
      return 1;
    case X86::CL:
      return 1;
    case X86::CS:
      return -1;
    case X86::CX:
      return 1;
    case X86::DH:
      return 2;
    case X86::DI:
      return 7;
    case X86::DIL:
      return 7;
    case X86::DL:
      return 2;
    case X86::DR0:
      return -1;
    case X86::DR1:
      return -1;
    case X86::DR2:
      return -1;
    case X86::DR3:
      return -1;
    case X86::DR4:
      return -1;
    case X86::DR5:
      return -1;
    case X86::DR6:
      return -1;
    case X86::DR7:
      return -1;
    case X86::DS:
      return -1;
    case X86::DX:
      return 2;
    case X86::EAX:
      return 0;
    case X86::EBP:
      return 4;
    case X86::EBX:
      return 3;
    case X86::ECR0:
      return -1;
    case X86::ECR1:
      return -1;
    case X86::ECR2:
      return -1;
    case X86::ECR3:
      return -1;
    case X86::ECR4:
      return -1;
    case X86::ECR5:
      return -1;
    case X86::ECR6:
      return -1;
    case X86::ECR7:
      return -1;
    case X86::ECX:
      return 1;
    case X86::EDI:
      return 7;
    case X86::EDX:
      return 2;
    case X86::EFLAGS:
      return -1;
    case X86::EIP:
      return 8;
    case X86::ES:
      return -1;
    case X86::ESI:
      return 6;
    case X86::ESP:
      return 5;
    case X86::FP0:
      return -1;
    case X86::FP1:
      return -1;
    case X86::FP2:
      return -1;
    case X86::FP3:
      return -1;
    case X86::FP4:
      return -1;
    case X86::FP5:
      return -1;
    case X86::FP6:
      return -1;
    case X86::FS:
      return -1;
    case X86::GS:
      return -1;
    case X86::IP:
      return -1;
    case X86::MM0:
      return 29;
    case X86::MM1:
      return 30;
    case X86::MM2:
      return 31;
    case X86::MM3:
      return 32;
    case X86::MM4:
      return 33;
    case X86::MM5:
      return 34;
    case X86::MM6:
      return 35;
    case X86::MM7:
      return 36;
    case X86::R10:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::R10B:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::R10D:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::R10W:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::R11:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::R11B:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::R11D:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::R11W:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::R12:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::R12B:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::R12D:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::R12W:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::R13:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::R13B:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::R13D:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::R13W:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::R14:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::R14B:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::R14D:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::R14W:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::R15:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::R15B:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::R15D:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::R15W:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::R8:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::R8B:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::R8D:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::R8W:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::R9:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::R9B:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::R9D:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::R9W:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::RAX:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::RBP:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::RBX:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::RCR0:
      return -1;
    case X86::RCR1:
      return -1;
    case X86::RCR2:
      return -1;
    case X86::RCR3:
      return -1;
    case X86::RCR4:
      return -1;
    case X86::RCR5:
      return -1;
    case X86::RCR6:
      return -1;
    case X86::RCR7:
      return -1;
    case X86::RCR8:
      return -1;
    case X86::RCX:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::RDI:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::RDX:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::RIP:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::RSI:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::RSP:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::SI:
      return 6;
    case X86::SIL:
      return 6;
    case X86::SP:
      return 5;
    case X86::SPL:
      return 5;
    case X86::SS:
      return -1;
    case X86::ST0:
      return 12;
    case X86::ST1:
      return 13;
    case X86::ST2:
      return 14;
    case X86::ST3:
      return 15;
    case X86::ST4:
      return 16;
    case X86::ST5:
      return 17;
    case X86::ST6:
      return 18;
    case X86::ST7:
      return 19;
    case X86::XMM0:
      return 21;
    case X86::XMM1:
      return 22;
    case X86::XMM10:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::XMM11:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::XMM12:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::XMM13:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::XMM14:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::XMM15:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::XMM2:
      return 23;
    case X86::XMM3:
      return 24;
    case X86::XMM4:
      return 25;
    case X86::XMM5:
      return 26;
    case X86::XMM6:
      return 27;
    case X86::XMM7:
      return 28;
    case X86::XMM8:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::XMM9:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::YMM0:
      return 21;
    case X86::YMM1:
      return 22;
    case X86::YMM10:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::YMM11:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::YMM12:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::YMM13:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::YMM14:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::YMM15:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::YMM2:
      return 23;
    case X86::YMM3:
      return 24;
    case X86::YMM4:
      return 25;
    case X86::YMM5:
      return 26;
    case X86::YMM6:
      return 27;
    case X86::YMM7:
      return 28;
    case X86::YMM8:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::YMM9:
      assert(0 && "Invalid register for this mode");
      return -1;
    };
  case 2:
    switch (RegNum) {
    default:
      assert(0 && "Invalid RegNum");
      return -1;
    case X86::AH:
      return 0;
    case X86::AL:
      return 0;
    case X86::AX:
      return 0;
    case X86::BH:
      return 3;
    case X86::BL:
      return 3;
    case X86::BP:
      return 5;
    case X86::BPL:
      return 5;
    case X86::BX:
      return 3;
    case X86::CH:
      return 1;
    case X86::CL:
      return 1;
    case X86::CS:
      return -1;
    case X86::CX:
      return 1;
    case X86::DH:
      return 2;
    case X86::DI:
      return 7;
    case X86::DIL:
      return 7;
    case X86::DL:
      return 2;
    case X86::DR0:
      return -1;
    case X86::DR1:
      return -1;
    case X86::DR2:
      return -1;
    case X86::DR3:
      return -1;
    case X86::DR4:
      return -1;
    case X86::DR5:
      return -1;
    case X86::DR6:
      return -1;
    case X86::DR7:
      return -1;
    case X86::DS:
      return -1;
    case X86::DX:
      return 2;
    case X86::EAX:
      return 0;
    case X86::EBP:
      return 5;
    case X86::EBX:
      return 3;
    case X86::ECR0:
      return -1;
    case X86::ECR1:
      return -1;
    case X86::ECR2:
      return -1;
    case X86::ECR3:
      return -1;
    case X86::ECR4:
      return -1;
    case X86::ECR5:
      return -1;
    case X86::ECR6:
      return -1;
    case X86::ECR7:
      return -1;
    case X86::ECX:
      return 1;
    case X86::EDI:
      return 7;
    case X86::EDX:
      return 2;
    case X86::EFLAGS:
      return -1;
    case X86::EIP:
      return 8;
    case X86::ES:
      return -1;
    case X86::ESI:
      return 6;
    case X86::ESP:
      return 4;
    case X86::FP0:
      return -1;
    case X86::FP1:
      return -1;
    case X86::FP2:
      return -1;
    case X86::FP3:
      return -1;
    case X86::FP4:
      return -1;
    case X86::FP5:
      return -1;
    case X86::FP6:
      return -1;
    case X86::FS:
      return -1;
    case X86::GS:
      return -1;
    case X86::IP:
      return -1;
    case X86::MM0:
      return 29;
    case X86::MM1:
      return 30;
    case X86::MM2:
      return 31;
    case X86::MM3:
      return 32;
    case X86::MM4:
      return 33;
    case X86::MM5:
      return 34;
    case X86::MM6:
      return 35;
    case X86::MM7:
      return 36;
    case X86::R10:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::R10B:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::R10D:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::R10W:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::R11:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::R11B:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::R11D:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::R11W:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::R12:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::R12B:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::R12D:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::R12W:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::R13:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::R13B:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::R13D:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::R13W:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::R14:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::R14B:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::R14D:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::R14W:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::R15:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::R15B:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::R15D:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::R15W:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::R8:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::R8B:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::R8D:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::R8W:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::R9:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::R9B:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::R9D:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::R9W:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::RAX:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::RBP:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::RBX:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::RCR0:
      return -1;
    case X86::RCR1:
      return -1;
    case X86::RCR2:
      return -1;
    case X86::RCR3:
      return -1;
    case X86::RCR4:
      return -1;
    case X86::RCR5:
      return -1;
    case X86::RCR6:
      return -1;
    case X86::RCR7:
      return -1;
    case X86::RCR8:
      return -1;
    case X86::RCX:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::RDI:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::RDX:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::RIP:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::RSI:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::RSP:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::SI:
      return 6;
    case X86::SIL:
      return 6;
    case X86::SP:
      return 4;
    case X86::SPL:
      return 4;
    case X86::SS:
      return -1;
    case X86::ST0:
      return 11;
    case X86::ST1:
      return 12;
    case X86::ST2:
      return 13;
    case X86::ST3:
      return 14;
    case X86::ST4:
      return 15;
    case X86::ST5:
      return 16;
    case X86::ST6:
      return 17;
    case X86::ST7:
      return 18;
    case X86::XMM0:
      return 21;
    case X86::XMM1:
      return 22;
    case X86::XMM10:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::XMM11:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::XMM12:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::XMM13:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::XMM14:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::XMM15:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::XMM2:
      return 23;
    case X86::XMM3:
      return 24;
    case X86::XMM4:
      return 25;
    case X86::XMM5:
      return 26;
    case X86::XMM6:
      return 27;
    case X86::XMM7:
      return 28;
    case X86::XMM8:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::XMM9:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::YMM0:
      return 21;
    case X86::YMM1:
      return 22;
    case X86::YMM10:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::YMM11:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::YMM12:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::YMM13:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::YMM14:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::YMM15:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::YMM2:
      return 23;
    case X86::YMM3:
      return 24;
    case X86::YMM4:
      return 25;
    case X86::YMM5:
      return 26;
    case X86::YMM6:
      return 27;
    case X86::YMM7:
      return 28;
    case X86::YMM8:
      assert(0 && "Invalid register for this mode");
      return -1;
    case X86::YMM9:
      assert(0 && "Invalid register for this mode");
      return -1;
    };
  };
}

} // End llvm namespace 
