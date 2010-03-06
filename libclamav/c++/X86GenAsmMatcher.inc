//===- TableGen'erated file -------------------------------------*- C++ -*-===//
//
// Assembly Matcher Source Fragment
//
// Automatically generated file, do not edit!
//
//===----------------------------------------------------------------------===//

static unsigned MatchRegisterName(StringRef Name) {
  switch (Name.size()) {
  default: break;
  case 2:	 // 25 strings to match.
    switch (Name[0]) {
    default: break;
    case 'a':	 // 3 strings to match.
      switch (Name[1]) {
      default: break;
      case 'h':	 // 1 strings to match.
        return 1;	 // "ah"
      case 'l':	 // 1 strings to match.
        return 2;	 // "al"
      case 'x':	 // 1 strings to match.
        return 3;	 // "ax"
      }
      break;
    case 'b':	 // 4 strings to match.
      switch (Name[1]) {
      default: break;
      case 'h':	 // 1 strings to match.
        return 4;	 // "bh"
      case 'l':	 // 1 strings to match.
        return 5;	 // "bl"
      case 'p':	 // 1 strings to match.
        return 6;	 // "bp"
      case 'x':	 // 1 strings to match.
        return 8;	 // "bx"
      }
      break;
    case 'c':	 // 4 strings to match.
      switch (Name[1]) {
      default: break;
      case 'h':	 // 1 strings to match.
        return 9;	 // "ch"
      case 'l':	 // 1 strings to match.
        return 10;	 // "cl"
      case 's':	 // 1 strings to match.
        return 11;	 // "cs"
      case 'x':	 // 1 strings to match.
        return 12;	 // "cx"
      }
      break;
    case 'd':	 // 5 strings to match.
      switch (Name[1]) {
      default: break;
      case 'h':	 // 1 strings to match.
        return 13;	 // "dh"
      case 'i':	 // 1 strings to match.
        return 14;	 // "di"
      case 'l':	 // 1 strings to match.
        return 16;	 // "dl"
      case 's':	 // 1 strings to match.
        return 25;	 // "ds"
      case 'x':	 // 1 strings to match.
        return 26;	 // "dx"
      }
      break;
    case 'e':	 // 1 strings to match.
      if (Name[1] != 's')
        break;
      return 43;	 // "es"
    case 'f':	 // 1 strings to match.
      if (Name[1] != 's')
        break;
      return 53;	 // "fs"
    case 'g':	 // 1 strings to match.
      if (Name[1] != 's')
        break;
      return 54;	 // "gs"
    case 'i':	 // 1 strings to match.
      if (Name[1] != 'p')
        break;
      return 55;	 // "ip"
    case 'r':	 // 2 strings to match.
      switch (Name[1]) {
      default: break;
      case '8':	 // 1 strings to match.
        return 88;	 // "r8"
      case '9':	 // 1 strings to match.
        return 92;	 // "r9"
      }
      break;
    case 's':	 // 3 strings to match.
      switch (Name[1]) {
      default: break;
      case 'i':	 // 1 strings to match.
        return 114;	 // "si"
      case 'p':	 // 1 strings to match.
        return 116;	 // "sp"
      case 's':	 // 1 strings to match.
        return 118;	 // "ss"
      }
      break;
    }
    break;
  case 3:	 // 57 strings to match.
    switch (Name[0]) {
    default: break;
    case 'b':	 // 1 strings to match.
      if (Name.substr(1,2) != "pl")
        break;
      return 7;	 // "bpl"
    case 'd':	 // 9 strings to match.
      switch (Name[1]) {
      default: break;
      case 'i':	 // 1 strings to match.
        if (Name[2] != 'l')
          break;
        return 15;	 // "dil"
      case 'r':	 // 8 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 1 strings to match.
          return 17;	 // "dr0"
        case '1':	 // 1 strings to match.
          return 18;	 // "dr1"
        case '2':	 // 1 strings to match.
          return 19;	 // "dr2"
        case '3':	 // 1 strings to match.
          return 20;	 // "dr3"
        case '4':	 // 1 strings to match.
          return 21;	 // "dr4"
        case '5':	 // 1 strings to match.
          return 22;	 // "dr5"
        case '6':	 // 1 strings to match.
          return 23;	 // "dr6"
        case '7':	 // 1 strings to match.
          return 24;	 // "dr7"
        }
        break;
      }
      break;
    case 'e':	 // 9 strings to match.
      switch (Name[1]) {
      default: break;
      case 'a':	 // 1 strings to match.
        if (Name[2] != 'x')
          break;
        return 27;	 // "eax"
      case 'b':	 // 2 strings to match.
        switch (Name[2]) {
        default: break;
        case 'p':	 // 1 strings to match.
          return 28;	 // "ebp"
        case 'x':	 // 1 strings to match.
          return 29;	 // "ebx"
        }
        break;
      case 'c':	 // 1 strings to match.
        if (Name[2] != 'x')
          break;
        return 38;	 // "ecx"
      case 'd':	 // 2 strings to match.
        switch (Name[2]) {
        default: break;
        case 'i':	 // 1 strings to match.
          return 39;	 // "edi"
        case 'x':	 // 1 strings to match.
          return 40;	 // "edx"
        }
        break;
      case 'i':	 // 1 strings to match.
        if (Name[2] != 'p')
          break;
        return 42;	 // "eip"
      case 's':	 // 2 strings to match.
        switch (Name[2]) {
        default: break;
        case 'i':	 // 1 strings to match.
          return 44;	 // "esi"
        case 'p':	 // 1 strings to match.
          return 45;	 // "esp"
        }
        break;
      }
      break;
    case 'f':	 // 7 strings to match.
      if (Name[1] != 'p')
        break;
      switch (Name[2]) {
      default: break;
      case '0':	 // 1 strings to match.
        return 46;	 // "fp0"
      case '1':	 // 1 strings to match.
        return 47;	 // "fp1"
      case '2':	 // 1 strings to match.
        return 48;	 // "fp2"
      case '3':	 // 1 strings to match.
        return 49;	 // "fp3"
      case '4':	 // 1 strings to match.
        return 50;	 // "fp4"
      case '5':	 // 1 strings to match.
        return 51;	 // "fp5"
      case '6':	 // 1 strings to match.
        return 52;	 // "fp6"
      }
      break;
    case 'm':	 // 8 strings to match.
      if (Name[1] != 'm')
        break;
      switch (Name[2]) {
      default: break;
      case '0':	 // 1 strings to match.
        return 56;	 // "mm0"
      case '1':	 // 1 strings to match.
        return 57;	 // "mm1"
      case '2':	 // 1 strings to match.
        return 58;	 // "mm2"
      case '3':	 // 1 strings to match.
        return 59;	 // "mm3"
      case '4':	 // 1 strings to match.
        return 60;	 // "mm4"
      case '5':	 // 1 strings to match.
        return 61;	 // "mm5"
      case '6':	 // 1 strings to match.
        return 62;	 // "mm6"
      case '7':	 // 1 strings to match.
        return 63;	 // "mm7"
      }
      break;
    case 'r':	 // 21 strings to match.
      switch (Name[1]) {
      default: break;
      case '1':	 // 6 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 1 strings to match.
          return 64;	 // "r10"
        case '1':	 // 1 strings to match.
          return 68;	 // "r11"
        case '2':	 // 1 strings to match.
          return 72;	 // "r12"
        case '3':	 // 1 strings to match.
          return 76;	 // "r13"
        case '4':	 // 1 strings to match.
          return 80;	 // "r14"
        case '5':	 // 1 strings to match.
          return 84;	 // "r15"
        }
        break;
      case '8':	 // 3 strings to match.
        switch (Name[2]) {
        default: break;
        case 'b':	 // 1 strings to match.
          return 89;	 // "r8b"
        case 'd':	 // 1 strings to match.
          return 90;	 // "r8d"
        case 'w':	 // 1 strings to match.
          return 91;	 // "r8w"
        }
        break;
      case '9':	 // 3 strings to match.
        switch (Name[2]) {
        default: break;
        case 'b':	 // 1 strings to match.
          return 93;	 // "r9b"
        case 'd':	 // 1 strings to match.
          return 94;	 // "r9d"
        case 'w':	 // 1 strings to match.
          return 95;	 // "r9w"
        }
        break;
      case 'a':	 // 1 strings to match.
        if (Name[2] != 'x')
          break;
        return 96;	 // "rax"
      case 'b':	 // 2 strings to match.
        switch (Name[2]) {
        default: break;
        case 'p':	 // 1 strings to match.
          return 97;	 // "rbp"
        case 'x':	 // 1 strings to match.
          return 98;	 // "rbx"
        }
        break;
      case 'c':	 // 1 strings to match.
        if (Name[2] != 'x')
          break;
        return 108;	 // "rcx"
      case 'd':	 // 2 strings to match.
        switch (Name[2]) {
        default: break;
        case 'i':	 // 1 strings to match.
          return 109;	 // "rdi"
        case 'x':	 // 1 strings to match.
          return 110;	 // "rdx"
        }
        break;
      case 'i':	 // 1 strings to match.
        if (Name[2] != 'p')
          break;
        return 111;	 // "rip"
      case 's':	 // 2 strings to match.
        switch (Name[2]) {
        default: break;
        case 'i':	 // 1 strings to match.
          return 112;	 // "rsi"
        case 'p':	 // 1 strings to match.
          return 113;	 // "rsp"
        }
        break;
      }
      break;
    case 's':	 // 2 strings to match.
      switch (Name[1]) {
      default: break;
      case 'i':	 // 1 strings to match.
        if (Name[2] != 'l')
          break;
        return 115;	 // "sil"
      case 'p':	 // 1 strings to match.
        if (Name[2] != 'l')
          break;
        return 117;	 // "spl"
      }
      break;
    }
    break;
  case 4:	 // 55 strings to match.
    switch (Name[0]) {
    default: break;
    case 'e':	 // 8 strings to match.
      if (Name.substr(1,2) != "cr")
        break;
      switch (Name[3]) {
      default: break;
      case '0':	 // 1 strings to match.
        return 30;	 // "ecr0"
      case '1':	 // 1 strings to match.
        return 31;	 // "ecr1"
      case '2':	 // 1 strings to match.
        return 32;	 // "ecr2"
      case '3':	 // 1 strings to match.
        return 33;	 // "ecr3"
      case '4':	 // 1 strings to match.
        return 34;	 // "ecr4"
      case '5':	 // 1 strings to match.
        return 35;	 // "ecr5"
      case '6':	 // 1 strings to match.
        return 36;	 // "ecr6"
      case '7':	 // 1 strings to match.
        return 37;	 // "ecr7"
      }
      break;
    case 'r':	 // 27 strings to match.
      switch (Name[1]) {
      default: break;
      case '1':	 // 18 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 3 strings to match.
          switch (Name[3]) {
          default: break;
          case 'b':	 // 1 strings to match.
            return 65;	 // "r10b"
          case 'd':	 // 1 strings to match.
            return 66;	 // "r10d"
          case 'w':	 // 1 strings to match.
            return 67;	 // "r10w"
          }
          break;
        case '1':	 // 3 strings to match.
          switch (Name[3]) {
          default: break;
          case 'b':	 // 1 strings to match.
            return 69;	 // "r11b"
          case 'd':	 // 1 strings to match.
            return 70;	 // "r11d"
          case 'w':	 // 1 strings to match.
            return 71;	 // "r11w"
          }
          break;
        case '2':	 // 3 strings to match.
          switch (Name[3]) {
          default: break;
          case 'b':	 // 1 strings to match.
            return 73;	 // "r12b"
          case 'd':	 // 1 strings to match.
            return 74;	 // "r12d"
          case 'w':	 // 1 strings to match.
            return 75;	 // "r12w"
          }
          break;
        case '3':	 // 3 strings to match.
          switch (Name[3]) {
          default: break;
          case 'b':	 // 1 strings to match.
            return 77;	 // "r13b"
          case 'd':	 // 1 strings to match.
            return 78;	 // "r13d"
          case 'w':	 // 1 strings to match.
            return 79;	 // "r13w"
          }
          break;
        case '4':	 // 3 strings to match.
          switch (Name[3]) {
          default: break;
          case 'b':	 // 1 strings to match.
            return 81;	 // "r14b"
          case 'd':	 // 1 strings to match.
            return 82;	 // "r14d"
          case 'w':	 // 1 strings to match.
            return 83;	 // "r14w"
          }
          break;
        case '5':	 // 3 strings to match.
          switch (Name[3]) {
          default: break;
          case 'b':	 // 1 strings to match.
            return 85;	 // "r15b"
          case 'd':	 // 1 strings to match.
            return 86;	 // "r15d"
          case 'w':	 // 1 strings to match.
            return 87;	 // "r15w"
          }
          break;
        }
        break;
      case 'c':	 // 9 strings to match.
        if (Name[2] != 'r')
          break;
        switch (Name[3]) {
        default: break;
        case '0':	 // 1 strings to match.
          return 99;	 // "rcr0"
        case '1':	 // 1 strings to match.
          return 100;	 // "rcr1"
        case '2':	 // 1 strings to match.
          return 101;	 // "rcr2"
        case '3':	 // 1 strings to match.
          return 102;	 // "rcr3"
        case '4':	 // 1 strings to match.
          return 103;	 // "rcr4"
        case '5':	 // 1 strings to match.
          return 104;	 // "rcr5"
        case '6':	 // 1 strings to match.
          return 105;	 // "rcr6"
        case '7':	 // 1 strings to match.
          return 106;	 // "rcr7"
        case '8':	 // 1 strings to match.
          return 107;	 // "rcr8"
        }
        break;
      }
      break;
    case 'x':	 // 10 strings to match.
      if (Name.substr(1,2) != "mm")
        break;
      switch (Name[3]) {
      default: break;
      case '0':	 // 1 strings to match.
        return 127;	 // "xmm0"
      case '1':	 // 1 strings to match.
        return 128;	 // "xmm1"
      case '2':	 // 1 strings to match.
        return 135;	 // "xmm2"
      case '3':	 // 1 strings to match.
        return 136;	 // "xmm3"
      case '4':	 // 1 strings to match.
        return 137;	 // "xmm4"
      case '5':	 // 1 strings to match.
        return 138;	 // "xmm5"
      case '6':	 // 1 strings to match.
        return 139;	 // "xmm6"
      case '7':	 // 1 strings to match.
        return 140;	 // "xmm7"
      case '8':	 // 1 strings to match.
        return 141;	 // "xmm8"
      case '9':	 // 1 strings to match.
        return 142;	 // "xmm9"
      }
      break;
    case 'y':	 // 10 strings to match.
      if (Name.substr(1,2) != "mm")
        break;
      switch (Name[3]) {
      default: break;
      case '0':	 // 1 strings to match.
        return 143;	 // "ymm0"
      case '1':	 // 1 strings to match.
        return 144;	 // "ymm1"
      case '2':	 // 1 strings to match.
        return 151;	 // "ymm2"
      case '3':	 // 1 strings to match.
        return 152;	 // "ymm3"
      case '4':	 // 1 strings to match.
        return 153;	 // "ymm4"
      case '5':	 // 1 strings to match.
        return 154;	 // "ymm5"
      case '6':	 // 1 strings to match.
        return 155;	 // "ymm6"
      case '7':	 // 1 strings to match.
        return 156;	 // "ymm7"
      case '8':	 // 1 strings to match.
        return 157;	 // "ymm8"
      case '9':	 // 1 strings to match.
        return 158;	 // "ymm9"
      }
      break;
    }
    break;
  case 5:	 // 21 strings to match.
    switch (Name[0]) {
    default: break;
    case 'f':	 // 1 strings to match.
      if (Name.substr(1,4) != "lags")
        break;
      return 41;	 // "flags"
    case 's':	 // 8 strings to match.
      if (Name.substr(1,2) != "t(")
        break;
      switch (Name[3]) {
      default: break;
      case '0':	 // 1 strings to match.
        if (Name[4] != ')')
          break;
        return 119;	 // "st(0)"
      case '1':	 // 1 strings to match.
        if (Name[4] != ')')
          break;
        return 120;	 // "st(1)"
      case '2':	 // 1 strings to match.
        if (Name[4] != ')')
          break;
        return 121;	 // "st(2)"
      case '3':	 // 1 strings to match.
        if (Name[4] != ')')
          break;
        return 122;	 // "st(3)"
      case '4':	 // 1 strings to match.
        if (Name[4] != ')')
          break;
        return 123;	 // "st(4)"
      case '5':	 // 1 strings to match.
        if (Name[4] != ')')
          break;
        return 124;	 // "st(5)"
      case '6':	 // 1 strings to match.
        if (Name[4] != ')')
          break;
        return 125;	 // "st(6)"
      case '7':	 // 1 strings to match.
        if (Name[4] != ')')
          break;
        return 126;	 // "st(7)"
      }
      break;
    case 'x':	 // 6 strings to match.
      if (Name.substr(1,3) != "mm1")
        break;
      switch (Name[4]) {
      default: break;
      case '0':	 // 1 strings to match.
        return 129;	 // "xmm10"
      case '1':	 // 1 strings to match.
        return 130;	 // "xmm11"
      case '2':	 // 1 strings to match.
        return 131;	 // "xmm12"
      case '3':	 // 1 strings to match.
        return 132;	 // "xmm13"
      case '4':	 // 1 strings to match.
        return 133;	 // "xmm14"
      case '5':	 // 1 strings to match.
        return 134;	 // "xmm15"
      }
      break;
    case 'y':	 // 6 strings to match.
      if (Name.substr(1,3) != "mm1")
        break;
      switch (Name[4]) {
      default: break;
      case '0':	 // 1 strings to match.
        return 145;	 // "ymm10"
      case '1':	 // 1 strings to match.
        return 146;	 // "ymm11"
      case '2':	 // 1 strings to match.
        return 147;	 // "ymm12"
      case '3':	 // 1 strings to match.
        return 148;	 // "ymm13"
      case '4':	 // 1 strings to match.
        return 149;	 // "ymm14"
      case '5':	 // 1 strings to match.
        return 150;	 // "ymm15"
      }
      break;
    }
    break;
  }
  return 0;
}

#ifndef REGISTERS_ONLY

// Unified function for converting operants to MCInst instances.

enum ConversionKind {
  Convert,
  Convert__Reg1_1__Tie0,
  Convert__Imm1_1,
  Convert__AbsMem1_1,
  Convert__Mem5_1,
  Convert__Reg1_1,
  Convert__Reg1_2__Tie0__Reg1_1,
  Convert__Mem5_2__Reg1_1,
  Convert__Reg1_2__Tie0__Imm1_1,
  Convert__Mem5_2__Imm1_1,
  Convert__Reg1_2__Tie0__Mem5_1,
  Convert__Reg1_2__Tie0__ImmSExt81_1,
  Convert__Mem5_2__ImmSExt81_1,
  Convert__Reg1_2__Reg1_1,
  Convert__Reg1_2__Mem5_1,
  Convert__Reg1_2__ImmSExt81_1,
  Convert__Reg1_2,
  Convert__Mem5_2,
  Convert__Reg1_2__Imm1_1,
  Convert__Imm1_1__Imm1_2,
  Convert__ImmSExt81_1,
  Convert__Reg1_2__NoSegMem4_1,
  Convert__Reg1_2__Mem4_1,
  Convert__AbsMem1_2,
  Convert__ImmSExt81_2,
  Convert__Reg1_2__Tie0,
  Convert__Reg1_1__Tie0__Reg1_2,
  Convert__Reg1_1__Tie0__Mem5_2,
  Convert__Reg1_3__Tie0__Reg1_2__ImmSExt81_1,
  Convert__Reg1_3__Tie0__Mem5_2__ImmSExt81_1,
  Convert__Reg1_3__Tie0__Reg1_2,
  Convert__Reg1_3__Tie0__Mem5_2,
  Convert__Reg1_3__Reg1_2__ImmSExt81_1,
  Convert__Mem5_3__Reg1_2__ImmSExt81_1,
  Convert__Reg1_3__Mem5_2__ImmSExt81_1,
  Convert__Reg1_3__Reg1_2__Imm1_1,
  Convert__Reg1_3__Mem5_2__Imm1_1,
  Convert__Reg1_3__Tie0__Reg1_2__Imm1_1,
  Convert__Reg1_3__Tie0__Mem5_2__Imm1_1,
  Convert__Mem5_3__Reg1_2,
  Convert__Mem5_3__Reg1_2__Imm1_1,
  Convert__Reg1_4__Tie0__Reg1_3__Imm1_1,
  Convert__Reg1_4__Tie0__Mem5_3__Imm1_1,
  NumConversionVariants
};

static bool ConvertToMCInst(ConversionKind Kind, MCInst &Inst, unsigned Opcode,
                      const SmallVectorImpl<MCParsedAsmOperand*> &Operands) {
  Inst.setOpcode(Opcode);
  switch (Kind) {
  default:
  case Convert:
    break;
  case Convert__Reg1_1__Tie0:
    ((X86Operand*)Operands[1])->addRegOperands(Inst, 1);
    Inst.addOperand(Inst.getOperand(0));
    break;
  case Convert__Imm1_1:
    ((X86Operand*)Operands[1])->addImmOperands(Inst, 1);
    break;
  case Convert__AbsMem1_1:
    ((X86Operand*)Operands[1])->addAbsMemOperands(Inst, 1);
    break;
  case Convert__Mem5_1:
    ((X86Operand*)Operands[1])->addMemOperands(Inst, 5);
    break;
  case Convert__Reg1_1:
    ((X86Operand*)Operands[1])->addRegOperands(Inst, 1);
    break;
  case Convert__Reg1_2__Tie0__Reg1_1:
    ((X86Operand*)Operands[2])->addRegOperands(Inst, 1);
    Inst.addOperand(Inst.getOperand(0));
    ((X86Operand*)Operands[1])->addRegOperands(Inst, 1);
    break;
  case Convert__Mem5_2__Reg1_1:
    ((X86Operand*)Operands[2])->addMemOperands(Inst, 5);
    ((X86Operand*)Operands[1])->addRegOperands(Inst, 1);
    break;
  case Convert__Reg1_2__Tie0__Imm1_1:
    ((X86Operand*)Operands[2])->addRegOperands(Inst, 1);
    Inst.addOperand(Inst.getOperand(0));
    ((X86Operand*)Operands[1])->addImmOperands(Inst, 1);
    break;
  case Convert__Mem5_2__Imm1_1:
    ((X86Operand*)Operands[2])->addMemOperands(Inst, 5);
    ((X86Operand*)Operands[1])->addImmOperands(Inst, 1);
    break;
  case Convert__Reg1_2__Tie0__Mem5_1:
    ((X86Operand*)Operands[2])->addRegOperands(Inst, 1);
    Inst.addOperand(Inst.getOperand(0));
    ((X86Operand*)Operands[1])->addMemOperands(Inst, 5);
    break;
  case Convert__Reg1_2__Tie0__ImmSExt81_1:
    ((X86Operand*)Operands[2])->addRegOperands(Inst, 1);
    Inst.addOperand(Inst.getOperand(0));
    ((X86Operand*)Operands[1])->addImmSExt8Operands(Inst, 1);
    break;
  case Convert__Mem5_2__ImmSExt81_1:
    ((X86Operand*)Operands[2])->addMemOperands(Inst, 5);
    ((X86Operand*)Operands[1])->addImmSExt8Operands(Inst, 1);
    break;
  case Convert__Reg1_2__Reg1_1:
    ((X86Operand*)Operands[2])->addRegOperands(Inst, 1);
    ((X86Operand*)Operands[1])->addRegOperands(Inst, 1);
    break;
  case Convert__Reg1_2__Mem5_1:
    ((X86Operand*)Operands[2])->addRegOperands(Inst, 1);
    ((X86Operand*)Operands[1])->addMemOperands(Inst, 5);
    break;
  case Convert__Reg1_2__ImmSExt81_1:
    ((X86Operand*)Operands[2])->addRegOperands(Inst, 1);
    ((X86Operand*)Operands[1])->addImmSExt8Operands(Inst, 1);
    break;
  case Convert__Reg1_2:
    ((X86Operand*)Operands[2])->addRegOperands(Inst, 1);
    break;
  case Convert__Mem5_2:
    ((X86Operand*)Operands[2])->addMemOperands(Inst, 5);
    break;
  case Convert__Reg1_2__Imm1_1:
    ((X86Operand*)Operands[2])->addRegOperands(Inst, 1);
    ((X86Operand*)Operands[1])->addImmOperands(Inst, 1);
    break;
  case Convert__Imm1_1__Imm1_2:
    ((X86Operand*)Operands[1])->addImmOperands(Inst, 1);
    ((X86Operand*)Operands[2])->addImmOperands(Inst, 1);
    break;
  case Convert__ImmSExt81_1:
    ((X86Operand*)Operands[1])->addImmSExt8Operands(Inst, 1);
    break;
  case Convert__Reg1_2__NoSegMem4_1:
    ((X86Operand*)Operands[2])->addRegOperands(Inst, 1);
    ((X86Operand*)Operands[1])->addNoSegMemOperands(Inst, 4);
    break;
  case Convert__Reg1_2__Mem4_1:
    ((X86Operand*)Operands[2])->addRegOperands(Inst, 1);
    ((X86Operand*)Operands[1])->addMemOperands(Inst, 4);
    break;
  case Convert__AbsMem1_2:
    ((X86Operand*)Operands[2])->addAbsMemOperands(Inst, 1);
    break;
  case Convert__ImmSExt81_2:
    ((X86Operand*)Operands[2])->addImmSExt8Operands(Inst, 1);
    break;
  case Convert__Reg1_2__Tie0:
    ((X86Operand*)Operands[2])->addRegOperands(Inst, 1);
    Inst.addOperand(Inst.getOperand(0));
    break;
  case Convert__Reg1_1__Tie0__Reg1_2:
    ((X86Operand*)Operands[1])->addRegOperands(Inst, 1);
    Inst.addOperand(Inst.getOperand(0));
    ((X86Operand*)Operands[2])->addRegOperands(Inst, 1);
    break;
  case Convert__Reg1_1__Tie0__Mem5_2:
    ((X86Operand*)Operands[1])->addRegOperands(Inst, 1);
    Inst.addOperand(Inst.getOperand(0));
    ((X86Operand*)Operands[2])->addMemOperands(Inst, 5);
    break;
  case Convert__Reg1_3__Tie0__Reg1_2__ImmSExt81_1:
    ((X86Operand*)Operands[3])->addRegOperands(Inst, 1);
    Inst.addOperand(Inst.getOperand(0));
    ((X86Operand*)Operands[2])->addRegOperands(Inst, 1);
    ((X86Operand*)Operands[1])->addImmSExt8Operands(Inst, 1);
    break;
  case Convert__Reg1_3__Tie0__Mem5_2__ImmSExt81_1:
    ((X86Operand*)Operands[3])->addRegOperands(Inst, 1);
    Inst.addOperand(Inst.getOperand(0));
    ((X86Operand*)Operands[2])->addMemOperands(Inst, 5);
    ((X86Operand*)Operands[1])->addImmSExt8Operands(Inst, 1);
    break;
  case Convert__Reg1_3__Tie0__Reg1_2:
    ((X86Operand*)Operands[3])->addRegOperands(Inst, 1);
    Inst.addOperand(Inst.getOperand(0));
    ((X86Operand*)Operands[2])->addRegOperands(Inst, 1);
    break;
  case Convert__Reg1_3__Tie0__Mem5_2:
    ((X86Operand*)Operands[3])->addRegOperands(Inst, 1);
    Inst.addOperand(Inst.getOperand(0));
    ((X86Operand*)Operands[2])->addMemOperands(Inst, 5);
    break;
  case Convert__Reg1_3__Reg1_2__ImmSExt81_1:
    ((X86Operand*)Operands[3])->addRegOperands(Inst, 1);
    ((X86Operand*)Operands[2])->addRegOperands(Inst, 1);
    ((X86Operand*)Operands[1])->addImmSExt8Operands(Inst, 1);
    break;
  case Convert__Mem5_3__Reg1_2__ImmSExt81_1:
    ((X86Operand*)Operands[3])->addMemOperands(Inst, 5);
    ((X86Operand*)Operands[2])->addRegOperands(Inst, 1);
    ((X86Operand*)Operands[1])->addImmSExt8Operands(Inst, 1);
    break;
  case Convert__Reg1_3__Mem5_2__ImmSExt81_1:
    ((X86Operand*)Operands[3])->addRegOperands(Inst, 1);
    ((X86Operand*)Operands[2])->addMemOperands(Inst, 5);
    ((X86Operand*)Operands[1])->addImmSExt8Operands(Inst, 1);
    break;
  case Convert__Reg1_3__Reg1_2__Imm1_1:
    ((X86Operand*)Operands[3])->addRegOperands(Inst, 1);
    ((X86Operand*)Operands[2])->addRegOperands(Inst, 1);
    ((X86Operand*)Operands[1])->addImmOperands(Inst, 1);
    break;
  case Convert__Reg1_3__Mem5_2__Imm1_1:
    ((X86Operand*)Operands[3])->addRegOperands(Inst, 1);
    ((X86Operand*)Operands[2])->addMemOperands(Inst, 5);
    ((X86Operand*)Operands[1])->addImmOperands(Inst, 1);
    break;
  case Convert__Reg1_3__Tie0__Reg1_2__Imm1_1:
    ((X86Operand*)Operands[3])->addRegOperands(Inst, 1);
    Inst.addOperand(Inst.getOperand(0));
    ((X86Operand*)Operands[2])->addRegOperands(Inst, 1);
    ((X86Operand*)Operands[1])->addImmOperands(Inst, 1);
    break;
  case Convert__Reg1_3__Tie0__Mem5_2__Imm1_1:
    ((X86Operand*)Operands[3])->addRegOperands(Inst, 1);
    Inst.addOperand(Inst.getOperand(0));
    ((X86Operand*)Operands[2])->addMemOperands(Inst, 5);
    ((X86Operand*)Operands[1])->addImmOperands(Inst, 1);
    break;
  case Convert__Mem5_3__Reg1_2:
    ((X86Operand*)Operands[3])->addMemOperands(Inst, 5);
    ((X86Operand*)Operands[2])->addRegOperands(Inst, 1);
    break;
  case Convert__Mem5_3__Reg1_2__Imm1_1:
    ((X86Operand*)Operands[3])->addMemOperands(Inst, 5);
    ((X86Operand*)Operands[2])->addRegOperands(Inst, 1);
    ((X86Operand*)Operands[1])->addImmOperands(Inst, 1);
    break;
  case Convert__Reg1_4__Tie0__Reg1_3__Imm1_1:
    ((X86Operand*)Operands[4])->addRegOperands(Inst, 1);
    Inst.addOperand(Inst.getOperand(0));
    ((X86Operand*)Operands[3])->addRegOperands(Inst, 1);
    ((X86Operand*)Operands[1])->addImmOperands(Inst, 1);
    break;
  case Convert__Reg1_4__Tie0__Mem5_3__Imm1_1:
    ((X86Operand*)Operands[4])->addRegOperands(Inst, 1);
    Inst.addOperand(Inst.getOperand(0));
    ((X86Operand*)Operands[3])->addMemOperands(Inst, 5);
    ((X86Operand*)Operands[1])->addImmOperands(Inst, 1);
    break;
  }
  return false;
}

namespace {

/// MatchClassKind - The kinds of classes which participate in
/// instruction matching.
enum MatchClassKind {
  InvalidMatchClass = 0,
  MCK__STAR_, // '*'
  MCK_1, // '1'
  MCK_3, // '3'
  MCK_adcb, // 'adcb'
  MCK_adcl, // 'adcl'
  MCK_adcq, // 'adcq'
  MCK_adcw, // 'adcw'
  MCK_addb, // 'addb'
  MCK_addl, // 'addl'
  MCK_addpd, // 'addpd'
  MCK_addps, // 'addps'
  MCK_addq, // 'addq'
  MCK_addsd, // 'addsd'
  MCK_addss, // 'addss'
  MCK_addsubpd, // 'addsubpd'
  MCK_addsubps, // 'addsubps'
  MCK_addw, // 'addw'
  MCK_andb, // 'andb'
  MCK_andl, // 'andl'
  MCK_andnpd, // 'andnpd'
  MCK_andnps, // 'andnps'
  MCK_andpd, // 'andpd'
  MCK_andps, // 'andps'
  MCK_andq, // 'andq'
  MCK_andw, // 'andw'
  MCK_blendpd, // 'blendpd'
  MCK_blendps, // 'blendps'
  MCK_blendvpd, // 'blendvpd'
  MCK_blendvps, // 'blendvps'
  MCK_bsfl, // 'bsfl'
  MCK_bsfq, // 'bsfq'
  MCK_bsfw, // 'bsfw'
  MCK_bsrl, // 'bsrl'
  MCK_bsrq, // 'bsrq'
  MCK_bsrw, // 'bsrw'
  MCK_bswapl, // 'bswapl'
  MCK_bswapq, // 'bswapq'
  MCK_btcl, // 'btcl'
  MCK_btcq, // 'btcq'
  MCK_btcw, // 'btcw'
  MCK_btl, // 'btl'
  MCK_btq, // 'btq'
  MCK_btrl, // 'btrl'
  MCK_btrq, // 'btrq'
  MCK_btrw, // 'btrw'
  MCK_btsl, // 'btsl'
  MCK_btsq, // 'btsq'
  MCK_btsw, // 'btsw'
  MCK_btw, // 'btw'
  MCK_call, // 'call'
  MCK_callq, // 'callq'
  MCK_cbtw, // 'cbtw'
  MCK_clc, // 'clc'
  MCK_cld, // 'cld'
  MCK_clflush, // 'clflush'
  MCK_cli, // 'cli'
  MCK_cltd, // 'cltd'
  MCK_cltq, // 'cltq'
  MCK_clts, // 'clts'
  MCK_cmc, // 'cmc'
  MCK_cmovael, // 'cmovael'
  MCK_cmovaeq, // 'cmovaeq'
  MCK_cmovaew, // 'cmovaew'
  MCK_cmoval, // 'cmoval'
  MCK_cmovaq, // 'cmovaq'
  MCK_cmovaw, // 'cmovaw'
  MCK_cmovbel, // 'cmovbel'
  MCK_cmovbeq, // 'cmovbeq'
  MCK_cmovbew, // 'cmovbew'
  MCK_cmovbl, // 'cmovbl'
  MCK_cmovbq, // 'cmovbq'
  MCK_cmovbw, // 'cmovbw'
  MCK_cmovel, // 'cmovel'
  MCK_cmoveq, // 'cmoveq'
  MCK_cmovew, // 'cmovew'
  MCK_cmovgel, // 'cmovgel'
  MCK_cmovgeq, // 'cmovgeq'
  MCK_cmovgew, // 'cmovgew'
  MCK_cmovgl, // 'cmovgl'
  MCK_cmovgq, // 'cmovgq'
  MCK_cmovgw, // 'cmovgw'
  MCK_cmovlel, // 'cmovlel'
  MCK_cmovleq, // 'cmovleq'
  MCK_cmovlew, // 'cmovlew'
  MCK_cmovll, // 'cmovll'
  MCK_cmovlq, // 'cmovlq'
  MCK_cmovlw, // 'cmovlw'
  MCK_cmovnel, // 'cmovnel'
  MCK_cmovneq, // 'cmovneq'
  MCK_cmovnew, // 'cmovnew'
  MCK_cmovnol, // 'cmovnol'
  MCK_cmovnoq, // 'cmovnoq'
  MCK_cmovnow, // 'cmovnow'
  MCK_cmovnpl, // 'cmovnpl'
  MCK_cmovnpq, // 'cmovnpq'
  MCK_cmovnpw, // 'cmovnpw'
  MCK_cmovnsl, // 'cmovnsl'
  MCK_cmovnsq, // 'cmovnsq'
  MCK_cmovnsw, // 'cmovnsw'
  MCK_cmovol, // 'cmovol'
  MCK_cmovoq, // 'cmovoq'
  MCK_cmovow, // 'cmovow'
  MCK_cmovpl, // 'cmovpl'
  MCK_cmovpq, // 'cmovpq'
  MCK_cmovpw, // 'cmovpw'
  MCK_cmovsl, // 'cmovsl'
  MCK_cmovsq, // 'cmovsq'
  MCK_cmovsw, // 'cmovsw'
  MCK_cmp, // 'cmp'
  MCK_cmpb, // 'cmpb'
  MCK_cmpl, // 'cmpl'
  MCK_cmpq, // 'cmpq'
  MCK_cmpsb, // 'cmpsb'
  MCK_cmpsl, // 'cmpsl'
  MCK_cmpsq, // 'cmpsq'
  MCK_cmpsw, // 'cmpsw'
  MCK_cmpw, // 'cmpw'
  MCK_cmpxchg16b, // 'cmpxchg16b'
  MCK_cmpxchg8b, // 'cmpxchg8b'
  MCK_cmpxchgb, // 'cmpxchgb'
  MCK_cmpxchgl, // 'cmpxchgl'
  MCK_cmpxchgq, // 'cmpxchgq'
  MCK_cmpxchgw, // 'cmpxchgw'
  MCK_comisd, // 'comisd'
  MCK_comiss, // 'comiss'
  MCK_cpuid, // 'cpuid'
  MCK_cqto, // 'cqto'
  MCK_crc32, // 'crc32'
  MCK_cs, // 'cs'
  MCK_cvtdq2pd, // 'cvtdq2pd'
  MCK_cvtdq2ps, // 'cvtdq2ps'
  MCK_cvtpd2dq, // 'cvtpd2dq'
  MCK_cvtpd2pi, // 'cvtpd2pi'
  MCK_cvtpd2ps, // 'cvtpd2ps'
  MCK_cvtpi2pd, // 'cvtpi2pd'
  MCK_cvtpi2ps, // 'cvtpi2ps'
  MCK_cvtps2dq, // 'cvtps2dq'
  MCK_cvtps2pd, // 'cvtps2pd'
  MCK_cvtps2pi, // 'cvtps2pi'
  MCK_cvtsd2siq, // 'cvtsd2siq'
  MCK_cvtsd2ss, // 'cvtsd2ss'
  MCK_cvtsi2sd, // 'cvtsi2sd'
  MCK_cvtsi2sdq, // 'cvtsi2sdq'
  MCK_cvtsi2ss, // 'cvtsi2ss'
  MCK_cvtsi2ssq, // 'cvtsi2ssq'
  MCK_cvtss2sd, // 'cvtss2sd'
  MCK_cvtss2sil, // 'cvtss2sil'
  MCK_cvtss2siq, // 'cvtss2siq'
  MCK_cvttpd2pi, // 'cvttpd2pi'
  MCK_cvttps2dq, // 'cvttps2dq'
  MCK_cvttps2pi, // 'cvttps2pi'
  MCK_cvttsd2si, // 'cvttsd2si'
  MCK_cvttsd2siq, // 'cvttsd2siq'
  MCK_cvttss2si, // 'cvttss2si'
  MCK_cvttss2siq, // 'cvttss2siq'
  MCK_cwtd, // 'cwtd'
  MCK_cwtl, // 'cwtl'
  MCK_decb, // 'decb'
  MCK_decl, // 'decl'
  MCK_decq, // 'decq'
  MCK_decw, // 'decw'
  MCK_divb, // 'divb'
  MCK_divl, // 'divl'
  MCK_divpd, // 'divpd'
  MCK_divps, // 'divps'
  MCK_divq, // 'divq'
  MCK_divsd, // 'divsd'
  MCK_divss, // 'divss'
  MCK_divw, // 'divw'
  MCK_dppd, // 'dppd'
  MCK_dpps, // 'dpps'
  MCK_ds, // 'ds'
  MCK_emms, // 'emms'
  MCK_enter, // 'enter'
  MCK_es, // 'es'
  MCK_extractps, // 'extractps'
  MCK_f2xm1, // 'f2xm1'
  MCK_fabs, // 'fabs'
  MCK_fadd, // 'fadd'
  MCK_faddl, // 'faddl'
  MCK_faddp, // 'faddp'
  MCK_fadds, // 'fadds'
  MCK_fbld, // 'fbld'
  MCK_fbstp, // 'fbstp'
  MCK_fchs, // 'fchs'
  MCK_fcmovb, // 'fcmovb'
  MCK_fcmovbe, // 'fcmovbe'
  MCK_fcmove, // 'fcmove'
  MCK_fcmovnb, // 'fcmovnb'
  MCK_fcmovnbe, // 'fcmovnbe'
  MCK_fcmovne, // 'fcmovne'
  MCK_fcmovnu, // 'fcmovnu'
  MCK_fcmovu, // 'fcmovu'
  MCK_fcom, // 'fcom'
  MCK_fcomi, // 'fcomi'
  MCK_fcomip, // 'fcomip'
  MCK_fcoml, // 'fcoml'
  MCK_fcomll, // 'fcomll'
  MCK_fcomp, // 'fcomp'
  MCK_fcompl, // 'fcompl'
  MCK_fcompll, // 'fcompll'
  MCK_fcompp, // 'fcompp'
  MCK_fcos, // 'fcos'
  MCK_fdecstp, // 'fdecstp'
  MCK_fdiv, // 'fdiv'
  MCK_fdivl, // 'fdivl'
  MCK_fdivp, // 'fdivp'
  MCK_fdivr, // 'fdivr'
  MCK_fdivrl, // 'fdivrl'
  MCK_fdivrp, // 'fdivrp'
  MCK_fdivrs, // 'fdivrs'
  MCK_fdivs, // 'fdivs'
  MCK_femms, // 'femms'
  MCK_ffree, // 'ffree'
  MCK_fiaddl, // 'fiaddl'
  MCK_fiadds, // 'fiadds'
  MCK_ficoml, // 'ficoml'
  MCK_ficompl, // 'ficompl'
  MCK_ficompw, // 'ficompw'
  MCK_ficomw, // 'ficomw'
  MCK_fidivl, // 'fidivl'
  MCK_fidivrl, // 'fidivrl'
  MCK_fidivrs, // 'fidivrs'
  MCK_fidivs, // 'fidivs'
  MCK_fildl, // 'fildl'
  MCK_fildll, // 'fildll'
  MCK_filds, // 'filds'
  MCK_fimull, // 'fimull'
  MCK_fimuls, // 'fimuls'
  MCK_fincstp, // 'fincstp'
  MCK_fistl, // 'fistl'
  MCK_fistpl, // 'fistpl'
  MCK_fistpll, // 'fistpll'
  MCK_fistps, // 'fistps'
  MCK_fists, // 'fists'
  MCK_fisttpl, // 'fisttpl'
  MCK_fisttpll, // 'fisttpll'
  MCK_fisttps, // 'fisttps'
  MCK_fisubl, // 'fisubl'
  MCK_fisubrl, // 'fisubrl'
  MCK_fisubrs, // 'fisubrs'
  MCK_fisubs, // 'fisubs'
  MCK_fld, // 'fld'
  MCK_fld1, // 'fld1'
  MCK_fldcw, // 'fldcw'
  MCK_fldenv, // 'fldenv'
  MCK_fldl, // 'fldl'
  MCK_fldl2e, // 'fldl2e'
  MCK_fldl2t, // 'fldl2t'
  MCK_fldlg2, // 'fldlg2'
  MCK_fldln2, // 'fldln2'
  MCK_fldpi, // 'fldpi'
  MCK_flds, // 'flds'
  MCK_fldt, // 'fldt'
  MCK_fldz, // 'fldz'
  MCK_fmul, // 'fmul'
  MCK_fmull, // 'fmull'
  MCK_fmulp, // 'fmulp'
  MCK_fmuls, // 'fmuls'
  MCK_fnclex, // 'fnclex'
  MCK_fninit, // 'fninit'
  MCK_fnop, // 'fnop'
  MCK_fnsave, // 'fnsave'
  MCK_fnstcw, // 'fnstcw'
  MCK_fnstenv, // 'fnstenv'
  MCK_fnstsw, // 'fnstsw'
  MCK_fpatan, // 'fpatan'
  MCK_fprem, // 'fprem'
  MCK_fprem1, // 'fprem1'
  MCK_fptan, // 'fptan'
  MCK_frndint, // 'frndint'
  MCK_frstor, // 'frstor'
  MCK_fs, // 'fs'
  MCK_fscale, // 'fscale'
  MCK_fsin, // 'fsin'
  MCK_fsincos, // 'fsincos'
  MCK_fsqrt, // 'fsqrt'
  MCK_fst, // 'fst'
  MCK_fstl, // 'fstl'
  MCK_fstp, // 'fstp'
  MCK_fstpl, // 'fstpl'
  MCK_fstps, // 'fstps'
  MCK_fstpt, // 'fstpt'
  MCK_fsts, // 'fsts'
  MCK_fsub, // 'fsub'
  MCK_fsubl, // 'fsubl'
  MCK_fsubp, // 'fsubp'
  MCK_fsubr, // 'fsubr'
  MCK_fsubrl, // 'fsubrl'
  MCK_fsubrp, // 'fsubrp'
  MCK_fsubrs, // 'fsubrs'
  MCK_fsubs, // 'fsubs'
  MCK_ftst, // 'ftst'
  MCK_fucom, // 'fucom'
  MCK_fucomi, // 'fucomi'
  MCK_fucomip, // 'fucomip'
  MCK_fucomp, // 'fucomp'
  MCK_fucompp, // 'fucompp'
  MCK_fxam, // 'fxam'
  MCK_fxch, // 'fxch'
  MCK_fxrstor, // 'fxrstor'
  MCK_fxsave, // 'fxsave'
  MCK_fxtract, // 'fxtract'
  MCK_fyl2x, // 'fyl2x'
  MCK_fyl2xp1, // 'fyl2xp1'
  MCK_gs, // 'gs'
  MCK_haddpd, // 'haddpd'
  MCK_haddps, // 'haddps'
  MCK_hlt, // 'hlt'
  MCK_hsubpd, // 'hsubpd'
  MCK_hsubps, // 'hsubps'
  MCK_idivb, // 'idivb'
  MCK_idivl, // 'idivl'
  MCK_idivq, // 'idivq'
  MCK_idivw, // 'idivw'
  MCK_imulb, // 'imulb'
  MCK_imull, // 'imull'
  MCK_imulq, // 'imulq'
  MCK_imulw, // 'imulw'
  MCK_inb, // 'inb'
  MCK_incb, // 'incb'
  MCK_incl, // 'incl'
  MCK_incq, // 'incq'
  MCK_incw, // 'incw'
  MCK_inl, // 'inl'
  MCK_insb, // 'insb'
  MCK_insertps, // 'insertps'
  MCK_insl, // 'insl'
  MCK_insw, // 'insw'
  MCK_int, // 'int'
  MCK_invd, // 'invd'
  MCK_invept, // 'invept'
  MCK_invlpg, // 'invlpg'
  MCK_invvpid, // 'invvpid'
  MCK_inw, // 'inw'
  MCK_iretl, // 'iretl'
  MCK_iretq, // 'iretq'
  MCK_iretw, // 'iretw'
  MCK_ja, // 'ja'
  MCK_jae, // 'jae'
  MCK_jb, // 'jb'
  MCK_jbe, // 'jbe'
  MCK_jcxz, // 'jcxz'
  MCK_je, // 'je'
  MCK_jg, // 'jg'
  MCK_jge, // 'jge'
  MCK_jl, // 'jl'
  MCK_jle, // 'jle'
  MCK_jmp, // 'jmp'
  MCK_jmpl, // 'jmpl'
  MCK_jmpq, // 'jmpq'
  MCK_jne, // 'jne'
  MCK_jno, // 'jno'
  MCK_jnp, // 'jnp'
  MCK_jns, // 'jns'
  MCK_jo, // 'jo'
  MCK_jp, // 'jp'
  MCK_js, // 'js'
  MCK_lahf, // 'lahf'
  MCK_larl, // 'larl'
  MCK_larq, // 'larq'
  MCK_larw, // 'larw'
  MCK_lcalll, // 'lcalll'
  MCK_lcallq, // 'lcallq'
  MCK_lcallw, // 'lcallw'
  MCK_lddqu, // 'lddqu'
  MCK_ldmxcsr, // 'ldmxcsr'
  MCK_ldsl, // 'ldsl'
  MCK_ldsw, // 'ldsw'
  MCK_leal, // 'leal'
  MCK_leaq, // 'leaq'
  MCK_leave, // 'leave'
  MCK_leaw, // 'leaw'
  MCK_lesl, // 'lesl'
  MCK_lesw, // 'lesw'
  MCK_lfence, // 'lfence'
  MCK_lfsl, // 'lfsl'
  MCK_lfsq, // 'lfsq'
  MCK_lfsw, // 'lfsw'
  MCK_lgdt, // 'lgdt'
  MCK_lgsl, // 'lgsl'
  MCK_lgsq, // 'lgsq'
  MCK_lgsw, // 'lgsw'
  MCK_lidt, // 'lidt'
  MCK_ljmpl, // 'ljmpl'
  MCK_ljmpq, // 'ljmpq'
  MCK_ljmpw, // 'ljmpw'
  MCK_lldtw, // 'lldtw'
  MCK_lmsww, // 'lmsww'
  MCK_lock, // 'lock'
  MCK_lodsb, // 'lodsb'
  MCK_lodsl, // 'lodsl'
  MCK_lodsq, // 'lodsq'
  MCK_lodsw, // 'lodsw'
  MCK_loop, // 'loop'
  MCK_loope, // 'loope'
  MCK_loopne, // 'loopne'
  MCK_lret, // 'lret'
  MCK_lsll, // 'lsll'
  MCK_lslq, // 'lslq'
  MCK_lslw, // 'lslw'
  MCK_lssl, // 'lssl'
  MCK_lssq, // 'lssq'
  MCK_lssw, // 'lssw'
  MCK_ltrw, // 'ltrw'
  MCK_maskmovdqu, // 'maskmovdqu'
  MCK_maskmovq, // 'maskmovq'
  MCK_maxpd, // 'maxpd'
  MCK_maxps, // 'maxps'
  MCK_maxsd, // 'maxsd'
  MCK_maxss, // 'maxss'
  MCK_mfence, // 'mfence'
  MCK_minpd, // 'minpd'
  MCK_minps, // 'minps'
  MCK_minsd, // 'minsd'
  MCK_minss, // 'minss'
  MCK_monitor, // 'monitor'
  MCK_movabsq, // 'movabsq'
  MCK_movapd, // 'movapd'
  MCK_movaps, // 'movaps'
  MCK_movb, // 'movb'
  MCK_movd, // 'movd'
  MCK_movddup, // 'movddup'
  MCK_movdq2q, // 'movdq2q'
  MCK_movdqa, // 'movdqa'
  MCK_movdqu, // 'movdqu'
  MCK_movhlps, // 'movhlps'
  MCK_movhpd, // 'movhpd'
  MCK_movhps, // 'movhps'
  MCK_movl, // 'movl'
  MCK_movlhps, // 'movlhps'
  MCK_movlpd, // 'movlpd'
  MCK_movlps, // 'movlps'
  MCK_movmskpd, // 'movmskpd'
  MCK_movmskps, // 'movmskps'
  MCK_movntdq, // 'movntdq'
  MCK_movntdqa, // 'movntdqa'
  MCK_movnti, // 'movnti'
  MCK_movntpd, // 'movntpd'
  MCK_movntps, // 'movntps'
  MCK_movntq, // 'movntq'
  MCK_movq, // 'movq'
  MCK_movq2dq, // 'movq2dq'
  MCK_movsb, // 'movsb'
  MCK_movsbl, // 'movsbl'
  MCK_movsbq, // 'movsbq'
  MCK_movsbw, // 'movsbw'
  MCK_movsd, // 'movsd'
  MCK_movshdup, // 'movshdup'
  MCK_movsl, // 'movsl'
  MCK_movsldup, // 'movsldup'
  MCK_movslq, // 'movslq'
  MCK_movss, // 'movss'
  MCK_movsw, // 'movsw'
  MCK_movswl, // 'movswl'
  MCK_movswq, // 'movswq'
  MCK_movupd, // 'movupd'
  MCK_movups, // 'movups'
  MCK_movw, // 'movw'
  MCK_movzbl, // 'movzbl'
  MCK_movzbq, // 'movzbq'
  MCK_movzbw, // 'movzbw'
  MCK_movzwl, // 'movzwl'
  MCK_movzwq, // 'movzwq'
  MCK_mpsadbw, // 'mpsadbw'
  MCK_mulb, // 'mulb'
  MCK_mull, // 'mull'
  MCK_mulpd, // 'mulpd'
  MCK_mulps, // 'mulps'
  MCK_mulq, // 'mulq'
  MCK_mulsd, // 'mulsd'
  MCK_mulss, // 'mulss'
  MCK_mulw, // 'mulw'
  MCK_mwait, // 'mwait'
  MCK_negb, // 'negb'
  MCK_negl, // 'negl'
  MCK_negq, // 'negq'
  MCK_negw, // 'negw'
  MCK_nop, // 'nop'
  MCK_nopl, // 'nopl'
  MCK_nopw, // 'nopw'
  MCK_notb, // 'notb'
  MCK_notl, // 'notl'
  MCK_notq, // 'notq'
  MCK_notw, // 'notw'
  MCK_orb, // 'orb'
  MCK_orl, // 'orl'
  MCK_orpd, // 'orpd'
  MCK_orps, // 'orps'
  MCK_orq, // 'orq'
  MCK_orw, // 'orw'
  MCK_outb, // 'outb'
  MCK_outl, // 'outl'
  MCK_outsb, // 'outsb'
  MCK_outsl, // 'outsl'
  MCK_outsw, // 'outsw'
  MCK_outw, // 'outw'
  MCK_pabsb, // 'pabsb'
  MCK_pabsd, // 'pabsd'
  MCK_pabsw, // 'pabsw'
  MCK_packssdw, // 'packssdw'
  MCK_packsswb, // 'packsswb'
  MCK_packusdw, // 'packusdw'
  MCK_packuswb, // 'packuswb'
  MCK_paddb, // 'paddb'
  MCK_paddd, // 'paddd'
  MCK_paddq, // 'paddq'
  MCK_paddsb, // 'paddsb'
  MCK_paddsw, // 'paddsw'
  MCK_paddusb, // 'paddusb'
  MCK_paddusw, // 'paddusw'
  MCK_paddw, // 'paddw'
  MCK_palignr, // 'palignr'
  MCK_pand, // 'pand'
  MCK_pandn, // 'pandn'
  MCK_pavgb, // 'pavgb'
  MCK_pavgw, // 'pavgw'
  MCK_pblendvb, // 'pblendvb'
  MCK_pblendw, // 'pblendw'
  MCK_pcmpeqb, // 'pcmpeqb'
  MCK_pcmpeqd, // 'pcmpeqd'
  MCK_pcmpeqq, // 'pcmpeqq'
  MCK_pcmpeqw, // 'pcmpeqw'
  MCK_pcmpestri, // 'pcmpestri'
  MCK_pcmpestrm, // 'pcmpestrm'
  MCK_pcmpgtb, // 'pcmpgtb'
  MCK_pcmpgtd, // 'pcmpgtd'
  MCK_pcmpgtq, // 'pcmpgtq'
  MCK_pcmpgtw, // 'pcmpgtw'
  MCK_pcmpistri, // 'pcmpistri'
  MCK_pcmpistrm, // 'pcmpistrm'
  MCK_pd, // 'pd'
  MCK_pextrb, // 'pextrb'
  MCK_pextrd, // 'pextrd'
  MCK_pextrq, // 'pextrq'
  MCK_pextrw, // 'pextrw'
  MCK_phaddd, // 'phaddd'
  MCK_phaddsw, // 'phaddsw'
  MCK_phaddw, // 'phaddw'
  MCK_phminposuw, // 'phminposuw'
  MCK_phsubd, // 'phsubd'
  MCK_phsubsw, // 'phsubsw'
  MCK_phsubw, // 'phsubw'
  MCK_pinsrb, // 'pinsrb'
  MCK_pinsrd, // 'pinsrd'
  MCK_pinsrq, // 'pinsrq'
  MCK_pinsrw, // 'pinsrw'
  MCK_pmaddubsw, // 'pmaddubsw'
  MCK_pmaddwd, // 'pmaddwd'
  MCK_pmaxsb, // 'pmaxsb'
  MCK_pmaxsd, // 'pmaxsd'
  MCK_pmaxsw, // 'pmaxsw'
  MCK_pmaxub, // 'pmaxub'
  MCK_pmaxud, // 'pmaxud'
  MCK_pmaxuw, // 'pmaxuw'
  MCK_pminsb, // 'pminsb'
  MCK_pminsd, // 'pminsd'
  MCK_pminsw, // 'pminsw'
  MCK_pminub, // 'pminub'
  MCK_pminud, // 'pminud'
  MCK_pminuw, // 'pminuw'
  MCK_pmovmskb, // 'pmovmskb'
  MCK_pmovsxbd, // 'pmovsxbd'
  MCK_pmovsxbq, // 'pmovsxbq'
  MCK_pmovsxbw, // 'pmovsxbw'
  MCK_pmovsxdq, // 'pmovsxdq'
  MCK_pmovsxwd, // 'pmovsxwd'
  MCK_pmovsxwq, // 'pmovsxwq'
  MCK_pmovzxbd, // 'pmovzxbd'
  MCK_pmovzxbq, // 'pmovzxbq'
  MCK_pmovzxbw, // 'pmovzxbw'
  MCK_pmovzxdq, // 'pmovzxdq'
  MCK_pmovzxwd, // 'pmovzxwd'
  MCK_pmovzxwq, // 'pmovzxwq'
  MCK_pmuldq, // 'pmuldq'
  MCK_pmulhrsw, // 'pmulhrsw'
  MCK_pmulhuw, // 'pmulhuw'
  MCK_pmulhw, // 'pmulhw'
  MCK_pmulld, // 'pmulld'
  MCK_pmullw, // 'pmullw'
  MCK_pmuludq, // 'pmuludq'
  MCK_popcntl, // 'popcntl'
  MCK_popcntq, // 'popcntq'
  MCK_popcntw, // 'popcntw'
  MCK_popfl, // 'popfl'
  MCK_popfq, // 'popfq'
  MCK_popfw, // 'popfw'
  MCK_popl, // 'popl'
  MCK_popq, // 'popq'
  MCK_popw, // 'popw'
  MCK_por, // 'por'
  MCK_prefetchnta, // 'prefetchnta'
  MCK_prefetcht0, // 'prefetcht0'
  MCK_prefetcht1, // 'prefetcht1'
  MCK_prefetcht2, // 'prefetcht2'
  MCK_ps, // 'ps'
  MCK_psadbw, // 'psadbw'
  MCK_pshufb, // 'pshufb'
  MCK_pshufd, // 'pshufd'
  MCK_pshufhw, // 'pshufhw'
  MCK_pshuflw, // 'pshuflw'
  MCK_pshufw, // 'pshufw'
  MCK_psignb, // 'psignb'
  MCK_psignd, // 'psignd'
  MCK_psignw, // 'psignw'
  MCK_pslld, // 'pslld'
  MCK_pslldq, // 'pslldq'
  MCK_psllq, // 'psllq'
  MCK_psllw, // 'psllw'
  MCK_psrad, // 'psrad'
  MCK_psraw, // 'psraw'
  MCK_psrld, // 'psrld'
  MCK_psrldq, // 'psrldq'
  MCK_psrlq, // 'psrlq'
  MCK_psrlw, // 'psrlw'
  MCK_psubb, // 'psubb'
  MCK_psubd, // 'psubd'
  MCK_psubq, // 'psubq'
  MCK_psubsb, // 'psubsb'
  MCK_psubsw, // 'psubsw'
  MCK_psubusb, // 'psubusb'
  MCK_psubusw, // 'psubusw'
  MCK_psubw, // 'psubw'
  MCK_ptest, // 'ptest'
  MCK_punpckhbw, // 'punpckhbw'
  MCK_punpckhdq, // 'punpckhdq'
  MCK_punpckhqdq, // 'punpckhqdq'
  MCK_punpckhwd, // 'punpckhwd'
  MCK_punpcklbw, // 'punpcklbw'
  MCK_punpckldq, // 'punpckldq'
  MCK_punpcklqdq, // 'punpcklqdq'
  MCK_punpcklwd, // 'punpcklwd'
  MCK_pushfl, // 'pushfl'
  MCK_pushfq, // 'pushfq'
  MCK_pushfw, // 'pushfw'
  MCK_pushl, // 'pushl'
  MCK_pushq, // 'pushq'
  MCK_pushw, // 'pushw'
  MCK_pxor, // 'pxor'
  MCK_rclb, // 'rclb'
  MCK_rcll, // 'rcll'
  MCK_rclq, // 'rclq'
  MCK_rclw, // 'rclw'
  MCK_rcpps, // 'rcpps'
  MCK_rcpss, // 'rcpss'
  MCK_rcrb, // 'rcrb'
  MCK_rcrl, // 'rcrl'
  MCK_rcrq, // 'rcrq'
  MCK_rcrw, // 'rcrw'
  MCK_rdmsr, // 'rdmsr'
  MCK_rdpmc, // 'rdpmc'
  MCK_rdtsc, // 'rdtsc'
  MCK_rdtscp, // 'rdtscp'
  MCK_rep, // 'rep'
  MCK_rep_59_movsq, // 'rep;movsq'
  MCK_rep_59_stosq, // 'rep;stosq'
  MCK_repne, // 'repne'
  MCK_ret, // 'ret'
  MCK_rolb, // 'rolb'
  MCK_roll, // 'roll'
  MCK_rolq, // 'rolq'
  MCK_rolw, // 'rolw'
  MCK_rorb, // 'rorb'
  MCK_rorl, // 'rorl'
  MCK_rorq, // 'rorq'
  MCK_rorw, // 'rorw'
  MCK_rsm, // 'rsm'
  MCK_rsqrtps, // 'rsqrtps'
  MCK_rsqrtss, // 'rsqrtss'
  MCK_sahf, // 'sahf'
  MCK_sarb, // 'sarb'
  MCK_sarl, // 'sarl'
  MCK_sarq, // 'sarq'
  MCK_sarw, // 'sarw'
  MCK_sbbb, // 'sbbb'
  MCK_sbbl, // 'sbbl'
  MCK_sbbq, // 'sbbq'
  MCK_sbbw, // 'sbbw'
  MCK_scasb, // 'scasb'
  MCK_scasl, // 'scasl'
  MCK_scasq, // 'scasq'
  MCK_scasw, // 'scasw'
  MCK_sd, // 'sd'
  MCK_seta, // 'seta'
  MCK_setae, // 'setae'
  MCK_setb, // 'setb'
  MCK_setbe, // 'setbe'
  MCK_sete, // 'sete'
  MCK_setg, // 'setg'
  MCK_setge, // 'setge'
  MCK_setl, // 'setl'
  MCK_setle, // 'setle'
  MCK_setne, // 'setne'
  MCK_setno, // 'setno'
  MCK_setnp, // 'setnp'
  MCK_setns, // 'setns'
  MCK_seto, // 'seto'
  MCK_setp, // 'setp'
  MCK_sets, // 'sets'
  MCK_sfence, // 'sfence'
  MCK_sgdt, // 'sgdt'
  MCK_shlb, // 'shlb'
  MCK_shldl, // 'shldl'
  MCK_shldq, // 'shldq'
  MCK_shldw, // 'shldw'
  MCK_shll, // 'shll'
  MCK_shlq, // 'shlq'
  MCK_shlw, // 'shlw'
  MCK_shrb, // 'shrb'
  MCK_shrdl, // 'shrdl'
  MCK_shrdq, // 'shrdq'
  MCK_shrdw, // 'shrdw'
  MCK_shrl, // 'shrl'
  MCK_shrq, // 'shrq'
  MCK_shrw, // 'shrw'
  MCK_shufpd, // 'shufpd'
  MCK_shufps, // 'shufps'
  MCK_sidt, // 'sidt'
  MCK_sldtq, // 'sldtq'
  MCK_sldtw, // 'sldtw'
  MCK_smswl, // 'smswl'
  MCK_smswq, // 'smswq'
  MCK_smsww, // 'smsww'
  MCK_sqrtpd, // 'sqrtpd'
  MCK_sqrtps, // 'sqrtps'
  MCK_sqrtsd, // 'sqrtsd'
  MCK_sqrtss, // 'sqrtss'
  MCK_ss, // 'ss'
  MCK_stc, // 'stc'
  MCK_std, // 'std'
  MCK_sti, // 'sti'
  MCK_stmxcsr, // 'stmxcsr'
  MCK_stosb, // 'stosb'
  MCK_stosl, // 'stosl'
  MCK_stosw, // 'stosw'
  MCK_strw, // 'strw'
  MCK_subb, // 'subb'
  MCK_subl, // 'subl'
  MCK_subpd, // 'subpd'
  MCK_subps, // 'subps'
  MCK_subq, // 'subq'
  MCK_subsd, // 'subsd'
  MCK_subss, // 'subss'
  MCK_subw, // 'subw'
  MCK_swapgs, // 'swapgs'
  MCK_syscall, // 'syscall'
  MCK_sysenter, // 'sysenter'
  MCK_sysexit, // 'sysexit'
  MCK_sysret, // 'sysret'
  MCK_testb, // 'testb'
  MCK_testl, // 'testl'
  MCK_testq, // 'testq'
  MCK_testw, // 'testw'
  MCK_ucomisd, // 'ucomisd'
  MCK_ucomiss, // 'ucomiss'
  MCK_ud2, // 'ud2'
  MCK_unpckhpd, // 'unpckhpd'
  MCK_unpckhps, // 'unpckhps'
  MCK_unpcklpd, // 'unpcklpd'
  MCK_unpcklps, // 'unpcklps'
  MCK_verr, // 'verr'
  MCK_verw, // 'verw'
  MCK_vmcall, // 'vmcall'
  MCK_vmclear, // 'vmclear'
  MCK_vmlaunch, // 'vmlaunch'
  MCK_vmptrld, // 'vmptrld'
  MCK_vmptrst, // 'vmptrst'
  MCK_vmreadl, // 'vmreadl'
  MCK_vmreadq, // 'vmreadq'
  MCK_vmresume, // 'vmresume'
  MCK_vmwritel, // 'vmwritel'
  MCK_vmwriteq, // 'vmwriteq'
  MCK_vmxoff, // 'vmxoff'
  MCK_vmxon, // 'vmxon'
  MCK_wait, // 'wait'
  MCK_wbinvd, // 'wbinvd'
  MCK_wrmsr, // 'wrmsr'
  MCK_xaddb, // 'xaddb'
  MCK_xaddl, // 'xaddl'
  MCK_xaddq, // 'xaddq'
  MCK_xaddw, // 'xaddw'
  MCK_xchgb, // 'xchgb'
  MCK_xchgl, // 'xchgl'
  MCK_xchgq, // 'xchgq'
  MCK_xchgw, // 'xchgw'
  MCK_xlatb, // 'xlatb'
  MCK_xorb, // 'xorb'
  MCK_xorl, // 'xorl'
  MCK_xorpd, // 'xorpd'
  MCK_xorps, // 'xorps'
  MCK_xorq, // 'xorq'
  MCK_xorw, // 'xorw'
  MCK_AL, // register class 'AL'
  MCK_CL, // register class 'CL'
  MCK_GR8_ABCD_L, // register class 'GR8_ABCD_L'
  MCK_GR8_ABCD_H, // register class 'GR8_ABCD_H'
  MCK_GR8_NOREX, // register class 'GR8_NOREX'
  MCK_GR8, // register class 'GR8'
  MCK_AX, // register class 'AX'
  MCK_DX, // register class 'DX'
  MCK_GR16_ABCD, // register class 'GR16_ABCD'
  MCK_GR16_NOREX, // register class 'GR16_NOREX'
  MCK_GR16, // register class 'GR16'
  MCK_EAX, // register class 'EAX'
  MCK_GR32_AD, // register class 'GR32_AD'
  MCK_GR32_ABCD, // register class 'GR32_ABCD'
  MCK_Reg14, // derived register class
  MCK_GR32_NOREX, // register class 'GR32_NOREX'
  MCK_GR32_NOSP, // register class 'GR32_NOSP'
  MCK_GR32, // register class 'GR32'
  MCK_RAX, // register class 'RAX'
  MCK_GR64_ABCD, // register class 'GR64_ABCD'
  MCK_GR64_NOREX_NOSP, // register class 'GR64_NOREX_NOSP'
  MCK_GR64_NOREX, // register class 'GR64_NOREX'
  MCK_GR64_NOSP, // register class 'GR64_NOSP'
  MCK_GR64, // register class 'GR64'
  MCK_VR64, // register class 'VR64'
  MCK_RFP32, // register class 'RFP32,RFP64,RFP80'
  MCK_XMM0, // register class 'XMM0'
  MCK_FR32, // register class 'FR32,FR64,VR128'
  MCK_VR256, // register class 'VR256'
  MCK_ST0, // register class 'ST0'
  MCK_RST, // register class 'RST'
  MCK_CCR, // register class 'CCR'
  MCK_FS, // register class 'FS'
  MCK_GS, // register class 'GS'
  MCK_SEGMENT_REG, // register class 'SEGMENT_REG'
  MCK_DEBUG_REG, // register class 'DEBUG_REG'
  MCK_CONTROL_REG_32, // register class 'CONTROL_REG_32'
  MCK_CONTROL_REG_64, // register class 'CONTROL_REG_64'
  MCK_ImmSExt8, // user defined class 'ImmSExt8AsmOperand'
  MCK_Imm, // user defined class 'ImmAsmOperand'
  MCK_AbsMem, // user defined class 'X86AbsMemAsmOperand'
  MCK_NoSegMem, // user defined class 'X86NoSegMemAsmOperand'
  MCK_Mem, // user defined class 'X86MemAsmOperand'
  NumMatchClassKinds
};

}

static MatchClassKind MatchTokenString(StringRef Name) {
  switch (Name.size()) {
  default: break;
  case 1:	 // 3 strings to match.
    switch (Name[0]) {
    default: break;
    case '*':	 // 1 strings to match.
      return MCK__STAR_;	 // "*"
    case '1':	 // 1 strings to match.
      return MCK_1;	 // "1"
    case '3':	 // 1 strings to match.
      return MCK_3;	 // "3"
    }
    break;
  case 2:	 // 17 strings to match.
    switch (Name[0]) {
    default: break;
    case 'c':	 // 1 strings to match.
      if (Name[1] != 's')
        break;
      return MCK_cs;	 // "cs"
    case 'd':	 // 1 strings to match.
      if (Name[1] != 's')
        break;
      return MCK_ds;	 // "ds"
    case 'e':	 // 1 strings to match.
      if (Name[1] != 's')
        break;
      return MCK_es;	 // "es"
    case 'f':	 // 1 strings to match.
      if (Name[1] != 's')
        break;
      return MCK_fs;	 // "fs"
    case 'g':	 // 1 strings to match.
      if (Name[1] != 's')
        break;
      return MCK_gs;	 // "gs"
    case 'j':	 // 8 strings to match.
      switch (Name[1]) {
      default: break;
      case 'a':	 // 1 strings to match.
        return MCK_ja;	 // "ja"
      case 'b':	 // 1 strings to match.
        return MCK_jb;	 // "jb"
      case 'e':	 // 1 strings to match.
        return MCK_je;	 // "je"
      case 'g':	 // 1 strings to match.
        return MCK_jg;	 // "jg"
      case 'l':	 // 1 strings to match.
        return MCK_jl;	 // "jl"
      case 'o':	 // 1 strings to match.
        return MCK_jo;	 // "jo"
      case 'p':	 // 1 strings to match.
        return MCK_jp;	 // "jp"
      case 's':	 // 1 strings to match.
        return MCK_js;	 // "js"
      }
      break;
    case 'p':	 // 2 strings to match.
      switch (Name[1]) {
      default: break;
      case 'd':	 // 1 strings to match.
        return MCK_pd;	 // "pd"
      case 's':	 // 1 strings to match.
        return MCK_ps;	 // "ps"
      }
      break;
    case 's':	 // 2 strings to match.
      switch (Name[1]) {
      default: break;
      case 'd':	 // 1 strings to match.
        return MCK_sd;	 // "sd"
      case 's':	 // 1 strings to match.
        return MCK_ss;	 // "ss"
      }
      break;
    }
    break;
  case 3:	 // 37 strings to match.
    switch (Name[0]) {
    default: break;
    case 'b':	 // 3 strings to match.
      if (Name[1] != 't')
        break;
      switch (Name[2]) {
      default: break;
      case 'l':	 // 1 strings to match.
        return MCK_btl;	 // "btl"
      case 'q':	 // 1 strings to match.
        return MCK_btq;	 // "btq"
      case 'w':	 // 1 strings to match.
        return MCK_btw;	 // "btw"
      }
      break;
    case 'c':	 // 5 strings to match.
      switch (Name[1]) {
      default: break;
      case 'l':	 // 3 strings to match.
        switch (Name[2]) {
        default: break;
        case 'c':	 // 1 strings to match.
          return MCK_clc;	 // "clc"
        case 'd':	 // 1 strings to match.
          return MCK_cld;	 // "cld"
        case 'i':	 // 1 strings to match.
          return MCK_cli;	 // "cli"
        }
        break;
      case 'm':	 // 2 strings to match.
        switch (Name[2]) {
        default: break;
        case 'c':	 // 1 strings to match.
          return MCK_cmc;	 // "cmc"
        case 'p':	 // 1 strings to match.
          return MCK_cmp;	 // "cmp"
        }
        break;
      }
      break;
    case 'f':	 // 2 strings to match.
      switch (Name[1]) {
      default: break;
      case 'l':	 // 1 strings to match.
        if (Name[2] != 'd')
          break;
        return MCK_fld;	 // "fld"
      case 's':	 // 1 strings to match.
        if (Name[2] != 't')
          break;
        return MCK_fst;	 // "fst"
      }
      break;
    case 'h':	 // 1 strings to match.
      if (Name.substr(1,2) != "lt")
        break;
      return MCK_hlt;	 // "hlt"
    case 'i':	 // 4 strings to match.
      if (Name[1] != 'n')
        break;
      switch (Name[2]) {
      default: break;
      case 'b':	 // 1 strings to match.
        return MCK_inb;	 // "inb"
      case 'l':	 // 1 strings to match.
        return MCK_inl;	 // "inl"
      case 't':	 // 1 strings to match.
        return MCK_int;	 // "int"
      case 'w':	 // 1 strings to match.
        return MCK_inw;	 // "inw"
      }
      break;
    case 'j':	 // 9 strings to match.
      switch (Name[1]) {
      default: break;
      case 'a':	 // 1 strings to match.
        if (Name[2] != 'e')
          break;
        return MCK_jae;	 // "jae"
      case 'b':	 // 1 strings to match.
        if (Name[2] != 'e')
          break;
        return MCK_jbe;	 // "jbe"
      case 'g':	 // 1 strings to match.
        if (Name[2] != 'e')
          break;
        return MCK_jge;	 // "jge"
      case 'l':	 // 1 strings to match.
        if (Name[2] != 'e')
          break;
        return MCK_jle;	 // "jle"
      case 'm':	 // 1 strings to match.
        if (Name[2] != 'p')
          break;
        return MCK_jmp;	 // "jmp"
      case 'n':	 // 4 strings to match.
        switch (Name[2]) {
        default: break;
        case 'e':	 // 1 strings to match.
          return MCK_jne;	 // "jne"
        case 'o':	 // 1 strings to match.
          return MCK_jno;	 // "jno"
        case 'p':	 // 1 strings to match.
          return MCK_jnp;	 // "jnp"
        case 's':	 // 1 strings to match.
          return MCK_jns;	 // "jns"
        }
        break;
      }
      break;
    case 'n':	 // 1 strings to match.
      if (Name.substr(1,2) != "op")
        break;
      return MCK_nop;	 // "nop"
    case 'o':	 // 4 strings to match.
      if (Name[1] != 'r')
        break;
      switch (Name[2]) {
      default: break;
      case 'b':	 // 1 strings to match.
        return MCK_orb;	 // "orb"
      case 'l':	 // 1 strings to match.
        return MCK_orl;	 // "orl"
      case 'q':	 // 1 strings to match.
        return MCK_orq;	 // "orq"
      case 'w':	 // 1 strings to match.
        return MCK_orw;	 // "orw"
      }
      break;
    case 'p':	 // 1 strings to match.
      if (Name.substr(1,2) != "or")
        break;
      return MCK_por;	 // "por"
    case 'r':	 // 3 strings to match.
      switch (Name[1]) {
      default: break;
      case 'e':	 // 2 strings to match.
        switch (Name[2]) {
        default: break;
        case 'p':	 // 1 strings to match.
          return MCK_rep;	 // "rep"
        case 't':	 // 1 strings to match.
          return MCK_ret;	 // "ret"
        }
        break;
      case 's':	 // 1 strings to match.
        if (Name[2] != 'm')
          break;
        return MCK_rsm;	 // "rsm"
      }
      break;
    case 's':	 // 3 strings to match.
      if (Name[1] != 't')
        break;
      switch (Name[2]) {
      default: break;
      case 'c':	 // 1 strings to match.
        return MCK_stc;	 // "stc"
      case 'd':	 // 1 strings to match.
        return MCK_std;	 // "std"
      case 'i':	 // 1 strings to match.
        return MCK_sti;	 // "sti"
      }
      break;
    case 'u':	 // 1 strings to match.
      if (Name.substr(1,2) != "d2")
        break;
      return MCK_ud2;	 // "ud2"
    }
    break;
  case 4:	 // 196 strings to match.
    switch (Name[0]) {
    default: break;
    case 'a':	 // 12 strings to match.
      switch (Name[1]) {
      default: break;
      case 'd':	 // 8 strings to match.
        switch (Name[2]) {
        default: break;
        case 'c':	 // 4 strings to match.
          switch (Name[3]) {
          default: break;
          case 'b':	 // 1 strings to match.
            return MCK_adcb;	 // "adcb"
          case 'l':	 // 1 strings to match.
            return MCK_adcl;	 // "adcl"
          case 'q':	 // 1 strings to match.
            return MCK_adcq;	 // "adcq"
          case 'w':	 // 1 strings to match.
            return MCK_adcw;	 // "adcw"
          }
          break;
        case 'd':	 // 4 strings to match.
          switch (Name[3]) {
          default: break;
          case 'b':	 // 1 strings to match.
            return MCK_addb;	 // "addb"
          case 'l':	 // 1 strings to match.
            return MCK_addl;	 // "addl"
          case 'q':	 // 1 strings to match.
            return MCK_addq;	 // "addq"
          case 'w':	 // 1 strings to match.
            return MCK_addw;	 // "addw"
          }
          break;
        }
        break;
      case 'n':	 // 4 strings to match.
        if (Name[2] != 'd')
          break;
        switch (Name[3]) {
        default: break;
        case 'b':	 // 1 strings to match.
          return MCK_andb;	 // "andb"
        case 'l':	 // 1 strings to match.
          return MCK_andl;	 // "andl"
        case 'q':	 // 1 strings to match.
          return MCK_andq;	 // "andq"
        case 'w':	 // 1 strings to match.
          return MCK_andw;	 // "andw"
        }
        break;
      }
      break;
    case 'b':	 // 15 strings to match.
      switch (Name[1]) {
      default: break;
      case 's':	 // 6 strings to match.
        switch (Name[2]) {
        default: break;
        case 'f':	 // 3 strings to match.
          switch (Name[3]) {
          default: break;
          case 'l':	 // 1 strings to match.
            return MCK_bsfl;	 // "bsfl"
          case 'q':	 // 1 strings to match.
            return MCK_bsfq;	 // "bsfq"
          case 'w':	 // 1 strings to match.
            return MCK_bsfw;	 // "bsfw"
          }
          break;
        case 'r':	 // 3 strings to match.
          switch (Name[3]) {
          default: break;
          case 'l':	 // 1 strings to match.
            return MCK_bsrl;	 // "bsrl"
          case 'q':	 // 1 strings to match.
            return MCK_bsrq;	 // "bsrq"
          case 'w':	 // 1 strings to match.
            return MCK_bsrw;	 // "bsrw"
          }
          break;
        }
        break;
      case 't':	 // 9 strings to match.
        switch (Name[2]) {
        default: break;
        case 'c':	 // 3 strings to match.
          switch (Name[3]) {
          default: break;
          case 'l':	 // 1 strings to match.
            return MCK_btcl;	 // "btcl"
          case 'q':	 // 1 strings to match.
            return MCK_btcq;	 // "btcq"
          case 'w':	 // 1 strings to match.
            return MCK_btcw;	 // "btcw"
          }
          break;
        case 'r':	 // 3 strings to match.
          switch (Name[3]) {
          default: break;
          case 'l':	 // 1 strings to match.
            return MCK_btrl;	 // "btrl"
          case 'q':	 // 1 strings to match.
            return MCK_btrq;	 // "btrq"
          case 'w':	 // 1 strings to match.
            return MCK_btrw;	 // "btrw"
          }
          break;
        case 's':	 // 3 strings to match.
          switch (Name[3]) {
          default: break;
          case 'l':	 // 1 strings to match.
            return MCK_btsl;	 // "btsl"
          case 'q':	 // 1 strings to match.
            return MCK_btsq;	 // "btsq"
          case 'w':	 // 1 strings to match.
            return MCK_btsw;	 // "btsw"
          }
          break;
        }
        break;
      }
      break;
    case 'c':	 // 12 strings to match.
      switch (Name[1]) {
      default: break;
      case 'a':	 // 1 strings to match.
        if (Name.substr(2,2) != "ll")
          break;
        return MCK_call;	 // "call"
      case 'b':	 // 1 strings to match.
        if (Name.substr(2,2) != "tw")
          break;
        return MCK_cbtw;	 // "cbtw"
      case 'l':	 // 3 strings to match.
        if (Name[2] != 't')
          break;
        switch (Name[3]) {
        default: break;
        case 'd':	 // 1 strings to match.
          return MCK_cltd;	 // "cltd"
        case 'q':	 // 1 strings to match.
          return MCK_cltq;	 // "cltq"
        case 's':	 // 1 strings to match.
          return MCK_clts;	 // "clts"
        }
        break;
      case 'm':	 // 4 strings to match.
        if (Name[2] != 'p')
          break;
        switch (Name[3]) {
        default: break;
        case 'b':	 // 1 strings to match.
          return MCK_cmpb;	 // "cmpb"
        case 'l':	 // 1 strings to match.
          return MCK_cmpl;	 // "cmpl"
        case 'q':	 // 1 strings to match.
          return MCK_cmpq;	 // "cmpq"
        case 'w':	 // 1 strings to match.
          return MCK_cmpw;	 // "cmpw"
        }
        break;
      case 'q':	 // 1 strings to match.
        if (Name.substr(2,2) != "to")
          break;
        return MCK_cqto;	 // "cqto"
      case 'w':	 // 2 strings to match.
        if (Name[2] != 't')
          break;
        switch (Name[3]) {
        default: break;
        case 'd':	 // 1 strings to match.
          return MCK_cwtd;	 // "cwtd"
        case 'l':	 // 1 strings to match.
          return MCK_cwtl;	 // "cwtl"
        }
        break;
      }
      break;
    case 'd':	 // 10 strings to match.
      switch (Name[1]) {
      default: break;
      case 'e':	 // 4 strings to match.
        if (Name[2] != 'c')
          break;
        switch (Name[3]) {
        default: break;
        case 'b':	 // 1 strings to match.
          return MCK_decb;	 // "decb"
        case 'l':	 // 1 strings to match.
          return MCK_decl;	 // "decl"
        case 'q':	 // 1 strings to match.
          return MCK_decq;	 // "decq"
        case 'w':	 // 1 strings to match.
          return MCK_decw;	 // "decw"
        }
        break;
      case 'i':	 // 4 strings to match.
        if (Name[2] != 'v')
          break;
        switch (Name[3]) {
        default: break;
        case 'b':	 // 1 strings to match.
          return MCK_divb;	 // "divb"
        case 'l':	 // 1 strings to match.
          return MCK_divl;	 // "divl"
        case 'q':	 // 1 strings to match.
          return MCK_divq;	 // "divq"
        case 'w':	 // 1 strings to match.
          return MCK_divw;	 // "divw"
        }
        break;
      case 'p':	 // 2 strings to match.
        if (Name[2] != 'p')
          break;
        switch (Name[3]) {
        default: break;
        case 'd':	 // 1 strings to match.
          return MCK_dppd;	 // "dppd"
        case 's':	 // 1 strings to match.
          return MCK_dpps;	 // "dpps"
        }
        break;
      }
      break;
    case 'e':	 // 1 strings to match.
      if (Name.substr(1,3) != "mms")
        break;
      return MCK_emms;	 // "emms"
    case 'f':	 // 22 strings to match.
      switch (Name[1]) {
      default: break;
      case 'a':	 // 2 strings to match.
        switch (Name[2]) {
        default: break;
        case 'b':	 // 1 strings to match.
          if (Name[3] != 's')
            break;
          return MCK_fabs;	 // "fabs"
        case 'd':	 // 1 strings to match.
          if (Name[3] != 'd')
            break;
          return MCK_fadd;	 // "fadd"
        }
        break;
      case 'b':	 // 1 strings to match.
        if (Name.substr(2,2) != "ld")
          break;
        return MCK_fbld;	 // "fbld"
      case 'c':	 // 3 strings to match.
        switch (Name[2]) {
        default: break;
        case 'h':	 // 1 strings to match.
          if (Name[3] != 's')
            break;
          return MCK_fchs;	 // "fchs"
        case 'o':	 // 2 strings to match.
          switch (Name[3]) {
          default: break;
          case 'm':	 // 1 strings to match.
            return MCK_fcom;	 // "fcom"
          case 's':	 // 1 strings to match.
            return MCK_fcos;	 // "fcos"
          }
          break;
        }
        break;
      case 'd':	 // 1 strings to match.
        if (Name.substr(2,2) != "iv")
          break;
        return MCK_fdiv;	 // "fdiv"
      case 'l':	 // 5 strings to match.
        if (Name[2] != 'd')
          break;
        switch (Name[3]) {
        default: break;
        case '1':	 // 1 strings to match.
          return MCK_fld1;	 // "fld1"
        case 'l':	 // 1 strings to match.
          return MCK_fldl;	 // "fldl"
        case 's':	 // 1 strings to match.
          return MCK_flds;	 // "flds"
        case 't':	 // 1 strings to match.
          return MCK_fldt;	 // "fldt"
        case 'z':	 // 1 strings to match.
          return MCK_fldz;	 // "fldz"
        }
        break;
      case 'm':	 // 1 strings to match.
        if (Name.substr(2,2) != "ul")
          break;
        return MCK_fmul;	 // "fmul"
      case 'n':	 // 1 strings to match.
        if (Name.substr(2,2) != "op")
          break;
        return MCK_fnop;	 // "fnop"
      case 's':	 // 5 strings to match.
        switch (Name[2]) {
        default: break;
        case 'i':	 // 1 strings to match.
          if (Name[3] != 'n')
            break;
          return MCK_fsin;	 // "fsin"
        case 't':	 // 3 strings to match.
          switch (Name[3]) {
          default: break;
          case 'l':	 // 1 strings to match.
            return MCK_fstl;	 // "fstl"
          case 'p':	 // 1 strings to match.
            return MCK_fstp;	 // "fstp"
          case 's':	 // 1 strings to match.
            return MCK_fsts;	 // "fsts"
          }
          break;
        case 'u':	 // 1 strings to match.
          if (Name[3] != 'b')
            break;
          return MCK_fsub;	 // "fsub"
        }
        break;
      case 't':	 // 1 strings to match.
        if (Name.substr(2,2) != "st")
          break;
        return MCK_ftst;	 // "ftst"
      case 'x':	 // 2 strings to match.
        switch (Name[2]) {
        default: break;
        case 'a':	 // 1 strings to match.
          if (Name[3] != 'm')
            break;
          return MCK_fxam;	 // "fxam"
        case 'c':	 // 1 strings to match.
          if (Name[3] != 'h')
            break;
          return MCK_fxch;	 // "fxch"
        }
        break;
      }
      break;
    case 'i':	 // 8 strings to match.
      if (Name[1] != 'n')
        break;
      switch (Name[2]) {
      default: break;
      case 'c':	 // 4 strings to match.
        switch (Name[3]) {
        default: break;
        case 'b':	 // 1 strings to match.
          return MCK_incb;	 // "incb"
        case 'l':	 // 1 strings to match.
          return MCK_incl;	 // "incl"
        case 'q':	 // 1 strings to match.
          return MCK_incq;	 // "incq"
        case 'w':	 // 1 strings to match.
          return MCK_incw;	 // "incw"
        }
        break;
      case 's':	 // 3 strings to match.
        switch (Name[3]) {
        default: break;
        case 'b':	 // 1 strings to match.
          return MCK_insb;	 // "insb"
        case 'l':	 // 1 strings to match.
          return MCK_insl;	 // "insl"
        case 'w':	 // 1 strings to match.
          return MCK_insw;	 // "insw"
        }
        break;
      case 'v':	 // 1 strings to match.
        if (Name[3] != 'd')
          break;
        return MCK_invd;	 // "invd"
      }
      break;
    case 'j':	 // 3 strings to match.
      switch (Name[1]) {
      default: break;
      case 'c':	 // 1 strings to match.
        if (Name.substr(2,2) != "xz")
          break;
        return MCK_jcxz;	 // "jcxz"
      case 'm':	 // 2 strings to match.
        if (Name[2] != 'p')
          break;
        switch (Name[3]) {
        default: break;
        case 'l':	 // 1 strings to match.
          return MCK_jmpl;	 // "jmpl"
        case 'q':	 // 1 strings to match.
          return MCK_jmpq;	 // "jmpq"
        }
        break;
      }
      break;
    case 'l':	 // 29 strings to match.
      switch (Name[1]) {
      default: break;
      case 'a':	 // 4 strings to match.
        switch (Name[2]) {
        default: break;
        case 'h':	 // 1 strings to match.
          if (Name[3] != 'f')
            break;
          return MCK_lahf;	 // "lahf"
        case 'r':	 // 3 strings to match.
          switch (Name[3]) {
          default: break;
          case 'l':	 // 1 strings to match.
            return MCK_larl;	 // "larl"
          case 'q':	 // 1 strings to match.
            return MCK_larq;	 // "larq"
          case 'w':	 // 1 strings to match.
            return MCK_larw;	 // "larw"
          }
          break;
        }
        break;
      case 'd':	 // 2 strings to match.
        if (Name[2] != 's')
          break;
        switch (Name[3]) {
        default: break;
        case 'l':	 // 1 strings to match.
          return MCK_ldsl;	 // "ldsl"
        case 'w':	 // 1 strings to match.
          return MCK_ldsw;	 // "ldsw"
        }
        break;
      case 'e':	 // 5 strings to match.
        switch (Name[2]) {
        default: break;
        case 'a':	 // 3 strings to match.
          switch (Name[3]) {
          default: break;
          case 'l':	 // 1 strings to match.
            return MCK_leal;	 // "leal"
          case 'q':	 // 1 strings to match.
            return MCK_leaq;	 // "leaq"
          case 'w':	 // 1 strings to match.
            return MCK_leaw;	 // "leaw"
          }
          break;
        case 's':	 // 2 strings to match.
          switch (Name[3]) {
          default: break;
          case 'l':	 // 1 strings to match.
            return MCK_lesl;	 // "lesl"
          case 'w':	 // 1 strings to match.
            return MCK_lesw;	 // "lesw"
          }
          break;
        }
        break;
      case 'f':	 // 3 strings to match.
        if (Name[2] != 's')
          break;
        switch (Name[3]) {
        default: break;
        case 'l':	 // 1 strings to match.
          return MCK_lfsl;	 // "lfsl"
        case 'q':	 // 1 strings to match.
          return MCK_lfsq;	 // "lfsq"
        case 'w':	 // 1 strings to match.
          return MCK_lfsw;	 // "lfsw"
        }
        break;
      case 'g':	 // 4 strings to match.
        switch (Name[2]) {
        default: break;
        case 'd':	 // 1 strings to match.
          if (Name[3] != 't')
            break;
          return MCK_lgdt;	 // "lgdt"
        case 's':	 // 3 strings to match.
          switch (Name[3]) {
          default: break;
          case 'l':	 // 1 strings to match.
            return MCK_lgsl;	 // "lgsl"
          case 'q':	 // 1 strings to match.
            return MCK_lgsq;	 // "lgsq"
          case 'w':	 // 1 strings to match.
            return MCK_lgsw;	 // "lgsw"
          }
          break;
        }
        break;
      case 'i':	 // 1 strings to match.
        if (Name.substr(2,2) != "dt")
          break;
        return MCK_lidt;	 // "lidt"
      case 'o':	 // 2 strings to match.
        switch (Name[2]) {
        default: break;
        case 'c':	 // 1 strings to match.
          if (Name[3] != 'k')
            break;
          return MCK_lock;	 // "lock"
        case 'o':	 // 1 strings to match.
          if (Name[3] != 'p')
            break;
          return MCK_loop;	 // "loop"
        }
        break;
      case 'r':	 // 1 strings to match.
        if (Name.substr(2,2) != "et")
          break;
        return MCK_lret;	 // "lret"
      case 's':	 // 6 strings to match.
        switch (Name[2]) {
        default: break;
        case 'l':	 // 3 strings to match.
          switch (Name[3]) {
          default: break;
          case 'l':	 // 1 strings to match.
            return MCK_lsll;	 // "lsll"
          case 'q':	 // 1 strings to match.
            return MCK_lslq;	 // "lslq"
          case 'w':	 // 1 strings to match.
            return MCK_lslw;	 // "lslw"
          }
          break;
        case 's':	 // 3 strings to match.
          switch (Name[3]) {
          default: break;
          case 'l':	 // 1 strings to match.
            return MCK_lssl;	 // "lssl"
          case 'q':	 // 1 strings to match.
            return MCK_lssq;	 // "lssq"
          case 'w':	 // 1 strings to match.
            return MCK_lssw;	 // "lssw"
          }
          break;
        }
        break;
      case 't':	 // 1 strings to match.
        if (Name.substr(2,2) != "rw")
          break;
        return MCK_ltrw;	 // "ltrw"
      }
      break;
    case 'm':	 // 9 strings to match.
      switch (Name[1]) {
      default: break;
      case 'o':	 // 5 strings to match.
        if (Name[2] != 'v')
          break;
        switch (Name[3]) {
        default: break;
        case 'b':	 // 1 strings to match.
          return MCK_movb;	 // "movb"
        case 'd':	 // 1 strings to match.
          return MCK_movd;	 // "movd"
        case 'l':	 // 1 strings to match.
          return MCK_movl;	 // "movl"
        case 'q':	 // 1 strings to match.
          return MCK_movq;	 // "movq"
        case 'w':	 // 1 strings to match.
          return MCK_movw;	 // "movw"
        }
        break;
      case 'u':	 // 4 strings to match.
        if (Name[2] != 'l')
          break;
        switch (Name[3]) {
        default: break;
        case 'b':	 // 1 strings to match.
          return MCK_mulb;	 // "mulb"
        case 'l':	 // 1 strings to match.
          return MCK_mull;	 // "mull"
        case 'q':	 // 1 strings to match.
          return MCK_mulq;	 // "mulq"
        case 'w':	 // 1 strings to match.
          return MCK_mulw;	 // "mulw"
        }
        break;
      }
      break;
    case 'n':	 // 10 strings to match.
      switch (Name[1]) {
      default: break;
      case 'e':	 // 4 strings to match.
        if (Name[2] != 'g')
          break;
        switch (Name[3]) {
        default: break;
        case 'b':	 // 1 strings to match.
          return MCK_negb;	 // "negb"
        case 'l':	 // 1 strings to match.
          return MCK_negl;	 // "negl"
        case 'q':	 // 1 strings to match.
          return MCK_negq;	 // "negq"
        case 'w':	 // 1 strings to match.
          return MCK_negw;	 // "negw"
        }
        break;
      case 'o':	 // 6 strings to match.
        switch (Name[2]) {
        default: break;
        case 'p':	 // 2 strings to match.
          switch (Name[3]) {
          default: break;
          case 'l':	 // 1 strings to match.
            return MCK_nopl;	 // "nopl"
          case 'w':	 // 1 strings to match.
            return MCK_nopw;	 // "nopw"
          }
          break;
        case 't':	 // 4 strings to match.
          switch (Name[3]) {
          default: break;
          case 'b':	 // 1 strings to match.
            return MCK_notb;	 // "notb"
          case 'l':	 // 1 strings to match.
            return MCK_notl;	 // "notl"
          case 'q':	 // 1 strings to match.
            return MCK_notq;	 // "notq"
          case 'w':	 // 1 strings to match.
            return MCK_notw;	 // "notw"
          }
          break;
        }
        break;
      }
      break;
    case 'o':	 // 5 strings to match.
      switch (Name[1]) {
      default: break;
      case 'r':	 // 2 strings to match.
        if (Name[2] != 'p')
          break;
        switch (Name[3]) {
        default: break;
        case 'd':	 // 1 strings to match.
          return MCK_orpd;	 // "orpd"
        case 's':	 // 1 strings to match.
          return MCK_orps;	 // "orps"
        }
        break;
      case 'u':	 // 3 strings to match.
        if (Name[2] != 't')
          break;
        switch (Name[3]) {
        default: break;
        case 'b':	 // 1 strings to match.
          return MCK_outb;	 // "outb"
        case 'l':	 // 1 strings to match.
          return MCK_outl;	 // "outl"
        case 'w':	 // 1 strings to match.
          return MCK_outw;	 // "outw"
        }
        break;
      }
      break;
    case 'p':	 // 5 strings to match.
      switch (Name[1]) {
      default: break;
      case 'a':	 // 1 strings to match.
        if (Name.substr(2,2) != "nd")
          break;
        return MCK_pand;	 // "pand"
      case 'o':	 // 3 strings to match.
        if (Name[2] != 'p')
          break;
        switch (Name[3]) {
        default: break;
        case 'l':	 // 1 strings to match.
          return MCK_popl;	 // "popl"
        case 'q':	 // 1 strings to match.
          return MCK_popq;	 // "popq"
        case 'w':	 // 1 strings to match.
          return MCK_popw;	 // "popw"
        }
        break;
      case 'x':	 // 1 strings to match.
        if (Name.substr(2,2) != "or")
          break;
        return MCK_pxor;	 // "pxor"
      }
      break;
    case 'r':	 // 16 strings to match.
      switch (Name[1]) {
      default: break;
      case 'c':	 // 8 strings to match.
        switch (Name[2]) {
        default: break;
        case 'l':	 // 4 strings to match.
          switch (Name[3]) {
          default: break;
          case 'b':	 // 1 strings to match.
            return MCK_rclb;	 // "rclb"
          case 'l':	 // 1 strings to match.
            return MCK_rcll;	 // "rcll"
          case 'q':	 // 1 strings to match.
            return MCK_rclq;	 // "rclq"
          case 'w':	 // 1 strings to match.
            return MCK_rclw;	 // "rclw"
          }
          break;
        case 'r':	 // 4 strings to match.
          switch (Name[3]) {
          default: break;
          case 'b':	 // 1 strings to match.
            return MCK_rcrb;	 // "rcrb"
          case 'l':	 // 1 strings to match.
            return MCK_rcrl;	 // "rcrl"
          case 'q':	 // 1 strings to match.
            return MCK_rcrq;	 // "rcrq"
          case 'w':	 // 1 strings to match.
            return MCK_rcrw;	 // "rcrw"
          }
          break;
        }
        break;
      case 'o':	 // 8 strings to match.
        switch (Name[2]) {
        default: break;
        case 'l':	 // 4 strings to match.
          switch (Name[3]) {
          default: break;
          case 'b':	 // 1 strings to match.
            return MCK_rolb;	 // "rolb"
          case 'l':	 // 1 strings to match.
            return MCK_roll;	 // "roll"
          case 'q':	 // 1 strings to match.
            return MCK_rolq;	 // "rolq"
          case 'w':	 // 1 strings to match.
            return MCK_rolw;	 // "rolw"
          }
          break;
        case 'r':	 // 4 strings to match.
          switch (Name[3]) {
          default: break;
          case 'b':	 // 1 strings to match.
            return MCK_rorb;	 // "rorb"
          case 'l':	 // 1 strings to match.
            return MCK_rorl;	 // "rorl"
          case 'q':	 // 1 strings to match.
            return MCK_rorq;	 // "rorq"
          case 'w':	 // 1 strings to match.
            return MCK_rorw;	 // "rorw"
          }
          break;
        }
        break;
      }
      break;
    case 's':	 // 32 strings to match.
      switch (Name[1]) {
      default: break;
      case 'a':	 // 5 strings to match.
        switch (Name[2]) {
        default: break;
        case 'h':	 // 1 strings to match.
          if (Name[3] != 'f')
            break;
          return MCK_sahf;	 // "sahf"
        case 'r':	 // 4 strings to match.
          switch (Name[3]) {
          default: break;
          case 'b':	 // 1 strings to match.
            return MCK_sarb;	 // "sarb"
          case 'l':	 // 1 strings to match.
            return MCK_sarl;	 // "sarl"
          case 'q':	 // 1 strings to match.
            return MCK_sarq;	 // "sarq"
          case 'w':	 // 1 strings to match.
            return MCK_sarw;	 // "sarw"
          }
          break;
        }
        break;
      case 'b':	 // 4 strings to match.
        if (Name[2] != 'b')
          break;
        switch (Name[3]) {
        default: break;
        case 'b':	 // 1 strings to match.
          return MCK_sbbb;	 // "sbbb"
        case 'l':	 // 1 strings to match.
          return MCK_sbbl;	 // "sbbl"
        case 'q':	 // 1 strings to match.
          return MCK_sbbq;	 // "sbbq"
        case 'w':	 // 1 strings to match.
          return MCK_sbbw;	 // "sbbw"
        }
        break;
      case 'e':	 // 8 strings to match.
        if (Name[2] != 't')
          break;
        switch (Name[3]) {
        default: break;
        case 'a':	 // 1 strings to match.
          return MCK_seta;	 // "seta"
        case 'b':	 // 1 strings to match.
          return MCK_setb;	 // "setb"
        case 'e':	 // 1 strings to match.
          return MCK_sete;	 // "sete"
        case 'g':	 // 1 strings to match.
          return MCK_setg;	 // "setg"
        case 'l':	 // 1 strings to match.
          return MCK_setl;	 // "setl"
        case 'o':	 // 1 strings to match.
          return MCK_seto;	 // "seto"
        case 'p':	 // 1 strings to match.
          return MCK_setp;	 // "setp"
        case 's':	 // 1 strings to match.
          return MCK_sets;	 // "sets"
        }
        break;
      case 'g':	 // 1 strings to match.
        if (Name.substr(2,2) != "dt")
          break;
        return MCK_sgdt;	 // "sgdt"
      case 'h':	 // 8 strings to match.
        switch (Name[2]) {
        default: break;
        case 'l':	 // 4 strings to match.
          switch (Name[3]) {
          default: break;
          case 'b':	 // 1 strings to match.
            return MCK_shlb;	 // "shlb"
          case 'l':	 // 1 strings to match.
            return MCK_shll;	 // "shll"
          case 'q':	 // 1 strings to match.
            return MCK_shlq;	 // "shlq"
          case 'w':	 // 1 strings to match.
            return MCK_shlw;	 // "shlw"
          }
          break;
        case 'r':	 // 4 strings to match.
          switch (Name[3]) {
          default: break;
          case 'b':	 // 1 strings to match.
            return MCK_shrb;	 // "shrb"
          case 'l':	 // 1 strings to match.
            return MCK_shrl;	 // "shrl"
          case 'q':	 // 1 strings to match.
            return MCK_shrq;	 // "shrq"
          case 'w':	 // 1 strings to match.
            return MCK_shrw;	 // "shrw"
          }
          break;
        }
        break;
      case 'i':	 // 1 strings to match.
        if (Name.substr(2,2) != "dt")
          break;
        return MCK_sidt;	 // "sidt"
      case 't':	 // 1 strings to match.
        if (Name.substr(2,2) != "rw")
          break;
        return MCK_strw;	 // "strw"
      case 'u':	 // 4 strings to match.
        if (Name[2] != 'b')
          break;
        switch (Name[3]) {
        default: break;
        case 'b':	 // 1 strings to match.
          return MCK_subb;	 // "subb"
        case 'l':	 // 1 strings to match.
          return MCK_subl;	 // "subl"
        case 'q':	 // 1 strings to match.
          return MCK_subq;	 // "subq"
        case 'w':	 // 1 strings to match.
          return MCK_subw;	 // "subw"
        }
        break;
      }
      break;
    case 'v':	 // 2 strings to match.
      if (Name.substr(1,2) != "er")
        break;
      switch (Name[3]) {
      default: break;
      case 'r':	 // 1 strings to match.
        return MCK_verr;	 // "verr"
      case 'w':	 // 1 strings to match.
        return MCK_verw;	 // "verw"
      }
      break;
    case 'w':	 // 1 strings to match.
      if (Name.substr(1,3) != "ait")
        break;
      return MCK_wait;	 // "wait"
    case 'x':	 // 4 strings to match.
      if (Name.substr(1,2) != "or")
        break;
      switch (Name[3]) {
      default: break;
      case 'b':	 // 1 strings to match.
        return MCK_xorb;	 // "xorb"
      case 'l':	 // 1 strings to match.
        return MCK_xorl;	 // "xorl"
      case 'q':	 // 1 strings to match.
        return MCK_xorq;	 // "xorq"
      case 'w':	 // 1 strings to match.
        return MCK_xorw;	 // "xorw"
      }
      break;
    }
    break;
  case 5:	 // 179 strings to match.
    switch (Name[0]) {
    default: break;
    case 'a':	 // 6 strings to match.
      switch (Name[1]) {
      default: break;
      case 'd':	 // 4 strings to match.
        if (Name[2] != 'd')
          break;
        switch (Name[3]) {
        default: break;
        case 'p':	 // 2 strings to match.
          switch (Name[4]) {
          default: break;
          case 'd':	 // 1 strings to match.
            return MCK_addpd;	 // "addpd"
          case 's':	 // 1 strings to match.
            return MCK_addps;	 // "addps"
          }
          break;
        case 's':	 // 2 strings to match.
          switch (Name[4]) {
          default: break;
          case 'd':	 // 1 strings to match.
            return MCK_addsd;	 // "addsd"
          case 's':	 // 1 strings to match.
            return MCK_addss;	 // "addss"
          }
          break;
        }
        break;
      case 'n':	 // 2 strings to match.
        if (Name.substr(2,2) != "dp")
          break;
        switch (Name[4]) {
        default: break;
        case 'd':	 // 1 strings to match.
          return MCK_andpd;	 // "andpd"
        case 's':	 // 1 strings to match.
          return MCK_andps;	 // "andps"
        }
        break;
      }
      break;
    case 'c':	 // 7 strings to match.
      switch (Name[1]) {
      default: break;
      case 'a':	 // 1 strings to match.
        if (Name.substr(2,3) != "llq")
          break;
        return MCK_callq;	 // "callq"
      case 'm':	 // 4 strings to match.
        if (Name.substr(2,2) != "ps")
          break;
        switch (Name[4]) {
        default: break;
        case 'b':	 // 1 strings to match.
          return MCK_cmpsb;	 // "cmpsb"
        case 'l':	 // 1 strings to match.
          return MCK_cmpsl;	 // "cmpsl"
        case 'q':	 // 1 strings to match.
          return MCK_cmpsq;	 // "cmpsq"
        case 'w':	 // 1 strings to match.
          return MCK_cmpsw;	 // "cmpsw"
        }
        break;
      case 'p':	 // 1 strings to match.
        if (Name.substr(2,3) != "uid")
          break;
        return MCK_cpuid;	 // "cpuid"
      case 'r':	 // 1 strings to match.
        if (Name.substr(2,3) != "c32")
          break;
        return MCK_crc32;	 // "crc32"
      }
      break;
    case 'd':	 // 4 strings to match.
      if (Name.substr(1,2) != "iv")
        break;
      switch (Name[3]) {
      default: break;
      case 'p':	 // 2 strings to match.
        switch (Name[4]) {
        default: break;
        case 'd':	 // 1 strings to match.
          return MCK_divpd;	 // "divpd"
        case 's':	 // 1 strings to match.
          return MCK_divps;	 // "divps"
        }
        break;
      case 's':	 // 2 strings to match.
        switch (Name[4]) {
        default: break;
        case 'd':	 // 1 strings to match.
          return MCK_divsd;	 // "divsd"
        case 's':	 // 1 strings to match.
          return MCK_divss;	 // "divss"
        }
        break;
      }
      break;
    case 'e':	 // 1 strings to match.
      if (Name.substr(1,4) != "nter")
        break;
      return MCK_enter;	 // "enter"
    case 'f':	 // 35 strings to match.
      switch (Name[1]) {
      default: break;
      case '2':	 // 1 strings to match.
        if (Name.substr(2,3) != "xm1")
          break;
        return MCK_f2xm1;	 // "f2xm1"
      case 'a':	 // 3 strings to match.
        if (Name.substr(2,2) != "dd")
          break;
        switch (Name[4]) {
        default: break;
        case 'l':	 // 1 strings to match.
          return MCK_faddl;	 // "faddl"
        case 'p':	 // 1 strings to match.
          return MCK_faddp;	 // "faddp"
        case 's':	 // 1 strings to match.
          return MCK_fadds;	 // "fadds"
        }
        break;
      case 'b':	 // 1 strings to match.
        if (Name.substr(2,3) != "stp")
          break;
        return MCK_fbstp;	 // "fbstp"
      case 'c':	 // 3 strings to match.
        if (Name.substr(2,2) != "om")
          break;
        switch (Name[4]) {
        default: break;
        case 'i':	 // 1 strings to match.
          return MCK_fcomi;	 // "fcomi"
        case 'l':	 // 1 strings to match.
          return MCK_fcoml;	 // "fcoml"
        case 'p':	 // 1 strings to match.
          return MCK_fcomp;	 // "fcomp"
        }
        break;
      case 'd':	 // 4 strings to match.
        if (Name.substr(2,2) != "iv")
          break;
        switch (Name[4]) {
        default: break;
        case 'l':	 // 1 strings to match.
          return MCK_fdivl;	 // "fdivl"
        case 'p':	 // 1 strings to match.
          return MCK_fdivp;	 // "fdivp"
        case 'r':	 // 1 strings to match.
          return MCK_fdivr;	 // "fdivr"
        case 's':	 // 1 strings to match.
          return MCK_fdivs;	 // "fdivs"
        }
        break;
      case 'e':	 // 1 strings to match.
        if (Name.substr(2,3) != "mms")
          break;
        return MCK_femms;	 // "femms"
      case 'f':	 // 1 strings to match.
        if (Name.substr(2,3) != "ree")
          break;
        return MCK_ffree;	 // "ffree"
      case 'i':	 // 4 strings to match.
        switch (Name[2]) {
        default: break;
        case 'l':	 // 2 strings to match.
          if (Name[3] != 'd')
            break;
          switch (Name[4]) {
          default: break;
          case 'l':	 // 1 strings to match.
            return MCK_fildl;	 // "fildl"
          case 's':	 // 1 strings to match.
            return MCK_filds;	 // "filds"
          }
          break;
        case 's':	 // 2 strings to match.
          if (Name[3] != 't')
            break;
          switch (Name[4]) {
          default: break;
          case 'l':	 // 1 strings to match.
            return MCK_fistl;	 // "fistl"
          case 's':	 // 1 strings to match.
            return MCK_fists;	 // "fists"
          }
          break;
        }
        break;
      case 'l':	 // 2 strings to match.
        if (Name[2] != 'd')
          break;
        switch (Name[3]) {
        default: break;
        case 'c':	 // 1 strings to match.
          if (Name[4] != 'w')
            break;
          return MCK_fldcw;	 // "fldcw"
        case 'p':	 // 1 strings to match.
          if (Name[4] != 'i')
            break;
          return MCK_fldpi;	 // "fldpi"
        }
        break;
      case 'm':	 // 3 strings to match.
        if (Name.substr(2,2) != "ul")
          break;
        switch (Name[4]) {
        default: break;
        case 'l':	 // 1 strings to match.
          return MCK_fmull;	 // "fmull"
        case 'p':	 // 1 strings to match.
          return MCK_fmulp;	 // "fmulp"
        case 's':	 // 1 strings to match.
          return MCK_fmuls;	 // "fmuls"
        }
        break;
      case 'p':	 // 2 strings to match.
        switch (Name[2]) {
        default: break;
        case 'r':	 // 1 strings to match.
          if (Name.substr(3,2) != "em")
            break;
          return MCK_fprem;	 // "fprem"
        case 't':	 // 1 strings to match.
          if (Name.substr(3,2) != "an")
            break;
          return MCK_fptan;	 // "fptan"
        }
        break;
      case 's':	 // 8 strings to match.
        switch (Name[2]) {
        default: break;
        case 'q':	 // 1 strings to match.
          if (Name.substr(3,2) != "rt")
            break;
          return MCK_fsqrt;	 // "fsqrt"
        case 't':	 // 3 strings to match.
          if (Name[3] != 'p')
            break;
          switch (Name[4]) {
          default: break;
          case 'l':	 // 1 strings to match.
            return MCK_fstpl;	 // "fstpl"
          case 's':	 // 1 strings to match.
            return MCK_fstps;	 // "fstps"
          case 't':	 // 1 strings to match.
            return MCK_fstpt;	 // "fstpt"
          }
          break;
        case 'u':	 // 4 strings to match.
          if (Name[3] != 'b')
            break;
          switch (Name[4]) {
          default: break;
          case 'l':	 // 1 strings to match.
            return MCK_fsubl;	 // "fsubl"
          case 'p':	 // 1 strings to match.
            return MCK_fsubp;	 // "fsubp"
          case 'r':	 // 1 strings to match.
            return MCK_fsubr;	 // "fsubr"
          case 's':	 // 1 strings to match.
            return MCK_fsubs;	 // "fsubs"
          }
          break;
        }
        break;
      case 'u':	 // 1 strings to match.
        if (Name.substr(2,3) != "com")
          break;
        return MCK_fucom;	 // "fucom"
      case 'y':	 // 1 strings to match.
        if (Name.substr(2,3) != "l2x")
          break;
        return MCK_fyl2x;	 // "fyl2x"
      }
      break;
    case 'i':	 // 11 strings to match.
      switch (Name[1]) {
      default: break;
      case 'd':	 // 4 strings to match.
        if (Name.substr(2,2) != "iv")
          break;
        switch (Name[4]) {
        default: break;
        case 'b':	 // 1 strings to match.
          return MCK_idivb;	 // "idivb"
        case 'l':	 // 1 strings to match.
          return MCK_idivl;	 // "idivl"
        case 'q':	 // 1 strings to match.
          return MCK_idivq;	 // "idivq"
        case 'w':	 // 1 strings to match.
          return MCK_idivw;	 // "idivw"
        }
        break;
      case 'm':	 // 4 strings to match.
        if (Name.substr(2,2) != "ul")
          break;
        switch (Name[4]) {
        default: break;
        case 'b':	 // 1 strings to match.
          return MCK_imulb;	 // "imulb"
        case 'l':	 // 1 strings to match.
          return MCK_imull;	 // "imull"
        case 'q':	 // 1 strings to match.
          return MCK_imulq;	 // "imulq"
        case 'w':	 // 1 strings to match.
          return MCK_imulw;	 // "imulw"
        }
        break;
      case 'r':	 // 3 strings to match.
        if (Name.substr(2,2) != "et")
          break;
        switch (Name[4]) {
        default: break;
        case 'l':	 // 1 strings to match.
          return MCK_iretl;	 // "iretl"
        case 'q':	 // 1 strings to match.
          return MCK_iretq;	 // "iretq"
        case 'w':	 // 1 strings to match.
          return MCK_iretw;	 // "iretw"
        }
        break;
      }
      break;
    case 'l':	 // 12 strings to match.
      switch (Name[1]) {
      default: break;
      case 'd':	 // 1 strings to match.
        if (Name.substr(2,3) != "dqu")
          break;
        return MCK_lddqu;	 // "lddqu"
      case 'e':	 // 1 strings to match.
        if (Name.substr(2,3) != "ave")
          break;
        return MCK_leave;	 // "leave"
      case 'j':	 // 3 strings to match.
        if (Name.substr(2,2) != "mp")
          break;
        switch (Name[4]) {
        default: break;
        case 'l':	 // 1 strings to match.
          return MCK_ljmpl;	 // "ljmpl"
        case 'q':	 // 1 strings to match.
          return MCK_ljmpq;	 // "ljmpq"
        case 'w':	 // 1 strings to match.
          return MCK_ljmpw;	 // "ljmpw"
        }
        break;
      case 'l':	 // 1 strings to match.
        if (Name.substr(2,3) != "dtw")
          break;
        return MCK_lldtw;	 // "lldtw"
      case 'm':	 // 1 strings to match.
        if (Name.substr(2,3) != "sww")
          break;
        return MCK_lmsww;	 // "lmsww"
      case 'o':	 // 5 strings to match.
        switch (Name[2]) {
        default: break;
        case 'd':	 // 4 strings to match.
          if (Name[3] != 's')
            break;
          switch (Name[4]) {
          default: break;
          case 'b':	 // 1 strings to match.
            return MCK_lodsb;	 // "lodsb"
          case 'l':	 // 1 strings to match.
            return MCK_lodsl;	 // "lodsl"
          case 'q':	 // 1 strings to match.
            return MCK_lodsq;	 // "lodsq"
          case 'w':	 // 1 strings to match.
            return MCK_lodsw;	 // "lodsw"
          }
          break;
        case 'o':	 // 1 strings to match.
          if (Name.substr(3,2) != "pe")
            break;
          return MCK_loope;	 // "loope"
        }
        break;
      }
      break;
    case 'm':	 // 18 strings to match.
      switch (Name[1]) {
      default: break;
      case 'a':	 // 4 strings to match.
        if (Name[2] != 'x')
          break;
        switch (Name[3]) {
        default: break;
        case 'p':	 // 2 strings to match.
          switch (Name[4]) {
          default: break;
          case 'd':	 // 1 strings to match.
            return MCK_maxpd;	 // "maxpd"
          case 's':	 // 1 strings to match.
            return MCK_maxps;	 // "maxps"
          }
          break;
        case 's':	 // 2 strings to match.
          switch (Name[4]) {
          default: break;
          case 'd':	 // 1 strings to match.
            return MCK_maxsd;	 // "maxsd"
          case 's':	 // 1 strings to match.
            return MCK_maxss;	 // "maxss"
          }
          break;
        }
        break;
      case 'i':	 // 4 strings to match.
        if (Name[2] != 'n')
          break;
        switch (Name[3]) {
        default: break;
        case 'p':	 // 2 strings to match.
          switch (Name[4]) {
          default: break;
          case 'd':	 // 1 strings to match.
            return MCK_minpd;	 // "minpd"
          case 's':	 // 1 strings to match.
            return MCK_minps;	 // "minps"
          }
          break;
        case 's':	 // 2 strings to match.
          switch (Name[4]) {
          default: break;
          case 'd':	 // 1 strings to match.
            return MCK_minsd;	 // "minsd"
          case 's':	 // 1 strings to match.
            return MCK_minss;	 // "minss"
          }
          break;
        }
        break;
      case 'o':	 // 5 strings to match.
        if (Name.substr(2,2) != "vs")
          break;
        switch (Name[4]) {
        default: break;
        case 'b':	 // 1 strings to match.
          return MCK_movsb;	 // "movsb"
        case 'd':	 // 1 strings to match.
          return MCK_movsd;	 // "movsd"
        case 'l':	 // 1 strings to match.
          return MCK_movsl;	 // "movsl"
        case 's':	 // 1 strings to match.
          return MCK_movss;	 // "movss"
        case 'w':	 // 1 strings to match.
          return MCK_movsw;	 // "movsw"
        }
        break;
      case 'u':	 // 4 strings to match.
        if (Name[2] != 'l')
          break;
        switch (Name[3]) {
        default: break;
        case 'p':	 // 2 strings to match.
          switch (Name[4]) {
          default: break;
          case 'd':	 // 1 strings to match.
            return MCK_mulpd;	 // "mulpd"
          case 's':	 // 1 strings to match.
            return MCK_mulps;	 // "mulps"
          }
          break;
        case 's':	 // 2 strings to match.
          switch (Name[4]) {
          default: break;
          case 'd':	 // 1 strings to match.
            return MCK_mulsd;	 // "mulsd"
          case 's':	 // 1 strings to match.
            return MCK_mulss;	 // "mulss"
          }
          break;
        }
        break;
      case 'w':	 // 1 strings to match.
        if (Name.substr(2,3) != "ait")
          break;
        return MCK_mwait;	 // "mwait"
      }
      break;
    case 'o':	 // 3 strings to match.
      if (Name.substr(1,3) != "uts")
        break;
      switch (Name[4]) {
      default: break;
      case 'b':	 // 1 strings to match.
        return MCK_outsb;	 // "outsb"
      case 'l':	 // 1 strings to match.
        return MCK_outsl;	 // "outsl"
      case 'w':	 // 1 strings to match.
        return MCK_outsw;	 // "outsw"
      }
      break;
    case 'p':	 // 29 strings to match.
      switch (Name[1]) {
      default: break;
      case 'a':	 // 10 strings to match.
        switch (Name[2]) {
        default: break;
        case 'b':	 // 3 strings to match.
          if (Name[3] != 's')
            break;
          switch (Name[4]) {
          default: break;
          case 'b':	 // 1 strings to match.
            return MCK_pabsb;	 // "pabsb"
          case 'd':	 // 1 strings to match.
            return MCK_pabsd;	 // "pabsd"
          case 'w':	 // 1 strings to match.
            return MCK_pabsw;	 // "pabsw"
          }
          break;
        case 'd':	 // 4 strings to match.
          if (Name[3] != 'd')
            break;
          switch (Name[4]) {
          default: break;
          case 'b':	 // 1 strings to match.
            return MCK_paddb;	 // "paddb"
          case 'd':	 // 1 strings to match.
            return MCK_paddd;	 // "paddd"
          case 'q':	 // 1 strings to match.
            return MCK_paddq;	 // "paddq"
          case 'w':	 // 1 strings to match.
            return MCK_paddw;	 // "paddw"
          }
          break;
        case 'n':	 // 1 strings to match.
          if (Name.substr(3,2) != "dn")
            break;
          return MCK_pandn;	 // "pandn"
        case 'v':	 // 2 strings to match.
          if (Name[3] != 'g')
            break;
          switch (Name[4]) {
          default: break;
          case 'b':	 // 1 strings to match.
            return MCK_pavgb;	 // "pavgb"
          case 'w':	 // 1 strings to match.
            return MCK_pavgw;	 // "pavgw"
          }
          break;
        }
        break;
      case 'o':	 // 3 strings to match.
        if (Name.substr(2,2) != "pf")
          break;
        switch (Name[4]) {
        default: break;
        case 'l':	 // 1 strings to match.
          return MCK_popfl;	 // "popfl"
        case 'q':	 // 1 strings to match.
          return MCK_popfq;	 // "popfq"
        case 'w':	 // 1 strings to match.
          return MCK_popfw;	 // "popfw"
        }
        break;
      case 's':	 // 12 strings to match.
        switch (Name[2]) {
        default: break;
        case 'l':	 // 3 strings to match.
          if (Name[3] != 'l')
            break;
          switch (Name[4]) {
          default: break;
          case 'd':	 // 1 strings to match.
            return MCK_pslld;	 // "pslld"
          case 'q':	 // 1 strings to match.
            return MCK_psllq;	 // "psllq"
          case 'w':	 // 1 strings to match.
            return MCK_psllw;	 // "psllw"
          }
          break;
        case 'r':	 // 5 strings to match.
          switch (Name[3]) {
          default: break;
          case 'a':	 // 2 strings to match.
            switch (Name[4]) {
            default: break;
            case 'd':	 // 1 strings to match.
              return MCK_psrad;	 // "psrad"
            case 'w':	 // 1 strings to match.
              return MCK_psraw;	 // "psraw"
            }
            break;
          case 'l':	 // 3 strings to match.
            switch (Name[4]) {
            default: break;
            case 'd':	 // 1 strings to match.
              return MCK_psrld;	 // "psrld"
            case 'q':	 // 1 strings to match.
              return MCK_psrlq;	 // "psrlq"
            case 'w':	 // 1 strings to match.
              return MCK_psrlw;	 // "psrlw"
            }
            break;
          }
          break;
        case 'u':	 // 4 strings to match.
          if (Name[3] != 'b')
            break;
          switch (Name[4]) {
          default: break;
          case 'b':	 // 1 strings to match.
            return MCK_psubb;	 // "psubb"
          case 'd':	 // 1 strings to match.
            return MCK_psubd;	 // "psubd"
          case 'q':	 // 1 strings to match.
            return MCK_psubq;	 // "psubq"
          case 'w':	 // 1 strings to match.
            return MCK_psubw;	 // "psubw"
          }
          break;
        }
        break;
      case 't':	 // 1 strings to match.
        if (Name.substr(2,3) != "est")
          break;
        return MCK_ptest;	 // "ptest"
      case 'u':	 // 3 strings to match.
        if (Name.substr(2,2) != "sh")
          break;
        switch (Name[4]) {
        default: break;
        case 'l':	 // 1 strings to match.
          return MCK_pushl;	 // "pushl"
        case 'q':	 // 1 strings to match.
          return MCK_pushq;	 // "pushq"
        case 'w':	 // 1 strings to match.
          return MCK_pushw;	 // "pushw"
        }
        break;
      }
      break;
    case 'r':	 // 6 strings to match.
      switch (Name[1]) {
      default: break;
      case 'c':	 // 2 strings to match.
        if (Name[2] != 'p')
          break;
        switch (Name[3]) {
        default: break;
        case 'p':	 // 1 strings to match.
          if (Name[4] != 's')
            break;
          return MCK_rcpps;	 // "rcpps"
        case 's':	 // 1 strings to match.
          if (Name[4] != 's')
            break;
          return MCK_rcpss;	 // "rcpss"
        }
        break;
      case 'd':	 // 3 strings to match.
        switch (Name[2]) {
        default: break;
        case 'm':	 // 1 strings to match.
          if (Name.substr(3,2) != "sr")
            break;
          return MCK_rdmsr;	 // "rdmsr"
        case 'p':	 // 1 strings to match.
          if (Name.substr(3,2) != "mc")
            break;
          return MCK_rdpmc;	 // "rdpmc"
        case 't':	 // 1 strings to match.
          if (Name.substr(3,2) != "sc")
            break;
          return MCK_rdtsc;	 // "rdtsc"
        }
        break;
      case 'e':	 // 1 strings to match.
        if (Name.substr(2,3) != "pne")
          break;
        return MCK_repne;	 // "repne"
      }
      break;
    case 's':	 // 30 strings to match.
      switch (Name[1]) {
      default: break;
      case 'c':	 // 4 strings to match.
        if (Name.substr(2,2) != "as")
          break;
        switch (Name[4]) {
        default: break;
        case 'b':	 // 1 strings to match.
          return MCK_scasb;	 // "scasb"
        case 'l':	 // 1 strings to match.
          return MCK_scasl;	 // "scasl"
        case 'q':	 // 1 strings to match.
          return MCK_scasq;	 // "scasq"
        case 'w':	 // 1 strings to match.
          return MCK_scasw;	 // "scasw"
        }
        break;
      case 'e':	 // 8 strings to match.
        if (Name[2] != 't')
          break;
        switch (Name[3]) {
        default: break;
        case 'a':	 // 1 strings to match.
          if (Name[4] != 'e')
            break;
          return MCK_setae;	 // "setae"
        case 'b':	 // 1 strings to match.
          if (Name[4] != 'e')
            break;
          return MCK_setbe;	 // "setbe"
        case 'g':	 // 1 strings to match.
          if (Name[4] != 'e')
            break;
          return MCK_setge;	 // "setge"
        case 'l':	 // 1 strings to match.
          if (Name[4] != 'e')
            break;
          return MCK_setle;	 // "setle"
        case 'n':	 // 4 strings to match.
          switch (Name[4]) {
          default: break;
          case 'e':	 // 1 strings to match.
            return MCK_setne;	 // "setne"
          case 'o':	 // 1 strings to match.
            return MCK_setno;	 // "setno"
          case 'p':	 // 1 strings to match.
            return MCK_setnp;	 // "setnp"
          case 's':	 // 1 strings to match.
            return MCK_setns;	 // "setns"
          }
          break;
        }
        break;
      case 'h':	 // 6 strings to match.
        switch (Name[2]) {
        default: break;
        case 'l':	 // 3 strings to match.
          if (Name[3] != 'd')
            break;
          switch (Name[4]) {
          default: break;
          case 'l':	 // 1 strings to match.
            return MCK_shldl;	 // "shldl"
          case 'q':	 // 1 strings to match.
            return MCK_shldq;	 // "shldq"
          case 'w':	 // 1 strings to match.
            return MCK_shldw;	 // "shldw"
          }
          break;
        case 'r':	 // 3 strings to match.
          if (Name[3] != 'd')
            break;
          switch (Name[4]) {
          default: break;
          case 'l':	 // 1 strings to match.
            return MCK_shrdl;	 // "shrdl"
          case 'q':	 // 1 strings to match.
            return MCK_shrdq;	 // "shrdq"
          case 'w':	 // 1 strings to match.
            return MCK_shrdw;	 // "shrdw"
          }
          break;
        }
        break;
      case 'l':	 // 2 strings to match.
        if (Name.substr(2,2) != "dt")
          break;
        switch (Name[4]) {
        default: break;
        case 'q':	 // 1 strings to match.
          return MCK_sldtq;	 // "sldtq"
        case 'w':	 // 1 strings to match.
          return MCK_sldtw;	 // "sldtw"
        }
        break;
      case 'm':	 // 3 strings to match.
        if (Name.substr(2,2) != "sw")
          break;
        switch (Name[4]) {
        default: break;
        case 'l':	 // 1 strings to match.
          return MCK_smswl;	 // "smswl"
        case 'q':	 // 1 strings to match.
          return MCK_smswq;	 // "smswq"
        case 'w':	 // 1 strings to match.
          return MCK_smsww;	 // "smsww"
        }
        break;
      case 't':	 // 3 strings to match.
        if (Name.substr(2,2) != "os")
          break;
        switch (Name[4]) {
        default: break;
        case 'b':	 // 1 strings to match.
          return MCK_stosb;	 // "stosb"
        case 'l':	 // 1 strings to match.
          return MCK_stosl;	 // "stosl"
        case 'w':	 // 1 strings to match.
          return MCK_stosw;	 // "stosw"
        }
        break;
      case 'u':	 // 4 strings to match.
        if (Name[2] != 'b')
          break;
        switch (Name[3]) {
        default: break;
        case 'p':	 // 2 strings to match.
          switch (Name[4]) {
          default: break;
          case 'd':	 // 1 strings to match.
            return MCK_subpd;	 // "subpd"
          case 's':	 // 1 strings to match.
            return MCK_subps;	 // "subps"
          }
          break;
        case 's':	 // 2 strings to match.
          switch (Name[4]) {
          default: break;
          case 'd':	 // 1 strings to match.
            return MCK_subsd;	 // "subsd"
          case 's':	 // 1 strings to match.
            return MCK_subss;	 // "subss"
          }
          break;
        }
        break;
      }
      break;
    case 't':	 // 4 strings to match.
      if (Name.substr(1,3) != "est")
        break;
      switch (Name[4]) {
      default: break;
      case 'b':	 // 1 strings to match.
        return MCK_testb;	 // "testb"
      case 'l':	 // 1 strings to match.
        return MCK_testl;	 // "testl"
      case 'q':	 // 1 strings to match.
        return MCK_testq;	 // "testq"
      case 'w':	 // 1 strings to match.
        return MCK_testw;	 // "testw"
      }
      break;
    case 'v':	 // 1 strings to match.
      if (Name.substr(1,4) != "mxon")
        break;
      return MCK_vmxon;	 // "vmxon"
    case 'w':	 // 1 strings to match.
      if (Name.substr(1,4) != "rmsr")
        break;
      return MCK_wrmsr;	 // "wrmsr"
    case 'x':	 // 11 strings to match.
      switch (Name[1]) {
      default: break;
      case 'a':	 // 4 strings to match.
        if (Name.substr(2,2) != "dd")
          break;
        switch (Name[4]) {
        default: break;
        case 'b':	 // 1 strings to match.
          return MCK_xaddb;	 // "xaddb"
        case 'l':	 // 1 strings to match.
          return MCK_xaddl;	 // "xaddl"
        case 'q':	 // 1 strings to match.
          return MCK_xaddq;	 // "xaddq"
        case 'w':	 // 1 strings to match.
          return MCK_xaddw;	 // "xaddw"
        }
        break;
      case 'c':	 // 4 strings to match.
        if (Name.substr(2,2) != "hg")
          break;
        switch (Name[4]) {
        default: break;
        case 'b':	 // 1 strings to match.
          return MCK_xchgb;	 // "xchgb"
        case 'l':	 // 1 strings to match.
          return MCK_xchgl;	 // "xchgl"
        case 'q':	 // 1 strings to match.
          return MCK_xchgq;	 // "xchgq"
        case 'w':	 // 1 strings to match.
          return MCK_xchgw;	 // "xchgw"
        }
        break;
      case 'l':	 // 1 strings to match.
        if (Name.substr(2,3) != "atb")
          break;
        return MCK_xlatb;	 // "xlatb"
      case 'o':	 // 2 strings to match.
        if (Name.substr(2,2) != "rp")
          break;
        switch (Name[4]) {
        default: break;
        case 'd':	 // 1 strings to match.
          return MCK_xorpd;	 // "xorpd"
        case 's':	 // 1 strings to match.
          return MCK_xorps;	 // "xorps"
        }
        break;
      }
      break;
    }
    break;
  case 6:	 // 165 strings to match.
    switch (Name[0]) {
    default: break;
    case 'a':	 // 2 strings to match.
      if (Name.substr(1,4) != "ndnp")
        break;
      switch (Name[5]) {
      default: break;
      case 'd':	 // 1 strings to match.
        return MCK_andnpd;	 // "andnpd"
      case 's':	 // 1 strings to match.
        return MCK_andnps;	 // "andnps"
      }
      break;
    case 'b':	 // 2 strings to match.
      if (Name.substr(1,4) != "swap")
        break;
      switch (Name[5]) {
      default: break;
      case 'l':	 // 1 strings to match.
        return MCK_bswapl;	 // "bswapl"
      case 'q':	 // 1 strings to match.
        return MCK_bswapq;	 // "bswapq"
      }
      break;
    case 'c':	 // 26 strings to match.
      switch (Name[1]) {
      default: break;
      case 'm':	 // 24 strings to match.
        if (Name.substr(2,2) != "ov")
          break;
        switch (Name[4]) {
        default: break;
        case 'a':	 // 3 strings to match.
          switch (Name[5]) {
          default: break;
          case 'l':	 // 1 strings to match.
            return MCK_cmoval;	 // "cmoval"
          case 'q':	 // 1 strings to match.
            return MCK_cmovaq;	 // "cmovaq"
          case 'w':	 // 1 strings to match.
            return MCK_cmovaw;	 // "cmovaw"
          }
          break;
        case 'b':	 // 3 strings to match.
          switch (Name[5]) {
          default: break;
          case 'l':	 // 1 strings to match.
            return MCK_cmovbl;	 // "cmovbl"
          case 'q':	 // 1 strings to match.
            return MCK_cmovbq;	 // "cmovbq"
          case 'w':	 // 1 strings to match.
            return MCK_cmovbw;	 // "cmovbw"
          }
          break;
        case 'e':	 // 3 strings to match.
          switch (Name[5]) {
          default: break;
          case 'l':	 // 1 strings to match.
            return MCK_cmovel;	 // "cmovel"
          case 'q':	 // 1 strings to match.
            return MCK_cmoveq;	 // "cmoveq"
          case 'w':	 // 1 strings to match.
            return MCK_cmovew;	 // "cmovew"
          }
          break;
        case 'g':	 // 3 strings to match.
          switch (Name[5]) {
          default: break;
          case 'l':	 // 1 strings to match.
            return MCK_cmovgl;	 // "cmovgl"
          case 'q':	 // 1 strings to match.
            return MCK_cmovgq;	 // "cmovgq"
          case 'w':	 // 1 strings to match.
            return MCK_cmovgw;	 // "cmovgw"
          }
          break;
        case 'l':	 // 3 strings to match.
          switch (Name[5]) {
          default: break;
          case 'l':	 // 1 strings to match.
            return MCK_cmovll;	 // "cmovll"
          case 'q':	 // 1 strings to match.
            return MCK_cmovlq;	 // "cmovlq"
          case 'w':	 // 1 strings to match.
            return MCK_cmovlw;	 // "cmovlw"
          }
          break;
        case 'o':	 // 3 strings to match.
          switch (Name[5]) {
          default: break;
          case 'l':	 // 1 strings to match.
            return MCK_cmovol;	 // "cmovol"
          case 'q':	 // 1 strings to match.
            return MCK_cmovoq;	 // "cmovoq"
          case 'w':	 // 1 strings to match.
            return MCK_cmovow;	 // "cmovow"
          }
          break;
        case 'p':	 // 3 strings to match.
          switch (Name[5]) {
          default: break;
          case 'l':	 // 1 strings to match.
            return MCK_cmovpl;	 // "cmovpl"
          case 'q':	 // 1 strings to match.
            return MCK_cmovpq;	 // "cmovpq"
          case 'w':	 // 1 strings to match.
            return MCK_cmovpw;	 // "cmovpw"
          }
          break;
        case 's':	 // 3 strings to match.
          switch (Name[5]) {
          default: break;
          case 'l':	 // 1 strings to match.
            return MCK_cmovsl;	 // "cmovsl"
          case 'q':	 // 1 strings to match.
            return MCK_cmovsq;	 // "cmovsq"
          case 'w':	 // 1 strings to match.
            return MCK_cmovsw;	 // "cmovsw"
          }
          break;
        }
        break;
      case 'o':	 // 2 strings to match.
        if (Name.substr(2,3) != "mis")
          break;
        switch (Name[5]) {
        default: break;
        case 'd':	 // 1 strings to match.
          return MCK_comisd;	 // "comisd"
        case 's':	 // 1 strings to match.
          return MCK_comiss;	 // "comiss"
        }
        break;
      }
      break;
    case 'f':	 // 43 strings to match.
      switch (Name[1]) {
      default: break;
      case 'c':	 // 7 strings to match.
        switch (Name[2]) {
        default: break;
        case 'm':	 // 3 strings to match.
          if (Name.substr(3,2) != "ov")
            break;
          switch (Name[5]) {
          default: break;
          case 'b':	 // 1 strings to match.
            return MCK_fcmovb;	 // "fcmovb"
          case 'e':	 // 1 strings to match.
            return MCK_fcmove;	 // "fcmove"
          case 'u':	 // 1 strings to match.
            return MCK_fcmovu;	 // "fcmovu"
          }
          break;
        case 'o':	 // 4 strings to match.
          if (Name[3] != 'm')
            break;
          switch (Name[4]) {
          default: break;
          case 'i':	 // 1 strings to match.
            if (Name[5] != 'p')
              break;
            return MCK_fcomip;	 // "fcomip"
          case 'l':	 // 1 strings to match.
            if (Name[5] != 'l')
              break;
            return MCK_fcomll;	 // "fcomll"
          case 'p':	 // 2 strings to match.
            switch (Name[5]) {
            default: break;
            case 'l':	 // 1 strings to match.
              return MCK_fcompl;	 // "fcompl"
            case 'p':	 // 1 strings to match.
              return MCK_fcompp;	 // "fcompp"
            }
            break;
          }
          break;
        }
        break;
      case 'd':	 // 3 strings to match.
        if (Name.substr(2,3) != "ivr")
          break;
        switch (Name[5]) {
        default: break;
        case 'l':	 // 1 strings to match.
          return MCK_fdivrl;	 // "fdivrl"
        case 'p':	 // 1 strings to match.
          return MCK_fdivrp;	 // "fdivrp"
        case 's':	 // 1 strings to match.
          return MCK_fdivrs;	 // "fdivrs"
        }
        break;
      case 'i':	 // 13 strings to match.
        switch (Name[2]) {
        default: break;
        case 'a':	 // 2 strings to match.
          if (Name.substr(3,2) != "dd")
            break;
          switch (Name[5]) {
          default: break;
          case 'l':	 // 1 strings to match.
            return MCK_fiaddl;	 // "fiaddl"
          case 's':	 // 1 strings to match.
            return MCK_fiadds;	 // "fiadds"
          }
          break;
        case 'c':	 // 2 strings to match.
          if (Name.substr(3,2) != "om")
            break;
          switch (Name[5]) {
          default: break;
          case 'l':	 // 1 strings to match.
            return MCK_ficoml;	 // "ficoml"
          case 'w':	 // 1 strings to match.
            return MCK_ficomw;	 // "ficomw"
          }
          break;
        case 'd':	 // 2 strings to match.
          if (Name.substr(3,2) != "iv")
            break;
          switch (Name[5]) {
          default: break;
          case 'l':	 // 1 strings to match.
            return MCK_fidivl;	 // "fidivl"
          case 's':	 // 1 strings to match.
            return MCK_fidivs;	 // "fidivs"
          }
          break;
        case 'l':	 // 1 strings to match.
          if (Name.substr(3,3) != "dll")
            break;
          return MCK_fildll;	 // "fildll"
        case 'm':	 // 2 strings to match.
          if (Name.substr(3,2) != "ul")
            break;
          switch (Name[5]) {
          default: break;
          case 'l':	 // 1 strings to match.
            return MCK_fimull;	 // "fimull"
          case 's':	 // 1 strings to match.
            return MCK_fimuls;	 // "fimuls"
          }
          break;
        case 's':	 // 4 strings to match.
          switch (Name[3]) {
          default: break;
          case 't':	 // 2 strings to match.
            if (Name[4] != 'p')
              break;
            switch (Name[5]) {
            default: break;
            case 'l':	 // 1 strings to match.
              return MCK_fistpl;	 // "fistpl"
            case 's':	 // 1 strings to match.
              return MCK_fistps;	 // "fistps"
            }
            break;
          case 'u':	 // 2 strings to match.
            if (Name[4] != 'b')
              break;
            switch (Name[5]) {
            default: break;
            case 'l':	 // 1 strings to match.
              return MCK_fisubl;	 // "fisubl"
            case 's':	 // 1 strings to match.
              return MCK_fisubs;	 // "fisubs"
            }
            break;
          }
          break;
        }
        break;
      case 'l':	 // 5 strings to match.
        if (Name[2] != 'd')
          break;
        switch (Name[3]) {
        default: break;
        case 'e':	 // 1 strings to match.
          if (Name.substr(4,2) != "nv")
            break;
          return MCK_fldenv;	 // "fldenv"
        case 'l':	 // 4 strings to match.
          switch (Name[4]) {
          default: break;
          case '2':	 // 2 strings to match.
            switch (Name[5]) {
            default: break;
            case 'e':	 // 1 strings to match.
              return MCK_fldl2e;	 // "fldl2e"
            case 't':	 // 1 strings to match.
              return MCK_fldl2t;	 // "fldl2t"
            }
            break;
          case 'g':	 // 1 strings to match.
            if (Name[5] != '2')
              break;
            return MCK_fldlg2;	 // "fldlg2"
          case 'n':	 // 1 strings to match.
            if (Name[5] != '2')
              break;
            return MCK_fldln2;	 // "fldln2"
          }
          break;
        }
        break;
      case 'n':	 // 5 strings to match.
        switch (Name[2]) {
        default: break;
        case 'c':	 // 1 strings to match.
          if (Name.substr(3,3) != "lex")
            break;
          return MCK_fnclex;	 // "fnclex"
        case 'i':	 // 1 strings to match.
          if (Name.substr(3,3) != "nit")
            break;
          return MCK_fninit;	 // "fninit"
        case 's':	 // 3 strings to match.
          switch (Name[3]) {
          default: break;
          case 'a':	 // 1 strings to match.
            if (Name.substr(4,2) != "ve")
              break;
            return MCK_fnsave;	 // "fnsave"
          case 't':	 // 2 strings to match.
            switch (Name[4]) {
            default: break;
            case 'c':	 // 1 strings to match.
              if (Name[5] != 'w')
                break;
              return MCK_fnstcw;	 // "fnstcw"
            case 's':	 // 1 strings to match.
              if (Name[5] != 'w')
                break;
              return MCK_fnstsw;	 // "fnstsw"
            }
            break;
          }
          break;
        }
        break;
      case 'p':	 // 2 strings to match.
        switch (Name[2]) {
        default: break;
        case 'a':	 // 1 strings to match.
          if (Name.substr(3,3) != "tan")
            break;
          return MCK_fpatan;	 // "fpatan"
        case 'r':	 // 1 strings to match.
          if (Name.substr(3,3) != "em1")
            break;
          return MCK_fprem1;	 // "fprem1"
        }
        break;
      case 'r':	 // 1 strings to match.
        if (Name.substr(2,4) != "stor")
          break;
        return MCK_frstor;	 // "frstor"
      case 's':	 // 4 strings to match.
        switch (Name[2]) {
        default: break;
        case 'c':	 // 1 strings to match.
          if (Name.substr(3,3) != "ale")
            break;
          return MCK_fscale;	 // "fscale"
        case 'u':	 // 3 strings to match.
          if (Name.substr(3,2) != "br")
            break;
          switch (Name[5]) {
          default: break;
          case 'l':	 // 1 strings to match.
            return MCK_fsubrl;	 // "fsubrl"
          case 'p':	 // 1 strings to match.
            return MCK_fsubrp;	 // "fsubrp"
          case 's':	 // 1 strings to match.
            return MCK_fsubrs;	 // "fsubrs"
          }
          break;
        }
        break;
      case 'u':	 // 2 strings to match.
        if (Name.substr(2,3) != "com")
          break;
        switch (Name[5]) {
        default: break;
        case 'i':	 // 1 strings to match.
          return MCK_fucomi;	 // "fucomi"
        case 'p':	 // 1 strings to match.
          return MCK_fucomp;	 // "fucomp"
        }
        break;
      case 'x':	 // 1 strings to match.
        if (Name.substr(2,4) != "save")
          break;
        return MCK_fxsave;	 // "fxsave"
      }
      break;
    case 'h':	 // 4 strings to match.
      switch (Name[1]) {
      default: break;
      case 'a':	 // 2 strings to match.
        if (Name.substr(2,3) != "ddp")
          break;
        switch (Name[5]) {
        default: break;
        case 'd':	 // 1 strings to match.
          return MCK_haddpd;	 // "haddpd"
        case 's':	 // 1 strings to match.
          return MCK_haddps;	 // "haddps"
        }
        break;
      case 's':	 // 2 strings to match.
        if (Name.substr(2,3) != "ubp")
          break;
        switch (Name[5]) {
        default: break;
        case 'd':	 // 1 strings to match.
          return MCK_hsubpd;	 // "hsubpd"
        case 's':	 // 1 strings to match.
          return MCK_hsubps;	 // "hsubps"
        }
        break;
      }
      break;
    case 'i':	 // 2 strings to match.
      if (Name.substr(1,2) != "nv")
        break;
      switch (Name[3]) {
      default: break;
      case 'e':	 // 1 strings to match.
        if (Name.substr(4,2) != "pt")
          break;
        return MCK_invept;	 // "invept"
      case 'l':	 // 1 strings to match.
        if (Name.substr(4,2) != "pg")
          break;
        return MCK_invlpg;	 // "invlpg"
      }
      break;
    case 'l':	 // 5 strings to match.
      switch (Name[1]) {
      default: break;
      case 'c':	 // 3 strings to match.
        if (Name.substr(2,3) != "all")
          break;
        switch (Name[5]) {
        default: break;
        case 'l':	 // 1 strings to match.
          return MCK_lcalll;	 // "lcalll"
        case 'q':	 // 1 strings to match.
          return MCK_lcallq;	 // "lcallq"
        case 'w':	 // 1 strings to match.
          return MCK_lcallw;	 // "lcallw"
        }
        break;
      case 'f':	 // 1 strings to match.
        if (Name.substr(2,4) != "ence")
          break;
        return MCK_lfence;	 // "lfence"
      case 'o':	 // 1 strings to match.
        if (Name.substr(2,4) != "opne")
          break;
        return MCK_loopne;	 // "loopne"
      }
      break;
    case 'm':	 // 24 strings to match.
      switch (Name[1]) {
      default: break;
      case 'f':	 // 1 strings to match.
        if (Name.substr(2,4) != "ence")
          break;
        return MCK_mfence;	 // "mfence"
      case 'o':	 // 23 strings to match.
        if (Name[2] != 'v')
          break;
        switch (Name[3]) {
        default: break;
        case 'a':	 // 2 strings to match.
          if (Name[4] != 'p')
            break;
          switch (Name[5]) {
          default: break;
          case 'd':	 // 1 strings to match.
            return MCK_movapd;	 // "movapd"
          case 's':	 // 1 strings to match.
            return MCK_movaps;	 // "movaps"
          }
          break;
        case 'd':	 // 2 strings to match.
          if (Name[4] != 'q')
            break;
          switch (Name[5]) {
          default: break;
          case 'a':	 // 1 strings to match.
            return MCK_movdqa;	 // "movdqa"
          case 'u':	 // 1 strings to match.
            return MCK_movdqu;	 // "movdqu"
          }
          break;
        case 'h':	 // 2 strings to match.
          if (Name[4] != 'p')
            break;
          switch (Name[5]) {
          default: break;
          case 'd':	 // 1 strings to match.
            return MCK_movhpd;	 // "movhpd"
          case 's':	 // 1 strings to match.
            return MCK_movhps;	 // "movhps"
          }
          break;
        case 'l':	 // 2 strings to match.
          if (Name[4] != 'p')
            break;
          switch (Name[5]) {
          default: break;
          case 'd':	 // 1 strings to match.
            return MCK_movlpd;	 // "movlpd"
          case 's':	 // 1 strings to match.
            return MCK_movlps;	 // "movlps"
          }
          break;
        case 'n':	 // 2 strings to match.
          if (Name[4] != 't')
            break;
          switch (Name[5]) {
          default: break;
          case 'i':	 // 1 strings to match.
            return MCK_movnti;	 // "movnti"
          case 'q':	 // 1 strings to match.
            return MCK_movntq;	 // "movntq"
          }
          break;
        case 's':	 // 6 strings to match.
          switch (Name[4]) {
          default: break;
          case 'b':	 // 3 strings to match.
            switch (Name[5]) {
            default: break;
            case 'l':	 // 1 strings to match.
              return MCK_movsbl;	 // "movsbl"
            case 'q':	 // 1 strings to match.
              return MCK_movsbq;	 // "movsbq"
            case 'w':	 // 1 strings to match.
              return MCK_movsbw;	 // "movsbw"
            }
            break;
          case 'l':	 // 1 strings to match.
            if (Name[5] != 'q')
              break;
            return MCK_movslq;	 // "movslq"
          case 'w':	 // 2 strings to match.
            switch (Name[5]) {
            default: break;
            case 'l':	 // 1 strings to match.
              return MCK_movswl;	 // "movswl"
            case 'q':	 // 1 strings to match.
              return MCK_movswq;	 // "movswq"
            }
            break;
          }
          break;
        case 'u':	 // 2 strings to match.
          if (Name[4] != 'p')
            break;
          switch (Name[5]) {
          default: break;
          case 'd':	 // 1 strings to match.
            return MCK_movupd;	 // "movupd"
          case 's':	 // 1 strings to match.
            return MCK_movups;	 // "movups"
          }
          break;
        case 'z':	 // 5 strings to match.
          switch (Name[4]) {
          default: break;
          case 'b':	 // 3 strings to match.
            switch (Name[5]) {
            default: break;
            case 'l':	 // 1 strings to match.
              return MCK_movzbl;	 // "movzbl"
            case 'q':	 // 1 strings to match.
              return MCK_movzbq;	 // "movzbq"
            case 'w':	 // 1 strings to match.
              return MCK_movzbw;	 // "movzbw"
            }
            break;
          case 'w':	 // 2 strings to match.
            switch (Name[5]) {
            default: break;
            case 'l':	 // 1 strings to match.
              return MCK_movzwl;	 // "movzwl"
            case 'q':	 // 1 strings to match.
              return MCK_movzwq;	 // "movzwq"
            }
            break;
          }
          break;
        }
        break;
      }
      break;
    case 'p':	 // 44 strings to match.
      switch (Name[1]) {
      default: break;
      case 'a':	 // 2 strings to match.
        if (Name.substr(2,3) != "dds")
          break;
        switch (Name[5]) {
        default: break;
        case 'b':	 // 1 strings to match.
          return MCK_paddsb;	 // "paddsb"
        case 'w':	 // 1 strings to match.
          return MCK_paddsw;	 // "paddsw"
        }
        break;
      case 'e':	 // 4 strings to match.
        if (Name.substr(2,3) != "xtr")
          break;
        switch (Name[5]) {
        default: break;
        case 'b':	 // 1 strings to match.
          return MCK_pextrb;	 // "pextrb"
        case 'd':	 // 1 strings to match.
          return MCK_pextrd;	 // "pextrd"
        case 'q':	 // 1 strings to match.
          return MCK_pextrq;	 // "pextrq"
        case 'w':	 // 1 strings to match.
          return MCK_pextrw;	 // "pextrw"
        }
        break;
      case 'h':	 // 4 strings to match.
        switch (Name[2]) {
        default: break;
        case 'a':	 // 2 strings to match.
          if (Name.substr(3,2) != "dd")
            break;
          switch (Name[5]) {
          default: break;
          case 'd':	 // 1 strings to match.
            return MCK_phaddd;	 // "phaddd"
          case 'w':	 // 1 strings to match.
            return MCK_phaddw;	 // "phaddw"
          }
          break;
        case 's':	 // 2 strings to match.
          if (Name.substr(3,2) != "ub")
            break;
          switch (Name[5]) {
          default: break;
          case 'd':	 // 1 strings to match.
            return MCK_phsubd;	 // "phsubd"
          case 'w':	 // 1 strings to match.
            return MCK_phsubw;	 // "phsubw"
          }
          break;
        }
        break;
      case 'i':	 // 4 strings to match.
        if (Name.substr(2,3) != "nsr")
          break;
        switch (Name[5]) {
        default: break;
        case 'b':	 // 1 strings to match.
          return MCK_pinsrb;	 // "pinsrb"
        case 'd':	 // 1 strings to match.
          return MCK_pinsrd;	 // "pinsrd"
        case 'q':	 // 1 strings to match.
          return MCK_pinsrq;	 // "pinsrq"
        case 'w':	 // 1 strings to match.
          return MCK_pinsrw;	 // "pinsrw"
        }
        break;
      case 'm':	 // 16 strings to match.
        switch (Name[2]) {
        default: break;
        case 'a':	 // 6 strings to match.
          if (Name[3] != 'x')
            break;
          switch (Name[4]) {
          default: break;
          case 's':	 // 3 strings to match.
            switch (Name[5]) {
            default: break;
            case 'b':	 // 1 strings to match.
              return MCK_pmaxsb;	 // "pmaxsb"
            case 'd':	 // 1 strings to match.
              return MCK_pmaxsd;	 // "pmaxsd"
            case 'w':	 // 1 strings to match.
              return MCK_pmaxsw;	 // "pmaxsw"
            }
            break;
          case 'u':	 // 3 strings to match.
            switch (Name[5]) {
            default: break;
            case 'b':	 // 1 strings to match.
              return MCK_pmaxub;	 // "pmaxub"
            case 'd':	 // 1 strings to match.
              return MCK_pmaxud;	 // "pmaxud"
            case 'w':	 // 1 strings to match.
              return MCK_pmaxuw;	 // "pmaxuw"
            }
            break;
          }
          break;
        case 'i':	 // 6 strings to match.
          if (Name[3] != 'n')
            break;
          switch (Name[4]) {
          default: break;
          case 's':	 // 3 strings to match.
            switch (Name[5]) {
            default: break;
            case 'b':	 // 1 strings to match.
              return MCK_pminsb;	 // "pminsb"
            case 'd':	 // 1 strings to match.
              return MCK_pminsd;	 // "pminsd"
            case 'w':	 // 1 strings to match.
              return MCK_pminsw;	 // "pminsw"
            }
            break;
          case 'u':	 // 3 strings to match.
            switch (Name[5]) {
            default: break;
            case 'b':	 // 1 strings to match.
              return MCK_pminub;	 // "pminub"
            case 'd':	 // 1 strings to match.
              return MCK_pminud;	 // "pminud"
            case 'w':	 // 1 strings to match.
              return MCK_pminuw;	 // "pminuw"
            }
            break;
          }
          break;
        case 'u':	 // 4 strings to match.
          if (Name[3] != 'l')
            break;
          switch (Name[4]) {
          default: break;
          case 'd':	 // 1 strings to match.
            if (Name[5] != 'q')
              break;
            return MCK_pmuldq;	 // "pmuldq"
          case 'h':	 // 1 strings to match.
            if (Name[5] != 'w')
              break;
            return MCK_pmulhw;	 // "pmulhw"
          case 'l':	 // 2 strings to match.
            switch (Name[5]) {
            default: break;
            case 'd':	 // 1 strings to match.
              return MCK_pmulld;	 // "pmulld"
            case 'w':	 // 1 strings to match.
              return MCK_pmullw;	 // "pmullw"
            }
            break;
          }
          break;
        }
        break;
      case 's':	 // 11 strings to match.
        switch (Name[2]) {
        default: break;
        case 'a':	 // 1 strings to match.
          if (Name.substr(3,3) != "dbw")
            break;
          return MCK_psadbw;	 // "psadbw"
        case 'h':	 // 3 strings to match.
          if (Name.substr(3,2) != "uf")
            break;
          switch (Name[5]) {
          default: break;
          case 'b':	 // 1 strings to match.
            return MCK_pshufb;	 // "pshufb"
          case 'd':	 // 1 strings to match.
            return MCK_pshufd;	 // "pshufd"
          case 'w':	 // 1 strings to match.
            return MCK_pshufw;	 // "pshufw"
          }
          break;
        case 'i':	 // 3 strings to match.
          if (Name.substr(3,2) != "gn")
            break;
          switch (Name[5]) {
          default: break;
          case 'b':	 // 1 strings to match.
            return MCK_psignb;	 // "psignb"
          case 'd':	 // 1 strings to match.
            return MCK_psignd;	 // "psignd"
          case 'w':	 // 1 strings to match.
            return MCK_psignw;	 // "psignw"
          }
          break;
        case 'l':	 // 1 strings to match.
          if (Name.substr(3,3) != "ldq")
            break;
          return MCK_pslldq;	 // "pslldq"
        case 'r':	 // 1 strings to match.
          if (Name.substr(3,3) != "ldq")
            break;
          return MCK_psrldq;	 // "psrldq"
        case 'u':	 // 2 strings to match.
          if (Name.substr(3,2) != "bs")
            break;
          switch (Name[5]) {
          default: break;
          case 'b':	 // 1 strings to match.
            return MCK_psubsb;	 // "psubsb"
          case 'w':	 // 1 strings to match.
            return MCK_psubsw;	 // "psubsw"
          }
          break;
        }
        break;
      case 'u':	 // 3 strings to match.
        if (Name.substr(2,3) != "shf")
          break;
        switch (Name[5]) {
        default: break;
        case 'l':	 // 1 strings to match.
          return MCK_pushfl;	 // "pushfl"
        case 'q':	 // 1 strings to match.
          return MCK_pushfq;	 // "pushfq"
        case 'w':	 // 1 strings to match.
          return MCK_pushfw;	 // "pushfw"
        }
        break;
      }
      break;
    case 'r':	 // 1 strings to match.
      if (Name.substr(1,5) != "dtscp")
        break;
      return MCK_rdtscp;	 // "rdtscp"
    case 's':	 // 9 strings to match.
      switch (Name[1]) {
      default: break;
      case 'f':	 // 1 strings to match.
        if (Name.substr(2,4) != "ence")
          break;
        return MCK_sfence;	 // "sfence"
      case 'h':	 // 2 strings to match.
        if (Name.substr(2,3) != "ufp")
          break;
        switch (Name[5]) {
        default: break;
        case 'd':	 // 1 strings to match.
          return MCK_shufpd;	 // "shufpd"
        case 's':	 // 1 strings to match.
          return MCK_shufps;	 // "shufps"
        }
        break;
      case 'q':	 // 4 strings to match.
        if (Name.substr(2,2) != "rt")
          break;
        switch (Name[4]) {
        default: break;
        case 'p':	 // 2 strings to match.
          switch (Name[5]) {
          default: break;
          case 'd':	 // 1 strings to match.
            return MCK_sqrtpd;	 // "sqrtpd"
          case 's':	 // 1 strings to match.
            return MCK_sqrtps;	 // "sqrtps"
          }
          break;
        case 's':	 // 2 strings to match.
          switch (Name[5]) {
          default: break;
          case 'd':	 // 1 strings to match.
            return MCK_sqrtsd;	 // "sqrtsd"
          case 's':	 // 1 strings to match.
            return MCK_sqrtss;	 // "sqrtss"
          }
          break;
        }
        break;
      case 'w':	 // 1 strings to match.
        if (Name.substr(2,4) != "apgs")
          break;
        return MCK_swapgs;	 // "swapgs"
      case 'y':	 // 1 strings to match.
        if (Name.substr(2,4) != "sret")
          break;
        return MCK_sysret;	 // "sysret"
      }
      break;
    case 'v':	 // 2 strings to match.
      if (Name[1] != 'm')
        break;
      switch (Name[2]) {
      default: break;
      case 'c':	 // 1 strings to match.
        if (Name.substr(3,3) != "all")
          break;
        return MCK_vmcall;	 // "vmcall"
      case 'x':	 // 1 strings to match.
        if (Name.substr(3,3) != "off")
          break;
        return MCK_vmxoff;	 // "vmxoff"
      }
      break;
    case 'w':	 // 1 strings to match.
      if (Name.substr(1,5) != "binvd")
        break;
      return MCK_wbinvd;	 // "wbinvd"
    }
    break;
  case 7:	 // 100 strings to match.
    switch (Name[0]) {
    default: break;
    case 'b':	 // 2 strings to match.
      if (Name.substr(1,5) != "lendp")
        break;
      switch (Name[6]) {
      default: break;
      case 'd':	 // 1 strings to match.
        return MCK_blendpd;	 // "blendpd"
      case 's':	 // 1 strings to match.
        return MCK_blendps;	 // "blendps"
      }
      break;
    case 'c':	 // 25 strings to match.
      switch (Name[1]) {
      default: break;
      case 'l':	 // 1 strings to match.
        if (Name.substr(2,5) != "flush")
          break;
        return MCK_clflush;	 // "clflush"
      case 'm':	 // 24 strings to match.
        if (Name.substr(2,2) != "ov")
          break;
        switch (Name[4]) {
        default: break;
        case 'a':	 // 3 strings to match.
          if (Name[5] != 'e')
            break;
          switch (Name[6]) {
          default: break;
          case 'l':	 // 1 strings to match.
            return MCK_cmovael;	 // "cmovael"
          case 'q':	 // 1 strings to match.
            return MCK_cmovaeq;	 // "cmovaeq"
          case 'w':	 // 1 strings to match.
            return MCK_cmovaew;	 // "cmovaew"
          }
          break;
        case 'b':	 // 3 strings to match.
          if (Name[5] != 'e')
            break;
          switch (Name[6]) {
          default: break;
          case 'l':	 // 1 strings to match.
            return MCK_cmovbel;	 // "cmovbel"
          case 'q':	 // 1 strings to match.
            return MCK_cmovbeq;	 // "cmovbeq"
          case 'w':	 // 1 strings to match.
            return MCK_cmovbew;	 // "cmovbew"
          }
          break;
        case 'g':	 // 3 strings to match.
          if (Name[5] != 'e')
            break;
          switch (Name[6]) {
          default: break;
          case 'l':	 // 1 strings to match.
            return MCK_cmovgel;	 // "cmovgel"
          case 'q':	 // 1 strings to match.
            return MCK_cmovgeq;	 // "cmovgeq"
          case 'w':	 // 1 strings to match.
            return MCK_cmovgew;	 // "cmovgew"
          }
          break;
        case 'l':	 // 3 strings to match.
          if (Name[5] != 'e')
            break;
          switch (Name[6]) {
          default: break;
          case 'l':	 // 1 strings to match.
            return MCK_cmovlel;	 // "cmovlel"
          case 'q':	 // 1 strings to match.
            return MCK_cmovleq;	 // "cmovleq"
          case 'w':	 // 1 strings to match.
            return MCK_cmovlew;	 // "cmovlew"
          }
          break;
        case 'n':	 // 12 strings to match.
          switch (Name[5]) {
          default: break;
          case 'e':	 // 3 strings to match.
            switch (Name[6]) {
            default: break;
            case 'l':	 // 1 strings to match.
              return MCK_cmovnel;	 // "cmovnel"
            case 'q':	 // 1 strings to match.
              return MCK_cmovneq;	 // "cmovneq"
            case 'w':	 // 1 strings to match.
              return MCK_cmovnew;	 // "cmovnew"
            }
            break;
          case 'o':	 // 3 strings to match.
            switch (Name[6]) {
            default: break;
            case 'l':	 // 1 strings to match.
              return MCK_cmovnol;	 // "cmovnol"
            case 'q':	 // 1 strings to match.
              return MCK_cmovnoq;	 // "cmovnoq"
            case 'w':	 // 1 strings to match.
              return MCK_cmovnow;	 // "cmovnow"
            }
            break;
          case 'p':	 // 3 strings to match.
            switch (Name[6]) {
            default: break;
            case 'l':	 // 1 strings to match.
              return MCK_cmovnpl;	 // "cmovnpl"
            case 'q':	 // 1 strings to match.
              return MCK_cmovnpq;	 // "cmovnpq"
            case 'w':	 // 1 strings to match.
              return MCK_cmovnpw;	 // "cmovnpw"
            }
            break;
          case 's':	 // 3 strings to match.
            switch (Name[6]) {
            default: break;
            case 'l':	 // 1 strings to match.
              return MCK_cmovnsl;	 // "cmovnsl"
            case 'q':	 // 1 strings to match.
              return MCK_cmovnsq;	 // "cmovnsq"
            case 'w':	 // 1 strings to match.
              return MCK_cmovnsw;	 // "cmovnsw"
            }
            break;
          }
          break;
        }
        break;
      }
      break;
    case 'f':	 // 24 strings to match.
      switch (Name[1]) {
      default: break;
      case 'c':	 // 5 strings to match.
        switch (Name[2]) {
        default: break;
        case 'm':	 // 4 strings to match.
          if (Name.substr(3,2) != "ov")
            break;
          switch (Name[5]) {
          default: break;
          case 'b':	 // 1 strings to match.
            if (Name[6] != 'e')
              break;
            return MCK_fcmovbe;	 // "fcmovbe"
          case 'n':	 // 3 strings to match.
            switch (Name[6]) {
            default: break;
            case 'b':	 // 1 strings to match.
              return MCK_fcmovnb;	 // "fcmovnb"
            case 'e':	 // 1 strings to match.
              return MCK_fcmovne;	 // "fcmovne"
            case 'u':	 // 1 strings to match.
              return MCK_fcmovnu;	 // "fcmovnu"
            }
            break;
          }
          break;
        case 'o':	 // 1 strings to match.
          if (Name.substr(3,4) != "mpll")
            break;
          return MCK_fcompll;	 // "fcompll"
        }
        break;
      case 'd':	 // 1 strings to match.
        if (Name.substr(2,5) != "ecstp")
          break;
        return MCK_fdecstp;	 // "fdecstp"
      case 'i':	 // 10 strings to match.
        switch (Name[2]) {
        default: break;
        case 'c':	 // 2 strings to match.
          if (Name.substr(3,3) != "omp")
            break;
          switch (Name[6]) {
          default: break;
          case 'l':	 // 1 strings to match.
            return MCK_ficompl;	 // "ficompl"
          case 'w':	 // 1 strings to match.
            return MCK_ficompw;	 // "ficompw"
          }
          break;
        case 'd':	 // 2 strings to match.
          if (Name.substr(3,3) != "ivr")
            break;
          switch (Name[6]) {
          default: break;
          case 'l':	 // 1 strings to match.
            return MCK_fidivrl;	 // "fidivrl"
          case 's':	 // 1 strings to match.
            return MCK_fidivrs;	 // "fidivrs"
          }
          break;
        case 'n':	 // 1 strings to match.
          if (Name.substr(3,4) != "cstp")
            break;
          return MCK_fincstp;	 // "fincstp"
        case 's':	 // 5 strings to match.
          switch (Name[3]) {
          default: break;
          case 't':	 // 3 strings to match.
            switch (Name[4]) {
            default: break;
            case 'p':	 // 1 strings to match.
              if (Name.substr(5,2) != "ll")
                break;
              return MCK_fistpll;	 // "fistpll"
            case 't':	 // 2 strings to match.
              if (Name[5] != 'p')
                break;
              switch (Name[6]) {
              default: break;
              case 'l':	 // 1 strings to match.
                return MCK_fisttpl;	 // "fisttpl"
              case 's':	 // 1 strings to match.
                return MCK_fisttps;	 // "fisttps"
              }
              break;
            }
            break;
          case 'u':	 // 2 strings to match.
            if (Name.substr(4,2) != "br")
              break;
            switch (Name[6]) {
            default: break;
            case 'l':	 // 1 strings to match.
              return MCK_fisubrl;	 // "fisubrl"
            case 's':	 // 1 strings to match.
              return MCK_fisubrs;	 // "fisubrs"
            }
            break;
          }
          break;
        }
        break;
      case 'n':	 // 1 strings to match.
        if (Name.substr(2,5) != "stenv")
          break;
        return MCK_fnstenv;	 // "fnstenv"
      case 'r':	 // 1 strings to match.
        if (Name.substr(2,5) != "ndint")
          break;
        return MCK_frndint;	 // "frndint"
      case 's':	 // 1 strings to match.
        if (Name.substr(2,5) != "incos")
          break;
        return MCK_fsincos;	 // "fsincos"
      case 'u':	 // 2 strings to match.
        if (Name.substr(2,3) != "com")
          break;
        switch (Name[5]) {
        default: break;
        case 'i':	 // 1 strings to match.
          if (Name[6] != 'p')
            break;
          return MCK_fucomip;	 // "fucomip"
        case 'p':	 // 1 strings to match.
          if (Name[6] != 'p')
            break;
          return MCK_fucompp;	 // "fucompp"
        }
        break;
      case 'x':	 // 2 strings to match.
        switch (Name[2]) {
        default: break;
        case 'r':	 // 1 strings to match.
          if (Name.substr(3,4) != "stor")
            break;
          return MCK_fxrstor;	 // "fxrstor"
        case 't':	 // 1 strings to match.
          if (Name.substr(3,4) != "ract")
            break;
          return MCK_fxtract;	 // "fxtract"
        }
        break;
      case 'y':	 // 1 strings to match.
        if (Name.substr(2,5) != "l2xp1")
          break;
        return MCK_fyl2xp1;	 // "fyl2xp1"
      }
      break;
    case 'i':	 // 1 strings to match.
      if (Name.substr(1,6) != "nvvpid")
        break;
      return MCK_invvpid;	 // "invvpid"
    case 'l':	 // 1 strings to match.
      if (Name.substr(1,6) != "dmxcsr")
        break;
      return MCK_ldmxcsr;	 // "ldmxcsr"
    case 'm':	 // 11 strings to match.
      switch (Name[1]) {
      default: break;
      case 'o':	 // 10 strings to match.
        switch (Name[2]) {
        default: break;
        case 'n':	 // 1 strings to match.
          if (Name.substr(3,4) != "itor")
            break;
          return MCK_monitor;	 // "monitor"
        case 'v':	 // 9 strings to match.
          switch (Name[3]) {
          default: break;
          case 'a':	 // 1 strings to match.
            if (Name.substr(4,3) != "bsq")
              break;
            return MCK_movabsq;	 // "movabsq"
          case 'd':	 // 2 strings to match.
            switch (Name[4]) {
            default: break;
            case 'd':	 // 1 strings to match.
              if (Name.substr(5,2) != "up")
                break;
              return MCK_movddup;	 // "movddup"
            case 'q':	 // 1 strings to match.
              if (Name.substr(5,2) != "2q")
                break;
              return MCK_movdq2q;	 // "movdq2q"
            }
            break;
          case 'h':	 // 1 strings to match.
            if (Name.substr(4,3) != "lps")
              break;
            return MCK_movhlps;	 // "movhlps"
          case 'l':	 // 1 strings to match.
            if (Name.substr(4,3) != "hps")
              break;
            return MCK_movlhps;	 // "movlhps"
          case 'n':	 // 3 strings to match.
            if (Name[4] != 't')
              break;
            switch (Name[5]) {
            default: break;
            case 'd':	 // 1 strings to match.
              if (Name[6] != 'q')
                break;
              return MCK_movntdq;	 // "movntdq"
            case 'p':	 // 2 strings to match.
              switch (Name[6]) {
              default: break;
              case 'd':	 // 1 strings to match.
                return MCK_movntpd;	 // "movntpd"
              case 's':	 // 1 strings to match.
                return MCK_movntps;	 // "movntps"
              }
              break;
            }
            break;
          case 'q':	 // 1 strings to match.
            if (Name.substr(4,3) != "2dq")
              break;
            return MCK_movq2dq;	 // "movq2dq"
          }
          break;
        }
        break;
      case 'p':	 // 1 strings to match.
        if (Name.substr(2,5) != "sadbw")
          break;
        return MCK_mpsadbw;	 // "mpsadbw"
      }
      break;
    case 'p':	 // 24 strings to match.
      switch (Name[1]) {
      default: break;
      case 'a':	 // 3 strings to match.
        switch (Name[2]) {
        default: break;
        case 'd':	 // 2 strings to match.
          if (Name.substr(3,3) != "dus")
            break;
          switch (Name[6]) {
          default: break;
          case 'b':	 // 1 strings to match.
            return MCK_paddusb;	 // "paddusb"
          case 'w':	 // 1 strings to match.
            return MCK_paddusw;	 // "paddusw"
          }
          break;
        case 'l':	 // 1 strings to match.
          if (Name.substr(3,4) != "ignr")
            break;
          return MCK_palignr;	 // "palignr"
        }
        break;
      case 'b':	 // 1 strings to match.
        if (Name.substr(2,5) != "lendw")
          break;
        return MCK_pblendw;	 // "pblendw"
      case 'c':	 // 8 strings to match.
        if (Name.substr(2,2) != "mp")
          break;
        switch (Name[4]) {
        default: break;
        case 'e':	 // 4 strings to match.
          if (Name[5] != 'q')
            break;
          switch (Name[6]) {
          default: break;
          case 'b':	 // 1 strings to match.
            return MCK_pcmpeqb;	 // "pcmpeqb"
          case 'd':	 // 1 strings to match.
            return MCK_pcmpeqd;	 // "pcmpeqd"
          case 'q':	 // 1 strings to match.
            return MCK_pcmpeqq;	 // "pcmpeqq"
          case 'w':	 // 1 strings to match.
            return MCK_pcmpeqw;	 // "pcmpeqw"
          }
          break;
        case 'g':	 // 4 strings to match.
          if (Name[5] != 't')
            break;
          switch (Name[6]) {
          default: break;
          case 'b':	 // 1 strings to match.
            return MCK_pcmpgtb;	 // "pcmpgtb"
          case 'd':	 // 1 strings to match.
            return MCK_pcmpgtd;	 // "pcmpgtd"
          case 'q':	 // 1 strings to match.
            return MCK_pcmpgtq;	 // "pcmpgtq"
          case 'w':	 // 1 strings to match.
            return MCK_pcmpgtw;	 // "pcmpgtw"
          }
          break;
        }
        break;
      case 'h':	 // 2 strings to match.
        switch (Name[2]) {
        default: break;
        case 'a':	 // 1 strings to match.
          if (Name.substr(3,4) != "ddsw")
            break;
          return MCK_phaddsw;	 // "phaddsw"
        case 's':	 // 1 strings to match.
          if (Name.substr(3,4) != "ubsw")
            break;
          return MCK_phsubsw;	 // "phsubsw"
        }
        break;
      case 'm':	 // 3 strings to match.
        switch (Name[2]) {
        default: break;
        case 'a':	 // 1 strings to match.
          if (Name.substr(3,4) != "ddwd")
            break;
          return MCK_pmaddwd;	 // "pmaddwd"
        case 'u':	 // 2 strings to match.
          if (Name[3] != 'l')
            break;
          switch (Name[4]) {
          default: break;
          case 'h':	 // 1 strings to match.
            if (Name.substr(5,2) != "uw")
              break;
            return MCK_pmulhuw;	 // "pmulhuw"
          case 'u':	 // 1 strings to match.
            if (Name.substr(5,2) != "dq")
              break;
            return MCK_pmuludq;	 // "pmuludq"
          }
          break;
        }
        break;
      case 'o':	 // 3 strings to match.
        if (Name.substr(2,4) != "pcnt")
          break;
        switch (Name[6]) {
        default: break;
        case 'l':	 // 1 strings to match.
          return MCK_popcntl;	 // "popcntl"
        case 'q':	 // 1 strings to match.
          return MCK_popcntq;	 // "popcntq"
        case 'w':	 // 1 strings to match.
          return MCK_popcntw;	 // "popcntw"
        }
        break;
      case 's':	 // 4 strings to match.
        switch (Name[2]) {
        default: break;
        case 'h':	 // 2 strings to match.
          if (Name.substr(3,2) != "uf")
            break;
          switch (Name[5]) {
          default: break;
          case 'h':	 // 1 strings to match.
            if (Name[6] != 'w')
              break;
            return MCK_pshufhw;	 // "pshufhw"
          case 'l':	 // 1 strings to match.
            if (Name[6] != 'w')
              break;
            return MCK_pshuflw;	 // "pshuflw"
          }
          break;
        case 'u':	 // 2 strings to match.
          if (Name.substr(3,3) != "bus")
            break;
          switch (Name[6]) {
          default: break;
          case 'b':	 // 1 strings to match.
            return MCK_psubusb;	 // "psubusb"
          case 'w':	 // 1 strings to match.
            return MCK_psubusw;	 // "psubusw"
          }
          break;
        }
        break;
      }
      break;
    case 'r':	 // 2 strings to match.
      if (Name.substr(1,4) != "sqrt")
        break;
      switch (Name[5]) {
      default: break;
      case 'p':	 // 1 strings to match.
        if (Name[6] != 's')
          break;
        return MCK_rsqrtps;	 // "rsqrtps"
      case 's':	 // 1 strings to match.
        if (Name[6] != 's')
          break;
        return MCK_rsqrtss;	 // "rsqrtss"
      }
      break;
    case 's':	 // 3 strings to match.
      switch (Name[1]) {
      default: break;
      case 't':	 // 1 strings to match.
        if (Name.substr(2,5) != "mxcsr")
          break;
        return MCK_stmxcsr;	 // "stmxcsr"
      case 'y':	 // 2 strings to match.
        if (Name[2] != 's')
          break;
        switch (Name[3]) {
        default: break;
        case 'c':	 // 1 strings to match.
          if (Name.substr(4,3) != "all")
            break;
          return MCK_syscall;	 // "syscall"
        case 'e':	 // 1 strings to match.
          if (Name.substr(4,3) != "xit")
            break;
          return MCK_sysexit;	 // "sysexit"
        }
        break;
      }
      break;
    case 'u':	 // 2 strings to match.
      if (Name.substr(1,5) != "comis")
        break;
      switch (Name[6]) {
      default: break;
      case 'd':	 // 1 strings to match.
        return MCK_ucomisd;	 // "ucomisd"
      case 's':	 // 1 strings to match.
        return MCK_ucomiss;	 // "ucomiss"
      }
      break;
    case 'v':	 // 5 strings to match.
      if (Name[1] != 'm')
        break;
      switch (Name[2]) {
      default: break;
      case 'c':	 // 1 strings to match.
        if (Name.substr(3,4) != "lear")
          break;
        return MCK_vmclear;	 // "vmclear"
      case 'p':	 // 2 strings to match.
        if (Name.substr(3,2) != "tr")
          break;
        switch (Name[5]) {
        default: break;
        case 'l':	 // 1 strings to match.
          if (Name[6] != 'd')
            break;
          return MCK_vmptrld;	 // "vmptrld"
        case 's':	 // 1 strings to match.
          if (Name[6] != 't')
            break;
          return MCK_vmptrst;	 // "vmptrst"
        }
        break;
      case 'r':	 // 2 strings to match.
        if (Name.substr(3,3) != "ead")
          break;
        switch (Name[6]) {
        default: break;
        case 'l':	 // 1 strings to match.
          return MCK_vmreadl;	 // "vmreadl"
        case 'q':	 // 1 strings to match.
          return MCK_vmreadq;	 // "vmreadq"
        }
        break;
      }
      break;
    }
    break;
  case 8:	 // 59 strings to match.
    switch (Name[0]) {
    default: break;
    case 'a':	 // 2 strings to match.
      if (Name.substr(1,6) != "ddsubp")
        break;
      switch (Name[7]) {
      default: break;
      case 'd':	 // 1 strings to match.
        return MCK_addsubpd;	 // "addsubpd"
      case 's':	 // 1 strings to match.
        return MCK_addsubps;	 // "addsubps"
      }
      break;
    case 'b':	 // 2 strings to match.
      if (Name.substr(1,6) != "lendvp")
        break;
      switch (Name[7]) {
      default: break;
      case 'd':	 // 1 strings to match.
        return MCK_blendvpd;	 // "blendvpd"
      case 's':	 // 1 strings to match.
        return MCK_blendvps;	 // "blendvps"
      }
      break;
    case 'c':	 // 18 strings to match.
      switch (Name[1]) {
      default: break;
      case 'm':	 // 4 strings to match.
        if (Name.substr(2,5) != "pxchg")
          break;
        switch (Name[7]) {
        default: break;
        case 'b':	 // 1 strings to match.
          return MCK_cmpxchgb;	 // "cmpxchgb"
        case 'l':	 // 1 strings to match.
          return MCK_cmpxchgl;	 // "cmpxchgl"
        case 'q':	 // 1 strings to match.
          return MCK_cmpxchgq;	 // "cmpxchgq"
        case 'w':	 // 1 strings to match.
          return MCK_cmpxchgw;	 // "cmpxchgw"
        }
        break;
      case 'v':	 // 14 strings to match.
        if (Name[2] != 't')
          break;
        switch (Name[3]) {
        default: break;
        case 'd':	 // 2 strings to match.
          if (Name.substr(4,3) != "q2p")
            break;
          switch (Name[7]) {
          default: break;
          case 'd':	 // 1 strings to match.
            return MCK_cvtdq2pd;	 // "cvtdq2pd"
          case 's':	 // 1 strings to match.
            return MCK_cvtdq2ps;	 // "cvtdq2ps"
          }
          break;
        case 'p':	 // 8 strings to match.
          switch (Name[4]) {
          default: break;
          case 'd':	 // 3 strings to match.
            if (Name[5] != '2')
              break;
            switch (Name[6]) {
            default: break;
            case 'd':	 // 1 strings to match.
              if (Name[7] != 'q')
                break;
              return MCK_cvtpd2dq;	 // "cvtpd2dq"
            case 'p':	 // 2 strings to match.
              switch (Name[7]) {
              default: break;
              case 'i':	 // 1 strings to match.
                return MCK_cvtpd2pi;	 // "cvtpd2pi"
              case 's':	 // 1 strings to match.
                return MCK_cvtpd2ps;	 // "cvtpd2ps"
              }
              break;
            }
            break;
          case 'i':	 // 2 strings to match.
            if (Name.substr(5,2) != "2p")
              break;
            switch (Name[7]) {
            default: break;
            case 'd':	 // 1 strings to match.
              return MCK_cvtpi2pd;	 // "cvtpi2pd"
            case 's':	 // 1 strings to match.
              return MCK_cvtpi2ps;	 // "cvtpi2ps"
            }
            break;
          case 's':	 // 3 strings to match.
            if (Name[5] != '2')
              break;
            switch (Name[6]) {
            default: break;
            case 'd':	 // 1 strings to match.
              if (Name[7] != 'q')
                break;
              return MCK_cvtps2dq;	 // "cvtps2dq"
            case 'p':	 // 2 strings to match.
              switch (Name[7]) {
              default: break;
              case 'd':	 // 1 strings to match.
                return MCK_cvtps2pd;	 // "cvtps2pd"
              case 'i':	 // 1 strings to match.
                return MCK_cvtps2pi;	 // "cvtps2pi"
              }
              break;
            }
            break;
          }
          break;
        case 's':	 // 4 strings to match.
          switch (Name[4]) {
          default: break;
          case 'd':	 // 1 strings to match.
            if (Name.substr(5,3) != "2ss")
              break;
            return MCK_cvtsd2ss;	 // "cvtsd2ss"
          case 'i':	 // 2 strings to match.
            if (Name.substr(5,2) != "2s")
              break;
            switch (Name[7]) {
            default: break;
            case 'd':	 // 1 strings to match.
              return MCK_cvtsi2sd;	 // "cvtsi2sd"
            case 's':	 // 1 strings to match.
              return MCK_cvtsi2ss;	 // "cvtsi2ss"
            }
            break;
          case 's':	 // 1 strings to match.
            if (Name.substr(5,3) != "2sd")
              break;
            return MCK_cvtss2sd;	 // "cvtss2sd"
          }
          break;
        }
        break;
      }
      break;
    case 'f':	 // 2 strings to match.
      switch (Name[1]) {
      default: break;
      case 'c':	 // 1 strings to match.
        if (Name.substr(2,6) != "movnbe")
          break;
        return MCK_fcmovnbe;	 // "fcmovnbe"
      case 'i':	 // 1 strings to match.
        if (Name.substr(2,6) != "sttpll")
          break;
        return MCK_fisttpll;	 // "fisttpll"
      }
      break;
    case 'i':	 // 1 strings to match.
      if (Name.substr(1,7) != "nsertps")
        break;
      return MCK_insertps;	 // "insertps"
    case 'm':	 // 6 strings to match.
      switch (Name[1]) {
      default: break;
      case 'a':	 // 1 strings to match.
        if (Name.substr(2,6) != "skmovq")
          break;
        return MCK_maskmovq;	 // "maskmovq"
      case 'o':	 // 5 strings to match.
        if (Name[2] != 'v')
          break;
        switch (Name[3]) {
        default: break;
        case 'm':	 // 2 strings to match.
          if (Name.substr(4,3) != "skp")
            break;
          switch (Name[7]) {
          default: break;
          case 'd':	 // 1 strings to match.
            return MCK_movmskpd;	 // "movmskpd"
          case 's':	 // 1 strings to match.
            return MCK_movmskps;	 // "movmskps"
          }
          break;
        case 'n':	 // 1 strings to match.
          if (Name.substr(4,4) != "tdqa")
            break;
          return MCK_movntdqa;	 // "movntdqa"
        case 's':	 // 2 strings to match.
          switch (Name[4]) {
          default: break;
          case 'h':	 // 1 strings to match.
            if (Name.substr(5,3) != "dup")
              break;
            return MCK_movshdup;	 // "movshdup"
          case 'l':	 // 1 strings to match.
            if (Name.substr(5,3) != "dup")
              break;
            return MCK_movsldup;	 // "movsldup"
          }
          break;
        }
        break;
      }
      break;
    case 'p':	 // 19 strings to match.
      switch (Name[1]) {
      default: break;
      case 'a':	 // 4 strings to match.
        if (Name.substr(2,2) != "ck")
          break;
        switch (Name[4]) {
        default: break;
        case 's':	 // 2 strings to match.
          if (Name[5] != 's')
            break;
          switch (Name[6]) {
          default: break;
          case 'd':	 // 1 strings to match.
            if (Name[7] != 'w')
              break;
            return MCK_packssdw;	 // "packssdw"
          case 'w':	 // 1 strings to match.
            if (Name[7] != 'b')
              break;
            return MCK_packsswb;	 // "packsswb"
          }
          break;
        case 'u':	 // 2 strings to match.
          if (Name[5] != 's')
            break;
          switch (Name[6]) {
          default: break;
          case 'd':	 // 1 strings to match.
            if (Name[7] != 'w')
              break;
            return MCK_packusdw;	 // "packusdw"
          case 'w':	 // 1 strings to match.
            if (Name[7] != 'b')
              break;
            return MCK_packuswb;	 // "packuswb"
          }
          break;
        }
        break;
      case 'b':	 // 1 strings to match.
        if (Name.substr(2,6) != "lendvb")
          break;
        return MCK_pblendvb;	 // "pblendvb"
      case 'm':	 // 14 strings to match.
        switch (Name[2]) {
        default: break;
        case 'o':	 // 13 strings to match.
          if (Name[3] != 'v')
            break;
          switch (Name[4]) {
          default: break;
          case 'm':	 // 1 strings to match.
            if (Name.substr(5,3) != "skb")
              break;
            return MCK_pmovmskb;	 // "pmovmskb"
          case 's':	 // 6 strings to match.
            if (Name[5] != 'x')
              break;
            switch (Name[6]) {
            default: break;
            case 'b':	 // 3 strings to match.
              switch (Name[7]) {
              default: break;
              case 'd':	 // 1 strings to match.
                return MCK_pmovsxbd;	 // "pmovsxbd"
              case 'q':	 // 1 strings to match.
                return MCK_pmovsxbq;	 // "pmovsxbq"
              case 'w':	 // 1 strings to match.
                return MCK_pmovsxbw;	 // "pmovsxbw"
              }
              break;
            case 'd':	 // 1 strings to match.
              if (Name[7] != 'q')
                break;
              return MCK_pmovsxdq;	 // "pmovsxdq"
            case 'w':	 // 2 strings to match.
              switch (Name[7]) {
              default: break;
              case 'd':	 // 1 strings to match.
                return MCK_pmovsxwd;	 // "pmovsxwd"
              case 'q':	 // 1 strings to match.
                return MCK_pmovsxwq;	 // "pmovsxwq"
              }
              break;
            }
            break;
          case 'z':	 // 6 strings to match.
            if (Name[5] != 'x')
              break;
            switch (Name[6]) {
            default: break;
            case 'b':	 // 3 strings to match.
              switch (Name[7]) {
              default: break;
              case 'd':	 // 1 strings to match.
                return MCK_pmovzxbd;	 // "pmovzxbd"
              case 'q':	 // 1 strings to match.
                return MCK_pmovzxbq;	 // "pmovzxbq"
              case 'w':	 // 1 strings to match.
                return MCK_pmovzxbw;	 // "pmovzxbw"
              }
              break;
            case 'd':	 // 1 strings to match.
              if (Name[7] != 'q')
                break;
              return MCK_pmovzxdq;	 // "pmovzxdq"
            case 'w':	 // 2 strings to match.
              switch (Name[7]) {
              default: break;
              case 'd':	 // 1 strings to match.
                return MCK_pmovzxwd;	 // "pmovzxwd"
              case 'q':	 // 1 strings to match.
                return MCK_pmovzxwq;	 // "pmovzxwq"
              }
              break;
            }
            break;
          }
          break;
        case 'u':	 // 1 strings to match.
          if (Name.substr(3,5) != "lhrsw")
            break;
          return MCK_pmulhrsw;	 // "pmulhrsw"
        }
        break;
      }
      break;
    case 's':	 // 1 strings to match.
      if (Name.substr(1,7) != "ysenter")
        break;
      return MCK_sysenter;	 // "sysenter"
    case 'u':	 // 4 strings to match.
      if (Name.substr(1,4) != "npck")
        break;
      switch (Name[5]) {
      default: break;
      case 'h':	 // 2 strings to match.
        if (Name[6] != 'p')
          break;
        switch (Name[7]) {
        default: break;
        case 'd':	 // 1 strings to match.
          return MCK_unpckhpd;	 // "unpckhpd"
        case 's':	 // 1 strings to match.
          return MCK_unpckhps;	 // "unpckhps"
        }
        break;
      case 'l':	 // 2 strings to match.
        if (Name[6] != 'p')
          break;
        switch (Name[7]) {
        default: break;
        case 'd':	 // 1 strings to match.
          return MCK_unpcklpd;	 // "unpcklpd"
        case 's':	 // 1 strings to match.
          return MCK_unpcklps;	 // "unpcklps"
        }
        break;
      }
      break;
    case 'v':	 // 4 strings to match.
      if (Name[1] != 'm')
        break;
      switch (Name[2]) {
      default: break;
      case 'l':	 // 1 strings to match.
        if (Name.substr(3,5) != "aunch")
          break;
        return MCK_vmlaunch;	 // "vmlaunch"
      case 'r':	 // 1 strings to match.
        if (Name.substr(3,5) != "esume")
          break;
        return MCK_vmresume;	 // "vmresume"
      case 'w':	 // 2 strings to match.
        if (Name.substr(3,4) != "rite")
          break;
        switch (Name[7]) {
        default: break;
        case 'l':	 // 1 strings to match.
          return MCK_vmwritel;	 // "vmwritel"
        case 'q':	 // 1 strings to match.
          return MCK_vmwriteq;	 // "vmwriteq"
        }
        break;
      }
      break;
    }
    break;
  case 9:	 // 25 strings to match.
    switch (Name[0]) {
    default: break;
    case 'c':	 // 11 strings to match.
      switch (Name[1]) {
      default: break;
      case 'm':	 // 1 strings to match.
        if (Name.substr(2,7) != "pxchg8b")
          break;
        return MCK_cmpxchg8b;	 // "cmpxchg8b"
      case 'v':	 // 10 strings to match.
        if (Name[2] != 't')
          break;
        switch (Name[3]) {
        default: break;
        case 's':	 // 5 strings to match.
          switch (Name[4]) {
          default: break;
          case 'd':	 // 1 strings to match.
            if (Name.substr(5,4) != "2siq")
              break;
            return MCK_cvtsd2siq;	 // "cvtsd2siq"
          case 'i':	 // 2 strings to match.
            if (Name.substr(5,2) != "2s")
              break;
            switch (Name[7]) {
            default: break;
            case 'd':	 // 1 strings to match.
              if (Name[8] != 'q')
                break;
              return MCK_cvtsi2sdq;	 // "cvtsi2sdq"
            case 's':	 // 1 strings to match.
              if (Name[8] != 'q')
                break;
              return MCK_cvtsi2ssq;	 // "cvtsi2ssq"
            }
            break;
          case 's':	 // 2 strings to match.
            if (Name.substr(5,3) != "2si")
              break;
            switch (Name[8]) {
            default: break;
            case 'l':	 // 1 strings to match.
              return MCK_cvtss2sil;	 // "cvtss2sil"
            case 'q':	 // 1 strings to match.
              return MCK_cvtss2siq;	 // "cvtss2siq"
            }
            break;
          }
          break;
        case 't':	 // 5 strings to match.
          switch (Name[4]) {
          default: break;
          case 'p':	 // 3 strings to match.
            switch (Name[5]) {
            default: break;
            case 'd':	 // 1 strings to match.
              if (Name.substr(6,3) != "2pi")
                break;
              return MCK_cvttpd2pi;	 // "cvttpd2pi"
            case 's':	 // 2 strings to match.
              if (Name[6] != '2')
                break;
              switch (Name[7]) {
              default: break;
              case 'd':	 // 1 strings to match.
                if (Name[8] != 'q')
                  break;
                return MCK_cvttps2dq;	 // "cvttps2dq"
              case 'p':	 // 1 strings to match.
                if (Name[8] != 'i')
                  break;
                return MCK_cvttps2pi;	 // "cvttps2pi"
              }
              break;
            }
            break;
          case 's':	 // 2 strings to match.
            switch (Name[5]) {
            default: break;
            case 'd':	 // 1 strings to match.
              if (Name.substr(6,3) != "2si")
                break;
              return MCK_cvttsd2si;	 // "cvttsd2si"
            case 's':	 // 1 strings to match.
              if (Name.substr(6,3) != "2si")
                break;
              return MCK_cvttss2si;	 // "cvttss2si"
            }
            break;
          }
          break;
        }
        break;
      }
      break;
    case 'e':	 // 1 strings to match.
      if (Name.substr(1,8) != "xtractps")
        break;
      return MCK_extractps;	 // "extractps"
    case 'p':	 // 11 strings to match.
      switch (Name[1]) {
      default: break;
      case 'c':	 // 4 strings to match.
        if (Name.substr(2,2) != "mp")
          break;
        switch (Name[4]) {
        default: break;
        case 'e':	 // 2 strings to match.
          if (Name.substr(5,3) != "str")
            break;
          switch (Name[8]) {
          default: break;
          case 'i':	 // 1 strings to match.
            return MCK_pcmpestri;	 // "pcmpestri"
          case 'm':	 // 1 strings to match.
            return MCK_pcmpestrm;	 // "pcmpestrm"
          }
          break;
        case 'i':	 // 2 strings to match.
          if (Name.substr(5,3) != "str")
            break;
          switch (Name[8]) {
          default: break;
          case 'i':	 // 1 strings to match.
            return MCK_pcmpistri;	 // "pcmpistri"
          case 'm':	 // 1 strings to match.
            return MCK_pcmpistrm;	 // "pcmpistrm"
          }
          break;
        }
        break;
      case 'm':	 // 1 strings to match.
        if (Name.substr(2,7) != "addubsw")
          break;
        return MCK_pmaddubsw;	 // "pmaddubsw"
      case 'u':	 // 6 strings to match.
        if (Name.substr(2,4) != "npck")
          break;
        switch (Name[6]) {
        default: break;
        case 'h':	 // 3 strings to match.
          switch (Name[7]) {
          default: break;
          case 'b':	 // 1 strings to match.
            if (Name[8] != 'w')
              break;
            return MCK_punpckhbw;	 // "punpckhbw"
          case 'd':	 // 1 strings to match.
            if (Name[8] != 'q')
              break;
            return MCK_punpckhdq;	 // "punpckhdq"
          case 'w':	 // 1 strings to match.
            if (Name[8] != 'd')
              break;
            return MCK_punpckhwd;	 // "punpckhwd"
          }
          break;
        case 'l':	 // 3 strings to match.
          switch (Name[7]) {
          default: break;
          case 'b':	 // 1 strings to match.
            if (Name[8] != 'w')
              break;
            return MCK_punpcklbw;	 // "punpcklbw"
          case 'd':	 // 1 strings to match.
            if (Name[8] != 'q')
              break;
            return MCK_punpckldq;	 // "punpckldq"
          case 'w':	 // 1 strings to match.
            if (Name[8] != 'd')
              break;
            return MCK_punpcklwd;	 // "punpcklwd"
          }
          break;
        }
        break;
      }
      break;
    case 'r':	 // 2 strings to match.
      if (Name.substr(1,3) != "ep;")
        break;
      switch (Name[4]) {
      default: break;
      case 'm':	 // 1 strings to match.
        if (Name.substr(5,4) != "ovsq")
          break;
        return MCK_rep_59_movsq;	 // "rep;movsq"
      case 's':	 // 1 strings to match.
        if (Name.substr(5,4) != "tosq")
          break;
        return MCK_rep_59_stosq;	 // "rep;stosq"
      }
      break;
    }
    break;
  case 10:	 // 10 strings to match.
    switch (Name[0]) {
    default: break;
    case 'c':	 // 3 strings to match.
      switch (Name[1]) {
      default: break;
      case 'm':	 // 1 strings to match.
        if (Name.substr(2,8) != "pxchg16b")
          break;
        return MCK_cmpxchg16b;	 // "cmpxchg16b"
      case 'v':	 // 2 strings to match.
        if (Name.substr(2,3) != "tts")
          break;
        switch (Name[5]) {
        default: break;
        case 'd':	 // 1 strings to match.
          if (Name.substr(6,4) != "2siq")
            break;
          return MCK_cvttsd2siq;	 // "cvttsd2siq"
        case 's':	 // 1 strings to match.
          if (Name.substr(6,4) != "2siq")
            break;
          return MCK_cvttss2siq;	 // "cvttss2siq"
        }
        break;
      }
      break;
    case 'm':	 // 1 strings to match.
      if (Name.substr(1,9) != "askmovdqu")
        break;
      return MCK_maskmovdqu;	 // "maskmovdqu"
    case 'p':	 // 6 strings to match.
      switch (Name[1]) {
      default: break;
      case 'h':	 // 1 strings to match.
        if (Name.substr(2,8) != "minposuw")
          break;
        return MCK_phminposuw;	 // "phminposuw"
      case 'r':	 // 3 strings to match.
        if (Name.substr(2,7) != "efetcht")
          break;
        switch (Name[9]) {
        default: break;
        case '0':	 // 1 strings to match.
          return MCK_prefetcht0;	 // "prefetcht0"
        case '1':	 // 1 strings to match.
          return MCK_prefetcht1;	 // "prefetcht1"
        case '2':	 // 1 strings to match.
          return MCK_prefetcht2;	 // "prefetcht2"
        }
        break;
      case 'u':	 // 2 strings to match.
        if (Name.substr(2,4) != "npck")
          break;
        switch (Name[6]) {
        default: break;
        case 'h':	 // 1 strings to match.
          if (Name.substr(7,3) != "qdq")
            break;
          return MCK_punpckhqdq;	 // "punpckhqdq"
        case 'l':	 // 1 strings to match.
          if (Name.substr(7,3) != "qdq")
            break;
          return MCK_punpcklqdq;	 // "punpcklqdq"
        }
        break;
      }
      break;
    }
    break;
  case 11:	 // 1 strings to match.
    if (Name.substr(0,11) != "prefetchnta")
      break;
    return MCK_prefetchnta;	 // "prefetchnta"
  }
  return InvalidMatchClass;
}

static MatchClassKind ClassifyOperand(MCParsedAsmOperand *GOp) {
  X86Operand &Operand = *(X86Operand*)GOp;
  if (Operand.isToken())
    return MatchTokenString(Operand.getToken());

  if (Operand.isReg()) {
    switch (Operand.getReg()) {
    default: return InvalidMatchClass;
    case X86::AL: return MCK_AL;
    case X86::DL: return MCK_GR8_ABCD_L;
    case X86::CL: return MCK_CL;
    case X86::BL: return MCK_GR8_ABCD_L;
    case X86::SIL: return MCK_GR8;
    case X86::DIL: return MCK_GR8;
    case X86::BPL: return MCK_GR8;
    case X86::SPL: return MCK_GR8;
    case X86::R8B: return MCK_GR8;
    case X86::R9B: return MCK_GR8;
    case X86::R10B: return MCK_GR8;
    case X86::R11B: return MCK_GR8;
    case X86::R12B: return MCK_GR8;
    case X86::R13B: return MCK_GR8;
    case X86::R14B: return MCK_GR8;
    case X86::R15B: return MCK_GR8;
    case X86::AH: return MCK_GR8_ABCD_H;
    case X86::DH: return MCK_GR8_ABCD_H;
    case X86::CH: return MCK_GR8_ABCD_H;
    case X86::BH: return MCK_GR8_ABCD_H;
    case X86::AX: return MCK_AX;
    case X86::DX: return MCK_DX;
    case X86::CX: return MCK_GR16_ABCD;
    case X86::BX: return MCK_GR16_ABCD;
    case X86::SI: return MCK_GR16_NOREX;
    case X86::DI: return MCK_GR16_NOREX;
    case X86::BP: return MCK_GR16_NOREX;
    case X86::SP: return MCK_GR16_NOREX;
    case X86::R8W: return MCK_GR16;
    case X86::R9W: return MCK_GR16;
    case X86::R10W: return MCK_GR16;
    case X86::R11W: return MCK_GR16;
    case X86::R12W: return MCK_GR16;
    case X86::R13W: return MCK_GR16;
    case X86::R14W: return MCK_GR16;
    case X86::R15W: return MCK_GR16;
    case X86::EAX: return MCK_EAX;
    case X86::EDX: return MCK_GR32_AD;
    case X86::ECX: return MCK_GR32_ABCD;
    case X86::EBX: return MCK_GR32_ABCD;
    case X86::ESI: return MCK_Reg14;
    case X86::EDI: return MCK_Reg14;
    case X86::EBP: return MCK_Reg14;
    case X86::ESP: return MCK_GR32_NOREX;
    case X86::R8D: return MCK_GR32_NOSP;
    case X86::R9D: return MCK_GR32_NOSP;
    case X86::R10D: return MCK_GR32_NOSP;
    case X86::R11D: return MCK_GR32_NOSP;
    case X86::R12D: return MCK_GR32_NOSP;
    case X86::R13D: return MCK_GR32_NOSP;
    case X86::R14D: return MCK_GR32_NOSP;
    case X86::R15D: return MCK_GR32_NOSP;
    case X86::RAX: return MCK_RAX;
    case X86::RDX: return MCK_GR64_ABCD;
    case X86::RCX: return MCK_GR64_ABCD;
    case X86::RBX: return MCK_GR64_ABCD;
    case X86::RSI: return MCK_GR64_NOREX_NOSP;
    case X86::RDI: return MCK_GR64_NOREX_NOSP;
    case X86::RBP: return MCK_GR64_NOREX_NOSP;
    case X86::RSP: return MCK_GR64_NOREX;
    case X86::R8: return MCK_GR64_NOSP;
    case X86::R9: return MCK_GR64_NOSP;
    case X86::R10: return MCK_GR64_NOSP;
    case X86::R11: return MCK_GR64_NOSP;
    case X86::R12: return MCK_GR64_NOSP;
    case X86::R13: return MCK_GR64_NOSP;
    case X86::R14: return MCK_GR64_NOSP;
    case X86::R15: return MCK_GR64_NOSP;
    case X86::RIP: return MCK_GR64_NOREX;
    case X86::MM0: return MCK_VR64;
    case X86::MM1: return MCK_VR64;
    case X86::MM2: return MCK_VR64;
    case X86::MM3: return MCK_VR64;
    case X86::MM4: return MCK_VR64;
    case X86::MM5: return MCK_VR64;
    case X86::MM6: return MCK_VR64;
    case X86::MM7: return MCK_VR64;
    case X86::FP0: return MCK_RFP32;
    case X86::FP1: return MCK_RFP32;
    case X86::FP2: return MCK_RFP32;
    case X86::FP3: return MCK_RFP32;
    case X86::FP4: return MCK_RFP32;
    case X86::FP5: return MCK_RFP32;
    case X86::FP6: return MCK_RFP32;
    case X86::XMM0: return MCK_XMM0;
    case X86::XMM1: return MCK_FR32;
    case X86::XMM2: return MCK_FR32;
    case X86::XMM3: return MCK_FR32;
    case X86::XMM4: return MCK_FR32;
    case X86::XMM5: return MCK_FR32;
    case X86::XMM6: return MCK_FR32;
    case X86::XMM7: return MCK_FR32;
    case X86::XMM8: return MCK_FR32;
    case X86::XMM9: return MCK_FR32;
    case X86::XMM10: return MCK_FR32;
    case X86::XMM11: return MCK_FR32;
    case X86::XMM12: return MCK_FR32;
    case X86::XMM13: return MCK_FR32;
    case X86::XMM14: return MCK_FR32;
    case X86::XMM15: return MCK_FR32;
    case X86::YMM0: return MCK_VR256;
    case X86::YMM1: return MCK_VR256;
    case X86::YMM2: return MCK_VR256;
    case X86::YMM3: return MCK_VR256;
    case X86::YMM4: return MCK_VR256;
    case X86::YMM5: return MCK_VR256;
    case X86::YMM6: return MCK_VR256;
    case X86::YMM7: return MCK_VR256;
    case X86::YMM8: return MCK_VR256;
    case X86::YMM9: return MCK_VR256;
    case X86::YMM10: return MCK_VR256;
    case X86::YMM11: return MCK_VR256;
    case X86::YMM12: return MCK_VR256;
    case X86::YMM13: return MCK_VR256;
    case X86::YMM14: return MCK_VR256;
    case X86::YMM15: return MCK_VR256;
    case X86::ST0: return MCK_ST0;
    case X86::ST1: return MCK_RST;
    case X86::ST2: return MCK_RST;
    case X86::ST3: return MCK_RST;
    case X86::ST4: return MCK_RST;
    case X86::ST5: return MCK_RST;
    case X86::ST6: return MCK_RST;
    case X86::ST7: return MCK_RST;
    case X86::EFLAGS: return MCK_CCR;
    case X86::CS: return MCK_SEGMENT_REG;
    case X86::DS: return MCK_SEGMENT_REG;
    case X86::SS: return MCK_SEGMENT_REG;
    case X86::ES: return MCK_SEGMENT_REG;
    case X86::FS: return MCK_FS;
    case X86::GS: return MCK_GS;
    case X86::DR0: return MCK_DEBUG_REG;
    case X86::DR1: return MCK_DEBUG_REG;
    case X86::DR2: return MCK_DEBUG_REG;
    case X86::DR3: return MCK_DEBUG_REG;
    case X86::DR4: return MCK_DEBUG_REG;
    case X86::DR5: return MCK_DEBUG_REG;
    case X86::DR6: return MCK_DEBUG_REG;
    case X86::DR7: return MCK_DEBUG_REG;
    case X86::ECR0: return MCK_CONTROL_REG_32;
    case X86::ECR1: return MCK_CONTROL_REG_32;
    case X86::ECR2: return MCK_CONTROL_REG_32;
    case X86::ECR3: return MCK_CONTROL_REG_32;
    case X86::ECR4: return MCK_CONTROL_REG_32;
    case X86::ECR5: return MCK_CONTROL_REG_32;
    case X86::ECR6: return MCK_CONTROL_REG_32;
    case X86::ECR7: return MCK_CONTROL_REG_32;
    case X86::RCR0: return MCK_CONTROL_REG_64;
    case X86::RCR1: return MCK_CONTROL_REG_64;
    case X86::RCR2: return MCK_CONTROL_REG_64;
    case X86::RCR3: return MCK_CONTROL_REG_64;
    case X86::RCR4: return MCK_CONTROL_REG_64;
    case X86::RCR5: return MCK_CONTROL_REG_64;
    case X86::RCR6: return MCK_CONTROL_REG_64;
    case X86::RCR7: return MCK_CONTROL_REG_64;
    case X86::RCR8: return MCK_CONTROL_REG_64;
    }
  }

  // 'ImmSExt8' class, subclass of 'Imm'
  if (Operand.isImmSExt8()) {
    assert(Operand.isImm() && "Invalid class relationship!");
    return MCK_ImmSExt8;
  }

  // 'Imm' class
  if (Operand.isImm()) {
    return MCK_Imm;
  }

  // 'AbsMem' class, subclass of 'Mem'
  if (Operand.isAbsMem()) {
    assert(Operand.isMem() && "Invalid class relationship!");
    return MCK_AbsMem;
  }

  // 'NoSegMem' class, subclass of 'Mem'
  if (Operand.isNoSegMem()) {
    assert(Operand.isMem() && "Invalid class relationship!");
    return MCK_NoSegMem;
  }

  // 'Mem' class
  if (Operand.isMem()) {
    return MCK_Mem;
  }

  return InvalidMatchClass;
}

/// IsSubclass - Compute whether \arg A is a subclass of \arg B.
static bool IsSubclass(MatchClassKind A, MatchClassKind B) {
  if (A == B)
    return true;

  switch (A) {
  default:
    return false;

  case MCK_AL:
    switch (B) {
    default: return false;
    case MCK_GR8_ABCD_L: return true;
    case MCK_GR8_NOREX: return true;
    case MCK_GR8: return true;
    }

  case MCK_CL:
    switch (B) {
    default: return false;
    case MCK_GR8_ABCD_L: return true;
    case MCK_GR8_NOREX: return true;
    case MCK_GR8: return true;
    }

  case MCK_GR8_ABCD_L:
    switch (B) {
    default: return false;
    case MCK_GR8_NOREX: return true;
    case MCK_GR8: return true;
    }

  case MCK_GR8_ABCD_H:
    switch (B) {
    default: return false;
    case MCK_GR8_NOREX: return true;
    case MCK_GR8: return true;
    }

  case MCK_GR8_NOREX:
    return B == MCK_GR8;

  case MCK_AX:
    switch (B) {
    default: return false;
    case MCK_GR16_ABCD: return true;
    case MCK_GR16_NOREX: return true;
    case MCK_GR16: return true;
    }

  case MCK_DX:
    switch (B) {
    default: return false;
    case MCK_GR16_ABCD: return true;
    case MCK_GR16_NOREX: return true;
    case MCK_GR16: return true;
    }

  case MCK_GR16_ABCD:
    switch (B) {
    default: return false;
    case MCK_GR16_NOREX: return true;
    case MCK_GR16: return true;
    }

  case MCK_GR16_NOREX:
    return B == MCK_GR16;

  case MCK_EAX:
    switch (B) {
    default: return false;
    case MCK_GR32_AD: return true;
    case MCK_GR32_ABCD: return true;
    case MCK_Reg14: return true;
    case MCK_GR32_NOREX: return true;
    case MCK_GR32_NOSP: return true;
    case MCK_GR32: return true;
    }

  case MCK_GR32_AD:
    switch (B) {
    default: return false;
    case MCK_GR32_ABCD: return true;
    case MCK_Reg14: return true;
    case MCK_GR32_NOREX: return true;
    case MCK_GR32_NOSP: return true;
    case MCK_GR32: return true;
    }

  case MCK_GR32_ABCD:
    switch (B) {
    default: return false;
    case MCK_Reg14: return true;
    case MCK_GR32_NOREX: return true;
    case MCK_GR32_NOSP: return true;
    case MCK_GR32: return true;
    }

  case MCK_Reg14:
    switch (B) {
    default: return false;
    case MCK_GR32_NOREX: return true;
    case MCK_GR32_NOSP: return true;
    case MCK_GR32: return true;
    }

  case MCK_GR32_NOREX:
    return B == MCK_GR32;

  case MCK_GR32_NOSP:
    return B == MCK_GR32;

  case MCK_RAX:
    switch (B) {
    default: return false;
    case MCK_GR64_ABCD: return true;
    case MCK_GR64_NOREX_NOSP: return true;
    case MCK_GR64_NOREX: return true;
    case MCK_GR64_NOSP: return true;
    case MCK_GR64: return true;
    }

  case MCK_GR64_ABCD:
    switch (B) {
    default: return false;
    case MCK_GR64_NOREX_NOSP: return true;
    case MCK_GR64_NOREX: return true;
    case MCK_GR64_NOSP: return true;
    case MCK_GR64: return true;
    }

  case MCK_GR64_NOREX_NOSP:
    switch (B) {
    default: return false;
    case MCK_GR64_NOREX: return true;
    case MCK_GR64_NOSP: return true;
    case MCK_GR64: return true;
    }

  case MCK_GR64_NOREX:
    return B == MCK_GR64;

  case MCK_GR64_NOSP:
    return B == MCK_GR64;

  case MCK_XMM0:
    return B == MCK_FR32;

  case MCK_ST0:
    return B == MCK_RST;

  case MCK_FS:
    return B == MCK_SEGMENT_REG;

  case MCK_GS:
    return B == MCK_SEGMENT_REG;

  case MCK_ImmSExt8:
    return B == MCK_Imm;

  case MCK_AbsMem:
    return B == MCK_Mem;

  case MCK_NoSegMem:
    return B == MCK_Mem;
  }
}

bool X86ATTAsmParser::
MatchInstruction(const SmallVectorImpl<MCParsedAsmOperand*> &Operands,
                 MCInst &Inst) {
  static const struct MatchEntry {
    unsigned Opcode;
    ConversionKind ConvertFn;
    MatchClassKind Classes[5];
  } MatchTable[2037] = {
    { X86::CBW, Convert, { MCK_cbtw } },
    { X86::CLC, Convert, { MCK_clc } },
    { X86::CLD, Convert, { MCK_cld } },
    { X86::CLI, Convert, { MCK_cli } },
    { X86::CDQ, Convert, { MCK_cltd } },
    { X86::CDQE, Convert, { MCK_cltq } },
    { X86::CLTS, Convert, { MCK_clts } },
    { X86::CMC, Convert, { MCK_cmc } },
    { X86::CMPS8, Convert, { MCK_cmpsb } },
    { X86::CMPS32, Convert, { MCK_cmpsl } },
    { X86::CMPS64, Convert, { MCK_cmpsq } },
    { X86::CMPS16, Convert, { MCK_cmpsw } },
    { X86::CPUID, Convert, { MCK_cpuid } },
    { X86::CQO, Convert, { MCK_cqto } },
    { X86::CS_PREFIX, Convert, { MCK_cs } },
    { X86::CWD, Convert, { MCK_cwtd } },
    { X86::CWDE, Convert, { MCK_cwtl } },
    { X86::DS_PREFIX, Convert, { MCK_ds } },
    { X86::MMX_EMMS, Convert, { MCK_emms } },
    { X86::ES_PREFIX, Convert, { MCK_es } },
    { X86::F2XM1, Convert, { MCK_f2xm1 } },
    { X86::ABS_F, Convert, { MCK_fabs } },
    { X86::CHS_F, Convert, { MCK_fchs } },
    { X86::FCOMPP, Convert, { MCK_fcompp } },
    { X86::COS_F, Convert, { MCK_fcos } },
    { X86::FDECSTP, Convert, { MCK_fdecstp } },
    { X86::MMX_FEMMS, Convert, { MCK_femms } },
    { X86::FINCSTP, Convert, { MCK_fincstp } },
    { X86::LD_F1, Convert, { MCK_fld1 } },
    { X86::FLDL2E, Convert, { MCK_fldl2e } },
    { X86::FLDL2T, Convert, { MCK_fldl2t } },
    { X86::FLDLG2, Convert, { MCK_fldlg2 } },
    { X86::FLDLN2, Convert, { MCK_fldln2 } },
    { X86::FLDPI, Convert, { MCK_fldpi } },
    { X86::LD_F0, Convert, { MCK_fldz } },
    { X86::FNCLEX, Convert, { MCK_fnclex } },
    { X86::FNINIT, Convert, { MCK_fninit } },
    { X86::FNOP, Convert, { MCK_fnop } },
    { X86::FPATAN, Convert, { MCK_fpatan } },
    { X86::FPREM, Convert, { MCK_fprem } },
    { X86::FPREM1, Convert, { MCK_fprem1 } },
    { X86::FPTAN, Convert, { MCK_fptan } },
    { X86::FRNDINT, Convert, { MCK_frndint } },
    { X86::FS_PREFIX, Convert, { MCK_fs } },
    { X86::FSCALE, Convert, { MCK_fscale } },
    { X86::SIN_F, Convert, { MCK_fsin } },
    { X86::FSINCOS, Convert, { MCK_fsincos } },
    { X86::SQRT_F, Convert, { MCK_fsqrt } },
    { X86::TST_F, Convert, { MCK_ftst } },
    { X86::UCOM_FPPr, Convert, { MCK_fucompp } },
    { X86::FXAM, Convert, { MCK_fxam } },
    { X86::FXTRACT, Convert, { MCK_fxtract } },
    { X86::FYL2X, Convert, { MCK_fyl2x } },
    { X86::FYL2XP1, Convert, { MCK_fyl2xp1 } },
    { X86::GS_PREFIX, Convert, { MCK_gs } },
    { X86::HLT, Convert, { MCK_hlt } },
    { X86::IN8, Convert, { MCK_insb } },
    { X86::IN32, Convert, { MCK_insl } },
    { X86::IN16, Convert, { MCK_insw } },
    { X86::INVD, Convert, { MCK_invd } },
    { X86::INVEPT, Convert, { MCK_invept } },
    { X86::INVVPID, Convert, { MCK_invvpid } },
    { X86::IRET32, Convert, { MCK_iretl } },
    { X86::IRET64, Convert, { MCK_iretq } },
    { X86::IRET16, Convert, { MCK_iretw } },
    { X86::LAHF, Convert, { MCK_lahf } },
    { X86::LEAVE, Convert, { MCK_leave } },
    { X86::LEAVE64, Convert, { MCK_leave } },
    { X86::LFENCE, Convert, { MCK_lfence } },
    { X86::LOCK_PREFIX, Convert, { MCK_lock } },
    { X86::LODSB, Convert, { MCK_lodsb } },
    { X86::LODSD, Convert, { MCK_lodsl } },
    { X86::LODSQ, Convert, { MCK_lodsq } },
    { X86::LODSW, Convert, { MCK_lodsw } },
    { X86::LRET, Convert, { MCK_lret } },
    { X86::MFENCE, Convert, { MCK_mfence } },
    { X86::MONITOR, Convert, { MCK_monitor } },
    { X86::MOVSB, Convert, { MCK_movsb } },
    { X86::MOVSD, Convert, { MCK_movsl } },
    { X86::MOVSW, Convert, { MCK_movsw } },
    { X86::MWAIT, Convert, { MCK_mwait } },
    { X86::NOOP, Convert, { MCK_nop } },
    { X86::OUTSB, Convert, { MCK_outsb } },
    { X86::OUTSD, Convert, { MCK_outsl } },
    { X86::OUTSW, Convert, { MCK_outsw } },
    { X86::POPFD, Convert, { MCK_popfl } },
    { X86::POPFQ, Convert, { MCK_popfq } },
    { X86::POPF, Convert, { MCK_popfw } },
    { X86::PUSHFD, Convert, { MCK_pushfl } },
    { X86::PUSHFQ64, Convert, { MCK_pushfq } },
    { X86::PUSHF, Convert, { MCK_pushfw } },
    { X86::RDMSR, Convert, { MCK_rdmsr } },
    { X86::RDPMC, Convert, { MCK_rdpmc } },
    { X86::RDTSC, Convert, { MCK_rdtsc } },
    { X86::RDTSCP, Convert, { MCK_rdtscp } },
    { X86::REP_PREFIX, Convert, { MCK_rep } },
    { X86::REP_MOVSQ, Convert, { MCK_rep_59_movsq } },
    { X86::REP_STOSQ, Convert, { MCK_rep_59_stosq } },
    { X86::REPNE_PREFIX, Convert, { MCK_repne } },
    { X86::RET, Convert, { MCK_ret } },
    { X86::RSM, Convert, { MCK_rsm } },
    { X86::SAHF, Convert, { MCK_sahf } },
    { X86::SCAS8, Convert, { MCK_scasb } },
    { X86::SCAS32, Convert, { MCK_scasl } },
    { X86::SCAS64, Convert, { MCK_scasq } },
    { X86::SCAS16, Convert, { MCK_scasw } },
    { X86::SFENCE, Convert, { MCK_sfence } },
    { X86::SS_PREFIX, Convert, { MCK_ss } },
    { X86::STC, Convert, { MCK_stc } },
    { X86::STD, Convert, { MCK_std } },
    { X86::STI, Convert, { MCK_sti } },
    { X86::STOSB, Convert, { MCK_stosb } },
    { X86::STOSD, Convert, { MCK_stosl } },
    { X86::STOSW, Convert, { MCK_stosw } },
    { X86::SWAPGS, Convert, { MCK_swapgs } },
    { X86::SYSCALL, Convert, { MCK_syscall } },
    { X86::SYSENTER, Convert, { MCK_sysenter } },
    { X86::SYSEXIT, Convert, { MCK_sysexit } },
    { X86::SYSEXIT64, Convert, { MCK_sysexit } },
    { X86::SYSRET, Convert, { MCK_sysret } },
    { X86::TRAP, Convert, { MCK_ud2 } },
    { X86::VMCALL, Convert, { MCK_vmcall } },
    { X86::VMLAUNCH, Convert, { MCK_vmlaunch } },
    { X86::VMRESUME, Convert, { MCK_vmresume } },
    { X86::VMXOFF, Convert, { MCK_vmxoff } },
    { X86::WAIT, Convert, { MCK_wait } },
    { X86::WBINVD, Convert, { MCK_wbinvd } },
    { X86::WRMSR, Convert, { MCK_wrmsr } },
    { X86::XLAT, Convert, { MCK_xlatb } },
    { X86::BSWAP32r, Convert__Reg1_1__Tie0, { MCK_bswapl, MCK_GR32 } },
    { X86::BSWAP64r, Convert__Reg1_1__Tie0, { MCK_bswapq, MCK_GR64 } },
    { X86::WINCALL64pcrel32, Convert__Imm1_1, { MCK_call, MCK_Imm } },
    { X86::CALLpcrel32, Convert__AbsMem1_1, { MCK_call, MCK_AbsMem } },
    { X86::CALL64pcrel32, Convert__Imm1_1, { MCK_callq, MCK_Imm } },
    { X86::CLFLUSH, Convert__Mem5_1, { MCK_clflush, MCK_Mem } },
    { X86::CMPXCHG16B, Convert__Mem5_1, { MCK_cmpxchg16b, MCK_Mem } },
    { X86::CMPXCHG8B, Convert__Mem5_1, { MCK_cmpxchg8b, MCK_Mem } },
    { X86::DEC8r, Convert__Reg1_1__Tie0, { MCK_decb, MCK_GR8 } },
    { X86::DEC8m, Convert__Mem5_1, { MCK_decb, MCK_Mem } },
    { X86::DEC32r, Convert__Reg1_1__Tie0, { MCK_decl, MCK_GR32 } },
    { X86::DEC64_32r, Convert__Reg1_1__Tie0, { MCK_decl, MCK_GR32 } },
    { X86::DEC32m, Convert__Mem5_1, { MCK_decl, MCK_Mem } },
    { X86::DEC64_32m, Convert__Mem5_1, { MCK_decl, MCK_Mem } },
    { X86::DEC64r, Convert__Reg1_1__Tie0, { MCK_decq, MCK_GR64 } },
    { X86::DEC64m, Convert__Mem5_1, { MCK_decq, MCK_Mem } },
    { X86::DEC16r, Convert__Reg1_1__Tie0, { MCK_decw, MCK_GR16 } },
    { X86::DEC64_16r, Convert__Reg1_1__Tie0, { MCK_decw, MCK_GR16 } },
    { X86::DEC16m, Convert__Mem5_1, { MCK_decw, MCK_Mem } },
    { X86::DEC64_16m, Convert__Mem5_1, { MCK_decw, MCK_Mem } },
    { X86::DIV8r, Convert__Reg1_1, { MCK_divb, MCK_GR8 } },
    { X86::DIV8m, Convert__Mem5_1, { MCK_divb, MCK_Mem } },
    { X86::DIV32r, Convert__Reg1_1, { MCK_divl, MCK_GR32 } },
    { X86::DIV32m, Convert__Mem5_1, { MCK_divl, MCK_Mem } },
    { X86::DIV64r, Convert__Reg1_1, { MCK_divq, MCK_GR64 } },
    { X86::DIV64m, Convert__Mem5_1, { MCK_divq, MCK_Mem } },
    { X86::DIV16r, Convert__Reg1_1, { MCK_divw, MCK_GR16 } },
    { X86::DIV16m, Convert__Mem5_1, { MCK_divw, MCK_Mem } },
    { X86::ADD_FST0r, Convert__Reg1_1, { MCK_fadd, MCK_RST } },
    { X86::ADD_F64m, Convert__Mem5_1, { MCK_faddl, MCK_Mem } },
    { X86::ADD_FPrST0, Convert__Reg1_1, { MCK_faddp, MCK_RST } },
    { X86::ADD_F32m, Convert__Mem5_1, { MCK_fadds, MCK_Mem } },
    { X86::FBLDm, Convert__Mem5_1, { MCK_fbld, MCK_Mem } },
    { X86::FBSTPm, Convert__Mem5_1, { MCK_fbstp, MCK_Mem } },
    { X86::COM_FST0r, Convert__Reg1_1, { MCK_fcom, MCK_RST } },
    { X86::FCOM32m, Convert__Mem5_1, { MCK_fcoml, MCK_Mem } },
    { X86::FCOM64m, Convert__Mem5_1, { MCK_fcomll, MCK_Mem } },
    { X86::COMP_FST0r, Convert__Reg1_1, { MCK_fcomp, MCK_RST } },
    { X86::FCOMP32m, Convert__Mem5_1, { MCK_fcompl, MCK_Mem } },
    { X86::FCOMP64m, Convert__Mem5_1, { MCK_fcompll, MCK_Mem } },
    { X86::DIV_FST0r, Convert__Reg1_1, { MCK_fdiv, MCK_RST } },
    { X86::DIV_F64m, Convert__Mem5_1, { MCK_fdivl, MCK_Mem } },
    { X86::DIVR_FPrST0, Convert__Reg1_1, { MCK_fdivp, MCK_RST } },
    { X86::DIVR_FST0r, Convert__Reg1_1, { MCK_fdivr, MCK_RST } },
    { X86::DIVR_F64m, Convert__Mem5_1, { MCK_fdivrl, MCK_Mem } },
    { X86::DIV_FPrST0, Convert__Reg1_1, { MCK_fdivrp, MCK_RST } },
    { X86::DIVR_F32m, Convert__Mem5_1, { MCK_fdivrs, MCK_Mem } },
    { X86::DIV_F32m, Convert__Mem5_1, { MCK_fdivs, MCK_Mem } },
    { X86::FFREE, Convert__Reg1_1, { MCK_ffree, MCK_RST } },
    { X86::ADD_FI32m, Convert__Mem5_1, { MCK_fiaddl, MCK_Mem } },
    { X86::ADD_FI16m, Convert__Mem5_1, { MCK_fiadds, MCK_Mem } },
    { X86::FICOM32m, Convert__Mem5_1, { MCK_ficoml, MCK_Mem } },
    { X86::FICOMP32m, Convert__Mem5_1, { MCK_ficompl, MCK_Mem } },
    { X86::FICOMP16m, Convert__Mem5_1, { MCK_ficompw, MCK_Mem } },
    { X86::FICOM16m, Convert__Mem5_1, { MCK_ficomw, MCK_Mem } },
    { X86::DIV_FI32m, Convert__Mem5_1, { MCK_fidivl, MCK_Mem } },
    { X86::DIVR_FI32m, Convert__Mem5_1, { MCK_fidivrl, MCK_Mem } },
    { X86::DIVR_FI16m, Convert__Mem5_1, { MCK_fidivrs, MCK_Mem } },
    { X86::DIV_FI16m, Convert__Mem5_1, { MCK_fidivs, MCK_Mem } },
    { X86::ILD_F32m, Convert__Mem5_1, { MCK_fildl, MCK_Mem } },
    { X86::ILD_F64m, Convert__Mem5_1, { MCK_fildll, MCK_Mem } },
    { X86::ILD_F16m, Convert__Mem5_1, { MCK_filds, MCK_Mem } },
    { X86::MUL_FI32m, Convert__Mem5_1, { MCK_fimull, MCK_Mem } },
    { X86::MUL_FI16m, Convert__Mem5_1, { MCK_fimuls, MCK_Mem } },
    { X86::IST_F32m, Convert__Mem5_1, { MCK_fistl, MCK_Mem } },
    { X86::IST_FP32m, Convert__Mem5_1, { MCK_fistpl, MCK_Mem } },
    { X86::IST_FP64m, Convert__Mem5_1, { MCK_fistpll, MCK_Mem } },
    { X86::IST_FP16m, Convert__Mem5_1, { MCK_fistps, MCK_Mem } },
    { X86::IST_F16m, Convert__Mem5_1, { MCK_fists, MCK_Mem } },
    { X86::ISTT_FP32m, Convert__Mem5_1, { MCK_fisttpl, MCK_Mem } },
    { X86::ISTT_FP64m, Convert__Mem5_1, { MCK_fisttpll, MCK_Mem } },
    { X86::ISTT_FP16m, Convert__Mem5_1, { MCK_fisttps, MCK_Mem } },
    { X86::SUB_FI32m, Convert__Mem5_1, { MCK_fisubl, MCK_Mem } },
    { X86::SUBR_FI32m, Convert__Mem5_1, { MCK_fisubrl, MCK_Mem } },
    { X86::SUBR_FI16m, Convert__Mem5_1, { MCK_fisubrs, MCK_Mem } },
    { X86::SUB_FI16m, Convert__Mem5_1, { MCK_fisubs, MCK_Mem } },
    { X86::LD_Frr, Convert__Reg1_1, { MCK_fld, MCK_RST } },
    { X86::FLDCW16m, Convert__Mem5_1, { MCK_fldcw, MCK_Mem } },
    { X86::FLDENVm, Convert__Mem5_1, { MCK_fldenv, MCK_Mem } },
    { X86::LD_F64m, Convert__Mem5_1, { MCK_fldl, MCK_Mem } },
    { X86::LD_F32m, Convert__Mem5_1, { MCK_flds, MCK_Mem } },
    { X86::LD_F80m, Convert__Mem5_1, { MCK_fldt, MCK_Mem } },
    { X86::MUL_FST0r, Convert__Reg1_1, { MCK_fmul, MCK_RST } },
    { X86::MUL_F64m, Convert__Mem5_1, { MCK_fmull, MCK_Mem } },
    { X86::MUL_FPrST0, Convert__Reg1_1, { MCK_fmulp, MCK_RST } },
    { X86::MUL_F32m, Convert__Mem5_1, { MCK_fmuls, MCK_Mem } },
    { X86::FSAVEm, Convert__Mem5_1, { MCK_fnsave, MCK_Mem } },
    { X86::FNSTCW16m, Convert__Mem5_1, { MCK_fnstcw, MCK_Mem } },
    { X86::FSTENVm, Convert__Mem5_1, { MCK_fnstenv, MCK_Mem } },
    { X86::FNSTSW8r, Convert, { MCK_fnstsw, MCK_AX } },
    { X86::FNSTSWm, Convert__Mem5_1, { MCK_fnstsw, MCK_Mem } },
    { X86::FRSTORm, Convert__Mem5_1, { MCK_frstor, MCK_Mem } },
    { X86::ST_Frr, Convert__Reg1_1, { MCK_fst, MCK_RST } },
    { X86::ST_F64m, Convert__Mem5_1, { MCK_fstl, MCK_Mem } },
    { X86::ST_FPrr, Convert__Reg1_1, { MCK_fstp, MCK_RST } },
    { X86::ST_FP64m, Convert__Mem5_1, { MCK_fstpl, MCK_Mem } },
    { X86::ST_FP32m, Convert__Mem5_1, { MCK_fstps, MCK_Mem } },
    { X86::ST_FP80m, Convert__Mem5_1, { MCK_fstpt, MCK_Mem } },
    { X86::ST_F32m, Convert__Mem5_1, { MCK_fsts, MCK_Mem } },
    { X86::SUB_FST0r, Convert__Reg1_1, { MCK_fsub, MCK_RST } },
    { X86::SUB_F64m, Convert__Mem5_1, { MCK_fsubl, MCK_Mem } },
    { X86::SUBR_FPrST0, Convert__Reg1_1, { MCK_fsubp, MCK_RST } },
    { X86::SUBR_FST0r, Convert__Reg1_1, { MCK_fsubr, MCK_RST } },
    { X86::SUBR_F64m, Convert__Mem5_1, { MCK_fsubrl, MCK_Mem } },
    { X86::SUB_FPrST0, Convert__Reg1_1, { MCK_fsubrp, MCK_RST } },
    { X86::SUBR_F32m, Convert__Mem5_1, { MCK_fsubrs, MCK_Mem } },
    { X86::SUB_F32m, Convert__Mem5_1, { MCK_fsubs, MCK_Mem } },
    { X86::UCOM_Fr, Convert__Reg1_1, { MCK_fucom, MCK_RST } },
    { X86::UCOM_FPr, Convert__Reg1_1, { MCK_fucomp, MCK_RST } },
    { X86::XCH_F, Convert__Reg1_1, { MCK_fxch, MCK_RST } },
    { X86::FXRSTOR, Convert__Mem5_1, { MCK_fxrstor, MCK_Mem } },
    { X86::FXSAVE, Convert__Mem5_1, { MCK_fxsave, MCK_Mem } },
    { X86::IDIV8r, Convert__Reg1_1, { MCK_idivb, MCK_GR8 } },
    { X86::IDIV8m, Convert__Mem5_1, { MCK_idivb, MCK_Mem } },
    { X86::IDIV32r, Convert__Reg1_1, { MCK_idivl, MCK_GR32 } },
    { X86::IDIV32m, Convert__Mem5_1, { MCK_idivl, MCK_Mem } },
    { X86::IDIV64r, Convert__Reg1_1, { MCK_idivq, MCK_GR64 } },
    { X86::IDIV64m, Convert__Mem5_1, { MCK_idivq, MCK_Mem } },
    { X86::IDIV16r, Convert__Reg1_1, { MCK_idivw, MCK_GR16 } },
    { X86::IDIV16m, Convert__Mem5_1, { MCK_idivw, MCK_Mem } },
    { X86::IMUL8r, Convert__Reg1_1, { MCK_imulb, MCK_GR8 } },
    { X86::IMUL8m, Convert__Mem5_1, { MCK_imulb, MCK_Mem } },
    { X86::IMUL32r, Convert__Reg1_1, { MCK_imull, MCK_GR32 } },
    { X86::IMUL32m, Convert__Mem5_1, { MCK_imull, MCK_Mem } },
    { X86::IMUL64r, Convert__Reg1_1, { MCK_imulq, MCK_GR64 } },
    { X86::IMUL64m, Convert__Mem5_1, { MCK_imulq, MCK_Mem } },
    { X86::IMUL16r, Convert__Reg1_1, { MCK_imulw, MCK_GR16 } },
    { X86::IMUL16m, Convert__Mem5_1, { MCK_imulw, MCK_Mem } },
    { X86::INC8r, Convert__Reg1_1__Tie0, { MCK_incb, MCK_GR8 } },
    { X86::INC8m, Convert__Mem5_1, { MCK_incb, MCK_Mem } },
    { X86::INC32r, Convert__Reg1_1__Tie0, { MCK_incl, MCK_GR32 } },
    { X86::INC64_32r, Convert__Reg1_1__Tie0, { MCK_incl, MCK_GR32 } },
    { X86::INC32m, Convert__Mem5_1, { MCK_incl, MCK_Mem } },
    { X86::INC64_32m, Convert__Mem5_1, { MCK_incl, MCK_Mem } },
    { X86::INC64r, Convert__Reg1_1__Tie0, { MCK_incq, MCK_GR64 } },
    { X86::INC64m, Convert__Mem5_1, { MCK_incq, MCK_Mem } },
    { X86::INC16r, Convert__Reg1_1__Tie0, { MCK_incw, MCK_GR16 } },
    { X86::INC64_16r, Convert__Reg1_1__Tie0, { MCK_incw, MCK_GR16 } },
    { X86::INC16m, Convert__Mem5_1, { MCK_incw, MCK_Mem } },
    { X86::INC64_16m, Convert__Mem5_1, { MCK_incw, MCK_Mem } },
    { X86::INT3, Convert, { MCK_int, MCK_3 } },
    { X86::INT, Convert__Imm1_1, { MCK_int, MCK_Imm } },
    { X86::INVLPG, Convert__Mem5_1, { MCK_invlpg, MCK_Mem } },
    { X86::JA_1, Convert__AbsMem1_1, { MCK_ja, MCK_AbsMem } },
    { X86::JA_4, Convert__AbsMem1_1, { MCK_ja, MCK_AbsMem } },
    { X86::JAE_1, Convert__AbsMem1_1, { MCK_jae, MCK_AbsMem } },
    { X86::JAE_4, Convert__AbsMem1_1, { MCK_jae, MCK_AbsMem } },
    { X86::JB_1, Convert__AbsMem1_1, { MCK_jb, MCK_AbsMem } },
    { X86::JB_4, Convert__AbsMem1_1, { MCK_jb, MCK_AbsMem } },
    { X86::JBE_1, Convert__AbsMem1_1, { MCK_jbe, MCK_AbsMem } },
    { X86::JBE_4, Convert__AbsMem1_1, { MCK_jbe, MCK_AbsMem } },
    { X86::JCXZ8, Convert__AbsMem1_1, { MCK_jcxz, MCK_AbsMem } },
    { X86::JE_1, Convert__AbsMem1_1, { MCK_je, MCK_AbsMem } },
    { X86::JE_4, Convert__AbsMem1_1, { MCK_je, MCK_AbsMem } },
    { X86::JG_1, Convert__AbsMem1_1, { MCK_jg, MCK_AbsMem } },
    { X86::JG_4, Convert__AbsMem1_1, { MCK_jg, MCK_AbsMem } },
    { X86::JGE_1, Convert__AbsMem1_1, { MCK_jge, MCK_AbsMem } },
    { X86::JGE_4, Convert__AbsMem1_1, { MCK_jge, MCK_AbsMem } },
    { X86::JL_1, Convert__AbsMem1_1, { MCK_jl, MCK_AbsMem } },
    { X86::JL_4, Convert__AbsMem1_1, { MCK_jl, MCK_AbsMem } },
    { X86::JLE_1, Convert__AbsMem1_1, { MCK_jle, MCK_AbsMem } },
    { X86::JLE_4, Convert__AbsMem1_1, { MCK_jle, MCK_AbsMem } },
    { X86::JMP_1, Convert__AbsMem1_1, { MCK_jmp, MCK_AbsMem } },
    { X86::JMP_4, Convert__AbsMem1_1, { MCK_jmp, MCK_AbsMem } },
    { X86::TAILJMPd, Convert__AbsMem1_1, { MCK_jmp, MCK_AbsMem } },
    { X86::JMP64pcrel32, Convert__AbsMem1_1, { MCK_jmpq, MCK_AbsMem } },
    { X86::JNE_1, Convert__AbsMem1_1, { MCK_jne, MCK_AbsMem } },
    { X86::JNE_4, Convert__AbsMem1_1, { MCK_jne, MCK_AbsMem } },
    { X86::JNO_1, Convert__AbsMem1_1, { MCK_jno, MCK_AbsMem } },
    { X86::JNO_4, Convert__AbsMem1_1, { MCK_jno, MCK_AbsMem } },
    { X86::JNP_1, Convert__AbsMem1_1, { MCK_jnp, MCK_AbsMem } },
    { X86::JNP_4, Convert__AbsMem1_1, { MCK_jnp, MCK_AbsMem } },
    { X86::JNS_1, Convert__AbsMem1_1, { MCK_jns, MCK_AbsMem } },
    { X86::JNS_4, Convert__AbsMem1_1, { MCK_jns, MCK_AbsMem } },
    { X86::JO_1, Convert__AbsMem1_1, { MCK_jo, MCK_AbsMem } },
    { X86::JO_4, Convert__AbsMem1_1, { MCK_jo, MCK_AbsMem } },
    { X86::JP_1, Convert__AbsMem1_1, { MCK_jp, MCK_AbsMem } },
    { X86::JP_4, Convert__AbsMem1_1, { MCK_jp, MCK_AbsMem } },
    { X86::JS_1, Convert__AbsMem1_1, { MCK_js, MCK_AbsMem } },
    { X86::JS_4, Convert__AbsMem1_1, { MCK_js, MCK_AbsMem } },
    { X86::LDMXCSR, Convert__Mem5_1, { MCK_ldmxcsr, MCK_Mem } },
    { X86::LGDTm, Convert__Mem5_1, { MCK_lgdt, MCK_Mem } },
    { X86::LIDTm, Convert__Mem5_1, { MCK_lidt, MCK_Mem } },
    { X86::LLDT16r, Convert__Reg1_1, { MCK_lldtw, MCK_GR16 } },
    { X86::LLDT16m, Convert__Mem5_1, { MCK_lldtw, MCK_Mem } },
    { X86::LMSW16r, Convert__Reg1_1, { MCK_lmsww, MCK_GR16 } },
    { X86::LMSW16m, Convert__Mem5_1, { MCK_lmsww, MCK_Mem } },
    { X86::LOOP, Convert__AbsMem1_1, { MCK_loop, MCK_AbsMem } },
    { X86::LOOPE, Convert__AbsMem1_1, { MCK_loope, MCK_AbsMem } },
    { X86::LOOPNE, Convert__AbsMem1_1, { MCK_loopne, MCK_AbsMem } },
    { X86::LRETI, Convert__Imm1_1, { MCK_lret, MCK_Imm } },
    { X86::LTRr, Convert__Reg1_1, { MCK_ltrw, MCK_GR16 } },
    { X86::LTRm, Convert__Mem5_1, { MCK_ltrw, MCK_Mem } },
    { X86::MUL8r, Convert__Reg1_1, { MCK_mulb, MCK_GR8 } },
    { X86::MUL8m, Convert__Mem5_1, { MCK_mulb, MCK_Mem } },
    { X86::MUL32r, Convert__Reg1_1, { MCK_mull, MCK_GR32 } },
    { X86::MUL32m, Convert__Mem5_1, { MCK_mull, MCK_Mem } },
    { X86::MUL64r, Convert__Reg1_1, { MCK_mulq, MCK_GR64 } },
    { X86::MUL64m, Convert__Mem5_1, { MCK_mulq, MCK_Mem } },
    { X86::MUL16r, Convert__Reg1_1, { MCK_mulw, MCK_GR16 } },
    { X86::MUL16m, Convert__Mem5_1, { MCK_mulw, MCK_Mem } },
    { X86::NEG8r, Convert__Reg1_1__Tie0, { MCK_negb, MCK_GR8 } },
    { X86::NEG8m, Convert__Mem5_1, { MCK_negb, MCK_Mem } },
    { X86::NEG32r, Convert__Reg1_1__Tie0, { MCK_negl, MCK_GR32 } },
    { X86::NEG32m, Convert__Mem5_1, { MCK_negl, MCK_Mem } },
    { X86::NEG64r, Convert__Reg1_1__Tie0, { MCK_negq, MCK_GR64 } },
    { X86::NEG64m, Convert__Mem5_1, { MCK_negq, MCK_Mem } },
    { X86::NEG16r, Convert__Reg1_1__Tie0, { MCK_negw, MCK_GR16 } },
    { X86::NEG16m, Convert__Mem5_1, { MCK_negw, MCK_Mem } },
    { X86::NOOPL, Convert__Mem5_1, { MCK_nopl, MCK_Mem } },
    { X86::NOOPW, Convert__Mem5_1, { MCK_nopw, MCK_Mem } },
    { X86::NOT8r, Convert__Reg1_1__Tie0, { MCK_notb, MCK_GR8 } },
    { X86::NOT8m, Convert__Mem5_1, { MCK_notb, MCK_Mem } },
    { X86::NOT32r, Convert__Reg1_1__Tie0, { MCK_notl, MCK_GR32 } },
    { X86::NOT32m, Convert__Mem5_1, { MCK_notl, MCK_Mem } },
    { X86::NOT64r, Convert__Reg1_1__Tie0, { MCK_notq, MCK_GR64 } },
    { X86::NOT64m, Convert__Mem5_1, { MCK_notq, MCK_Mem } },
    { X86::NOT16r, Convert__Reg1_1__Tie0, { MCK_notw, MCK_GR16 } },
    { X86::NOT16m, Convert__Mem5_1, { MCK_notw, MCK_Mem } },
    { X86::POP32r, Convert__Reg1_1, { MCK_popl, MCK_GR32 } },
    { X86::POP32rmr, Convert__Reg1_1, { MCK_popl, MCK_GR32 } },
    { X86::POPFS32, Convert, { MCK_popl, MCK_FS } },
    { X86::POPGS32, Convert, { MCK_popl, MCK_GS } },
    { X86::POP32rmm, Convert__Mem5_1, { MCK_popl, MCK_Mem } },
    { X86::POP64r, Convert__Reg1_1, { MCK_popq, MCK_GR64 } },
    { X86::POP64rmr, Convert__Reg1_1, { MCK_popq, MCK_GR64 } },
    { X86::POPFS64, Convert, { MCK_popq, MCK_FS } },
    { X86::POPGS64, Convert, { MCK_popq, MCK_GS } },
    { X86::POP64rmm, Convert__Mem5_1, { MCK_popq, MCK_Mem } },
    { X86::POP16r, Convert__Reg1_1, { MCK_popw, MCK_GR16 } },
    { X86::POP16rmr, Convert__Reg1_1, { MCK_popw, MCK_GR16 } },
    { X86::POPFS16, Convert, { MCK_popw, MCK_FS } },
    { X86::POPGS16, Convert, { MCK_popw, MCK_GS } },
    { X86::POP16rmm, Convert__Mem5_1, { MCK_popw, MCK_Mem } },
    { X86::PREFETCHNTA, Convert__Mem5_1, { MCK_prefetchnta, MCK_Mem } },
    { X86::PREFETCHT0, Convert__Mem5_1, { MCK_prefetcht0, MCK_Mem } },
    { X86::PREFETCHT1, Convert__Mem5_1, { MCK_prefetcht1, MCK_Mem } },
    { X86::PREFETCHT2, Convert__Mem5_1, { MCK_prefetcht2, MCK_Mem } },
    { X86::PUSH32r, Convert__Reg1_1, { MCK_pushl, MCK_GR32 } },
    { X86::PUSH32rmr, Convert__Reg1_1, { MCK_pushl, MCK_GR32 } },
    { X86::PUSHFS32, Convert, { MCK_pushl, MCK_FS } },
    { X86::PUSHGS32, Convert, { MCK_pushl, MCK_GS } },
    { X86::PUSH32i16, Convert__Imm1_1, { MCK_pushl, MCK_Imm } },
    { X86::PUSH32i32, Convert__Imm1_1, { MCK_pushl, MCK_Imm } },
    { X86::PUSH32i8, Convert__Imm1_1, { MCK_pushl, MCK_Imm } },
    { X86::PUSH32rmm, Convert__Mem5_1, { MCK_pushl, MCK_Mem } },
    { X86::PUSH64r, Convert__Reg1_1, { MCK_pushq, MCK_GR64 } },
    { X86::PUSH64rmr, Convert__Reg1_1, { MCK_pushq, MCK_GR64 } },
    { X86::PUSHFS64, Convert, { MCK_pushq, MCK_FS } },
    { X86::PUSHGS64, Convert, { MCK_pushq, MCK_GS } },
    { X86::PUSH64i16, Convert__Imm1_1, { MCK_pushq, MCK_Imm } },
    { X86::PUSH64i32, Convert__Imm1_1, { MCK_pushq, MCK_Imm } },
    { X86::PUSH64i8, Convert__Imm1_1, { MCK_pushq, MCK_Imm } },
    { X86::PUSH64rmm, Convert__Mem5_1, { MCK_pushq, MCK_Mem } },
    { X86::PUSH16r, Convert__Reg1_1, { MCK_pushw, MCK_GR16 } },
    { X86::PUSH16rmr, Convert__Reg1_1, { MCK_pushw, MCK_GR16 } },
    { X86::PUSHFS16, Convert, { MCK_pushw, MCK_FS } },
    { X86::PUSHGS16, Convert, { MCK_pushw, MCK_GS } },
    { X86::PUSH16rmm, Convert__Mem5_1, { MCK_pushw, MCK_Mem } },
    { X86::RETI, Convert__Imm1_1, { MCK_ret, MCK_Imm } },
    { X86::ROL8r1, Convert__Reg1_1__Tie0, { MCK_rolb, MCK_GR8 } },
    { X86::ROL8m1, Convert__Mem5_1, { MCK_rolb, MCK_Mem } },
    { X86::ROL32r1, Convert__Reg1_1__Tie0, { MCK_roll, MCK_GR32 } },
    { X86::ROL32m1, Convert__Mem5_1, { MCK_roll, MCK_Mem } },
    { X86::ROL64r1, Convert__Reg1_1__Tie0, { MCK_rolq, MCK_GR64 } },
    { X86::ROL64m1, Convert__Mem5_1, { MCK_rolq, MCK_Mem } },
    { X86::ROL16r1, Convert__Reg1_1__Tie0, { MCK_rolw, MCK_GR16 } },
    { X86::ROL16m1, Convert__Mem5_1, { MCK_rolw, MCK_Mem } },
    { X86::ROR8r1, Convert__Reg1_1__Tie0, { MCK_rorb, MCK_GR8 } },
    { X86::ROR8m1, Convert__Mem5_1, { MCK_rorb, MCK_Mem } },
    { X86::ROR32r1, Convert__Reg1_1__Tie0, { MCK_rorl, MCK_GR32 } },
    { X86::ROR32m1, Convert__Mem5_1, { MCK_rorl, MCK_Mem } },
    { X86::ROR64r1, Convert__Reg1_1__Tie0, { MCK_rorq, MCK_GR64 } },
    { X86::ROR64m1, Convert__Mem5_1, { MCK_rorq, MCK_Mem } },
    { X86::ROR16r1, Convert__Reg1_1__Tie0, { MCK_rorw, MCK_GR16 } },
    { X86::ROR16m1, Convert__Mem5_1, { MCK_rorw, MCK_Mem } },
    { X86::SAR8r1, Convert__Reg1_1__Tie0, { MCK_sarb, MCK_GR8 } },
    { X86::SAR8m1, Convert__Mem5_1, { MCK_sarb, MCK_Mem } },
    { X86::SAR32r1, Convert__Reg1_1__Tie0, { MCK_sarl, MCK_GR32 } },
    { X86::SAR32m1, Convert__Mem5_1, { MCK_sarl, MCK_Mem } },
    { X86::SAR64r1, Convert__Reg1_1__Tie0, { MCK_sarq, MCK_GR64 } },
    { X86::SAR64m1, Convert__Mem5_1, { MCK_sarq, MCK_Mem } },
    { X86::SAR16r1, Convert__Reg1_1__Tie0, { MCK_sarw, MCK_GR16 } },
    { X86::SAR16m1, Convert__Mem5_1, { MCK_sarw, MCK_Mem } },
    { X86::SETAr, Convert__Reg1_1, { MCK_seta, MCK_GR8 } },
    { X86::SETAm, Convert__Mem5_1, { MCK_seta, MCK_Mem } },
    { X86::SETAEr, Convert__Reg1_1, { MCK_setae, MCK_GR8 } },
    { X86::SETAEm, Convert__Mem5_1, { MCK_setae, MCK_Mem } },
    { X86::SETBr, Convert__Reg1_1, { MCK_setb, MCK_GR8 } },
    { X86::SETBm, Convert__Mem5_1, { MCK_setb, MCK_Mem } },
    { X86::SETBEr, Convert__Reg1_1, { MCK_setbe, MCK_GR8 } },
    { X86::SETBEm, Convert__Mem5_1, { MCK_setbe, MCK_Mem } },
    { X86::SETEr, Convert__Reg1_1, { MCK_sete, MCK_GR8 } },
    { X86::SETEm, Convert__Mem5_1, { MCK_sete, MCK_Mem } },
    { X86::SETGr, Convert__Reg1_1, { MCK_setg, MCK_GR8 } },
    { X86::SETGm, Convert__Mem5_1, { MCK_setg, MCK_Mem } },
    { X86::SETGEr, Convert__Reg1_1, { MCK_setge, MCK_GR8 } },
    { X86::SETGEm, Convert__Mem5_1, { MCK_setge, MCK_Mem } },
    { X86::SETLr, Convert__Reg1_1, { MCK_setl, MCK_GR8 } },
    { X86::SETLm, Convert__Mem5_1, { MCK_setl, MCK_Mem } },
    { X86::SETLEr, Convert__Reg1_1, { MCK_setle, MCK_GR8 } },
    { X86::SETLEm, Convert__Mem5_1, { MCK_setle, MCK_Mem } },
    { X86::SETNEr, Convert__Reg1_1, { MCK_setne, MCK_GR8 } },
    { X86::SETNEm, Convert__Mem5_1, { MCK_setne, MCK_Mem } },
    { X86::SETNOr, Convert__Reg1_1, { MCK_setno, MCK_GR8 } },
    { X86::SETNOm, Convert__Mem5_1, { MCK_setno, MCK_Mem } },
    { X86::SETNPr, Convert__Reg1_1, { MCK_setnp, MCK_GR8 } },
    { X86::SETNPm, Convert__Mem5_1, { MCK_setnp, MCK_Mem } },
    { X86::SETNSr, Convert__Reg1_1, { MCK_setns, MCK_GR8 } },
    { X86::SETNSm, Convert__Mem5_1, { MCK_setns, MCK_Mem } },
    { X86::SETOr, Convert__Reg1_1, { MCK_seto, MCK_GR8 } },
    { X86::SETOm, Convert__Mem5_1, { MCK_seto, MCK_Mem } },
    { X86::SETPr, Convert__Reg1_1, { MCK_setp, MCK_GR8 } },
    { X86::SETPm, Convert__Mem5_1, { MCK_setp, MCK_Mem } },
    { X86::SETSr, Convert__Reg1_1, { MCK_sets, MCK_GR8 } },
    { X86::SETSm, Convert__Mem5_1, { MCK_sets, MCK_Mem } },
    { X86::SGDTm, Convert__Mem5_1, { MCK_sgdt, MCK_Mem } },
    { X86::SHL8r1, Convert__Reg1_1__Tie0, { MCK_shlb, MCK_GR8 } },
    { X86::SHL8m1, Convert__Mem5_1, { MCK_shlb, MCK_Mem } },
    { X86::SHL32r1, Convert__Reg1_1__Tie0, { MCK_shll, MCK_GR32 } },
    { X86::SHL32m1, Convert__Mem5_1, { MCK_shll, MCK_Mem } },
    { X86::SHL64r1, Convert__Reg1_1__Tie0, { MCK_shlq, MCK_GR64 } },
    { X86::SHL64m1, Convert__Mem5_1, { MCK_shlq, MCK_Mem } },
    { X86::SHL16r1, Convert__Reg1_1__Tie0, { MCK_shlw, MCK_GR16 } },
    { X86::SHL16m1, Convert__Mem5_1, { MCK_shlw, MCK_Mem } },
    { X86::SHR8r1, Convert__Reg1_1__Tie0, { MCK_shrb, MCK_GR8 } },
    { X86::SHR8m1, Convert__Mem5_1, { MCK_shrb, MCK_Mem } },
    { X86::SHR32r1, Convert__Reg1_1__Tie0, { MCK_shrl, MCK_GR32 } },
    { X86::SHR32m1, Convert__Mem5_1, { MCK_shrl, MCK_Mem } },
    { X86::SHR64r1, Convert__Reg1_1__Tie0, { MCK_shrq, MCK_GR64 } },
    { X86::SHR64m1, Convert__Mem5_1, { MCK_shrq, MCK_Mem } },
    { X86::SHR16r1, Convert__Reg1_1__Tie0, { MCK_shrw, MCK_GR16 } },
    { X86::SHR16m1, Convert__Mem5_1, { MCK_shrw, MCK_Mem } },
    { X86::SIDTm, Convert__Mem5_1, { MCK_sidt, MCK_Mem } },
    { X86::SLDT64r, Convert__Reg1_1, { MCK_sldtq, MCK_GR64 } },
    { X86::SLDT64m, Convert__Mem5_1, { MCK_sldtq, MCK_Mem } },
    { X86::SLDT16r, Convert__Reg1_1, { MCK_sldtw, MCK_GR16 } },
    { X86::SLDT16m, Convert__Mem5_1, { MCK_sldtw, MCK_Mem } },
    { X86::SMSW32r, Convert__Reg1_1, { MCK_smswl, MCK_GR32 } },
    { X86::SMSW64r, Convert__Reg1_1, { MCK_smswq, MCK_GR64 } },
    { X86::SMSW16r, Convert__Reg1_1, { MCK_smsww, MCK_GR16 } },
    { X86::SMSW16m, Convert__Mem5_1, { MCK_smsww, MCK_Mem } },
    { X86::STMXCSR, Convert__Mem5_1, { MCK_stmxcsr, MCK_Mem } },
    { X86::STRr, Convert__Reg1_1, { MCK_strw, MCK_GR16 } },
    { X86::STRm, Convert__Mem5_1, { MCK_strw, MCK_Mem } },
    { X86::VERRr, Convert__Reg1_1, { MCK_verr, MCK_GR16 } },
    { X86::VERRm, Convert__Mem5_1, { MCK_verr, MCK_Mem } },
    { X86::VERWr, Convert__Reg1_1, { MCK_verw, MCK_GR16 } },
    { X86::VERWm, Convert__Mem5_1, { MCK_verw, MCK_Mem } },
    { X86::VMCLEARm, Convert__Mem5_1, { MCK_vmclear, MCK_Mem } },
    { X86::VMPTRLDm, Convert__Mem5_1, { MCK_vmptrld, MCK_Mem } },
    { X86::VMPTRSTm, Convert__Mem5_1, { MCK_vmptrst, MCK_Mem } },
    { X86::VMXON, Convert__Mem5_1, { MCK_vmxon, MCK_Mem } },
    { X86::ADC8rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_adcb, MCK_GR8, MCK_GR8 } },
    { X86::ADC8rr_REV, Convert__Reg1_2__Tie0__Reg1_1, { MCK_adcb, MCK_GR8, MCK_GR8 } },
    { X86::ADC8mr, Convert__Mem5_2__Reg1_1, { MCK_adcb, MCK_GR8, MCK_Mem } },
    { X86::ADC8i8, Convert__Imm1_1, { MCK_adcb, MCK_Imm, MCK_AL } },
    { X86::ADC8ri, Convert__Reg1_2__Tie0__Imm1_1, { MCK_adcb, MCK_Imm, MCK_GR8 } },
    { X86::ADC8mi, Convert__Mem5_2__Imm1_1, { MCK_adcb, MCK_Imm, MCK_Mem } },
    { X86::ADC8rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_adcb, MCK_Mem, MCK_GR8 } },
    { X86::ADC32rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_adcl, MCK_GR32, MCK_GR32 } },
    { X86::ADC32rr_REV, Convert__Reg1_2__Tie0__Reg1_1, { MCK_adcl, MCK_GR32, MCK_GR32 } },
    { X86::ADC32mr, Convert__Mem5_2__Reg1_1, { MCK_adcl, MCK_GR32, MCK_Mem } },
    { X86::ADC32ri8, Convert__Reg1_2__Tie0__ImmSExt81_1, { MCK_adcl, MCK_ImmSExt8, MCK_GR32 } },
    { X86::ADC32mi8, Convert__Mem5_2__ImmSExt81_1, { MCK_adcl, MCK_ImmSExt8, MCK_Mem } },
    { X86::ADC32i32, Convert__Imm1_1, { MCK_adcl, MCK_Imm, MCK_EAX } },
    { X86::ADC32ri, Convert__Reg1_2__Tie0__Imm1_1, { MCK_adcl, MCK_Imm, MCK_GR32 } },
    { X86::ADC32mi, Convert__Mem5_2__Imm1_1, { MCK_adcl, MCK_Imm, MCK_Mem } },
    { X86::ADC32rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_adcl, MCK_Mem, MCK_GR32 } },
    { X86::ADC64rr_REV, Convert__Reg1_2__Tie0__Reg1_1, { MCK_adcq, MCK_GR64, MCK_GR32 } },
    { X86::ADC64rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_adcq, MCK_GR64, MCK_GR64 } },
    { X86::ADC64mr, Convert__Mem5_2__Reg1_1, { MCK_adcq, MCK_GR64, MCK_Mem } },
    { X86::ADC64ri8, Convert__Reg1_2__Tie0__ImmSExt81_1, { MCK_adcq, MCK_ImmSExt8, MCK_GR64 } },
    { X86::ADC64mi8, Convert__Mem5_2__ImmSExt81_1, { MCK_adcq, MCK_ImmSExt8, MCK_Mem } },
    { X86::ADC64i32, Convert__Imm1_1, { MCK_adcq, MCK_Imm, MCK_RAX } },
    { X86::ADC64ri32, Convert__Reg1_2__Tie0__Imm1_1, { MCK_adcq, MCK_Imm, MCK_GR64 } },
    { X86::ADC64mi32, Convert__Mem5_2__Imm1_1, { MCK_adcq, MCK_Imm, MCK_Mem } },
    { X86::ADC64rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_adcq, MCK_Mem, MCK_GR64 } },
    { X86::ADC16rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_adcw, MCK_GR16, MCK_GR16 } },
    { X86::ADC16rr_REV, Convert__Reg1_2__Tie0__Reg1_1, { MCK_adcw, MCK_GR16, MCK_GR16 } },
    { X86::ADC16mr, Convert__Mem5_2__Reg1_1, { MCK_adcw, MCK_GR16, MCK_Mem } },
    { X86::ADC16ri8, Convert__Reg1_2__Tie0__ImmSExt81_1, { MCK_adcw, MCK_ImmSExt8, MCK_GR16 } },
    { X86::ADC16mi8, Convert__Mem5_2__ImmSExt81_1, { MCK_adcw, MCK_ImmSExt8, MCK_Mem } },
    { X86::ADC16i16, Convert__Imm1_1, { MCK_adcw, MCK_Imm, MCK_AX } },
    { X86::ADC16ri, Convert__Reg1_2__Tie0__Imm1_1, { MCK_adcw, MCK_Imm, MCK_GR16 } },
    { X86::ADC16mi, Convert__Mem5_2__Imm1_1, { MCK_adcw, MCK_Imm, MCK_Mem } },
    { X86::ADC16rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_adcw, MCK_Mem, MCK_GR16 } },
    { X86::ADD8mrmrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_addb, MCK_GR8, MCK_GR8 } },
    { X86::ADD8rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_addb, MCK_GR8, MCK_GR8 } },
    { X86::ADD8mr, Convert__Mem5_2__Reg1_1, { MCK_addb, MCK_GR8, MCK_Mem } },
    { X86::ADD8i8, Convert__Imm1_1, { MCK_addb, MCK_Imm, MCK_AL } },
    { X86::ADD8ri, Convert__Reg1_2__Tie0__Imm1_1, { MCK_addb, MCK_Imm, MCK_GR8 } },
    { X86::ADD8mi, Convert__Mem5_2__Imm1_1, { MCK_addb, MCK_Imm, MCK_Mem } },
    { X86::ADD8rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_addb, MCK_Mem, MCK_GR8 } },
    { X86::ADD32mrmrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_addl, MCK_GR16, MCK_GR16 } },
    { X86::ADD32rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_addl, MCK_GR32, MCK_GR32 } },
    { X86::ADD32mr, Convert__Mem5_2__Reg1_1, { MCK_addl, MCK_GR32, MCK_Mem } },
    { X86::ADD64mrmrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_addl, MCK_GR64, MCK_GR64 } },
    { X86::ADD32ri8, Convert__Reg1_2__Tie0__ImmSExt81_1, { MCK_addl, MCK_ImmSExt8, MCK_GR32 } },
    { X86::ADD32mi8, Convert__Mem5_2__ImmSExt81_1, { MCK_addl, MCK_ImmSExt8, MCK_Mem } },
    { X86::ADD32i32, Convert__Imm1_1, { MCK_addl, MCK_Imm, MCK_EAX } },
    { X86::ADD32ri, Convert__Reg1_2__Tie0__Imm1_1, { MCK_addl, MCK_Imm, MCK_GR32 } },
    { X86::ADD32mi, Convert__Mem5_2__Imm1_1, { MCK_addl, MCK_Imm, MCK_Mem } },
    { X86::ADD32rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_addl, MCK_Mem, MCK_GR32 } },
    { X86::ADDPDrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_addpd, MCK_FR32, MCK_FR32 } },
    { X86::ADDPDrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_addpd, MCK_Mem, MCK_FR32 } },
    { X86::ADDPSrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_addps, MCK_FR32, MCK_FR32 } },
    { X86::ADDPSrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_addps, MCK_Mem, MCK_FR32 } },
    { X86::ADD64rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_addq, MCK_GR64, MCK_GR64 } },
    { X86::ADD64mr, Convert__Mem5_2__Reg1_1, { MCK_addq, MCK_GR64, MCK_Mem } },
    { X86::ADD64ri8, Convert__Reg1_2__Tie0__ImmSExt81_1, { MCK_addq, MCK_ImmSExt8, MCK_GR64 } },
    { X86::ADD64mi8, Convert__Mem5_2__ImmSExt81_1, { MCK_addq, MCK_ImmSExt8, MCK_Mem } },
    { X86::ADD64i32, Convert__Imm1_1, { MCK_addq, MCK_Imm, MCK_RAX } },
    { X86::ADD64ri32, Convert__Reg1_2__Tie0__Imm1_1, { MCK_addq, MCK_Imm, MCK_GR64 } },
    { X86::ADD64mi32, Convert__Mem5_2__Imm1_1, { MCK_addq, MCK_Imm, MCK_Mem } },
    { X86::ADD64rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_addq, MCK_Mem, MCK_GR64 } },
    { X86::ADDSDrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_addsd, MCK_FR32, MCK_FR32 } },
    { X86::ADDSDrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_addsd, MCK_Mem, MCK_FR32 } },
    { X86::ADDSSrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_addss, MCK_FR32, MCK_FR32 } },
    { X86::ADDSSrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_addss, MCK_Mem, MCK_FR32 } },
    { X86::ADDSUBPDrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_addsubpd, MCK_FR32, MCK_FR32 } },
    { X86::ADDSUBPDrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_addsubpd, MCK_Mem, MCK_FR32 } },
    { X86::ADDSUBPSrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_addsubps, MCK_FR32, MCK_FR32 } },
    { X86::ADDSUBPSrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_addsubps, MCK_Mem, MCK_FR32 } },
    { X86::ADD16mrmrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_addw, MCK_GR16, MCK_GR16 } },
    { X86::ADD16rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_addw, MCK_GR16, MCK_GR16 } },
    { X86::ADD16mr, Convert__Mem5_2__Reg1_1, { MCK_addw, MCK_GR16, MCK_Mem } },
    { X86::ADD16ri8, Convert__Reg1_2__Tie0__ImmSExt81_1, { MCK_addw, MCK_ImmSExt8, MCK_GR16 } },
    { X86::ADD16mi8, Convert__Mem5_2__ImmSExt81_1, { MCK_addw, MCK_ImmSExt8, MCK_Mem } },
    { X86::ADD16i16, Convert__Imm1_1, { MCK_addw, MCK_Imm, MCK_AX } },
    { X86::ADD16ri, Convert__Reg1_2__Tie0__Imm1_1, { MCK_addw, MCK_Imm, MCK_GR16 } },
    { X86::ADD16mi, Convert__Mem5_2__Imm1_1, { MCK_addw, MCK_Imm, MCK_Mem } },
    { X86::ADD16rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_addw, MCK_Mem, MCK_GR16 } },
    { X86::AND8rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_andb, MCK_GR8, MCK_GR8 } },
    { X86::AND8rr_REV, Convert__Reg1_2__Tie0__Reg1_1, { MCK_andb, MCK_GR8, MCK_GR8 } },
    { X86::AND8mr, Convert__Mem5_2__Reg1_1, { MCK_andb, MCK_GR8, MCK_Mem } },
    { X86::AND8i8, Convert__Imm1_1, { MCK_andb, MCK_Imm, MCK_AL } },
    { X86::AND8ri, Convert__Reg1_2__Tie0__Imm1_1, { MCK_andb, MCK_Imm, MCK_GR8 } },
    { X86::AND8mi, Convert__Mem5_2__Imm1_1, { MCK_andb, MCK_Imm, MCK_Mem } },
    { X86::AND8rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_andb, MCK_Mem, MCK_GR8 } },
    { X86::AND32rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_andl, MCK_GR32, MCK_GR32 } },
    { X86::AND32rr_REV, Convert__Reg1_2__Tie0__Reg1_1, { MCK_andl, MCK_GR32, MCK_GR32 } },
    { X86::AND32mr, Convert__Mem5_2__Reg1_1, { MCK_andl, MCK_GR32, MCK_Mem } },
    { X86::AND32ri8, Convert__Reg1_2__Tie0__ImmSExt81_1, { MCK_andl, MCK_ImmSExt8, MCK_GR32 } },
    { X86::AND32mi8, Convert__Mem5_2__ImmSExt81_1, { MCK_andl, MCK_ImmSExt8, MCK_Mem } },
    { X86::AND32i32, Convert__Imm1_1, { MCK_andl, MCK_Imm, MCK_EAX } },
    { X86::AND32ri, Convert__Reg1_2__Tie0__Imm1_1, { MCK_andl, MCK_Imm, MCK_GR32 } },
    { X86::AND32mi, Convert__Mem5_2__Imm1_1, { MCK_andl, MCK_Imm, MCK_Mem } },
    { X86::AND32rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_andl, MCK_Mem, MCK_GR32 } },
    { X86::ANDNPDrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_andnpd, MCK_FR32, MCK_FR32 } },
    { X86::FsANDNPDrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_andnpd, MCK_FR32, MCK_FR32 } },
    { X86::ANDNPDrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_andnpd, MCK_Mem, MCK_FR32 } },
    { X86::FsANDNPDrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_andnpd, MCK_Mem, MCK_FR32 } },
    { X86::ANDNPSrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_andnps, MCK_FR32, MCK_FR32 } },
    { X86::FsANDNPSrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_andnps, MCK_FR32, MCK_FR32 } },
    { X86::ANDNPSrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_andnps, MCK_Mem, MCK_FR32 } },
    { X86::FsANDNPSrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_andnps, MCK_Mem, MCK_FR32 } },
    { X86::ANDPDrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_andpd, MCK_FR32, MCK_FR32 } },
    { X86::FsANDPDrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_andpd, MCK_FR32, MCK_FR32 } },
    { X86::ANDPDrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_andpd, MCK_Mem, MCK_FR32 } },
    { X86::FsANDPDrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_andpd, MCK_Mem, MCK_FR32 } },
    { X86::ANDPSrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_andps, MCK_FR32, MCK_FR32 } },
    { X86::FsANDPSrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_andps, MCK_FR32, MCK_FR32 } },
    { X86::ANDPSrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_andps, MCK_Mem, MCK_FR32 } },
    { X86::FsANDPSrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_andps, MCK_Mem, MCK_FR32 } },
    { X86::AND64rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_andq, MCK_GR64, MCK_GR64 } },
    { X86::AND64rr_REV, Convert__Reg1_2__Tie0__Reg1_1, { MCK_andq, MCK_GR64, MCK_GR64 } },
    { X86::AND64mr, Convert__Mem5_2__Reg1_1, { MCK_andq, MCK_GR64, MCK_Mem } },
    { X86::AND64ri8, Convert__Reg1_2__Tie0__ImmSExt81_1, { MCK_andq, MCK_ImmSExt8, MCK_GR64 } },
    { X86::AND64mi8, Convert__Mem5_2__ImmSExt81_1, { MCK_andq, MCK_ImmSExt8, MCK_Mem } },
    { X86::AND64i32, Convert__Imm1_1, { MCK_andq, MCK_Imm, MCK_RAX } },
    { X86::AND64ri32, Convert__Reg1_2__Tie0__Imm1_1, { MCK_andq, MCK_Imm, MCK_GR64 } },
    { X86::AND64mi32, Convert__Mem5_2__Imm1_1, { MCK_andq, MCK_Imm, MCK_Mem } },
    { X86::AND64rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_andq, MCK_Mem, MCK_GR64 } },
    { X86::AND16rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_andw, MCK_GR16, MCK_GR16 } },
    { X86::AND16rr_REV, Convert__Reg1_2__Tie0__Reg1_1, { MCK_andw, MCK_GR16, MCK_GR16 } },
    { X86::AND16mr, Convert__Mem5_2__Reg1_1, { MCK_andw, MCK_GR16, MCK_Mem } },
    { X86::AND16ri8, Convert__Reg1_2__Tie0__ImmSExt81_1, { MCK_andw, MCK_ImmSExt8, MCK_GR16 } },
    { X86::AND16mi8, Convert__Mem5_2__ImmSExt81_1, { MCK_andw, MCK_ImmSExt8, MCK_Mem } },
    { X86::AND16i16, Convert__Imm1_1, { MCK_andw, MCK_Imm, MCK_AX } },
    { X86::AND16ri, Convert__Reg1_2__Tie0__Imm1_1, { MCK_andw, MCK_Imm, MCK_GR16 } },
    { X86::AND16mi, Convert__Mem5_2__Imm1_1, { MCK_andw, MCK_Imm, MCK_Mem } },
    { X86::AND16rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_andw, MCK_Mem, MCK_GR16 } },
    { X86::BSF32rr, Convert__Reg1_2__Reg1_1, { MCK_bsfl, MCK_GR32, MCK_GR32 } },
    { X86::BSF32rm, Convert__Reg1_2__Mem5_1, { MCK_bsfl, MCK_Mem, MCK_GR32 } },
    { X86::BSF64rr, Convert__Reg1_2__Reg1_1, { MCK_bsfq, MCK_GR64, MCK_GR64 } },
    { X86::BSF64rm, Convert__Reg1_2__Mem5_1, { MCK_bsfq, MCK_Mem, MCK_GR64 } },
    { X86::BSF16rr, Convert__Reg1_2__Reg1_1, { MCK_bsfw, MCK_GR16, MCK_GR16 } },
    { X86::BSF16rm, Convert__Reg1_2__Mem5_1, { MCK_bsfw, MCK_Mem, MCK_GR16 } },
    { X86::BSR32rr, Convert__Reg1_2__Reg1_1, { MCK_bsrl, MCK_GR32, MCK_GR32 } },
    { X86::BSR32rm, Convert__Reg1_2__Mem5_1, { MCK_bsrl, MCK_Mem, MCK_GR32 } },
    { X86::BSR64rr, Convert__Reg1_2__Reg1_1, { MCK_bsrq, MCK_GR64, MCK_GR64 } },
    { X86::BSR64rm, Convert__Reg1_2__Mem5_1, { MCK_bsrq, MCK_Mem, MCK_GR64 } },
    { X86::BSR16rr, Convert__Reg1_2__Reg1_1, { MCK_bsrw, MCK_GR16, MCK_GR16 } },
    { X86::BSR16rm, Convert__Reg1_2__Mem5_1, { MCK_bsrw, MCK_Mem, MCK_GR16 } },
    { X86::BTC32rr, Convert__Reg1_2__Reg1_1, { MCK_btcl, MCK_GR32, MCK_GR32 } },
    { X86::BTC32mr, Convert__Mem5_2__Reg1_1, { MCK_btcl, MCK_GR32, MCK_Mem } },
    { X86::BTC32ri8, Convert__Reg1_2__ImmSExt81_1, { MCK_btcl, MCK_ImmSExt8, MCK_GR32 } },
    { X86::BTC32mi8, Convert__Mem5_2__ImmSExt81_1, { MCK_btcl, MCK_ImmSExt8, MCK_Mem } },
    { X86::BTC64rr, Convert__Reg1_2__Reg1_1, { MCK_btcq, MCK_GR64, MCK_GR64 } },
    { X86::BTC64mr, Convert__Mem5_2__Reg1_1, { MCK_btcq, MCK_GR64, MCK_Mem } },
    { X86::BTC64ri8, Convert__Reg1_2__ImmSExt81_1, { MCK_btcq, MCK_ImmSExt8, MCK_GR64 } },
    { X86::BTC64mi8, Convert__Mem5_2__ImmSExt81_1, { MCK_btcq, MCK_ImmSExt8, MCK_Mem } },
    { X86::BTC16rr, Convert__Reg1_2__Reg1_1, { MCK_btcw, MCK_GR16, MCK_GR16 } },
    { X86::BTC16mr, Convert__Mem5_2__Reg1_1, { MCK_btcw, MCK_GR16, MCK_Mem } },
    { X86::BTC16ri8, Convert__Reg1_2__ImmSExt81_1, { MCK_btcw, MCK_ImmSExt8, MCK_GR16 } },
    { X86::BTC16mi8, Convert__Mem5_2__ImmSExt81_1, { MCK_btcw, MCK_ImmSExt8, MCK_Mem } },
    { X86::BT32rr, Convert__Reg1_2__Reg1_1, { MCK_btl, MCK_GR32, MCK_GR32 } },
    { X86::BT32mr, Convert__Mem5_2__Reg1_1, { MCK_btl, MCK_GR32, MCK_Mem } },
    { X86::BT32ri8, Convert__Reg1_2__ImmSExt81_1, { MCK_btl, MCK_ImmSExt8, MCK_GR32 } },
    { X86::BT32mi8, Convert__Mem5_2__ImmSExt81_1, { MCK_btl, MCK_ImmSExt8, MCK_Mem } },
    { X86::BT64rr, Convert__Reg1_2__Reg1_1, { MCK_btq, MCK_GR64, MCK_GR64 } },
    { X86::BT64mr, Convert__Mem5_2__Reg1_1, { MCK_btq, MCK_GR64, MCK_Mem } },
    { X86::BT64ri8, Convert__Reg1_2__ImmSExt81_1, { MCK_btq, MCK_ImmSExt8, MCK_GR64 } },
    { X86::BT64mi8, Convert__Mem5_2__ImmSExt81_1, { MCK_btq, MCK_ImmSExt8, MCK_Mem } },
    { X86::BTR32rr, Convert__Reg1_2__Reg1_1, { MCK_btrl, MCK_GR32, MCK_GR32 } },
    { X86::BTR32mr, Convert__Mem5_2__Reg1_1, { MCK_btrl, MCK_GR32, MCK_Mem } },
    { X86::BTR32ri8, Convert__Reg1_2__ImmSExt81_1, { MCK_btrl, MCK_ImmSExt8, MCK_GR32 } },
    { X86::BTR32mi8, Convert__Mem5_2__ImmSExt81_1, { MCK_btrl, MCK_ImmSExt8, MCK_Mem } },
    { X86::BTR64rr, Convert__Reg1_2__Reg1_1, { MCK_btrq, MCK_GR64, MCK_GR64 } },
    { X86::BTR64mr, Convert__Mem5_2__Reg1_1, { MCK_btrq, MCK_GR64, MCK_Mem } },
    { X86::BTR64ri8, Convert__Reg1_2__ImmSExt81_1, { MCK_btrq, MCK_ImmSExt8, MCK_GR64 } },
    { X86::BTR64mi8, Convert__Mem5_2__ImmSExt81_1, { MCK_btrq, MCK_ImmSExt8, MCK_Mem } },
    { X86::BTR16rr, Convert__Reg1_2__Reg1_1, { MCK_btrw, MCK_GR16, MCK_GR16 } },
    { X86::BTR16mr, Convert__Mem5_2__Reg1_1, { MCK_btrw, MCK_GR16, MCK_Mem } },
    { X86::BTR16ri8, Convert__Reg1_2__ImmSExt81_1, { MCK_btrw, MCK_ImmSExt8, MCK_GR16 } },
    { X86::BTR16mi8, Convert__Mem5_2__ImmSExt81_1, { MCK_btrw, MCK_ImmSExt8, MCK_Mem } },
    { X86::BTS32rr, Convert__Reg1_2__Reg1_1, { MCK_btsl, MCK_GR32, MCK_GR32 } },
    { X86::BTS32mr, Convert__Mem5_2__Reg1_1, { MCK_btsl, MCK_GR32, MCK_Mem } },
    { X86::BTS32ri8, Convert__Reg1_2__ImmSExt81_1, { MCK_btsl, MCK_ImmSExt8, MCK_GR32 } },
    { X86::BTS32mi8, Convert__Mem5_2__ImmSExt81_1, { MCK_btsl, MCK_ImmSExt8, MCK_Mem } },
    { X86::BTS64rr, Convert__Reg1_2__Reg1_1, { MCK_btsq, MCK_GR64, MCK_GR64 } },
    { X86::BTS64mr, Convert__Mem5_2__Reg1_1, { MCK_btsq, MCK_GR64, MCK_Mem } },
    { X86::BTS64ri8, Convert__Reg1_2__ImmSExt81_1, { MCK_btsq, MCK_ImmSExt8, MCK_GR64 } },
    { X86::BTS64mi8, Convert__Mem5_2__ImmSExt81_1, { MCK_btsq, MCK_ImmSExt8, MCK_Mem } },
    { X86::BTS16rr, Convert__Reg1_2__Reg1_1, { MCK_btsw, MCK_GR16, MCK_GR16 } },
    { X86::BTS16mr, Convert__Mem5_2__Reg1_1, { MCK_btsw, MCK_GR16, MCK_Mem } },
    { X86::BTS16ri8, Convert__Reg1_2__ImmSExt81_1, { MCK_btsw, MCK_ImmSExt8, MCK_GR16 } },
    { X86::BTS16mi8, Convert__Mem5_2__ImmSExt81_1, { MCK_btsw, MCK_ImmSExt8, MCK_Mem } },
    { X86::BT16rr, Convert__Reg1_2__Reg1_1, { MCK_btw, MCK_GR16, MCK_GR16 } },
    { X86::BT16mr, Convert__Mem5_2__Reg1_1, { MCK_btw, MCK_GR16, MCK_Mem } },
    { X86::BT16ri8, Convert__Reg1_2__ImmSExt81_1, { MCK_btw, MCK_ImmSExt8, MCK_GR16 } },
    { X86::BT16mi8, Convert__Mem5_2__ImmSExt81_1, { MCK_btw, MCK_ImmSExt8, MCK_Mem } },
    { X86::CALL32r, Convert__Reg1_2, { MCK_call, MCK__STAR_, MCK_GR32 } },
    { X86::WINCALL64r, Convert__Reg1_2, { MCK_call, MCK__STAR_, MCK_GR64 } },
    { X86::CALL32m, Convert__Mem5_2, { MCK_call, MCK__STAR_, MCK_Mem } },
    { X86::WINCALL64m, Convert__Mem5_2, { MCK_call, MCK__STAR_, MCK_Mem } },
    { X86::CALL64r, Convert__Reg1_2, { MCK_callq, MCK__STAR_, MCK_GR64 } },
    { X86::CALL64m, Convert__Mem5_2, { MCK_callq, MCK__STAR_, MCK_Mem } },
    { X86::CMOVAE32rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_cmovael, MCK_GR32, MCK_GR32 } },
    { X86::CMOVAE32rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_cmovael, MCK_Mem, MCK_GR32 } },
    { X86::CMOVAE64rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_cmovaeq, MCK_GR64, MCK_GR64 } },
    { X86::CMOVAE64rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_cmovaeq, MCK_Mem, MCK_GR64 } },
    { X86::CMOVAE16rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_cmovaew, MCK_GR16, MCK_GR16 } },
    { X86::CMOVAE16rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_cmovaew, MCK_Mem, MCK_GR16 } },
    { X86::CMOVA32rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_cmoval, MCK_GR32, MCK_GR32 } },
    { X86::CMOVA32rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_cmoval, MCK_Mem, MCK_GR32 } },
    { X86::CMOVA64rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_cmovaq, MCK_GR64, MCK_GR64 } },
    { X86::CMOVA64rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_cmovaq, MCK_Mem, MCK_GR64 } },
    { X86::CMOVA16rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_cmovaw, MCK_GR16, MCK_GR16 } },
    { X86::CMOVA16rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_cmovaw, MCK_Mem, MCK_GR16 } },
    { X86::CMOVBE32rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_cmovbel, MCK_GR32, MCK_GR32 } },
    { X86::CMOVBE32rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_cmovbel, MCK_Mem, MCK_GR32 } },
    { X86::CMOVBE64rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_cmovbeq, MCK_GR64, MCK_GR64 } },
    { X86::CMOVBE64rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_cmovbeq, MCK_Mem, MCK_GR64 } },
    { X86::CMOVBE16rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_cmovbew, MCK_GR16, MCK_GR16 } },
    { X86::CMOVBE16rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_cmovbew, MCK_Mem, MCK_GR16 } },
    { X86::CMOVB32rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_cmovbl, MCK_GR32, MCK_GR32 } },
    { X86::CMOVB32rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_cmovbl, MCK_Mem, MCK_GR32 } },
    { X86::CMOVB64rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_cmovbq, MCK_GR64, MCK_GR64 } },
    { X86::CMOVB64rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_cmovbq, MCK_Mem, MCK_GR64 } },
    { X86::CMOVB16rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_cmovbw, MCK_GR16, MCK_GR16 } },
    { X86::CMOVB16rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_cmovbw, MCK_Mem, MCK_GR16 } },
    { X86::CMOVE32rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_cmovel, MCK_GR32, MCK_GR32 } },
    { X86::CMOVE32rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_cmovel, MCK_Mem, MCK_GR32 } },
    { X86::CMOVE64rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_cmoveq, MCK_GR64, MCK_GR64 } },
    { X86::CMOVE64rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_cmoveq, MCK_Mem, MCK_GR64 } },
    { X86::CMOVE16rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_cmovew, MCK_GR16, MCK_GR16 } },
    { X86::CMOVE16rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_cmovew, MCK_Mem, MCK_GR16 } },
    { X86::CMOVGE32rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_cmovgel, MCK_GR32, MCK_GR32 } },
    { X86::CMOVGE32rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_cmovgel, MCK_Mem, MCK_GR32 } },
    { X86::CMOVGE64rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_cmovgeq, MCK_GR64, MCK_GR64 } },
    { X86::CMOVGE64rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_cmovgeq, MCK_Mem, MCK_GR64 } },
    { X86::CMOVGE16rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_cmovgew, MCK_GR16, MCK_GR16 } },
    { X86::CMOVGE16rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_cmovgew, MCK_Mem, MCK_GR16 } },
    { X86::CMOVG32rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_cmovgl, MCK_GR32, MCK_GR32 } },
    { X86::CMOVG32rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_cmovgl, MCK_Mem, MCK_GR32 } },
    { X86::CMOVG64rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_cmovgq, MCK_GR64, MCK_GR64 } },
    { X86::CMOVG64rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_cmovgq, MCK_Mem, MCK_GR64 } },
    { X86::CMOVG16rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_cmovgw, MCK_GR16, MCK_GR16 } },
    { X86::CMOVG16rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_cmovgw, MCK_Mem, MCK_GR16 } },
    { X86::CMOVLE32rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_cmovlel, MCK_GR32, MCK_GR32 } },
    { X86::CMOVLE32rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_cmovlel, MCK_Mem, MCK_GR32 } },
    { X86::CMOVLE64rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_cmovleq, MCK_GR64, MCK_GR64 } },
    { X86::CMOVLE64rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_cmovleq, MCK_Mem, MCK_GR64 } },
    { X86::CMOVLE16rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_cmovlew, MCK_GR16, MCK_GR16 } },
    { X86::CMOVLE16rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_cmovlew, MCK_Mem, MCK_GR16 } },
    { X86::CMOVL32rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_cmovll, MCK_GR32, MCK_GR32 } },
    { X86::CMOVL32rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_cmovll, MCK_Mem, MCK_GR32 } },
    { X86::CMOVL64rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_cmovlq, MCK_GR64, MCK_GR64 } },
    { X86::CMOVL64rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_cmovlq, MCK_Mem, MCK_GR64 } },
    { X86::CMOVL16rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_cmovlw, MCK_GR16, MCK_GR16 } },
    { X86::CMOVL16rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_cmovlw, MCK_Mem, MCK_GR16 } },
    { X86::CMOVNE32rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_cmovnel, MCK_GR32, MCK_GR32 } },
    { X86::CMOVNE32rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_cmovnel, MCK_Mem, MCK_GR32 } },
    { X86::CMOVNE64rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_cmovneq, MCK_GR64, MCK_GR64 } },
    { X86::CMOVNE64rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_cmovneq, MCK_Mem, MCK_GR64 } },
    { X86::CMOVNE16rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_cmovnew, MCK_GR16, MCK_GR16 } },
    { X86::CMOVNE16rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_cmovnew, MCK_Mem, MCK_GR16 } },
    { X86::CMOVNO32rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_cmovnol, MCK_GR32, MCK_GR32 } },
    { X86::CMOVNO32rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_cmovnol, MCK_Mem, MCK_GR32 } },
    { X86::CMOVNO64rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_cmovnoq, MCK_GR64, MCK_GR64 } },
    { X86::CMOVNO64rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_cmovnoq, MCK_Mem, MCK_GR64 } },
    { X86::CMOVNO16rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_cmovnow, MCK_GR16, MCK_GR16 } },
    { X86::CMOVNO16rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_cmovnow, MCK_Mem, MCK_GR16 } },
    { X86::CMOVNP32rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_cmovnpl, MCK_GR32, MCK_GR32 } },
    { X86::CMOVNP32rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_cmovnpl, MCK_Mem, MCK_GR32 } },
    { X86::CMOVNP64rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_cmovnpq, MCK_GR64, MCK_GR64 } },
    { X86::CMOVNP64rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_cmovnpq, MCK_Mem, MCK_GR64 } },
    { X86::CMOVNP16rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_cmovnpw, MCK_GR16, MCK_GR16 } },
    { X86::CMOVNP16rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_cmovnpw, MCK_Mem, MCK_GR16 } },
    { X86::CMOVNS32rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_cmovnsl, MCK_GR32, MCK_GR32 } },
    { X86::CMOVNS32rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_cmovnsl, MCK_Mem, MCK_GR32 } },
    { X86::CMOVNS64rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_cmovnsq, MCK_GR64, MCK_GR64 } },
    { X86::CMOVNS64rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_cmovnsq, MCK_Mem, MCK_GR64 } },
    { X86::CMOVNS16rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_cmovnsw, MCK_GR16, MCK_GR16 } },
    { X86::CMOVNS16rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_cmovnsw, MCK_Mem, MCK_GR16 } },
    { X86::CMOVO32rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_cmovol, MCK_GR32, MCK_GR32 } },
    { X86::CMOVO32rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_cmovol, MCK_Mem, MCK_GR32 } },
    { X86::CMOVO64rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_cmovoq, MCK_GR64, MCK_GR64 } },
    { X86::CMOVO64rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_cmovoq, MCK_Mem, MCK_GR64 } },
    { X86::CMOVO16rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_cmovow, MCK_GR16, MCK_GR16 } },
    { X86::CMOVO16rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_cmovow, MCK_Mem, MCK_GR16 } },
    { X86::CMOVP32rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_cmovpl, MCK_GR32, MCK_GR32 } },
    { X86::CMOVP32rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_cmovpl, MCK_Mem, MCK_GR32 } },
    { X86::CMOVP64rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_cmovpq, MCK_GR64, MCK_GR64 } },
    { X86::CMOVP64rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_cmovpq, MCK_Mem, MCK_GR64 } },
    { X86::CMOVP16rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_cmovpw, MCK_GR16, MCK_GR16 } },
    { X86::CMOVP16rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_cmovpw, MCK_Mem, MCK_GR16 } },
    { X86::CMOVS32rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_cmovsl, MCK_GR32, MCK_GR32 } },
    { X86::CMOVS32rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_cmovsl, MCK_Mem, MCK_GR32 } },
    { X86::CMOVS64rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_cmovsq, MCK_GR64, MCK_GR64 } },
    { X86::CMOVS64rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_cmovsq, MCK_Mem, MCK_GR64 } },
    { X86::CMOVS16rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_cmovsw, MCK_GR16, MCK_GR16 } },
    { X86::CMOVS16rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_cmovsw, MCK_Mem, MCK_GR16 } },
    { X86::CMP8mrmrr, Convert__Reg1_2__Reg1_1, { MCK_cmpb, MCK_GR8, MCK_GR8 } },
    { X86::CMP8rr, Convert__Reg1_2__Reg1_1, { MCK_cmpb, MCK_GR8, MCK_GR8 } },
    { X86::CMP8mr, Convert__Mem5_2__Reg1_1, { MCK_cmpb, MCK_GR8, MCK_Mem } },
    { X86::CMP8i8, Convert__Imm1_1, { MCK_cmpb, MCK_Imm, MCK_AL } },
    { X86::CMP8ri, Convert__Reg1_2__Imm1_1, { MCK_cmpb, MCK_Imm, MCK_GR8 } },
    { X86::CMP8mi, Convert__Mem5_2__Imm1_1, { MCK_cmpb, MCK_Imm, MCK_Mem } },
    { X86::CMP8rm, Convert__Reg1_2__Mem5_1, { MCK_cmpb, MCK_Mem, MCK_GR8 } },
    { X86::CMP32mrmrr, Convert__Reg1_2__Reg1_1, { MCK_cmpl, MCK_GR32, MCK_GR32 } },
    { X86::CMP32rr, Convert__Reg1_2__Reg1_1, { MCK_cmpl, MCK_GR32, MCK_GR32 } },
    { X86::CMP32mr, Convert__Mem5_2__Reg1_1, { MCK_cmpl, MCK_GR32, MCK_Mem } },
    { X86::CMP32ri8, Convert__Reg1_2__ImmSExt81_1, { MCK_cmpl, MCK_ImmSExt8, MCK_GR32 } },
    { X86::CMP32mi8, Convert__Mem5_2__ImmSExt81_1, { MCK_cmpl, MCK_ImmSExt8, MCK_Mem } },
    { X86::CMP32i32, Convert__Imm1_1, { MCK_cmpl, MCK_Imm, MCK_EAX } },
    { X86::CMP32ri, Convert__Reg1_2__Imm1_1, { MCK_cmpl, MCK_Imm, MCK_GR32 } },
    { X86::CMP32mi, Convert__Mem5_2__Imm1_1, { MCK_cmpl, MCK_Imm, MCK_Mem } },
    { X86::CMP32rm, Convert__Reg1_2__Mem5_1, { MCK_cmpl, MCK_Mem, MCK_GR32 } },
    { X86::CMP64mrmrr, Convert__Reg1_2__Reg1_1, { MCK_cmpq, MCK_GR64, MCK_GR64 } },
    { X86::CMP64rr, Convert__Reg1_2__Reg1_1, { MCK_cmpq, MCK_GR64, MCK_GR64 } },
    { X86::CMP64mr, Convert__Mem5_2__Reg1_1, { MCK_cmpq, MCK_GR64, MCK_Mem } },
    { X86::CMP64ri8, Convert__Reg1_2__ImmSExt81_1, { MCK_cmpq, MCK_ImmSExt8, MCK_GR64 } },
    { X86::CMP64mi8, Convert__Mem5_2__ImmSExt81_1, { MCK_cmpq, MCK_ImmSExt8, MCK_Mem } },
    { X86::CMP64i32, Convert__Imm1_1, { MCK_cmpq, MCK_Imm, MCK_RAX } },
    { X86::CMP64ri32, Convert__Reg1_2__Imm1_1, { MCK_cmpq, MCK_Imm, MCK_GR64 } },
    { X86::CMP64mi32, Convert__Mem5_2__Imm1_1, { MCK_cmpq, MCK_Imm, MCK_Mem } },
    { X86::CMP64rm, Convert__Reg1_2__Mem5_1, { MCK_cmpq, MCK_Mem, MCK_GR64 } },
    { X86::CMP16mrmrr, Convert__Reg1_2__Reg1_1, { MCK_cmpw, MCK_GR16, MCK_GR16 } },
    { X86::CMP16rr, Convert__Reg1_2__Reg1_1, { MCK_cmpw, MCK_GR16, MCK_GR16 } },
    { X86::CMP16mr, Convert__Mem5_2__Reg1_1, { MCK_cmpw, MCK_GR16, MCK_Mem } },
    { X86::CMP16ri8, Convert__Reg1_2__ImmSExt81_1, { MCK_cmpw, MCK_ImmSExt8, MCK_GR16 } },
    { X86::CMP16mi8, Convert__Mem5_2__ImmSExt81_1, { MCK_cmpw, MCK_ImmSExt8, MCK_Mem } },
    { X86::CMP16i16, Convert__Imm1_1, { MCK_cmpw, MCK_Imm, MCK_AX } },
    { X86::CMP16ri, Convert__Reg1_2__Imm1_1, { MCK_cmpw, MCK_Imm, MCK_GR16 } },
    { X86::CMP16mi, Convert__Mem5_2__Imm1_1, { MCK_cmpw, MCK_Imm, MCK_Mem } },
    { X86::CMP16rm, Convert__Reg1_2__Mem5_1, { MCK_cmpw, MCK_Mem, MCK_GR16 } },
    { X86::CMPXCHG8rr, Convert__Reg1_2__Reg1_1, { MCK_cmpxchgb, MCK_GR8, MCK_GR8 } },
    { X86::CMPXCHG8rm, Convert__Mem5_2__Reg1_1, { MCK_cmpxchgb, MCK_GR8, MCK_Mem } },
    { X86::CMPXCHG32rr, Convert__Reg1_2__Reg1_1, { MCK_cmpxchgl, MCK_GR32, MCK_GR32 } },
    { X86::CMPXCHG32rm, Convert__Mem5_2__Reg1_1, { MCK_cmpxchgl, MCK_GR32, MCK_Mem } },
    { X86::CMPXCHG64rr, Convert__Reg1_2__Reg1_1, { MCK_cmpxchgq, MCK_GR64, MCK_GR64 } },
    { X86::CMPXCHG64rm, Convert__Mem5_2__Reg1_1, { MCK_cmpxchgq, MCK_GR64, MCK_Mem } },
    { X86::CMPXCHG16rr, Convert__Reg1_2__Reg1_1, { MCK_cmpxchgw, MCK_GR16, MCK_GR16 } },
    { X86::CMPXCHG16rm, Convert__Mem5_2__Reg1_1, { MCK_cmpxchgw, MCK_GR16, MCK_Mem } },
    { X86::COMISDrr, Convert__Reg1_2__Reg1_1, { MCK_comisd, MCK_FR32, MCK_FR32 } },
    { X86::COMISDrm, Convert__Reg1_2__Mem5_1, { MCK_comisd, MCK_Mem, MCK_FR32 } },
    { X86::COMISSrr, Convert__Reg1_2__Reg1_1, { MCK_comiss, MCK_FR32, MCK_FR32 } },
    { X86::COMISSrm, Convert__Reg1_2__Mem5_1, { MCK_comiss, MCK_Mem, MCK_FR32 } },
    { X86::CRC32r8, Convert__Reg1_2__Tie0__Reg1_1, { MCK_crc32, MCK_GR8, MCK_GR32 } },
    { X86::CRC32r16, Convert__Reg1_2__Tie0__Reg1_1, { MCK_crc32, MCK_GR16, MCK_GR32 } },
    { X86::CRC32r32, Convert__Reg1_2__Tie0__Reg1_1, { MCK_crc32, MCK_GR32, MCK_GR32 } },
    { X86::CRC64r64, Convert__Reg1_2__Tie0__Reg1_1, { MCK_crc32, MCK_GR64, MCK_GR64 } },
    { X86::CRC32m16, Convert__Reg1_2__Tie0__Mem5_1, { MCK_crc32, MCK_Mem, MCK_GR32 } },
    { X86::CRC32m32, Convert__Reg1_2__Tie0__Mem5_1, { MCK_crc32, MCK_Mem, MCK_GR32 } },
    { X86::CRC32m8, Convert__Reg1_2__Tie0__Mem5_1, { MCK_crc32, MCK_Mem, MCK_GR32 } },
    { X86::CRC64m64, Convert__Reg1_2__Tie0__Mem5_1, { MCK_crc32, MCK_Mem, MCK_GR64 } },
    { X86::CVTDQ2PDrr, Convert__Reg1_2__Reg1_1, { MCK_cvtdq2pd, MCK_FR32, MCK_FR32 } },
    { X86::CVTDQ2PDrm, Convert__Reg1_2__Mem5_1, { MCK_cvtdq2pd, MCK_Mem, MCK_FR32 } },
    { X86::CVTDQ2PSrr, Convert__Reg1_2__Reg1_1, { MCK_cvtdq2ps, MCK_FR32, MCK_FR32 } },
    { X86::CVTDQ2PSrm, Convert__Reg1_2__Mem5_1, { MCK_cvtdq2ps, MCK_Mem, MCK_FR32 } },
    { X86::CVTPD2DQrr, Convert__Reg1_2__Reg1_1, { MCK_cvtpd2dq, MCK_FR32, MCK_FR32 } },
    { X86::CVTPD2DQrm, Convert__Reg1_2__Mem5_1, { MCK_cvtpd2dq, MCK_Mem, MCK_FR32 } },
    { X86::MMX_CVTPD2PIrr, Convert__Reg1_2__Reg1_1, { MCK_cvtpd2pi, MCK_FR32, MCK_VR64 } },
    { X86::MMX_CVTPD2PIrm, Convert__Reg1_2__Mem5_1, { MCK_cvtpd2pi, MCK_Mem, MCK_VR64 } },
    { X86::CVTPD2PSrr, Convert__Reg1_2__Reg1_1, { MCK_cvtpd2ps, MCK_FR32, MCK_FR32 } },
    { X86::CVTPD2PSrm, Convert__Reg1_2__Mem5_1, { MCK_cvtpd2ps, MCK_Mem, MCK_FR32 } },
    { X86::MMX_CVTPI2PDrr, Convert__Reg1_2__Reg1_1, { MCK_cvtpi2pd, MCK_VR64, MCK_FR32 } },
    { X86::MMX_CVTPI2PDrm, Convert__Reg1_2__Mem5_1, { MCK_cvtpi2pd, MCK_Mem, MCK_FR32 } },
    { X86::MMX_CVTPI2PSrr, Convert__Reg1_2__Reg1_1, { MCK_cvtpi2ps, MCK_VR64, MCK_FR32 } },
    { X86::MMX_CVTPI2PSrm, Convert__Reg1_2__Mem5_1, { MCK_cvtpi2ps, MCK_Mem, MCK_FR32 } },
    { X86::CVTPS2DQrr, Convert__Reg1_2__Reg1_1, { MCK_cvtps2dq, MCK_FR32, MCK_FR32 } },
    { X86::CVTPS2DQrm, Convert__Reg1_2__Mem5_1, { MCK_cvtps2dq, MCK_Mem, MCK_FR32 } },
    { X86::CVTPS2PDrr, Convert__Reg1_2__Reg1_1, { MCK_cvtps2pd, MCK_FR32, MCK_FR32 } },
    { X86::CVTPS2PDrm, Convert__Reg1_2__Mem5_1, { MCK_cvtps2pd, MCK_Mem, MCK_FR32 } },
    { X86::MMX_CVTPS2PIrr, Convert__Reg1_2__Reg1_1, { MCK_cvtps2pi, MCK_FR32, MCK_VR64 } },
    { X86::MMX_CVTPS2PIrm, Convert__Reg1_2__Mem5_1, { MCK_cvtps2pi, MCK_Mem, MCK_VR64 } },
    { X86::CVTSD2SI64rr, Convert__Reg1_2__Reg1_1, { MCK_cvtsd2siq, MCK_FR32, MCK_GR64 } },
    { X86::CVTSD2SI64rm, Convert__Reg1_2__Mem5_1, { MCK_cvtsd2siq, MCK_Mem, MCK_GR64 } },
    { X86::CVTSD2SSrr, Convert__Reg1_2__Reg1_1, { MCK_cvtsd2ss, MCK_FR32, MCK_FR32 } },
    { X86::CVTSD2SSrm, Convert__Reg1_2__Mem5_1, { MCK_cvtsd2ss, MCK_Mem, MCK_FR32 } },
    { X86::CVTSI2SDrr, Convert__Reg1_2__Reg1_1, { MCK_cvtsi2sd, MCK_GR32, MCK_FR32 } },
    { X86::CVTSI2SDrm, Convert__Reg1_2__Mem5_1, { MCK_cvtsi2sd, MCK_Mem, MCK_FR32 } },
    { X86::CVTSI2SD64rr, Convert__Reg1_2__Reg1_1, { MCK_cvtsi2sdq, MCK_GR64, MCK_FR32 } },
    { X86::CVTSI2SD64rm, Convert__Reg1_2__Mem5_1, { MCK_cvtsi2sdq, MCK_Mem, MCK_FR32 } },
    { X86::CVTSI2SSrr, Convert__Reg1_2__Reg1_1, { MCK_cvtsi2ss, MCK_GR32, MCK_FR32 } },
    { X86::CVTSI2SSrm, Convert__Reg1_2__Mem5_1, { MCK_cvtsi2ss, MCK_Mem, MCK_FR32 } },
    { X86::CVTSI2SS64rr, Convert__Reg1_2__Reg1_1, { MCK_cvtsi2ssq, MCK_GR64, MCK_FR32 } },
    { X86::CVTSI2SS64rm, Convert__Reg1_2__Mem5_1, { MCK_cvtsi2ssq, MCK_Mem, MCK_FR32 } },
    { X86::CVTSS2SDrr, Convert__Reg1_2__Reg1_1, { MCK_cvtss2sd, MCK_FR32, MCK_FR32 } },
    { X86::CVTSS2SDrm, Convert__Reg1_2__Mem5_1, { MCK_cvtss2sd, MCK_Mem, MCK_FR32 } },
    { X86::CVTSS2SIrr, Convert__Reg1_2__Reg1_1, { MCK_cvtss2sil, MCK_FR32, MCK_GR32 } },
    { X86::CVTSS2SIrm, Convert__Reg1_2__Mem5_1, { MCK_cvtss2sil, MCK_Mem, MCK_GR32 } },
    { X86::CVTSS2SI64rr, Convert__Reg1_2__Reg1_1, { MCK_cvtss2siq, MCK_FR32, MCK_GR64 } },
    { X86::CVTSS2SI64rm, Convert__Reg1_2__Mem5_1, { MCK_cvtss2siq, MCK_Mem, MCK_GR64 } },
    { X86::MMX_CVTTPD2PIrr, Convert__Reg1_2__Reg1_1, { MCK_cvttpd2pi, MCK_FR32, MCK_VR64 } },
    { X86::MMX_CVTTPD2PIrm, Convert__Reg1_2__Mem5_1, { MCK_cvttpd2pi, MCK_Mem, MCK_VR64 } },
    { X86::CVTTPS2DQrr, Convert__Reg1_2__Reg1_1, { MCK_cvttps2dq, MCK_FR32, MCK_FR32 } },
    { X86::CVTTPS2DQrm, Convert__Reg1_2__Mem5_1, { MCK_cvttps2dq, MCK_Mem, MCK_FR32 } },
    { X86::MMX_CVTTPS2PIrr, Convert__Reg1_2__Reg1_1, { MCK_cvttps2pi, MCK_FR32, MCK_VR64 } },
    { X86::MMX_CVTTPS2PIrm, Convert__Reg1_2__Mem5_1, { MCK_cvttps2pi, MCK_Mem, MCK_VR64 } },
    { X86::CVTTSD2SIrr, Convert__Reg1_2__Reg1_1, { MCK_cvttsd2si, MCK_FR32, MCK_GR32 } },
    { X86::CVTTSD2SIrm, Convert__Reg1_2__Mem5_1, { MCK_cvttsd2si, MCK_Mem, MCK_GR32 } },
    { X86::CVTTSD2SI64rr, Convert__Reg1_2__Reg1_1, { MCK_cvttsd2siq, MCK_FR32, MCK_GR64 } },
    { X86::CVTTSD2SI64rm, Convert__Reg1_2__Mem5_1, { MCK_cvttsd2siq, MCK_Mem, MCK_GR64 } },
    { X86::CVTTSS2SIrr, Convert__Reg1_2__Reg1_1, { MCK_cvttss2si, MCK_FR32, MCK_GR32 } },
    { X86::CVTTSS2SIrm, Convert__Reg1_2__Mem5_1, { MCK_cvttss2si, MCK_Mem, MCK_GR32 } },
    { X86::CVTTSS2SI64rr, Convert__Reg1_2__Reg1_1, { MCK_cvttss2siq, MCK_FR32, MCK_GR64 } },
    { X86::CVTTSS2SI64rm, Convert__Reg1_2__Mem5_1, { MCK_cvttss2siq, MCK_Mem, MCK_GR64 } },
    { X86::DIVPDrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_divpd, MCK_FR32, MCK_FR32 } },
    { X86::DIVPDrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_divpd, MCK_Mem, MCK_FR32 } },
    { X86::DIVPSrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_divps, MCK_FR32, MCK_FR32 } },
    { X86::DIVPSrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_divps, MCK_Mem, MCK_FR32 } },
    { X86::DIVSDrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_divsd, MCK_FR32, MCK_FR32 } },
    { X86::DIVSDrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_divsd, MCK_Mem, MCK_FR32 } },
    { X86::DIVSSrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_divss, MCK_FR32, MCK_FR32 } },
    { X86::DIVSSrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_divss, MCK_Mem, MCK_FR32 } },
    { X86::ENTER, Convert__Imm1_1__Imm1_2, { MCK_enter, MCK_Imm, MCK_Imm } },
    { X86::ADD_FrST0, Convert__Reg1_2, { MCK_fadd, MCK_ST0, MCK_RST } },
    { X86::CMOVB_F, Convert__Reg1_1, { MCK_fcmovb, MCK_RST, MCK_ST0 } },
    { X86::CMOVBE_F, Convert__Reg1_1, { MCK_fcmovbe, MCK_RST, MCK_ST0 } },
    { X86::CMOVE_F, Convert__Reg1_1, { MCK_fcmove, MCK_RST, MCK_ST0 } },
    { X86::CMOVNB_F, Convert__Reg1_1, { MCK_fcmovnb, MCK_RST, MCK_ST0 } },
    { X86::CMOVNBE_F, Convert__Reg1_1, { MCK_fcmovnbe, MCK_RST, MCK_ST0 } },
    { X86::CMOVNE_F, Convert__Reg1_1, { MCK_fcmovne, MCK_RST, MCK_ST0 } },
    { X86::CMOVNP_F, Convert__Reg1_1, { MCK_fcmovnu, MCK_RST, MCK_ST0 } },
    { X86::CMOVP_F, Convert__Reg1_1, { MCK_fcmovu, MCK_RST, MCK_ST0 } },
    { X86::COM_FIr, Convert__Reg1_1, { MCK_fcomi, MCK_RST, MCK_ST0 } },
    { X86::COM_FIPr, Convert__Reg1_1, { MCK_fcomip, MCK_RST, MCK_ST0 } },
    { X86::DIVR_FrST0, Convert__Reg1_2, { MCK_fdiv, MCK_ST0, MCK_RST } },
    { X86::DIV_FrST0, Convert__Reg1_2, { MCK_fdivr, MCK_ST0, MCK_RST } },
    { X86::MUL_FrST0, Convert__Reg1_2, { MCK_fmul, MCK_ST0, MCK_RST } },
    { X86::SUBR_FrST0, Convert__Reg1_2, { MCK_fsub, MCK_ST0, MCK_RST } },
    { X86::SUB_FrST0, Convert__Reg1_2, { MCK_fsubr, MCK_ST0, MCK_RST } },
    { X86::UCOM_FIr, Convert__Reg1_1, { MCK_fucomi, MCK_RST, MCK_ST0 } },
    { X86::UCOM_FIPr, Convert__Reg1_1, { MCK_fucomip, MCK_RST, MCK_ST0 } },
    { X86::HADDPDrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_haddpd, MCK_FR32, MCK_FR32 } },
    { X86::HADDPDrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_haddpd, MCK_Mem, MCK_FR32 } },
    { X86::HADDPSrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_haddps, MCK_FR32, MCK_FR32 } },
    { X86::HADDPSrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_haddps, MCK_Mem, MCK_FR32 } },
    { X86::HSUBPDrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_hsubpd, MCK_FR32, MCK_FR32 } },
    { X86::HSUBPDrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_hsubpd, MCK_Mem, MCK_FR32 } },
    { X86::HSUBPSrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_hsubps, MCK_FR32, MCK_FR32 } },
    { X86::HSUBPSrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_hsubps, MCK_Mem, MCK_FR32 } },
    { X86::IMUL32rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_imull, MCK_GR32, MCK_GR32 } },
    { X86::IMUL32rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_imull, MCK_Mem, MCK_GR32 } },
    { X86::IMUL64rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_imulq, MCK_GR64, MCK_GR64 } },
    { X86::IMUL64rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_imulq, MCK_Mem, MCK_GR64 } },
    { X86::IMUL16rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_imulw, MCK_GR16, MCK_GR16 } },
    { X86::IMUL16rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_imulw, MCK_Mem, MCK_GR16 } },
    { X86::IN8rr, Convert, { MCK_inb, MCK_DX, MCK_AL } },
    { X86::IN8ri, Convert__ImmSExt81_1, { MCK_inb, MCK_ImmSExt8, MCK_AL } },
    { X86::IN32rr, Convert, { MCK_inl, MCK_DX, MCK_EAX } },
    { X86::IN32ri, Convert__ImmSExt81_1, { MCK_inl, MCK_ImmSExt8, MCK_EAX } },
    { X86::IN16rr, Convert, { MCK_inw, MCK_DX, MCK_AX } },
    { X86::IN16ri, Convert__ImmSExt81_1, { MCK_inw, MCK_ImmSExt8, MCK_AX } },
    { X86::TAILJMPm, Convert__Mem5_2, { MCK_jmp, MCK__STAR_, MCK_Mem } },
    { X86::JMP32r, Convert__Reg1_2, { MCK_jmpl, MCK__STAR_, MCK_GR32 } },
    { X86::TAILJMPr, Convert__Reg1_2, { MCK_jmpl, MCK__STAR_, MCK_GR32 } },
    { X86::JMP32m, Convert__Mem5_2, { MCK_jmpl, MCK__STAR_, MCK_Mem } },
    { X86::JMP64r, Convert__Reg1_2, { MCK_jmpq, MCK__STAR_, MCK_GR64 } },
    { X86::TAILJMPr64, Convert__Reg1_2, { MCK_jmpq, MCK__STAR_, MCK_GR64 } },
    { X86::JMP64m, Convert__Mem5_2, { MCK_jmpq, MCK__STAR_, MCK_Mem } },
    { X86::LAR32rr, Convert__Reg1_2__Reg1_1, { MCK_larl, MCK_GR32, MCK_GR32 } },
    { X86::LAR32rm, Convert__Reg1_2__Mem5_1, { MCK_larl, MCK_Mem, MCK_GR32 } },
    { X86::LAR64rr, Convert__Reg1_2__Reg1_1, { MCK_larq, MCK_GR32, MCK_GR64 } },
    { X86::LAR64rm, Convert__Reg1_2__Mem5_1, { MCK_larq, MCK_Mem, MCK_GR64 } },
    { X86::LAR16rr, Convert__Reg1_2__Reg1_1, { MCK_larw, MCK_GR16, MCK_GR16 } },
    { X86::LAR16rm, Convert__Reg1_2__Mem5_1, { MCK_larw, MCK_Mem, MCK_GR16 } },
    { X86::FARCALL32m, Convert__Mem5_2, { MCK_lcalll, MCK__STAR_, MCK_Mem } },
    { X86::FARCALL32i, Convert__Imm1_1__Imm1_2, { MCK_lcalll, MCK_Imm, MCK_Imm } },
    { X86::FARCALL64, Convert__Mem5_2, { MCK_lcallq, MCK__STAR_, MCK_Mem } },
    { X86::FARCALL16m, Convert__Mem5_2, { MCK_lcallw, MCK__STAR_, MCK_Mem } },
    { X86::FARCALL16i, Convert__Imm1_1__Imm1_2, { MCK_lcallw, MCK_Imm, MCK_Imm } },
    { X86::LDDQUrm, Convert__Reg1_2__Mem5_1, { MCK_lddqu, MCK_Mem, MCK_FR32 } },
    { X86::LDS32rm, Convert__Reg1_2__Mem5_1, { MCK_ldsl, MCK_Mem, MCK_GR32 } },
    { X86::LDS16rm, Convert__Reg1_2__Mem5_1, { MCK_ldsw, MCK_Mem, MCK_GR16 } },
    { X86::LEA32r, Convert__Reg1_2__NoSegMem4_1, { MCK_leal, MCK_NoSegMem, MCK_GR32 } },
    { X86::LEA64_32r, Convert__Reg1_2__Mem4_1, { MCK_leal, MCK_Mem, MCK_GR32 } },
    { X86::LEA64r, Convert__Reg1_2__Mem4_1, { MCK_leaq, MCK_Mem, MCK_GR64 } },
    { X86::LEA16r, Convert__Reg1_2__NoSegMem4_1, { MCK_leaw, MCK_NoSegMem, MCK_GR16 } },
    { X86::LES32rm, Convert__Reg1_2__Mem5_1, { MCK_lesl, MCK_Mem, MCK_GR32 } },
    { X86::LES16rm, Convert__Reg1_2__Mem5_1, { MCK_lesw, MCK_Mem, MCK_GR16 } },
    { X86::LFS32rm, Convert__Reg1_2__Mem5_1, { MCK_lfsl, MCK_Mem, MCK_GR32 } },
    { X86::LFS64rm, Convert__Reg1_2__Mem5_1, { MCK_lfsq, MCK_Mem, MCK_GR64 } },
    { X86::LFS16rm, Convert__Reg1_2__Mem5_1, { MCK_lfsw, MCK_Mem, MCK_GR16 } },
    { X86::LGS32rm, Convert__Reg1_2__Mem5_1, { MCK_lgsl, MCK_Mem, MCK_GR32 } },
    { X86::LGS64rm, Convert__Reg1_2__Mem5_1, { MCK_lgsq, MCK_Mem, MCK_GR64 } },
    { X86::LGS16rm, Convert__Reg1_2__Mem5_1, { MCK_lgsw, MCK_Mem, MCK_GR16 } },
    { X86::FARJMP32m, Convert__Mem5_2, { MCK_ljmpl, MCK__STAR_, MCK_Mem } },
    { X86::FARJMP32i, Convert__Imm1_1__Imm1_2, { MCK_ljmpl, MCK_Imm, MCK_Imm } },
    { X86::FARJMP64, Convert__Mem5_2, { MCK_ljmpq, MCK__STAR_, MCK_Mem } },
    { X86::FARJMP16m, Convert__Mem5_2, { MCK_ljmpw, MCK__STAR_, MCK_Mem } },
    { X86::FARJMP16i, Convert__Imm1_1__Imm1_2, { MCK_ljmpw, MCK_Imm, MCK_Imm } },
    { X86::LSL32rr, Convert__Reg1_2__Reg1_1, { MCK_lsll, MCK_GR32, MCK_GR32 } },
    { X86::LSL32rm, Convert__Reg1_2__Mem5_1, { MCK_lsll, MCK_Mem, MCK_GR32 } },
    { X86::LSL64rr, Convert__Reg1_2__Reg1_1, { MCK_lslq, MCK_GR64, MCK_GR64 } },
    { X86::LSL64rm, Convert__Reg1_2__Mem5_1, { MCK_lslq, MCK_Mem, MCK_GR64 } },
    { X86::LSL16rr, Convert__Reg1_2__Reg1_1, { MCK_lslw, MCK_GR16, MCK_GR16 } },
    { X86::LSL16rm, Convert__Reg1_2__Mem5_1, { MCK_lslw, MCK_Mem, MCK_GR16 } },
    { X86::LSS32rm, Convert__Reg1_2__Mem5_1, { MCK_lssl, MCK_Mem, MCK_GR32 } },
    { X86::LSS64rm, Convert__Reg1_2__Mem5_1, { MCK_lssq, MCK_Mem, MCK_GR64 } },
    { X86::LSS16rm, Convert__Reg1_2__Mem5_1, { MCK_lssw, MCK_Mem, MCK_GR16 } },
    { X86::MASKMOVDQU, Convert__Reg1_2__Reg1_1, { MCK_maskmovdqu, MCK_FR32, MCK_FR32 } },
    { X86::MASKMOVDQU64, Convert__Reg1_2__Reg1_1, { MCK_maskmovdqu, MCK_FR32, MCK_FR32 } },
    { X86::MMX_MASKMOVQ, Convert__Reg1_2__Reg1_1, { MCK_maskmovq, MCK_VR64, MCK_VR64 } },
    { X86::MMX_MASKMOVQ64, Convert__Reg1_2__Reg1_1, { MCK_maskmovq, MCK_VR64, MCK_VR64 } },
    { X86::MAXPDrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_maxpd, MCK_FR32, MCK_FR32 } },
    { X86::MAXPDrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_maxpd, MCK_Mem, MCK_FR32 } },
    { X86::MAXPSrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_maxps, MCK_FR32, MCK_FR32 } },
    { X86::MAXPSrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_maxps, MCK_Mem, MCK_FR32 } },
    { X86::MAXSDrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_maxsd, MCK_FR32, MCK_FR32 } },
    { X86::MAXSDrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_maxsd, MCK_Mem, MCK_FR32 } },
    { X86::MAXSSrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_maxss, MCK_FR32, MCK_FR32 } },
    { X86::MAXSSrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_maxss, MCK_Mem, MCK_FR32 } },
    { X86::MINPDrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_minpd, MCK_FR32, MCK_FR32 } },
    { X86::MINPDrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_minpd, MCK_Mem, MCK_FR32 } },
    { X86::MINPSrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_minps, MCK_FR32, MCK_FR32 } },
    { X86::MINPSrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_minps, MCK_Mem, MCK_FR32 } },
    { X86::MINSDrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_minsd, MCK_FR32, MCK_FR32 } },
    { X86::MINSDrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_minsd, MCK_Mem, MCK_FR32 } },
    { X86::MINSSrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_minss, MCK_FR32, MCK_FR32 } },
    { X86::MINSSrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_minss, MCK_Mem, MCK_FR32 } },
    { X86::MOV64ri, Convert__Reg1_2__Imm1_1, { MCK_movabsq, MCK_Imm, MCK_GR64 } },
    { X86::FsMOVAPDrr, Convert__Reg1_2__Reg1_1, { MCK_movapd, MCK_FR32, MCK_FR32 } },
    { X86::MOVAPDrr, Convert__Reg1_2__Reg1_1, { MCK_movapd, MCK_FR32, MCK_FR32 } },
    { X86::MOVAPDmr, Convert__Mem5_2__Reg1_1, { MCK_movapd, MCK_FR32, MCK_Mem } },
    { X86::FsMOVAPDrm, Convert__Reg1_2__Mem5_1, { MCK_movapd, MCK_Mem, MCK_FR32 } },
    { X86::MOVAPDrm, Convert__Reg1_2__Mem5_1, { MCK_movapd, MCK_Mem, MCK_FR32 } },
    { X86::FsMOVAPSrr, Convert__Reg1_2__Reg1_1, { MCK_movaps, MCK_FR32, MCK_FR32 } },
    { X86::MOVAPSrr, Convert__Reg1_2__Reg1_1, { MCK_movaps, MCK_FR32, MCK_FR32 } },
    { X86::MOVAPSmr, Convert__Mem5_2__Reg1_1, { MCK_movaps, MCK_FR32, MCK_Mem } },
    { X86::FsMOVAPSrm, Convert__Reg1_2__Mem5_1, { MCK_movaps, MCK_Mem, MCK_FR32 } },
    { X86::MOVAPSrm, Convert__Reg1_2__Mem5_1, { MCK_movaps, MCK_Mem, MCK_FR32 } },
    { X86::MOV8ao8, Convert__AbsMem1_2, { MCK_movb, MCK_AL, MCK_AbsMem } },
    { X86::MOV8rr_NOREX, Convert__Reg1_2__Reg1_1, { MCK_movb, MCK_GR8_NOREX, MCK_GR8_NOREX } },
    { X86::MOV8mr_NOREX, Convert__Mem5_2__Reg1_1, { MCK_movb, MCK_GR8_NOREX, MCK_Mem } },
    { X86::MOV8rr, Convert__Reg1_2__Reg1_1, { MCK_movb, MCK_GR8, MCK_GR8 } },
    { X86::MOV8rr_REV, Convert__Reg1_2__Reg1_1, { MCK_movb, MCK_GR8, MCK_GR8 } },
    { X86::MOV8mr, Convert__Mem5_2__Reg1_1, { MCK_movb, MCK_GR8, MCK_Mem } },
    { X86::MOV8ri, Convert__Reg1_2__Imm1_1, { MCK_movb, MCK_Imm, MCK_GR8 } },
    { X86::MOV8mi, Convert__Mem5_2__Imm1_1, { MCK_movb, MCK_Imm, MCK_Mem } },
    { X86::MOV8o8a, Convert__AbsMem1_1, { MCK_movb, MCK_AbsMem, MCK_AL } },
    { X86::MOV8rm_NOREX, Convert__Reg1_2__Mem5_1, { MCK_movb, MCK_Mem, MCK_GR8_NOREX } },
    { X86::MOV8rm, Convert__Reg1_2__Mem5_1, { MCK_movb, MCK_Mem, MCK_GR8 } },
    { X86::MMX_MOVD64rr, Convert__Reg1_2__Reg1_1, { MCK_movd, MCK_GR32, MCK_VR64 } },
    { X86::MMX_MOVZDI2PDIrr, Convert__Reg1_2__Reg1_1, { MCK_movd, MCK_GR32, MCK_VR64 } },
    { X86::MOVDI2PDIrr, Convert__Reg1_2__Reg1_1, { MCK_movd, MCK_GR32, MCK_FR32 } },
    { X86::MOVDI2SSrr, Convert__Reg1_2__Reg1_1, { MCK_movd, MCK_GR32, MCK_FR32 } },
    { X86::MOVZDI2PDIrr, Convert__Reg1_2__Reg1_1, { MCK_movd, MCK_GR32, MCK_FR32 } },
    { X86::MMX_MOVD64rrv164, Convert__Reg1_2__Reg1_1, { MCK_movd, MCK_GR64, MCK_VR64 } },
    { X86::MMX_MOVD64to64rr, Convert__Reg1_2__Reg1_1, { MCK_movd, MCK_GR64, MCK_VR64 } },
    { X86::MOV64toPQIrr, Convert__Reg1_2__Reg1_1, { MCK_movd, MCK_GR64, MCK_FR32 } },
    { X86::MOV64toSDrr, Convert__Reg1_2__Reg1_1, { MCK_movd, MCK_GR64, MCK_FR32 } },
    { X86::MOVZQI2PQIrr, Convert__Reg1_2__Reg1_1, { MCK_movd, MCK_GR64, MCK_FR32 } },
    { X86::MMX_MOVD64grr, Convert__Reg1_2__Reg1_1, { MCK_movd, MCK_VR64, MCK_GR32 } },
    { X86::MMX_MOVD64from64rr, Convert__Reg1_2__Reg1_1, { MCK_movd, MCK_VR64, MCK_GR64 } },
    { X86::MMX_MOVD64mr, Convert__Mem5_2__Reg1_1, { MCK_movd, MCK_VR64, MCK_Mem } },
    { X86::MOVPDI2DIrr, Convert__Reg1_2__Reg1_1, { MCK_movd, MCK_FR32, MCK_GR32 } },
    { X86::MOVSS2DIrr, Convert__Reg1_2__Reg1_1, { MCK_movd, MCK_FR32, MCK_GR32 } },
    { X86::MOVPQIto64rr, Convert__Reg1_2__Reg1_1, { MCK_movd, MCK_FR32, MCK_GR64 } },
    { X86::MOVSDto64rr, Convert__Reg1_2__Reg1_1, { MCK_movd, MCK_FR32, MCK_GR64 } },
    { X86::MOVPDI2DImr, Convert__Mem5_2__Reg1_1, { MCK_movd, MCK_FR32, MCK_Mem } },
    { X86::MOVSS2DImr, Convert__Mem5_2__Reg1_1, { MCK_movd, MCK_FR32, MCK_Mem } },
    { X86::MMX_MOVD64rm, Convert__Reg1_2__Mem5_1, { MCK_movd, MCK_Mem, MCK_VR64 } },
    { X86::MMX_MOVZDI2PDIrm, Convert__Reg1_2__Mem5_1, { MCK_movd, MCK_Mem, MCK_VR64 } },
    { X86::MOVDI2PDIrm, Convert__Reg1_2__Mem5_1, { MCK_movd, MCK_Mem, MCK_FR32 } },
    { X86::MOVDI2SSrm, Convert__Reg1_2__Mem5_1, { MCK_movd, MCK_Mem, MCK_FR32 } },
    { X86::MOVZDI2PDIrm, Convert__Reg1_2__Mem5_1, { MCK_movd, MCK_Mem, MCK_FR32 } },
    { X86::MOVDDUPrr, Convert__Reg1_2__Reg1_1, { MCK_movddup, MCK_FR32, MCK_FR32 } },
    { X86::MOVDDUPrm, Convert__Reg1_2__Mem5_1, { MCK_movddup, MCK_Mem, MCK_FR32 } },
    { X86::MMX_MOVDQ2Qrr, Convert__Reg1_2__Reg1_1, { MCK_movdq2q, MCK_FR32, MCK_VR64 } },
    { X86::MOVDQArr, Convert__Reg1_2__Reg1_1, { MCK_movdqa, MCK_FR32, MCK_FR32 } },
    { X86::MOVDQAmr, Convert__Mem5_2__Reg1_1, { MCK_movdqa, MCK_FR32, MCK_Mem } },
    { X86::MOVDQArm, Convert__Reg1_2__Mem5_1, { MCK_movdqa, MCK_Mem, MCK_FR32 } },
    { X86::MOVDQUmr, Convert__Mem5_2__Reg1_1, { MCK_movdqu, MCK_FR32, MCK_Mem } },
    { X86::MOVDQUrm, Convert__Reg1_2__Mem5_1, { MCK_movdqu, MCK_Mem, MCK_FR32 } },
    { X86::MOVHLPSrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_movhlps, MCK_FR32, MCK_FR32 } },
    { X86::MOVHPDmr, Convert__Mem5_2__Reg1_1, { MCK_movhpd, MCK_FR32, MCK_Mem } },
    { X86::MOVHPDrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_movhpd, MCK_Mem, MCK_FR32 } },
    { X86::MOVHPSmr, Convert__Mem5_2__Reg1_1, { MCK_movhps, MCK_FR32, MCK_Mem } },
    { X86::MOVHPSrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_movhps, MCK_Mem, MCK_FR32 } },
    { X86::MOV32ao32, Convert__AbsMem1_2, { MCK_movl, MCK_EAX, MCK_AbsMem } },
    { X86::MOV32rr, Convert__Reg1_2__Reg1_1, { MCK_movl, MCK_GR32, MCK_GR32 } },
    { X86::MOV32rr_REV, Convert__Reg1_2__Reg1_1, { MCK_movl, MCK_GR32, MCK_GR32 } },
    { X86::MOV32dr, Convert__Reg1_2__Reg1_1, { MCK_movl, MCK_GR32, MCK_DEBUG_REG } },
    { X86::MOV32mr, Convert__Mem5_2__Reg1_1, { MCK_movl, MCK_GR32, MCK_Mem } },
    { X86::MOV32rd, Convert__Reg1_2__Reg1_1, { MCK_movl, MCK_DEBUG_REG, MCK_GR32 } },
    { X86::MOV32ri, Convert__Reg1_2__Imm1_1, { MCK_movl, MCK_Imm, MCK_GR32 } },
    { X86::MOV32mi, Convert__Mem5_2__Imm1_1, { MCK_movl, MCK_Imm, MCK_Mem } },
    { X86::MOV32o32a, Convert__AbsMem1_1, { MCK_movl, MCK_AbsMem, MCK_EAX } },
    { X86::MOV32rm, Convert__Reg1_2__Mem5_1, { MCK_movl, MCK_Mem, MCK_GR32 } },
    { X86::MOVLHPSrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_movlhps, MCK_FR32, MCK_FR32 } },
    { X86::MOVLPDmr, Convert__Mem5_2__Reg1_1, { MCK_movlpd, MCK_FR32, MCK_Mem } },
    { X86::MOVLPDrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_movlpd, MCK_Mem, MCK_FR32 } },
    { X86::MOVLPSmr, Convert__Mem5_2__Reg1_1, { MCK_movlps, MCK_FR32, MCK_Mem } },
    { X86::MOVLPSrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_movlps, MCK_Mem, MCK_FR32 } },
    { X86::MOVMSKPDrr, Convert__Reg1_2__Reg1_1, { MCK_movmskpd, MCK_FR32, MCK_GR32 } },
    { X86::MOVMSKPSrr, Convert__Reg1_2__Reg1_1, { MCK_movmskps, MCK_FR32, MCK_GR32 } },
    { X86::MOVNTDQ_64mr, Convert__Mem5_2__Reg1_1, { MCK_movntdq, MCK_FR32, MCK_Mem } },
    { X86::MOVNTDQmr, Convert__Mem5_2__Reg1_1, { MCK_movntdq, MCK_FR32, MCK_Mem } },
    { X86::MOVNTDQArm, Convert__Reg1_2__Mem5_1, { MCK_movntdqa, MCK_Mem, MCK_FR32 } },
    { X86::MOVNTImr, Convert__Mem5_2__Reg1_1, { MCK_movnti, MCK_GR32, MCK_Mem } },
    { X86::MOVNTI_64mr, Convert__Mem5_2__Reg1_1, { MCK_movnti, MCK_GR64, MCK_Mem } },
    { X86::MOVNTPDmr, Convert__Mem5_2__Reg1_1, { MCK_movntpd, MCK_FR32, MCK_Mem } },
    { X86::MOVNTPSmr, Convert__Mem5_2__Reg1_1, { MCK_movntps, MCK_FR32, MCK_Mem } },
    { X86::MMX_MOVNTQmr, Convert__Mem5_2__Reg1_1, { MCK_movntq, MCK_VR64, MCK_Mem } },
    { X86::MOV32cr, Convert__Reg1_2__Reg1_1, { MCK_movq, MCK_GR32, MCK_CONTROL_REG_32 } },
    { X86::MOV64ao64, Convert__AbsMem1_2, { MCK_movq, MCK_RAX, MCK_AbsMem } },
    { X86::MOV64ao8, Convert__AbsMem1_2, { MCK_movq, MCK_RAX, MCK_AbsMem } },
    { X86::MOV64rr, Convert__Reg1_2__Reg1_1, { MCK_movq, MCK_GR64, MCK_GR64 } },
    { X86::MOV64rr_REV, Convert__Reg1_2__Reg1_1, { MCK_movq, MCK_GR64, MCK_GR64 } },
    { X86::MOV64sr, Convert__Reg1_2__Reg1_1, { MCK_movq, MCK_GR64, MCK_SEGMENT_REG } },
    { X86::MOV64dr, Convert__Reg1_2__Reg1_1, { MCK_movq, MCK_GR64, MCK_DEBUG_REG } },
    { X86::MOV64cr, Convert__Reg1_2__Reg1_1, { MCK_movq, MCK_GR64, MCK_CONTROL_REG_64 } },
    { X86::MOV64mr, Convert__Mem5_2__Reg1_1, { MCK_movq, MCK_GR64, MCK_Mem } },
    { X86::MMX_MOVQ64rr, Convert__Reg1_2__Reg1_1, { MCK_movq, MCK_VR64, MCK_VR64 } },
    { X86::MMX_MOVQ64gmr, Convert__Mem5_2__Reg1_1, { MCK_movq, MCK_VR64, MCK_Mem } },
    { X86::MMX_MOVQ64mr, Convert__Mem5_2__Reg1_1, { MCK_movq, MCK_VR64, MCK_Mem } },
    { X86::MOVQxrxr, Convert__Reg1_2__Reg1_1, { MCK_movq, MCK_FR32, MCK_FR32 } },
    { X86::MOVZPQILo2PQIrr, Convert__Reg1_2__Reg1_1, { MCK_movq, MCK_FR32, MCK_FR32 } },
    { X86::MOVLQ128mr, Convert__Mem5_2__Reg1_1, { MCK_movq, MCK_FR32, MCK_Mem } },
    { X86::MOVPQI2QImr, Convert__Mem5_2__Reg1_1, { MCK_movq, MCK_FR32, MCK_Mem } },
    { X86::MOVSDto64mr, Convert__Mem5_2__Reg1_1, { MCK_movq, MCK_FR32, MCK_Mem } },
    { X86::MOV64rs, Convert__Reg1_2__Reg1_1, { MCK_movq, MCK_SEGMENT_REG, MCK_GR64 } },
    { X86::MOV64ms, Convert__Mem5_2__Reg1_1, { MCK_movq, MCK_SEGMENT_REG, MCK_Mem } },
    { X86::MOV64rd, Convert__Reg1_2__Reg1_1, { MCK_movq, MCK_DEBUG_REG, MCK_GR64 } },
    { X86::MOV32rc, Convert__Reg1_2__Reg1_1, { MCK_movq, MCK_CONTROL_REG_32, MCK_GR32 } },
    { X86::MOV64rc, Convert__Reg1_2__Reg1_1, { MCK_movq, MCK_CONTROL_REG_64, MCK_GR64 } },
    { X86::MOV64ri32, Convert__Reg1_2__Imm1_1, { MCK_movq, MCK_Imm, MCK_GR64 } },
    { X86::MOV64mi32, Convert__Mem5_2__Imm1_1, { MCK_movq, MCK_Imm, MCK_Mem } },
    { X86::MOV64o64a, Convert__AbsMem1_1, { MCK_movq, MCK_AbsMem, MCK_RAX } },
    { X86::MOV64o8a, Convert__AbsMem1_1, { MCK_movq, MCK_AbsMem, MCK_RAX } },
    { X86::MOV64rm, Convert__Reg1_2__Mem5_1, { MCK_movq, MCK_Mem, MCK_GR64 } },
    { X86::MMX_MOVQ64rm, Convert__Reg1_2__Mem5_1, { MCK_movq, MCK_Mem, MCK_VR64 } },
    { X86::MOV64toSDrm, Convert__Reg1_2__Mem5_1, { MCK_movq, MCK_Mem, MCK_FR32 } },
    { X86::MOVQI2PQIrm, Convert__Reg1_2__Mem5_1, { MCK_movq, MCK_Mem, MCK_FR32 } },
    { X86::MOVZPQILo2PQIrm, Convert__Reg1_2__Mem5_1, { MCK_movq, MCK_Mem, MCK_FR32 } },
    { X86::MOVZQI2PQIrm, Convert__Reg1_2__Mem5_1, { MCK_movq, MCK_Mem, MCK_FR32 } },
    { X86::MOV64sm, Convert__Reg1_2__Mem5_1, { MCK_movq, MCK_Mem, MCK_SEGMENT_REG } },
    { X86::MMX_MOVQ2DQrr, Convert__Reg1_2__Reg1_1, { MCK_movq2dq, MCK_VR64, MCK_FR32 } },
    { X86::MMX_MOVQ2FR64rr, Convert__Reg1_2__Reg1_1, { MCK_movq2dq, MCK_VR64, MCK_FR32 } },
    { X86::MOVSX32rr8, Convert__Reg1_2__Reg1_1, { MCK_movsbl, MCK_GR8, MCK_GR32 } },
    { X86::MOVSX32rm8, Convert__Reg1_2__Mem5_1, { MCK_movsbl, MCK_Mem, MCK_GR32 } },
    { X86::MOVSX64rr8, Convert__Reg1_2__Reg1_1, { MCK_movsbq, MCK_GR8, MCK_GR64 } },
    { X86::MOVSX64rm8, Convert__Reg1_2__Mem5_1, { MCK_movsbq, MCK_Mem, MCK_GR64 } },
    { X86::MOVSX16rr8W, Convert__Reg1_2__Reg1_1, { MCK_movsbw, MCK_GR8, MCK_GR16 } },
    { X86::MOVSX16rm8W, Convert__Reg1_2__Mem5_1, { MCK_movsbw, MCK_Mem, MCK_GR16 } },
    { X86::MOVSDrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_movsd, MCK_FR32, MCK_FR32 } },
    { X86::MOVSDmr, Convert__Mem5_2__Reg1_1, { MCK_movsd, MCK_FR32, MCK_Mem } },
    { X86::MOVSDrm, Convert__Reg1_2__Mem5_1, { MCK_movsd, MCK_Mem, MCK_FR32 } },
    { X86::MOVSHDUPrr, Convert__Reg1_2__Reg1_1, { MCK_movshdup, MCK_FR32, MCK_FR32 } },
    { X86::MOVSHDUPrm, Convert__Reg1_2__Mem5_1, { MCK_movshdup, MCK_Mem, MCK_FR32 } },
    { X86::MOVSLDUPrr, Convert__Reg1_2__Reg1_1, { MCK_movsldup, MCK_FR32, MCK_FR32 } },
    { X86::MOVSLDUPrm, Convert__Reg1_2__Mem5_1, { MCK_movsldup, MCK_Mem, MCK_FR32 } },
    { X86::MOVSX64rr32, Convert__Reg1_2__Reg1_1, { MCK_movslq, MCK_GR32, MCK_GR64 } },
    { X86::MOVSX64rm32, Convert__Reg1_2__Mem5_1, { MCK_movslq, MCK_Mem, MCK_GR64 } },
    { X86::MOVSSrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_movss, MCK_FR32, MCK_FR32 } },
    { X86::MOVSSmr, Convert__Mem5_2__Reg1_1, { MCK_movss, MCK_FR32, MCK_Mem } },
    { X86::MOVSSrm, Convert__Reg1_2__Mem5_1, { MCK_movss, MCK_Mem, MCK_FR32 } },
    { X86::MOVSX32rr16, Convert__Reg1_2__Reg1_1, { MCK_movswl, MCK_GR16, MCK_GR32 } },
    { X86::MOVSX32rm16, Convert__Reg1_2__Mem5_1, { MCK_movswl, MCK_Mem, MCK_GR32 } },
    { X86::MOVSX64rr16, Convert__Reg1_2__Reg1_1, { MCK_movswq, MCK_GR16, MCK_GR64 } },
    { X86::MOVSX64rm16, Convert__Reg1_2__Mem5_1, { MCK_movswq, MCK_Mem, MCK_GR64 } },
    { X86::MOVUPDrr, Convert__Reg1_2__Reg1_1, { MCK_movupd, MCK_FR32, MCK_FR32 } },
    { X86::MOVUPDmr, Convert__Mem5_2__Reg1_1, { MCK_movupd, MCK_FR32, MCK_Mem } },
    { X86::MOVUPDrm, Convert__Reg1_2__Mem5_1, { MCK_movupd, MCK_Mem, MCK_FR32 } },
    { X86::MOVUPSrr, Convert__Reg1_2__Reg1_1, { MCK_movups, MCK_FR32, MCK_FR32 } },
    { X86::MOVUPSmr, Convert__Mem5_2__Reg1_1, { MCK_movups, MCK_FR32, MCK_Mem } },
    { X86::MOVUPSrm, Convert__Reg1_2__Mem5_1, { MCK_movups, MCK_Mem, MCK_FR32 } },
    { X86::MOV16ao16, Convert__AbsMem1_2, { MCK_movw, MCK_AX, MCK_AbsMem } },
    { X86::MOV16rr, Convert__Reg1_2__Reg1_1, { MCK_movw, MCK_GR16, MCK_GR16 } },
    { X86::MOV16rr_REV, Convert__Reg1_2__Reg1_1, { MCK_movw, MCK_GR16, MCK_GR16 } },
    { X86::MOV16sr, Convert__Reg1_2__Reg1_1, { MCK_movw, MCK_GR16, MCK_SEGMENT_REG } },
    { X86::MOV16mr, Convert__Mem5_2__Reg1_1, { MCK_movw, MCK_GR16, MCK_Mem } },
    { X86::MOV16rs, Convert__Reg1_2__Reg1_1, { MCK_movw, MCK_SEGMENT_REG, MCK_GR16 } },
    { X86::MOV16ms, Convert__Mem5_2__Reg1_1, { MCK_movw, MCK_SEGMENT_REG, MCK_Mem } },
    { X86::MOV16ri, Convert__Reg1_2__Imm1_1, { MCK_movw, MCK_Imm, MCK_GR16 } },
    { X86::MOV16mi, Convert__Mem5_2__Imm1_1, { MCK_movw, MCK_Imm, MCK_Mem } },
    { X86::MOV16o16a, Convert__AbsMem1_1, { MCK_movw, MCK_AbsMem, MCK_AX } },
    { X86::MOV16rm, Convert__Reg1_2__Mem5_1, { MCK_movw, MCK_Mem, MCK_GR16 } },
    { X86::MOV16sm, Convert__Reg1_2__Mem5_1, { MCK_movw, MCK_Mem, MCK_SEGMENT_REG } },
    { X86::MOVZX32_NOREXrr8, Convert__Reg1_2__Reg1_1, { MCK_movzbl, MCK_GR8, MCK_GR32_NOREX } },
    { X86::MOVZX32rr8, Convert__Reg1_2__Reg1_1, { MCK_movzbl, MCK_GR8, MCK_GR32 } },
    { X86::MOVZX32_NOREXrm8, Convert__Reg1_2__Mem5_1, { MCK_movzbl, MCK_Mem, MCK_GR32_NOREX } },
    { X86::MOVZX32rm8, Convert__Reg1_2__Mem5_1, { MCK_movzbl, MCK_Mem, MCK_GR32 } },
    { X86::MOVZX64rr8_Q, Convert__Reg1_2__Reg1_1, { MCK_movzbq, MCK_GR8, MCK_GR64 } },
    { X86::MOVZX64rm8_Q, Convert__Reg1_2__Mem5_1, { MCK_movzbq, MCK_Mem, MCK_GR64 } },
    { X86::MOVZX16rr8W, Convert__Reg1_2__Reg1_1, { MCK_movzbw, MCK_GR8, MCK_GR16 } },
    { X86::MOVZX16rm8W, Convert__Reg1_2__Mem5_1, { MCK_movzbw, MCK_Mem, MCK_GR16 } },
    { X86::MOVZX32rr16, Convert__Reg1_2__Reg1_1, { MCK_movzwl, MCK_GR16, MCK_GR32 } },
    { X86::MOVZX32rm16, Convert__Reg1_2__Mem5_1, { MCK_movzwl, MCK_Mem, MCK_GR32 } },
    { X86::MOVZX64rr16_Q, Convert__Reg1_2__Reg1_1, { MCK_movzwq, MCK_GR16, MCK_GR64 } },
    { X86::MOVZX64rm16_Q, Convert__Reg1_2__Mem5_1, { MCK_movzwq, MCK_Mem, MCK_GR64 } },
    { X86::MULPDrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_mulpd, MCK_FR32, MCK_FR32 } },
    { X86::MULPDrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_mulpd, MCK_Mem, MCK_FR32 } },
    { X86::MULPSrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_mulps, MCK_FR32, MCK_FR32 } },
    { X86::MULPSrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_mulps, MCK_Mem, MCK_FR32 } },
    { X86::MULSDrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_mulsd, MCK_FR32, MCK_FR32 } },
    { X86::MULSDrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_mulsd, MCK_Mem, MCK_FR32 } },
    { X86::MULSSrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_mulss, MCK_FR32, MCK_FR32 } },
    { X86::MULSSrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_mulss, MCK_Mem, MCK_FR32 } },
    { X86::OR8rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_orb, MCK_GR8, MCK_GR8 } },
    { X86::OR8rr_REV, Convert__Reg1_2__Tie0__Reg1_1, { MCK_orb, MCK_GR8, MCK_GR8 } },
    { X86::OR8mr, Convert__Mem5_2__Reg1_1, { MCK_orb, MCK_GR8, MCK_Mem } },
    { X86::OR8i8, Convert__Imm1_1, { MCK_orb, MCK_Imm, MCK_AL } },
    { X86::OR8ri, Convert__Reg1_2__Tie0__Imm1_1, { MCK_orb, MCK_Imm, MCK_GR8 } },
    { X86::OR8mi, Convert__Mem5_2__Imm1_1, { MCK_orb, MCK_Imm, MCK_Mem } },
    { X86::OR8rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_orb, MCK_Mem, MCK_GR8 } },
    { X86::OR32rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_orl, MCK_GR32, MCK_GR32 } },
    { X86::OR32rr_REV, Convert__Reg1_2__Tie0__Reg1_1, { MCK_orl, MCK_GR32, MCK_GR32 } },
    { X86::OR32mr, Convert__Mem5_2__Reg1_1, { MCK_orl, MCK_GR32, MCK_Mem } },
    { X86::OR32ri8, Convert__Reg1_2__Tie0__ImmSExt81_1, { MCK_orl, MCK_ImmSExt8, MCK_GR32 } },
    { X86::OR32mi8, Convert__Mem5_2__ImmSExt81_1, { MCK_orl, MCK_ImmSExt8, MCK_Mem } },
    { X86::OR32i32, Convert__Imm1_1, { MCK_orl, MCK_Imm, MCK_EAX } },
    { X86::OR32ri, Convert__Reg1_2__Tie0__Imm1_1, { MCK_orl, MCK_Imm, MCK_GR32 } },
    { X86::OR32mi, Convert__Mem5_2__Imm1_1, { MCK_orl, MCK_Imm, MCK_Mem } },
    { X86::OR32rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_orl, MCK_Mem, MCK_GR32 } },
    { X86::FsORPDrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_orpd, MCK_FR32, MCK_FR32 } },
    { X86::ORPDrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_orpd, MCK_FR32, MCK_FR32 } },
    { X86::FsORPDrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_orpd, MCK_Mem, MCK_FR32 } },
    { X86::ORPDrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_orpd, MCK_Mem, MCK_FR32 } },
    { X86::FsORPSrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_orps, MCK_FR32, MCK_FR32 } },
    { X86::ORPSrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_orps, MCK_FR32, MCK_FR32 } },
    { X86::FsORPSrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_orps, MCK_Mem, MCK_FR32 } },
    { X86::ORPSrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_orps, MCK_Mem, MCK_FR32 } },
    { X86::OR64rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_orq, MCK_GR64, MCK_GR64 } },
    { X86::OR64rr_REV, Convert__Reg1_2__Tie0__Reg1_1, { MCK_orq, MCK_GR64, MCK_GR64 } },
    { X86::OR64mr, Convert__Mem5_2__Reg1_1, { MCK_orq, MCK_GR64, MCK_Mem } },
    { X86::OR64ri8, Convert__Reg1_2__Tie0__ImmSExt81_1, { MCK_orq, MCK_ImmSExt8, MCK_GR64 } },
    { X86::OR64mi8, Convert__Mem5_2__ImmSExt81_1, { MCK_orq, MCK_ImmSExt8, MCK_Mem } },
    { X86::OR64i32, Convert__Imm1_1, { MCK_orq, MCK_Imm, MCK_RAX } },
    { X86::OR64ri32, Convert__Reg1_2__Tie0__Imm1_1, { MCK_orq, MCK_Imm, MCK_GR64 } },
    { X86::OR64mi32, Convert__Mem5_2__Imm1_1, { MCK_orq, MCK_Imm, MCK_Mem } },
    { X86::OR64rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_orq, MCK_Mem, MCK_GR64 } },
    { X86::OR16rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_orw, MCK_GR16, MCK_GR16 } },
    { X86::OR16rr_REV, Convert__Reg1_2__Tie0__Reg1_1, { MCK_orw, MCK_GR16, MCK_GR16 } },
    { X86::OR16mr, Convert__Mem5_2__Reg1_1, { MCK_orw, MCK_GR16, MCK_Mem } },
    { X86::OR16ri8, Convert__Reg1_2__Tie0__ImmSExt81_1, { MCK_orw, MCK_ImmSExt8, MCK_GR16 } },
    { X86::OR16mi8, Convert__Mem5_2__ImmSExt81_1, { MCK_orw, MCK_ImmSExt8, MCK_Mem } },
    { X86::OR16i16, Convert__Imm1_1, { MCK_orw, MCK_Imm, MCK_AX } },
    { X86::OR16ri, Convert__Reg1_2__Tie0__Imm1_1, { MCK_orw, MCK_Imm, MCK_GR16 } },
    { X86::OR16mi, Convert__Mem5_2__Imm1_1, { MCK_orw, MCK_Imm, MCK_Mem } },
    { X86::OR16rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_orw, MCK_Mem, MCK_GR16 } },
    { X86::OUT8rr, Convert, { MCK_outb, MCK_AL, MCK_DX } },
    { X86::OUT8ir, Convert__ImmSExt81_2, { MCK_outb, MCK_AL, MCK_ImmSExt8 } },
    { X86::OUT32rr, Convert, { MCK_outl, MCK_EAX, MCK_DX } },
    { X86::OUT32ir, Convert__ImmSExt81_2, { MCK_outl, MCK_EAX, MCK_ImmSExt8 } },
    { X86::OUT16rr, Convert, { MCK_outw, MCK_AX, MCK_DX } },
    { X86::OUT16ir, Convert__ImmSExt81_2, { MCK_outw, MCK_AX, MCK_ImmSExt8 } },
    { X86::PABSBrr64, Convert__Reg1_2__Reg1_1, { MCK_pabsb, MCK_VR64, MCK_VR64 } },
    { X86::PABSBrr128, Convert__Reg1_2__Reg1_1, { MCK_pabsb, MCK_FR32, MCK_FR32 } },
    { X86::PABSBrm64, Convert__Reg1_2__Mem5_1, { MCK_pabsb, MCK_Mem, MCK_VR64 } },
    { X86::PABSBrm128, Convert__Reg1_2__Mem5_1, { MCK_pabsb, MCK_Mem, MCK_FR32 } },
    { X86::PABSDrr64, Convert__Reg1_2__Reg1_1, { MCK_pabsd, MCK_VR64, MCK_VR64 } },
    { X86::PABSDrr128, Convert__Reg1_2__Reg1_1, { MCK_pabsd, MCK_FR32, MCK_FR32 } },
    { X86::PABSDrm64, Convert__Reg1_2__Mem5_1, { MCK_pabsd, MCK_Mem, MCK_VR64 } },
    { X86::PABSDrm128, Convert__Reg1_2__Mem5_1, { MCK_pabsd, MCK_Mem, MCK_FR32 } },
    { X86::PABSWrr64, Convert__Reg1_2__Reg1_1, { MCK_pabsw, MCK_VR64, MCK_VR64 } },
    { X86::PABSWrr128, Convert__Reg1_2__Reg1_1, { MCK_pabsw, MCK_FR32, MCK_FR32 } },
    { X86::PABSWrm64, Convert__Reg1_2__Mem5_1, { MCK_pabsw, MCK_Mem, MCK_VR64 } },
    { X86::PABSWrm128, Convert__Reg1_2__Mem5_1, { MCK_pabsw, MCK_Mem, MCK_FR32 } },
    { X86::MMX_PACKSSDWrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_packssdw, MCK_VR64, MCK_VR64 } },
    { X86::PACKSSDWrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_packssdw, MCK_FR32, MCK_FR32 } },
    { X86::MMX_PACKSSDWrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_packssdw, MCK_Mem, MCK_VR64 } },
    { X86::PACKSSDWrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_packssdw, MCK_Mem, MCK_FR32 } },
    { X86::MMX_PACKSSWBrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_packsswb, MCK_VR64, MCK_VR64 } },
    { X86::PACKSSWBrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_packsswb, MCK_FR32, MCK_FR32 } },
    { X86::MMX_PACKSSWBrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_packsswb, MCK_Mem, MCK_VR64 } },
    { X86::PACKSSWBrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_packsswb, MCK_Mem, MCK_FR32 } },
    { X86::PACKUSDWrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_packusdw, MCK_FR32, MCK_FR32 } },
    { X86::PACKUSDWrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_packusdw, MCK_Mem, MCK_FR32 } },
    { X86::MMX_PACKUSWBrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_packuswb, MCK_VR64, MCK_VR64 } },
    { X86::PACKUSWBrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_packuswb, MCK_FR32, MCK_FR32 } },
    { X86::MMX_PACKUSWBrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_packuswb, MCK_Mem, MCK_VR64 } },
    { X86::PACKUSWBrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_packuswb, MCK_Mem, MCK_FR32 } },
    { X86::MMX_PADDBrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_paddb, MCK_VR64, MCK_VR64 } },
    { X86::PADDBrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_paddb, MCK_FR32, MCK_FR32 } },
    { X86::MMX_PADDBrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_paddb, MCK_Mem, MCK_VR64 } },
    { X86::PADDBrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_paddb, MCK_Mem, MCK_FR32 } },
    { X86::MMX_PADDDrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_paddd, MCK_VR64, MCK_VR64 } },
    { X86::PADDDrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_paddd, MCK_FR32, MCK_FR32 } },
    { X86::MMX_PADDDrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_paddd, MCK_Mem, MCK_VR64 } },
    { X86::PADDDrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_paddd, MCK_Mem, MCK_FR32 } },
    { X86::MMX_PADDQrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_paddq, MCK_VR64, MCK_VR64 } },
    { X86::PADDQrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_paddq, MCK_FR32, MCK_FR32 } },
    { X86::MMX_PADDQrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_paddq, MCK_Mem, MCK_VR64 } },
    { X86::PADDQrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_paddq, MCK_Mem, MCK_FR32 } },
    { X86::MMX_PADDSBrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_paddsb, MCK_VR64, MCK_VR64 } },
    { X86::PADDSBrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_paddsb, MCK_FR32, MCK_FR32 } },
    { X86::MMX_PADDSBrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_paddsb, MCK_Mem, MCK_VR64 } },
    { X86::PADDSBrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_paddsb, MCK_Mem, MCK_FR32 } },
    { X86::MMX_PADDSWrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_paddsw, MCK_VR64, MCK_VR64 } },
    { X86::PADDSWrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_paddsw, MCK_FR32, MCK_FR32 } },
    { X86::MMX_PADDSWrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_paddsw, MCK_Mem, MCK_VR64 } },
    { X86::PADDSWrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_paddsw, MCK_Mem, MCK_FR32 } },
    { X86::MMX_PADDUSBrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_paddusb, MCK_VR64, MCK_VR64 } },
    { X86::PADDUSBrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_paddusb, MCK_FR32, MCK_FR32 } },
    { X86::MMX_PADDUSBrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_paddusb, MCK_Mem, MCK_VR64 } },
    { X86::PADDUSBrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_paddusb, MCK_Mem, MCK_FR32 } },
    { X86::MMX_PADDUSWrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_paddusw, MCK_VR64, MCK_VR64 } },
    { X86::PADDUSWrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_paddusw, MCK_FR32, MCK_FR32 } },
    { X86::MMX_PADDUSWrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_paddusw, MCK_Mem, MCK_VR64 } },
    { X86::PADDUSWrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_paddusw, MCK_Mem, MCK_FR32 } },
    { X86::MMX_PADDWrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_paddw, MCK_VR64, MCK_VR64 } },
    { X86::PADDWrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_paddw, MCK_FR32, MCK_FR32 } },
    { X86::MMX_PADDWrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_paddw, MCK_Mem, MCK_VR64 } },
    { X86::PADDWrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_paddw, MCK_Mem, MCK_FR32 } },
    { X86::MMX_PANDrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_pand, MCK_VR64, MCK_VR64 } },
    { X86::PANDrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_pand, MCK_FR32, MCK_FR32 } },
    { X86::MMX_PANDrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_pand, MCK_Mem, MCK_VR64 } },
    { X86::PANDrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_pand, MCK_Mem, MCK_FR32 } },
    { X86::MMX_PANDNrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_pandn, MCK_VR64, MCK_VR64 } },
    { X86::PANDNrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_pandn, MCK_FR32, MCK_FR32 } },
    { X86::MMX_PANDNrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_pandn, MCK_Mem, MCK_VR64 } },
    { X86::PANDNrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_pandn, MCK_Mem, MCK_FR32 } },
    { X86::MMX_PAVGBrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_pavgb, MCK_VR64, MCK_VR64 } },
    { X86::PAVGBrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_pavgb, MCK_FR32, MCK_FR32 } },
    { X86::MMX_PAVGBrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_pavgb, MCK_Mem, MCK_VR64 } },
    { X86::PAVGBrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_pavgb, MCK_Mem, MCK_FR32 } },
    { X86::MMX_PAVGWrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_pavgw, MCK_VR64, MCK_VR64 } },
    { X86::PAVGWrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_pavgw, MCK_FR32, MCK_FR32 } },
    { X86::MMX_PAVGWrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_pavgw, MCK_Mem, MCK_VR64 } },
    { X86::PAVGWrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_pavgw, MCK_Mem, MCK_FR32 } },
    { X86::MMX_PCMPEQBrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_pcmpeqb, MCK_VR64, MCK_VR64 } },
    { X86::PCMPEQBrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_pcmpeqb, MCK_FR32, MCK_FR32 } },
    { X86::MMX_PCMPEQBrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_pcmpeqb, MCK_Mem, MCK_VR64 } },
    { X86::PCMPEQBrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_pcmpeqb, MCK_Mem, MCK_FR32 } },
    { X86::MMX_PCMPEQDrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_pcmpeqd, MCK_VR64, MCK_VR64 } },
    { X86::PCMPEQDrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_pcmpeqd, MCK_FR32, MCK_FR32 } },
    { X86::MMX_PCMPEQDrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_pcmpeqd, MCK_Mem, MCK_VR64 } },
    { X86::PCMPEQDrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_pcmpeqd, MCK_Mem, MCK_FR32 } },
    { X86::PCMPEQQrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_pcmpeqq, MCK_FR32, MCK_FR32 } },
    { X86::PCMPEQQrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_pcmpeqq, MCK_Mem, MCK_FR32 } },
    { X86::MMX_PCMPEQWrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_pcmpeqw, MCK_VR64, MCK_VR64 } },
    { X86::PCMPEQWrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_pcmpeqw, MCK_FR32, MCK_FR32 } },
    { X86::MMX_PCMPEQWrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_pcmpeqw, MCK_Mem, MCK_VR64 } },
    { X86::PCMPEQWrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_pcmpeqw, MCK_Mem, MCK_FR32 } },
    { X86::MMX_PCMPGTBrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_pcmpgtb, MCK_VR64, MCK_VR64 } },
    { X86::PCMPGTBrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_pcmpgtb, MCK_FR32, MCK_FR32 } },
    { X86::MMX_PCMPGTBrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_pcmpgtb, MCK_Mem, MCK_VR64 } },
    { X86::PCMPGTBrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_pcmpgtb, MCK_Mem, MCK_FR32 } },
    { X86::MMX_PCMPGTDrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_pcmpgtd, MCK_VR64, MCK_VR64 } },
    { X86::PCMPGTDrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_pcmpgtd, MCK_FR32, MCK_FR32 } },
    { X86::MMX_PCMPGTDrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_pcmpgtd, MCK_Mem, MCK_VR64 } },
    { X86::PCMPGTDrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_pcmpgtd, MCK_Mem, MCK_FR32 } },
    { X86::PCMPGTQrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_pcmpgtq, MCK_FR32, MCK_FR32 } },
    { X86::PCMPGTQrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_pcmpgtq, MCK_Mem, MCK_FR32 } },
    { X86::MMX_PCMPGTWrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_pcmpgtw, MCK_VR64, MCK_VR64 } },
    { X86::PCMPGTWrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_pcmpgtw, MCK_FR32, MCK_FR32 } },
    { X86::MMX_PCMPGTWrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_pcmpgtw, MCK_Mem, MCK_VR64 } },
    { X86::PCMPGTWrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_pcmpgtw, MCK_Mem, MCK_FR32 } },
    { X86::PHADDDrr64, Convert__Reg1_2__Tie0__Reg1_1, { MCK_phaddd, MCK_VR64, MCK_VR64 } },
    { X86::PHADDDrr128, Convert__Reg1_2__Tie0__Reg1_1, { MCK_phaddd, MCK_FR32, MCK_FR32 } },
    { X86::PHADDDrm64, Convert__Reg1_2__Tie0__Mem5_1, { MCK_phaddd, MCK_Mem, MCK_VR64 } },
    { X86::PHADDDrm128, Convert__Reg1_2__Tie0__Mem5_1, { MCK_phaddd, MCK_Mem, MCK_FR32 } },
    { X86::PHADDSWrr64, Convert__Reg1_2__Tie0__Reg1_1, { MCK_phaddsw, MCK_VR64, MCK_VR64 } },
    { X86::PHADDSWrr128, Convert__Reg1_2__Tie0__Reg1_1, { MCK_phaddsw, MCK_FR32, MCK_FR32 } },
    { X86::PHADDSWrm64, Convert__Reg1_2__Tie0__Mem5_1, { MCK_phaddsw, MCK_Mem, MCK_VR64 } },
    { X86::PHADDSWrm128, Convert__Reg1_2__Tie0__Mem5_1, { MCK_phaddsw, MCK_Mem, MCK_FR32 } },
    { X86::PHADDWrr64, Convert__Reg1_2__Tie0__Reg1_1, { MCK_phaddw, MCK_VR64, MCK_VR64 } },
    { X86::PHADDWrr128, Convert__Reg1_2__Tie0__Reg1_1, { MCK_phaddw, MCK_FR32, MCK_FR32 } },
    { X86::PHADDWrm64, Convert__Reg1_2__Tie0__Mem5_1, { MCK_phaddw, MCK_Mem, MCK_VR64 } },
    { X86::PHADDWrm128, Convert__Reg1_2__Tie0__Mem5_1, { MCK_phaddw, MCK_Mem, MCK_FR32 } },
    { X86::PHMINPOSUWrr128, Convert__Reg1_2__Reg1_1, { MCK_phminposuw, MCK_FR32, MCK_FR32 } },
    { X86::PHMINPOSUWrm128, Convert__Reg1_2__Mem5_1, { MCK_phminposuw, MCK_Mem, MCK_FR32 } },
    { X86::PHSUBDrr64, Convert__Reg1_2__Tie0__Reg1_1, { MCK_phsubd, MCK_VR64, MCK_VR64 } },
    { X86::PHSUBDrr128, Convert__Reg1_2__Tie0__Reg1_1, { MCK_phsubd, MCK_FR32, MCK_FR32 } },
    { X86::PHSUBDrm64, Convert__Reg1_2__Tie0__Mem5_1, { MCK_phsubd, MCK_Mem, MCK_VR64 } },
    { X86::PHSUBDrm128, Convert__Reg1_2__Tie0__Mem5_1, { MCK_phsubd, MCK_Mem, MCK_FR32 } },
    { X86::PHSUBSWrr64, Convert__Reg1_2__Tie0__Reg1_1, { MCK_phsubsw, MCK_VR64, MCK_VR64 } },
    { X86::PHSUBSWrr128, Convert__Reg1_2__Tie0__Reg1_1, { MCK_phsubsw, MCK_FR32, MCK_FR32 } },
    { X86::PHSUBSWrm64, Convert__Reg1_2__Tie0__Mem5_1, { MCK_phsubsw, MCK_Mem, MCK_VR64 } },
    { X86::PHSUBSWrm128, Convert__Reg1_2__Tie0__Mem5_1, { MCK_phsubsw, MCK_Mem, MCK_FR32 } },
    { X86::PHSUBWrr64, Convert__Reg1_2__Tie0__Reg1_1, { MCK_phsubw, MCK_VR64, MCK_VR64 } },
    { X86::PHSUBWrr128, Convert__Reg1_2__Tie0__Reg1_1, { MCK_phsubw, MCK_FR32, MCK_FR32 } },
    { X86::PHSUBWrm64, Convert__Reg1_2__Tie0__Mem5_1, { MCK_phsubw, MCK_Mem, MCK_VR64 } },
    { X86::PHSUBWrm128, Convert__Reg1_2__Tie0__Mem5_1, { MCK_phsubw, MCK_Mem, MCK_FR32 } },
    { X86::PMADDUBSWrr64, Convert__Reg1_2__Tie0__Reg1_1, { MCK_pmaddubsw, MCK_VR64, MCK_VR64 } },
    { X86::PMADDUBSWrr128, Convert__Reg1_2__Tie0__Reg1_1, { MCK_pmaddubsw, MCK_FR32, MCK_FR32 } },
    { X86::PMADDUBSWrm64, Convert__Reg1_2__Tie0__Mem5_1, { MCK_pmaddubsw, MCK_Mem, MCK_VR64 } },
    { X86::PMADDUBSWrm128, Convert__Reg1_2__Tie0__Mem5_1, { MCK_pmaddubsw, MCK_Mem, MCK_FR32 } },
    { X86::MMX_PMADDWDrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_pmaddwd, MCK_VR64, MCK_VR64 } },
    { X86::PMADDWDrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_pmaddwd, MCK_FR32, MCK_FR32 } },
    { X86::MMX_PMADDWDrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_pmaddwd, MCK_Mem, MCK_VR64 } },
    { X86::PMADDWDrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_pmaddwd, MCK_Mem, MCK_FR32 } },
    { X86::PMAXSBrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_pmaxsb, MCK_FR32, MCK_FR32 } },
    { X86::PMAXSBrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_pmaxsb, MCK_Mem, MCK_FR32 } },
    { X86::PMAXSDrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_pmaxsd, MCK_FR32, MCK_FR32 } },
    { X86::PMAXSDrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_pmaxsd, MCK_Mem, MCK_FR32 } },
    { X86::MMX_PMAXSWrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_pmaxsw, MCK_VR64, MCK_VR64 } },
    { X86::PMAXSWrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_pmaxsw, MCK_FR32, MCK_FR32 } },
    { X86::MMX_PMAXSWrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_pmaxsw, MCK_Mem, MCK_VR64 } },
    { X86::PMAXSWrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_pmaxsw, MCK_Mem, MCK_FR32 } },
    { X86::MMX_PMAXUBrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_pmaxub, MCK_VR64, MCK_VR64 } },
    { X86::PMAXUBrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_pmaxub, MCK_FR32, MCK_FR32 } },
    { X86::MMX_PMAXUBrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_pmaxub, MCK_Mem, MCK_VR64 } },
    { X86::PMAXUBrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_pmaxub, MCK_Mem, MCK_FR32 } },
    { X86::PMAXUDrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_pmaxud, MCK_FR32, MCK_FR32 } },
    { X86::PMAXUDrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_pmaxud, MCK_Mem, MCK_FR32 } },
    { X86::PMAXUWrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_pmaxuw, MCK_FR32, MCK_FR32 } },
    { X86::PMAXUWrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_pmaxuw, MCK_Mem, MCK_FR32 } },
    { X86::PMINSBrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_pminsb, MCK_FR32, MCK_FR32 } },
    { X86::PMINSBrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_pminsb, MCK_Mem, MCK_FR32 } },
    { X86::PMINSDrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_pminsd, MCK_FR32, MCK_FR32 } },
    { X86::PMINSDrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_pminsd, MCK_Mem, MCK_FR32 } },
    { X86::MMX_PMINSWrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_pminsw, MCK_VR64, MCK_VR64 } },
    { X86::PMINSWrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_pminsw, MCK_FR32, MCK_FR32 } },
    { X86::MMX_PMINSWrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_pminsw, MCK_Mem, MCK_VR64 } },
    { X86::PMINSWrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_pminsw, MCK_Mem, MCK_FR32 } },
    { X86::MMX_PMINUBrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_pminub, MCK_VR64, MCK_VR64 } },
    { X86::PMINUBrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_pminub, MCK_FR32, MCK_FR32 } },
    { X86::MMX_PMINUBrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_pminub, MCK_Mem, MCK_VR64 } },
    { X86::PMINUBrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_pminub, MCK_Mem, MCK_FR32 } },
    { X86::PMINUDrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_pminud, MCK_FR32, MCK_FR32 } },
    { X86::PMINUDrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_pminud, MCK_Mem, MCK_FR32 } },
    { X86::PMINUWrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_pminuw, MCK_FR32, MCK_FR32 } },
    { X86::PMINUWrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_pminuw, MCK_Mem, MCK_FR32 } },
    { X86::MMX_PMOVMSKBrr, Convert__Reg1_2__Reg1_1, { MCK_pmovmskb, MCK_VR64, MCK_GR32 } },
    { X86::PMOVMSKBrr, Convert__Reg1_2__Reg1_1, { MCK_pmovmskb, MCK_FR32, MCK_GR32 } },
    { X86::PMOVSXBDrr, Convert__Reg1_2__Reg1_1, { MCK_pmovsxbd, MCK_FR32, MCK_FR32 } },
    { X86::PMOVSXBDrm, Convert__Reg1_2__Mem5_1, { MCK_pmovsxbd, MCK_Mem, MCK_FR32 } },
    { X86::PMOVSXBQrr, Convert__Reg1_2__Reg1_1, { MCK_pmovsxbq, MCK_FR32, MCK_FR32 } },
    { X86::PMOVSXBQrm, Convert__Reg1_2__Mem5_1, { MCK_pmovsxbq, MCK_Mem, MCK_FR32 } },
    { X86::PMOVSXBWrr, Convert__Reg1_2__Reg1_1, { MCK_pmovsxbw, MCK_FR32, MCK_FR32 } },
    { X86::PMOVSXBWrm, Convert__Reg1_2__Mem5_1, { MCK_pmovsxbw, MCK_Mem, MCK_FR32 } },
    { X86::PMOVSXDQrr, Convert__Reg1_2__Reg1_1, { MCK_pmovsxdq, MCK_FR32, MCK_FR32 } },
    { X86::PMOVSXDQrm, Convert__Reg1_2__Mem5_1, { MCK_pmovsxdq, MCK_Mem, MCK_FR32 } },
    { X86::PMOVSXWDrr, Convert__Reg1_2__Reg1_1, { MCK_pmovsxwd, MCK_FR32, MCK_FR32 } },
    { X86::PMOVSXWDrm, Convert__Reg1_2__Mem5_1, { MCK_pmovsxwd, MCK_Mem, MCK_FR32 } },
    { X86::PMOVSXWQrr, Convert__Reg1_2__Reg1_1, { MCK_pmovsxwq, MCK_FR32, MCK_FR32 } },
    { X86::PMOVSXWQrm, Convert__Reg1_2__Mem5_1, { MCK_pmovsxwq, MCK_Mem, MCK_FR32 } },
    { X86::PMOVZXBDrr, Convert__Reg1_2__Reg1_1, { MCK_pmovzxbd, MCK_FR32, MCK_FR32 } },
    { X86::PMOVZXBDrm, Convert__Reg1_2__Mem5_1, { MCK_pmovzxbd, MCK_Mem, MCK_FR32 } },
    { X86::PMOVZXBQrr, Convert__Reg1_2__Reg1_1, { MCK_pmovzxbq, MCK_FR32, MCK_FR32 } },
    { X86::PMOVZXBQrm, Convert__Reg1_2__Mem5_1, { MCK_pmovzxbq, MCK_Mem, MCK_FR32 } },
    { X86::PMOVZXBWrr, Convert__Reg1_2__Reg1_1, { MCK_pmovzxbw, MCK_FR32, MCK_FR32 } },
    { X86::PMOVZXBWrm, Convert__Reg1_2__Mem5_1, { MCK_pmovzxbw, MCK_Mem, MCK_FR32 } },
    { X86::PMOVZXDQrr, Convert__Reg1_2__Reg1_1, { MCK_pmovzxdq, MCK_FR32, MCK_FR32 } },
    { X86::PMOVZXDQrm, Convert__Reg1_2__Mem5_1, { MCK_pmovzxdq, MCK_Mem, MCK_FR32 } },
    { X86::PMOVZXWDrr, Convert__Reg1_2__Reg1_1, { MCK_pmovzxwd, MCK_FR32, MCK_FR32 } },
    { X86::PMOVZXWDrm, Convert__Reg1_2__Mem5_1, { MCK_pmovzxwd, MCK_Mem, MCK_FR32 } },
    { X86::PMOVZXWQrr, Convert__Reg1_2__Reg1_1, { MCK_pmovzxwq, MCK_FR32, MCK_FR32 } },
    { X86::PMOVZXWQrm, Convert__Reg1_2__Mem5_1, { MCK_pmovzxwq, MCK_Mem, MCK_FR32 } },
    { X86::PMULDQrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_pmuldq, MCK_FR32, MCK_FR32 } },
    { X86::PMULDQrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_pmuldq, MCK_Mem, MCK_FR32 } },
    { X86::PMULHRSWrr64, Convert__Reg1_2__Tie0__Reg1_1, { MCK_pmulhrsw, MCK_VR64, MCK_VR64 } },
    { X86::PMULHRSWrr128, Convert__Reg1_2__Tie0__Reg1_1, { MCK_pmulhrsw, MCK_FR32, MCK_FR32 } },
    { X86::PMULHRSWrm64, Convert__Reg1_2__Tie0__Mem5_1, { MCK_pmulhrsw, MCK_Mem, MCK_VR64 } },
    { X86::PMULHRSWrm128, Convert__Reg1_2__Tie0__Mem5_1, { MCK_pmulhrsw, MCK_Mem, MCK_FR32 } },
    { X86::MMX_PMULHUWrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_pmulhuw, MCK_VR64, MCK_VR64 } },
    { X86::PMULHUWrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_pmulhuw, MCK_FR32, MCK_FR32 } },
    { X86::MMX_PMULHUWrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_pmulhuw, MCK_Mem, MCK_VR64 } },
    { X86::PMULHUWrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_pmulhuw, MCK_Mem, MCK_FR32 } },
    { X86::MMX_PMULHWrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_pmulhw, MCK_VR64, MCK_VR64 } },
    { X86::PMULHWrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_pmulhw, MCK_FR32, MCK_FR32 } },
    { X86::MMX_PMULHWrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_pmulhw, MCK_Mem, MCK_VR64 } },
    { X86::PMULHWrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_pmulhw, MCK_Mem, MCK_FR32 } },
    { X86::PMULLDrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_pmulld, MCK_FR32, MCK_FR32 } },
    { X86::PMULLDrr_int, Convert__Reg1_2__Tie0__Reg1_1, { MCK_pmulld, MCK_FR32, MCK_FR32 } },
    { X86::PMULLDrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_pmulld, MCK_Mem, MCK_FR32 } },
    { X86::PMULLDrm_int, Convert__Reg1_2__Tie0__Mem5_1, { MCK_pmulld, MCK_Mem, MCK_FR32 } },
    { X86::MMX_PMULLWrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_pmullw, MCK_VR64, MCK_VR64 } },
    { X86::PMULLWrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_pmullw, MCK_FR32, MCK_FR32 } },
    { X86::MMX_PMULLWrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_pmullw, MCK_Mem, MCK_VR64 } },
    { X86::PMULLWrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_pmullw, MCK_Mem, MCK_FR32 } },
    { X86::MMX_PMULUDQrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_pmuludq, MCK_VR64, MCK_VR64 } },
    { X86::PMULUDQrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_pmuludq, MCK_FR32, MCK_FR32 } },
    { X86::MMX_PMULUDQrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_pmuludq, MCK_Mem, MCK_VR64 } },
    { X86::PMULUDQrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_pmuludq, MCK_Mem, MCK_FR32 } },
    { X86::POPCNT32rr, Convert__Reg1_2__Reg1_1, { MCK_popcntl, MCK_GR32, MCK_GR32 } },
    { X86::POPCNT32rm, Convert__Reg1_2__Mem5_1, { MCK_popcntl, MCK_Mem, MCK_GR32 } },
    { X86::POPCNT64rr, Convert__Reg1_2__Reg1_1, { MCK_popcntq, MCK_GR64, MCK_GR64 } },
    { X86::POPCNT64rm, Convert__Reg1_2__Mem5_1, { MCK_popcntq, MCK_Mem, MCK_GR64 } },
    { X86::POPCNT16rr, Convert__Reg1_2__Reg1_1, { MCK_popcntw, MCK_GR16, MCK_GR16 } },
    { X86::POPCNT16rm, Convert__Reg1_2__Mem5_1, { MCK_popcntw, MCK_Mem, MCK_GR16 } },
    { X86::MMX_PORrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_por, MCK_VR64, MCK_VR64 } },
    { X86::PORrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_por, MCK_FR32, MCK_FR32 } },
    { X86::MMX_PORrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_por, MCK_Mem, MCK_VR64 } },
    { X86::PORrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_por, MCK_Mem, MCK_FR32 } },
    { X86::MMX_PSADBWrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_psadbw, MCK_VR64, MCK_VR64 } },
    { X86::PSADBWrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_psadbw, MCK_FR32, MCK_FR32 } },
    { X86::MMX_PSADBWrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_psadbw, MCK_Mem, MCK_VR64 } },
    { X86::PSADBWrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_psadbw, MCK_Mem, MCK_FR32 } },
    { X86::PSHUFBrr64, Convert__Reg1_2__Tie0__Reg1_1, { MCK_pshufb, MCK_VR64, MCK_VR64 } },
    { X86::PSHUFBrr128, Convert__Reg1_2__Tie0__Reg1_1, { MCK_pshufb, MCK_FR32, MCK_FR32 } },
    { X86::PSHUFBrm64, Convert__Reg1_2__Tie0__Mem5_1, { MCK_pshufb, MCK_Mem, MCK_VR64 } },
    { X86::PSHUFBrm128, Convert__Reg1_2__Tie0__Mem5_1, { MCK_pshufb, MCK_Mem, MCK_FR32 } },
    { X86::PSIGNBrr64, Convert__Reg1_2__Tie0__Reg1_1, { MCK_psignb, MCK_VR64, MCK_VR64 } },
    { X86::PSIGNBrr128, Convert__Reg1_2__Tie0__Reg1_1, { MCK_psignb, MCK_FR32, MCK_FR32 } },
    { X86::PSIGNBrm64, Convert__Reg1_2__Tie0__Mem5_1, { MCK_psignb, MCK_Mem, MCK_VR64 } },
    { X86::PSIGNBrm128, Convert__Reg1_2__Tie0__Mem5_1, { MCK_psignb, MCK_Mem, MCK_FR32 } },
    { X86::PSIGNDrr64, Convert__Reg1_2__Tie0__Reg1_1, { MCK_psignd, MCK_VR64, MCK_VR64 } },
    { X86::PSIGNDrr128, Convert__Reg1_2__Tie0__Reg1_1, { MCK_psignd, MCK_FR32, MCK_FR32 } },
    { X86::PSIGNDrm64, Convert__Reg1_2__Tie0__Mem5_1, { MCK_psignd, MCK_Mem, MCK_VR64 } },
    { X86::PSIGNDrm128, Convert__Reg1_2__Tie0__Mem5_1, { MCK_psignd, MCK_Mem, MCK_FR32 } },
    { X86::PSIGNWrr64, Convert__Reg1_2__Tie0__Reg1_1, { MCK_psignw, MCK_VR64, MCK_VR64 } },
    { X86::PSIGNWrr128, Convert__Reg1_2__Tie0__Reg1_1, { MCK_psignw, MCK_FR32, MCK_FR32 } },
    { X86::PSIGNWrm64, Convert__Reg1_2__Tie0__Mem5_1, { MCK_psignw, MCK_Mem, MCK_VR64 } },
    { X86::PSIGNWrm128, Convert__Reg1_2__Tie0__Mem5_1, { MCK_psignw, MCK_Mem, MCK_FR32 } },
    { X86::MMX_PSLLDrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_pslld, MCK_VR64, MCK_VR64 } },
    { X86::PSLLDrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_pslld, MCK_FR32, MCK_FR32 } },
    { X86::MMX_PSLLDri, Convert__Reg1_2__Tie0__ImmSExt81_1, { MCK_pslld, MCK_ImmSExt8, MCK_VR64 } },
    { X86::PSLLDri, Convert__Reg1_2__Tie0__ImmSExt81_1, { MCK_pslld, MCK_ImmSExt8, MCK_FR32 } },
    { X86::MMX_PSLLDrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_pslld, MCK_Mem, MCK_VR64 } },
    { X86::PSLLDrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_pslld, MCK_Mem, MCK_FR32 } },
    { X86::PSLLDQri, Convert__Reg1_2__Tie0__ImmSExt81_1, { MCK_pslldq, MCK_ImmSExt8, MCK_FR32 } },
    { X86::MMX_PSLLQrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_psllq, MCK_VR64, MCK_VR64 } },
    { X86::PSLLQrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_psllq, MCK_FR32, MCK_FR32 } },
    { X86::MMX_PSLLQri, Convert__Reg1_2__Tie0__ImmSExt81_1, { MCK_psllq, MCK_ImmSExt8, MCK_VR64 } },
    { X86::PSLLQri, Convert__Reg1_2__Tie0__ImmSExt81_1, { MCK_psllq, MCK_ImmSExt8, MCK_FR32 } },
    { X86::MMX_PSLLQrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_psllq, MCK_Mem, MCK_VR64 } },
    { X86::PSLLQrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_psllq, MCK_Mem, MCK_FR32 } },
    { X86::MMX_PSLLWrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_psllw, MCK_VR64, MCK_VR64 } },
    { X86::PSLLWrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_psllw, MCK_FR32, MCK_FR32 } },
    { X86::MMX_PSLLWri, Convert__Reg1_2__Tie0__ImmSExt81_1, { MCK_psllw, MCK_ImmSExt8, MCK_VR64 } },
    { X86::PSLLWri, Convert__Reg1_2__Tie0__ImmSExt81_1, { MCK_psllw, MCK_ImmSExt8, MCK_FR32 } },
    { X86::MMX_PSLLWrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_psllw, MCK_Mem, MCK_VR64 } },
    { X86::PSLLWrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_psllw, MCK_Mem, MCK_FR32 } },
    { X86::MMX_PSRADrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_psrad, MCK_VR64, MCK_VR64 } },
    { X86::PSRADrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_psrad, MCK_FR32, MCK_FR32 } },
    { X86::MMX_PSRADri, Convert__Reg1_2__Tie0__ImmSExt81_1, { MCK_psrad, MCK_ImmSExt8, MCK_VR64 } },
    { X86::PSRADri, Convert__Reg1_2__Tie0__ImmSExt81_1, { MCK_psrad, MCK_ImmSExt8, MCK_FR32 } },
    { X86::MMX_PSRADrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_psrad, MCK_Mem, MCK_VR64 } },
    { X86::PSRADrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_psrad, MCK_Mem, MCK_FR32 } },
    { X86::MMX_PSRAWrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_psraw, MCK_VR64, MCK_VR64 } },
    { X86::PSRAWrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_psraw, MCK_FR32, MCK_FR32 } },
    { X86::MMX_PSRAWri, Convert__Reg1_2__Tie0__ImmSExt81_1, { MCK_psraw, MCK_ImmSExt8, MCK_VR64 } },
    { X86::PSRAWri, Convert__Reg1_2__Tie0__ImmSExt81_1, { MCK_psraw, MCK_ImmSExt8, MCK_FR32 } },
    { X86::MMX_PSRAWrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_psraw, MCK_Mem, MCK_VR64 } },
    { X86::PSRAWrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_psraw, MCK_Mem, MCK_FR32 } },
    { X86::MMX_PSRLDrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_psrld, MCK_VR64, MCK_VR64 } },
    { X86::PSRLDrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_psrld, MCK_FR32, MCK_FR32 } },
    { X86::MMX_PSRLDri, Convert__Reg1_2__Tie0__ImmSExt81_1, { MCK_psrld, MCK_ImmSExt8, MCK_VR64 } },
    { X86::PSRLDri, Convert__Reg1_2__Tie0__ImmSExt81_1, { MCK_psrld, MCK_ImmSExt8, MCK_FR32 } },
    { X86::MMX_PSRLDrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_psrld, MCK_Mem, MCK_VR64 } },
    { X86::PSRLDrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_psrld, MCK_Mem, MCK_FR32 } },
    { X86::PSRLDQri, Convert__Reg1_2__Tie0__ImmSExt81_1, { MCK_psrldq, MCK_ImmSExt8, MCK_FR32 } },
    { X86::MMX_PSRLQrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_psrlq, MCK_VR64, MCK_VR64 } },
    { X86::PSRLQrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_psrlq, MCK_FR32, MCK_FR32 } },
    { X86::MMX_PSRLQri, Convert__Reg1_2__Tie0__ImmSExt81_1, { MCK_psrlq, MCK_ImmSExt8, MCK_VR64 } },
    { X86::PSRLQri, Convert__Reg1_2__Tie0__ImmSExt81_1, { MCK_psrlq, MCK_ImmSExt8, MCK_FR32 } },
    { X86::MMX_PSRLQrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_psrlq, MCK_Mem, MCK_VR64 } },
    { X86::PSRLQrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_psrlq, MCK_Mem, MCK_FR32 } },
    { X86::MMX_PSRLWrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_psrlw, MCK_VR64, MCK_VR64 } },
    { X86::PSRLWrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_psrlw, MCK_FR32, MCK_FR32 } },
    { X86::MMX_PSRLWri, Convert__Reg1_2__Tie0__ImmSExt81_1, { MCK_psrlw, MCK_ImmSExt8, MCK_VR64 } },
    { X86::PSRLWri, Convert__Reg1_2__Tie0__ImmSExt81_1, { MCK_psrlw, MCK_ImmSExt8, MCK_FR32 } },
    { X86::MMX_PSRLWrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_psrlw, MCK_Mem, MCK_VR64 } },
    { X86::PSRLWrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_psrlw, MCK_Mem, MCK_FR32 } },
    { X86::MMX_PSUBBrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_psubb, MCK_VR64, MCK_VR64 } },
    { X86::PSUBBrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_psubb, MCK_FR32, MCK_FR32 } },
    { X86::MMX_PSUBBrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_psubb, MCK_Mem, MCK_VR64 } },
    { X86::PSUBBrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_psubb, MCK_Mem, MCK_FR32 } },
    { X86::MMX_PSUBDrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_psubd, MCK_VR64, MCK_VR64 } },
    { X86::PSUBDrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_psubd, MCK_FR32, MCK_FR32 } },
    { X86::MMX_PSUBDrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_psubd, MCK_Mem, MCK_VR64 } },
    { X86::PSUBDrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_psubd, MCK_Mem, MCK_FR32 } },
    { X86::MMX_PSUBQrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_psubq, MCK_VR64, MCK_VR64 } },
    { X86::PSUBQrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_psubq, MCK_FR32, MCK_FR32 } },
    { X86::MMX_PSUBQrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_psubq, MCK_Mem, MCK_VR64 } },
    { X86::PSUBQrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_psubq, MCK_Mem, MCK_FR32 } },
    { X86::MMX_PSUBSBrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_psubsb, MCK_VR64, MCK_VR64 } },
    { X86::PSUBSBrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_psubsb, MCK_FR32, MCK_FR32 } },
    { X86::MMX_PSUBSBrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_psubsb, MCK_Mem, MCK_VR64 } },
    { X86::PSUBSBrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_psubsb, MCK_Mem, MCK_FR32 } },
    { X86::MMX_PSUBSWrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_psubsw, MCK_VR64, MCK_VR64 } },
    { X86::PSUBSWrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_psubsw, MCK_FR32, MCK_FR32 } },
    { X86::MMX_PSUBSWrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_psubsw, MCK_Mem, MCK_VR64 } },
    { X86::PSUBSWrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_psubsw, MCK_Mem, MCK_FR32 } },
    { X86::MMX_PSUBUSBrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_psubusb, MCK_VR64, MCK_VR64 } },
    { X86::PSUBUSBrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_psubusb, MCK_FR32, MCK_FR32 } },
    { X86::MMX_PSUBUSBrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_psubusb, MCK_Mem, MCK_VR64 } },
    { X86::PSUBUSBrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_psubusb, MCK_Mem, MCK_FR32 } },
    { X86::MMX_PSUBUSWrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_psubusw, MCK_VR64, MCK_VR64 } },
    { X86::PSUBUSWrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_psubusw, MCK_FR32, MCK_FR32 } },
    { X86::MMX_PSUBUSWrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_psubusw, MCK_Mem, MCK_VR64 } },
    { X86::PSUBUSWrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_psubusw, MCK_Mem, MCK_FR32 } },
    { X86::MMX_PSUBWrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_psubw, MCK_VR64, MCK_VR64 } },
    { X86::PSUBWrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_psubw, MCK_FR32, MCK_FR32 } },
    { X86::MMX_PSUBWrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_psubw, MCK_Mem, MCK_VR64 } },
    { X86::PSUBWrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_psubw, MCK_Mem, MCK_FR32 } },
    { X86::PTESTrr, Convert__Reg1_2__Reg1_1, { MCK_ptest, MCK_FR32, MCK_FR32 } },
    { X86::PTESTrm, Convert__Reg1_2__Mem5_1, { MCK_ptest, MCK_Mem, MCK_FR32 } },
    { X86::MMX_PUNPCKHBWrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_punpckhbw, MCK_VR64, MCK_VR64 } },
    { X86::PUNPCKHBWrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_punpckhbw, MCK_FR32, MCK_FR32 } },
    { X86::MMX_PUNPCKHBWrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_punpckhbw, MCK_Mem, MCK_VR64 } },
    { X86::PUNPCKHBWrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_punpckhbw, MCK_Mem, MCK_FR32 } },
    { X86::MMX_PUNPCKHDQrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_punpckhdq, MCK_VR64, MCK_VR64 } },
    { X86::PUNPCKHDQrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_punpckhdq, MCK_FR32, MCK_FR32 } },
    { X86::MMX_PUNPCKHDQrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_punpckhdq, MCK_Mem, MCK_VR64 } },
    { X86::PUNPCKHDQrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_punpckhdq, MCK_Mem, MCK_FR32 } },
    { X86::PUNPCKHQDQrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_punpckhqdq, MCK_FR32, MCK_FR32 } },
    { X86::PUNPCKHQDQrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_punpckhqdq, MCK_Mem, MCK_FR32 } },
    { X86::MMX_PUNPCKHWDrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_punpckhwd, MCK_VR64, MCK_VR64 } },
    { X86::PUNPCKHWDrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_punpckhwd, MCK_FR32, MCK_FR32 } },
    { X86::MMX_PUNPCKHWDrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_punpckhwd, MCK_Mem, MCK_VR64 } },
    { X86::PUNPCKHWDrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_punpckhwd, MCK_Mem, MCK_FR32 } },
    { X86::MMX_PUNPCKLBWrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_punpcklbw, MCK_VR64, MCK_VR64 } },
    { X86::PUNPCKLBWrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_punpcklbw, MCK_FR32, MCK_FR32 } },
    { X86::MMX_PUNPCKLBWrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_punpcklbw, MCK_Mem, MCK_VR64 } },
    { X86::PUNPCKLBWrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_punpcklbw, MCK_Mem, MCK_FR32 } },
    { X86::MMX_PUNPCKLDQrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_punpckldq, MCK_VR64, MCK_VR64 } },
    { X86::PUNPCKLDQrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_punpckldq, MCK_FR32, MCK_FR32 } },
    { X86::MMX_PUNPCKLDQrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_punpckldq, MCK_Mem, MCK_VR64 } },
    { X86::PUNPCKLDQrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_punpckldq, MCK_Mem, MCK_FR32 } },
    { X86::PUNPCKLQDQrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_punpcklqdq, MCK_FR32, MCK_FR32 } },
    { X86::PUNPCKLQDQrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_punpcklqdq, MCK_Mem, MCK_FR32 } },
    { X86::MMX_PUNPCKLWDrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_punpcklwd, MCK_VR64, MCK_VR64 } },
    { X86::PUNPCKLWDrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_punpcklwd, MCK_FR32, MCK_FR32 } },
    { X86::MMX_PUNPCKLWDrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_punpcklwd, MCK_Mem, MCK_VR64 } },
    { X86::PUNPCKLWDrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_punpcklwd, MCK_Mem, MCK_FR32 } },
    { X86::MMX_PXORrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_pxor, MCK_VR64, MCK_VR64 } },
    { X86::PXORrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_pxor, MCK_FR32, MCK_FR32 } },
    { X86::MMX_PXORrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_pxor, MCK_Mem, MCK_VR64 } },
    { X86::PXORrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_pxor, MCK_Mem, MCK_FR32 } },
    { X86::RCL8r1, Convert__Reg1_2__Tie0, { MCK_rclb, MCK_1, MCK_GR8 } },
    { X86::RCL8m1, Convert__Mem5_2, { MCK_rclb, MCK_1, MCK_Mem } },
    { X86::RCL8rCL, Convert__Reg1_2__Tie0, { MCK_rclb, MCK_CL, MCK_GR8 } },
    { X86::RCL8mCL, Convert__Mem5_2, { MCK_rclb, MCK_CL, MCK_Mem } },
    { X86::RCL8ri, Convert__Reg1_2__Tie0__Imm1_1, { MCK_rclb, MCK_Imm, MCK_GR8 } },
    { X86::RCL8mi, Convert__Mem5_2__Imm1_1, { MCK_rclb, MCK_Imm, MCK_Mem } },
    { X86::RCL32r1, Convert__Reg1_2__Tie0, { MCK_rcll, MCK_1, MCK_GR32 } },
    { X86::RCL32m1, Convert__Mem5_2, { MCK_rcll, MCK_1, MCK_Mem } },
    { X86::RCL32rCL, Convert__Reg1_2__Tie0, { MCK_rcll, MCK_CL, MCK_GR32 } },
    { X86::RCL32mCL, Convert__Mem5_2, { MCK_rcll, MCK_CL, MCK_Mem } },
    { X86::RCL32ri, Convert__Reg1_2__Tie0__Imm1_1, { MCK_rcll, MCK_Imm, MCK_GR32 } },
    { X86::RCL32mi, Convert__Mem5_2__Imm1_1, { MCK_rcll, MCK_Imm, MCK_Mem } },
    { X86::RCL64r1, Convert__Reg1_2__Tie0, { MCK_rclq, MCK_1, MCK_GR64 } },
    { X86::RCL64m1, Convert__Mem5_2, { MCK_rclq, MCK_1, MCK_Mem } },
    { X86::RCL64rCL, Convert__Reg1_2__Tie0, { MCK_rclq, MCK_CL, MCK_GR64 } },
    { X86::RCL64mCL, Convert__Mem5_2, { MCK_rclq, MCK_CL, MCK_Mem } },
    { X86::RCL64ri, Convert__Reg1_2__Tie0__Imm1_1, { MCK_rclq, MCK_Imm, MCK_GR64 } },
    { X86::RCL64mi, Convert__Mem5_2__Imm1_1, { MCK_rclq, MCK_Imm, MCK_Mem } },
    { X86::RCL16r1, Convert__Reg1_2__Tie0, { MCK_rclw, MCK_1, MCK_GR16 } },
    { X86::RCL16m1, Convert__Mem5_2, { MCK_rclw, MCK_1, MCK_Mem } },
    { X86::RCL16rCL, Convert__Reg1_2__Tie0, { MCK_rclw, MCK_CL, MCK_GR16 } },
    { X86::RCL16mCL, Convert__Mem5_2, { MCK_rclw, MCK_CL, MCK_Mem } },
    { X86::RCL16ri, Convert__Reg1_2__Tie0__Imm1_1, { MCK_rclw, MCK_Imm, MCK_GR16 } },
    { X86::RCL16mi, Convert__Mem5_2__Imm1_1, { MCK_rclw, MCK_Imm, MCK_Mem } },
    { X86::RCPPSr, Convert__Reg1_2__Reg1_1, { MCK_rcpps, MCK_FR32, MCK_FR32 } },
    { X86::RCPPSm, Convert__Reg1_2__Mem5_1, { MCK_rcpps, MCK_Mem, MCK_FR32 } },
    { X86::RCPSSr, Convert__Reg1_2__Reg1_1, { MCK_rcpss, MCK_FR32, MCK_FR32 } },
    { X86::RCPSSm, Convert__Reg1_2__Mem5_1, { MCK_rcpss, MCK_Mem, MCK_FR32 } },
    { X86::RCR8r1, Convert__Reg1_2__Tie0, { MCK_rcrb, MCK_1, MCK_GR8 } },
    { X86::RCR8m1, Convert__Mem5_2, { MCK_rcrb, MCK_1, MCK_Mem } },
    { X86::RCR8rCL, Convert__Reg1_2__Tie0, { MCK_rcrb, MCK_CL, MCK_GR8 } },
    { X86::RCR8mCL, Convert__Mem5_2, { MCK_rcrb, MCK_CL, MCK_Mem } },
    { X86::RCR8ri, Convert__Reg1_2__Tie0__Imm1_1, { MCK_rcrb, MCK_Imm, MCK_GR8 } },
    { X86::RCR8mi, Convert__Mem5_2__Imm1_1, { MCK_rcrb, MCK_Imm, MCK_Mem } },
    { X86::RCR32r1, Convert__Reg1_2__Tie0, { MCK_rcrl, MCK_1, MCK_GR32 } },
    { X86::RCR32m1, Convert__Mem5_2, { MCK_rcrl, MCK_1, MCK_Mem } },
    { X86::RCR32rCL, Convert__Reg1_2__Tie0, { MCK_rcrl, MCK_CL, MCK_GR32 } },
    { X86::RCR32mCL, Convert__Mem5_2, { MCK_rcrl, MCK_CL, MCK_Mem } },
    { X86::RCR32ri, Convert__Reg1_2__Tie0__Imm1_1, { MCK_rcrl, MCK_Imm, MCK_GR32 } },
    { X86::RCR32mi, Convert__Mem5_2__Imm1_1, { MCK_rcrl, MCK_Imm, MCK_Mem } },
    { X86::RCR64r1, Convert__Reg1_2__Tie0, { MCK_rcrq, MCK_1, MCK_GR64 } },
    { X86::RCR64m1, Convert__Mem5_2, { MCK_rcrq, MCK_1, MCK_Mem } },
    { X86::RCR64rCL, Convert__Reg1_2__Tie0, { MCK_rcrq, MCK_CL, MCK_GR64 } },
    { X86::RCR64mCL, Convert__Mem5_2, { MCK_rcrq, MCK_CL, MCK_Mem } },
    { X86::RCR64ri, Convert__Reg1_2__Tie0__Imm1_1, { MCK_rcrq, MCK_Imm, MCK_GR64 } },
    { X86::RCR64mi, Convert__Mem5_2__Imm1_1, { MCK_rcrq, MCK_Imm, MCK_Mem } },
    { X86::RCR16r1, Convert__Reg1_2__Tie0, { MCK_rcrw, MCK_1, MCK_GR16 } },
    { X86::RCR16m1, Convert__Mem5_2, { MCK_rcrw, MCK_1, MCK_Mem } },
    { X86::RCR16rCL, Convert__Reg1_2__Tie0, { MCK_rcrw, MCK_CL, MCK_GR16 } },
    { X86::RCR16mCL, Convert__Mem5_2, { MCK_rcrw, MCK_CL, MCK_Mem } },
    { X86::RCR16ri, Convert__Reg1_2__Tie0__Imm1_1, { MCK_rcrw, MCK_Imm, MCK_GR16 } },
    { X86::RCR16mi, Convert__Mem5_2__Imm1_1, { MCK_rcrw, MCK_Imm, MCK_Mem } },
    { X86::ROL8rCL, Convert__Reg1_2__Tie0, { MCK_rolb, MCK_CL, MCK_GR8 } },
    { X86::ROL8mCL, Convert__Mem5_2, { MCK_rolb, MCK_CL, MCK_Mem } },
    { X86::ROL8ri, Convert__Reg1_2__Tie0__Imm1_1, { MCK_rolb, MCK_Imm, MCK_GR8 } },
    { X86::ROL8mi, Convert__Mem5_2__Imm1_1, { MCK_rolb, MCK_Imm, MCK_Mem } },
    { X86::ROL32rCL, Convert__Reg1_2__Tie0, { MCK_roll, MCK_CL, MCK_GR32 } },
    { X86::ROL32mCL, Convert__Mem5_2, { MCK_roll, MCK_CL, MCK_Mem } },
    { X86::ROL32ri, Convert__Reg1_2__Tie0__Imm1_1, { MCK_roll, MCK_Imm, MCK_GR32 } },
    { X86::ROL32mi, Convert__Mem5_2__Imm1_1, { MCK_roll, MCK_Imm, MCK_Mem } },
    { X86::ROL64rCL, Convert__Reg1_2__Tie0, { MCK_rolq, MCK_CL, MCK_GR64 } },
    { X86::ROL64mCL, Convert__Mem5_2, { MCK_rolq, MCK_CL, MCK_Mem } },
    { X86::ROL64ri, Convert__Reg1_2__Tie0__Imm1_1, { MCK_rolq, MCK_Imm, MCK_GR64 } },
    { X86::ROL64mi, Convert__Mem5_2__Imm1_1, { MCK_rolq, MCK_Imm, MCK_Mem } },
    { X86::ROL16rCL, Convert__Reg1_2__Tie0, { MCK_rolw, MCK_CL, MCK_GR16 } },
    { X86::ROL16mCL, Convert__Mem5_2, { MCK_rolw, MCK_CL, MCK_Mem } },
    { X86::ROL16ri, Convert__Reg1_2__Tie0__Imm1_1, { MCK_rolw, MCK_Imm, MCK_GR16 } },
    { X86::ROL16mi, Convert__Mem5_2__Imm1_1, { MCK_rolw, MCK_Imm, MCK_Mem } },
    { X86::ROR8rCL, Convert__Reg1_2__Tie0, { MCK_rorb, MCK_CL, MCK_GR8 } },
    { X86::ROR8mCL, Convert__Mem5_2, { MCK_rorb, MCK_CL, MCK_Mem } },
    { X86::ROR8ri, Convert__Reg1_2__Tie0__Imm1_1, { MCK_rorb, MCK_Imm, MCK_GR8 } },
    { X86::ROR8mi, Convert__Mem5_2__Imm1_1, { MCK_rorb, MCK_Imm, MCK_Mem } },
    { X86::ROR32rCL, Convert__Reg1_2__Tie0, { MCK_rorl, MCK_CL, MCK_GR32 } },
    { X86::ROR32mCL, Convert__Mem5_2, { MCK_rorl, MCK_CL, MCK_Mem } },
    { X86::ROR32ri, Convert__Reg1_2__Tie0__Imm1_1, { MCK_rorl, MCK_Imm, MCK_GR32 } },
    { X86::ROR32mi, Convert__Mem5_2__Imm1_1, { MCK_rorl, MCK_Imm, MCK_Mem } },
    { X86::ROR64rCL, Convert__Reg1_2__Tie0, { MCK_rorq, MCK_CL, MCK_GR64 } },
    { X86::ROR64mCL, Convert__Mem5_2, { MCK_rorq, MCK_CL, MCK_Mem } },
    { X86::ROR64ri, Convert__Reg1_2__Tie0__Imm1_1, { MCK_rorq, MCK_Imm, MCK_GR64 } },
    { X86::ROR64mi, Convert__Mem5_2__Imm1_1, { MCK_rorq, MCK_Imm, MCK_Mem } },
    { X86::ROR16rCL, Convert__Reg1_2__Tie0, { MCK_rorw, MCK_CL, MCK_GR16 } },
    { X86::ROR16mCL, Convert__Mem5_2, { MCK_rorw, MCK_CL, MCK_Mem } },
    { X86::ROR16ri, Convert__Reg1_2__Tie0__Imm1_1, { MCK_rorw, MCK_Imm, MCK_GR16 } },
    { X86::ROR16mi, Convert__Mem5_2__Imm1_1, { MCK_rorw, MCK_Imm, MCK_Mem } },
    { X86::RSQRTPSr, Convert__Reg1_2__Reg1_1, { MCK_rsqrtps, MCK_FR32, MCK_FR32 } },
    { X86::RSQRTPSm, Convert__Reg1_2__Mem5_1, { MCK_rsqrtps, MCK_Mem, MCK_FR32 } },
    { X86::RSQRTSSr, Convert__Reg1_2__Reg1_1, { MCK_rsqrtss, MCK_FR32, MCK_FR32 } },
    { X86::RSQRTSSm, Convert__Reg1_2__Mem5_1, { MCK_rsqrtss, MCK_Mem, MCK_FR32 } },
    { X86::SAR8rCL, Convert__Reg1_2__Tie0, { MCK_sarb, MCK_CL, MCK_GR8 } },
    { X86::SAR8mCL, Convert__Mem5_2, { MCK_sarb, MCK_CL, MCK_Mem } },
    { X86::SAR8ri, Convert__Reg1_2__Tie0__Imm1_1, { MCK_sarb, MCK_Imm, MCK_GR8 } },
    { X86::SAR8mi, Convert__Mem5_2__Imm1_1, { MCK_sarb, MCK_Imm, MCK_Mem } },
    { X86::SAR32rCL, Convert__Reg1_2__Tie0, { MCK_sarl, MCK_CL, MCK_GR32 } },
    { X86::SAR32mCL, Convert__Mem5_2, { MCK_sarl, MCK_CL, MCK_Mem } },
    { X86::SAR32ri, Convert__Reg1_2__Tie0__Imm1_1, { MCK_sarl, MCK_Imm, MCK_GR32 } },
    { X86::SAR32mi, Convert__Mem5_2__Imm1_1, { MCK_sarl, MCK_Imm, MCK_Mem } },
    { X86::SAR64rCL, Convert__Reg1_2__Tie0, { MCK_sarq, MCK_CL, MCK_GR64 } },
    { X86::SAR64mCL, Convert__Mem5_2, { MCK_sarq, MCK_CL, MCK_Mem } },
    { X86::SAR64ri, Convert__Reg1_2__Tie0__Imm1_1, { MCK_sarq, MCK_Imm, MCK_GR64 } },
    { X86::SAR64mi, Convert__Mem5_2__Imm1_1, { MCK_sarq, MCK_Imm, MCK_Mem } },
    { X86::SAR16rCL, Convert__Reg1_2__Tie0, { MCK_sarw, MCK_CL, MCK_GR16 } },
    { X86::SAR16mCL, Convert__Mem5_2, { MCK_sarw, MCK_CL, MCK_Mem } },
    { X86::SAR16ri, Convert__Reg1_2__Tie0__Imm1_1, { MCK_sarw, MCK_Imm, MCK_GR16 } },
    { X86::SAR16mi, Convert__Mem5_2__Imm1_1, { MCK_sarw, MCK_Imm, MCK_Mem } },
    { X86::SBB8rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_sbbb, MCK_GR8, MCK_GR8 } },
    { X86::SBB8rr_REV, Convert__Reg1_2__Tie0__Reg1_1, { MCK_sbbb, MCK_GR8, MCK_GR8 } },
    { X86::SBB8mr, Convert__Mem5_2__Reg1_1, { MCK_sbbb, MCK_GR8, MCK_Mem } },
    { X86::SBB8i8, Convert__Imm1_1, { MCK_sbbb, MCK_Imm, MCK_AL } },
    { X86::SBB8ri, Convert__Reg1_2__Tie0__Imm1_1, { MCK_sbbb, MCK_Imm, MCK_GR8 } },
    { X86::SBB8mi, Convert__Mem5_2__Imm1_1, { MCK_sbbb, MCK_Imm, MCK_Mem } },
    { X86::SBB8rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_sbbb, MCK_Mem, MCK_GR8 } },
    { X86::SBB32rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_sbbl, MCK_GR32, MCK_GR32 } },
    { X86::SBB32rr_REV, Convert__Reg1_2__Tie0__Reg1_1, { MCK_sbbl, MCK_GR32, MCK_GR32 } },
    { X86::SBB32mr, Convert__Mem5_2__Reg1_1, { MCK_sbbl, MCK_GR32, MCK_Mem } },
    { X86::SBB32ri8, Convert__Reg1_2__Tie0__ImmSExt81_1, { MCK_sbbl, MCK_ImmSExt8, MCK_GR32 } },
    { X86::SBB32mi8, Convert__Mem5_2__ImmSExt81_1, { MCK_sbbl, MCK_ImmSExt8, MCK_Mem } },
    { X86::SBB32i32, Convert__Imm1_1, { MCK_sbbl, MCK_Imm, MCK_EAX } },
    { X86::SBB32ri, Convert__Reg1_2__Tie0__Imm1_1, { MCK_sbbl, MCK_Imm, MCK_GR32 } },
    { X86::SBB32mi, Convert__Mem5_2__Imm1_1, { MCK_sbbl, MCK_Imm, MCK_Mem } },
    { X86::SBB32rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_sbbl, MCK_Mem, MCK_GR32 } },
    { X86::SBB64rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_sbbq, MCK_GR64, MCK_GR64 } },
    { X86::SBB64rr_REV, Convert__Reg1_2__Tie0__Reg1_1, { MCK_sbbq, MCK_GR64, MCK_GR64 } },
    { X86::SBB64mr, Convert__Mem5_2__Reg1_1, { MCK_sbbq, MCK_GR64, MCK_Mem } },
    { X86::SBB64ri8, Convert__Reg1_2__Tie0__ImmSExt81_1, { MCK_sbbq, MCK_ImmSExt8, MCK_GR64 } },
    { X86::SBB64mi8, Convert__Mem5_2__ImmSExt81_1, { MCK_sbbq, MCK_ImmSExt8, MCK_Mem } },
    { X86::SBB64i32, Convert__Imm1_1, { MCK_sbbq, MCK_Imm, MCK_RAX } },
    { X86::SBB64ri32, Convert__Reg1_2__Tie0__Imm1_1, { MCK_sbbq, MCK_Imm, MCK_GR64 } },
    { X86::SBB64mi32, Convert__Mem5_2__Imm1_1, { MCK_sbbq, MCK_Imm, MCK_Mem } },
    { X86::SBB64rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_sbbq, MCK_Mem, MCK_GR64 } },
    { X86::SBB16rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_sbbw, MCK_GR16, MCK_GR16 } },
    { X86::SBB16rr_REV, Convert__Reg1_2__Tie0__Reg1_1, { MCK_sbbw, MCK_GR16, MCK_GR16 } },
    { X86::SBB16mr, Convert__Mem5_2__Reg1_1, { MCK_sbbw, MCK_GR16, MCK_Mem } },
    { X86::SBB16ri8, Convert__Reg1_2__Tie0__ImmSExt81_1, { MCK_sbbw, MCK_ImmSExt8, MCK_GR16 } },
    { X86::SBB16mi8, Convert__Mem5_2__ImmSExt81_1, { MCK_sbbw, MCK_ImmSExt8, MCK_Mem } },
    { X86::SBB16i16, Convert__Imm1_1, { MCK_sbbw, MCK_Imm, MCK_AX } },
    { X86::SBB16ri, Convert__Reg1_2__Tie0__Imm1_1, { MCK_sbbw, MCK_Imm, MCK_GR16 } },
    { X86::SBB16mi, Convert__Mem5_2__Imm1_1, { MCK_sbbw, MCK_Imm, MCK_Mem } },
    { X86::SBB16rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_sbbw, MCK_Mem, MCK_GR16 } },
    { X86::SHL8rCL, Convert__Reg1_2__Tie0, { MCK_shlb, MCK_CL, MCK_GR8 } },
    { X86::SHL8mCL, Convert__Mem5_2, { MCK_shlb, MCK_CL, MCK_Mem } },
    { X86::SHL8ri, Convert__Reg1_2__Tie0__Imm1_1, { MCK_shlb, MCK_Imm, MCK_GR8 } },
    { X86::SHL8mi, Convert__Mem5_2__Imm1_1, { MCK_shlb, MCK_Imm, MCK_Mem } },
    { X86::SHL32rCL, Convert__Reg1_2__Tie0, { MCK_shll, MCK_CL, MCK_GR32 } },
    { X86::SHL32mCL, Convert__Mem5_2, { MCK_shll, MCK_CL, MCK_Mem } },
    { X86::SHL32ri, Convert__Reg1_2__Tie0__Imm1_1, { MCK_shll, MCK_Imm, MCK_GR32 } },
    { X86::SHL32mi, Convert__Mem5_2__Imm1_1, { MCK_shll, MCK_Imm, MCK_Mem } },
    { X86::SHL64rCL, Convert__Reg1_2__Tie0, { MCK_shlq, MCK_CL, MCK_GR64 } },
    { X86::SHL64mCL, Convert__Mem5_2, { MCK_shlq, MCK_CL, MCK_Mem } },
    { X86::SHL64ri, Convert__Reg1_2__Tie0__Imm1_1, { MCK_shlq, MCK_Imm, MCK_GR64 } },
    { X86::SHL64mi, Convert__Mem5_2__Imm1_1, { MCK_shlq, MCK_Imm, MCK_Mem } },
    { X86::SHL16rCL, Convert__Reg1_2__Tie0, { MCK_shlw, MCK_CL, MCK_GR16 } },
    { X86::SHL16mCL, Convert__Mem5_2, { MCK_shlw, MCK_CL, MCK_Mem } },
    { X86::SHL16ri, Convert__Reg1_2__Tie0__Imm1_1, { MCK_shlw, MCK_Imm, MCK_GR16 } },
    { X86::SHL16mi, Convert__Mem5_2__Imm1_1, { MCK_shlw, MCK_Imm, MCK_Mem } },
    { X86::SHR8rCL, Convert__Reg1_2__Tie0, { MCK_shrb, MCK_CL, MCK_GR8 } },
    { X86::SHR8mCL, Convert__Mem5_2, { MCK_shrb, MCK_CL, MCK_Mem } },
    { X86::SHR8ri, Convert__Reg1_2__Tie0__Imm1_1, { MCK_shrb, MCK_Imm, MCK_GR8 } },
    { X86::SHR8mi, Convert__Mem5_2__Imm1_1, { MCK_shrb, MCK_Imm, MCK_Mem } },
    { X86::SHR32rCL, Convert__Reg1_2__Tie0, { MCK_shrl, MCK_CL, MCK_GR32 } },
    { X86::SHR32mCL, Convert__Mem5_2, { MCK_shrl, MCK_CL, MCK_Mem } },
    { X86::SHR32ri, Convert__Reg1_2__Tie0__Imm1_1, { MCK_shrl, MCK_Imm, MCK_GR32 } },
    { X86::SHR32mi, Convert__Mem5_2__Imm1_1, { MCK_shrl, MCK_Imm, MCK_Mem } },
    { X86::SHR64rCL, Convert__Reg1_2__Tie0, { MCK_shrq, MCK_CL, MCK_GR64 } },
    { X86::SHR64mCL, Convert__Mem5_2, { MCK_shrq, MCK_CL, MCK_Mem } },
    { X86::SHR64ri, Convert__Reg1_2__Tie0__Imm1_1, { MCK_shrq, MCK_Imm, MCK_GR64 } },
    { X86::SHR64mi, Convert__Mem5_2__Imm1_1, { MCK_shrq, MCK_Imm, MCK_Mem } },
    { X86::SHR16rCL, Convert__Reg1_2__Tie0, { MCK_shrw, MCK_CL, MCK_GR16 } },
    { X86::SHR16mCL, Convert__Mem5_2, { MCK_shrw, MCK_CL, MCK_Mem } },
    { X86::SHR16ri, Convert__Reg1_2__Tie0__Imm1_1, { MCK_shrw, MCK_Imm, MCK_GR16 } },
    { X86::SHR16mi, Convert__Mem5_2__Imm1_1, { MCK_shrw, MCK_Imm, MCK_Mem } },
    { X86::SQRTPDr, Convert__Reg1_2__Reg1_1, { MCK_sqrtpd, MCK_FR32, MCK_FR32 } },
    { X86::SQRTPDm, Convert__Reg1_2__Mem5_1, { MCK_sqrtpd, MCK_Mem, MCK_FR32 } },
    { X86::SQRTPSr, Convert__Reg1_2__Reg1_1, { MCK_sqrtps, MCK_FR32, MCK_FR32 } },
    { X86::SQRTPSm, Convert__Reg1_2__Mem5_1, { MCK_sqrtps, MCK_Mem, MCK_FR32 } },
    { X86::SQRTSDr, Convert__Reg1_2__Reg1_1, { MCK_sqrtsd, MCK_FR32, MCK_FR32 } },
    { X86::SQRTSDm, Convert__Reg1_2__Mem5_1, { MCK_sqrtsd, MCK_Mem, MCK_FR32 } },
    { X86::SQRTSSr, Convert__Reg1_2__Reg1_1, { MCK_sqrtss, MCK_FR32, MCK_FR32 } },
    { X86::SQRTSSm, Convert__Reg1_2__Mem5_1, { MCK_sqrtss, MCK_Mem, MCK_FR32 } },
    { X86::SUB8rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_subb, MCK_GR8, MCK_GR8 } },
    { X86::SUB8rr_REV, Convert__Reg1_2__Tie0__Reg1_1, { MCK_subb, MCK_GR8, MCK_GR8 } },
    { X86::SUB8mr, Convert__Mem5_2__Reg1_1, { MCK_subb, MCK_GR8, MCK_Mem } },
    { X86::SUB8i8, Convert__Imm1_1, { MCK_subb, MCK_Imm, MCK_AL } },
    { X86::SUB8ri, Convert__Reg1_2__Tie0__Imm1_1, { MCK_subb, MCK_Imm, MCK_GR8 } },
    { X86::SUB8mi, Convert__Mem5_2__Imm1_1, { MCK_subb, MCK_Imm, MCK_Mem } },
    { X86::SUB8rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_subb, MCK_Mem, MCK_GR8 } },
    { X86::SUB32rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_subl, MCK_GR32, MCK_GR32 } },
    { X86::SUB32rr_REV, Convert__Reg1_2__Tie0__Reg1_1, { MCK_subl, MCK_GR32, MCK_GR32 } },
    { X86::SUB32mr, Convert__Mem5_2__Reg1_1, { MCK_subl, MCK_GR32, MCK_Mem } },
    { X86::SUB32ri8, Convert__Reg1_2__Tie0__ImmSExt81_1, { MCK_subl, MCK_ImmSExt8, MCK_GR32 } },
    { X86::SUB32mi8, Convert__Mem5_2__ImmSExt81_1, { MCK_subl, MCK_ImmSExt8, MCK_Mem } },
    { X86::SUB32i32, Convert__Imm1_1, { MCK_subl, MCK_Imm, MCK_EAX } },
    { X86::SUB32ri, Convert__Reg1_2__Tie0__Imm1_1, { MCK_subl, MCK_Imm, MCK_GR32 } },
    { X86::SUB32mi, Convert__Mem5_2__Imm1_1, { MCK_subl, MCK_Imm, MCK_Mem } },
    { X86::SUB32rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_subl, MCK_Mem, MCK_GR32 } },
    { X86::SUBPDrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_subpd, MCK_FR32, MCK_FR32 } },
    { X86::SUBPDrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_subpd, MCK_Mem, MCK_FR32 } },
    { X86::SUBPSrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_subps, MCK_FR32, MCK_FR32 } },
    { X86::SUBPSrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_subps, MCK_Mem, MCK_FR32 } },
    { X86::SUB64rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_subq, MCK_GR64, MCK_GR64 } },
    { X86::SUB64rr_REV, Convert__Reg1_2__Tie0__Reg1_1, { MCK_subq, MCK_GR64, MCK_GR64 } },
    { X86::SUB64mr, Convert__Mem5_2__Reg1_1, { MCK_subq, MCK_GR64, MCK_Mem } },
    { X86::SUB64ri8, Convert__Reg1_2__Tie0__ImmSExt81_1, { MCK_subq, MCK_ImmSExt8, MCK_GR64 } },
    { X86::SUB64mi8, Convert__Mem5_2__ImmSExt81_1, { MCK_subq, MCK_ImmSExt8, MCK_Mem } },
    { X86::SUB64i32, Convert__Imm1_1, { MCK_subq, MCK_Imm, MCK_RAX } },
    { X86::SUB64ri32, Convert__Reg1_2__Tie0__Imm1_1, { MCK_subq, MCK_Imm, MCK_GR64 } },
    { X86::SUB64mi32, Convert__Mem5_2__Imm1_1, { MCK_subq, MCK_Imm, MCK_Mem } },
    { X86::SUB64rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_subq, MCK_Mem, MCK_GR64 } },
    { X86::SUBSDrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_subsd, MCK_FR32, MCK_FR32 } },
    { X86::SUBSDrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_subsd, MCK_Mem, MCK_FR32 } },
    { X86::SUBSSrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_subss, MCK_FR32, MCK_FR32 } },
    { X86::SUBSSrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_subss, MCK_Mem, MCK_FR32 } },
    { X86::SUB16rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_subw, MCK_GR16, MCK_GR16 } },
    { X86::SUB16rr_REV, Convert__Reg1_2__Tie0__Reg1_1, { MCK_subw, MCK_GR16, MCK_GR16 } },
    { X86::SUB16mr, Convert__Mem5_2__Reg1_1, { MCK_subw, MCK_GR16, MCK_Mem } },
    { X86::SUB16ri8, Convert__Reg1_2__Tie0__ImmSExt81_1, { MCK_subw, MCK_ImmSExt8, MCK_GR16 } },
    { X86::SUB16mi8, Convert__Mem5_2__ImmSExt81_1, { MCK_subw, MCK_ImmSExt8, MCK_Mem } },
    { X86::SUB16i16, Convert__Imm1_1, { MCK_subw, MCK_Imm, MCK_AX } },
    { X86::SUB16ri, Convert__Reg1_2__Tie0__Imm1_1, { MCK_subw, MCK_Imm, MCK_GR16 } },
    { X86::SUB16mi, Convert__Mem5_2__Imm1_1, { MCK_subw, MCK_Imm, MCK_Mem } },
    { X86::SUB16rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_subw, MCK_Mem, MCK_GR16 } },
    { X86::TEST8rr, Convert__Reg1_2__Reg1_1, { MCK_testb, MCK_GR8, MCK_GR8 } },
    { X86::TEST8i8, Convert__Imm1_1, { MCK_testb, MCK_Imm, MCK_AL } },
    { X86::TEST8ri, Convert__Reg1_2__Imm1_1, { MCK_testb, MCK_Imm, MCK_GR8 } },
    { X86::TEST8mi, Convert__Mem5_2__Imm1_1, { MCK_testb, MCK_Imm, MCK_Mem } },
    { X86::TEST8rm, Convert__Reg1_2__Mem5_1, { MCK_testb, MCK_Mem, MCK_GR8 } },
    { X86::TEST32rr, Convert__Reg1_2__Reg1_1, { MCK_testl, MCK_GR32, MCK_GR32 } },
    { X86::TEST32i32, Convert__Imm1_1, { MCK_testl, MCK_Imm, MCK_EAX } },
    { X86::TEST32ri, Convert__Reg1_2__Imm1_1, { MCK_testl, MCK_Imm, MCK_GR32 } },
    { X86::TEST32mi, Convert__Mem5_2__Imm1_1, { MCK_testl, MCK_Imm, MCK_Mem } },
    { X86::TEST32rm, Convert__Reg1_2__Mem5_1, { MCK_testl, MCK_Mem, MCK_GR32 } },
    { X86::TEST64rr, Convert__Reg1_2__Reg1_1, { MCK_testq, MCK_GR64, MCK_GR64 } },
    { X86::TEST64i32, Convert__Imm1_1, { MCK_testq, MCK_Imm, MCK_RAX } },
    { X86::TEST64ri32, Convert__Reg1_2__Imm1_1, { MCK_testq, MCK_Imm, MCK_GR64 } },
    { X86::TEST64mi32, Convert__Mem5_2__Imm1_1, { MCK_testq, MCK_Imm, MCK_Mem } },
    { X86::TEST64rm, Convert__Reg1_2__Mem5_1, { MCK_testq, MCK_Mem, MCK_GR64 } },
    { X86::TEST16rr, Convert__Reg1_2__Reg1_1, { MCK_testw, MCK_GR16, MCK_GR16 } },
    { X86::TEST16i16, Convert__Imm1_1, { MCK_testw, MCK_Imm, MCK_AX } },
    { X86::TEST16ri, Convert__Reg1_2__Imm1_1, { MCK_testw, MCK_Imm, MCK_GR16 } },
    { X86::TEST16mi, Convert__Mem5_2__Imm1_1, { MCK_testw, MCK_Imm, MCK_Mem } },
    { X86::TEST16rm, Convert__Reg1_2__Mem5_1, { MCK_testw, MCK_Mem, MCK_GR16 } },
    { X86::UCOMISDrr, Convert__Reg1_2__Reg1_1, { MCK_ucomisd, MCK_FR32, MCK_FR32 } },
    { X86::UCOMISDrm, Convert__Reg1_2__Mem5_1, { MCK_ucomisd, MCK_Mem, MCK_FR32 } },
    { X86::UCOMISSrr, Convert__Reg1_2__Reg1_1, { MCK_ucomiss, MCK_FR32, MCK_FR32 } },
    { X86::UCOMISSrm, Convert__Reg1_2__Mem5_1, { MCK_ucomiss, MCK_Mem, MCK_FR32 } },
    { X86::UNPCKHPDrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_unpckhpd, MCK_FR32, MCK_FR32 } },
    { X86::UNPCKHPDrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_unpckhpd, MCK_Mem, MCK_FR32 } },
    { X86::UNPCKHPSrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_unpckhps, MCK_FR32, MCK_FR32 } },
    { X86::UNPCKHPSrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_unpckhps, MCK_Mem, MCK_FR32 } },
    { X86::UNPCKLPDrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_unpcklpd, MCK_FR32, MCK_FR32 } },
    { X86::UNPCKLPDrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_unpcklpd, MCK_Mem, MCK_FR32 } },
    { X86::UNPCKLPSrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_unpcklps, MCK_FR32, MCK_FR32 } },
    { X86::UNPCKLPSrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_unpcklps, MCK_Mem, MCK_FR32 } },
    { X86::VMREAD32rr, Convert__Reg1_2__Reg1_1, { MCK_vmreadl, MCK_GR32, MCK_GR32 } },
    { X86::VMREAD32rm, Convert__Mem5_2__Reg1_1, { MCK_vmreadl, MCK_GR32, MCK_Mem } },
    { X86::VMREAD64rr, Convert__Reg1_2__Reg1_1, { MCK_vmreadq, MCK_GR64, MCK_GR64 } },
    { X86::VMREAD64rm, Convert__Mem5_2__Reg1_1, { MCK_vmreadq, MCK_GR64, MCK_Mem } },
    { X86::VMWRITE32rr, Convert__Reg1_2__Reg1_1, { MCK_vmwritel, MCK_GR32, MCK_GR32 } },
    { X86::VMWRITE32rm, Convert__Reg1_2__Mem5_1, { MCK_vmwritel, MCK_Mem, MCK_GR32 } },
    { X86::VMWRITE64rr, Convert__Reg1_2__Reg1_1, { MCK_vmwriteq, MCK_GR64, MCK_GR64 } },
    { X86::VMWRITE64rm, Convert__Reg1_2__Mem5_1, { MCK_vmwriteq, MCK_Mem, MCK_GR64 } },
    { X86::XADD8rr, Convert__Reg1_2__Reg1_1, { MCK_xaddb, MCK_GR8, MCK_GR8 } },
    { X86::XADD8rm, Convert__Mem5_2__Reg1_1, { MCK_xaddb, MCK_GR8, MCK_Mem } },
    { X86::XADD32rr, Convert__Reg1_2__Reg1_1, { MCK_xaddl, MCK_GR32, MCK_GR32 } },
    { X86::XADD32rm, Convert__Mem5_2__Reg1_1, { MCK_xaddl, MCK_GR32, MCK_Mem } },
    { X86::XADD64rr, Convert__Reg1_2__Reg1_1, { MCK_xaddq, MCK_GR64, MCK_GR64 } },
    { X86::XADD64rm, Convert__Mem5_2__Reg1_1, { MCK_xaddq, MCK_GR64, MCK_Mem } },
    { X86::XADD16rr, Convert__Reg1_2__Reg1_1, { MCK_xaddw, MCK_GR16, MCK_GR16 } },
    { X86::XADD16rm, Convert__Mem5_2__Reg1_1, { MCK_xaddw, MCK_GR16, MCK_Mem } },
    { X86::XCHG8rr, Convert__Reg1_1__Tie0__Reg1_2, { MCK_xchgb, MCK_GR8, MCK_GR8 } },
    { X86::XCHG8rm, Convert__Reg1_1__Tie0__Mem5_2, { MCK_xchgb, MCK_GR8, MCK_Mem } },
    { X86::XCHG32ar, Convert__Reg1_1, { MCK_xchgl, MCK_GR32, MCK_EAX } },
    { X86::XCHG32rr, Convert__Reg1_1__Tie0__Reg1_2, { MCK_xchgl, MCK_GR32, MCK_GR32 } },
    { X86::XCHG32rm, Convert__Reg1_1__Tie0__Mem5_2, { MCK_xchgl, MCK_GR32, MCK_Mem } },
    { X86::XCHG64ar, Convert__Reg1_1, { MCK_xchgq, MCK_GR64, MCK_RAX } },
    { X86::XCHG64rr, Convert__Reg1_1__Tie0__Reg1_2, { MCK_xchgq, MCK_GR64, MCK_GR64 } },
    { X86::XCHG64rm, Convert__Reg1_1__Tie0__Mem5_2, { MCK_xchgq, MCK_GR64, MCK_Mem } },
    { X86::XCHG16ar, Convert__Reg1_1, { MCK_xchgw, MCK_GR16, MCK_AX } },
    { X86::XCHG16rr, Convert__Reg1_1__Tie0__Reg1_2, { MCK_xchgw, MCK_GR16, MCK_GR16 } },
    { X86::XCHG16rm, Convert__Reg1_1__Tie0__Mem5_2, { MCK_xchgw, MCK_GR16, MCK_Mem } },
    { X86::XOR8rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_xorb, MCK_GR8, MCK_GR8 } },
    { X86::XOR8rr_REV, Convert__Reg1_2__Tie0__Reg1_1, { MCK_xorb, MCK_GR8, MCK_GR8 } },
    { X86::XOR8mr, Convert__Mem5_2__Reg1_1, { MCK_xorb, MCK_GR8, MCK_Mem } },
    { X86::XOR8i8, Convert__Imm1_1, { MCK_xorb, MCK_Imm, MCK_AL } },
    { X86::XOR8ri, Convert__Reg1_2__Tie0__Imm1_1, { MCK_xorb, MCK_Imm, MCK_GR8 } },
    { X86::XOR8mi, Convert__Mem5_2__Imm1_1, { MCK_xorb, MCK_Imm, MCK_Mem } },
    { X86::XOR8rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_xorb, MCK_Mem, MCK_GR8 } },
    { X86::XOR32rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_xorl, MCK_GR32, MCK_GR32 } },
    { X86::XOR32rr_REV, Convert__Reg1_2__Tie0__Reg1_1, { MCK_xorl, MCK_GR32, MCK_GR32 } },
    { X86::XOR32mr, Convert__Mem5_2__Reg1_1, { MCK_xorl, MCK_GR32, MCK_Mem } },
    { X86::XOR32ri8, Convert__Reg1_2__Tie0__ImmSExt81_1, { MCK_xorl, MCK_ImmSExt8, MCK_GR32 } },
    { X86::XOR32mi8, Convert__Mem5_2__ImmSExt81_1, { MCK_xorl, MCK_ImmSExt8, MCK_Mem } },
    { X86::XOR32i32, Convert__Imm1_1, { MCK_xorl, MCK_Imm, MCK_EAX } },
    { X86::XOR32ri, Convert__Reg1_2__Tie0__Imm1_1, { MCK_xorl, MCK_Imm, MCK_GR32 } },
    { X86::XOR32mi, Convert__Mem5_2__Imm1_1, { MCK_xorl, MCK_Imm, MCK_Mem } },
    { X86::XOR32rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_xorl, MCK_Mem, MCK_GR32 } },
    { X86::FsXORPDrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_xorpd, MCK_FR32, MCK_FR32 } },
    { X86::XORPDrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_xorpd, MCK_FR32, MCK_FR32 } },
    { X86::FsXORPDrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_xorpd, MCK_Mem, MCK_FR32 } },
    { X86::XORPDrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_xorpd, MCK_Mem, MCK_FR32 } },
    { X86::FsXORPSrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_xorps, MCK_FR32, MCK_FR32 } },
    { X86::XORPSrr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_xorps, MCK_FR32, MCK_FR32 } },
    { X86::FsXORPSrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_xorps, MCK_Mem, MCK_FR32 } },
    { X86::XORPSrm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_xorps, MCK_Mem, MCK_FR32 } },
    { X86::XOR64rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_xorq, MCK_GR64, MCK_GR64 } },
    { X86::XOR64rr_REV, Convert__Reg1_2__Tie0__Reg1_1, { MCK_xorq, MCK_GR64, MCK_GR64 } },
    { X86::XOR64mr, Convert__Mem5_2__Reg1_1, { MCK_xorq, MCK_GR64, MCK_Mem } },
    { X86::XOR64ri8, Convert__Reg1_2__Tie0__ImmSExt81_1, { MCK_xorq, MCK_ImmSExt8, MCK_GR64 } },
    { X86::XOR64mi8, Convert__Mem5_2__ImmSExt81_1, { MCK_xorq, MCK_ImmSExt8, MCK_Mem } },
    { X86::XOR64i32, Convert__Imm1_1, { MCK_xorq, MCK_Imm, MCK_RAX } },
    { X86::XOR64ri32, Convert__Reg1_2__Tie0__Imm1_1, { MCK_xorq, MCK_Imm, MCK_GR64 } },
    { X86::XOR64mi32, Convert__Mem5_2__Imm1_1, { MCK_xorq, MCK_Imm, MCK_Mem } },
    { X86::XOR64rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_xorq, MCK_Mem, MCK_GR64 } },
    { X86::XOR16rr, Convert__Reg1_2__Tie0__Reg1_1, { MCK_xorw, MCK_GR16, MCK_GR16 } },
    { X86::XOR16rr_REV, Convert__Reg1_2__Tie0__Reg1_1, { MCK_xorw, MCK_GR16, MCK_GR16 } },
    { X86::XOR16mr, Convert__Mem5_2__Reg1_1, { MCK_xorw, MCK_GR16, MCK_Mem } },
    { X86::XOR16ri8, Convert__Reg1_2__Tie0__ImmSExt81_1, { MCK_xorw, MCK_ImmSExt8, MCK_GR16 } },
    { X86::XOR16mi8, Convert__Mem5_2__ImmSExt81_1, { MCK_xorw, MCK_ImmSExt8, MCK_Mem } },
    { X86::XOR16i16, Convert__Imm1_1, { MCK_xorw, MCK_Imm, MCK_AX } },
    { X86::XOR16ri, Convert__Reg1_2__Tie0__Imm1_1, { MCK_xorw, MCK_Imm, MCK_GR16 } },
    { X86::XOR16mi, Convert__Mem5_2__Imm1_1, { MCK_xorw, MCK_Imm, MCK_Mem } },
    { X86::XOR16rm, Convert__Reg1_2__Tie0__Mem5_1, { MCK_xorw, MCK_Mem, MCK_GR16 } },
    { X86::BLENDPDrri, Convert__Reg1_3__Tie0__Reg1_2__ImmSExt81_1, { MCK_blendpd, MCK_ImmSExt8, MCK_FR32, MCK_FR32 } },
    { X86::BLENDPDrmi, Convert__Reg1_3__Tie0__Mem5_2__ImmSExt81_1, { MCK_blendpd, MCK_ImmSExt8, MCK_Mem, MCK_FR32 } },
    { X86::BLENDPSrri, Convert__Reg1_3__Tie0__Reg1_2__ImmSExt81_1, { MCK_blendps, MCK_ImmSExt8, MCK_FR32, MCK_FR32 } },
    { X86::BLENDPSrmi, Convert__Reg1_3__Tie0__Mem5_2__ImmSExt81_1, { MCK_blendps, MCK_ImmSExt8, MCK_Mem, MCK_FR32 } },
    { X86::BLENDVPDrr0, Convert__Reg1_3__Tie0__Reg1_2, { MCK_blendvpd, MCK_XMM0, MCK_FR32, MCK_FR32 } },
    { X86::BLENDVPDrm0, Convert__Reg1_3__Tie0__Mem5_2, { MCK_blendvpd, MCK_XMM0, MCK_Mem, MCK_FR32 } },
    { X86::BLENDVPSrr0, Convert__Reg1_3__Tie0__Reg1_2, { MCK_blendvps, MCK_XMM0, MCK_FR32, MCK_FR32 } },
    { X86::BLENDVPSrm0, Convert__Reg1_3__Tie0__Mem5_2, { MCK_blendvps, MCK_XMM0, MCK_Mem, MCK_FR32 } },
    { X86::DPPDrri, Convert__Reg1_3__Tie0__Reg1_2__ImmSExt81_1, { MCK_dppd, MCK_ImmSExt8, MCK_FR32, MCK_FR32 } },
    { X86::DPPDrmi, Convert__Reg1_3__Tie0__Mem5_2__ImmSExt81_1, { MCK_dppd, MCK_ImmSExt8, MCK_Mem, MCK_FR32 } },
    { X86::DPPSrri, Convert__Reg1_3__Tie0__Reg1_2__ImmSExt81_1, { MCK_dpps, MCK_ImmSExt8, MCK_FR32, MCK_FR32 } },
    { X86::DPPSrmi, Convert__Reg1_3__Tie0__Mem5_2__ImmSExt81_1, { MCK_dpps, MCK_ImmSExt8, MCK_Mem, MCK_FR32 } },
    { X86::EXTRACTPSrr, Convert__Reg1_3__Reg1_2__ImmSExt81_1, { MCK_extractps, MCK_ImmSExt8, MCK_FR32, MCK_GR32 } },
    { X86::EXTRACTPSmr, Convert__Mem5_3__Reg1_2__ImmSExt81_1, { MCK_extractps, MCK_ImmSExt8, MCK_FR32, MCK_Mem } },
    { X86::IMUL32rri8, Convert__Reg1_3__Reg1_2__ImmSExt81_1, { MCK_imull, MCK_ImmSExt8, MCK_GR32, MCK_GR32 } },
    { X86::IMUL32rmi8, Convert__Reg1_3__Mem5_2__ImmSExt81_1, { MCK_imull, MCK_ImmSExt8, MCK_Mem, MCK_GR32 } },
    { X86::IMUL32rri, Convert__Reg1_3__Reg1_2__Imm1_1, { MCK_imull, MCK_Imm, MCK_GR32, MCK_GR32 } },
    { X86::IMUL32rmi, Convert__Reg1_3__Mem5_2__Imm1_1, { MCK_imull, MCK_Imm, MCK_Mem, MCK_GR32 } },
    { X86::IMUL64rri8, Convert__Reg1_3__Reg1_2__ImmSExt81_1, { MCK_imulq, MCK_ImmSExt8, MCK_GR64, MCK_GR64 } },
    { X86::IMUL64rmi8, Convert__Reg1_3__Mem5_2__ImmSExt81_1, { MCK_imulq, MCK_ImmSExt8, MCK_Mem, MCK_GR64 } },
    { X86::IMUL64rri32, Convert__Reg1_3__Reg1_2__Imm1_1, { MCK_imulq, MCK_Imm, MCK_GR64, MCK_GR64 } },
    { X86::IMUL64rmi32, Convert__Reg1_3__Mem5_2__Imm1_1, { MCK_imulq, MCK_Imm, MCK_Mem, MCK_GR64 } },
    { X86::IMUL16rri8, Convert__Reg1_3__Reg1_2__ImmSExt81_1, { MCK_imulw, MCK_ImmSExt8, MCK_GR16, MCK_GR16 } },
    { X86::IMUL16rmi8, Convert__Reg1_3__Mem5_2__ImmSExt81_1, { MCK_imulw, MCK_ImmSExt8, MCK_Mem, MCK_GR16 } },
    { X86::IMUL16rri, Convert__Reg1_3__Reg1_2__Imm1_1, { MCK_imulw, MCK_Imm, MCK_GR16, MCK_GR16 } },
    { X86::IMUL16rmi, Convert__Reg1_3__Mem5_2__Imm1_1, { MCK_imulw, MCK_Imm, MCK_Mem, MCK_GR16 } },
    { X86::INSERTPSrr, Convert__Reg1_3__Tie0__Reg1_2__ImmSExt81_1, { MCK_insertps, MCK_ImmSExt8, MCK_FR32, MCK_FR32 } },
    { X86::INSERTPSrm, Convert__Reg1_3__Tie0__Mem5_2__ImmSExt81_1, { MCK_insertps, MCK_ImmSExt8, MCK_Mem, MCK_FR32 } },
    { X86::MPSADBWrri, Convert__Reg1_3__Tie0__Reg1_2__ImmSExt81_1, { MCK_mpsadbw, MCK_ImmSExt8, MCK_FR32, MCK_FR32 } },
    { X86::MPSADBWrmi, Convert__Reg1_3__Tie0__Mem5_2__ImmSExt81_1, { MCK_mpsadbw, MCK_ImmSExt8, MCK_Mem, MCK_FR32 } },
    { X86::PALIGNR64rr, Convert__Reg1_3__Tie0__Reg1_2__Imm1_1, { MCK_palignr, MCK_Imm, MCK_VR64, MCK_VR64 } },
    { X86::PALIGNR128rr, Convert__Reg1_3__Tie0__Reg1_2__Imm1_1, { MCK_palignr, MCK_Imm, MCK_FR32, MCK_FR32 } },
    { X86::PALIGNR64rm, Convert__Reg1_3__Tie0__Mem5_2__Imm1_1, { MCK_palignr, MCK_Imm, MCK_Mem, MCK_VR64 } },
    { X86::PALIGNR128rm, Convert__Reg1_3__Tie0__Mem5_2__Imm1_1, { MCK_palignr, MCK_Imm, MCK_Mem, MCK_FR32 } },
    { X86::PBLENDVBrr0, Convert__Reg1_3__Tie0__Reg1_2, { MCK_pblendvb, MCK_XMM0, MCK_FR32, MCK_FR32 } },
    { X86::PBLENDVBrm0, Convert__Reg1_3__Tie0__Mem5_2, { MCK_pblendvb, MCK_XMM0, MCK_Mem, MCK_FR32 } },
    { X86::PBLENDWrri, Convert__Reg1_3__Tie0__Reg1_2__ImmSExt81_1, { MCK_pblendw, MCK_ImmSExt8, MCK_FR32, MCK_FR32 } },
    { X86::PBLENDWrmi, Convert__Reg1_3__Tie0__Mem5_2__ImmSExt81_1, { MCK_pblendw, MCK_ImmSExt8, MCK_Mem, MCK_FR32 } },
    { X86::PCMPESTRIArr, Convert__Reg1_3__Reg1_2__Imm1_1, { MCK_pcmpestri, MCK_Imm, MCK_FR32, MCK_FR32 } },
    { X86::PCMPESTRICrr, Convert__Reg1_3__Reg1_2__Imm1_1, { MCK_pcmpestri, MCK_Imm, MCK_FR32, MCK_FR32 } },
    { X86::PCMPESTRIOrr, Convert__Reg1_3__Reg1_2__Imm1_1, { MCK_pcmpestri, MCK_Imm, MCK_FR32, MCK_FR32 } },
    { X86::PCMPESTRISrr, Convert__Reg1_3__Reg1_2__Imm1_1, { MCK_pcmpestri, MCK_Imm, MCK_FR32, MCK_FR32 } },
    { X86::PCMPESTRIZrr, Convert__Reg1_3__Reg1_2__Imm1_1, { MCK_pcmpestri, MCK_Imm, MCK_FR32, MCK_FR32 } },
    { X86::PCMPESTRIrr, Convert__Reg1_3__Reg1_2__Imm1_1, { MCK_pcmpestri, MCK_Imm, MCK_FR32, MCK_FR32 } },
    { X86::PCMPESTRIArm, Convert__Reg1_3__Mem5_2__Imm1_1, { MCK_pcmpestri, MCK_Imm, MCK_Mem, MCK_FR32 } },
    { X86::PCMPESTRICrm, Convert__Reg1_3__Mem5_2__Imm1_1, { MCK_pcmpestri, MCK_Imm, MCK_Mem, MCK_FR32 } },
    { X86::PCMPESTRIOrm, Convert__Reg1_3__Mem5_2__Imm1_1, { MCK_pcmpestri, MCK_Imm, MCK_Mem, MCK_FR32 } },
    { X86::PCMPESTRISrm, Convert__Reg1_3__Mem5_2__Imm1_1, { MCK_pcmpestri, MCK_Imm, MCK_Mem, MCK_FR32 } },
    { X86::PCMPESTRIZrm, Convert__Reg1_3__Mem5_2__Imm1_1, { MCK_pcmpestri, MCK_Imm, MCK_Mem, MCK_FR32 } },
    { X86::PCMPESTRIrm, Convert__Reg1_3__Mem5_2__Imm1_1, { MCK_pcmpestri, MCK_Imm, MCK_Mem, MCK_FR32 } },
    { X86::PCMPESTRM128rr, Convert__Reg1_3__Reg1_2__Imm1_1, { MCK_pcmpestrm, MCK_Imm, MCK_FR32, MCK_FR32 } },
    { X86::PCMPESTRM128rm, Convert__Reg1_3__Mem5_2__Imm1_1, { MCK_pcmpestrm, MCK_Imm, MCK_Mem, MCK_FR32 } },
    { X86::PCMPISTRIArr, Convert__Reg1_3__Reg1_2__Imm1_1, { MCK_pcmpistri, MCK_Imm, MCK_FR32, MCK_FR32 } },
    { X86::PCMPISTRICrr, Convert__Reg1_3__Reg1_2__Imm1_1, { MCK_pcmpistri, MCK_Imm, MCK_FR32, MCK_FR32 } },
    { X86::PCMPISTRIOrr, Convert__Reg1_3__Reg1_2__Imm1_1, { MCK_pcmpistri, MCK_Imm, MCK_FR32, MCK_FR32 } },
    { X86::PCMPISTRISrr, Convert__Reg1_3__Reg1_2__Imm1_1, { MCK_pcmpistri, MCK_Imm, MCK_FR32, MCK_FR32 } },
    { X86::PCMPISTRIZrr, Convert__Reg1_3__Reg1_2__Imm1_1, { MCK_pcmpistri, MCK_Imm, MCK_FR32, MCK_FR32 } },
    { X86::PCMPISTRIrr, Convert__Reg1_3__Reg1_2__Imm1_1, { MCK_pcmpistri, MCK_Imm, MCK_FR32, MCK_FR32 } },
    { X86::PCMPISTRIArm, Convert__Reg1_3__Mem5_2__Imm1_1, { MCK_pcmpistri, MCK_Imm, MCK_Mem, MCK_FR32 } },
    { X86::PCMPISTRICrm, Convert__Reg1_3__Mem5_2__Imm1_1, { MCK_pcmpistri, MCK_Imm, MCK_Mem, MCK_FR32 } },
    { X86::PCMPISTRIOrm, Convert__Reg1_3__Mem5_2__Imm1_1, { MCK_pcmpistri, MCK_Imm, MCK_Mem, MCK_FR32 } },
    { X86::PCMPISTRISrm, Convert__Reg1_3__Mem5_2__Imm1_1, { MCK_pcmpistri, MCK_Imm, MCK_Mem, MCK_FR32 } },
    { X86::PCMPISTRIZrm, Convert__Reg1_3__Mem5_2__Imm1_1, { MCK_pcmpistri, MCK_Imm, MCK_Mem, MCK_FR32 } },
    { X86::PCMPISTRIrm, Convert__Reg1_3__Mem5_2__Imm1_1, { MCK_pcmpistri, MCK_Imm, MCK_Mem, MCK_FR32 } },
    { X86::PCMPISTRM128rr, Convert__Reg1_3__Reg1_2__Imm1_1, { MCK_pcmpistrm, MCK_Imm, MCK_FR32, MCK_FR32 } },
    { X86::PCMPISTRM128rm, Convert__Reg1_3__Mem5_2__Imm1_1, { MCK_pcmpistrm, MCK_Imm, MCK_Mem, MCK_FR32 } },
    { X86::PEXTRBrr, Convert__Reg1_3__Reg1_2__ImmSExt81_1, { MCK_pextrb, MCK_ImmSExt8, MCK_FR32, MCK_GR32 } },
    { X86::PEXTRBmr, Convert__Mem5_3__Reg1_2__ImmSExt81_1, { MCK_pextrb, MCK_ImmSExt8, MCK_FR32, MCK_Mem } },
    { X86::PEXTRDrr, Convert__Reg1_3__Reg1_2__ImmSExt81_1, { MCK_pextrd, MCK_ImmSExt8, MCK_FR32, MCK_GR32 } },
    { X86::PEXTRDmr, Convert__Mem5_3__Reg1_2__ImmSExt81_1, { MCK_pextrd, MCK_ImmSExt8, MCK_FR32, MCK_Mem } },
    { X86::PEXTRQrr, Convert__Reg1_3__Reg1_2__ImmSExt81_1, { MCK_pextrq, MCK_ImmSExt8, MCK_FR32, MCK_GR64 } },
    { X86::PEXTRQmr, Convert__Mem5_3__Reg1_2__ImmSExt81_1, { MCK_pextrq, MCK_ImmSExt8, MCK_FR32, MCK_Mem } },
    { X86::MMX_PEXTRWri, Convert__Reg1_3__Reg1_2__ImmSExt81_1, { MCK_pextrw, MCK_ImmSExt8, MCK_VR64, MCK_GR32 } },
    { X86::PEXTRWri, Convert__Reg1_3__Reg1_2__ImmSExt81_1, { MCK_pextrw, MCK_ImmSExt8, MCK_FR32, MCK_GR32 } },
    { X86::PEXTRWmr, Convert__Mem5_3__Reg1_2__ImmSExt81_1, { MCK_pextrw, MCK_ImmSExt8, MCK_FR32, MCK_Mem } },
    { X86::PINSRBrr, Convert__Reg1_3__Tie0__Reg1_2__ImmSExt81_1, { MCK_pinsrb, MCK_ImmSExt8, MCK_GR32, MCK_FR32 } },
    { X86::PINSRBrm, Convert__Reg1_3__Tie0__Mem5_2__ImmSExt81_1, { MCK_pinsrb, MCK_ImmSExt8, MCK_Mem, MCK_FR32 } },
    { X86::PINSRDrr, Convert__Reg1_3__Tie0__Reg1_2__ImmSExt81_1, { MCK_pinsrd, MCK_ImmSExt8, MCK_GR32, MCK_FR32 } },
    { X86::PINSRDrm, Convert__Reg1_3__Tie0__Mem5_2__ImmSExt81_1, { MCK_pinsrd, MCK_ImmSExt8, MCK_Mem, MCK_FR32 } },
    { X86::PINSRQrr, Convert__Reg1_3__Tie0__Reg1_2__ImmSExt81_1, { MCK_pinsrq, MCK_ImmSExt8, MCK_GR64, MCK_FR32 } },
    { X86::PINSRQrm, Convert__Reg1_3__Tie0__Mem5_2__ImmSExt81_1, { MCK_pinsrq, MCK_ImmSExt8, MCK_Mem, MCK_FR32 } },
    { X86::MMX_PINSRWrri, Convert__Reg1_3__Tie0__Reg1_2__ImmSExt81_1, { MCK_pinsrw, MCK_ImmSExt8, MCK_GR32, MCK_VR64 } },
    { X86::PINSRWrri, Convert__Reg1_3__Tie0__Reg1_2__ImmSExt81_1, { MCK_pinsrw, MCK_ImmSExt8, MCK_GR32, MCK_FR32 } },
    { X86::MMX_PINSRWrmi, Convert__Reg1_3__Tie0__Mem5_2__ImmSExt81_1, { MCK_pinsrw, MCK_ImmSExt8, MCK_Mem, MCK_VR64 } },
    { X86::PINSRWrmi, Convert__Reg1_3__Tie0__Mem5_2__ImmSExt81_1, { MCK_pinsrw, MCK_ImmSExt8, MCK_Mem, MCK_FR32 } },
    { X86::PSHUFDri, Convert__Reg1_3__Reg1_2__Imm1_1, { MCK_pshufd, MCK_Imm, MCK_FR32, MCK_FR32 } },
    { X86::PSHUFDmi, Convert__Reg1_3__Mem5_2__Imm1_1, { MCK_pshufd, MCK_Imm, MCK_Mem, MCK_FR32 } },
    { X86::PSHUFHWri, Convert__Reg1_3__Reg1_2__Imm1_1, { MCK_pshufhw, MCK_Imm, MCK_FR32, MCK_FR32 } },
    { X86::PSHUFHWmi, Convert__Reg1_3__Mem5_2__Imm1_1, { MCK_pshufhw, MCK_Imm, MCK_Mem, MCK_FR32 } },
    { X86::PSHUFLWri, Convert__Reg1_3__Reg1_2__Imm1_1, { MCK_pshuflw, MCK_Imm, MCK_FR32, MCK_FR32 } },
    { X86::PSHUFLWmi, Convert__Reg1_3__Mem5_2__Imm1_1, { MCK_pshuflw, MCK_Imm, MCK_Mem, MCK_FR32 } },
    { X86::MMX_PSHUFWri, Convert__Reg1_3__Reg1_2__Imm1_1, { MCK_pshufw, MCK_Imm, MCK_VR64, MCK_VR64 } },
    { X86::MMX_PSHUFWmi, Convert__Reg1_3__Mem5_2__Imm1_1, { MCK_pshufw, MCK_Imm, MCK_Mem, MCK_VR64 } },
    { X86::SHLD32rrCL, Convert__Reg1_3__Tie0__Reg1_2, { MCK_shldl, MCK_CL, MCK_GR32, MCK_GR32 } },
    { X86::SHLD32mrCL, Convert__Mem5_3__Reg1_2, { MCK_shldl, MCK_CL, MCK_GR32, MCK_Mem } },
    { X86::SHLD32rri8, Convert__Reg1_3__Tie0__Reg1_2__Imm1_1, { MCK_shldl, MCK_Imm, MCK_GR32, MCK_GR32 } },
    { X86::SHLD32mri8, Convert__Mem5_3__Reg1_2__Imm1_1, { MCK_shldl, MCK_Imm, MCK_GR32, MCK_Mem } },
    { X86::SHLD64rrCL, Convert__Reg1_3__Tie0__Reg1_2, { MCK_shldq, MCK_CL, MCK_GR64, MCK_GR64 } },
    { X86::SHLD64mrCL, Convert__Mem5_3__Reg1_2, { MCK_shldq, MCK_CL, MCK_GR64, MCK_Mem } },
    { X86::SHLD64rri8, Convert__Reg1_3__Tie0__Reg1_2__Imm1_1, { MCK_shldq, MCK_Imm, MCK_GR64, MCK_GR64 } },
    { X86::SHLD64mri8, Convert__Mem5_3__Reg1_2__Imm1_1, { MCK_shldq, MCK_Imm, MCK_GR64, MCK_Mem } },
    { X86::SHLD16rrCL, Convert__Reg1_3__Tie0__Reg1_2, { MCK_shldw, MCK_CL, MCK_GR16, MCK_GR16 } },
    { X86::SHLD16mrCL, Convert__Mem5_3__Reg1_2, { MCK_shldw, MCK_CL, MCK_GR16, MCK_Mem } },
    { X86::SHLD16rri8, Convert__Reg1_3__Tie0__Reg1_2__Imm1_1, { MCK_shldw, MCK_Imm, MCK_GR16, MCK_GR16 } },
    { X86::SHLD16mri8, Convert__Mem5_3__Reg1_2__Imm1_1, { MCK_shldw, MCK_Imm, MCK_GR16, MCK_Mem } },
    { X86::SHRD32rrCL, Convert__Reg1_3__Tie0__Reg1_2, { MCK_shrdl, MCK_CL, MCK_GR32, MCK_GR32 } },
    { X86::SHRD32mrCL, Convert__Mem5_3__Reg1_2, { MCK_shrdl, MCK_CL, MCK_GR32, MCK_Mem } },
    { X86::SHRD32rri8, Convert__Reg1_3__Tie0__Reg1_2__Imm1_1, { MCK_shrdl, MCK_Imm, MCK_GR32, MCK_GR32 } },
    { X86::SHRD32mri8, Convert__Mem5_3__Reg1_2__Imm1_1, { MCK_shrdl, MCK_Imm, MCK_GR32, MCK_Mem } },
    { X86::SHRD64rrCL, Convert__Reg1_3__Tie0__Reg1_2, { MCK_shrdq, MCK_CL, MCK_GR64, MCK_GR64 } },
    { X86::SHRD64mrCL, Convert__Mem5_3__Reg1_2, { MCK_shrdq, MCK_CL, MCK_GR64, MCK_Mem } },
    { X86::SHRD64rri8, Convert__Reg1_3__Tie0__Reg1_2__Imm1_1, { MCK_shrdq, MCK_Imm, MCK_GR64, MCK_GR64 } },
    { X86::SHRD64mri8, Convert__Mem5_3__Reg1_2__Imm1_1, { MCK_shrdq, MCK_Imm, MCK_GR64, MCK_Mem } },
    { X86::SHRD16rrCL, Convert__Reg1_3__Tie0__Reg1_2, { MCK_shrdw, MCK_CL, MCK_GR16, MCK_GR16 } },
    { X86::SHRD16mrCL, Convert__Mem5_3__Reg1_2, { MCK_shrdw, MCK_CL, MCK_GR16, MCK_Mem } },
    { X86::SHRD16rri8, Convert__Reg1_3__Tie0__Reg1_2__Imm1_1, { MCK_shrdw, MCK_Imm, MCK_GR16, MCK_GR16 } },
    { X86::SHRD16mri8, Convert__Mem5_3__Reg1_2__Imm1_1, { MCK_shrdw, MCK_Imm, MCK_GR16, MCK_Mem } },
    { X86::SHUFPDrri, Convert__Reg1_3__Tie0__Reg1_2__Imm1_1, { MCK_shufpd, MCK_Imm, MCK_FR32, MCK_FR32 } },
    { X86::SHUFPDrmi, Convert__Reg1_3__Tie0__Mem5_2__Imm1_1, { MCK_shufpd, MCK_Imm, MCK_Mem, MCK_FR32 } },
    { X86::SHUFPSrri, Convert__Reg1_3__Tie0__Reg1_2__Imm1_1, { MCK_shufps, MCK_Imm, MCK_FR32, MCK_FR32 } },
    { X86::SHUFPSrmi, Convert__Reg1_3__Tie0__Mem5_2__Imm1_1, { MCK_shufps, MCK_Imm, MCK_Mem, MCK_FR32 } },
    { X86::CMPPDrri, Convert__Reg1_4__Tie0__Reg1_3__Imm1_1, { MCK_cmp, MCK_Imm, MCK_pd, MCK_FR32, MCK_FR32 } },
    { X86::CMPPDrmi, Convert__Reg1_4__Tie0__Mem5_3__Imm1_1, { MCK_cmp, MCK_Imm, MCK_pd, MCK_Mem, MCK_FR32 } },
    { X86::CMPPSrri, Convert__Reg1_4__Tie0__Reg1_3__Imm1_1, { MCK_cmp, MCK_Imm, MCK_ps, MCK_FR32, MCK_FR32 } },
    { X86::CMPPSrmi, Convert__Reg1_4__Tie0__Mem5_3__Imm1_1, { MCK_cmp, MCK_Imm, MCK_ps, MCK_Mem, MCK_FR32 } },
    { X86::CMPSDrr, Convert__Reg1_4__Tie0__Reg1_3__Imm1_1, { MCK_cmp, MCK_Imm, MCK_sd, MCK_FR32, MCK_FR32 } },
    { X86::CMPSDrm, Convert__Reg1_4__Tie0__Mem5_3__Imm1_1, { MCK_cmp, MCK_Imm, MCK_sd, MCK_Mem, MCK_FR32 } },
    { X86::CMPSSrr, Convert__Reg1_4__Tie0__Reg1_3__Imm1_1, { MCK_cmp, MCK_Imm, MCK_ss, MCK_FR32, MCK_FR32 } },
    { X86::CMPSSrm, Convert__Reg1_4__Tie0__Mem5_3__Imm1_1, { MCK_cmp, MCK_Imm, MCK_ss, MCK_Mem, MCK_FR32 } },
  };

  // Eliminate obvious mismatches.
  if (Operands.size() > 5)
    return true;

  // Compute the class list for this operand vector.
  MatchClassKind Classes[5];
  for (unsigned i = 0, e = Operands.size(); i != e; ++i) {
    Classes[i] = ClassifyOperand(Operands[i]);

    // Check for invalid operands before matching.
    if (Classes[i] == InvalidMatchClass)
      return true;
  }

  // Mark unused classes.
  for (unsigned i = Operands.size(), e = 5; i != e; ++i)
    Classes[i] = InvalidMatchClass;

  // Search the table.
  for (const MatchEntry *it = MatchTable, *ie = MatchTable + 2037; it != ie; ++it) {
    if (!IsSubclass(Classes[0], it->Classes[0]))
      continue;
    if (!IsSubclass(Classes[1], it->Classes[1]))
      continue;
    if (!IsSubclass(Classes[2], it->Classes[2]))
      continue;
    if (!IsSubclass(Classes[3], it->Classes[3]))
      continue;
    if (!IsSubclass(Classes[4], it->Classes[4]))
      continue;

    return ConvertToMCInst(it->ConvertFn, Inst, it->Opcode, Operands);
  }

  return true;
}

#endif // REGISTERS_ONLY
