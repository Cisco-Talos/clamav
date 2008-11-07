/*
 *  Copyright (C) 2008 Sourcefire, Inc.
 *
 *  Authors: aCaB <acab@clamav.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */

#ifndef __DISASMPRIV_H
#define __DISASMPRIV_H

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "others.h"

enum X86OPS {
  OP_INVALID,
  OP_AAA,
  OP_AAD,
  OP_AAM,
  OP_AAS,
  OP_ADD,
  OP_ADC,
  OP_AND,
  OP_ARPL,
  OP_BOUND,
  OP_BSF,
  OP_BSR,
  OP_BSWAP,
  OP_BT,
  OP_BTC,
  OP_BTR,
  OP_BTS,
  OP_CALL,
  OP_CDQ,
  OP_CWD,
  OP_CWDE,
  OP_CBW,
  OP_CLC,
  OP_CLD,
  OP_CLI,
  OP_CLTS,
  OP_CMC,
  OP_CMOVO,
  OP_CMOVNO,
  OP_CMOVC,
  OP_CMOVNC,
  OP_CMOVZ,
  OP_CMOVNZ,
  OP_CMOVBE,
  OP_CMOVA,
  OP_CMOVS,
  OP_CMOVNS,
  OP_CMOVP,
  OP_CMOVNP,
  OP_CMOVL,
  OP_CMOVGE,
  OP_CMOVLE,
  OP_CMOVG,
  OP_CMP,
  OP_CMPSD,
  OP_CMPSW,
  OP_CMPSB,
  OP_CMPXCHG,
  OP_CMPXCHG8B,
  OP_CPUID,
  OP_DAA,
  OP_DAS,
  OP_DEC,
  OP_DIV,
  OP_ENTER,
  OP_FWAIT,
  OP_HLT,
  OP_IDIV,
  OP_IMUL,
  OP_INC,
  OP_IN,
  OP_INSD,
  OP_INSW,
  OP_INSB,
  OP_INT,
  OP_INT3,
  OP_INTO,
  OP_INVD,
  OP_INVLPG,
  OP_IRET,
  OP_JO,
  OP_JNO,
  OP_JC,
  OP_JNC,
  OP_JZ,
  OP_JNZ,
  OP_JBE,
  OP_JA,
  OP_JS,
  OP_JNS,
  OP_JP,
  OP_JNP,
  OP_JL,
  OP_JGE,
  OP_JLE,
  OP_JG,
  OP_JMP,
  OP_LAHF,
  OP_LAR,
  OP_LDS,
  OP_LES,
  OP_LFS,
  OP_LGS,
  OP_LEA,
  OP_LEAVE,
  OP_LGDT,
  OP_LIDT,
  OP_LLDT,
  OP_PREFIX_LOCK,
  OP_LODSD,
  OP_LODSW,
  OP_LODSB,
  OP_LOOP,
  OP_LOOPE,
  OP_LOOPNE,
  OP_JECXZ,
  OP_LSL,
  OP_LSS,
  OP_LTR,
  OP_MOV,
  OP_MOVSD,
  OP_MOVSW,
  OP_MOVSB,
  OP_MOVSX,
  OP_MOVZX,
  OP_MUL,
  OP_NEG,
  OP_NOP,
  OP_NOT,
  OP_OR,
  OP_OUT,
  OP_OUTSD,
  OP_OUTSW,
  OP_OUTSB,
  OP_PUSH,
  OP_PUSHAD,
  OP_PUSHA,
  OP_PUSHFD,
  OP_PUSHF,
  OP_POP,
  OP_POPAD,
  OP_POPFD,
  OP_POPF,
  OP_RCL,
  OP_RCR,
  OP_RDMSR,
  OP_RDPMC,
  OP_RDTSC,
  OP_PREFIX_REPE,
  OP_PREFIX_REPNE,
  OP_RETF,
  OP_RETN,
  OP_ROL,
  OP_ROR,
  OP_RSM,
  OP_SAHF,
  OP_SAR,
  OP_SBB,
  OP_SCASD,
  OP_SCASW,
  OP_SCASB,
  OP_SETO,
  OP_SETNO,
  OP_SETC,
  OP_SETNC,
  OP_SETZ,
  OP_SETNZ,
  OP_SETBE,
  OP_SETA,
  OP_SETS,
  OP_SETNS,
  OP_SETP,
  OP_SETNP,
  OP_SETL,
  OP_SETGE,
  OP_SETLE,
  OP_SETG,
  OP_SGDT,
  OP_SIDT,
  OP_SHL,
  OP_SHLD,
  OP_SHR,
  OP_SHRD,
  OP_SLDT,
  OP_STOSD,
  OP_STOSW,
  OP_STOSB,
  OP_STR,
  OP_STC,
  OP_STD,
  OP_STI,
  OP_SUB,
  OP_SYSCALL,
  OP_SYSENTER,
  OP_SYSEXIT,
  OP_SYSRET,
  OP_TEST,
  OP_UD2,
  OP_VERR,
  OP_VERRW,
  OP_WBINVD,
  OP_WRMSR,
  OP_XADD,
  OP_XCHG,
  OP_XLAT,
  OP_XOR,
  OP_PREFIX_OPSIZE,
  OP_PREFIX_ADDRSIZE,
  OP_PREFIX_SEGMENT,
  OP_2BYTE,

  OP_FPU,

  OP_F2XM1,
  OP_FABS,
  OP_FADD,
  OP_FADDP,
  OP_FBLD,
  OP_FBSTP,
  OP_FCHS,
  OP_FCLEX,
  OP_FCMOVB,
  OP_FCMOVBE,
  OP_FCMOVE,
  OP_FCMOVNB,
  OP_FCMOVNBE,
  OP_FCMOVNE,
  OP_FCMOVNU,
  OP_FCMOVU,
  OP_FCOM,
  OP_FCOMI,
  OP_FCOMIP,
  OP_FCOMP,
  OP_FCOMPP,
  OP_FCOS,
  OP_FDECSTP,
  OP_FDIV,
  OP_FDIVP,
  OP_FDIVR,
  OP_FDIVRP,
  OP_FFREE,
  OP_FIADD,
  OP_FICOM,
  OP_FICOMP,
  OP_FIDIV,
  OP_FIDIVR,
  OP_FILD,
  OP_FIMUL,
  OP_FINCSTP,
  OP_FINIT,
  OP_FIST,
  OP_FISTP,
  OP_FISTTP,
  OP_FISUB,
  OP_FISUBR,
  OP_FLD,
  OP_FLD1,
  OP_FLDCW,
  OP_FLDENV,
  OP_FLDL2E,
  OP_FLDL2T,
  OP_FLDLG2,
  OP_FLDLN2,
  OP_FLDPI,
  OP_FLDZ,
  OP_FMUL,
  OP_FMULP,
  OP_FNOP,
  OP_FPATAN,
  OP_FPREM,
  OP_FPREM1,
  OP_FPTAN,
  OP_FRNDINT,
  OP_FRSTOR,
  OP_FSCALE,
  OP_FSIN,
  OP_FSINCOS,
  OP_FSQRT,
  OP_FSAVE,
  OP_FST,
  OP_FSTCW,
  OP_FSTENV,
  OP_FSTP,
  OP_FSTSW,
  OP_FSUB,
  OP_FSUBP,
  OP_FSUBR,
  OP_FSUBRP,
  OP_FTST,
  OP_FUCOM,
  OP_FUCOMI,
  OP_FUCOMIP,
  OP_FUCOMP,
  OP_FUCOMPP,
  OP_FXAM,
  OP_FXCH,
  OP_FXTRACT,
  OP_FYL2X,
  OP_FYL2XP1
};


enum DIS_STATE {
  STATE_GETOP,
  STATE_CHECKDTYPE,
  STATE_CHECKSTYPE,
  STATE_DECODEX87,
  STATE_FINALIZE,
  STATE_COMPLETE,
  STATE_ERROR
};

enum DIS_ACCESS {
  ACCESS_NOARG, /* arg not present */
  ACCESS_IMM,   /* immediate */
  ACCESS_REL,   /* +/- immediate */
  ACCESS_REG,   /* register */
  ACCESS_MEM    /* [something] */
};

enum DIS_SIZE { /* for mem access, immediate and relative */
  SIZEB,
  SIZEW,
  SIZED,
  SIZEF,
  SIZEQ,
  SIZET,
  SIZEPTR
};


enum X86REGS {
  REG_EAX, REG_ECX, REG_EDX, REG_EBX, REG_ESP, REG_EBP, REG_ESI, REG_EDI,
  REG_AX, REG_CX, REG_DX, REG_BX, REG_SP, REG_BP, REG_SI, REG_DI,
  REG_AH, REG_CH, REG_DH, REG_BH, REG_AL, REG_CL, REG_DL, REG_BL,
  REG_ES, REG_CS, REG_SS, REG_DS, REG_FS, REG_GS,
  REG_CR0, REG_CR1, REG_CR2, REG_CR3, REG_CR4, REG_CR5, REG_CR6, REG_CR7,
  REG_DR0, REG_DR1, REG_DR2, REG_DR3, REG_DR4, REG_DR5, REG_DR6, REG_DR7,
  REG_ST0, REG_ST1, REG_ST2, REG_ST3, REG_ST4, REG_ST5, REG_ST6, REG_ST7,
  REG_INVALID
};


struct DIS_ARGS {
  enum DIS_ACCESS access;
  enum DIS_SIZE size;
  enum X86REGS reg;
  union {
    uint8_t b;
    int8_t rb;
    uint16_t w;
    int16_t rw;
    uint32_t d;
    int32_t rd;
    /*    uint48_t f; FIXME */
    uint64_t q;
    int64_t rq;
    struct {
      enum X86REGS r1;  /* scaled */
      enum X86REGS r2;  /* added */
      uint8_t scale; /* r1 multiplier */
      int32_t disp;
    } marg;
  } arg;
};


/* FIXME: pack this thing and make macroes to access it in different compilers */
struct DISASMED {
  uint16_t table_op;
  uint16_t real_op;
  enum DIS_STATE state;
  uint32_t opsize;
  uint32_t adsize;
  uint32_t segment;
  uint8_t cur;
  struct DIS_ARGS args[3];
};

#endif
