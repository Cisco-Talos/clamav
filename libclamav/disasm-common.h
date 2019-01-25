/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2008-2013 Sourcefire, Inc.
 *
 *  Authors: Török Edvin
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

#ifndef DISASM_BC_H
#define DISASM_BC_H
/** @file */
/** X86 opcode */
enum X86OPS {
  OP_INVALID,
  OP_AAA,/**< Ascii Adjust after Addition */
  OP_AAD,/**< Ascii Adjust AX before Division */
  OP_AAM,/**< Ascii Adjust AX after Multiply */
  OP_AAS,/**< Ascii Adjust AL after Subtraction */
  OP_ADD,/**< Add */
  OP_ADC,/**< Add with Carry */
  OP_AND,/**< Logical And */
  OP_ARPL,/**< Adjust Requested Privilege Level */
  OP_BOUND,/**< Check Array Index Against Bounds */
  OP_BSF,/**< Bit Scan Forward */
  OP_BSR,/**< Bit Scan Reverse */
  OP_BSWAP,/**< Byte Swap */
  OP_BT,/**< Bit Test */
  OP_BTC,/**< Bit Test and Complement */
  OP_BTR,/**< Bit Test and Reset */
  OP_BTS,/**< Bit Test and Set */
  OP_CALL,/**< Call */
  OP_CDQ,/**< Convert DoubleWord to QuadWord*/
  OP_CWD,
  OP_CWDE,/**< Convert Word to DoubleWord */
  OP_CBW,/**< Convert Byte to Word */
  OP_CLC,/**< Clear Carry Flag */
  OP_CLD,/**< Clear Direction Flag */
  OP_CLI,/**< Clear Interrupt Flag */
  OP_CLTS,/**< Clear Task-Switched Flag in CR0 */
  OP_CMC,/**< Complement Carry Flag */
  OP_CMOVO,/**< Conditional Move if Overflow */
  OP_CMOVNO,/**< Conditional Move if Not Overflow */
  OP_CMOVC,/**< Conditional Move if Carry */
  OP_CMOVNC,/**< Conditional Move if Not Carry */
  OP_CMOVZ,/**< Conditional Move if Zero */
  OP_CMOVNZ,/**< Conditional Move if Non-Zero */
  OP_CMOVBE,/**< Conditional Move if Below or Equal */
  OP_CMOVA,/**< Conditional Move if Above */
  OP_CMOVS,/**< Conditional Move if Sign */
  OP_CMOVNS,/**< Conditional Move if Not Sign */
  OP_CMOVP,/**< Conditional Move if Parity */
  OP_CMOVNP,/**< Conditional Move if Not Parity */
  OP_CMOVL,/**< Conditional Move if Less */
  OP_CMOVGE,/**< Conditional Move if Greater or Equal */
  OP_CMOVLE,/**< Conditional Move if Less than or Equal */
  OP_CMOVG,/**< Conditional Move if Greater */
  OP_CMP,/**< Compare */
  OP_CMPSD,/**< Compare String DoubleWord */
  OP_CMPSW,/**< Compare String Word */
  OP_CMPSB,/**< Compare String Byte */
  OP_CMPXCHG,/**< Compare and Exchange */
  OP_CMPXCHG8B,/**< Compare and Exchange Bytes */
  OP_CPUID,/**< CPU Identification */
  OP_DAA,/**< Decimal Adjust AL after Addition */
  OP_DAS,/**< Decimal Adjust AL after Subtraction */
  OP_DEC,/**< Decrement by 1 */
  OP_DIV,/**< Unsigned Divide */
  OP_ENTER,/**< Make Stack Frame for Procedure Parameters */
  OP_FWAIT,/**< Wait */
  OP_HLT,/**< Halt */
  OP_IDIV,/**< Signed Divide */
  OP_IMUL,/**< Signed Multiply */
  OP_INC,/**< Increment by 1 */
  OP_IN,/**< INput from port */
  OP_INSD,/**< INput from port to String Doubleword */
  OP_INSW,/**< INput from port to String Word */
  OP_INSB,/**< INput from port to String Byte */
  OP_INT,/**< INTerrupt */
  OP_INT3,/**< INTerrupt 3 (breakpoint) */
  OP_INTO,/**< INTerrupt 4 if Overflow */
  OP_INVD,/**< Invalidate Internal Caches */
  OP_INVLPG,/**< Invalidate TLB Entry */
  OP_IRET,/**< Interrupt Return */
  OP_JO,/**< Jump if Overflow */
  OP_JNO,/**< Jump if Not Overflow */
  OP_JC,/**< Jump if Carry */
  OP_JNC,/**< Jump if Not Carry */
  OP_JZ,/**< Jump if Zero */
  OP_JNZ,/**< Jump if Not Zero */
  OP_JBE,/**< Jump if Below or Equal */
  OP_JA,/**< Jump if Above */
  OP_JS,/**< Jump if Sign */
  OP_JNS,/**< Jump if Not Sign */
  OP_JP,/**< Jump if Parity */
  OP_JNP,/**< Jump if Not Parity */
  OP_JL,/**< Jump if Less */
  OP_JGE,/**< Jump if Greater or Equal */
  OP_JLE,/**< Jump if Less or Equal */
  OP_JG,/**< Jump if Greater */
  OP_JMP,/**< Jump (unconditional) */
  OP_LAHF,/**< Load Status Flags into AH Register */
  OP_LAR,/**< load Access Rights Byte */
  OP_LDS,/**< Load Far Pointer into DS */
  OP_LES,/**< Load Far Pointer into ES */
  OP_LFS,/**< Load Far Pointer into FS */
  OP_LGS,/**< Load Far Pointer into GS */
  OP_LEA,/**< Load Effective Address */
  OP_LEAVE,/**< High Level Procedure Exit */
  OP_LGDT,/**< Load Global Descript Table Register */
  OP_LIDT,/**< Load Interrupt Descriptor Table Register */
  OP_LLDT,/**< Load Local Descriptor Table Register */
  OP_PREFIX_LOCK,/**< Assert LOCK# Signal Prefix */
  OP_LODSD,/**< Load String Dword*/
  OP_LODSW,/**< Load String Word */
  OP_LODSB,/**< Load String Byte */
  OP_LOOP,/**< Loop According to ECX Counter */
  OP_LOOPE,/**< Loop According to ECX Counter and ZF=1 */
  OP_LOOPNE,/**< Loop According to ECX Counter and ZF=0 */
  OP_JECXZ,/**< Jump if ECX is Zero */
  OP_LSL,/**< Load Segment Limit */
  OP_LSS,/**< Load Far Pointer into SS */
  OP_LTR,/**< Load Task Register */
  OP_MOV,/**< Move */
  OP_MOVSD,/**< Move Data from String to String Doubleword */
  OP_MOVSW,/**< Move Data from String to String Word */
  OP_MOVSB,/**< Move Data from String to String Byte */
  OP_MOVSX,/**< Move with Sign-Extension */
  OP_MOVZX,/**< Move with Zero-Extension */
  OP_MUL,/**< Unsigned Multiply */
  OP_NEG,/**< Two's Complement Negation */
  OP_NOP,/**< No Operation */
  OP_NOT,/**< One's Complement Negation */
  OP_OR,/**< Logical Inclusive OR */
  OP_OUT,/**< Output to Port */
  OP_OUTSD,/**< Output String to Port Doubleword */
  OP_OUTSW,/**< Output String to Port Word */
  OP_OUTSB,/**< Output String to Port Bytes */
  OP_PUSH,/**< Push Onto the Stack */
  OP_PUSHAD,/**< Push All Double General Purpose Registers */
  OP_PUSHA,
  OP_PUSHFD,/**< Push EFLAGS Register onto the Stack */
  OP_PUSHF,
  OP_POP,/**< Pop a Value from the Stack */
  OP_POPAD,/**< Pop All Double General Purpose Registers from the Stack */
  OP_POPFD,/**< Pop Stack into EFLAGS Register */
  OP_POPF,
  OP_RCL,/**< Rotate Carry Left */
  OP_RCR,/**< Rotate Carry Right */
  OP_RDMSR,/**< Read from Model Specific Register */
  OP_RDPMC,/**< Read Performance Monitoring Counters */
  OP_RDTSC,/**< Read Time-Stamp Counter */
  OP_PREFIX_REPE,/**< Repeat String Operation Prefix while Equal */
  OP_PREFIX_REPNE,/**< Repeat String Operation Prefix while Not Equal */
  OP_RETF,/**< Return from Far Procedure */
  OP_RETN,/**< Return from Near Procedure */
  OP_ROL,/**< Rotate Left */
  OP_ROR,/**< Rotate Right */
  OP_RSM,/**< Resume from System Management Mode */
  OP_SAHF,/**< Store AH into Flags */
  OP_SAR,/**< Shift Arithmetic Right */
  OP_SBB,/**< Subtract with Borrow */
  OP_SCASD,/**< Scan String Doubleword */
  OP_SCASW,/**< Scan String Word */
  OP_SCASB,/**< Scan String Byte */
  OP_SETO,/**< Set Byte on Overflow */
  OP_SETNO,/**< Set Byte on Not Overflow */
  OP_SETC,/**< Set Byte on Carry */
  OP_SETNC,/**< Set Byte on Not Carry */
  OP_SETZ,/**< Set Byte on Zero */
  OP_SETNZ,/**< Set Byte on Not Zero */
  OP_SETBE,/**< Set Byte on Below or Equal */
  OP_SETA,/**< Set Byte on Above */
  OP_SETS,/**< Set Byte on Sign */
  OP_SETNS,/**< Set Byte on Not Sign */
  OP_SETP,/**< Set Byte on Parity */
  OP_SETNP,/**< Set Byte on Not Parity */
  OP_SETL,/**< Set Byte on Less */
  OP_SETGE,/**< Set Byte on Greater or Equal */
  OP_SETLE,/**< Set Byte on Less or Equal */
  OP_SETG,/**< Set Byte on Greater */
  OP_SGDT,/**< Store Global Descriptor Table Register */
  OP_SIDT,/**< Store Interrupt Descriptor Table Register */
  OP_SHL,/**< Shift Left */
  OP_SHLD,/**< Double Precision Shift Left */
  OP_SHR,/**< Shift Right */
  OP_SHRD,/**< Double Precision Shift Right */
  OP_SLDT,/**< Store Local Descriptor Table Register */
  OP_STOSD,/**< Store String Doubleword */
  OP_STOSW,/**< Store String Word */
  OP_STOSB,/**< Store String Byte */
  OP_STR,/**< Store Task Register */
  OP_STC,/**< Set Carry Flag */
  OP_STD,/**< Set Direction Flag */
  OP_STI,/**< Set Interrupt Flag */
  OP_SUB,/**< Subtract */
  OP_SYSCALL,/**< Fast System Call */
  OP_SYSENTER,/**< Fast System Call */
  OP_SYSEXIT,/**< Fast Return from Fast System Call */
  OP_SYSRET,/**< Return from Fast System Call */
  OP_TEST,/**< Logical Compare */
  OP_UD2,/**< Undefined Instruction */
  OP_VERR,/**< Verify a Segment for Reading */
  OP_VERRW,/**< Verify a Segment for Writing */
  OP_WBINVD,/**< Write Back and Invalidate Cache */
  OP_WRMSR,/**< Write to Model Specific Register */
  OP_XADD,/**< Exchange and Add */
  OP_XCHG,/**< Exchange Register/Memory with Register */
  OP_XLAT,/**< Table Look-up Translation */
  OP_XOR,/**< Logical Exclusive OR */
  OP_PREFIX_OPSIZE,
  OP_PREFIX_ADDRSIZE,
  OP_PREFIX_SEGMENT,
  OP_2BYTE,

  OP_FPU,/**< FPU operation */

  OP_F2XM1,/**< Compute 2x-1 */
  OP_FABS,/**< Absolute Value */
  OP_FADD,/**< Floating Point Add */
  OP_FADDP,/**< Floating Point Add, Pop */
  OP_FBLD,/**< Load Binary Coded Decimal */
  OP_FBSTP,/**< Store BCD Integer and Pop */
  OP_FCHS,/**< Change Sign */
  OP_FCLEX,/**< Clear Exceptions */
  OP_FCMOVB,/**< Floating Point Move on Below */
  OP_FCMOVBE,/**< Floating Point Move on Below or Equal */
  OP_FCMOVE,/**< Floating Point Move on Equal */
  OP_FCMOVNB,/**< Floating Point Move on Not Below */
  OP_FCMOVNBE,/**< Floating Point Move on Not Below or Equal */
  OP_FCMOVNE,/**< Floating Point Move on Not Equal */
  OP_FCMOVNU,/**< Floating Point Move on Not Unordered */
  OP_FCMOVU,/**< Floating Point Move on Unordered */
  OP_FCOM,/**< Compare Floating Pointer Values and Set FPU Flags */
  OP_FCOMI,/**< Compare Floating Pointer Values and Set EFLAGS */
  OP_FCOMIP,/**< Compare Floating Pointer Values and Set EFLAGS, Pop */
  OP_FCOMP,/**< Compare Floating Pointer Values and Set FPU Flags, Pop */
  OP_FCOMPP,/**< Compare Floating Pointer Values and Set FPU Flags, Pop Twice */
  OP_FCOS,/**< Cosine */
  OP_FDECSTP,/**< Decrement Stack Top Pointer */
  OP_FDIV,/**< Floating Point Divide */
  OP_FDIVP,/**< Floating Point Divide, Pop */
  OP_FDIVR,/**< Floating Point Reverse Divide */
  OP_FDIVRP,/**< Floating Point Reverse Divide, Pop */
  OP_FFREE,/**< Free Floating Point Register */
  OP_FIADD,/**< Floating Point Add */
  OP_FICOM,/**< Compare Integer */
  OP_FICOMP,/**< Compare Integer, Pop */
  OP_FIDIV,/**< Floating Point Divide by Integer */
  OP_FIDIVR,/**< Floating Point Reverse Divide by Integer */
  OP_FILD,/**< Load Integer */
  OP_FIMUL,/**< Floating Point Multiply with Integer */
  OP_FINCSTP,/**< Increment Stack-Top Pointer */
  OP_FINIT,/**< Initialize Floating-Point Unit */
  OP_FIST,/**< Store Integer */
  OP_FISTP,/**< Store Integer, Pop */
  OP_FISTTP,/**< Store Integer with Truncation */
  OP_FISUB,/**< Floating Point Integer Subtract */
  OP_FISUBR,/**< Floating Point Reverse Integer Subtract */
  OP_FLD,/**< Load Floating Point Value */
  OP_FLD1,/**< Load Constant 1 */
  OP_FLDCW,/**< Load x87 FPU Control Word */
  OP_FLDENV,/**< Load x87 FPU Environment */
  OP_FLDL2E,/**< Load Constant log_2(e) */
  OP_FLDL2T,/**< Load Constant log_2(10) */
  OP_FLDLG2,/**< Load Constant log_10(2) */
  OP_FLDLN2,/**< Load Constant log_e(2) */
  OP_FLDPI,/**< Load Constant PI */
  OP_FLDZ,/**< Load Constant Zero */
  OP_FMUL,/**< Floating Point Multiply */
  OP_FMULP,/**< Floating Point Multiply, Pop */
  OP_FNOP,/**< No Operation */
  OP_FPATAN,/**< Partial Arctangent */
  OP_FPREM,/**< Partial Remainder */
  OP_FPREM1,/**< Partial Remainder */
  OP_FPTAN,/**< Partial Tangent */
  OP_FRNDINT,/**< Round to Integer */
  OP_FRSTOR,/**< Restore x86 FPU State */
  OP_FSCALE,/**< Scale */
  OP_FSIN,/* Sine */
  OP_FSINCOS,/**< Sine and Cosine */
  OP_FSQRT,/**< Square Root */
  OP_FSAVE,/**< Store x87 FPU State */
  OP_FST,/**< Store Floating Point Value */
  OP_FSTCW,/**< Store x87 FPU Control Word */
  OP_FSTENV,/**< Store x87 FPU Environment */
  OP_FSTP,/**< Store Floating Point Value, Pop */
  OP_FSTSW,/**< Store x87 FPU Status Word */
  OP_FSUB,/**< Floating Point Subtract */
  OP_FSUBP,/**< Floating Point Subtract, Pop */
  OP_FSUBR,/**< Floating Point Reverse Subtract */
  OP_FSUBRP,/**< Floating Point Reverse Subtract, Pop */
  OP_FTST,/**< Floating Point Test */
  OP_FUCOM,/**< Floating Point Unordered Compare */
  OP_FUCOMI,/**< Floating Point Unordered Compare with Integer */
  OP_FUCOMIP,/**< Floating Point Unorder Compare with Integer, Pop */
  OP_FUCOMP,/**< Floating Point Unorder Compare, Pop */
  OP_FUCOMPP,/**< Floating Point Unorder Compare, Pop Twice */
  OP_FXAM,/**< Examine ModR/M */
  OP_FXCH,/**< Exchange Register Contents */
  OP_FXTRACT,/**< Extract Exponent and Significand */
  OP_FYL2X,/**< Compute y*log2x */
  OP_FYL2XP1 /**< Compute y*log2(x+1) */
};

/** Access type */
enum DIS_ACCESS {
  ACCESS_NOARG, /**< arg not present */
  ACCESS_IMM,   /**< immediate */
  ACCESS_REL,   /**< +/- immediate */
  ACCESS_REG,   /**< register */
  ACCESS_MEM    /**< [memory] */
};

/** for mem access, immediate and relative */
enum DIS_SIZE {
  SIZEB,/**< Byte size access */
  SIZEW,/**< Word size access */
  SIZED,/**< Doubleword size access */
  SIZEF,/**< 6-byte access (seg+reg pair)*/
  SIZEQ,/**< Quadword access */
  SIZET,/**< 10-byte access */
  SIZEPTR /** ptr */
};

/** X86 registers */
enum X86REGS {
  X86_REG_EAX, X86_REG_ECX, X86_REG_EDX, X86_REG_EBX, X86_REG_ESP, X86_REG_EBP, X86_REG_ESI, X86_REG_EDI,
  X86_REG_AX, X86_REG_CX, X86_REG_DX, X86_REG_BX, X86_REG_SP, X86_REG_BP, X86_REG_SI, X86_REG_DI,
  X86_REG_AH, X86_REG_CH, X86_REG_DH, X86_REG_BH, X86_REG_AL, X86_REG_CL, X86_REG_DL, X86_REG_BL,
  X86_REG_ES, X86_REG_CS, X86_REG_SS, X86_REG_DS, X86_REG_FS, X86_REG_GS,
  X86_REG_CR0, X86_REG_CR1, X86_REG_CR2, X86_REG_CR3, X86_REG_CR4, X86_REG_CR5, X86_REG_CR6, X86_REG_CR7,
  X86_REG_DR0, X86_REG_DR1, X86_REG_DR2, X86_REG_DR3, X86_REG_DR4, X86_REG_DR5, X86_REG_DR6, X86_REG_DR7,
  X86_REG_ST0, X86_REG_ST1, X86_REG_ST2, X86_REG_ST3, X86_REG_ST4, X86_REG_ST5, X86_REG_ST6, X86_REG_ST7,
  X86_REG_INVALID
};

/** disassembly result, 64-byte, matched by type-8 signatures */
struct DISASM_RESULT {
    uint16_t real_op;
    uint8_t opsize;
    uint8_t adsize;
    uint8_t segment;
    uint8_t arg[3][10];
    uint8_t extra[29];
};
#endif

