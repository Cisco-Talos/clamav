/*
 *  Copyright (C) 2009 Sourcefire, Inc.
 *  All rights reserved.
 *  Authors: Török Edvin
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/** @file */
#ifndef BYTECODE_API_H
#define BYTECODE_API_H

#ifdef __CLAMBC__
#include "bytecode_execs.h"
#include "bytecode_pe.h"
#include "bytecode_disasm.h"
#endif

#ifndef __CLAMBC__
#include "execs.h"
struct DISASM_RESULT;
#endif

struct foo {
    struct foo *nxt;
};

/** Bytecode trigger kind */
enum BytecodeKind {
    /** generic bytecode, not tied a specific hook */
    BC_GENERIC=0,
    _BC_START_HOOKS=256,
    /** triggered by a logical signature */
    BC_LOGICAL=256,
    /** a PE unpacker */
    BC_PE_UNPACKER,
    _BC_LAST_HOOK
};

#ifdef __CLAMBC__

/** @brief Logical signature match counts
 *
 *  This is a low-level variable, use the Macros in bytecode_local.h instead to
 *  access it.
 * */
extern const uint32_t __clambc_match_counts[64];
/** Executable info, if this is a PE hook */
extern const struct cli_exe_info __clambc_exeinfo;
/** PE data, if this is a PE hook */
extern const struct cli_pe_hook_data __clambc_pedata;

/** Kind of the bytecode */
const uint16_t __clambc_kind;

uint32_t test0(struct foo*, uint32_t);
uint32_t test1(uint32_t, uint32_t);

/**
 * @brief Reads specified amount of bytes from the current file
 * into a buffer.
 *
 * @param[in] size amount of bytes to read
 * @param[out] data pointer to buffer where data is read into
 * @return amount read.
 */
int32_t read(uint8_t *data, int32_t size);


enum {
    /**set file position to specified absolute position */
    SEEK_SET=0,
    /**set file position relative to current position */
    SEEK_CUR,
    /**set file position relative to file end*/
    SEEK_END
};

/**
 * @brief Writes the specified amount of bytes from a buffer to the
 * current temporary file.
 * @param[in] data pointer to buffer of data to write
 * @param[in] size amount of bytes to write
 * \p size bytes to temporary file, from the buffer pointed to
 * byte
 * @return amount of bytes successfully written
 */
int32_t write(uint8_t *data, int32_t size);

/**
 * @brief Changes the current file position to the specified one.
 * @sa SEEK_SET, SEEK_CUR, SEEK_END
 * @param[in] pos offset (absolute or relative depending on \p whence param)
 * @param[in] whence one of \p SEEK_SET, \p SEEK_CUR, \p SEEK_END
 * @return absolute position in file
 */
int32_t seek(int32_t pos, uint32_t whence);

/**
 * Sets the name of the virus found.
 *
 * @param[in] name the name of the virus
 * @param[in] len length of the virusname
 * @return 0
 */
uint32_t setvirusname(const uint8_t *name, uint32_t len);

/**
 * Prints a debug message.
 *
 * @param[in] str Message to print
 * @param[in] len length of message to print
 * @return 0
 */
uint32_t debug_print_str(const uint8_t *str, uint32_t len);

/**
 * Prints a number as a debug message.
 *
 * @param[in] a number to print
 * @param b unused
 * @return 0
 */
uint32_t debug_print_uint(uint32_t a, uint32_t b);

/**
 * Disassembles starting from current file position, the specified amount of
 * bytes.
 *  @param[out] result pointer to struct holding result
 *  @param[in] len how many bytes to disassemble
 *  @return 0 for success
 *
 * You can use lseek to disassemble starting from a different location.
 * This is a low-level API, the result is in ClamAV type-8 signature format 
 * (64 bytes/instruction).
 *  \sa DisassembleAt
 * */
uint32_t disasm_x86(struct DISASM_RESULT* result, uint32_t len);

/* tracing API */

/* a scope: lexical block, function, or compile unit */
uint32_t trace_directory(const uint8_t* directory, uint32_t dummy);
uint32_t trace_scope(const uint8_t* newscope, uint32_t scopeid);
uint32_t trace_source(const uint8_t* srcfile, uint32_t line);
uint32_t trace_op(const uint8_t* opname, uint32_t column);
uint32_t trace_value(const uint8_t* name, uint32_t v);
uint32_t trace_ptr(const uint8_t* ptr, uint32_t dummy);

#endif
#endif
