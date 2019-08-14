/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2009-2013 Sourcefire, Inc.

 *  Authors: Török Edvin, Kevin Lin
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

/** @file bytecode_api.h */
#ifndef BYTECODE_API_H
#define BYTECODE_API_H

#ifdef __CLAMBC__
#include "bytecode_execs.h"
#include "bytecode_pe.h"
#include "bytecode_disasm.h"
#include "bytecode_detect.h"
#endif

#ifndef __CLAMBC__
struct cli_exe_section;
struct DISASM_RESULT;
#endif

  /**
\group_pe
   * Invalid RVA specified
   */
#define PE_INVALID_RVA 0xFFFFFFFF

/**
\group_config
 * Specifies the bytecode type and how ClamAV executes it
 */
enum BytecodeKind {
    /** generic bytecode, not tied a specific hook */
    BC_GENERIC=0,
    /** triggered at startup, only one is allowed per ClamAV startup */
    BC_STARTUP=1,
    _BC_START_HOOKS=256,
    /** executed on a logical trigger */
    BC_LOGICAL=256,
    /** specifies a PE unpacker, executed on PE files on a logical trigger */
    BC_PE_UNPACKER,
    /** specifies a PDF hook, executes at a predetermined point of PDF parsing for PDF files */
    BC_PDF,
    /** specifies a PE hook, executes at a predetermined point in PE parsing for PE files,
      * both packed and unpacked files */
    BC_PE_ALL,
    /** specifies a PRECLASS hook, executes at the end of file property collection and
      * operates on the original file targeted for property collection */
    BC_PRECLASS,
    _BC_LAST_HOOK
};

/**
\group_config
 * LibClamAV functionality level constants
 */
enum FunctionalityLevels {
    FUNC_LEVEL_096       = 51, /* LibClamAV release 0.96.0: bytecode engine released */
    FUNC_LEVEL_096_dev   = 52,
    FUNC_LEVEL_096_1     = 53, /* LibClamAV release 0.96.1: logical signature use of VI/macros
                                * requires this minimum functionality level */
    FUNC_LEVEL_096_1_dev = 54,
    FUNC_LEVEL_096_2     = 54, /* LibClamAV release 0.96.2: PDF Hooks require this minimum level */
    FUNC_LEVEL_096_2_dev = 55,
    FUNC_LEVEL_096_3     = 55, /* LibClamAV release 0.96.3: BC_PE_ALL bytecodes require this minimum level */
    FUNC_LEVEL_096_4     = 56, /* LibClamAV release 0.96.4: minimum recommended engine version, older versions
                                * have quadratic load time */
    FUNC_LEVEL_096_5     = 58, /* LibClamAV release 0.96.5 */
    FUNC_LEVEL_097       = 60, /* LibClamAV release 0.97.0: older bytecodes may incorrectly use 57 */
    FUNC_LEVEL_097_1     = 61, /* LibClamAV release 0.97.1 */
    FUNC_LEVEL_097_2     = 62, /* LibClamAV release 0.97.2 */
    FUNC_LEVEL_097_3     = 63, /* LibClamAV release 0.97.3 */ /*last bcc changes as former team resigns*/
    FUNC_LEVEL_097_4     = 64, /* LibClamAV release 0.97.4 */
    FUNC_LEVEL_097_5     = 65, /* LibClamAV release 0.97.5 */
    FUNC_LEVEL_097_6     = 67, /* LibClamAV release 0.97.6 */
    FUNC_LEVEL_097_7     = 68, /* LibClamAV release 0.97.7 */
    FUNC_LEVEL_097_8     = 69, /* LibClamAV release 0.97.8 */
    FUNC_LEVEL_098_1     = 76, /* LibClamAV release 0.98.1 */ /*last syncing to clamav*/
    FUNC_LEVEL_098_2     = 77, /* LibClamAV release 0.98.2 */
    FUNC_LEVEL_098_3     = 77, /* LibClamAV release 0.98.3 */
    FUNC_LEVEL_098_4     = 77, /* LibClamAV release 0.98.4 */
    FUNC_LEVEL_098_5     = 79, /* LibClamAV release 0.98.5: JSON reading API requires this minimum level */
    FUNC_LEVEL_098_6     = 79, /* LibClamAV release 0.98.6 */
    FUNC_LEVEL_098_7     = 80, /* LibClamAV release 0.98.7: BC_PRECLASS bytecodes require minimum level */
    FUNC_LEVEL_099       = 81, /* LibClamAV release 0.99, 0.99-beta1(.1-.5), 0.99-beta2 */
    FUNC_LEVEL_099_1     = 82, /* LibClamAV release 0.99.1 */
    FUNC_LEVEL_099_2     = 82, /* LibClamAV release 0.99.2 */
    FUNC_LEVEL_099_3     = 84, /* LibClamAV release 0.99.3 */
    FUNC_LEVEL_099_4     = 85, /* LibClamAV release 0.99.4 */
    FUNC_LEVEL_0100_0_BETA = 90, /* LibClamAV beta release 0.100.0-beta */
    FUNC_LEVEL_0100_0    = 91, /* LibClamAV release 0.100.0, 0.100.0-rc */
    FUNC_LEVEL_0100_1    = 92, /**< LibClamAV release 0.100.1 */
    FUNC_LEVEL_0100_2    = 93, /**< LibClamAV release 0.100.2 */
    FUNC_LEVEL_0100_3    = 94, /**< LibClamAV release 0.100.3 */
    FUNC_LEVEL_0101_0_BETA = 100, /* LibClamAV beta release 0.101.0-beta */
    FUNC_LEVEL_0101_0    = 101, /* LibClamAV release 0.101.0, 0.101.0-rc */
    FUNC_LEVEL_0101_1    = 102, /* LibClamAV release 0.101.1 */
    FUNC_LEVEL_0101_2    = 102, /* LibClamAV release 0.101.2 */
    FUNC_LEVEL_0101_3    = 102, /* LibClamAV release 0.101.3 */
    FUNC_LEVEL_0101_4    = 105, /* LibClamAV release 0.101.4 */
    FUNC_LEVEL_100       = 255 /* future release candidate */
};

/**
\group_pdf
 * Phase of PDF parsing used for PDF Hooks
 */
enum pdf_phase {
    PDF_PHASE_NONE,     /* not a PDF */
    PDF_PHASE_PARSED,   /* after parsing a PDF, object flags can be set etc. */
    PDF_PHASE_POSTDUMP, /* after an obj was dumped and scanned */
    PDF_PHASE_END,      /* after the pdf scan finished */
    PDF_PHASE_PRE       /* before pdf is parsed at all */
};

/**
\group_pdf
 * PDF flags
 */
enum pdf_flag {
    BAD_PDF_VERSION=0,      /* */
    BAD_PDF_HEADERPOS,      /* */
    BAD_PDF_TRAILER,        /* */
    BAD_PDF_TOOMANYOBJS,    /* */
    BAD_STREAM_FILTERS,     /* */
    BAD_FLATE,              /* */
    BAD_FLATESTART,         /* */
    BAD_STREAMSTART,        /* */
    BAD_ASCIIDECODE,        /* */
    BAD_INDOBJ,             /* */
    UNTERMINATED_OBJ_DICT,  /* */
    ESCAPED_COMMON_PDFNAME, /* */
    HEX_JAVASCRIPT,         /* */
    UNKNOWN_FILTER,         /* */
    MANY_FILTERS,           /* */
    HAS_OPENACTION,         /* */
    BAD_STREAMLEN,          /* */
    ENCRYPTED_PDF,          /* */
    LINEARIZED_PDF,         /* not bad, just as flag */
    DECRYPTABLE_PDF,        /* */
    HAS_LAUNCHACTION        /* */
};

/**
\group_pdf
 * PDF obj flags
 */
enum pdf_objflags {
    OBJ_STREAM=0,        /* */
    OBJ_DICT,            /* */
    OBJ_EMBEDDED_FILE,   /* */
    OBJ_FILTER_AH,       /* */
    OBJ_FILTER_A85,      /* */
    OBJ_FILTER_FLATE,    /* */
    OBJ_FILTER_LZW,      /* */
    OBJ_FILTER_RL,       /* */
    OBJ_FILTER_FAX,      /* */
    OBJ_FILTER_JBIG2,    /* */
    OBJ_FILTER_DCT,      /* */
    OBJ_FILTER_JPX,      /* */
    OBJ_FILTER_CRYPT,    /* */
    OBJ_FILTER_UNKNOWN,  /* */
    OBJ_JAVASCRIPT,      /* */
    OBJ_OPENACTION,      /* */
    OBJ_HASFILTERS,      /* */
    OBJ_SIGNED,          /* */
    OBJ_IMAGE,           /* */
    OBJ_TRUNCATED,       /* */
    OBJ_FORCEDUMP,       /* */
    OBJ_FILTER_STANDARD, /* */
    OBJ_LAUNCHACTION,    /* */
    OBJ_PAGE,            /* */
    OBJ_CONTENTS         /* */
};

/**
\group_json
 * JSON types
 */
enum bc_json_type {
    JSON_TYPE_NULL=0,    /* */
    JSON_TYPE_BOOLEAN,   /* */
    JSON_TYPE_DOUBLE,    /* */
    JSON_TYPE_INT,       /* */
    JSON_TYPE_OBJECT,    /* */
    JSON_TYPE_ARRAY,     /* */
    JSON_TYPE_STRING     /* */
};

/**
\group_engine
 * Scan option flag values for engine_scan_options(). *DEPRECATED*
 */
#define CL_SCAN_RAW                     0x0
#define CL_SCAN_ARCHIVE                 0x1
#define CL_SCAN_MAIL                    0x2
#define CL_SCAN_OLE2                    0x4
#define CL_SCAN_BLOCKENCRYPTED          0x8
#define CL_SCAN_HTML                    0x10
#define CL_SCAN_PE                      0x20
#define CL_SCAN_BLOCKBROKEN             0x40
#define CL_SCAN_MAILURL                 0x80  /* deprecated circa 2009 */
#define CL_SCAN_BLOCKMAX                0x100
#define CL_SCAN_ALGORITHMIC             0x200
//#define UNUSED                        0x400
#define CL_SCAN_PHISHING_BLOCKSSL       0x800 /* ssl mismatches, not ssl by itself*/
#define CL_SCAN_PHISHING_BLOCKCLOAK     0x1000
#define CL_SCAN_ELF                     0x2000
#define CL_SCAN_PDF                     0x4000
#define CL_SCAN_STRUCTURED              0x8000
#define CL_SCAN_STRUCTURED_SSN_NORMAL   0x10000
#define CL_SCAN_STRUCTURED_SSN_STRIPPED 0x20000
#define CL_SCAN_PARTIAL_MESSAGE         0x40000
#define CL_SCAN_HEURISTIC_PRECEDENCE    0x80000
#define CL_SCAN_BLOCKMACROS             0x100000
#define CL_SCAN_ALLMATCHES              0x200000
#define CL_SCAN_SWF                     0x400000
#define CL_SCAN_PARTITION_INTXN         0x800000
#define CL_SCAN_XMLDOCS                 0x1000000
#define CL_SCAN_HWP3                    0x2000000
//#define UNUSED                        0x4000000
//#define UNUSED                        0x8000000
#define CL_SCAN_FILE_PROPERTIES         0x10000000
//#define UNUSED                        0x20000000
#define CL_SCAN_PERFORMANCE_INFO        0x40000000 /* Collect performance timings */
#define CL_SCAN_INTERNAL_COLLECT_SHA    0x80000000 /* Enables hash output in sha-collect builds - for internal use only */


#ifdef __CLAMBC__

/* --------------- BEGIN GLOBALS -------------------------------------------- */
/**
\group_globals
 * Logical signature match counts
 * @brief This is a low-level variable, use the Macros in bytecode_local.h instead to
 *        access it.
 */
extern const uint32_t __clambc_match_counts[64];

/**
\group_globals
  * Logical signature match offsets
  * @brief This is a low-level variable, use the Macros in bytecode_local.h instead to
  *        access it.
  */
extern const uint32_t __clambc_match_offsets[64];

/**
\group_globals
 * PE data, if this is a PE hook.
 */
extern const struct cli_pe_hook_data __clambc_pedata;
/**
\group_globals
 * File size (max 4G).
 */
extern const uint32_t __clambc_filesize[1];

/**
\group_globals
 * Kind of the bytecode, affects LibClamAV usage
 */
const uint16_t __clambc_kind;
/* ---------------- END GLOBALS --------------------------------------------- */
/* ---------------- BEGIN 0.96 APIs (don't touch) --------------------------- */
/**
 * Test api.
 * @param[in] a 0xf00dbeef
 * @param[in] b 0xbeeff00d
 * @return 0x12345678 if parameters match, 0x55 otherwise
*/
uint32_t test1(uint32_t a, uint32_t b);

/**
\group_file
 * Reads specified amount of bytes from the current file
 * into a buffer. Also moves current position in the file.
 * @param[in] size amount of bytes to read
 * @param[out] data pointer to buffer where data is read into
 * @return amount read.
 */
int32_t read(uint8_t *data, int32_t size);

/**
\group_file
 */
enum {
    /**set file position to specified absolute position */
    SEEK_SET=0,
    /**set file position relative to current position */
    SEEK_CUR,
    /**set file position relative to file end*/
    SEEK_END
};

/**
\group_file
 * Writes the specified amount of bytes from a buffer to the
 * current temporary file.
 * @param[in] data pointer to buffer of data to write
 * @param[in] size amount of bytes to write
 * \p size bytes to temporary file, from the buffer pointed to
 * byte
 * @return amount of bytes successfully written
 */
int32_t write(uint8_t *data, int32_t size);

/**
\group_file
 * Changes the current file position to the specified one.
 * @sa SEEK_SET, SEEK_CUR, SEEK_END
 * @param[in] pos offset (absolute or relative depending on \p whence param)
 * @param[in] whence one of \p SEEK_SET, \p SEEK_CUR, \p SEEK_END
 * @return absolute position in file
 */
int32_t seek(int32_t pos, uint32_t whence);

/**
\group_scan
 * Sets the name of the virus found.
 * @param[in] name the name of the virus
 * @param[in] len length of the virusname
 * @return 0
 */
uint32_t setvirusname(const uint8_t *name, uint32_t len);

/**
\group_debug
 * Prints a debug message string.
 * @param[in] str Message to print
 * @param[in] len length of message to print
 * @return 0
 */
uint32_t debug_print_str(const uint8_t *str, uint32_t len);

/**
\group_debug
 * Prints a number as a debug message.
 * This is similar to \p debug_print_str_nonl.
 * @param[in] a number to print
 * @return 0
 */
uint32_t debug_print_uint(uint32_t a);

/**
\group_disasm
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
 */
uint32_t disasm_x86(struct DISASM_RESULT* result, uint32_t len);

/* tracing API, private */

/* a scope: lexical block, function, or compile unit */
uint32_t trace_directory(const uint8_t* directory, uint32_t dummy);
uint32_t trace_scope(const uint8_t* newscope, uint32_t scopeid);
uint32_t trace_source(const uint8_t* srcfile, uint32_t line);
uint32_t trace_op(const uint8_t* opname, uint32_t column);
uint32_t trace_value(const uint8_t* name, uint32_t v);
uint32_t trace_ptr(const uint8_t* ptr, uint32_t dummy);

/**
\group_pe
 * Converts a RVA (Relative Virtual Address) to
 * an absolute PE file offset.
 * @param[in] rva a rva address from the PE file
 * @return absolute file offset mapped to the \p rva,
 * or PE_INVALID_RVA if the \p rva is invalid.
 */
uint32_t pe_rawaddr(uint32_t rva);

/**
\group_file
 * Looks for the specified sequence of bytes in the current file.
 * @param[in] data the sequence of bytes to look for
 * @param[in] len length of \p data, cannot be more than 1024
 * @return offset in the current file if match is found, -1 otherwise
 */
int32_t file_find(const uint8_t* data, uint32_t len);

/**
\group_file
 * Read a single byte from current file
 * @param[in] offset file offset
 * @return byte at offset \p off in the current file, or -1 if offset is
 * invalid
 */
int32_t file_byteat(uint32_t offset);

/**
\group_adt
 * Allocates memory. Currently this memory is freed automatically on exit
 * from the bytecode, and there is no way to free it sooner.
 * @param[in] size amount of memory to allocate in bytes
 * @return pointer to allocated memory
 */
void* malloc(uint32_t size);

/**
 * Test api2.
 * @param[in] a 0xf00d
 * @return 0xd00f if parameter matches, 0x5555 otherwise
 */
uint32_t test2(uint32_t a);

/**
\group_pe
 * Gets information about the specified PE section.
 * @param[out] section PE section information will be stored here
 * @param[in] num PE section number
 * @return  0 - success
 * @return -1 - failure
 */
int32_t get_pe_section(struct cli_exe_section *section, uint32_t num);

/**
\group_file
  * Fills the specified buffer with at least \p fill bytes.
  * @param[out] buffer the buffer to fill
  * @param[in] len length of buffer
  * @param[in] filled how much of the buffer is currently filled
  * @param[in] cursor position of cursor in buffer
  * @param[in] fill amount of bytes to fill in (0 is valid)
  * @return <0 on error
  * @return  0 on EOF
  * @return  number bytes available in buffer (starting from 0)\n
  * The character at the cursor will be at position 0 after this call.
  */
int32_t fill_buffer(uint8_t* buffer, uint32_t len, uint32_t filled,
                    uint32_t cursor, uint32_t fill);

/**
\group_scan
 * Prepares for extracting a new file, if we've already extracted one it scans
 * it.
 * @param[in] id an id for the new file (for example position in container)
 * @return 1 if previous extracted file was infected
 */
int32_t extract_new(int32_t id);

/**
\group_file
  * Reads a number in the specified radix starting from the current position.
  * Non-numeric characters are ignored.
  * @param[in] radix 10 or 16
  * @return the number read
  */
int32_t read_number(uint32_t radix);

/**
\group_adt
 * Creates a new hashset and returns its id.
 * @return ID for new hashset
 */
int32_t hashset_new(void);

/**
\group_adt
 * Add a new 32-bit key to the hashset.
 * @param[in] hs ID of hashset (from hashset_new)
 * @param[in] key the key to add
 * @return 0 on success
 */
int32_t hashset_add(int32_t hs, uint32_t key);

/**
\group_adt
 * Remove a 32-bit key from the hashset.
 * @param[in] hs ID of hashset (from hashset_new)
 * @param[in] key the key to add
 * @return 0 on success
 */
int32_t hashset_remove(int32_t hs, uint32_t key);

/**
\group_adt
 * Returns whether the hashset contains the specified key.
 * @param[in] hs ID of hashset (from hashset_new)
 * @param[in] key the key to lookup
 * @return 1 if found
 * @return 0 if not found
 * @return <0 on invalid hashset ID
 */
int32_t hashset_contains(int32_t hs, uint32_t key);

/**
\group_adt
 * Deallocates the memory used by the specified hashset.
 * Trying to use the hashset after this will result in an error.
 * The hashset may not be used after this.
 * All hashsets are automatically deallocated when bytecode
 * finishes execution.
 * @param[in] id ID of hashset (from hashset_new)
 * @return 0 on success
 */
int32_t hashset_done(int32_t id);

/**
\group_adt
 * Returns whether the hashset is empty.
 * @param[in] id of hashset (from hashset_new)
 * @return 0 on success
 */
int32_t hashset_empty(int32_t id);

/**
\group_adt
 * Creates a new pipe with the specified buffer size
 * @param[in] size size of buffer
 * @return ID of newly created buffer_pipe
 */
int32_t  buffer_pipe_new(uint32_t size);

/**
  \group_adt
  * Creates a new pipe with the specified buffer size w/ tied input
  * to the current file, at the specified position.
  * @param[in] pos starting position of pipe input in current file
  * @return ID of newly created buffer_pipe
  */
int32_t  buffer_pipe_new_fromfile(uint32_t pos);

/**
\group_adt
  * Returns the amount of bytes available to read.
  * @param[in] id ID of buffer_pipe
  * @return amount of bytes available to read
  */
uint32_t buffer_pipe_read_avail(int32_t id);

/**
\group_adt
  * Returns a pointer to the buffer for reading.
  * The 'amount' parameter should be obtained by a call to
  * buffer_pipe_read_avail().
  * @param[in] id ID of buffer_pipe
  * @param[in] amount to read
  * @return pointer to buffer, or NULL if buffer has less than
  * specified amount
  */
//uint8_t *buffer_pipe_read_get(int32_t id, uint32_t amount);
const uint8_t *buffer_pipe_read_get(int32_t id, uint32_t amount);

/**
\group_adt
  * Updates read cursor in buffer_pipe.
  * @param[in] id ID of buffer_pipe
  * @param[in] amount amount of bytes to move read cursor
  * @return 0 on success
  */
int32_t  buffer_pipe_read_stopped(int32_t id, uint32_t amount);

/**
\group_adt
  * Returns the amount of bytes available for writing.
  * @param[in] id ID of buffer_pipe
  * @return amount of bytes available for writing
  */
uint32_t buffer_pipe_write_avail(int32_t id);

/**
\group_adt
  * Returns pointer to writable buffer.
  * The 'size' parameter should be obtained by a call to
  * buffer_pipe_write_avail().
  * @param[in] id ID of buffer_pipe
  * @param[in] size amount of bytes to write
  * @return pointer to write buffer, or NULL if requested amount
  * is more than what is available in the buffer
  */
uint8_t *buffer_pipe_write_get(int32_t id, uint32_t size);

/**
\group_adt
  * Updates the write cursor in buffer_pipe.
  * @param[in] id ID of buffer_pipe
  * @param[in] amount amount of bytes to move write cursor
  * @return 0 on success
  */
int32_t  buffer_pipe_write_stopped(int32_t id, uint32_t amount);

/**
\group_adt
  * Deallocate memory used by buffer.
  * After this all attempts to use this buffer will result in error.
  * All buffer_pipes are automatically deallocated when bytecode
  * finishes execution.
  * @param[in] id ID of buffer_pipe
  * @return 0 on success
  */
int32_t  buffer_pipe_done(int32_t id);

/**
\group_adt
  * Initializes inflate data structures for decompressing data
  * 'from_buffer' and writing uncompressed uncompressed data 'to_buffer'.
  * @param[in] from_buffer ID of buffer_pipe to read compressed data from
  * @param[in] to_buffer ID of buffer_pipe to write decompressed data to
  * @param[in] windowBits (see zlib documentation)
  * @return ID of newly created inflate data structure, <0 on failure
  */
int32_t inflate_init(int32_t from_buffer, int32_t to_buffer, int32_t windowBits);

/**
\group_adt
  * Inflate all available data in the input buffer, and write to output buffer.
  * Stops when the input buffer becomes empty, or write buffer becomes full.
  * Also attempts to recover from corrupted inflate stream (via inflateSync).
  * This function can be called repeatedly on success after filling the input
  * buffer, and flushing the output buffer.
  * The inflate stream is done processing when 0 bytes are available from output
  * buffer, and input buffer is not empty.
  * @param[in] id ID of inflate data structure
  * @return 0 on success, zlib error code otherwise
  */
int32_t inflate_process(int32_t id);

/**
\group_adt
  * Deallocates inflate data structure.
  * Using the inflate data structure after this will result in an error.
  * All inflate data structures are automatically deallocated when bytecode
  * finishes execution.
  * @param[in] id ID of inflate data structure
  * @return 0 on success.
  */
int32_t inflate_done(int32_t id);

/**
\group_scan
  * Report a runtime error at the specified locationID.
  * @param[in] locationid (line << 8) | (column&0xff)
  * @return 0
  */
int32_t bytecode_rt_error(int32_t locationid);

/**
\group_js
  * Initializes JS normalizer for reading 'from_buffer'.
  * Normalized JS will be written to a single tempfile,
  * one normalized JS per line, and automatically scanned
  * when the bytecode finishes execution.
  * @param[in] from_buffer ID of buffer_pipe to read javascript from
  * @return ID of JS normalizer, <0 on failure
  */
int32_t jsnorm_init(int32_t from_buffer);

/**
\group_js
  * Normalize all javascript from the input buffer, and write to tempfile.
  * You can call this function repeatedly on success, if you (re)fill the input
  * buffer.
  * @param[in] id ID of JS normalizer
  * @return 0 on success, <0 on failure
  */
int32_t jsnorm_process(int32_t id);

/**
\group_js
  * Flushes JS normalizer.
  * @param[in] id ID of js normalizer to flush
  * @return 0 on success, <0 on failure
  */
int32_t jsnorm_done(int32_t id);

/* ---------------- END 0.96 APIs (don't touch) --------------------------- */
/* ---------------- BEGIN 0.96.1 APIs ------------------------------------- */

/* ---------------- Math -------------------------------------------------- */

/**
\group_math
  * Returns 2^26*log2(a/b)
  * @param[in] a input
  * @param[in] b input
  * @return 2^26*log2(a/b)
  */
int32_t ilog2(uint32_t a, uint32_t b);

/**
\group_math
  * Returns c*a^b.
  * @param[in] a integer
  * @param[in] b integer
  * @param[in] c integer
  * @return c*pow(a,b)
  */
int32_t ipow(int32_t a, int32_t b, int32_t c);

/**
\group_math
  * Returns exp(a/b)*c
  * @param[in] a integer
  * @param[in] b integer
  * @param[in] c integer
  * @return c*exp(a/b)
  */
uint32_t iexp(int32_t a, int32_t b, int32_t c);

/**
\group_math
  * Returns c*sin(a/b).
  * @param[in] a integer
  * @param[in] b integer
  * @param[in] c integer
  * @return c*sin(a/b)
  */
int32_t isin(int32_t a, int32_t b, int32_t c);

/**
\group_math
  * Returns c*cos(a/b).
  * @param[in] a integer
  * @param[in] b integer
  * @param[in] c integer
  * @return c*sin(a/b)
  */
int32_t icos(int32_t a, int32_t b, int32_t c);

/* ---------------- String operations --------------------------------------- */
/**
\group_string
  * Return position of match, -1 otherwise.
  * @param[in] haystack buffer to search
  * @param[in] haysize size of \p haystack
  * @param[in] needle substring to search
  * @param[in] needlesize size of needle
  * @return location of match, -1 otherwise
  */
int32_t memstr(const uint8_t* haystack, int32_t haysize,
               const uint8_t* needle, int32_t needlesize);

/**
\group_string
  * Returns hexadecimal characters \p hex1 and \p hex2 converted to 8-bit
  * number.
  * @param[in] hex1 hexadecimal character
  * @param[in] hex2 hexadecimal character
  * @return hex1 hex2 converted to 8-bit integer, -1 on error
  */
int32_t hex2ui(uint32_t hex1, uint32_t hex2);

/**
\group_string
  * Converts string to positive number.
  * @param[in] str buffer
  * @param[in] size size of \p str
  * @return >0 string converted to number if possible, -1 on error
  */
int32_t atoi(const uint8_t* str, int32_t size);

/**
\group_debug
  * Prints a debug message with a trailing newline,
  * but preceded by 'LibClamAV debug'.
  * @param[in] str the string
  * @param[in] len length of \p str
  * @return 0
  */
uint32_t debug_print_str_start(const uint8_t *str, uint32_t len);

/**
\group_debug
  * Prints a debug message with a trailing newline,
  * and not preceded by 'LibClamAV debug'.
  * @param[in] str the string
  * @param[in] len length of \p str
  * @return 0
  */
uint32_t debug_print_str_nonl(const uint8_t *str, uint32_t len);

/**
\group_string
  * Returns an approximation for the entropy of \p buffer.
  * @param[in] buffer input buffer
  * @param[in] size size of buffer
  * @return entropy estimation * 2^26
  */
uint32_t entropy_buffer(uint8_t* buffer, int32_t size);

/* ------------------ Data Structures --------------------------------------- */
/**
\group_adt
  * Creates a new map and returns its id.
  * @param[in] keysize size of key
  * @param[in] valuesize size of value, if 0 then value is allocated separately
  * @return ID of new map
  */
int32_t map_new(int32_t keysize, int32_t valuesize);

/**
\group_adt
  * Inserts the specified key/value pair into the map.
  * @param[in] id id of table
  * @param[in] key key
  * @param[in] ksize size of \p key
  * @return 0 - if key existed before
  * @return 1 - if key didn't exist before
  * @return <0 - if ksize doesn't match keysize specified at table creation
  */
int32_t map_addkey(const uint8_t *key, int32_t ksize, int32_t id);

/**
\group_adt
  * Sets the value for the last inserted key with map_addkey.
  * @param[in] id id of table
  * @param[in] value value
  * @param[in] vsize size of \p value
  * @return 0 - if update was successful
  * @return <0 - if there is no last key
  */
int32_t map_setvalue(const uint8_t *value, int32_t vsize, int32_t id);

/**
\group_adt
  * Remove an element from the map.
  * @param[in] id id of map
  * @param[in] key key
  * @param[in] ksize size of key
  * @return 0 on success, key was present
  * @return 1 if key was not present
  * @return <0 if ksize doesn't match keysize specified at table creation
  */
int32_t map_remove(const uint8_t* key, int32_t ksize, int32_t id);

/**
\group_adt
  * Looks up key in map.
  * The map remember the last looked up key (so you can retrieve the
  * value).
  * @param[in] id id of map
  * @param[in] key key
  * @param[in] ksize size of key
  * @return 0 - if not found
  * @return 1 - if found
  * @return <0 - if ksize doesn't match the size specified at table creation
  */
int32_t map_find(const uint8_t* key, int32_t ksize, int32_t id);

/**
\group_adt
  * Returns the size of value obtained during last map_find.
  * @param[in] id id of map.
  * @return size of value
  */
int32_t map_getvaluesize(int32_t id);

/**
\group_adt
  * Returns the value obtained during last map_find.
  * @param[in] id id of map.
  * @param[in] size size of value (obtained from map_getvaluesize)
  * @return value
  */
uint8_t* map_getvalue(int32_t id, int32_t size);

/**
\group_adt
  * Deallocates the memory used by the specified map.
  * Trying to use the map after this will result in an error.
  * All maps are automatically deallocated when the bytecode finishes
  * execution.
  * @param[in] id id of map
  * @return 0 - success
  * @return -1 - invalid map
  */
int32_t map_done(int32_t id);

/* -------------- File Operations ------------------------------------------- */
/**
\group_file
  * Looks for the specified sequence of bytes in the current file, up to the
  * specified position.
  * @param[in] data the sequence of bytes to look for
  * @param[in] len length of \p data, cannot be more than 1024
  * @param[in] maxpos maximum position to look for a match,
  * note that this is 1 byte after the end of last possible match:
  * match_pos + \p len < \p maxpos
  * @return offset in the current file if match is found, -1 otherwise
  */
int32_t file_find_limit(const uint8_t *data, uint32_t len, int32_t maxpos);

/* ------------- Engine Query ----------------------------------------------- */
/**
\group_engine
  * Returns the current engine (feature) functionality level.
  * To map these to ClamAV releases, compare it with #FunctionalityLevels.
  * @return an integer representing current engine functionality level.
  */
uint32_t engine_functionality_level(void);

/**
\group_engine
  * Returns the current engine (dconf) functionality level.
  * Usually identical to engine_functionality_level(), unless distro backported
  * patches. Compare with #FunctionalityLevels.
  * @return an integer representing the DCONF (security fixes) level.
  */
uint32_t engine_dconf_level(void);

/**
\group_engine
  * Returns the current engine's scan options. **DEPRECATED**
  * @return CL_SCAN* flags
  */
uint32_t engine_scan_options(void);

/**
\group_engine
  * Returns the current engine's db options.
  * @return CL_DB_* flags
  */
uint32_t engine_db_options(void);

/* ---------------- Scan Control -------------------------------------------- */
/**
\group_scan
  * Sets the container type for the currently extracted file.
  * @param[in] container container type (CL_TYPE_*)
  * @return current setting for container (CL_TYPE_ANY default)
  */
int32_t extract_set_container(uint32_t container);

/**
\group_scan
  * Toggles the read/seek API to read from the currently extracted file, and
  * back.
  * You must call seek after switching inputs to position the cursor to a valid
  * position.
  * @param[in] extracted_file 1 - switch to reading from extracted file\n
                              0 - switch back to original input
  * @return -1 on error (if no extracted file exists)
  * @return  0 on success
  */
int32_t input_switch(int32_t extracted_file);

/* ---------------- END 0.96.1 APIs ------------------------------------- */
/* ---------------- BEGIN 0.96.2 APIs ----------------------------------- */

/**
\group_env
  * Queries the environment this bytecode runs in.
  * Used by BC_STARTUP to disable bytecode when bugs are known for the current
  * platform.
  * @param[out] env - the full environment
  * @param[in] len - size of \p env
  * @return 0
  */
uint32_t get_environment(struct cli_environment *env, uint32_t len);

/**
\group_env
  * Disables the bytecode completely if condition is true.
  * Can only be called from the BC_STARTUP bytecode.
  * @param[in] reason - why the bytecode had to be disabled
  * @param[in] len - length of reason
  * @param[in] cond - condition
  * @return 0 - auto mode
  * @return 1 - JIT disabled
  * @return 2 - fully disabled
  */
uint32_t disable_bytecode_if(const int8_t *reason, uint32_t len, uint32_t cond);

/**
\group_env
  * Disables the JIT completely if condition is true.
  * Can only be called from the BC_STARTUP bytecode.
  * @param[in] reason - why the JIT had to be disabled
  * @param[in] len - length of reason
  * @param[in] cond - condition
  * @return 0 - auto mode
  * @return 1 - JIT disabled
  * @return 2 - fully disabled
  */
uint32_t disable_jit_if(const int8_t* reason, uint32_t len, uint32_t cond);

/**
 \group_env
  * Compares two version numbers.
  * @param[in] lhs - left hand side of comparison
  * @param[in] lhs_len - length of \p lhs
  * @param[in] rhs - right hand side of comparison
  * @param[in] rhs_len - length of \p rhs
  * @return -1 - lhs < rhs
  * @return 0 - lhs == rhs
  * @return 1 - lhs > rhs
  */
int32_t version_compare(const uint8_t* lhs, uint32_t lhs_len,
                    const uint8_t* rhs, uint32_t rhs_len);

/**
\group_env
  * Disables the JIT if the platform id matches.
  * 0xff can be used instead of a field to mark ANY.
  * @param[in] a -  os_category << 24 | arch << 20 | compiler << 16 | flevel << 8 | dconf
  * @param[in] b -  big_endian << 28 | sizeof_ptr << 24 | cpp_version
  * @param[in] c -  os_features << 24 | c_version
  * @return 0 - no match
  * @return 1 - match
  */
uint32_t check_platform(uint32_t a, uint32_t b, uint32_t c);

/* --------------------- PDF APIs ----------------------------------- */
/**
\group_pdf
 * Return number of pdf objects
 * @return -1 - if not called from PDF hook
 * @return >=0 - number of PDF objects
*/
int32_t pdf_get_obj_num(void);

/**
\group_pdf
  * Return the flags for the entire PDF (as set so far).
  * @return -1 - if not called from PDF hook
  * @return >=0 - pdf flags
  */
int32_t pdf_get_flags(void);

/**
\group_pdf
  * Sets the flags for the entire PDF.
  * It is recommended that you retrieve old flags, and just add new ones.
  * @param[in] flags - flags to set.
  * @return 0 - success
           -1 - invalid phase */
int32_t pdf_set_flags(int32_t flags);

/**
\group_pdf
  * Lookup pdf object with specified id.
  * @param[in] id - pdf id (objnumber << 8 | generationid)
  * @return -1 - if object id doesn't exist
  * @return >=0 - object index
  */
int32_t pdf_lookupobj(uint32_t id);

/**
\group_pdf
  * Return the size of the specified PDF obj.
  * @param[in] objidx - object index (from 0), not object id!
  * @return 0 - if not called from PDF hook, or invalid objnum
  * @return >=0 - size of object */
uint32_t pdf_getobjsize(int32_t objidx);

/**
\group_pdf
 * Return the undecoded object.
 * Meant only for reading, write modifies the fmap buffer, so avoid!
 * @param[in] objidx - object index (from 0), not object id!
 * @param[in] amount - size returned by pdf_getobjsize (or smaller)
 * @return NULL - invalid objidx/amount
 * @return pointer - pointer to original object */
//uint8_t *pdf_getobj(int32_t objidx, uint32_t amount);
const uint8_t *pdf_getobj(int32_t objidx, uint32_t amount);

/**
\group_pdf
 * Return the object id for the specified object index.
 * @param[in] objidx - object index (from 0)
 * @return -1 - object index invalid
 * @return >=0 - object id (obj id << 8 | generation id)
 */
int32_t pdf_getobjid(int32_t objidx);

/**
\group_pdf
 * Return the object flags for the specified object index.
 * @param[in] objidx - object index (from 0)
 * @return -1 - object index invalid
 * @return >=0 - object flags
 */
int32_t pdf_getobjflags(int32_t objidx);

/**
\group_pdf
 * Sets the object flags for the specified object index.
 * This can be used to force dumping of a certain obj, by setting the
 * OBJ_FORCEDUMP flag for example.
 * @param[in] objidx - object index (from 0)
 * @param[in] flags - value to set flags
 * @return -1 - object index invalid
 * @return >=0 - flags set
 */
int32_t pdf_setobjflags(int32_t objidx, int32_t flags);

/**
\group_pdf
 * Return the object's offset in the PDF.
 * @param[in] objidx - object index (from 0)
 * @return -1 - object index invalid
 * @return >=0 - offset
 */
int32_t pdf_get_offset(int32_t objidx);

/**
\group_pdf
  * Return an 'enum pdf_phase'.
  * Identifies at which phase this bytecode was called.
  * @return the current #pdf_phase
  */
int32_t pdf_get_phase(void);

/**
\group_pdf
 * Return the currently dumped obj index.
 * Valid only in PDF_PHASE_POSTDUMP.
 * @return >=0 - object index
 * @return  -1 - invalid phase
 */
int32_t pdf_get_dumpedobjid(void);

/* ----------------------------- Icon APIs -------------------------- */
/**
\group_icon
 * Attempts to match current executable's icon against the specified icon
 * groups.
 * @param[in] group1 - same as GROUP1 in LDB signatures
 * @param[in] group1_len - length of \p group1
 * @param[in] group2 - same as GROUP2 in LDB signatures
 * @param[in] group2_len - length of \p group2
 * @return -1 - invalid call, or sizes (only valid for PE hooks)
 * @return  0 - not a match
 * @return  1 - match
 */
int32_t matchicon(const uint8_t* group1, int32_t group1_len,
                  const uint8_t* group2, int32_t group2_len);
/* ---------------- END 0.96.2 APIs   ----------------------------------- */
/* ----------------- BEGIN 0.96.4 APIs ---------------------------------- */
/**
\group_engine
 * Returns whether running on JIT. As side-effect it disables
 * interp / JIT comparisons in test mode (errors are still checked)
 * @return 1 - running on JIT
 * @return 0 - running on ClamAV interpreter
 */
int32_t running_on_jit(void);

/**
\group_file
 * Get file reliability flag, higher value means less reliable.
 * When >0 import tables and such are not reliable
 * @return 0 - normal
 * @return 1 - embedded PE
 * @return 2 - unpacker created file (not impl. yet)
 */
int32_t get_file_reliability(void);

/* ----------------- END 0.96.4 APIs ---------------------------------- */
/* ----------------- BEGIN 0.98.4 APIs -------------------------------- */
/* ----------------- JSON Parsing APIs -------------------------------- */
/**
\group_json
 * @return 0 - json is disabled or option not specified
 * @return 1 - json is active and properties are available
 */
int32_t json_is_active(void);

/**
\group_json
 * @return objid of json object with specified name
 * @return 0 if json object of specified name cannot be found
 * @return -1 if an error has occurred
 * @param[in] name - name of object in ASCII
 * @param[in] name_len - length of specified name (not including terminating NULL),
 *                       must be >= 0
 * @param[in] objid - id value of json object to query
 */
int32_t json_get_object(const int8_t* name, int32_t name_len, int32_t objid);

/**
\group_json
 * @return type (json_type) of json object specified
 * @return -1 if type unknown or invalid id
 * @param[in] objid - id value of json object to query
 */
int32_t json_get_type(int32_t objid);

/**
\group_json
 * @return number of elements in the json array of objid
 * @return -1 if an error has occurred
 * @return -2 if object is not JSON_TYPE_ARRAY
 * @param[in] objid - id value of json object (should be JSON_TYPE_ARRAY) to query
 */
int32_t json_get_array_length(int32_t objid);

/**
\group_json
 * @return objid of json object at idx of json array of objid
 * @return 0 if invalid idx
 * @return -1 if an error has occurred
 * @return -2 if object is not JSON_TYPE_ARRAY
 * @param[in] idx - index of array to query, must be >= 0 and less than array length
 * @param[in] objid - id value of json object (should be JSON_TYPE_ARRAY) to query
 */
int32_t json_get_array_idx(int32_t idx, int32_t objid);

/**
\group_json
 * @return length of json string of objid, not including terminating null-character
 * @return -1 if an error has occurred
 * @return -2 if object is not JSON_TYPE_STRING
 * @param[in] objid - id value of json object (should be JSON_TYPE_STRING) to query
 */
int32_t json_get_string_length(int32_t objid);

/**
\group_json
 * @return number of characters transferred (capped by str_len),
 *         including terminating null-character
 * @return -1 if an error has occurred
 * @return -2 if object is not JSON_TYPE_STRING
 * @param[out] str - user location to store string data; will be null-terminated
 * @param[in] str_len - length of str or limit of string data to read,
 *                      including terminating null-character
 * @param[in] objid - id value of json object (should be JSON_TYPE_STRING) to query
 */
int32_t json_get_string(int8_t* str, int32_t str_len, int32_t objid);

/**
\group_json
 * @return boolean value of queried objid; will force other types to boolean
 * @param[in] objid - id value of json object to query
 */
int32_t json_get_boolean(int32_t objid);

/**
\group_json
 * @return integer value of queried objid; will force other types to integer
 * @param[in] objid - id value of json object to query
 */
int32_t json_get_int(int32_t objid);

//int64_t json_get_int64(int32_t objid);
/* bytecode does not support double type */
//double json_get_double(int32_t objid);

/* ----------------- END 0.98.4 APIs ---------------------------------- */
/* ----------------- BEGIN 0.101.0 APIs ------------------------------- */
/* ----------------- Scan Options APIs -------------------------------- */
/**
\group_engine
  * Check if any given scan option is enabled.
  * Returns non-zero if the following named options are set:
  *
  * "general allmatch"                - all-match mode is enabled
  * "general collect metadata"        - --gen-json is enabled
  * "general heuristics"              - --gen-json is enabled
  *
  * "parse archive"                   - archive parsing is enabled
  * "parse pdf"                       - pdf parsing is enabled
  * "parse swf"                       - swf parsing is enabled
  * "parse hwp3"                      - hwp3 parsing is enabled
  * "parse xmldocs"                   - xmldocs parsing is enabled
  * "parse mail"                      - mail parsing is enabled
  * "parse ole2"                      - ole2 parsing is enabled
  * "parse html"                      - html parsing is enabled
  * "parse pe"                        - pe parsing is enabled
  *
  * "heuristic precedence"            - heuristic signatures are set to take precedence
  * "heuristic broken"                - broken pe heuristic is enabled
  * "heuristic exceeds max"           - heuristic for when max settings are exceeded is enabled
  * "heuristic phishing ssl mismatch" - phishing ssl mismatch heuristic is enabled
  * "heuristic phishing cloak"        - phishing cloak heuristic is enabled
  * "heuristic macros"                - macros heuristic is enabled
  * "heuristic encrypted"             - encrypted heuristic is enabled
  * "heuristic partition intxn"       - macpartition intxnros heuristic is enabled
  * "heuristic structured"            - structured heuristic is enabled
  * "heuristic structured ssn normal" - structured ssn normal heuristic is enabled
  * "heuristic structured ssn stripped" - structured ssn stripped heuristic is enabled
  *
  * "mail partial message"            - parsing of partial mail messages is enabled
  *
  * "dev collect sha"                 - --dev-collect-hashes is enabled
  * "dev collect performance info"    - --dev-performance is enabled
  *
  * @param[in] scan_options enum value for desired scan option category.
  * @return CL_SCAN_<OPTION>_* flags
  */
uint32_t engine_scan_options_ex(const uint8_t *option_name, uint32_t name_len);

/* ----------------- END 0.101 APIs ---------------------------------- */
#endif
#endif
