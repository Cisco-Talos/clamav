/*
 *  Copyright (C) 2009-2010 Sourcefire, Inc.
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

/** Bytecode trigger kind */
enum BytecodeKind {
    /** generic bytecode, not tied a specific hook */
    BC_GENERIC=0,
    BC_STARTUP=1,
    _BC_START_HOOKS=256,
    /** triggered by a logical signature */
    BC_LOGICAL=256,
    /** a PE unpacker */
    BC_PE_UNPACKER,
    /* PDF hook */
    BC_PDF,
    BC_PE_ALL,/* both packed and unpacked files */
    _BC_LAST_HOOK
};

enum {
  /** Invalid RVA specified */
  PE_INVALID_RVA = 0xFFFFFFFF
};

/** LibClamAV functionality level constants */
enum FunctionalityLevels {
    FUNC_LEVEL_096 = 51,
    FUNC_LEVEL_096_dev,
    FUNC_LEVEL_096_1,
    FUNC_LEVEL_096_1_dev=54,
    FUNC_LEVEL_096_2=54,
    FUNC_LEVEL_096_2_dev
};

/** Phase of PDF parsing */
enum pdf_phase {
    PDF_PHASE_NONE /* not a PDF */,
    PDF_PHASE_PARSED, /* after parsing a PDF, object flags can be set etc. */
    PDF_PHASE_POSTDUMP, /* after an obj was dumped and scanned */
    PDF_PHASE_END, /* after the pdf scan finished */
    PDF_PHASE_PRE /* before pdf is parsed at all */
};

/** PDF flags */
enum pdf_flag {
    BAD_PDF_VERSION=0,
    BAD_PDF_HEADERPOS,
    BAD_PDF_TRAILER,
    BAD_PDF_TOOMANYOBJS,
    BAD_STREAM_FILTERS,
    BAD_FLATE,
    BAD_FLATESTART,
    BAD_STREAMSTART,
    BAD_ASCIIDECODE,
    BAD_INDOBJ,
    UNTERMINATED_OBJ_DICT,
    ESCAPED_COMMON_PDFNAME,
    HEX_JAVASCRIPT,
    UNKNOWN_FILTER,
    MANY_FILTERS,
    HAS_OPENACTION,
    BAD_STREAMLEN,
    ENCRYPTED_PDF,
    LINEARIZED_PDF, /* not bad, just as flag */
    DECRYPTABLE_PDF,
    HAS_LAUNCHACTION
};

/** PDF obj flags */
enum pdf_objflags {
    OBJ_STREAM=0,
    OBJ_DICT,
    OBJ_EMBEDDED_FILE,
    OBJ_FILTER_AH,
    OBJ_FILTER_A85,
    OBJ_FILTER_FLATE,
    OBJ_FILTER_LZW,
    OBJ_FILTER_RL,
    OBJ_FILTER_FAX,
    OBJ_FILTER_JBIG2,
    OBJ_FILTER_DCT,
    OBJ_FILTER_JPX,
    OBJ_FILTER_CRYPT,
    OBJ_FILTER_UNKNOWN,
    OBJ_JAVASCRIPT,
    OBJ_OPENACTION,
    OBJ_HASFILTERS,
    OBJ_SIGNED,
    OBJ_IMAGE,
    OBJ_TRUNCATED,
    OBJ_FORCEDUMP,
    OBJ_FILTER_STANDARD,
    OBJ_LAUNCHACTION,
    OBJ_PAGE,
    OBJ_CONTENTS
};

#ifdef __CLAMBC__

/* --------------- BEGIN GLOBALS -------------------------------------------- */
/** @brief Logical signature match counts
 *
 *  This is a low-level variable, use the Macros in bytecode_local.h instead to
 *  access it.
\group_globals
 * */
extern const uint32_t __clambc_match_counts[64];

/** @brief Logical signature match offsets
  * This is a low-level variable, use the Macros in bytecode_local.h instead to
  * access it.
\group_globals
  */
extern const uint32_t __clambc_match_offsets[64];

/** PE data, if this is a PE hook.
  \group_globals */
extern const struct cli_pe_hook_data __clambc_pedata;
/** File size (max 4G). 
   \group_globals */
extern const uint32_t __clambc_filesize[1];

/** Kind of the bytecode
\group_globals
*/
const uint16_t __clambc_kind;
/* ---------------- END GLOBALS --------------------------------------------- */
/* ---------------- BEGIN 0.96 APIs (don't touch) --------------------------- */
/** Test api. 
  @param a 0xf00dbeef
  @param b 0xbeeff00d
  @return 0x12345678 if parameters match, 0x55 otherwise
*/
uint32_t test1(uint32_t a, uint32_t b);

/**
 * @brief Reads specified amount of bytes from the current file
 * into a buffer. Also moves current position in the file.
 *
 * @param[in] size amount of bytes to read
 * @param[out] data pointer to buffer where data is read into
 * @return amount read.
 * \group_file
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
 * \group_file
 */
int32_t write(uint8_t *data, int32_t size);

/**
 * @brief Changes the current file position to the specified one.
 * @sa SEEK_SET, SEEK_CUR, SEEK_END
 * @param[in] pos offset (absolute or relative depending on \p whence param)
 * @param[in] whence one of \p SEEK_SET, \p SEEK_CUR, \p SEEK_END
 * @return absolute position in file
 * \group_file
 */
int32_t seek(int32_t pos, uint32_t whence);

/**
 * Sets the name of the virus found.
 *
 * @param[in] name the name of the virus
 * @param[in] len length of the virusname
 * @return 0
 * \group_scan
 */
uint32_t setvirusname(const uint8_t *name, uint32_t len);

/**
 * Prints a debug message.
 *
 * @param[in] str Message to print
 * @param[in] len length of message to print
 * @return 0
 * \group_string
 */
uint32_t debug_print_str(const uint8_t *str, uint32_t len);

/**
 * Prints a number as a debug message.
 * This is like \p debug_print_str_nonl!
 *
 * @param[in] a number to print
 * @return 0
 * \group_string
 */
uint32_t debug_print_uint(uint32_t a);

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
 \group_disasm
 */
uint32_t disasm_x86(struct DISASM_RESULT* result, uint32_t len);

/* tracing API */

/* a scope: lexical block, function, or compile unit */
uint32_t trace_directory(const uint8_t* directory, uint32_t dummy);
uint32_t trace_scope(const uint8_t* newscope, uint32_t scopeid);
uint32_t trace_source(const uint8_t* srcfile, uint32_t line);
uint32_t trace_op(const uint8_t* opname, uint32_t column);
uint32_t trace_value(const uint8_t* name, uint32_t v);
uint32_t trace_ptr(const uint8_t* ptr, uint32_t dummy);

/** Converts a RVA (Relative Virtual Address) to
  * an absolute PE file offset.
  * @param rva a rva address from the PE file
  * @return absolute file offset mapped to the \p rva,
  * or PE_INVALID_RVA if the \p rva is invalid.
  \group_pe
  */
uint32_t pe_rawaddr(uint32_t rva);

/** Looks for the specified sequence of bytes in the current file.
  \group_file
  * @param[in] data the sequence of bytes to look for
  * @param len length of \p data, cannot be more than 1024
  * @return offset in the current file if match is found, -1 otherwise */
int32_t file_find(const uint8_t* data, uint32_t len);

/** Read a single byte from current file
  \group_file
  * @param offset file offset
  * @return byte at offset \p off in the current file, or -1 if offset is
  * invalid */
int32_t file_byteat(uint32_t offset);

/** Allocates memory. Currently this memory is freed automatically on exit
  from the bytecode, and there is no way to free it sooner.
  \group_adt
  @param size amount of memory to allocate in bytes
  @return pointer to allocated memory */
void* malloc(uint32_t size);

/** Test api2.
  * @param a 0xf00d
  * @return 0xd00f if parameter matches, 0x5555 otherwise */
uint32_t test2(uint32_t a);

/** Gets information about the specified PE section.
  \group_pe
 * @param[out] section PE section information will be stored here
 * @param[in] num PE section number
 * @return  0 - success
           -1 - failure */
int32_t get_pe_section(struct cli_exe_section *section, uint32_t num);

/** Fills the specified buffer with at least \p fill bytes.
  \group_file
 * @param[out] buffer the buffer to fill
 * @param[in] len length of buffer
 * @param[in] filled how much of the buffer is currently filled
 * @param[in] cursor position of cursor in buffer
 * @param[in] fill amount of bytes to fill in (0 is valid)
 * @return <0 on error,
 *          0 on EOF,
 *          number bytes available in buffer (starting from 0)
 * The character at the cursor will be at position 0 after this call.
 */
int32_t fill_buffer(uint8_t* buffer, uint32_t len, uint32_t filled,
                    uint32_t cursor, uint32_t fill);

/**
 * Prepares for extracting a new file, if we've already extracted one it scans
 * it.
 \group_scan
 * @param[in] id an id for the new file (for example position in container)
 * @return 1 if previous extracted file was infected
*/
int32_t extract_new(int32_t id);

/**   
 * Reads a number in the specified radix starting from the current position.
 * \group_file 
  * Non-numeric characters are ignored.
  * @param[in] radix 10 or 16
  * @return the number read
  */
int32_t read_number(uint32_t radix);

/**
  * Creates a new hashset and returns its id.
  \group_adt
  * @return ID for new hashset */
int32_t hashset_new(void);

/**
  * Add a new 32-bit key to the hashset.
  \group_adt
  * @param hs ID of hashset (from hashset_new)
  * @param key the key to add
  * @return 0 on success */
int32_t hashset_add(int32_t hs, uint32_t key);

/**
  * Remove a 32-bit key from the hashset.
  \group_adt
  * @param hs ID of hashset (from hashset_new)
  * @param key the key to add
  * @return 0 on success */
int32_t hashset_remove(int32_t hs, uint32_t key);

/**
  * Returns whether the hashset contains the specified key.
  \group_adt
  * @param hs ID of hashset (from hashset_new)
  * @param key the key to lookup
  * @return 1 if found, 0 if not found, <0 on invalid hashset ID */
int32_t hashset_contains(int32_t hs, uint32_t key);

/**
  * Deallocates the memory used by the specified hashset.
  \group_adt
  * Trying to use the hashset after this will result in an error.
  * The hashset may not be used after this.
  * All hashsets are automatically deallocated when bytecode
  * finishes execution.
  * @param id ID of hashset (from hashset_new)
  * @return 0 on success */
int32_t hashset_done(int32_t id);

/**
  * Returns whether the hashset is empty.
  \group_adt
  * @param id of hashset (from hashset_new)
  * @return 0 on success */
int32_t hashset_empty(int32_t id);

/**
  * Creates a new pipe with the specified buffer size
  \group_adt
  * @param size size of buffer
  * @return ID of newly created buffer_pipe */
int32_t  buffer_pipe_new(uint32_t size);

/**
  * Same as buffer_pipe_new, except the pipe's input is tied
  \group_adt
  \group_file
  * to the current file, at the specified position.
  * @param pos starting position of pipe input in current file
  * @return ID of newly created buffer_pipe */
int32_t  buffer_pipe_new_fromfile(uint32_t pos);

/**
  * Returns the amount of bytes available to read.
  \group_adt
  * @param id ID of buffer_pipe
  * @return amount of bytes available to read */
uint32_t buffer_pipe_read_avail(int32_t id);

/**
  * Returns a pointer to the buffer for reading.
  \group_adt
  * The 'amount' parameter should be obtained by a call to
  * buffer_pipe_read_avail().
  * @param id ID of buffer_pipe
  * @param amount to read
  * @return pointer to buffer, or NULL if buffer has less than
  specified amount */
uint8_t *buffer_pipe_read_get(int32_t id, uint32_t amount);

/**
  \group_adt
  * Updates read cursor in buffer_pipe.
  * @param id ID of buffer_pipe
  * @param amount amount of bytes to move read cursor
  * @return 0 on success */
int32_t  buffer_pipe_read_stopped(int32_t id, uint32_t amount);

/**
  * Returns the amount of bytes available for writing.
  \group_adt
  * @param id ID of buffer_pipe
  * @return amount of bytes available for writing */
uint32_t buffer_pipe_write_avail(int32_t id);

/**
  \group_adt
  * Returns pointer to writable buffer.
  * The 'amount' parameter should be obtained by a call to
  * buffer_pipe_write_avail().
  * @param id ID of buffer_pipe
  * @param size amount of bytes to write
  * @return pointer to write buffer, or NULL if requested amount
  is more than what is available in the buffer */
uint8_t *buffer_pipe_write_get(int32_t id, uint32_t size);

/**
  * Updates the write cursor in buffer_pipe.
  \group_adt
  * @param id ID of buffer_pipe
  * @param amount amount of bytes to move write cursor
  * @return 0 on success */
int32_t  buffer_pipe_write_stopped(int32_t id, uint32_t amount);

/**
  * Deallocate memory used by buffer.
  \group_adt
  * After this all attempts to use this buffer will result in error.
  * All buffer_pipes are automatically deallocated when bytecode
  * finishes execution.
  * @param id ID of buffer_pipe
  * @return 0 on success */
int32_t  buffer_pipe_done(int32_t id);

/**
  * Initializes inflate data structures for decompressing data
  \group_adt
  * 'from_buffer' and writing uncompressed uncompressed data 'to_buffer'.
  * @param from_buffer ID of buffer_pipe to read compressed data from
  * @param to_buffer ID of buffer_pipe to write decompressed data to
  * @param windowBits (see zlib documentation)
  * @return ID of newly created inflate data structure, <0 on failure */
int32_t inflate_init(int32_t from_buffer, int32_t to_buffer, int32_t windowBits);

/**
  * Inflate all available data in the input buffer, and write to output buffer.
  * Stops when the input buffer becomes empty, or write buffer becomes full.
  * Also attempts to recover from corrupted inflate stream (via inflateSync).
  * This function can be called repeatedly on success after filling the input
  * buffer, and flushing the output buffer.
  * The inflate stream is done processing when 0 bytes are available from output
  * buffer, and input buffer is not empty.
  \group_adt
  * @param id ID of inflate data structure
  * @return 0 on success, zlib error code otherwise */
int32_t inflate_process(int32_t id);

/**
  * Deallocates inflate data structure.
  * Using the inflate data structure after this will result in an error.
  * All inflate data structures are automatically deallocated when bytecode
  * finishes execution.
  \group_adt
  * @param id ID of inflate data structure
  * @return 0 on success.*/
int32_t inflate_done(int32_t id);

/** 
  * Report a runtime error at the specified locationID.
  \group_scan
  * @param locationid (line << 8) | (column&0xff)
  * @return 0 */
int32_t bytecode_rt_error(int32_t locationid);

/**
  * Initializes JS normalizer for reading 'from_buffer'.
  * Normalized JS will be written to a single tempfile,
  * one normalized JS per line, and automatically scanned 
  * when the bytecode finishes execution. 
  \group_js
  * @param from_buffer ID of buffer_pipe to read javascript from
  * @return ID of JS normalizer, <0 on failure */
int32_t jsnorm_init(int32_t from_buffer);

/**
  * Normalize all javascript from the input buffer, and write to tempfile.
  * You can call this function repeatedly on success, if you (re)fill the input
  * buffer.
  \group_js
  * @param id ID of JS normalizer
  * @return 0 on success, <0 on failure */
int32_t jsnorm_process(int32_t id);

/**
  * Flushes JS normalizer.
  \group_js
  * @param id ID of js normalizer to flush
  * @return 0 - success
           -1 - failure */
int32_t jsnorm_done(int32_t id);

/* ---------------- END 0.96 APIs (don't touch) --------------------------- */
/* ---------------- BEGIN 0.96.1 APIs ------------------------------------- */

/* ---------------- Math -------------------------------------------------- */

/**
  *  Returns 2^26*log2(a/b)
  * @param a input 
  * @param b input
  * @return 2^26*log2(a/b)
  \group_math
  */
int32_t ilog2(uint32_t a, uint32_t b);

/**
  * Returns c*a^b.
  * @param a integer
  * @param b integer
  * @param c integer
  * @return c*pow(a,b)
  \group_math
  */
int32_t ipow(int32_t a, int32_t b, int32_t c);

/**
  * Returns exp(a/b)*c
  * @param a integer
  * @param b integer
  * @param c integer
  * @return c*exp(a/b)
  \group_math
  */
uint32_t iexp(int32_t a, int32_t b, int32_t c);

/**
  * Returns c*sin(a/b).
  * @param a integer
  * @param b integer
  * @param c integer
  * @return c*sin(a/b)
  \group_math
  */
int32_t isin(int32_t a, int32_t b, int32_t c);

/**
  * Returns c*cos(a/b).
  * @param a integer
  * @param b integer
  * @param c integer
  * @return c*sin(a/b)
  \group_math
  */
int32_t icos(int32_t a, int32_t b, int32_t c);

/* ---------------- String operations --------------------------------------- */
/**
  * Return position of match, -1 otherwise.
  * @param haystack buffer to search
  * @param haysize size of \p haystack
  * @param needle substring to search
  * @param needlesize size of needle
  * @return location of match, -1 otherwise
  \group_string
  */
int32_t memstr(const uint8_t* haystack, int32_t haysize,
               const uint8_t* needle, int32_t needlesize);

/**
  * Returns hexadecimal characters \p hex1 and \p hex2 converted to 8-bit
  * number.
  * @param hex1 hexadecimal character
  * @param hex2 hexadecimal character
  * @return hex1 hex2 converted to 8-bit integer, -1 on error
  \group_string
  */
int32_t hex2ui(uint32_t hex1, uint32_t hex2);

/**
  * Converts string to positive number.
  * @param str buffer
  * @param size size of \p str
  * @return >0 string converted to number if possible, -1 on error
  \group_string
  */
int32_t atoi(const uint8_t* str, int32_t size);

/**
  * Prints a debug message with a trailing newline,
  * but preceded by 'LibClamAV debug'.
  * @param str the string
  * @param len length of \p str
  * @return 0
  \group_string
  */
uint32_t debug_print_str_start(const uint8_t *str, uint32_t len);

/**
  * Prints a debug message with a trailing newline,
  * and not preceded by 'LibClamAV debug'.
  * @param str the string
  * @param len length of \p str
  * @return 0
  \group_string
  */
uint32_t debug_print_str_nonl(const uint8_t *str, uint32_t len);

/**
  * Returns an approximation for the entropy of \p buffer.
  * @param buffer input buffer
  * @param size size of buffer
  * @return entropy estimation * 2^26
  \group_string
  */
uint32_t entropy_buffer(uint8_t* buffer, int32_t size);

/* ------------------ Data Structures --------------------------------------- */
/**
  * Creates a new map and returns its id.
  * @param keysize size of key
  * @param valuesize size of value, if 0 then value is allocated separately
  * @return ID of new map
\group_adt
  */
int32_t map_new(int32_t keysize, int32_t valuesize);

/**
  * Inserts the specified key/value pair into the map.
  * @param id id of table
  * @param key key
  * @param ksize size of \p key
  * @return 0 - if key existed before
            1 - if key didn't exist before
           <0 - if ksize doesn't match keysize specified at table creation
\group_adt
  */
int32_t map_addkey(const uint8_t *key, int32_t ksize, int32_t id);

/**
  * Sets the value for the last inserted key with map_addkey.
  * @param id id of table
  * @param value value
  * @param vsize size of \p value
  * @return 0 - if update was successful
           <0 - if there is no last key
\group_adt
  */
int32_t map_setvalue(const uint8_t *value, int32_t vsize, int32_t id);

/**
  * Remove an element from the map.
  * @param id id of map
  * @param key key
  * @param ksize size of key
  * @return 0 on success, key was present
            1 if key was not present
           <0 if ksize doesn't match keysize specified at table creation
\group_adt
  */
int32_t map_remove(const uint8_t* key, int32_t ksize, int32_t id);

/**
  * Looks up key in map. 
  * The map remember the last looked up key (so you can retrieve the
  * value).
  * 
  * @param id id of map
  * @param key key
  * @param ksize size of key
  * @return 0 - if not found
            1 - if found
           <0 - if ksize doesn't match the size specified at table creation
\group_adt
  */
int32_t map_find(const uint8_t* key, int32_t ksize, int32_t id);

/**
  * Returns the size of value obtained during last map_find.
  * @param id id of map.
  * @return size of value
\group_adt
  */
int32_t map_getvaluesize(int32_t id);

/**
  * Returns the value obtained during last map_find.
  * @param id id of map.
  * @param size size of value (obtained from map_getvaluesize)
  * @return value
\group_adt
  */
uint8_t* map_getvalue(int32_t id, int32_t size);

/**
  * Deallocates the memory used by the specified map.
  * Trying to use the map after this will result in an error.
  * All maps are automatically deallocated when the bytecode finishes
  * execution.
  * @param id id of map
  * @return 0 - success
           -1 - invalid map
\group_adt
  */
int32_t map_done(int32_t id);

/* -------------- File Operations ------------------------------------------- */
/** Looks for the specified sequence of bytes in the current file, up to the
 * specified position.
 * @param[in] data the sequence of bytes to look for
 * @param len length of \p data, cannot be more than 1024
 * @param maxpos maximum position to look for a match, 
 * note that this is 1 byte after the end of last possible match:
 * match_pos + \p len < \p maxpos
 * @return offset in the current file if match is found, -1 otherwise 
 * \group_file
 */
int32_t file_find_limit(const uint8_t *data, uint32_t len, int32_t maxpos);

/* ------------- Engine Query ----------------------------------------------- */
/**
  * Returns the current engine (feature) functionality level.
  * To map these to ClamAV releases, compare it with #FunctionalityLevels.
  * @return an integer representing current engine functionality level.
  * \group_engine
  */
uint32_t engine_functionality_level(void);

/**
  * Returns the current engine (dconf) functionality level.
  * Usually identical to engine_functionality_level(), unless distro backported
  * patches. Compare with #FunctionalityLevels.
  * @return an integer representing the DCONF (security fixes) level.
  * \group_engine
  */
uint32_t engine_dconf_level(void);

/**
  * Returns the current engine's scan options.
  * @return CL_SCAN* flags 
  * \group_engine
  */
uint32_t engine_scan_options(void);

/**
  * Returns the current engine's db options.
  * @return CL_DB_* flags
  * \group_engine
  */
uint32_t engine_db_options(void);

/* ---------------- Scan Control -------------------------------------------- */
/**
  * Sets the container type for the currently extracted file.
  * @param container container type (CL_TYPE_*)
  * @return current setting for container (CL_TYPE_ANY default)
  * \group_scan
  */
int32_t extract_set_container(uint32_t container);

/**
  * Toggles the read/seek API to read from the currently extracted file, and
  * back.
  * You must call seek after switching inputs to position the cursor to a valid
  * position.
  * @param extracted_file 1 - switch to reading from extracted file, 
                          0 - switch back to original input
  * @return -1 on error (if no extracted file exists)
             0 on success
  * \group_scan
  */
int32_t input_switch(int32_t extracted_file);

/* ---------------- END 0.96.1 APIs ------------------------------------- */
/* ---------------- BEGIN 0.96.2 APIs ----------------------------------- */

/** Queries the environment this bytecode runs in.
  * Used by BC_STARTUP to disable bytecode when bugs are known for the current
  * platform.
  * @param[out] env - the full environment
  * @param len - size of \p env
  * @return 0
  \group_env
  */
uint32_t get_environment(struct cli_environment *env, uint32_t len);

/** Disables the bytecode completely if condition is true.
  Can only be called from the BC_STARTUP bytecode.
  @param reason - why the bytecode had to be disabled
  @param len - length of reason
  @param cond - condition
  @return 0 - auto mode
          1 - JIT disabled
          2 - fully disabled
  \group_env
  */
uint32_t disable_bytecode_if(const int8_t *reason, uint32_t len, uint32_t cond);

/** Disables the JIT completely if condition is true.
  Can only be called from the BC_STARTUP bytecode.
  @param reason - why the JIT had to be disabled
  @param len - length of reason
  @param cond - condition
  @return 0 - auto mode
          1 - JIT disabled
          2 - fully disabled
  \group_env
  */
uint32_t disable_jit_if(const int8_t* reason, uint32_t len, uint32_t cond);

/** Compares two version numbers.
  * @param[in] lhs - left hand side of comparison
    @param lhs_len - length of \p lhs
    @param[in] rhs - right hand side of comparison
    @param rhs_len - length of \p rhs
    @return -1 - lhs < rhs
            0 - lhs == rhs
            1 - lhs > rhs
  \group_env
  */
int32_t version_compare(const uint8_t* lhs, uint32_t lhs_len,
                    const uint8_t* rhs, uint32_t rhs_len);

/** Disables the JIT if the platform id matches.
  * 0xff can be used instead of a field to mark ANY.
  * @param a -  os_category << 24 | arch << 20 | compiler << 16 | flevel << 8 | dconf
    @param b -  big_endian << 28 | sizeof_ptr << 24 | cpp_version
    @param c -  os_features << 24 | c_version
    @return 0 - no match
            1 - match
  \group_env
  */
uint32_t check_platform(uint32_t a, uint32_t b, uint32_t c);

/* --------------------- PDF APIs ----------------------------------- */
/** Return number of pdf objects 
 * @return -1 - if not called from PDF hook
          >=0 - number of PDF objects
  \group_pdf
*/
int32_t pdf_get_obj_num(void);

/** Return the flags for the entire PDF (as set so far).
  * @return -1 - if not called from PDF hook
           >=0 - pdf flags
  \group_pdf
  */
int32_t pdf_get_flags(void);

/** Sets the flags for the entire PDF.
  * It is recommended that you retrieve old flags, and just add new ones.
  \group_pdf
  * @param flags - flags to set.
  * @return 0 - success
           -1 - invalid phase */
int32_t pdf_set_flags(int32_t flags);

/** Lookup pdf object with specified id.
  \group_pdf
  * @param id - pdf id (objnumber << 8 | generationid)
    @return -1 - if object id doesn't exist
           >=0 - object index
  */
int32_t pdf_lookupobj(uint32_t id);

/** Return the size of the specified PDF obj.
  \group_pdf
  * @param objidx - object index (from 0), not object id!
  * @return 0 - if not called from PDF hook, or invalid objnum
          >=0 - size of object */
uint32_t pdf_getobjsize(int32_t objidx);

/** Return the undecoded object.
  \group_pdf
  Meant only for reading, write modifies the fmap buffer, so avoid!
  @param objidx - object index (from 0), not object id!
  @param amount - size returned by pdf_getobjsize (or smaller)
  @return NULL - invalid objidx/amount
          pointer - pointer to original object */
uint8_t *pdf_getobj(int32_t objidx, uint32_t amount);

/* Return the object id for the specified object index.
  \group_pdf
   @param objidx - object index (from 0)
   @return -1 - object index invalid
          >=0 - object id (obj id << 8 | generation id)
*/
int32_t pdf_getobjid(int32_t objidx);

/* Return the object flags for the specified object index.
  \group_pdf
   @param objidx - object index (from 0)
   @return -1 - object index invalid
          >=0 - object flags
*/
int32_t pdf_getobjflags(int32_t objidx);

/* Sets the object flags for the specified object index.
  \group_pdf
   This can be used to force dumping of a certain obj, by setting the
   OBJ_FORCEDUMP flag for example.
   @param objidx - object index (from 0)
   @return -1 - object index invalid
          >=0 - flags set
*/
int32_t pdf_setobjflags(int32_t objidx, int32_t flags);

/* Return the object's offset in the PDF.
  \group_pdf
   @param objidx - object index (from 0)
   @return -1 - object index invalid
          >=0 - offset
*/
int32_t pdf_get_offset(int32_t objidx);

/** Return an 'enum pdf_phase'.
  \group_pdf
  * Identifies at which phase this bytecode was called.
  * @return the current #pdf_phase
  */
int32_t pdf_get_phase(void);

/** Return the currently dumped obj index.
  \group_pdf
 * Valid only in PDF_PHASE_POSTDUMP.
 * @return >=0 - object index
            -1 - invalid phase
 */
int32_t pdf_get_dumpedobjid(void);

/* ----------------------------- Icon APIs -------------------------- */
/** Attempts to match current executable's icon against the specified icon
 * groups.
 \group_icon
 * @param[in] group1 - same as GROUP1 in LDB signatures
 * @param group1_len - length of \p group1
 * @param[in] group2 - same as GROUP2 in LDB signatures
 * @param group2_len - length of \p group2
 * @return -1 - invalid call, or sizes (only valid for PE hooks)
            0 - not a match
            1 - match
 */

int32_t matchicon(const uint8_t* group1, int32_t group1_len,
                  const uint8_t* group2, int32_t group2_len);
/* ---------------- END 0.96.2 APIs   ----------------------------------- */
/* ----------------- BEGIN 0.96.4 APIs ---------------------------------- */
/* Returns whether running on JIT. As side-effect it disables
 * interp / JIT comparisons in test mode (errors are still checked) */
int32_t running_on_jit(void);

/* Get file reliability flag, higher value means less reliable 
 * 0 - normal
 * 1 - embedded PE
 * 2 - unpacker created file (not impl. yet)
 *
 * when >0 import tables and such are not reliable */
int32_t get_file_reliability(void);

/* ----------------- END 0.96.4 APIs ---------------------------------- */
#endif
#endif
