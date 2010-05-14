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

static const unsigned  PE_INVALID_RVA = 0xFFFFFFFF ;

/** LibClamAV functionality level constants */
enum FunctionalityLevels {
    FUNC_LEVEL_096 = 51,
    FUNC_LEVEL_096_dev
};

#ifdef __CLAMBC__

/* --------------- BEGIN GLOBALS -------------------------------------------- */
/** @brief Logical signature match counts
 *
 *  This is a low-level variable, use the Macros in bytecode_local.h instead to
 *  access it.
 * */
extern const uint32_t __clambc_match_counts[64];

/** @brief Logical signature match offsets
  * This is a low-level variable, use the Macros in bytecode_local.h instead to
  * access it.
  */
extern const uint32_t __clambc_match_offsets[64];

/** PE data, if this is a PE hook */
extern const struct cli_pe_hook_data __clambc_pedata;
/** File size (max 4G) */
extern const uint32_t __clambc_filesize[1];

/** Kind of the bytecode */
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
 * This is like \p debug_print_str_nonl!
 *
 * @param[in] a number to print
 * @return 0
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
  */
uint32_t pe_rawaddr(uint32_t rva);

/** Looks for the specified sequence of bytes in the current file.
  * @param[in] data the sequence of bytes to look for
  * @param len length of \p data, cannot be more than 1024
  * @return offset in the current file if match is found, -1 otherwise */
int32_t file_find(const uint8_t* data, uint32_t len);

/** Read a single byte from current file
  * @param offset file offset
  * @return byte at offset \p off in the current file, or -1 if offset is
  * invalid */
int32_t file_byteat(uint32_t offset);

/** Allocates memory. Currently this memory is freed automatically on exit
  from the bytecode, and there is no way to free it sooner.
  @param size amount of memory to allocate in bytes
  @return pointer to allocated memory */
void* malloc(uint32_t size);

/** Test api2.
  * @param a 0xf00d
  * @return 0xd00f if parameter matches, 0x5555 otherwise */
uint32_t test2(uint32_t a);

/** Gets information about the specified PE section.
 * @param[out] section PE section information will be stored here
 * @param[in] num PE section number */
int32_t get_pe_section(struct cli_exe_section *section, uint32_t num);

/** Fills the specified buffer with at least \p fill bytes.
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
 * @param[in] id an id for the new file (for example position in container)
 * @return 1 if previous extracted file was infected
*/
int32_t extract_new(int32_t id);

/**
  * Reads a number in the specified radix starting from the current position.
  * Non-numeric characters are ignored.
  * @param[in] radix 10 or 16
  * @return the number read
  */
int32_t read_number(uint32_t radix);

/**
  * Creates a new hashset and returns its id.
  * @return ID for new hashset */
int32_t hashset_new(void);

/**
  * Add a new 32-bit key to the hashset.
  * @param hs ID of hashset (from hashset_new)
  * @param key the key to add
  * @return 0 on success */
int32_t hashset_add(int32_t hs, uint32_t key);

/**
  * Remove a 32-bit key from the hashset.
  * @param hs ID of hashset (from hashset_new)
  * @param key the key to add
  * @return 0 on success */
int32_t hashset_remove(int32_t hs, uint32_t key);

/**
  * Returns whether the hashset contains the specified key.
  * @param hs ID of hashset (from hashset_new)
  * @param key the key to lookup
  * @return 1 if found, 0 if not found, <0 on invalid hashset ID */
int32_t hashset_contains(int32_t hs, uint32_t key);

/**
  * Deallocates the memory used by the specified hashset.
  * Trying to use the hashset after this will result in an error.
  * The hashset may not be used after this.
  * All hashsets are automatically deallocated when bytecode
  * finishes execution.
  * @param id ID of hashset (from hashset_new)
  * @return 0 on success */
int32_t hashset_done(int32_t id);

/**
  * Returns whether the hashset is empty.
  * @param id of hashset (from hashset_new)
  * @return 0 on success */
int32_t hashset_empty(int32_t id);

/**
  * Creates a new pipe with the specified buffer size
  * @param size size of buffer
  * @return ID of newly created buffer_pipe */
int32_t  buffer_pipe_new(uint32_t size);

/**
  * Same as buffer_pipe_new, except the pipe's input is tied
  * to the current file, at the specified position.
  * @param pos starting position of pipe input in current file
  * @return ID of newly created buffer_pipe */
int32_t  buffer_pipe_new_fromfile(uint32_t pos);

/**
  * Returns the amount of bytes available to read.
  * @param id ID of buffer_pipe
  * @return amount of bytes available to read */
uint32_t buffer_pipe_read_avail(int32_t id);

/**
  * Returns a pointer to the buffer for reading.
  * The 'amount' parameter should be obtained by a call to
  * buffer_pipe_read_avail().
  * @param id ID of buffer_pipe
  * @param amount to read
  * @return pointer to buffer, or NULL if buffer has less than
  specified amount */
uint8_t *buffer_pipe_read_get(int32_t id, uint32_t amount);

/**
  * Updates read cursor in buffer_pipe.
  * @param id ID of buffer_pipe
  * @param amount amount of bytes to move read cursor
  * @return 0 on success */
int32_t  buffer_pipe_read_stopped(int32_t id, uint32_t amount);

/**
  * Returns the amount of bytes available for writing.
  * @param id ID of buffer_pipe
  * @return amount of bytes available for writing */
uint32_t buffer_pipe_write_avail(int32_t id);

/**
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
  * @param id ID of buffer_pipe
  * @param amount amount of bytes to move write cursor
  * @return 0 on success */
int32_t  buffer_pipe_write_stopped(int32_t id, uint32_t amount);

/**
  * Deallocate memory used by buffer.
  * After this all attempts to use this buffer will result in error.
  * All buffer_pipes are automatically deallocated when bytecode
  * finishes execution.
  * @param id ID of buffer_pipe
  * @return 0 on success */
int32_t  buffer_pipe_done(int32_t id);

/**
  * Initializes inflate data structures for decompressing data
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
  * @param id ID of inflate data structure
  * @return 0 on success, zlib error code otherwise */
int32_t inflate_process(int32_t id);

/**
  * Deallocates inflate data structure.
  * Using the inflate data structure after this will result in an error.
  * All inflate data structures are automatically deallocated when bytecode
  * finishes execution.
  * @param id ID of inflate data structure
  * @return 0 on success.*/
int32_t inflate_done(int32_t id);

/** 
  * Report a runtime error at the specified locationID.
  * @param locationid (line << 8) | (column&0xff)
  * @return 0 */
int32_t bytecode_rt_error(int32_t locationid);

/**
  * Initializes JS normalizer for reading 'from_buffer'.
  * Normalized JS will be written to a single tempfile,
  * one normalized JS per line, and automatically scanned 
  * when the bytecode finishes execution. 
  * @param from_buffer ID of buffer_pipe to read javascript from
  * @return ID of JS normalizer, <0 on failure */
int32_t jsnorm_init(int32_t from_buffer);

/**
  * Normalize all javascript from the input buffer, and write to tempfile.
  * You can call this function repeatedly on success, if you (re)fill the input
  * buffer.
  * @param id ID of JS normalizer
  * @return 0 on success, <0 on failure */
int32_t jsnorm_process(int32_t id);

/**
  * Flushes JS normalizer.
  * @param id ID of js normalizer to flush */
int32_t jsnorm_done(int32_t id);

/* ---------------- END 0.96 APIs (don't touch) --------------------------- */
/* ---------------- BEGIN 0.96.1 APIs ------------------------------------- */

/** --------------- math -----------------*/

/**
  *  Returns 2^26*log2(a/b)
  * @param a input 
  * @param b input
  * @return 2^26*log2(a/b)
  */
int32_t ilog2(uint32_t a, uint32_t b);

/**
  * Returns c*a^b.
  * @param a integer
  * @param b integer
  * @param c integer
  * @return c*pow(a,b)
  */
int32_t ipow(int32_t a, int32_t b, int32_t c);

/**
  * Returns exp(a/b)*c
  * @param a integer
  * @param b integer
  * @param c integer
  * @return c*exp(a/b)
  */
uint32_t iexp(int32_t a, int32_t b, int32_t c);

/**
  * Returns c*sin(a/b).
  * @param a integer
  * @param b integer
  * @param c integer
  * @return c*sin(a/b)
  */
int32_t isin(int32_t a, int32_t b, int32_t c);

/**
  * Returns c*cos(a/b).
  * @param a integer
  * @param b integer
  * @param c integer
  * @return c*sin(a/b)
  */
int32_t icos(int32_t a, int32_t b, int32_t c);

/** --------------- string operations -----------------*/
/**
  * Return position of match, -1 otherwise.
  * @param haystack buffer to search
  * @param haysize size of \p haystack
  * @param needle substring to search
  * @param needlesize size of needle
  * @return location of match, -1 otherwise
  */
int32_t memstr(const uint8_t* haystack, int32_t haysize,
               const uint8_t* needle, int32_t needlesize);

/**
  * Returns hexadecimal characters \p hex1 and \p hex2 converted to 8-bit
  * number.
  * @param hex1 hexadecimal character
  * @param hex2 hexadecimal character
  * @return hex1 hex2 converted to 8-bit integer, -1 on error
  */
int32_t hex2ui(uint32_t hex1, uint32_t hex2);

/**
  * Converts string to positive number.
  * @param str buffer
  * @param size size of \p str
  * @return >0 string converted to number if possible, -1 on error
  */
int32_t atoi(const uint8_t* str, int32_t size);

/**
  * Prints a debug message with a trailing newline,
  * but preceded by 'LibClamAV debug'.
  * @param str the string
  * @param len length of \p str
  * @return 0
  */
uint32_t debug_print_str_start(const uint8_t *str, uint32_t len);

/**
  * Prints a debug message with a trailing newline,
  * and not preceded by 'LibClamAV debug'.
  * @param str the string
  * @param len length of \p str
  * @return 0
  */
uint32_t debug_print_str_nonl(const uint8_t *str, uint32_t len);

/**
  * Returns an approximation for the entropy of \p buffer.
  * @param buffer input buffer
  * @param size size of buffer
  * @return entropy estimation * 2^26
  */
uint32_t entropy_buffer(uint8_t* buffer, int32_t size);

/* ------------------ data structures -------------------- */
/**
  * Creates a new map and returns its id.
  * @param keysize size of key
  * @param valuesize size of value, if 0 then value is allocated separately
  * @return ID of new map */
int32_t map_new(int32_t keysize, int32_t valuesize);

/**
  * Inserts the specified key/value pair into the map.
  * @param id id of table
  * @param key key
  * @param ksize size of \p key
  * @return 0 - if key existed before
            1 - if key didn't exist before
           <0 - if ksize doesn't match keysize specified at table creation
  */
int32_t map_addkey(const uint8_t *key, int32_t ksize, int32_t id);

/**
  * Sets the value for the last inserted key with map_addkey.
  * @param id id of table
  * @param value value
  * @param vsize size of \p value
  * @return 0 - if update was successful
           <0 - if there is no last key
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
  */
int32_t map_find(const uint8_t* key, int32_t ksize, int32_t id);

/**
  * Returns the size of value obtained during last map_find.
  * @param id id of map.
  * @return size of value
  */
int32_t map_getvaluesize(int32_t id);

/**
  * Returns the value obtained during last map_find.
  * @param id id of map.
  * @param size size of value (obtained from map_getvaluesize)
  * @return value
  */
uint8_t* map_getvalue(int32_t id, int32_t size);

/**
  * Deallocates the memory used by the specified map.
  * Trying to use the map after this will result in an error.
  * All maps are automatically deallocated when the bytecode finishes
  * execution.
  */
int32_t map_done(int32_t id);

/** -------------- file operations --------------------- */
/** Looks for the specified sequence of bytes in the current file, up to the
 * specified position.
 * @param[in] data the sequence of bytes to look for
 * @param len length of \p data, cannot be more than 1024
 * @param maxpos maximum position to look for a match, 
 * note that this is 1 byte after the end of last possible match:
 * match_pos + \p len < \p maxpos
 * @return offset in the current file if match is found, -1 otherwise */
int32_t file_find_limit(const uint8_t *data, uint32_t len, int32_t maxpos);

/** ------------- engine query ------------------------ */
/**
  * Returns the current engine (feature) functionality level.
  */
uint32_t engine_functionality_level(void);

/**
  * Returns the current engine (dconf) functionality level.
  */
uint32_t engine_dconf_level(void);

/**
  * Returns the current engine's scan options.
  */
uint32_t engine_scan_options(void);

/**
  * Returns the current engine's db options.
  */
uint32_t engine_db_options(void);

/* ---------------- scan control --------------------------- */
/**
  * Sets the container type for the currently extracted file.
  * @param container container type (CL_TYPE_*)
  * @return current setting for container (CL_TYPE_ANY default)
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
  */
int32_t input_switch(int32_t extracted_file);

/* ---------------- END 0.96.1 APIs ------------------------------------- */
#endif
#endif
