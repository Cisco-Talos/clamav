/*
 * Main YARA header file for ClamAV
 * 
 * Copyright (C) 2014 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 * 
 * Authors: Steven Morgan
 * 
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License version 2 as published by the
 * Free Software Foundation.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

/* Most of this file was derived from yara 2.1.0 libyara/yara.h and
   other YARA header files. Following is the YARA copyright. */
/*
Copyright (c) 2007-2013. The YARA Authors. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _YARA_CLAM_H_
#define _YARA_CLAM_H_

#define LEX_BUF_SIZE  1024

#define EXTERNAL_VARIABLE_TYPE_NULL          0
#define EXTERNAL_VARIABLE_TYPE_ANY           1
#define EXTERNAL_VARIABLE_TYPE_INTEGER       2
#define EXTERNAL_VARIABLE_TYPE_BOOLEAN       3
#define EXTERNAL_VARIABLE_TYPE_FIXED_STRING  4
#define EXTERNAL_VARIABLE_TYPE_MALLOC_STRING 5

#define EXTERNAL_VARIABLE_IS_NULL(x) \
    ((x) != NULL ? (x)->type == EXTERNAL_VARIABLE_TYPE_NULL : TRUE)

#define STRING_TFLAGS_FOUND             0x01

#define STRING_GFLAGS_REFERENCED        0x01
#define STRING_GFLAGS_HEXADECIMAL       0x02
#define STRING_GFLAGS_NO_CASE           0x04
#define STRING_GFLAGS_ASCII             0x08
#define STRING_GFLAGS_WIDE              0x10
#define STRING_GFLAGS_REGEXP            0x20
#define STRING_GFLAGS_FAST_HEX_REGEXP   0x40
#define STRING_GFLAGS_FULL_WORD         0x80
#define STRING_GFLAGS_ANONYMOUS         0x100
#define STRING_GFLAGS_SINGLE_MATCH      0x200
#define STRING_GFLAGS_LITERAL           0x400
#define STRING_GFLAGS_FITS_IN_ATOM      0x800
#define STRING_GFLAGS_NULL              0x1000
#define STRING_GFLAGS_CHAIN_PART        0x2000
#define STRING_GFLAGS_CHAIN_TAIL        0x4000
#define STRING_GFLAGS_REGEXP_DOT_ALL    0x8000

#define STRING_IS_HEX(x) \
    (((x)->g_flags) & STRING_GFLAGS_HEXADECIMAL)

#define STRING_IS_NO_CASE(x) \
    (((x)->g_flags) & STRING_GFLAGS_NO_CASE)

#define STRING_IS_ASCII(x) \
    (((x)->g_flags) & STRING_GFLAGS_ASCII)

#define STRING_IS_WIDE(x) \
    (((x)->g_flags) & STRING_GFLAGS_WIDE)

#define STRING_IS_REGEXP(x) \
    (((x)->g_flags) & STRING_GFLAGS_REGEXP)

#define STRING_IS_REGEXP_DOT_ALL(x) \
    (((x)->g_flags) & STRING_GFLAGS_REGEXP_DOT_ALL)

#define STRING_IS_FULL_WORD(x) \
    (((x)->g_flags) & STRING_GFLAGS_FULL_WORD)

#define STRING_IS_ANONYMOUS(x) \
    (((x)->g_flags) & STRING_GFLAGS_ANONYMOUS)

#define STRING_IS_REFERENCED(x) \
    (((x)->g_flags) & STRING_GFLAGS_REFERENCED)

#define STRING_IS_SINGLE_MATCH(x) \
    (((x)->g_flags) & STRING_GFLAGS_SINGLE_MATCH)

#define STRING_IS_LITERAL(x) \
    (((x)->g_flags) & STRING_GFLAGS_LITERAL)

#define STRING_IS_FAST_HEX_REGEXP(x) \
    (((x)->g_flags) & STRING_GFLAGS_FAST_HEX_REGEXP)

#define STRING_IS_CHAIN_PART(x) \
    (((x)->g_flags) & STRING_GFLAGS_CHAIN_PART)

#define STRING_IS_CHAIN_TAIL(x) \
    (((x)->g_flags) & STRING_GFLAGS_CHAIN_TAIL)

#define STRING_IS_NULL(x) \
    ((x) == NULL || ((x)->g_flags) & STRING_GFLAGS_NULL)

#define STRING_FITS_IN_ATOM(x) \
    (((x)->g_flags) & STRING_GFLAGS_FITS_IN_ATOM)

#define STRING_FOUND(x) \
    ((x)->matches[yr_get_tidx()].tail != NULL)


#define RULE_TFLAGS_MATCH                0x01

#define RULE_GFLAGS_PRIVATE              0x01
#define RULE_GFLAGS_GLOBAL               0x02
#define RULE_GFLAGS_REQUIRE_EXECUTABLE   0x04
#define RULE_GFLAGS_REQUIRE_FILE         0x08
#define RULE_GFLAGS_NULL                 0x1000

#define RULE_IS_PRIVATE(x) \
    (((x)->g_flags) & RULE_GFLAGS_PRIVATE)

#define RULE_IS_GLOBAL(x) \
    (((x)->g_flags) & RULE_GFLAGS_GLOBAL)

#define RULE_IS_NULL(x) \
    (((x)->g_flags) & RULE_GFLAGS_NULL)

#define RULE_MATCHES(x) \
    ((x)->t_flags[yr_get_tidx()] & RULE_TFLAGS_MATCH)


#define DECLARE_REFERENCE(type, name) \
    union { type name; int64_t name##_; }

#define SIZED_STRING_FLAGS_NO_CASE  1
#define SIZED_STRING_FLAGS_DOT_ALL  2

typedef struct _SIZED_STRING
{
    int length;
    int flags;
    char c_string[1];

} SIZED_STRING;


/* From libyara/include/yara/error.h            */
#ifndef ERROR_SUCCESS
#define ERROR_SUCCESS                           0
#endif

#define ERROR_INSUFICIENT_MEMORY                1
#define ERROR_COULD_NOT_ATTACH_TO_PROCESS       2
#define ERROR_COULD_NOT_OPEN_FILE               3
#define ERROR_COULD_NOT_MAP_FILE                4
#define ERROR_INVALID_FILE                      6
#define ERROR_CORRUPT_FILE                      7
#define ERROR_UNSUPPORTED_FILE_VERSION          8
#define ERROR_INVALID_REGULAR_EXPRESSION        9
#define ERROR_INVALID_HEX_STRING                10
#define ERROR_SYNTAX_ERROR                      11
#define ERROR_LOOP_NESTING_LIMIT_EXCEEDED       12
#define ERROR_DUPLICATE_LOOP_IDENTIFIER         13
#define ERROR_DUPLICATE_IDENTIFIER              14
#define ERROR_DUPLICATE_TAG_IDENTIFIER          15
#define ERROR_DUPLICATE_META_IDENTIFIER         16
#define ERROR_DUPLICATE_STRING_IDENTIFIER       17
#define ERROR_UNREFERENCED_STRING               18
#define ERROR_UNDEFINED_STRING                  19
#define ERROR_UNDEFINED_IDENTIFIER              20
#define ERROR_MISPLACED_ANONYMOUS_STRING        21
#define ERROR_INCLUDES_CIRCULAR_REFERENCE       22
#define ERROR_INCLUDE_DEPTH_EXCEEDED            23
#define ERROR_WRONG_TYPE                        24
#define ERROR_EXEC_STACK_OVERFLOW               25
#define ERROR_SCAN_TIMEOUT                      26
#define ERROR_TOO_MANY_SCAN_THREADS             27
#define ERROR_CALLBACK_ERROR                    28
#define ERROR_INVALID_ARGUMENT                  29
#define ERROR_TOO_MANY_MATCHES                  30
#define ERROR_INTERNAL_FATAL_ERROR              31
#define ERROR_NESTED_FOR_OF_LOOP                32
#define ERROR_INVALID_FIELD_NAME                33
#define ERROR_UNKNOWN_MODULE                    34
#define ERROR_NOT_A_STRUCTURE                   35
#define ERROR_NOT_AN_ARRAY                      36
#define ERROR_NOT_A_FUNCTION                    37
#define ERROR_INVALID_FORMAT                    38
#define ERROR_TOO_MANY_ARGUMENTS                39
#define ERROR_WRONG_NUMBER_OF_ARGUMENTS         40


/*
typedef struct _YR_MATCH
{
  int64_t offset;
  int32_t length;

  union {
    uint8_t* data;            // Confirmed matches use "data",
    int32_t chain_length;    // unconfirmed ones use "chain_length"
  };

  struct _YR_MATCH*  prev;
  struct _YR_MATCH*  next;

} YR_MATCH;

typedef struct _YR_MATCHES
{
  int32_t count;

  DECLARE_REFERENCE(YR_MATCH*, head);
  DECLARE_REFERENCE(YR_MATCH*, tail);

} YR_MATCHES;
*/

typedef struct _YR_META
{
  int32_t type;
  int32_t integer;

  DECLARE_REFERENCE(char*, identifier);
  DECLARE_REFERENCE(char*, string);

} YR_META;

typedef struct _YR_STRING
{
  int32_t g_flags;
  int32_t length;

  DECLARE_REFERENCE(char*, identifier);
  DECLARE_REFERENCE(uint8_t*, string);
  DECLARE_REFERENCE(struct _YR_STRING*, chained_to);

  int32_t chain_gap_min;
  int32_t chain_gap_max;

    //  YR_MATCHES matches[MAX_THREADS];
    //  YR_MATCHES unconfirmed_matches[MAX_THREADS];

} YR_STRING;

typedef struct _YR_EXTERNAL_VARIABLE
{
  int32_t type;
  int64_t integer;

  DECLARE_REFERENCE(char*, identifier);
  DECLARE_REFERENCE(char*, string);

} YR_EXTERNAL_VARIABLE;


//from re.h:

typedef struct RE RE;
typedef struct RE_NODE RE_NODE;

struct RE_NODE
{
  int type;

  union {
    int value;
    int count;
    int start;
  };

  union {
    int mask;
    int end;
  };

  int greedy;

  uint8_t* class_vector;

  RE_NODE* left;
  RE_NODE* right;

  void* forward_code;
  void* backward_code;
};


struct RE {

  uint32_t flags;
  RE_NODE* root_node;

  const char* error_message;
  int error_code;
};

//misc

#define yr_strdup cli_strdup
#define yr_malloc cli_malloc
#define yr_free free
#define xtoi cli_hex2num
#define strlcpy cli_strlcpy

typedef struct _yc_compiler {
  char                lex_buf[LEX_BUF_SIZE];
  char*               lex_buf_ptr;
  unsigned short      lex_buf_len;
} yc_compiler;

#define YR_COMPILER yc_compiler

#endif

