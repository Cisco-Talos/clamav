/*
 *  ClamAV bytecode internal API
 *  This is an automatically generated file!
 *
 *  Copyright (C) 2009-2010 Sourcefire, Inc.
 *  All rights reserved.
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
 * SUCH DAMAGE
 */
#include "cltypes.h"
#include "type_desc.h"
#include "bytecode_api.h"
#include "bytecode_api_impl.h"
#include "bytecode_priv.h"
#include <stdlib.h>

uint32_t cli_bcapi_test1(struct cli_bc_ctx *ctx , uint32_t, uint32_t);
int32_t cli_bcapi_read(struct cli_bc_ctx *ctx , uint8_t*, int32_t);
int32_t cli_bcapi_write(struct cli_bc_ctx *ctx , uint8_t*, int32_t);
int32_t cli_bcapi_seek(struct cli_bc_ctx *ctx , int32_t, uint32_t);
uint32_t cli_bcapi_setvirusname(struct cli_bc_ctx *ctx , const uint8_t*, uint32_t);
uint32_t cli_bcapi_debug_print_str(struct cli_bc_ctx *ctx , const uint8_t*, uint32_t);
uint32_t cli_bcapi_debug_print_uint(struct cli_bc_ctx *ctx , uint32_t);
uint32_t cli_bcapi_disasm_x86(struct cli_bc_ctx *ctx , struct DISASM_RESULT*, uint32_t);
uint32_t cli_bcapi_trace_directory(struct cli_bc_ctx *ctx , const uint8_t*, uint32_t);
uint32_t cli_bcapi_trace_scope(struct cli_bc_ctx *ctx , const uint8_t*, uint32_t);
uint32_t cli_bcapi_trace_source(struct cli_bc_ctx *ctx , const uint8_t*, uint32_t);
uint32_t cli_bcapi_trace_op(struct cli_bc_ctx *ctx , const uint8_t*, uint32_t);
uint32_t cli_bcapi_trace_value(struct cli_bc_ctx *ctx , const uint8_t*, uint32_t);
uint32_t cli_bcapi_trace_ptr(struct cli_bc_ctx *ctx , const uint8_t*, uint32_t);
uint32_t cli_bcapi_pe_rawaddr(struct cli_bc_ctx *ctx , uint32_t);
int32_t cli_bcapi_file_find(struct cli_bc_ctx *ctx , const uint8_t*, uint32_t);
int32_t cli_bcapi_file_byteat(struct cli_bc_ctx *ctx , uint32_t);
uint8_t* cli_bcapi_malloc(struct cli_bc_ctx *ctx , uint32_t);
uint32_t cli_bcapi_test2(struct cli_bc_ctx *ctx , uint32_t);
int32_t cli_bcapi_get_pe_section(struct cli_bc_ctx *ctx , struct cli_exe_section*, uint32_t);
int32_t cli_bcapi_fill_buffer(struct cli_bc_ctx *ctx , uint8_t*, uint32_t, uint32_t, uint32_t, uint32_t);
int32_t cli_bcapi_extract_new(struct cli_bc_ctx *ctx , int32_t);
int32_t cli_bcapi_read_number(struct cli_bc_ctx *ctx , uint32_t);
int32_t cli_bcapi_hashset_new(struct cli_bc_ctx *ctx );
int32_t cli_bcapi_hashset_add(struct cli_bc_ctx *ctx , int32_t, uint32_t);
int32_t cli_bcapi_hashset_remove(struct cli_bc_ctx *ctx , int32_t, uint32_t);
int32_t cli_bcapi_hashset_contains(struct cli_bc_ctx *ctx , int32_t, uint32_t);
int32_t cli_bcapi_hashset_done(struct cli_bc_ctx *ctx , int32_t);
int32_t cli_bcapi_inflate_init(struct cli_bc_ctx *ctx );
int32_t cli_bcapi_inflate_process(struct cli_bc_ctx *ctx , int32_t, uint8_t*, uint32_t, uint8_t*, uint32_t);
int32_t cli_bcapi_inflate_done(struct cli_bc_ctx *ctx , int32_t);

const struct cli_apiglobal cli_globals[] = {
/* Bytecode globals BEGIN */
	{"__clambc_kind", GLOBAL_KIND, 16,
	 ((char*)&((struct cli_bc_ctx*)0)->hooks.kind - (char*)NULL)},
	{"__clambc_match_counts", GLOBAL_MATCH_COUNTS, 76,
	 ((char*)&((struct cli_bc_ctx*)0)->hooks.match_counts - (char*)NULL)},
	{"__clambc_filesize", GLOBAL_FILESIZE, 75,
	 ((char*)&((struct cli_bc_ctx*)0)->hooks.filesize - (char*)NULL)},
	{"__clambc_pedata", GLOBAL_PEDATA, 69,
	 ((char*)&((struct cli_bc_ctx*)0)->hooks.pedata - (char*)NULL)}
/* Bytecode globals END */
};
const unsigned cli_apicall_maxglobal = _LAST_GLOBAL-1;
static uint16_t cli_tmp0[]={32, 32, 16, 74, 73, 72, 70, 32, 32, 32, 32};
static uint16_t cli_tmp1[]={71};
static uint16_t cli_tmp2[]={32, 32};
static uint16_t cli_tmp3[]={16, 8, 8, 32, 32, 32, 32, 32, 64, 32, 32, 16, 16, 16, 16, 16, 16, 32, 32, 32, 32, 16, 16, 64, 64, 64, 64, 32, 32, 70};
static uint16_t cli_tmp4[]={16, 8, 8, 32, 32, 32, 32, 32, 32, 32, 32, 32, 16, 16, 16, 16, 16, 16, 32, 32, 32, 32, 16, 16, 32, 32, 32, 32, 32, 32, 70};
static uint16_t cli_tmp5[]={32, 16, 16, 32, 32, 32, 16, 16};
static uint16_t cli_tmp6[]={32};
static uint16_t cli_tmp7[]={32};
static uint16_t cli_tmp8[]={32, 32};
static uint16_t cli_tmp9[]={32, 32, 65, 32, 65, 32};
static uint16_t cli_tmp10[]={32};
static uint16_t cli_tmp11[]={32, 32, 32};
static uint16_t cli_tmp12[]={32, 65, 32, 32, 32, 32};
static uint16_t cli_tmp13[]={32, 83, 32};
static uint16_t cli_tmp14[]={84};
static uint16_t cli_tmp15[]={32, 32, 32, 32, 32, 32, 32, 32, 32};
static uint16_t cli_tmp16[]={65, 32};
static uint16_t cli_tmp17[]={32, 65, 32};
static uint16_t cli_tmp18[]={32, 88, 32};
static uint16_t cli_tmp19[]={89};
static uint16_t cli_tmp20[]={16, 8, 8, 8, 91, 90};
static uint16_t cli_tmp21[]={8};
static uint16_t cli_tmp22[]={92};
static uint16_t cli_tmp23[]={8};

const struct cli_bc_type cli_apicall_types[]={
	{DStructType, cli_tmp0, 11, 0, 0},
	{DArrayType, cli_tmp1, 16, 0, 0},
	{DStructType, cli_tmp2, 2, 0, 0},
	{DStructType, cli_tmp3, 30, 0, 0},
	{DStructType, cli_tmp4, 31, 0, 0},
	{DStructType, cli_tmp5, 8, 0, 0},
	{DArrayType, cli_tmp6, 1, 0, 0},
	{DArrayType, cli_tmp7, 64, 0, 0},
	{DFunctionType, cli_tmp8, 2, 0, 0},
	{DFunctionType, cli_tmp9, 6, 0, 0},
	{DFunctionType, cli_tmp10, 1, 0, 0},
	{DFunctionType, cli_tmp11, 3, 0, 0},
	{DFunctionType, cli_tmp12, 6, 0, 0},
	{DFunctionType, cli_tmp13, 3, 0, 0},
	{DPointerType, cli_tmp14, 1, 0, 0},
	{DStructType, cli_tmp15, 9, 0, 0},
	{DFunctionType, cli_tmp16, 2, 0, 0},
	{DFunctionType, cli_tmp17, 3, 0, 0},
	{DFunctionType, cli_tmp18, 3, 0, 0},
	{DPointerType, cli_tmp19, 1, 0, 0},
	{DStructType, cli_tmp20, 6, 0, 0},
	{DArrayType, cli_tmp21, 29, 0, 0},
	{DArrayType, cli_tmp22, 3, 0, 0},
	{DArrayType, cli_tmp23, 10, 0, 0}
};

const unsigned cli_apicall_maxtypes=sizeof(cli_apicall_types)/sizeof(cli_apicall_types[0]);
const struct cli_apicall cli_apicalls[]={
/* Bytecode APIcalls BEGIN */
	{"test1", 11, 0, 0},
	{"read", 17, 0, 1},
	{"write", 17, 1, 1},
	{"seek", 11, 1, 0},
	{"setvirusname", 17, 2, 1},
	{"debug_print_str", 17, 3, 1},
	{"debug_print_uint", 8, 0, 2},
	{"disasm_x86", 18, 4, 1},
	{"trace_directory", 17, 5, 1},
	{"trace_scope", 17, 6, 1},
	{"trace_source", 17, 7, 1},
	{"trace_op", 17, 8, 1},
	{"trace_value", 17, 9, 1},
	{"trace_ptr", 17, 10, 1},
	{"pe_rawaddr", 8, 1, 2},
	{"file_find", 17, 11, 1},
	{"file_byteat", 8, 2, 2},
	{"malloc", 16, 0, 3},
	{"test2", 8, 3, 2},
	{"get_pe_section", 13, 12, 1},
	{"fill_buffer", 12, 0, 4},
	{"extract_new", 8, 4, 2},
	{"read_number", 8, 5, 2},
	{"hashset_new", 10, 0, 5},
	{"hashset_add", 11, 2, 0},
	{"hashset_remove", 11, 3, 0},
	{"hashset_contains", 11, 4, 0},
	{"hashset_done", 8, 6, 2},
	{"inflate_init", 10, 1, 5},
	{"inflate_process", 9, 0, 6},
	{"inflate_done", 8, 7, 2}
/* Bytecode APIcalls END */
};
const cli_apicall_int2 cli_apicalls0[] = {
	(cli_apicall_int2)cli_bcapi_test1,
	(cli_apicall_int2)cli_bcapi_seek,
	(cli_apicall_int2)cli_bcapi_hashset_add,
	(cli_apicall_int2)cli_bcapi_hashset_remove,
	(cli_apicall_int2)cli_bcapi_hashset_contains
};
const cli_apicall_pointer cli_apicalls1[] = {
	(cli_apicall_pointer)cli_bcapi_read,
	(cli_apicall_pointer)cli_bcapi_write,
	(cli_apicall_pointer)cli_bcapi_setvirusname,
	(cli_apicall_pointer)cli_bcapi_debug_print_str,
	(cli_apicall_pointer)cli_bcapi_disasm_x86,
	(cli_apicall_pointer)cli_bcapi_trace_directory,
	(cli_apicall_pointer)cli_bcapi_trace_scope,
	(cli_apicall_pointer)cli_bcapi_trace_source,
	(cli_apicall_pointer)cli_bcapi_trace_op,
	(cli_apicall_pointer)cli_bcapi_trace_value,
	(cli_apicall_pointer)cli_bcapi_trace_ptr,
	(cli_apicall_pointer)cli_bcapi_file_find,
	(cli_apicall_pointer)cli_bcapi_get_pe_section
};
const cli_apicall_int1 cli_apicalls2[] = {
	(cli_apicall_int1)cli_bcapi_debug_print_uint,
	(cli_apicall_int1)cli_bcapi_pe_rawaddr,
	(cli_apicall_int1)cli_bcapi_file_byteat,
	(cli_apicall_int1)cli_bcapi_test2,
	(cli_apicall_int1)cli_bcapi_extract_new,
	(cli_apicall_int1)cli_bcapi_read_number,
	(cli_apicall_int1)cli_bcapi_hashset_done,
	(cli_apicall_int1)cli_bcapi_inflate_done
};
const cli_apicall_malloclike cli_apicalls3[] = {
	(cli_apicall_malloclike)cli_bcapi_malloc
};
const cli_apicall_ptrbuffdata cli_apicalls4[] = {
	(cli_apicall_ptrbuffdata)cli_bcapi_fill_buffer
};
const cli_apicall_allocobj cli_apicalls5[] = {
	(cli_apicall_allocobj)cli_bcapi_hashset_new,
	(cli_apicall_allocobj)cli_bcapi_inflate_init
};
const cli_apicall_bufops cli_apicalls6[] = {
	(cli_apicall_bufops)cli_bcapi_inflate_process
};
const unsigned cli_apicall_maxapi = sizeof(cli_apicalls)/sizeof(cli_apicalls[0]);
