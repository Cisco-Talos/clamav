/*
 *  ClamAV bytecode internal API
 *  This is an automatically generated file!
 *
 *  Copyright (C) 2009 Sourcefire, Inc.
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

uint32_t cli_bcapi_test0(struct cli_bc_ctx *ctx, struct foo*, uint32_t);
uint32_t cli_bcapi_test1(struct cli_bc_ctx *ctx, uint32_t, uint32_t);
int32_t cli_bcapi_read(struct cli_bc_ctx *ctx, uint8_t*, int32_t);
int32_t cli_bcapi_write(struct cli_bc_ctx *ctx, uint8_t*, int32_t);
int32_t cli_bcapi_seek(struct cli_bc_ctx *ctx, int32_t, uint32_t);
uint32_t cli_bcapi_setvirusname(struct cli_bc_ctx *ctx, const const uint8_t*, uint32_t);
uint32_t cli_bcapi_debug_print_str(struct cli_bc_ctx *ctx, const const uint8_t*, uint32_t);
uint32_t cli_bcapi_debug_print_uint(struct cli_bc_ctx *ctx, uint32_t, uint32_t);
uint32_t cli_bcapi_disasm_x86(struct cli_bc_ctx *ctx, struct DISASM_RESULT*, uint32_t);
uint32_t cli_bcapi_trace_directory(struct cli_bc_ctx *ctx, const const uint8_t*, uint32_t);
uint32_t cli_bcapi_trace_scope(struct cli_bc_ctx *ctx, const const uint8_t*, uint32_t);
uint32_t cli_bcapi_trace_source(struct cli_bc_ctx *ctx, const const uint8_t*, uint32_t);
uint32_t cli_bcapi_trace_op(struct cli_bc_ctx *ctx, const const uint8_t*, uint32_t);
uint32_t cli_bcapi_trace_value(struct cli_bc_ctx *ctx, const const uint8_t*, uint32_t);
uint32_t cli_bcapi_trace_ptr(struct cli_bc_ctx *ctx, const const uint8_t*, uint32_t);
uint32_t cli_bcapi_pe_rawaddr(struct cli_bc_ctx *ctx, uint32_t, uint32_t);
int32_t cli_bcapi_file_find(struct cli_bc_ctx *ctx, const const uint8_t*, uint32_t);
int32_t cli_bcapi_file_byteat(struct cli_bc_ctx *ctx, uint32_t, uint32_t);

const struct cli_apiglobal cli_globals[] = {
/* Bytecode globals BEGIN */
	{"__clambc_kind", GLOBAL_KIND, 16,
	 ((char*)&((struct cli_bc_ctx*)0)->hooks.kind - (char*)NULL)},
	{"__clambc_match_counts", GLOBAL_MATCH_COUNTS, 84,
	 ((char*)&((struct cli_bc_ctx*)0)->hooks.match_counts - (char*)NULL)},
	{"__clambc_filesize", GLOBAL_FILESIZE, 83,
	 ((char*)&((struct cli_bc_ctx*)0)->hooks.filesize - (char*)NULL)},
	{"__clambc_exeinfo", GLOBAL_EXEINFO, 79,
	 ((char*)&((struct cli_bc_ctx*)0)->hooks.exeinfo - (char*)NULL)},
	{"__clambc_pedata", GLOBAL_PEDATA, 69,
	 ((char*)&((struct cli_bc_ctx*)0)->hooks.pedata - (char*)NULL)}
/* Bytecode globals END */
};
const unsigned cli_apicall_maxglobal = _LAST_GLOBAL-1;
static uint16_t cli_tmp0[]={79, 77, 75, 72, 70, 32, 32, 32, 32, 8, 65};
static uint16_t cli_tmp1[]={71};
static uint16_t cli_tmp2[]={32, 32};
static uint16_t cli_tmp3[]={73};
static uint16_t cli_tmp4[]={16, 8, 8, 32, 32, 32, 32, 32, 64, 32, 32, 16, 16, 16, 16, 16, 16, 32, 32, 32, 32, 16, 16, 64, 64, 64, 64, 32, 32, 74};
static uint16_t cli_tmp5[]={71};
static uint16_t cli_tmp6[]={76};
static uint16_t cli_tmp7[]={16, 8, 8, 32, 32, 32, 32, 32, 32, 32, 32, 32, 16, 16, 16, 16, 16, 16, 32, 32, 32, 32, 16, 16, 32, 32, 32, 32, 32, 32, 74};
static uint16_t cli_tmp8[]={78};
static uint16_t cli_tmp9[]={32, 16, 16, 32, 32, 32, 16, 16};
static uint16_t cli_tmp10[]={81, 32, 32, 16, 80};
static uint16_t cli_tmp11[]={8};
static uint16_t cli_tmp12[]={82};
static uint16_t cli_tmp13[]={32, 32, 32, 32, 32, 32, 32, 32, 32};
static uint16_t cli_tmp14[]={32};
static uint16_t cli_tmp15[]={32};
static uint16_t cli_tmp16[]={32, 32, 32};
static uint16_t cli_tmp17[]={32, 65, 32};
static uint16_t cli_tmp18[]={32, 88, 32};
static uint16_t cli_tmp19[]={89};
static uint16_t cli_tmp20[]={16, 8, 8, 8, 91, 90};
static uint16_t cli_tmp21[]={8};
static uint16_t cli_tmp22[]={92};
static uint16_t cli_tmp23[]={8};
static uint16_t cli_tmp24[]={32, 94, 32};
static uint16_t cli_tmp25[]={95};
static uint16_t cli_tmp26[]={94};

const struct cli_bc_type cli_apicall_types[]={
	{DStructType, cli_tmp0, 11, 0, 0},
	{DPointerType, cli_tmp1, 1, 0, 0},
	{DStructType, cli_tmp2, 2, 0, 0},
	{DPointerType, cli_tmp3, 1, 0, 0},
	{DStructType, cli_tmp4, 30, 0, 0},
	{DArrayType, cli_tmp5, 16, 0, 0},
	{DPointerType, cli_tmp6, 1, 0, 0},
	{DStructType, cli_tmp7, 31, 0, 0},
	{DPointerType, cli_tmp8, 1, 0, 0},
	{DStructType, cli_tmp9, 8, 0, 0},
	{DStructType, cli_tmp10, 5, 0, 0},
	{DPointerType, cli_tmp11, 1, 0, 0},
	{DPointerType, cli_tmp12, 1, 0, 0},
	{DStructType, cli_tmp13, 9, 0, 0},
	{DArrayType, cli_tmp14, 1, 0, 0},
	{DArrayType, cli_tmp15, 64, 0, 0},
	{DFunctionType, cli_tmp16, 3, 0, 0},
	{DFunctionType, cli_tmp17, 3, 0, 0},
	{DFunctionType, cli_tmp18, 3, 0, 0},
	{DPointerType, cli_tmp19, 1, 0, 0},
	{DStructType, cli_tmp20, 6, 0, 0},
	{DArrayType, cli_tmp21, 29, 0, 0},
	{DArrayType, cli_tmp22, 3, 0, 0},
	{DArrayType, cli_tmp23, 10, 0, 0},
	{DFunctionType, cli_tmp24, 3, 0, 0},
	{DPointerType, cli_tmp25, 1, 0, 0},
	{DStructType, cli_tmp26, 1, 0, 0}
};

const unsigned cli_apicall_maxtypes=sizeof(cli_apicall_types)/sizeof(cli_apicall_types[0]);
const struct cli_apicall cli_apicalls[]={
/* Bytecode APIcalls BEGIN */
	{"test0", 24, 0, 1},
	{"test1", 16, 0, 0},
	{"read", 17, 1, 1},
	{"write", 17, 2, 1},
	{"seek", 16, 1, 0},
	{"setvirusname", 17, 3, 1},
	{"debug_print_str", 17, 4, 1},
	{"debug_print_uint", 16, 2, 0},
	{"disasm_x86", 18, 5, 1},
	{"trace_directory", 17, 6, 1},
	{"trace_scope", 17, 7, 1},
	{"trace_source", 17, 8, 1},
	{"trace_op", 17, 9, 1},
	{"trace_value", 17, 10, 1},
	{"trace_ptr", 17, 11, 1},
	{"pe_rawaddr", 16, 3, 0},
	{"file_find", 17, 12, 1},
	{"file_byteat", 16, 4, 0}
/* Bytecode APIcalls END */
};
const cli_apicall_int2 cli_apicalls0[] = {
	(cli_apicall_int2)cli_bcapi_test1,
	(cli_apicall_int2)cli_bcapi_seek,
	(cli_apicall_int2)cli_bcapi_debug_print_uint,
	(cli_apicall_int2)cli_bcapi_pe_rawaddr,
	(cli_apicall_int2)cli_bcapi_file_byteat
};
const cli_apicall_pointer cli_apicalls1[] = {
	(cli_apicall_pointer)cli_bcapi_test0,
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
	(cli_apicall_pointer)cli_bcapi_file_find
};
const unsigned cli_apicall_maxapi = sizeof(cli_apicalls)/sizeof(cli_apicalls[0]);
