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

const struct cli_apiglobal cli_globals[] = {
/* Bytecode globals BEGIN */
	{"__clambc_kind", GLOBAL_KIND, 16,
	 ((char*)&((struct cli_bc_ctx*)0)->hooks.kind - (char*)NULL)},
	{"__clambc_match_counts", GLOBAL_MATCH_COUNTS, 82,
	 ((char*)&((struct cli_bc_ctx*)0)->hooks.match_counts - (char*)NULL)},
	{"__clambc_exeinfo", GLOBAL_EXEINFO, 79,
	 ((char*)&((struct cli_bc_ctx*)0)->hooks.exeinfo - (char*)NULL)},
	{"__clambc_pedata", GLOBAL_PEDATA, 69,
	 ((char*)&((struct cli_bc_ctx*)0)->hooks.pedata - (char*)NULL)}
/* Bytecode globals END */
};
const unsigned cli_apicall_maxglobal = _LAST_GLOBAL-1;
static uint16_t cli_tmp0[]={79, 77, 75, 72, 70, 32, 32, 32, 8, 65};
static uint16_t cli_tmp1[]={71};
static uint16_t cli_tmp2[]={32, 32};
static uint16_t cli_tmp3[]={73};
static uint16_t cli_tmp4[]={16, 8, 8, 32, 32, 32, 32, 32, 64, 32, 32, 16, 16, 16, 16, 16, 16, 32, 32, 32, 32, 16, 16, 64, 64, 64, 64, 32, 32, 74};
static uint16_t cli_tmp5[]={71};
static uint16_t cli_tmp6[]={76};
static uint16_t cli_tmp7[]={16, 8, 8, 32, 32, 32, 32, 32, 32, 32, 32, 32, 16, 16, 16, 16, 16, 16, 32, 32, 32, 32, 16, 16, 32, 32, 32, 32, 32, 32, 74};
static uint16_t cli_tmp8[]={78};
static uint16_t cli_tmp9[]={32, 16, 16, 32, 32, 32, 16, 16};
static uint16_t cli_tmp10[]={80, 32, 32, 16};
static uint16_t cli_tmp11[]={81};
static uint16_t cli_tmp12[]={32, 32, 32, 32, 32, 32, 32, 32, 32};
static uint16_t cli_tmp13[]={32};
static uint16_t cli_tmp14[]={32, 65, 32};
static uint16_t cli_tmp15[]={32, 85, 32};
static uint16_t cli_tmp16[]={86};
static uint16_t cli_tmp17[]={16, 8, 8, 8, 88, 87};
static uint16_t cli_tmp18[]={8};
static uint16_t cli_tmp19[]={89};
static uint16_t cli_tmp20[]={8};
static uint16_t cli_tmp21[]={32, 32, 32};
static uint16_t cli_tmp22[]={32, 92, 32};
static uint16_t cli_tmp23[]={93};
static uint16_t cli_tmp24[]={92};

const struct cli_bc_type cli_apicall_types[]={
	{DStructType, cli_tmp0, 10, 0, 0},
	{DPointerType, cli_tmp1, 1, 0, 0},
	{DStructType, cli_tmp2, 2, 0, 0},
	{DPointerType, cli_tmp3, 1, 0, 0},
	{DStructType, cli_tmp4, 30, 0, 0},
	{DArrayType, cli_tmp5, 16, 0, 0},
	{DPointerType, cli_tmp6, 1, 0, 0},
	{DStructType, cli_tmp7, 31, 0, 0},
	{DPointerType, cli_tmp8, 1, 0, 0},
	{DStructType, cli_tmp9, 8, 0, 0},
	{DStructType, cli_tmp10, 4, 0, 0},
	{DPointerType, cli_tmp11, 1, 0, 0},
	{DStructType, cli_tmp12, 9, 0, 0},
	{DArrayType, cli_tmp13, 64, 0, 0},
	{DFunctionType, cli_tmp14, 3, 0, 0},
	{DFunctionType, cli_tmp15, 3, 0, 0},
	{DPointerType, cli_tmp16, 1, 0, 0},
	{DStructType, cli_tmp17, 6, 0, 0},
	{DArrayType, cli_tmp18, 29, 0, 0},
	{DArrayType, cli_tmp19, 10, 0, 0},
	{DArrayType, cli_tmp20, 3, 0, 0},
	{DFunctionType, cli_tmp21, 3, 0, 0},
	{DFunctionType, cli_tmp22, 3, 0, 0},
	{DPointerType, cli_tmp23, 1, 0, 0},
	{DStructType, cli_tmp24, 1, 0, 0}
};

const unsigned cli_apicall_maxtypes=sizeof(cli_apicall_types)/sizeof(cli_apicall_types[0]);
const struct cli_apicall cli_apicalls[]={
/* Bytecode APIcalls BEGIN */
	{"test0", 22, 0, 1},
	{"test1", 21, 0, 0},
	{"read", 14, 1, 1},
	{"write", 14, 2, 1},
	{"seek", 21, 1, 0},
	{"setvirusname", 14, 3, 1},
	{"debug_print_str", 14, 4, 1},
	{"debug_print_uint", 21, 2, 0},
	{"disasm_x86", 15, 5, 1},
	{"trace_directory", 14, 6, 1},
	{"trace_scope", 14, 7, 1},
	{"trace_source", 14, 8, 1},
	{"trace_op", 14, 9, 1},
	{"trace_value", 14, 10, 1}
/* Bytecode APIcalls END */
};
const cli_apicall_int2 cli_apicalls0[] = {
	(cli_apicall_int2)cli_bcapi_test1,
	(cli_apicall_int2)cli_bcapi_seek,
	(cli_apicall_int2)cli_bcapi_debug_print_uint
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
	(cli_apicall_pointer)cli_bcapi_trace_value
};
const unsigned cli_apicall_maxapi = sizeof(cli_apicalls)/sizeof(cli_apicalls[0]);
