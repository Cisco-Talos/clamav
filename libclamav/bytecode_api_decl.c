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
int32_t cli_bcapi_get_pe_section(struct cli_bc_ctx *ctx , void*, uint32_t);
int32_t cli_bcapi_fill_buffer(struct cli_bc_ctx *ctx , uint8_t*, uint32_t, uint32_t, uint32_t, uint32_t);
int32_t cli_bcapi_extract_new(struct cli_bc_ctx *ctx , int32_t);
int32_t cli_bcapi_read_number(struct cli_bc_ctx *ctx , uint32_t);
int32_t cli_bcapi_hashset_new(struct cli_bc_ctx *ctx );
int32_t cli_bcapi_hashset_add(struct cli_bc_ctx *ctx , int32_t, uint32_t);
int32_t cli_bcapi_hashset_remove(struct cli_bc_ctx *ctx , int32_t, uint32_t);
int32_t cli_bcapi_hashset_contains(struct cli_bc_ctx *ctx , int32_t, uint32_t);
int32_t cli_bcapi_hashset_done(struct cli_bc_ctx *ctx , int32_t);
int32_t cli_bcapi_hashset_empty(struct cli_bc_ctx *ctx , int32_t);
int32_t cli_bcapi_buffer_pipe_new(struct cli_bc_ctx *ctx , uint32_t);
int32_t cli_bcapi_buffer_pipe_new_fromfile(struct cli_bc_ctx *ctx , uint32_t);
uint32_t cli_bcapi_buffer_pipe_read_avail(struct cli_bc_ctx *ctx , int32_t);
const uint8_t* cli_bcapi_buffer_pipe_read_get(struct cli_bc_ctx *ctx , int32_t, uint32_t);
int32_t cli_bcapi_buffer_pipe_read_stopped(struct cli_bc_ctx *ctx , int32_t, uint32_t);
uint32_t cli_bcapi_buffer_pipe_write_avail(struct cli_bc_ctx *ctx , int32_t);
uint8_t* cli_bcapi_buffer_pipe_write_get(struct cli_bc_ctx *ctx , int32_t, uint32_t);
int32_t cli_bcapi_buffer_pipe_write_stopped(struct cli_bc_ctx *ctx , int32_t, uint32_t);
int32_t cli_bcapi_buffer_pipe_done(struct cli_bc_ctx *ctx , int32_t);
int32_t cli_bcapi_inflate_init(struct cli_bc_ctx *ctx , int32_t, int32_t, int32_t);
int32_t cli_bcapi_inflate_process(struct cli_bc_ctx *ctx , int32_t);
int32_t cli_bcapi_inflate_done(struct cli_bc_ctx *ctx , int32_t);
int32_t cli_bcapi_bytecode_rt_error(struct cli_bc_ctx *ctx , int32_t);
int32_t cli_bcapi_jsnorm_init(struct cli_bc_ctx *ctx , int32_t);
int32_t cli_bcapi_jsnorm_process(struct cli_bc_ctx *ctx , int32_t);
int32_t cli_bcapi_jsnorm_done(struct cli_bc_ctx *ctx , int32_t);
int32_t cli_bcapi_ilog2(struct cli_bc_ctx *ctx , uint32_t, uint32_t);
int32_t cli_bcapi_ipow(struct cli_bc_ctx *ctx , int32_t, int32_t, int32_t);
uint32_t cli_bcapi_iexp(struct cli_bc_ctx *ctx , int32_t, int32_t, int32_t);
int32_t cli_bcapi_isin(struct cli_bc_ctx *ctx , int32_t, int32_t, int32_t);
int32_t cli_bcapi_icos(struct cli_bc_ctx *ctx , int32_t, int32_t, int32_t);
int32_t cli_bcapi_memstr(struct cli_bc_ctx *ctx , const uint8_t*, int32_t, const uint8_t*, int32_t);
int32_t cli_bcapi_hex2ui(struct cli_bc_ctx *ctx , uint32_t, uint32_t);
int32_t cli_bcapi_atoi(struct cli_bc_ctx *ctx , const uint8_t*, int32_t);
uint32_t cli_bcapi_debug_print_str_start(struct cli_bc_ctx *ctx , const uint8_t*, uint32_t);
uint32_t cli_bcapi_debug_print_str_nonl(struct cli_bc_ctx *ctx , const uint8_t*, uint32_t);
uint32_t cli_bcapi_entropy_buffer(struct cli_bc_ctx *ctx , uint8_t*, int32_t);
int32_t cli_bcapi_map_new(struct cli_bc_ctx *ctx , int32_t, int32_t);
int32_t cli_bcapi_map_addkey(struct cli_bc_ctx *ctx , const uint8_t*, int32_t, int32_t);
int32_t cli_bcapi_map_setvalue(struct cli_bc_ctx *ctx , const uint8_t*, int32_t, int32_t);
int32_t cli_bcapi_map_remove(struct cli_bc_ctx *ctx , const uint8_t*, int32_t, int32_t);
int32_t cli_bcapi_map_find(struct cli_bc_ctx *ctx , const uint8_t*, int32_t, int32_t);
int32_t cli_bcapi_map_getvaluesize(struct cli_bc_ctx *ctx , int32_t);
uint8_t* cli_bcapi_map_getvalue(struct cli_bc_ctx *ctx , int32_t, int32_t);
int32_t cli_bcapi_map_done(struct cli_bc_ctx *ctx , int32_t);
int32_t cli_bcapi_file_find_limit(struct cli_bc_ctx *ctx , const uint8_t*, uint32_t, int32_t);
uint32_t cli_bcapi_engine_functionality_level(struct cli_bc_ctx *ctx );
uint32_t cli_bcapi_engine_dconf_level(struct cli_bc_ctx *ctx );
uint32_t cli_bcapi_engine_scan_options(struct cli_bc_ctx *ctx );
uint32_t cli_bcapi_engine_db_options(struct cli_bc_ctx *ctx );
int32_t cli_bcapi_extract_set_container(struct cli_bc_ctx *ctx , uint32_t);
int32_t cli_bcapi_input_switch(struct cli_bc_ctx *ctx , int32_t);
uint32_t cli_bcapi_get_environment(struct cli_bc_ctx *ctx , struct cli_environment*, uint32_t);
uint32_t cli_bcapi_disable_bytecode_if(struct cli_bc_ctx *ctx , const int8_t*, uint32_t, uint32_t);
uint32_t cli_bcapi_disable_jit_if(struct cli_bc_ctx *ctx , const int8_t*, uint32_t, uint32_t);
int32_t cli_bcapi_version_compare(struct cli_bc_ctx *ctx , const uint8_t*, uint32_t, const uint8_t*, uint32_t);
uint32_t cli_bcapi_check_platform(struct cli_bc_ctx *ctx , uint32_t, uint32_t, uint32_t);
int32_t cli_bcapi_pdf_get_obj_num(struct cli_bc_ctx *ctx );
int32_t cli_bcapi_pdf_get_flags(struct cli_bc_ctx *ctx );
int32_t cli_bcapi_pdf_set_flags(struct cli_bc_ctx *ctx , int32_t);
int32_t cli_bcapi_pdf_lookupobj(struct cli_bc_ctx *ctx , uint32_t);
uint32_t cli_bcapi_pdf_getobjsize(struct cli_bc_ctx *ctx , int32_t);
const uint8_t* cli_bcapi_pdf_getobj(struct cli_bc_ctx *ctx , int32_t, uint32_t);
int32_t cli_bcapi_pdf_getobjid(struct cli_bc_ctx *ctx , int32_t);
int32_t cli_bcapi_pdf_getobjflags(struct cli_bc_ctx *ctx , int32_t);
int32_t cli_bcapi_pdf_setobjflags(struct cli_bc_ctx *ctx , int32_t, int32_t);
int32_t cli_bcapi_pdf_get_offset(struct cli_bc_ctx *ctx , int32_t);
int32_t cli_bcapi_pdf_get_phase(struct cli_bc_ctx *ctx );
int32_t cli_bcapi_pdf_get_dumpedobjid(struct cli_bc_ctx *ctx );
int32_t cli_bcapi_matchicon(struct cli_bc_ctx *ctx , const uint8_t*, int32_t, const uint8_t*, int32_t);
int32_t cli_bcapi_running_on_jit(struct cli_bc_ctx *ctx );
int32_t cli_bcapi_get_file_reliability(struct cli_bc_ctx *ctx );

const struct cli_apiglobal cli_globals[] = {
/* Bytecode globals BEGIN */
	{"__clambc_match_offsets", GLOBAL_MATCH_OFFSETS, 76,
	 ((char*)&((struct cli_bc_ctx*)0)->hooks.match_offsets - (char*)NULL)},
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
static uint16_t cli_tmp0[]={32, 32, 16, 16, 74, 73, 32, 72, 70, 32, 32, 32, 32};
static uint16_t cli_tmp1[]={71};
static uint16_t cli_tmp2[]={32, 32};
static uint16_t cli_tmp3[]={16, 8, 8, 32, 32, 32, 32, 32, 64, 32, 32, 16, 16, 16, 16, 16, 16, 32, 32, 32, 32, 16, 16, 64, 64, 64, 64, 32, 32, 70};
static uint16_t cli_tmp4[]={16, 8, 8, 32, 32, 32, 32, 32, 32, 32, 32, 32, 16, 16, 16, 16, 16, 16, 32, 32, 32, 32, 16, 16, 32, 32, 32, 32, 32, 32, 70};
static uint16_t cli_tmp5[]={32, 16, 16, 32, 32, 32, 16, 16};
static uint16_t cli_tmp6[]={32};
static uint16_t cli_tmp7[]={32};
static uint16_t cli_tmp8[]={32};
static uint16_t cli_tmp9[]={32, 65, 32, 65, 32};
static uint16_t cli_tmp10[]={32, 32};
static uint16_t cli_tmp11[]={32, 32, 32};
static uint16_t cli_tmp12[]={65, 32, 32};
static uint16_t cli_tmp13[]={32, 32, 32, 32};
static uint16_t cli_tmp14[]={32, 65, 32, 32};
static uint16_t cli_tmp15[]={32, 85, 32};
static uint16_t cli_tmp16[]={86};
static uint16_t cli_tmp17[]={32, 32, 32, 32, 32, 32, 32, 87, 87, 87, 87, 87, 87, 87, 8, 8, 8, 8, 8, 8, 8, 8, 8};
static uint16_t cli_tmp18[]={8};
static uint16_t cli_tmp19[]={32, 65, 32};
static uint16_t cli_tmp20[]={32, 65, 32, 32, 32, 32};
static uint16_t cli_tmp21[]={32, 91, 32};
static uint16_t cli_tmp22[]={92};
static uint16_t cli_tmp23[]={32, 32, 32, 32, 32, 32, 32, 32, 32};
static uint16_t cli_tmp24[]={65, 32};
static uint16_t cli_tmp25[]={32, 95, 32};
static uint16_t cli_tmp26[]={96};
static uint16_t cli_tmp27[]={16, 8, 8, 8, 98, 97};
static uint16_t cli_tmp28[]={8};
static uint16_t cli_tmp29[]={99};
static uint16_t cli_tmp30[]={8};

const struct cli_bc_type cli_apicall_types[]={
	{DStructType, cli_tmp0, 13, 0, 0},
	{DArrayType, cli_tmp1, 16, 0, 0},
	{DStructType, cli_tmp2, 2, 0, 0},
	{DStructType, cli_tmp3, 30, 0, 0},
	{DStructType, cli_tmp4, 31, 0, 0},
	{DStructType, cli_tmp5, 8, 0, 0},
	{DArrayType, cli_tmp6, 1, 0, 0},
	{DArrayType, cli_tmp7, 64, 0, 0},
	{DFunctionType, cli_tmp8, 1, 0, 0},
	{DFunctionType, cli_tmp9, 5, 0, 0},
	{DFunctionType, cli_tmp10, 2, 0, 0},
	{DFunctionType, cli_tmp11, 3, 0, 0},
	{DFunctionType, cli_tmp12, 3, 0, 0},
	{DFunctionType, cli_tmp13, 4, 0, 0},
	{DFunctionType, cli_tmp14, 4, 0, 0},
	{DFunctionType, cli_tmp15, 3, 0, 0},
	{DPointerType, cli_tmp16, 1, 0, 0},
	{DStructType, cli_tmp17, 23, 0, 0},
	{DArrayType, cli_tmp18, 65, 0, 0},
	{DFunctionType, cli_tmp19, 3, 0, 0},
	{DFunctionType, cli_tmp20, 6, 0, 0},
	{DFunctionType, cli_tmp21, 3, 0, 0},
	{DPointerType, cli_tmp22, 1, 0, 0},
	{DStructType, cli_tmp23, 9, 0, 0},
	{DFunctionType, cli_tmp24, 2, 0, 0},
	{DFunctionType, cli_tmp25, 3, 0, 0},
	{DPointerType, cli_tmp26, 1, 0, 0},
	{DStructType, cli_tmp27, 6, 0, 0},
	{DArrayType, cli_tmp28, 29, 0, 0},
	{DArrayType, cli_tmp29, 3, 0, 0},
	{DArrayType, cli_tmp30, 10, 0, 0}
};

const unsigned cli_apicall_maxtypes=sizeof(cli_apicall_types)/sizeof(cli_apicall_types[0]);
const struct cli_apicall cli_apicalls[]={
/* Bytecode APIcalls BEGIN */
	{"test1", 11, 0, 0},
	{"read", 19, 0, 1},
	{"write", 19, 1, 1},
	{"seek", 11, 1, 0},
	{"setvirusname", 19, 2, 1},
	{"debug_print_str", 19, 3, 1},
	{"debug_print_uint", 10, 0, 2},
	{"disasm_x86", 25, 4, 1},
	{"trace_directory", 19, 5, 1},
	{"trace_scope", 19, 6, 1},
	{"trace_source", 19, 7, 1},
	{"trace_op", 19, 8, 1},
	{"trace_value", 19, 9, 1},
	{"trace_ptr", 19, 10, 1},
	{"pe_rawaddr", 10, 1, 2},
	{"file_find", 19, 11, 1},
	{"file_byteat", 10, 2, 2},
	{"malloc", 24, 0, 3},
	{"test2", 10, 3, 2},
	{"get_pe_section", 21, 12, 1},
	{"fill_buffer", 20, 0, 4},
	{"extract_new", 10, 4, 2},
	{"read_number", 10, 5, 2},
	{"hashset_new", 8, 0, 5},
	{"hashset_add", 11, 2, 0},
	{"hashset_remove", 11, 3, 0},
	{"hashset_contains", 11, 4, 0},
	{"hashset_done", 10, 6, 2},
	{"hashset_empty", 10, 7, 2},
	{"buffer_pipe_new", 10, 8, 2},
	{"buffer_pipe_new_fromfile", 10, 9, 2},
	{"buffer_pipe_read_avail", 10, 10, 2},
	{"buffer_pipe_read_get", 12, 0, 6},
	{"buffer_pipe_read_stopped", 11, 5, 0},
	{"buffer_pipe_write_avail", 10, 11, 2},
	{"buffer_pipe_write_get", 12, 1, 6},
	{"buffer_pipe_write_stopped", 11, 6, 0},
	{"buffer_pipe_done", 10, 12, 2},
	{"inflate_init", 13, 0, 7},
	{"inflate_process", 10, 13, 2},
	{"inflate_done", 10, 14, 2},
	{"bytecode_rt_error", 10, 15, 2},
	{"jsnorm_init", 10, 16, 2},
	{"jsnorm_process", 10, 17, 2},
	{"jsnorm_done", 10, 18, 2},
	{"ilog2", 11, 7, 0},
	{"ipow", 13, 1, 7},
	{"iexp", 13, 2, 7},
	{"isin", 13, 3, 7},
	{"icos", 13, 4, 7},
	{"memstr", 9, 0, 8},
	{"hex2ui", 11, 8, 0},
	{"atoi", 19, 13, 1},
	{"debug_print_str_start", 19, 14, 1},
	{"debug_print_str_nonl", 19, 15, 1},
	{"entropy_buffer", 19, 16, 1},
	{"map_new", 11, 9, 0},
	{"map_addkey", 14, 0, 9},
	{"map_setvalue", 14, 1, 9},
	{"map_remove", 14, 2, 9},
	{"map_find", 14, 3, 9},
	{"map_getvaluesize", 10, 19, 2},
	{"map_getvalue", 12, 2, 6},
	{"map_done", 10, 20, 2},
	{"file_find_limit", 14, 4, 9},
	{"engine_functionality_level", 8, 1, 5},
	{"engine_dconf_level", 8, 2, 5},
	{"engine_scan_options", 8, 3, 5},
	{"engine_db_options", 8, 4, 5},
	{"extract_set_container", 10, 21, 2},
	{"input_switch", 10, 22, 2},
	{"get_environment", 15, 17, 1},
	{"disable_bytecode_if", 14, 5, 9},
	{"disable_jit_if", 14, 6, 9},
	{"version_compare", 9, 1, 8},
	{"check_platform", 13, 5, 7},
	{"pdf_get_obj_num", 8, 5, 5},
	{"pdf_get_flags", 8, 6, 5},
	{"pdf_set_flags", 10, 23, 2},
	{"pdf_lookupobj", 10, 24, 2},
	{"pdf_getobjsize", 10, 25, 2},
	{"pdf_getobj", 12, 3, 6},
	{"pdf_getobjid", 10, 26, 2},
	{"pdf_getobjflags", 10, 27, 2},
	{"pdf_setobjflags", 11, 10, 0},
	{"pdf_get_offset", 10, 28, 2},
	{"pdf_get_phase", 8, 7, 5},
	{"pdf_get_dumpedobjid", 8, 8, 5},
	{"matchicon", 9, 2, 8},
	{"running_on_jit", 8, 9, 5},
	{"get_file_reliability", 8, 10, 5}
/* Bytecode APIcalls END */
};
const cli_apicall_int2 cli_apicalls0[] = {
	(cli_apicall_int2)cli_bcapi_test1,
	(cli_apicall_int2)cli_bcapi_seek,
	(cli_apicall_int2)cli_bcapi_hashset_add,
	(cli_apicall_int2)cli_bcapi_hashset_remove,
	(cli_apicall_int2)cli_bcapi_hashset_contains,
	(cli_apicall_int2)cli_bcapi_buffer_pipe_read_stopped,
	(cli_apicall_int2)cli_bcapi_buffer_pipe_write_stopped,
	(cli_apicall_int2)cli_bcapi_ilog2,
	(cli_apicall_int2)cli_bcapi_hex2ui,
	(cli_apicall_int2)cli_bcapi_map_new,
	(cli_apicall_int2)cli_bcapi_pdf_setobjflags
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
	(cli_apicall_pointer)cli_bcapi_get_pe_section,
	(cli_apicall_pointer)cli_bcapi_atoi,
	(cli_apicall_pointer)cli_bcapi_debug_print_str_start,
	(cli_apicall_pointer)cli_bcapi_debug_print_str_nonl,
	(cli_apicall_pointer)cli_bcapi_entropy_buffer,
	(cli_apicall_pointer)cli_bcapi_get_environment
};
const cli_apicall_int1 cli_apicalls2[] = {
	(cli_apicall_int1)cli_bcapi_debug_print_uint,
	(cli_apicall_int1)cli_bcapi_pe_rawaddr,
	(cli_apicall_int1)cli_bcapi_file_byteat,
	(cli_apicall_int1)cli_bcapi_test2,
	(cli_apicall_int1)cli_bcapi_extract_new,
	(cli_apicall_int1)cli_bcapi_read_number,
	(cli_apicall_int1)cli_bcapi_hashset_done,
	(cli_apicall_int1)cli_bcapi_hashset_empty,
	(cli_apicall_int1)cli_bcapi_buffer_pipe_new,
	(cli_apicall_int1)cli_bcapi_buffer_pipe_new_fromfile,
	(cli_apicall_int1)cli_bcapi_buffer_pipe_read_avail,
	(cli_apicall_int1)cli_bcapi_buffer_pipe_write_avail,
	(cli_apicall_int1)cli_bcapi_buffer_pipe_done,
	(cli_apicall_int1)cli_bcapi_inflate_process,
	(cli_apicall_int1)cli_bcapi_inflate_done,
	(cli_apicall_int1)cli_bcapi_bytecode_rt_error,
	(cli_apicall_int1)cli_bcapi_jsnorm_init,
	(cli_apicall_int1)cli_bcapi_jsnorm_process,
	(cli_apicall_int1)cli_bcapi_jsnorm_done,
	(cli_apicall_int1)cli_bcapi_map_getvaluesize,
	(cli_apicall_int1)cli_bcapi_map_done,
	(cli_apicall_int1)cli_bcapi_extract_set_container,
	(cli_apicall_int1)cli_bcapi_input_switch,
	(cli_apicall_int1)cli_bcapi_pdf_set_flags,
	(cli_apicall_int1)cli_bcapi_pdf_lookupobj,
	(cli_apicall_int1)cli_bcapi_pdf_getobjsize,
	(cli_apicall_int1)cli_bcapi_pdf_getobjid,
	(cli_apicall_int1)cli_bcapi_pdf_getobjflags,
	(cli_apicall_int1)cli_bcapi_pdf_get_offset
};
const cli_apicall_malloclike cli_apicalls3[] = {
	(cli_apicall_malloclike)cli_bcapi_malloc
};
const cli_apicall_ptrbuffdata cli_apicalls4[] = {
	(cli_apicall_ptrbuffdata)cli_bcapi_fill_buffer
};
const cli_apicall_allocobj cli_apicalls5[] = {
	(cli_apicall_allocobj)cli_bcapi_hashset_new,
	(cli_apicall_allocobj)cli_bcapi_engine_functionality_level,
	(cli_apicall_allocobj)cli_bcapi_engine_dconf_level,
	(cli_apicall_allocobj)cli_bcapi_engine_scan_options,
	(cli_apicall_allocobj)cli_bcapi_engine_db_options,
	(cli_apicall_allocobj)cli_bcapi_pdf_get_obj_num,
	(cli_apicall_allocobj)cli_bcapi_pdf_get_flags,
	(cli_apicall_allocobj)cli_bcapi_pdf_get_phase,
	(cli_apicall_allocobj)cli_bcapi_pdf_get_dumpedobjid,
	(cli_apicall_allocobj)cli_bcapi_running_on_jit,
	(cli_apicall_allocobj)cli_bcapi_get_file_reliability
};
const cli_apicall_bufget cli_apicalls6[] = {
	(cli_apicall_bufget)cli_bcapi_buffer_pipe_read_get,
	(cli_apicall_bufget)cli_bcapi_buffer_pipe_write_get,
	(cli_apicall_bufget)cli_bcapi_map_getvalue,
	(cli_apicall_bufget)cli_bcapi_pdf_getobj
};
const cli_apicall_int3 cli_apicalls7[] = {
	(cli_apicall_int3)cli_bcapi_inflate_init,
	(cli_apicall_int3)cli_bcapi_ipow,
	(cli_apicall_int3)cli_bcapi_iexp,
	(cli_apicall_int3)cli_bcapi_isin,
	(cli_apicall_int3)cli_bcapi_icos,
	(cli_apicall_int3)cli_bcapi_check_platform
};
const cli_apicall_2bufs cli_apicalls8[] = {
	(cli_apicall_2bufs)cli_bcapi_memstr,
	(cli_apicall_2bufs)cli_bcapi_version_compare,
	(cli_apicall_2bufs)cli_bcapi_matchicon
};
const cli_apicall_ptrbufid cli_apicalls9[] = {
	(cli_apicall_ptrbufid)cli_bcapi_map_addkey,
	(cli_apicall_ptrbufid)cli_bcapi_map_setvalue,
	(cli_apicall_ptrbufid)cli_bcapi_map_remove,
	(cli_apicall_ptrbufid)cli_bcapi_map_find,
	(cli_apicall_ptrbufid)cli_bcapi_file_find_limit,
	(cli_apicall_ptrbufid)cli_bcapi_disable_bytecode_if,
	(cli_apicall_ptrbufid)cli_bcapi_disable_jit_if
};
const unsigned cli_apicall_maxapi = sizeof(cli_apicalls)/sizeof(cli_apicalls[0]);
