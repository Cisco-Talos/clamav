/*
 *  ClamAV bytecode internal API
 *  This is an automatically generated file!
 *
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2009-2013 Sourcefire, Inc.
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
#ifndef BYTECODE_API_IMPL_H
#define BYTECODE_API_IMPL_H

struct cli_bc_bctx;
struct cli_environment;
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
int32_t cli_bcapi_json_is_active(struct cli_bc_ctx *ctx );
int32_t cli_bcapi_json_get_object(struct cli_bc_ctx *ctx , const int8_t*, int32_t, int32_t);
int32_t cli_bcapi_json_get_type(struct cli_bc_ctx *ctx , int32_t);
int32_t cli_bcapi_json_get_array_length(struct cli_bc_ctx *ctx , int32_t);
int32_t cli_bcapi_json_get_array_idx(struct cli_bc_ctx *ctx , int32_t, int32_t);
int32_t cli_bcapi_json_get_string_length(struct cli_bc_ctx *ctx , int32_t);
int32_t cli_bcapi_json_get_string(struct cli_bc_ctx *ctx , int8_t*, int32_t, int32_t);
int32_t cli_bcapi_json_get_boolean(struct cli_bc_ctx *ctx , int32_t);
int32_t cli_bcapi_json_get_int(struct cli_bc_ctx *ctx , int32_t);
uint32_t cli_bcapi_engine_scan_options_ex(struct cli_bc_ctx *ctx , const uint8_t*, uint32_t);

#endif
