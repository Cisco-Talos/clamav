/*
 *  ClamAV bytecode internal API
 *  This is an automatically generated file!
 *
 *  Copyright (C) 2009 Sourcefire, Inc.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
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
int32_t cli_bcapi_seek(struct cli_bc_ctx *ctx, int32_t, uint32_t);
uint32_t cli_bcapi_setvirusname(struct cli_bc_ctx *ctx, const const uint8_t*, uint32_t);
uint32_t cli_bcapi_debug_print_str(struct cli_bc_ctx *ctx, const const uint8_t*, uint32_t);
uint32_t cli_bcapi_debug_print_uint(struct cli_bc_ctx *ctx, uint32_t, uint32_t);

const struct cli_apiglobal cli_globals[] = {
/* Bytecode globals BEGIN */
	{"__clambc_match_counts", GLOBAL_MATCH_COUNTS, 73,
	 ((char*)&((struct cli_bc_ctx*)0)->hooks.match_counts - (char*)NULL)},
	{"__clambc_exeinfo", GLOBAL_EXEINFO, 70,
	 ((char*)&((struct cli_bc_ctx*)0)->hooks.exeinfo - (char*)NULL)},
	{"__clambc_kind", GLOBAL_KIND, 16,
	 ((char*)&((struct cli_bc_ctx*)0)->hooks.kind - (char*)NULL)},
	{"__clambc_pedata", GLOBAL_PEDATA, 69,
	 ((char*)&((struct cli_bc_ctx*)0)->hooks.pedata - (char*)NULL)}
/* Bytecode globals END */
};
const unsigned cli_apicall_maxglobal = _LAST_GLOBAL-1;
static uint16_t cli_tmp0[]={};
static uint16_t cli_tmp1[]={71, 32, 32, 16};
static uint16_t cli_tmp2[]={72};
static uint16_t cli_tmp3[]={32, 32, 32, 32, 32, 32, 32, 32, 32};
static uint16_t cli_tmp4[]={32};
static uint16_t cli_tmp5[]={32, 32, 32};
static uint16_t cli_tmp6[]={32, 65, 32};
static uint16_t cli_tmp7[]={32, 77, 32};
static uint16_t cli_tmp8[]={78};
static uint16_t cli_tmp9[]={77};

const struct cli_bc_type cli_apicall_types[]={
	{, cli_tmp0, , 0, 0},
	{DStructType, cli_tmp1, 4, 0, 0},
	{DPointerType, cli_tmp2, 1, 0, 0},
	{DStructType, cli_tmp3, 9, 0, 0},
	{DArrayType, cli_tmp4, 64, 0, 0},
	{DFunctionType, cli_tmp5, 3, 0, 0},
	{DFunctionType, cli_tmp6, 3, 0, 0},
	{DFunctionType, cli_tmp7, 3, 0, 0},
	{DPointerType, cli_tmp8, 1, 0, 0},
	{DStructType, cli_tmp9, 1, 0, 0}
};

const unsigned cli_apicall_maxtypes=sizeof(cli_apicall_types)/sizeof(cli_apicall_types[0]);
const struct cli_apicall cli_apicalls[]={
/* Bytecode APIcalls BEGIN */
	{"test0", 7, 0, 1},
	{"test1", 5, 0, 0},
	{"read", 6, 1, 1},
	{"seek", 5, 1, 0},
	{"setvirusname", 6, 2, 1},
	{"debug_print_str", 6, 3, 1},
	{"debug_print_uint", 5, 2, 0}
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
	(cli_apicall_pointer)cli_bcapi_setvirusname,
	(cli_apicall_pointer)cli_bcapi_debug_print_str
};
const unsigned cli_apicall_maxapi = sizeof(cli_apicalls)/sizeof(cli_apicalls[0]);
