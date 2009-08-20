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

static uint16_t cli_tmp0[]={32, 70, 32};
static uint16_t cli_tmp1[]={71};
static uint16_t cli_tmp2[]={70};
static uint16_t cli_tmp3[]={32, 32, 32};

const struct cli_bc_type cli_apicall_types[]={
	{FunctionType, cli_tmp0, 3},
	{PointerType, cli_tmp1, 1},
	{StructType, cli_tmp2, 1},
	{FunctionType, cli_tmp3, 3}
};

const unsigned cli_apicall_maxtypes=sizeof(cli_apicall_types)/sizeof(cli_apicall_types[0]);
const struct cli_apicall cli_apicalls[]={
/* Bytecode APIcalls BEGIN */
	{"cli_bcapi_test0", 0, 0, 1},
	{"cli_bcapi_test1", 3, 0, 0}
/* Bytecode APIcalls END */
};
const cli_apicall_int2 cli_apicalls0[] = {
	cli_bcapi_test1
};
const cli_apicall_pointer cli_apicalls1[] = {
	(cli_apicall_pointer)cli_bcapi_test0
};
const unsigned cli_apicall_maxapi = sizeof(cli_apicalls)/sizeof(cli_apicalls[0]);
