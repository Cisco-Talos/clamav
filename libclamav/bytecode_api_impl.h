/*
 *  ClamAV bytecode internal API
 *
 *  Copyright (C) 2009 Sourcefire, Inc.
 *
 *  Authors: Török Edvin
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
struct cli_bc_ctx;
uint32_t cli_bcapi_test0(struct cli_bc_ctx *, struct foo*, uint32_t);
uint32_t cli_bcapi_test1(struct cli_bc_ctx *, uint32_t, uint32_t);

int32_t cli_bcapi_read(struct cli_bc_ctx*, uint8_t *data, int32_t size);
int32_t cli_bcapi_seek(struct cli_bc_ctx*, int32_t pos, uint32_t whence);

uint32_t cli_bcapi_setvirusname(struct cli_bc_ctx*, const uint8_t *name, uint32_t len);

uint32_t cli_bcapi_debug_print_str(struct cli_bc_ctx *ctx, const uint8_t*, uint32_t);
uint32_t cli_bcapi_debug_print_uint(struct cli_bc_ctx *ctx, uint32_t, uint32_t);
