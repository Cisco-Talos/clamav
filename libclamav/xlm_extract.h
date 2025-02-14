/*
 *  Extract XLM (Excel 4.0) macro source code for component MS Office Documents
 *
 *  Copyright (C) 2020-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  Authors: Jonas Zaddach
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

/**
 * Throughout this file, I refer to the Microsoft Office Excel 97 - 2007 Binary File Format (.xls) Specification, which can be found
 * here: http://download.microsoft.com/download/5/0/1/501ED102-E53F-4CE0-AA6B-B0F93629DDC6/Office/Excel97-2007BinaryFileFormat(xls)Specification.pdf
 */

#ifndef __XLM_EXTRACT_H
#define __XLM_EXTRACT_H

#include "others.h"
#include "clamav-types.h"
#include "uniq.h"

// Page 58 CONTINUE record Microsoft Office Excel97-2007Binary File Format (.xls) Specification
#define BIFF8_MAX_RECORD_LENGTH 8228

typedef enum biff8_opcode {
    OPC_FORMULA         = 0x06,
    OPC_NAME            = 0x18,
    OPC_CONTINUE        = 0x3C,
    OPC_BOUNDSHEET      = 0x85,
    OPC_MSODRAWINGGROUP = 0xEB,
    OPC_STRING          = 0x207,
} biff8_opcode;

cl_error_t cli_extract_xlm_macros_and_images(const char *dir, cli_ctx *ctx, char *hash, uint32_t which);
#endif
