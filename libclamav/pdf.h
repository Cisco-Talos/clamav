/*
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *  Copyright (C) 2014 Cisco Systems, Inc. All rights reserved.
 *
 *  Authors: Nigel Horne
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
#ifndef __PDF_H
#define __PDF_H

#include "others.h"
struct pdf_obj {
    uint32_t start;
    uint32_t id;
    uint32_t flags;
    uint32_t statsflags;
    char *path;
};

enum pdf_array_type { PDF_ARR_UNKNOWN=0, PDF_ARR_STRING, PDF_ARR_ARRAY };

struct pdf_array_node {
    void *data;
    size_t datasz;
    enum pdf_array_type type;

    struct pdf_array_node *prev;
    struct pdf_array_node *next;
};

struct pdf_array {
    struct pdf_array_node *nodes;
};

#define OBJ_FLAG_PDFNAME_NONE 0x0
#define OBJ_FLAG_PDFNAME_DONE 0x1

int cli_pdf(const char *dir, cli_ctx *ctx, off_t offset);

#endif
