/*
 *  Copyright (C) 2016-2017 Cisco and/or its affiliates. All rights reserved.
 *
 *  Author: Kevin Lin
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
 *
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations
 *  including the two.
 *  
 *  You must obey the GNU General Public License in all respects
 *  for all of the code used other than OpenSSL.  If you modify
 *  file(s) with this exception, you may extend this exception to your
 *  version of the file(s), but you are not obligated to do so.  If you
 *  do not wish to do so, delete this exception statement from your
 *  version.  If you delete this exception statement from all source
 *  files in the program, then also delete it here.
 */
#ifndef __PDFDECODE_H__
#define __PDFDECODE_H__

#include "pdf.h"

/**
 * @brief       Wrapper function for pdf_decodestream_internal.
 * 
 * Allocate a token object to store decoded filter data.
 * Parse/decode the filter data and scan it.
 * 
 * @param pdf       Pdf context structure.
 * @param obj       The object we found the filter content in.
 * @param params    Dictionary parameters describing the filter data.
 * @param stream    Filter stream buffer pointer.
 * @param streamlen Length of filter stream buffer.
 * @param xref      Indicates if the stream is an /XRef stream.  Do not apply forced decryption on /XRef streams.
 * @param fout      File descriptor to write to a temp file.
 * @param[out] rc   Return code ()
 * @param objstm    Object stream context structure.
 * @return size_t   The number of bytes written to fout to be scanned.
 */
size_t pdf_decodestream(
    struct pdf_struct *pdf, struct pdf_obj *obj, struct pdf_dict *params,
    const char *stream, uint32_t streamlen, int xref, int fout, cl_error_t *status,
    struct objstm_struct *objstm);

#endif /* __PDFDECODE_H__ */
