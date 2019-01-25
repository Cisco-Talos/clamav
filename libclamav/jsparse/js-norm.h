/*
 *  Javascript normalizer.
 *
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2008-2013 Sourcefire, Inc.
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
#ifndef JS_NORM_H
#define JS_NORM_H
struct parser_state;
struct text_buffer;

struct parser_state *cli_js_init(void);
void cli_js_process_buffer(struct parser_state *state, const char *buf, size_t n);
void cli_js_parse_done(struct parser_state* state);
void cli_js_output(struct parser_state *state, const char *tempdir);
void cli_js_destroy(struct parser_state *state);

char *cli_unescape(const char *str);

#endif
