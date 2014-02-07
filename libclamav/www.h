/*
 *  Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 *
 *  Author: Shawn Webb
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

#if !defined(_LIBCLAMAV_WWW_H)
#define _LIBCLAMAV_WWW_H

int connect_host(const char *host, const char *port, uint32_t timeout, int useAsync);
size_t encoded_size(const char *postdata);
char *encode_data(const char *postdata);
void submit_post(const char *host, const char *port, const char *method, const char *url, const char *postdata, uint32_t timeout);

#endif
