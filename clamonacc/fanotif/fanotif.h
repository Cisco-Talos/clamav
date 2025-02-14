/*
 *  Copyright (C) 2019-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  Authors: Mickey Sola
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

#ifndef __ONAS_FAN_H
#define __ONAS_FAN_H

// libclamav
#include "clamav.h"

#include "../clamonacc.h"

// void *onas_fan_th(void *arg);
cl_error_t onas_setup_fanotif(struct onas_context **ctx);
int onas_fan_eloop(struct onas_context **ctx);

#endif
