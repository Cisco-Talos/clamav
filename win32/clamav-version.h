/*
 *  Copyright (C) 2019-2022 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  Authors: Micah Snyder
 *
 *  This file is NOT auto-generated and must be manually updated for each release.
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

#ifndef CLAMAV_VER_H
#define CLAMAV_VER_H

/**
 * @macro
 * Version number of the clamav package release
 */
#define CLAMAV_VERSION "0.103.5"

/**
 * @macro
 * Numerical representation of the version number of the clamav package
 * release. This is a 24 bit number with 8 bits for major number, 8 bits
 * for minor and 8 bits for patch. Version 1.2.3 becomes 0x010203.
 */
#define CLAMAV_VERSION_NUM 0x006600

/**
 * @macro
 * Version number of the clamav library release
 */
#define LIBCLAMAV_VERSION "9:4:0"

/**
 * @macro
 * Numerical representation of the version number of the libclamav library
 * release. This is a 24 bit number with 8 bits for major number, 8 bits
 * for minor and 8 bits for patch. Version 1.2.3 becomes 0x010203.
 */
#define LIBCLAMAV_VERSION_NUM 0x090400

/**
 * @macro
 * Version number of the clamav library release
 */
#define LIBFRESHCLAM_VERSION "2:0:0"

/**
 * @macro
 * Numerical representation of the version number of the libfreshclam library
 * release. This is a 24 bit number with 8 bits for major number, 8 bits
 * for minor and 8 bits for patch. Version 1.2.3 becomes 0x010203.
 */
#define LIBFRESHCLAM_VERSION_NUM 0x020000

#endif /* CLAMAV_VER_H */
