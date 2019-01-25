/* 
 *  Simple library to detect and validate SSN and Credit Card numbers.
 *
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Martin Roesch <roesch@sourcefire.com>
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

#ifndef __DLP_H_
#define __DLP_H_

#include <stdio.h>

/* these macros define the SSN string format to search for */
#define SSN_FORMAT_HYPHENS    0     /* xxx-yy-zzzz */
#define SSN_FORMAT_STRIPPED   1     /* xxxyyzzzz */

/*
 * will check if a valid credit card number exists within the 
 * first 16 bytes of the supplied buffer.  Validation supplied
 * via the Luhn algorithm.
 * Params:
 *      buffer => data buffer to be validated.
 *      length => length of supplied buffer.  Values greater than 16 are
 *                truncated to 16.  Values less than 13 are rejected. 
 * Returns:
 *      1 on a find, 0 on a miss
 */
int dlp_is_valid_cc(const unsigned char *buffer, int length);

/* Searches the supplied buffer for credit card numbers and returns
 * the number of CC's found.
 * Params:
 *      buffer => data buffer to be analyzed.
 *      length => length of buffer.  
 * Returns:
 *      Count of detected CC #'s.
 */
int dlp_get_cc_count(const unsigned char *buffer, int length);

/* Searches the supplied buffer for CC #'s.  Bails out as soon as a 
 * validated number is detected.
 * Params:
 *      buffer => data buffer to be analyzed.
 *      length => length of buffer.
 * Returns:
 *      1 on detect, 0 on fail
 */
int dlp_has_cc(const unsigned char *buffer, int length);

/* Checks the supplied buffer for a valid SSN number.  Validation
 * is supplied via area and group number validation.  Valid numbers
 * which are not in circulation (666 series, 000 series) are NOT
 * detected, only numbers that can be valid in the real world.  Searches
 * only the first 11 or 9 bytes (based on the selected format)!
 * Params:
 *      buffer => buffer to be validated
 *      length => length of buffer to validate
 * Returns:
 *      1 on detect, 0 on failure
 */
int dlp_is_valid_ssn(const unsigned char *buffer, int length, int format);

/* Searches the supplied buffer for valid SSNs.  Note that this function
 * is effectively searching the buffer TWICE looking for the hyphenated and
 * stripped forms of the SSN.  There will be a performance impact!
 * Params:
 *      buffer => buffer to search
 *      length => length of the buffer
 * Returns:
 *      Count of SSNs in the supplied buffer
 */
int dlp_get_ssn_count(const unsigned char *buffer, int length);

/* Searches the supplied buffer for valid SSNs formatted as xxxyyzzzz.
 * Params:
 *      buffer => buffer to search
 *      length => length of the buffer
 * Returns:
 *      Count of SSNs in the supplied buffer.
 */
int dlp_get_stripped_ssn_count(const unsigned char *buffer, int length);

/* Searches the supplied buffer for valid SSNs formatted as xxx-yy-zzzz.
 * Params:
 *      buffer => buffer to search
 *      length => length of the buffer
 * Returns:
 *      Count of SSNs in the supplied buffer.
 */
int dlp_get_normal_ssn_count(const unsigned char *buffer, int length);

/* Searches the supplied buffer for a SSN in any format.  This searches the
 * buffer twice for both the stripped and hyphenated versions of an SSN so
 * there will be a performance impact!
 * Params:
 *      buffer => buffer to search
 *      length => length of the buffer
 * Returns:
 *      1 on detect, 0 on fail
 */
int dlp_has_ssn(const unsigned char *buffer, int length);

/* Searches the supplied buffer for a SSN in the stripped xxxyyzzzz format.
 * Params:
 *      buffer => buffer to search
 *      length => length of the buffer
 * Returns:
 *      1 on detect, 0 on fail
 */
int dlp_has_stripped_ssn(const unsigned char *buffer, int length);

/* Searches the supplied buffer for a SSN in the normal xxx-yy-zzzz format.
 * Params:
 *      buffer => buffer to search
 *      length => length of the buffer
 * Returns:
 *      1 on detect, 0 on fail
 */
int dlp_has_normal_ssn(const unsigned char *buffer, int length);

int cdn_ctn_is_valid(const char *, int);
int cdn_eft_is_valid(const char *, int);
int us_micr_is_valid(const char *, int);

#endif  /* __DLP_H_ */
