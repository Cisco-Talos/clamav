/* 
 *  Simple library to detect and validate SSN and Credit Card numbers.
 *
 *  Copyright (C) 2007-2008 Sourcefire, Inc.
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

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <openssl/ssl.h>
#include <openssl/err.h>
#include "libclamav/crypto.h"

#include <stdio.h>
#include <ctype.h>  
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include "dlp.h"
#include "others.h"
#include "str.h"

/* detection mode macros for the contains_* functions */
#define DETECT_MODE_DETECT  0
#define DETECT_MODE_COUNT   1

/* group number mapping is here */
/* http://www.socialsecurity.gov/employer/highgroup.txt */
/* here's a perl script to convert the raw data from the highgroup.txt
 * file to the data set in ssn_max_group[]:
--
local $/;
my $i = <>;
my $count = 0;
while ($i =~ s/(\d{3}) (\d{2})//) {
    print int($2) .", ";
    if ($count == 18) 
    {
        print "\n";
        $count = 0;
    }
    else
    {
        $count++;
    }
 }
 --
  *
  * run 'perl convert.pl < highgroup.txt' to generate the data
  *
  */

/* MAX_AREA is the maximum assigned area number.  This can be derived from 
 * the data in the highgroup.txt file by looking at the last area->group 
 * mapping from that file.
 */ 
#define MAX_AREA 772
 
/* array of max group numbers for a given area number */
/*
static int ssn_max_group[MAX_AREA+1] = { 0,
    6, 6, 4, 8, 8, 8, 6, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 
    90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 88, 88, 88, 88, 72, 72, 72, 72, 
    70, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 96, 96, 96, 96, 96, 96, 96, 96, 
    96, 96, 96, 96, 96, 96, 96, 96, 96, 96, 96, 96, 96, 96, 96, 96, 96, 96, 96, 
    96, 96, 96, 96, 96, 96, 96, 96, 96, 96, 96, 96, 96, 96, 96, 96, 96, 96, 96, 
    96, 96, 96, 96, 96, 96, 96, 96, 96, 96, 96, 96, 96, 96, 96, 96, 96, 96, 96, 
    96, 96, 96, 96, 96, 96, 94, 94, 94, 94, 94, 94, 94, 94, 94, 94, 94, 94, 94, 
    94, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 17, 17, 17, 17, 17, 17, 
    17, 17, 17, 17, 17, 17, 84, 84, 84, 84, 84, 84, 84, 84, 84, 84, 84, 84, 84, 
    84, 84, 84, 84, 84, 84, 84, 84, 84, 84, 84, 82, 82, 82, 82, 82, 82, 82, 82, 
    82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 
    82, 82, 79, 79, 79, 79, 79, 79, 79, 79, 77, 6, 4, 99, 99, 99, 99, 99, 99, 
    99, 99, 99, 53, 53, 53, 53, 53, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 
    99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 
    99, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 
    13, 13, 13, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 33, 33, 
    31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 6, 6, 6, 6, 6, 6, 
    6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 
    6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 4, 4, 4, 4, 4, 4, 4, 4, 4, 
    35, 35, 35, 35, 35, 35, 33, 33, 33, 33, 33, 33, 33, 33, 33, 33, 33, 33, 33, 
    33, 33, 33, 33, 33, 33, 29, 29, 29, 29, 29, 29, 29, 29, 27, 27, 27, 27, 27, 
    67, 67, 67, 67, 67, 67, 67, 67, 99, 99, 99, 99, 99, 99, 99, 99, 63, 61, 61, 
    61, 61, 61, 61, 61, 61, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 
    99, 99, 23, 23, 23, 23, 23, 23, 23, 21, 21, 99, 99, 99, 99, 99, 99, 99, 99, 
    99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 51, 51, 51, 51, 49, 49, 49, 49, 
    49, 49, 37, 37, 37, 37, 37, 37, 37, 37, 25, 25, 25, 25, 25, 25, 25, 25, 25, 
    25, 25, 25, 23, 23, 23, 33, 33, 41, 39, 53, 51, 51, 51, 27, 27, 27, 27, 27, 
    27, 27, 45, 43, 79, 77, 55, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 63, 63, 
    63, 61, 61, 61, 61, 61, 61, 75, 73, 73, 73, 73, 99, 99, 99, 99, 99, 99, 99, 
    99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 
    99, 99, 99, 51, 99, 99, 45, 45, 43, 37, 99, 99, 99, 99, 99, 61, 99, 3, 99, 
    99, 99, 99, 99, 99, 99, 84, 84, 84, 84, 99, 99, 67, 67, 65, 65, 65, 65, 65, 
    65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 11, 
    11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 96, 
    96, 44, 44, 46, 46, 46, 44, 28, 26, 26, 26, 26, 16, 16, 16, 14, 14, 14, 14, 
    36, 34, 34, 34, 34, 34, 34, 34, 34, 14, 14, 12, 12, 90, 14, 14, 14, 14, 12, 
    12, 12, 12, 12, 12, 9, 9, 7, 7, 7, 7, 7, 7, 7, 18, 18, 18, 18, 18, 
    18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 
    28, 18, 18, 10, 14, 10, 10, 10, 10, 10, 9, 9, 3, 1, 5, 5, 5, 5, 5, 
    5, 3, 3, 82, 82, 66, 66, 64, 64, 64, 64, 64
};
*/



int dlp_is_valid_cc(const unsigned char *buffer, int length)
{
    int mult = 0;
    int sum = 0;
    int i = 0;
    int val = 0;
    int digits = 0;
    char cc_digits[20];
    
    if(buffer == NULL || length < 13)
        return 0;
    /* if the first digit is greater than 6 it isn't one of the major
     * credit cards
     * reference => http://www.beachnet.com/~hstiles/cardtype.html
     */
    if(!isdigit(buffer[0]) || buffer[0] > '6')
        return 0;
        
    if(length > 19)
        length = 19;

    for(i = 0; i < length; i++)
    {
	if(isdigit(buffer[i]) == 0)
	{
	    if(buffer[i] == ' ' || buffer[i] == '-')
		continue;
	    else
		break;
	}
	cc_digits[digits] = buffer[i];
	digits++;
    }
    cc_digits[digits] = 0;

    if(digits < 13 || (i < length && isdigit(buffer[i])))
	return 0;

    for(i = digits - 1; i >= 0; i--)
    {
	val = cc_digits[i] - '0';
        if(mult)
        {
            if((val *= 2) > 9) val -= 9;
        }
	mult = !mult;
	sum += val;
    }

    if(sum % 10)
	return 0;

    if(digits == 13) /* VISA */
    {
	if(cc_digits[0] == '4') {
	    cli_dbgmsg("dlp_is_valid_cc: VISA [1] (%s)\n", cc_digits);
	    return 1;
	}
    }
    else if(digits == 14) /* Diners Club */
    {
	if(cc_digits[0] == '3' && (cc_digits[1] == '6' || cc_digits[1] == '8'))
	{
	    cli_dbgmsg("dlp_is_valid_cc: Diners Club [1] (%s)\n", cc_digits);
	    return 1;
	}
	else if(cc_digits[0] == '3' && cc_digits[1] == '0')
	{
	    val = cc_digits[2] - '0';
	    if(val >= 0 && val <= 5) {
		cli_dbgmsg("dlp_is_valid_cc: Diners Club [2] (%s)\n", cc_digits);
		return 1;
	    }
	}
    }
    else if(digits == 15)
    {
	if(cc_digits[0] == '3' && (cc_digits[1] == '4' || cc_digits[1] == '7')) /*AMEX*/
	{
	    cli_dbgmsg("dlp_is_valid_cc: AMEX (%s)\n", cc_digits);
	    return 1;
	}
	else if(!strncmp(cc_digits, "2131", 4) || !strncmp(cc_digits, "1800", 4))
	{ /* JCB  */
	    cli_dbgmsg("dlp_is_valid_cc: JCB [1] (%s)\n", cc_digits);
	    return 1;
	}
    }
    else if(digits == 16)
    {
	if(cc_digits[0] == '3') /* JCB */
	{
	    cli_dbgmsg("dlp_is_valid_cc: JCB [2] (%s)\n", cc_digits);
	    return 1;
	}
	else if(cc_digits[0] == '4') /* VISA */
	{
	    cli_dbgmsg("dlp_is_valid_cc: VISA [2] (%s)\n", cc_digits);
	    return 1;
	}
	else if(cc_digits[0] == '5') /* MASTERCARD */
	{
	    val = cc_digits[1] - '0';
	    if(val >= 1 && val <= 5) {
		cli_dbgmsg("dlp_is_valid_cc: MASTERCARD (%s)\n", cc_digits);
		return 1;
	    }
	}
	else if(!strncmp(cc_digits, "6011", 4)) /* Discover */
	{
	    cli_dbgmsg("dlp_is_valid_cc: Discover (%s)\n", cc_digits);
	    return 1;
	} 
    }

    return 0;
}

static int contains_cc(const unsigned char *buffer, int length, int detmode)
{
    const unsigned char *idx;
    const unsigned char *end;
    int count = 0;
    
    if(buffer == NULL || length < 13)
    {
        return 0;         
    }

    end = buffer + length;
    idx = buffer;
    while(idx < end)
    {
        if(isdigit(*idx))
        {
            if((idx == buffer || !isdigit(idx[-1])) && dlp_is_valid_cc(idx, length - (idx - buffer)) == 1)
            {
                if(detmode == DETECT_MODE_DETECT)
                    return 1;
                else
                {
                    count++;
                    /* if we got a valid match we should increment the idx ptr
                     * to gain a little performance
                     */
                    idx += (length > 15?15:(length-1));
                }
            }
        }
        idx++;
    }
    
    return count;
}

int dlp_get_cc_count(const unsigned char *buffer, int length)
{
    return contains_cc(buffer, length, DETECT_MODE_COUNT);
}

int dlp_has_cc(const unsigned char *buffer, int length)
{
    return contains_cc(buffer, length, DETECT_MODE_DETECT);
}

int dlp_is_valid_ssn(const unsigned char *buffer, int length, int format)
{
    int area_number;
    int group_number;
    int serial_number;
    int minlength;
    int retval = 1;
    char numbuf[12];
    
    if(buffer == NULL)
        return 0;
        
    minlength = (format==SSN_FORMAT_HYPHENS?11:9);

    if(length < minlength)
        return 0;

    if((length > minlength) && isdigit(buffer[minlength]))
	return 0;
        
    strncpy(numbuf, (const char*)buffer, minlength);
    numbuf[minlength] = 0;

    /* sscanf parses and (basically) validates the string for us */
    switch(format)
    {
        case SSN_FORMAT_HYPHENS:
	    if(numbuf[3] != '-' || numbuf[6] != '-')
		return 0;

            if(sscanf((const char *) numbuf, 
                      "%3d-%2d-%4d", 
                      &area_number, 
                      &group_number, 
                      &serial_number) != 3)
            {
                return 0;
            }       
            break;
        case SSN_FORMAT_STRIPPED:
	    if(!cli_isnumber(numbuf))
		return 0;

            if(sscanf((const char *) numbuf,  
                       "%3d%2d%4d", 
                       &area_number, 
                       &group_number, 
                       &serial_number) != 3)
             {
                 return 0;
             }       
             break;
        default:
	    cli_dbgmsg("dlp_is_valid_ssn: unknown format type %d \n", format);
	    return 0;
    }
        
    /* start validating */
    /* validation data taken from 
     * http://en.wikipedia.org/wiki/Social_Security_number_%28United_States%29
     */
    if(area_number > MAX_AREA || 
       area_number == 666 || 
       area_number <= 0 || 
       group_number <= 0 || 
       group_number > 99 || 
       serial_number <= 0 ||
       serial_number > 9999)
        retval = 0;
        
    if(area_number == 987 && group_number == 65) 
    {
        if(serial_number >= 4320 && serial_number <= 4329)
            retval = 0;
    }
    
    /*
    if(group_number > ssn_max_group[area_number])
        retval = 0;
    */
    if(retval)
	cli_dbgmsg("dlp_is_valid_ssn: SSN_%s: %s\n", format == SSN_FORMAT_HYPHENS ? "HYPHENS" : "STRIPPED", numbuf);

    return retval;
}

static int contains_ssn(const unsigned char *buffer, int length, int format, int detmode)
{
    const unsigned char *idx;
    const unsigned char *end;
    int count = 0;
    
    if(buffer == NULL || length < 9)
        return 0; 

    end = buffer + length;
    idx = buffer;
    while(idx < end)
    {
        if(isdigit(*idx))
        {
            /* check for area number and the first hyphen */
            if((idx == buffer || !isdigit(idx[-1])) && dlp_is_valid_ssn(idx, length - (idx - buffer), format) == 1)
            {
                if(detmode == DETECT_MODE_COUNT)
                {
                    count++;
                        /* hop over the matched bytes if we found an SSN */
                    idx += ((format == SSN_FORMAT_HYPHENS)?11:9);
                }
                else
                {
                    return 1;                                                                            
                }
            }
        }
        idx++;
    }
    
    return count;   
}

int dlp_get_stripped_ssn_count(const unsigned char *buffer, int length)
{
    return contains_ssn(buffer, 
                        length, 
                        SSN_FORMAT_STRIPPED, 
                        DETECT_MODE_COUNT);
}

int dlp_get_normal_ssn_count(const unsigned char *buffer, int length)
{
    return contains_ssn(buffer, 
                        length, 
                        SSN_FORMAT_HYPHENS, 
                        DETECT_MODE_COUNT);
}

int dlp_get_ssn_count(const unsigned char *buffer, int length)
{
    /* this will suck for performance but will find SSNs in either
     * format
     */
    return (dlp_get_stripped_ssn_count(buffer, length) + dlp_get_normal_ssn_count(buffer, length));
}

int dlp_has_ssn(const unsigned char *buffer, int length)
{
    return (contains_ssn(buffer, 
                         length, 
                         SSN_FORMAT_HYPHENS, 
                         DETECT_MODE_DETECT)
            | contains_ssn(buffer, 
                           length, 
                           SSN_FORMAT_STRIPPED, 
                           DETECT_MODE_DETECT));
}

int dlp_has_stripped_ssn(const unsigned char *buffer, int length)
{
    return contains_ssn(buffer, 
                        length, 
                        SSN_FORMAT_STRIPPED, 
                        DETECT_MODE_DETECT);
}

int dlp_has_normal_ssn(const unsigned char *buffer, int length)
{
    return contains_ssn(buffer, 
                        length, 
                        SSN_FORMAT_HYPHENS, 
                        DETECT_MODE_DETECT);
}
