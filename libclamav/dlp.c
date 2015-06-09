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



/*
 *  The function below was re-written to check common case
 *  credit/debit card numbers Visa, Mastercard, Amex, Discover
 *  first within respective length groups.
 *
 *  The following credit/debit card formats are checked in this
 *  function:
 *
 *  Credit/Debit Card           # of digits     Luhn Algorithm in Use?
 *  -----------------           -----------     ----------------------
 *  
 *  Laser Debit (UK/Ireland)        16-19               Yes
 *  Solo Credit/Debit               16-19               Yes
 *  China Union Pay                 16-19               Unknown
 *  VISA Electron Debit             16                  Yes
 *  Dankort                         16                  Unknown
 *  Discover                        16                  Yes
 *  Instapay                        16                  Yes
 *  Maestro                         16                  Unknown
 *  Diner's Club (US and Canada)    16                  Yes
 *  Japan Credit Bureau (JCB)       15 or 16            Yes
 *  Mastercard                      16                  Yes
 *  VISA (regular)                  16                  Yes
 *  AMEX                            15                  Yes
 *  Enroute Credit/Debit            15                  Yes
 *  Diner's Club International      14                  Yes
 *  Diner's Club Carte Blanche      14                  Yes
 *  VISA (Original Card)            13                  Yes
 *
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

    if(length > 19)     /* if card digits length is > 19, make it 19    */
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

    if (digits == 13)	/* VISA Original Card */
    {
        if (cc_digits[0] == '4')
        {
            cli_dbgmsg("dlp_is_valid_cc: VISA Original (13 digits) (%s)\n", cc_digits);
            return 1;   /* first digit is 4, valid */
	}
    }	    /* end if digits == 13  */
    else if (digits == 16)
    {
        if (cli_debug_flag) {  /* Only need the following checks if debug is on */
            /* Visa Electron Debit Card (16 digits in length, Luhn Algorithm in use) */
            
            if (cc_digits[0] == '4' && cc_digits[1] == '0' && cc_digits[2] == '2' && cc_digits[3] == '6')
            {
                cli_dbgmsg("dlp_is_valid_dc: Visa Electron Debit Card (%s)\n", cc_digits);
                return 1;   /* first four digits are 4026, valid */
            }
            else if (!strncmp(cc_digits, "417500", 6))
            {
                cli_dbgmsg("dlp_is_valid_dc: Visa Electron Debit Card (%s)\n", cc_digits);
                return 1;   /* first six digits are 417500, valid */
            }
            else if (cc_digits[0] == '4' && cc_digits[1] == '5' && cc_digits[2] == '0' && cc_digits[3] == '8')
            {
                cli_dbgmsg("dlp_is_valid_dc: Visa Electron Debit Card (%s)\n", cc_digits);
                return 1;   /* first four digits are 4508, valid */
            }
            else if (cc_digits[0] == '4' && cc_digits[1] == '8' && cc_digits[2] == '4' && cc_digits[3] == '4')
            {
                cli_dbgmsg("dlp_is_valid_dc: Visa Electron Debit Card (%s)\n", cc_digits);
                return 1;   /* first four digits are 4844, valid */
            }
            else if (cc_digits[0] == '4' && cc_digits[1] == '9' && cc_digits[2] == '1' && cc_digits[3] == '3')
            {
                cli_dbgmsg("dlp_is_valid_dc: Visa Electron Debit Card (%s)\n", cc_digits);
                return 1;   /* first four digits are 4913, valid */
            }
            else if (cc_digits[0] == '4' && cc_digits[1] == '9' && cc_digits[2] == '1' && cc_digits[3] == '7')
            {
                cli_dbgmsg("dlp_is_valid_dc: Visa Electron Debit Card (%s)\n", cc_digits);
                return 1;   /* first four digits are 4917, valid */
            }
        }

        if (cc_digits[0] == '4') /* Regular VISA Card (16 digits) */
        {
            cli_dbgmsg("dlp_is_valid_cc: VISA Card (16 digits) (%s)\n", cc_digits);
            return 1;   /* first digit is 4, valid */
        }
        else if (cc_digits[0] == '5' && cc_digits[1] == '0' && cc_digits[2] == '1' && cc_digits[3] == '9')
        {   /* Dankort credit/debit card (16 digits), unsure of Luhn algorithm  */
            cli_dbgmsg("dlp_is_valid_cc: Dankort (%s)\n", cc_digits);
            return 1;   /* first four digits are 5019, valid */
        }
        else if (cc_digits[0] == '5') /* MASTERCARD */
        {
            val = cc_digits[1] - '0';
            if (val >= 1 && val <= 5)
            {
                cli_dbgmsg("dlp_is_valid_cc: MASTERCARD (%s)\n", cc_digits);
                return 1;   /* first digit is 5, 2nd digit is 1 to 5, valid */
            }
        }
        else if (!strncmp(cc_digits, "6011", 4)) /* Discover Card */
        {
            cli_dbgmsg("dlp_is_valid_cc: Discover Card (%s)\n", cc_digits);
            return 1;   /* first four digits are 6011, valid */
        }
        else if (!strncmp(cc_digits, "65", 2)) /* Also Discover Card */
        {
            cli_dbgmsg("dlp_is_valid_cc: Discover Card (%s)\n", cc_digits);
            return 1;   /* first two digits are 65, valid */
        }
        else if (!strncmp(cc_digits, "64", 2)) /* Also Discover Card */
        {
            val = cc_digits[2] - '0';
            if (val >= 4 && val <= 9)
            {
                cli_dbgmsg("dlp_is_valid_cc: Discover Card (%s)\n", cc_digits);
                return 1;   /* first two digits are 64, 3rd digit is 4 to 9, valid */
            }
        }
        else if (!strncmp(cc_digits, "622", 3)) /* Also Discover Card */
        {
            val = cc_digits[3] - '0';
            if (val >= 1 && val <= 9)
            {
                cli_dbgmsg("dlp_is_valid_cc: Discover Card (%s)\n", cc_digits);
                return 1;   /* first three digits are 622, 4th digit is 1 to 9, valid */
            }
        }
        
        /* Japan Credit Bureau, 16 digits, Luhn Algorithm in Use */
        
        else if (cc_digits[0] == '3' && cc_digits[1] == '5') /* Japan Credit Bureau */
        {
            val = cc_digits[2] - '0';
            if (val >= 2 && val <= 8)
            {
                cli_dbgmsg("dlp_is_valid_cc: Japan Credit Bureau [2] (%s)\n", cc_digits);
                return 1;   /* first two digits are 35, 3rd digit is 2 to 8, valid */
            }
        }

        /* InstaPay Credit Card (637x-639x, 16 digits, Luhn Algorithm)  */

        else if (cc_digits[0] == '6' && cc_digits[1] == '3')
        {
            val = cc_digits[2] - '0';
            if (val >= 7 && val <= 9)
            {
                cli_dbgmsg("dlp_is_valid_cc: InstaPay Card (%s)\n", cc_digits);
                return 1;   /* first two digits are 63, 3rd digit 7 to 9, valid */
            }
        }
        else if (cc_digits[0] == '5' && cc_digits[1] == '6') /* Maestro */
        {
            val = cc_digits[2] - '0';
            if (val >= 0 && val <= '5')
            {
                cli_dbgmsg("dlp_is_valid_cc: Maestro (%s)\n", cc_digits);
                return 1;   /* first two digits is 56, 3rd digit is 0 to 5, valid */
            }
        }
        
        /* China Union Pay Credit Card, at least 16 digits in length, unsure of Luhn */

        else if (cc_digits[0] == '6' && cc_digits[1] == '2')
        {
            val = cc_digits[2] - '0';
            if (val >= 0 && val <= 1)
            {
                cli_dbgmsg("dlp_is_valid_dc: China Union Pay Credit Card (%s)\n", cc_digits);
                return 1;
            }
        }
        else if (cc_digits[0] == '6' && cc_digits[1] == '2' && cc_digits[2] == '5')
        {
            cli_dbgmsg("dlp_is_valid_dc: China Union Pay Credit Card (%s)\n", cc_digits);
            return 1;
        }
        else if (cc_digits[0] == '5' && (cc_digits[1] == '4' || cc_digits[1] == '5'))
        {
            cli_dbgmsg("dlp_is_valid_cc: Diner's Club (US and Canada) (%s)\n", cc_digits);
            return 1;   /* first two digits are 54 or 55, valid */
        }

        /* Laser Debit Card (Ireland), 16 digits in length, Luhn Algorithm in use */

        else if (cc_digits[0] == '6' && cc_digits[1] == '3' && cc_digits[2] == '0' && cc_digits[3] == '4')
        {
            cli_dbgmsg("dlp_is_valid_dc: Laser Debit Card (%s)\n", cc_digits);
            return 1;   /* first four digits are 6304, valid */
        }
        else if (cc_digits[0] == '6' && cc_digits[1] == '7' && cc_digits[2] == '0' && cc_digits[3] == '6')
        {
            cli_dbgmsg("dlp_is_valid_dc: Laser Debit Card (%s)\n", cc_digits);
            return 1;   /* first four digits are 6706, valid */
        }
        else if (cc_digits[0] == '6' && cc_digits[1] == '7' && cc_digits[2] == '7' && cc_digits[3] == '1')
        {
            cli_dbgmsg("dlp_is_valid_dc: Laser Debit Card (%s)\n", cc_digits);
            return 1;   /* first four digits are 6771, valid */
        }
        else if (cc_digits[0] == '6' && cc_digits[1] == '3' && cc_digits[2] == '3' && cc_digits[3] == '4')
        {
            cli_dbgmsg("dlp_is_valid_dc: Solo Credit Card (%s)\n", cc_digits);
            return 1;   /* first four digits are 6334, valid */
        }
        else if (cc_digits[0] == '6' && cc_digits[1] == '7' && cc_digits[2] == '6' && cc_digits[3] == '7')
        {
            cli_dbgmsg("dlp_is_valid_dc: Solo Credit Card (%s)\n", cc_digits);
            return 1;   /* First four digits are 6767, valid */
        }
    }       /* end else if digits == 16 */
    else if (digits == 15)
    {
        if (cc_digits[0] == '3' && (cc_digits[1] == '4' || cc_digits[1] == '7')) /*AMEX*/
	{
            cli_dbgmsg("dlp_is_valid_cc: AMEX (%s)\n", cc_digits);
            return 1;   /* first two digits are 34 or 37, valid */
        }
	else if (!strncmp(cc_digits, "2131", 4) || !strncmp(cc_digits, "1800", 4))
        { /* Japan Credit Bureau  */
            cli_dbgmsg("dlp_is_valid_cc: Japan Credit Bureau [1] (%s)\n", cc_digits);
            return 1;   /* first four digits are 2131 or 1800, valid */
	}

	/* Enroute credit/debit card, 15 digits, starts with 2014 or 2149, Luhn Algorithm */

	else if (cc_digits[0] == '2' && cc_digits[1] == '0' && cc_digits[2] == '1' && cc_digits[3] == '4')
	{
            cli_dbgmsg("dlp_is_valid_cc: Enroute Card (%s)\n", cc_digits);
            return 1;   /* first four digits are 2014, valid */
	}
	else if (cc_digits[0] == '2' && cc_digits[1] == '1' && cc_digits[2] == '4' && cc_digits[3] == '9')
	{
            cli_dbgmsg("dlp_is_valid_cc: Enroute Card (%s)\n", cc_digits);
            return 1;   /* first four digits are 2149, valid */
        }
    }	    /* end else if digits == 15	*/
    else if (digits > 16 && digits <= 19)
    {
        /* China Union Pay Credit Card, 16 to 19 digits in length, unsure of Luhn */

        if (cc_digits[0] == '6' && cc_digits[1] == '2')
        {
            val = cc_digits[2] - '0';
            if (val >= 0 && val <= 5)
            {
                cli_dbgmsg("dlp_is_valid_dc: China Union Pay Credit Card (%s)\n", cc_digits);
                return 1;   /* first two digits 62, 3rd digit is 0 to 5, valid */
            }
        }

        /* Solo Credit/Debit Card, 16 to 19 digits in length, Luhn algorithm in use */

        else if (cc_digits[0] == '6' && cc_digits[1] == '3' && cc_digits[2] == '3' && cc_digits[3] == '4')
        {
            cli_dbgmsg("dlp_is_valid_dc: Solo Credit Card (%s)\n", cc_digits);
            return 1;   /* First four digits are 6334, valid */
        }
        else if (cc_digits[0] == '6' && cc_digits[1] == '7' && cc_digits[2] == '6' && cc_digits[3] == '7')
        {
            cli_dbgmsg("dlp_is_valid_dc: Solo Credit Card (%s)\n", cc_digits);
            return 1;   /* First four digits are 6767, valid */
        }

        /* Laser Debit Card (Ireland), 16 to 19 digits in length, Luhn Algorithm in use */

        else if (cc_digits[0] == '6' && cc_digits[1] == '3' && cc_digits[2] == '0' && cc_digits[3] == '4')
        {
            cli_dbgmsg("dlp_is_valid_dc: Laser Debit Card (%s)\n", cc_digits);
            return 1;   /* first four digits are 6304, valid */
        }
        else if (cc_digits[0] == '6' && cc_digits[1] == '7' && cc_digits[2] == '0' && cc_digits[3] == '6')
        {
            cli_dbgmsg("dlp_is_valid_dc: Laser Debit Card (%s)\n", cc_digits);
            return 1;   /* first four digits are 6706, valid */
        }
        else if (cc_digits[0] == '6' && cc_digits[1] == '7' && cc_digits[2] == '7' && cc_digits[3] == '1')
        {
            cli_dbgmsg("dlp_is_valid_dc: Laser Debit Card (%s)\n", cc_digits);
            return 1;   /* first four digits are 6771, valid */
        }
        else if (cc_digits[0] == '6' && cc_digits[1] == '7' && cc_digits[2] == '0' && cc_digits[3] == '9')
        {
            cli_dbgmsg("dlp_is_valid_dc: Laser Debit Card (%s)\n", cc_digits);
            return 1;   /* first four digits are 6709, valid */
        }
    }       /* end if digits > 16 and <= 19 */
    else if (digits == 14) /* Diners Club */
    {
	if (cc_digits[0] == '3' && (cc_digits[1] == '6' || cc_digits[1] == '8'))
	{
            cli_dbgmsg("dlp_is_valid_cc: Diners Club International (%s)\n", cc_digits);
            return 1;   /* first two digits are 36 or 38, valid */
        }
	else if (cc_digits[0] == '3' && cc_digits[1] == '0')
        {
            val = cc_digits[2] - '0';
            if (val >= 0 && val <= 5) {
                cli_dbgmsg("dlp_is_valid_cc: Diners Club Carte Blanche (%s)\n", cc_digits);
                return 1;   /* first two digits are 35, 3rd digit is 0 to 5, valid */
            }
        }
    }       /* end else if digits == 14 */
 
    return 0;   /* credit card or debit card number is not valid */
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

/*  The program below checks for the instances of where a   */
/*  Canadian Bank Routing Number or EFT is found, or if a   */
/*  U.S. MICR Bank Routing Number is encountered.           */

/*  Author: Bill Parker                                     */
/*  Date:   February 17, 2013                               */
/*  Last Modified: February 25, 2013                        */

/*  Purpose: To provide Snort and ClamAV the ability to     */
/*  detect canadian and U.S. bank routing transaction       */
/*  numbers via the DLP module in ClamAV or the SDF pre-    */
/*  processor in the Snort IDS.                             */


/*  Are first three or last three digits a valid bank code  */
int is_bank_code_valid(int bank_code)
{
    switch (bank_code) {
        case 1:     return 1;    /*  Bank of Montreal    */
        case 2:     return 1;    /*  Bank of Nova Scotia */
        case 3:     return 1;    /*  Royal Bank of Canada    */
        case 4:     return 1;    /*  Toronto-Dominion Bank   */
        case 6:     return 1;    /*  National Bank of Canada */
        case 10:    return 1;    /*  Canadian Imperial Bank of Commerce  */
        case 16:    return 1;    /*  HSBC Canada */
        case 30:    return 1;    /*  Canadian Western Bank   */
        case 39:    return 1;    /*  Laurentian Bank of Canada   */
        case 117:   return 1;    /*  Government of Canada    */
        case 127:   return 1;    /*  Canada Post (Money Orders)  */
        case 177:   return 1;    /*  Bank of Canada  */
        case 219:   return 1;    /*  ATB Financial   */
        case 260:   return 1;    /*  Citibank Canada */
        case 290:   return 1;    /*  UBS Bank (Canada)   */
        case 308:   return 1;    /*  Bank of China (Canada)  */
        case 309:   return 1;    /*  Citizens Bank of Canada */
        case 326:   return 1;    /*  President’s Choice Financial    */
        case 338:   return 1;    /*  Canadian Tire Bank  */
        case 340:   return 1;    /*  ICICI Bank Canada   */
        case 509:   return 1;    /*  Canada Trust    */
        case 540:   return 1;    /*  Manulife Bank   */
        case 614:   return 1;    /*  ING Direct Canada   */
        case 809:   return 1;    /*  Central 1 [Credit Union] – BC Region    */
        case 815:   return 1;    /*  Caisses Desjardins du Québec    */
        case 819:   return 1;    /*  Caisses populaires Desjardins du Manitoba   */
        case 828:   return 1;    /*  Central 1 [Credit Union] – ON Region    */
        case 829:   return 1;    /*  Caisses populaires Desjardins de l’Ontario  */
        case 837:   return 1;    /*  Meridian Credit Union   */
        case 839:   return 1;    /*  Credit Union Heritage (Nova Scotia) */
        case 865:   return 1;    /*  Caisses populaires Desjardins acadiennes */
        case 879:   return 1;    /*  Credit Union Central of Manitoba    */
        case 889:   return 1;    /*  Credit Union Central of Saskatchewan    */
        case 899:   return 1;    /*  Credit Union Central Alberta    */
        case 900:   return 1;    /*  Unknown???  */
        default:    return 0;    /*  NO MATCH...FAIL */
    }   /*  end if switch(bank_code)    */

    return 0;
}       /*  end function is_bank_code_valid()   */

/*  This function checks if the supplied string is a valid  */
/*  canadian transit number, the format is as follows:      */

/*  XXXXX-YYY where XXXXX is a branch number, and YYY is    */
/*  the institutional number.                               */

/*  note: it does NOT appear that the canadian RTN or EFT   */
/*  number formats contain any type of checksum algorithm   */
/*  or a check digit.                                       */
int cdn_ctn_is_valid(const char *buffer, int length)
{
    int i;
    int bank_code = 0;          /*  last three digits of Canada RTN/MICR is Bank I.D.   */

    if (buffer == NULL || length < 9)   /* if the buffer is empty or  */
        return 0;                       /* the length is less than 9, it's not valid    */

    if (buffer[5] != '-') return 0;     /* if the 6th char isn't a '-', not a valid RTN */

    for (i = 0; i < 5; i++)
        if (isdigit(buffer[i]) == 0)
            return 0;

    /*  Check the various branch codes which are listed, but there  */
    /*  may be more valid codes which could be added as well...     */

    /*  convert last three elements in buffer to a numeric value    */

    for (i = 6; i < 9; i++) {
        if (isdigit(buffer[i]) == 0)
            return 0;
        bank_code = (bank_code * 10) + (buffer[i] - '0');
    }

    /* now have a switch sandwich for bank codes    */
    return(is_bank_code_valid(bank_code));  /*  return 1 if valid, 0 if not */
}

/*  If the string is a canadian EFT (Electronic Fund        */
/*  Transaction), the format is as follows:                 */

/*  0YYYXXXX, where a leading zero is required, XXXXX is a  */
/*  branch number, and YYY is the institution number.       */

/*  note: it does NOT appear that the canadian RTN or EFT   */
/*  number formats contain any type of checksum algorithm   */
/*  or a check digit.                                       */

int cdn_eft_is_valid(const char *buffer, int length)
{
    int bank_code = 0;
    int i;

    if (buffer == NULL || length < 9)   /* if the buffer is empty or  */
        return 0;                       /* the length is less than 9, it's not valid    */

    if (buffer[0] != '0') return 0;     /* if the 1st char isn't a '0', not a valid EFT */

    for (i = 1; i < 4; i++)
    {
        if (isdigit(buffer[i]) == 0)
            return 0;
        bank_code = (bank_code * 10) + (buffer[i] - '0');
    }

    /*  Check the various branch codes which are listed, but there  */
    /*  may be more valid codes which could be added as well...     */
    if (!is_bank_code_valid(bank_code))
        return 0;

    for(i = 4; i < 9; i++)
        if (isdigit(buffer[i]) == 0)
            return 0;

    return 1;
}

int us_micr_is_valid(const char *buffer, int length)
{
    int result, sum, sum1, sum2, sum3;
    int i;
    unsigned char micr_digits[9];

    if (buffer == NULL || length < 9)   /* if the buffer is empty or    */
        return 0;                       /* the length is < 9, it's not valid    */

    /* loop and make sure all the characters are actually digits    */

    for (i = 0; i < 9; i++)
    {
        if (isdigit(buffer[i]) == 0)
            return 0;
        micr_digits[i] = buffer[i];
    }

    /*  see if we have a valid MICR number via the following formula */

    /*  7 * (micr_digits[0] + micr_digits[3] + micr_digits[6]) +    */
    /*  3 * (micr_digits[1] + micr_digits[4] + micr_digits[7]) +    */
    /*  9 * (micr_digits[2] + micr_digits[5]) (the check digit is   */
    /*  computed by the sum above modulus 10                        */

    sum1 = 7 * ((micr_digits[0] - '0') + (micr_digits[3] - '0') + (micr_digits[6] - '0'));
    sum2 = 3 * ((micr_digits[1] - '0') + (micr_digits[4] - '0') + (micr_digits[7] - '0'));
    sum3 = 9 * ((micr_digits[2] - '0') + (micr_digits[5] - '0'));
    sum = sum1 + sum2 + sum3;
    result = sum % 10;

    if (result == (micr_digits[8] - '0'))
        return 1;   /* last digit of MICR matches result    */
    return 0;       /* MICR number isn't valid  */
}
