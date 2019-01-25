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

#define IIN_SIZE 6
#define MAX_CC_BREAKS 8

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
  Following is a table of payment card "issuer identification number" ranges
  and additional info such as card number length.
*/

struct iin_map_struct {
    uint32_t iin_start;
    uint32_t iin_end;
    uint8_t card_len;
    uint8_t luhn;
    const char* iin_name;
};

/* Maestro card range, 550000-699999, encompasses ranges
   of several other cards including Discover and UnionPay.
*/

static struct iin_map_struct iin_map[] = {
    {100000, 199999, 15, 1, "UATP"},
    {300000, 305999, 14, 1, "Diner's Club - Carte Blanche"},
    {309500, 309599, 14, 1, "Diner's Club International"},
    {340000, 349999, 15, 1, "American Express"},
    {352800, 358999, 16, 1, "JCB"},
    {360000, 369999, 14, 1, "Diner's Club International"},
    {370000, 379999, 15, 1, "American Express"},
    {380000, 399999, 16, 1, "Diner's Club International"},
    {400000, 499999, 16, 1, "Visa"},
    {500000, 509999, 16, 1, "Maestro"},
    {510000, 559999, 16, 1, "Master Card"},
    {560000, 699999, 16, 1, "Maestro/Discover/UnionPay/etc."},
    {0}
};

/* Fixme: some card ranges can have lengths other than 16 */

static const struct iin_map_struct * get_iin(char * digits)
{
    int iin = atoi(digits);
    int i = 0;

    while (iin_map[i].iin_start != 0) {
        if (iin < iin_map[i].iin_start)
            break;
        if (iin <= iin_map[i].iin_end) {
            cli_dbgmsg("Credit card IIN %s matched range for %s\n", digits, iin_map[i].iin_name);
            return &iin_map[i];
        }
        i++;
    }
    cli_dbgmsg("Credit card %s did not match an IIN range\n", digits);
    return NULL;
}

int dlp_is_valid_cc(const unsigned char *buffer, int length)
{
    int mult = 0;
    int sum = 0;
    int i = 0;
    int val = 0;
    int digits = 0;
    char cc_digits[20];
    int pad_allowance = MAX_CC_BREAKS;
    const struct iin_map_struct * iin;
    int need;
    
    if(buffer == NULL || length < 13)
        return 0;
    /* if the first digit is greater than 6 it isn't one of the major
     * credit cards
     * reference => http://www.beachnet.com/~hstiles/cardtype.html
     */
    if(!isdigit(buffer[0]) || buffer[0] > '6' || buffer[0] == 2)
        return 0;

    if(length > 19 + pad_allowance)     /* max credit card length is 19, with allowance for punctuation */
        length = 19 + pad_allowance;

    /* Look for possible 6 digit IIN */
    for(i = 0; i < length && digits < IIN_SIZE; i++) {
	if(isdigit(buffer[i]) == 0) {
            if(buffer[i] == ' ' || buffer[i] == '-')
                if (pad_allowance-- > 0)
                    continue;
            break;
	}
	cc_digits[digits] = buffer[i];
	digits++;
    }

    if (digits == IIN_SIZE)
        cc_digits[digits] = 0;
    else 
        return 0;

    /* See if it is a valid IIN. */ 
    iin = get_iin(cc_digits);
    if (iin == NULL)
         return 0;

    /* Look for the remaining needed digits. */
    for (/*same 'i' from previous for-loop*/; i < length && digits < iin->card_len; i++) {
	if(isdigit(buffer[i]) == 0) {
            if(buffer[i] == ' ' || buffer[i] == '-')
                if (pad_allowance-- > 0)
                    continue;
            break;
	}
	cc_digits[digits] = buffer[i];
        digits++;
    }

    // should be !isdigit(buffer[i]) ?
    if(digits < 13 || (i < length && isdigit(buffer[i])))
	return 0;

    //figure out luhn digits 
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

    cli_dbgmsg("Luhn algorithm successful for %s\n", cc_digits);

    return 1;
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
