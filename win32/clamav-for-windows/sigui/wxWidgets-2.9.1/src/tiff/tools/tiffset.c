/******************************************************************************
 * $Id$
 *
 * Project:  libtiff tools
 * Purpose:  Mainline for setting metadata in existing TIFF files.
 * Author:   Frank Warmerdam, warmerdam@pobox.com
 *
 ******************************************************************************
 * Copyright (c) 2000, Frank Warmerdam
 *
 * Permission to use, copy, modify, distribute, and sell this software and 
 * its documentation for any purpose is hereby granted without fee, provided
 * that (i) the above copyright notices and this permission notice appear in
 * all copies of the software and related documentation, and (ii) the names of
 * Sam Leffler and Silicon Graphics may not be used in any advertising or
 * publicity relating to the software without the specific, prior written
 * permission of Sam Leffler and Silicon Graphics.
 * 
 * THE SOFTWARE IS PROVIDED "AS-IS" AND WITHOUT WARRANTY OF ANY KIND, 
 * EXPRESS, IMPLIED OR OTHERWISE, INCLUDING WITHOUT LIMITATION, ANY 
 * WARRANTY OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.  
 * 
 * IN NO EVENT SHALL SAM LEFFLER OR SILICON GRAPHICS BE LIABLE FOR
 * ANY SPECIAL, INCIDENTAL, INDIRECT OR CONSEQUENTIAL DAMAGES OF ANY KIND,
 * OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
 * WHETHER OR NOT ADVISED OF THE POSSIBILITY OF DAMAGE, AND ON ANY THEORY OF 
 * LIABILITY, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE 
 * OF THIS SOFTWARE.
 ******************************************************************************
 *
 * $Log: tiffset.c,v $
 * Revision 1.11  2005/09/13 14:13:42  dron
 * Avoid warnings.
 *
 * Revision 1.10  2005/02/24 14:47:11  fwarmerdam
 * Updated header.
 *
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "tiffio.h"

static char* usageMsg[] = {
"usage: tiffset [options] filename",
"where options are:",
" -s <tagname> [count] <value>...   set the tag value",
" -sf <tagname> <filename>  read the tag value from file (for ASCII tags only)",
NULL
};

static void
usage(void)
{
	int i;
	for (i = 0; usageMsg[i]; i++)
		fprintf(stderr, "%s\n", usageMsg[i]);
	exit(-1);
}

static const TIFFFieldInfo *
GetField(TIFF *tiff, const char *tagname)
{
    const TIFFFieldInfo *fip;

    if( atoi(tagname) > 0 )
        fip = TIFFFieldWithTag(tiff, (ttag_t)atoi(tagname));
    else
        fip = TIFFFieldWithName(tiff, tagname);

    if (!fip) {
        fprintf( stderr, "Field name %s not recognised.\n", tagname );
        return (TIFFFieldInfo *)NULL;
    }

    return fip;
}

int
main(int argc, char* argv[])
{
    TIFF *tiff;
    int  arg_index;

    if (argc < 2)
        usage();

    tiff = TIFFOpen(argv[argc-1], "r+");
    if (tiff == NULL)
        return 2;

    for( arg_index = 1; arg_index < argc-1; arg_index++ ) {
        if (strcmp(argv[arg_index],"-s") == 0 && arg_index < argc-3) {
            const TIFFFieldInfo *fip;
            const char *tagname;

            arg_index++;
            tagname = argv[arg_index];
            fip = GetField(tiff, tagname);

            if (!fip)
                return 3;

            arg_index++;
            if (fip->field_type == TIFF_ASCII) {
                if (TIFFSetField(tiff, fip->field_tag, argv[arg_index]) != 1)
                    fprintf( stderr, "Failed to set %s=%s\n",
                             fip->field_name, argv[arg_index] );
            } else if (fip->field_writecount > 0) {
                int     ret = 1;
                short   wc;

                if (fip->field_writecount == TIFF_VARIABLE)
                        wc = atoi(argv[arg_index++]);
                else
                        wc = fip->field_writecount;

                if (argc - arg_index < wc) {
                    fprintf( stderr,
                             "Number of tag values is not enough. "
                             "Expected %d values for %s tag, got %d\n",
                             wc, fip->field_name, argc - arg_index);
                    return 4;
                }
                    
                if (wc > 1) {
                        int     i, size;
                        void    *array;

                        switch (fip->field_type) {
                                /*
                                 * XXX: We can't use TIFFDataWidth()
                                 * to determine the space needed to store
                                 * the value. For TIFF_RATIONAL values
                                 * TIFFDataWidth() returns 8, but we use 4-byte
                                 * float to represent rationals.
                                 */
                                case TIFF_BYTE:
                                case TIFF_ASCII:
                                case TIFF_SBYTE:
                                case TIFF_UNDEFINED:
				default:
                                    size = 1;
                                    break;

                                case TIFF_SHORT:
                                case TIFF_SSHORT:
                                    size = 2;
                                    break;

                                case TIFF_LONG:
                                case TIFF_SLONG:
                                case TIFF_FLOAT:
                                case TIFF_IFD:
                                case TIFF_RATIONAL:
                                case TIFF_SRATIONAL:
                                    size = 4;
                                    break;

                                case TIFF_DOUBLE:
                                    size = 8;
                                    break;
                        }

                        array = _TIFFmalloc(wc * size);
                        if (!array) {
                                fprintf(stderr, "No space for %s tag\n",
                                        tagname);
                                return 4;
                        }

                        switch (fip->field_type) {
                            case TIFF_BYTE:
                                for (i = 0; i < wc; i++)
                                    ((uint8 *)array)[i] = atoi(argv[arg_index+i]);
                                break;
                            case TIFF_SHORT:
                                for (i = 0; i < wc; i++)
                                    ((uint16 *)array)[i] = atoi(argv[arg_index+i]);
                                break;
                            case TIFF_SBYTE:
                                for (i = 0; i < wc; i++)
                                    ((int8 *)array)[i] = atoi(argv[arg_index+i]);
                                break;
                            case TIFF_SSHORT:
                                for (i = 0; i < wc; i++)
                                    ((int16 *)array)[i] = atoi(argv[arg_index+i]);
                                break;
                            case TIFF_LONG:
                                for (i = 0; i < wc; i++)
                                    ((uint32 *)array)[i] = atol(argv[arg_index+i]);
                                break;
                            case TIFF_SLONG:
                            case TIFF_IFD:
                                for (i = 0; i < wc; i++)
                                    ((uint32 *)array)[i] = atol(argv[arg_index+i]);
                                break;
                            case TIFF_DOUBLE:
                                for (i = 0; i < wc; i++)
                                    ((double *)array)[i] = atof(argv[arg_index+i]);
                                break;
                            case TIFF_RATIONAL:
                            case TIFF_SRATIONAL:
                            case TIFF_FLOAT:
                                for (i = 0; i < wc; i++)
                                    ((float *)array)[i] = (float)atof(argv[arg_index+i]);
                                break;
                            default:
                                break;
                        }
                
                        if (fip->field_passcount) {
                                ret = TIFFSetField(tiff, fip->field_tag,
                                                   wc, array);
                        } else {
                                ret = TIFFSetField(tiff, fip->field_tag,
                                                   array);
                        }

                        _TIFFfree(array);
                } else {
                        switch (fip->field_type) {
                            case TIFF_BYTE:
                            case TIFF_SHORT:
                            case TIFF_SBYTE:
                            case TIFF_SSHORT:
                                ret = TIFFSetField(tiff, fip->field_tag,
                                                   atoi(argv[arg_index++]));
                                break;
                            case TIFF_LONG:
                            case TIFF_SLONG:
                            case TIFF_IFD:
                                ret = TIFFSetField(tiff, fip->field_tag,
                                                   atol(argv[arg_index++]));
                                break;
                            case TIFF_DOUBLE:
                                ret = TIFFSetField(tiff, fip->field_tag,
                                                   atof(argv[arg_index++]));
                                break;
                            case TIFF_RATIONAL:
                            case TIFF_SRATIONAL:
                            case TIFF_FLOAT:
                                ret = TIFFSetField(tiff, fip->field_tag,
                                                   (float)atof(argv[arg_index++]));
                                break;
                            default:
                                break;
                        }
                }

                if (ret != 1)
                    fprintf(stderr, "Failed to set %s\n", fip->field_name);
                arg_index += wc;
            }
        } else if (strcmp(argv[arg_index],"-sf") == 0 && arg_index < argc-3) {
            FILE    *fp;
            const TIFFFieldInfo *fip;
            char    *text;
            int     len;

            arg_index++;
            fip = GetField(tiff, argv[arg_index]);

            if (!fip)
                return 3;

            if (fip->field_type != TIFF_ASCII) {
                fprintf( stderr,
                         "Only ASCII tags can be set from file. "
                         "%s is not ASCII tag.\n", fip->field_name );
                return 5;
            }

            arg_index++;
            fp = fopen( argv[arg_index], "rt" );
            if(fp == NULL) {
                perror( argv[arg_index] );
                continue;
            }

            text = (char *) malloc(1000000);
            len = fread( text, 1, 999999, fp );
            text[len] = '\0';

            fclose( fp );

            if(TIFFSetField( tiff, fip->field_tag, text ) != 1) {
                fprintf(stderr, "Failed to set %s from file %s\n", 
                        fip->field_name, argv[arg_index]);
            }

            _TIFFfree( text );
            arg_index++;
        } else {
            fprintf(stderr, "Unrecognised option: %s\n",
                    argv[arg_index]);
            usage();
        }
    }

    TIFFRewriteDirectory(tiff);
    TIFFClose(tiff);
    return 0;
}

/* vim: set ts=8 sts=8 sw=8 noet: */
