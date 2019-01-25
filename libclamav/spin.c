/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Alberto Wu
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

/*
** spin.c
** 
** 19/07/2k5 - Finally started coding something
** 21/07/2k5 - Works, started clearing the mess
** 31/07/2k5 - Porting to libclamav
*/

/*
** Unpacks pespin v1.1
**
** Funny thing to reverse
**
** [ A big fat thank to christoph for not letting me give up ]
*/

/*
** TODO ( a fat one ):
**
** OEP restore and unhijacking
** code redir handling (at least near OEP)
** passwd protection (didn't really look at it)
**
** All this stuff really needs a way better emu and a hell of unlaming
** ATM not worth the effort... and pespin v1.3 is out :@
**
*/

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdlib.h>
#include <string.h>

#include "clamav.h"
#include "pe.h"
#include "rebuildpe.h"
#include "execs.h"
#include "others.h"
#include "packlibs.h"
#include "spin.h"

static char exec86(uint8_t aelle, uint8_t cielle, char *curremu, int *retval)
{
    int len = 0;
    *retval = 0;
    while (len < 0x24)
    {
        uint8_t opcode = curremu[len], support;
        len++;
        switch (opcode)
        {
        case 0xeb:
            len++;
        case 0x0a:
            len++;
        case 0x90:
        case 0xf8:
        case 0xf9:
            break;

        case 0x02: /* add al, cl */
            aelle += cielle;
            len++;
            break;
        case 0x2a: /* sub al, cl */
            aelle -= cielle;
            len++;
            break;
        case 0x04: /* add al, ?? */
            aelle += curremu[len];
            len++;
            break;
        case 0x2c: /* sub al, ?? */
            aelle -= curremu[len];
            len++;
            break;
        case 0x32: /* xor al, cl */
            aelle ^= cielle;
            len++;
            break;
        case 0x34: /* xor al, ?? */
            aelle ^= curremu[len];
            len++;
            break;

        case 0xfe: /* inc/dec al */
            if (curremu[len] == '\xc0')
                aelle++;
            else
                aelle--;
            len++;
            break;

        case 0xc0: /* ror/rol al, ?? */
            support = curremu[len];
            len++;
            if (support == 0xc0)
                CLI_ROL(aelle, curremu[len]);
            else
                CLI_ROR(aelle, curremu[len]);
            len++;
            break;

        default:
            cli_dbgmsg("spin: bogus opcode %x\n", opcode);
            *retval = 1;
            return aelle;
        }
    }
    if (len != 0x24 || curremu[len] != '\xaa')
    {
        cli_dbgmsg("spin: bad emucode\n");
        *retval = 1;
    }
    return aelle;
}

static uint32_t summit(char *src, int size)
{
    uint32_t eax = 0xffffffff, ebx = 0xffffffff;
    int i;

    while (size)
    {
        eax ^= *src++ << 8 & 0xff00;
        eax = eax >> 3 & 0x1fffffff;
        for (i = 0; i < 4; i++)
        {
            uint32_t swap;
            eax ^= ebx >> 8 & 0xff;
            eax += 0x7801a108;
            eax ^= ebx;
            CLI_ROR(eax, ebx & 0xff);
            swap = eax;
            eax = ebx;
            ebx = swap;
        }
        size--;
    }
    return ebx;
}

int unspin(char *src, int ssize, struct cli_exe_section *sections, int sectcnt, uint32_t nep, int desc, cli_ctx *ctx)
{
    char *curr, *emu, *ep, *spinned;
    char **sects;
    int blobsz = 0, j;
    uint32_t key32, bitmap, bitman;
    uint32_t len;
    uint8_t key8;

    cli_dbgmsg("in unspin\n");

    if ((spinned = (char *)cli_malloc(sections[sectcnt].rsz)) == NULL)
    {
        cli_dbgmsg("spin: Unable to allocate memory for spinned\n");
        return 1;
    }

    memcpy(spinned, src + sections[sectcnt].raw, sections[sectcnt].rsz);
    ep = spinned + nep - sections[sectcnt].rva;

    curr = ep + 0xdb;
    if (*curr != '\xbb')
    {
        free(spinned);
        cli_dbgmsg("spin: Not spinned or bad version\n");
        return 1;
    }

    key8 = (uint8_t) * ++curr;
    curr += 4;
    if (*curr != '\xb9')
    {
        free(spinned);
        cli_dbgmsg("spin: Not spinned or bad version\n");
        return 1;
    }

    if ((len = cli_readint32(curr + 1)) != 0x11fe)
    {
        free(spinned);
        cli_dbgmsg("spin: Not spinned or bad version\n");
        return 1;
    }

    cli_dbgmsg("spin: Key8 is %x, Len is %x\n", key8, len);

    if (!CLI_ISCONTAINED(spinned, sections[sectcnt].rsz, ep, len + 0x1fe5 - 1))
    {
        free(spinned);
        cli_dbgmsg("spin: len out of bounds, giving up\n");
        return 1;
    }

    if (ep[0x1e0] != '\xb8')
        cli_dbgmsg("spin: prolly not spinned, expect failure\n");

    if ((cli_readint32(ep + 0x1e1) & 0x00200000))
        cli_dbgmsg("spin: password protected, expect failure\n");

    curr = ep + 0x1fe5 + len - 1;
    while (len--)
    {
        *curr = (*curr) ^ (key8--);
        curr--;
    }

    if (!CLI_ISCONTAINED(spinned, sections[sectcnt].rsz, ep + 0x3217, 4))
    {
        free(spinned);
        cli_dbgmsg("spin: key out of bounds, giving up\n");
        return 1;
    }

    curr = ep + 0x26eb;
    key32 = cli_readint32(curr);
    if ((len = cli_readint32(curr + 5)) != 0x5a0)
    {
        free(spinned);
        cli_dbgmsg("spin: Not spinned or bad version\n");
        return 1;
    }

    curr = ep + 0x2d5;
    cli_dbgmsg("spin: Key is %x, Len is %x\n", key32, len);

    while (len--)
    {
        if (key32 & 1)
        {
            key32 = key32 >> 1;
            key32 ^= 0x8c328834;
        }
        else
        {
            key32 = key32 >> 1;
        }
        *curr = *curr ^ (key32 & 0xff);
        curr++;
    }

    len = ssize - cli_readint32(ep + 0x429); /* sub size, value */
    if (len >= (uint32_t)ssize)
    {
        free(spinned);
        cli_dbgmsg("spin: crc out of bounds, giving up\n");
        return 1;
    }
    key32 = cli_readint32(ep + 0x3217) - summit(src, len);

    memcpy(src + sections[sectcnt].raw, spinned, sections[sectcnt].rsz);
    free(spinned);                                                  /* done CRC'ing - can have a dirty buffer now */
    ep = src + nep + sections[sectcnt].raw - sections[sectcnt].rva; /* Fix the helper */

    if (!CLI_ISCONTAINED(src, ssize, ep + 0x3207, 4))
    { /* this one holds all ep based checks */
        cli_dbgmsg("spin: key out of bounds, giving up\n");
        return 1;
    }
    bitmap = cli_readint32(ep + 0x3207);
    cli_dbgmsg("spin: Key32 is %x - XORbitmap is %x\n", key32, bitmap);

    cli_dbgmsg("spin: Decrypting sects (xor)\n");
    for (j = 0; j < sectcnt; j++)
    {

        if (bitmap & 1)
        {
            uint32_t size = sections[j].rsz;
            char *ptr = src + sections[j].raw;
            uint32_t keydup = key32;

            if (!CLI_ISCONTAINED(src, ssize, ptr, size))
            {
                cli_dbgmsg("spin: sect %d out of file, giving up\n", j);
                return 1; /* FIXME: Already checked in pe.c? */
            }

            while (size--)
            {
                if (!(keydup & 1))
                {
                    keydup = keydup >> 1;
                    keydup ^= 0xed43af31;
                }
                else
                {
                    keydup = keydup >> 1;
                }
                *ptr = *ptr ^ (keydup & 0xff);
                ptr++;
            }
        }
        bitmap = bitmap >> 1;
    }

    cli_dbgmsg("spin: done\n");

    curr = ep + 0x644;
    if ((len = cli_readint32(curr)) != 0x180)
    {
        cli_dbgmsg("spin: Not spinned or bad version\n");
        return 1;
    }

    key32 = cli_readint32(curr + 0x0c);
    cli_dbgmsg("spin: Key is %x, Len is %x\n", key32, len);
    curr = ep + 0x28d3;

    if (!CLI_ISCONTAINED(src, ssize, curr, len))
    { /* always true but i may decide to remove the previous check */
        cli_dbgmsg("spin: key out of bounds, giving up\n");
        return 1;
    }
    while (len--)
    {
        if (key32 & 1)
        {
            key32 = key32 >> 1;
            key32 ^= 0xed43af32;
        }
        else
        {
            key32 = key32 >> 1;
        }
        *curr = *curr ^ (key32 & 0xff);
        curr++;
    }

    curr = ep + 0x28dd;
    if ((len = cli_readint32(curr)) != 0x1a1)
    {
        cli_dbgmsg("spin: Not spinned or bad version\n");
        return 1;
    }

    cli_dbgmsg("spin: POLY1 len is %x\n", len);
    curr += 0xf; /* POLY1 */
    emu = ep + 0x6d4;
    if (!CLI_ISCONTAINED(src, ssize, emu, len))
    {
        cli_dbgmsg("spin: poly1 out of bounds\n");
        return 1;
    }
    while (len)
    {
        int xcfailure = 0;
        *emu = exec86(*emu, len-- & 0xff, curr, &xcfailure); /* unlame POLY1 */
        if (xcfailure)
        {
            cli_dbgmsg("spin: cannot exec poly1\n");
            return 1;
        }
        emu++;
    }

    bitmap = cli_readint32(ep + 0x6f1);
    cli_dbgmsg("spin: POLYbitmap is %x - decrypting sects (poly)\n", bitmap);
    curr = ep + 0x755;

    for (j = 0; j < sectcnt; j++)
    {
        if (bitmap & 1)
        {
            uint32_t notthesamelen = sections[j].rsz;

            emu = src + sections[j].raw;

            if (!CLI_ISCONTAINED(src, ssize, curr, 0x24))
            { /* section bounds already checked twice now */
                cli_dbgmsg("spin: poly1 emucode is out of file?\n");
                return 1;
            }

            while (notthesamelen)
            {
                int xcfailure = 0;
                *emu = exec86(*emu, notthesamelen-- & 0xff, curr, &xcfailure);
                if (xcfailure)
                {
                    cli_dbgmsg("spin: cannot exec section\n");
                    return 1;
                }
                emu++;
            }
        }
        bitmap = bitmap >> 1;
    }

    cli_dbgmsg("spin: done\n");

    bitmap = cli_readint32(ep + 0x3061);
    bitman = bitmap;

    /* FIXMELIMITS: possibly rewrite to use the limits api */
    if (ctx->engine->maxfilesize)
    {
        unsigned long int filesize = 0;

        for (j = 0; j < sectcnt; j++)
        {
            if (bitmap & 1)
            {
                if (filesize > ctx->engine->maxfilesize || sections[j].vsz > ctx->engine->maxfilesize - filesize)
                    return 2;
                filesize += sections[j].vsz;
            }
            bitmap >>= 1;
        }

        bitmap = bitman;
    }

    cli_dbgmsg("spin: Compression bitmap is %x\n", bitmap);
    if ((sects = (char **)cli_malloc(sectcnt * sizeof(char *))) == NULL)
    {
        cli_dbgmsg("spin: malloc(%zu) failed\n", (size_t)sectcnt * sizeof(char *));
        return 1;
    }

    len = 0;
    for (j = 0; j < sectcnt; j++)
    {
        if (bitmap & 1)
        {
            if ((sects[j] = (char *)cli_malloc(sections[j].vsz)) == NULL)
            {
                cli_dbgmsg("spin: malloc(%u) failed\n", sections[j].vsz);
                len = 1;
                break;
            }
            blobsz += sections[j].vsz;
            memset(sects[j], 0, sections[j].vsz);
            cli_dbgmsg("spin: Growing sect%d: was %x will be %x\n", j, sections[j].rsz, sections[j].vsz);
            if (cli_unfsg(src + sections[j].raw, sects[j], sections[j].rsz, sections[j].vsz, NULL, NULL) == -1)
            {
                len++;
                cli_dbgmsg("spin: Unpack failure\n");
            }
        }
        else
        {
            blobsz += sections[j].rsz;
            sects[j] = src + sections[j].raw;
            cli_dbgmsg("spin: Not growing sect%d\n", j);
        }
        bitmap >>= 1;
    }

    cli_dbgmsg("spin: decompression complete\n");

    if (len)
    {
        int t;
        for (t = 0; t < j; t++)
        {
            if (bitman & 1)
                free(sects[t]);
            bitman = bitman >> 1 & 0x7fffffff;
        }
        free(sects);
        return 1;
    }

    key32 = cli_readint32(ep + 0x2fee);
    if (key32)
    {
        /*    len = cli_readint32(ep+0x2fc8); -- Using vsizes instead */

        for (j = 0; j < sectcnt; j++)
        {
            if (sections[j].rva <= key32 && key32 - sections[j].rva < sections[j].vsz && CLI_ISCONTAINED(src + sections[j].raw, sections[j].rsz, src + sections[j].raw, key32 - sections[j].rva))
                break;
        }

        if (j != sectcnt && ((bitman & (1 << j)) == 0))
        { /* FIXME: not really sure either the res sect is lamed or just compressed, but this'll save some major headaches */
            cli_dbgmsg("spin: Resources (sect%d) appear to be compressed\n\tuncompressed offset %x, len %x\n\tcompressed offset %x, len %x\n", j, sections[j].rva, key32 - sections[j].rva, key32, sections[j].vsz - (key32 - sections[j].rva));

            if ((curr = (char *)cli_malloc(sections[j].vsz)) != NULL)
            {
                memcpy(curr, src + sections[j].raw, key32 - sections[j].rva);                           /* Uncompressed part */
                memset(curr + key32 - sections[j].rva, 0, sections[j].vsz - (key32 - sections[j].rva)); /* bzero */
                if (cli_unfsg(src + sections[j].raw + key32 - sections[j].rva, curr + key32 - sections[j].rva, sections[j].rsz - (key32 - sections[j].rva), sections[j].vsz - (key32 - sections[j].rva), NULL, NULL))
                {

                    free(curr);
                    cli_dbgmsg("spin: Failed to grow resources, continuing anyway\n");
                    blobsz += sections[j].rsz;
                }
                else
                {
                    sects[j] = curr;
                    bitman |= 1 << j;
                    cli_dbgmsg("spin: Resources grown\n");
                    blobsz += sections[j].vsz;
                }
            }
            else
            {
                /* malloc failed but i'm too deep into this crap to quit without leaking more :( */
                cli_dbgmsg("spin: memory allocation failed, continuing anyway\n");
                blobsz += sections[j].rsz;
            }
        }
        else
        {
            cli_dbgmsg("spin: No res?!\n");
        }
    }

    bitmap = bitman; /* save as a free() bitmap */

    if ((ep = (char *)cli_malloc(blobsz)) != NULL)
    {
        struct cli_exe_section *rebhlp;
        if ((rebhlp = (struct cli_exe_section *)cli_malloc(sizeof(struct cli_exe_section) * (sectcnt))) != NULL)
        {
            char *to = ep;
            int retval = 0;

            for (j = 0; j < sectcnt; j++)
            {
                rebhlp[j].raw = (j > 0) ? (rebhlp[j - 1].raw + rebhlp[j - 1].rsz) : 0;
                rebhlp[j].rsz = (bitmap & 1) ? sections[j].vsz : sections[j].rsz;
                rebhlp[j].rva = sections[j].rva;
                rebhlp[j].vsz = sections[j].vsz;

                memcpy(to, sects[j], rebhlp[j].rsz);
                to += rebhlp[j].rsz;
                if (bitmap & 1)
                    free(sects[j]);
                bitmap = bitmap >> 1;
            }

            if (!cli_rebuildpe(ep, rebhlp, sectcnt, 0x400000, 0x1000, 0, 0, desc))
            { /* can't be bothered fixing those values: the rebuilt exe is completely broken anyway. */
                cli_dbgmsg("spin: Cannot write unpacked file\n");
                retval = 1;
            }
            free(rebhlp);
            free(ep);
            free(sects);
            return retval;
        }
        free(ep);
    }

    cli_dbgmsg("spin: free bitmap is %x\n", bitman);
    for (j = 0; j < sectcnt; j++)
    {
        if (bitmap & 1)
            free(sects[j]);
        bitman = bitman >> 1 & 0x7fffffff;
    }
    free(sects);
    return 1; /* :( */
}
