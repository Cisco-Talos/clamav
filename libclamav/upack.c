/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Michal 'GiM' Spadlinski
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
#ifdef        HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef        HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef        HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef        HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef        HAVE_STRING_H
#include <string.h>
#endif

#include "clamav.h"
#include "pe.h"
#include "rebuildpe.h"
#include "others.h"
#include "upack.h"
#include "mew.h"

#define EC32(x) le32_to_host(x) /* Convert little endian to host */
#define CE32(x) be32_to_host(x) /* Convert big endian to host */

int unupack399(char *, uint32_t, uint32_t, char *, uint32_t, char *, char *, uint32_t, char *);

enum { UPACK_399, UPACK_11_12, UPACK_0151477, UPACK_0297729 };

int unupack(int upack, char *dest, uint32_t dsize, char *buff, uint32_t vma, uint32_t ep, uint32_t base, uint32_t va, int file)
{
	int j, searchval;
	char *loc_esi = NULL, *loc_edi = NULL, *loc_ebx = NULL, *end_edi = NULL, *save_edi = NULL, *alvalue = NULL;
	char *paddr = NULL, *pushed_esi = NULL, *save2 = NULL;
	uint32_t save1, save3, loc_ecx, count, shlsize, original_ep, ret, loc_ebx_u;
	struct cli_exe_section section;
	int upack_version = UPACK_399;

	/* buff [168 bytes] doesn't have to be checked, since it was checked in pe.c */
	if (upack)
	{
		uint32_t aljump, shroff, lngjmpoff;

		/* dummy characteristics ;/ */
		if (buff[5] == '\xff' && buff[6] == '\x36')
			upack_version = UPACK_0297729;
		loc_esi = dest + (cli_readint32(buff + 1) -  vma);

		if (!CLI_ISCONTAINED(dest, dsize, loc_esi, 12))
			return -1;
		original_ep = cli_readint32(loc_esi);
		loc_esi += 4;
		/*cli_readint32(loc_esi);*/
		loc_esi += 4;

		original_ep -= vma;
		cli_dbgmsg("Upack: EP: %08x original:  %08X || %08x\n", ep, original_ep, cli_readint32(loc_esi-8));

		if (upack_version == UPACK_399)
		{
			/* jmp 1 */
			loc_edi = dest + (cli_readint32(loc_esi) -  vma);
			if (!CLI_ISCONTAINED(dest, dsize, dest+ep+0xa, 2) || dest[ep+0xa] != '\xeb')
				return -1;
			loc_esi = dest + *(dest + ep + 0xb) + ep + 0xc;

			/* use this as a temp var */
			/* jmp 2 + 0xa */
			alvalue = loc_esi+0x1a;
			if (!CLI_ISCONTAINED(dest, dsize, alvalue, 2) || *alvalue != '\xeb')
				return -1;
			alvalue++;
			alvalue += (*alvalue&0xff) + 1 + 0xa;
			lngjmpoff = 8;
		} else {
			if (!CLI_ISCONTAINED(dest, dsize, dest+ep+7, 5) || dest[ep+7] != '\xe9')
				return -1;
			loc_esi = dest + cli_readint32(dest + ep + 8) + ep + 0xc;
			alvalue = loc_esi + 0x25;
			lngjmpoff = 10;
		}

		if (!CLI_ISCONTAINED(dest, dsize, alvalue, 2) || *alvalue != '\xb5')
			return -1;
		alvalue++;
		count = *alvalue&0xff;

		if (!CLI_ISCONTAINED(dest, dsize, alvalue, lngjmpoff+5) || *(alvalue+lngjmpoff) != '\xe9')
			return -1;
		/* use this as a temp to make a long jmp to head of unpacking proc */
		shlsize = cli_readint32(alvalue + lngjmpoff+1);
		/* upack_399 + upack_0151477 */
		if (upack_version == UPACK_399)
			shlsize = shlsize + (loc_esi - dest) + *(loc_esi+0x1b) + 0x1c + 0x018; /* read checked above */
		else
			/* there is no additional jump in upack_0297729 */
			shlsize = shlsize + (loc_esi - dest) + 0x035;
		/* do the jump, 43 - point to jecxz */
		alvalue = dest+shlsize+43;

		/* 0.39 */
		aljump = 8;
		shroff = 24;
		if (!CLI_ISCONTAINED(dest, dsize, alvalue-1, 2) || *(alvalue-1) != '\xe3')
		{
			/* in upack_0297729 and upack_0151477 jecxz is at offset: 46 */
			alvalue = dest+shlsize+46;
			if (!CLI_ISCONTAINED(dest, dsize, alvalue-1, 2) || *(alvalue-1) != '\xe3')
				return -1;
			else {
				if (upack_version != UPACK_0297729)
					upack_version = UPACK_0151477;
				aljump = 7;
				shroff = 26;
			}
			
		}
		/* do jecxz */
		alvalue += (*alvalue&0xff) + 1;
		/* is there a long jump ? */
		if (!CLI_ISCONTAINED(dest, dsize, alvalue, aljump+5) || *(alvalue+aljump) != '\xe9')
			return -1;
		/* do jmp, 1+4 - size of jmp instruction, aljump - instruction offset, 27 offset to cmp al,xx*/
		ret = cli_readint32(alvalue+aljump+1);
		alvalue += ret + aljump+1+4 + 27;
		if (upack_version == UPACK_0297729)
			alvalue += 2;
		/* shr ebp */
		if (!CLI_ISCONTAINED(dest, dsize, dest+shlsize+shroff, 3) || *(dest+shlsize+shroff) != '\xc1' || *(dest+shlsize+shroff+1) != '\xed')
			return -1;
		shlsize = (*(dest + shlsize + shroff+2))&0xff;
		count *= 0x100;
		if (shlsize < 2 || shlsize > 8)
		{
			cli_dbgmsg ("Upack: context bits out of bounds\n");
			return -1;
		}
		cli_dbgmsg("Upack: Context Bits parameter used with lzma: %02x, %02x\n", shlsize, count);
		/* check if loc_esi + .. == 0xbe -> mov esi */
		/* upack_0297729 has mov esi, .. + mov edi, .., in upack_0151477 and upack_399 EDI has been already set before */
		if (upack_version == UPACK_0297729)
		{
			if (!CLI_ISCONTAINED(dest, dsize, loc_esi+6, 10) || *(loc_esi+6) != '\xbe' || *(loc_esi+11) != '\xbf')
				return -1;
			if ((uint32_t)cli_readint32(loc_esi + 7) < base || (uint32_t)cli_readint32(loc_esi+7) > vma)
				return -1;
			loc_edi = dest + (cli_readint32(loc_esi + 12) - vma);
			loc_esi = dest + (cli_readint32(loc_esi + 7) - base);
		} else {
			if (!CLI_ISCONTAINED(dest, dsize, loc_esi+7, 5) || *(loc_esi+7) != '\xbe')
				return -1;
			loc_esi = dest + (cli_readint32(loc_esi + 8) - vma);
		}

		if (upack_version == UPACK_0297729)
		{
			/* 0x16*4=0x58, 6longs*4 = 24, 0x64-last loc_esi read location */
			if (!CLI_ISCONTAINED(dest, dsize, loc_edi, (0x58 + 24 + 4*count)) || !CLI_ISCONTAINED(dest, dsize, loc_esi, (0x58 + 0x64 + 4)))
				return -1;

			/* XXX I don't know if this [0x16] is constant number, not enough samples provided */
			for (j=0; j<0x16; j++, loc_esi+=4, loc_edi+=4)
				cli_writeint32(loc_edi, cli_readint32(loc_esi)); 
		} else {
			/* 0x27*4=0x9c, 6longs*4 = 24, 0x34-last loc_esi read location */
			if (!CLI_ISCONTAINED(dest, dsize, loc_edi, (0x9c + 24 + 4*count)) || !CLI_ISCONTAINED(dest, dsize, loc_esi, (0x9c + 0x34 + 4)))
				return -1;
			for (j=0; j<0x27; j++, loc_esi+=4, loc_edi+=4)
				cli_writeint32(loc_edi, cli_readint32(loc_esi)); 
		}
		save3 = cli_readint32(loc_esi + 4);
		paddr = dest + ((uint32_t)cli_readint32(loc_edi - 4)) - vma;
		loc_ebx = loc_edi;
		cli_writeint32(loc_edi, 0xffffffff);
		loc_edi+=4;
		cli_writeint32(loc_edi, 0);
		loc_edi+=4;
		for (j=0; j<4; j++, loc_edi+=4)
		    cli_writeint32(loc_edi, (1));

		for (j=0; (unsigned int)j<count; j++, loc_edi+=4)
		    cli_writeint32(loc_edi, 0x400);
		
		loc_edi = dest + cli_readint32(loc_esi + 0xc) - vma;
		if (upack_version == UPACK_0297729)
			loc_edi = dest+vma-base; /* XXX not enough samples provided to be sure of it! */

		pushed_esi = loc_edi;
		if (upack_version == UPACK_0297729)
		{
			end_edi = dest + cli_readint32(loc_esi + 0x64) - vma;
			save3 = cli_readint32(loc_esi + 0x40);
		} else {
                        end_edi = dest + cli_readint32(loc_esi + 0x34) - vma;
                }
                if (loc_edi > end_edi) {
                        cli_dbgmsg("Upack: loc_edi > end_edi breaks cli_rebuildpe() bb#11216\n");
                        return -1;
                }
		/* begin end */
		cli_dbgmsg("Upack: data initialized, before upack lzma call!\n");
		if ((ret = (uint32_t)unupack399(dest, dsize, 0, loc_ebx, 0, loc_edi, end_edi, shlsize, paddr)) == 0xffffffff)
			return -1;
	/* alternative begin */
	} else {
		int ep_jmp_offs, rep_stosd_count_offs, context_bits_offs;
		loc_esi = dest + vma + ep;
		/* yet another dummy characteristics ;/ */
		if (buff[0] == '\xbe' && buff[5] == '\xad' && buff[6] == '\x8b' && buff[7] == '\xf8')
			upack_version = UPACK_11_12;

		if (upack_version == UPACK_11_12)
		{
			ep_jmp_offs = 0x1a4;
			rep_stosd_count_offs = 0x1b;
			context_bits_offs = 0x41;
			alvalue = loc_esi + 0x184;
		} else {
			ep_jmp_offs = 0x217;
			rep_stosd_count_offs = 0x3a;
			context_bits_offs = 0x5f;
			alvalue = loc_esi + 0x1c1;
		}

		if (!CLI_ISCONTAINED(dest, dsize, loc_esi, ep_jmp_offs+4))
			return -1;
		save1 = cli_readint32(loc_esi + ep_jmp_offs);
		original_ep = (loc_esi - dest) + ep_jmp_offs + 4;
		original_ep += (int32_t)save1;
		cli_dbgmsg("Upack: EP: %08x original %08x\n", ep, original_ep);

		/* this are really ugly hacks,
		 * rep_stosd_count_offs & context_bits_offs are < ep_jmp_offs,
		 * so checked in CLI_ISCONTAINED above */
		count = (*(loc_esi + rep_stosd_count_offs))&0xff;
		shlsize = (*(loc_esi + context_bits_offs))&0xff;
		shlsize = 8 - shlsize;
		if (shlsize < 2 || shlsize > 8)
		{
			cli_dbgmsg ("Upack: context bits out of bounds\n");
			return -1;
		}
		count *= 0x100;
		cli_dbgmsg("Upack: Context Bits parameter used with lzma: %02x, %02x\n", shlsize, count);
		if (upack_version == UPACK_399)
		{
			loc_esi += 4;
			loc_ecx = cli_readint32(loc_esi+2);
			cli_writeint32(loc_esi+2,0);
			if (!loc_ecx)
			{
				cli_dbgmsg("Upack: something's wrong, report back\n");
				return -1;/* XXX XXX XXX XXX */
			}
			loc_esi -= (loc_ecx - 2);
			if (!CLI_ISCONTAINED(dest, dsize, loc_esi, 12))
				return -1;

			cli_dbgmsg("Upack: %p %p %08x %08x\n", loc_esi, dest, cli_readint32(loc_esi), base);
			loc_ebx_u = loc_esi - (dest + cli_readint32(loc_esi) - base);
			cli_dbgmsg("Upack: EBX: %08x\n", loc_ebx_u);
			loc_esi += 4;
			save2 = loc_edi = dest + cli_readint32(loc_esi) - base;
			cli_dbgmsg("Upack: DEST: %08x, %08x\n", cli_readint32(loc_esi), cli_readint32(loc_esi) - base);
			loc_esi += 4;
			/* 2vGiM: j is signed. Is that really what you want? Will it cause problems with the following checks?
			 * yes! this is wrong! how did you notice that?!
			 */
			j = cli_readint32(loc_esi);
			if (j<0)
			{
				cli_dbgmsg("Upack: probably hand-crafted data, report back\n");
				return -1;
			}
			loc_esi += 4;
			cli_dbgmsg("Upack: ecx counter: %08x\n", j);

			if (((uint64_t)count+j) * 4 > UINT_MAX)
				return -1;
			if (!CLI_ISCONTAINED(dest, dsize, loc_esi, (j*4)) || !CLI_ISCONTAINED(dest, dsize, loc_edi, ((j+count)*4)))
				return -1;
			for (;j--; loc_edi+=4, loc_esi+=4)
				cli_writeint32(loc_edi, cli_readint32(loc_esi));
			if (!CLI_ISCONTAINED(dest, dsize, save2, 8))
				return -1;
			loc_ecx = cli_readint32(save2);
			save2 += 4;
			loc_esi = save2;
			/* I could probably do simple loc_esi+= (0xe<<2),
			 *  but I'm not sure if there is always 0xe and is always ebx =0
			 */
			do {
				loc_esi += loc_ebx_u;
				loc_esi += 4;
			} while (--loc_ecx);
			if (!CLI_ISCONTAINED(dest, dsize, loc_esi, 4))
				return -1;
			save1 = cli_readint32(loc_esi); /* loc_eax = 0x400 */
			loc_esi += 4;

			for (j=0; (uint32_t)j<count; j++, loc_edi+=4) /* checked above */
				cli_writeint32(loc_edi, (save1));

			if (!CLI_ISCONTAINED(dest, dsize, (loc_esi+0x10), 4))
				return -1;
			cli_writeint32(loc_esi+0x10, (uint32_t)cli_readint32(loc_esi+0x10)+loc_ebx_u);
			loc_ebx = loc_esi+0x14;
			loc_esi = save2;
			/* loc_ebx_u gets saved */
			/* checked above, (...save2, 8) */
			save_edi = loc_edi = dest + ((uint32_t)cli_readint32(loc_esi) - base);
			loc_esi +=4;
			cli_dbgmsg("Upack: before_fixing\n");
			/* fix values */
			if (!CLI_ISCONTAINED(dest, dsize, loc_ebx-4, (12 + 4*4)) || !CLI_ISCONTAINED(dest, dsize, loc_esi+0x24, 4) || !CLI_ISCONTAINED(dest, dsize, loc_esi+0x40, 4))
				return -1;
			for (j=2; j<6; j++)
			      cli_writeint32(loc_ebx+(j<<2), cli_readint32(loc_ebx+(j<<2)));
			paddr = dest + cli_readint32(loc_ebx - 4) - base;
			save1 = loc_ecx;
			pushed_esi = loc_edi;
			end_edi = dest + cli_readint32(loc_esi+0x24) - base;
			vma = cli_readint32(loc_ebx); cli_writeint32(loc_ebx, cli_readint32(loc_ebx + 4)); cli_writeint32((loc_ebx + 4), vma);
		/* Upack 1.1/1.2 is something between 0.39 2-section and 0.39 3-section */
		} else if (upack_version == UPACK_11_12) {
			cli_dbgmsg("Upack v 1.1/1.2\n");
			loc_esi = dest + 0x148; /* always constant? */
			loc_edi = dest + cli_readint32(loc_esi) - base; /* read checked above */
			loc_esi += 4;
			save_edi = loc_edi;
			/* movsd */
			paddr = dest + ((uint32_t)cli_readint32(loc_esi)) - base;
			loc_esi += 4;
			loc_edi += 4;
			loc_ebx = loc_edi;
		
			if (((uint64_t)count+6) * 4 > UINT_MAX)
				return -1;
			if (!CLI_ISCONTAINED(dest, dsize, loc_edi, ((6+count)*4)))
				return -1;
			cli_writeint32(loc_edi, 0xffffffff);
			loc_edi += 4;
			cli_writeint32(loc_edi, 0);
			loc_edi += 4;
			for (j=0; j<4; j++, loc_edi+=4)
				cli_writeint32(loc_edi, (1));

			for (j=0; (uint32_t)j<count; j++, loc_edi+=4)
				cli_writeint32(loc_edi, 0x400);
			
			loc_edi = dest + cli_readint32(loc_esi) - base; /* read checked above */
			pushed_esi = loc_edi;
			loc_esi += 4;
			loc_ecx = 0;

			loc_esi += 4;

			end_edi = dest + cli_readint32(loc_esi-0x28) - base; /* read checked above */
			loc_esi = save_edi;
		}
                if (loc_edi > end_edi) {
                        cli_dbgmsg("Upack(alt begin): loc_edi > end_edi breaks cli_rebuildpe() bb#11216\n");
                        return -1;
                }
		cli_dbgmsg("Upack: data initialized, before upack lzma call!\n");
		if ((ret = (uint32_t)unupack399(dest, dsize, loc_ecx, loc_ebx, loc_ecx, loc_edi, end_edi, shlsize, paddr)) == 0xffffffff)
			return -1;
		if (upack_version == UPACK_399)
			save3 = cli_readint32(loc_esi + 0x40);
		else if (upack_version == UPACK_11_12)
			save3 = cli_readint32(dest + vma + ep + 0x174);
	}

	/* let's fix calls */
	loc_ecx = 0;
	if (!CLI_ISCONTAINED(dest, dsize, alvalue, 1)) {
		cli_dbgmsg("Upack: alvalue out of bounds\n");
		return -1;
	}

	searchval = *alvalue&0xff;
	cli_dbgmsg("Upack: loops: %08x search value: %02x\n", save3, searchval);
	while(save3) {
		if (!CLI_ISCONTAINED(dest, dsize, pushed_esi + loc_ecx, 1))
		{
			cli_dbgmsg("Upack: callfixerr %p %08x = %p, %p\n", dest, dsize, dest+dsize, pushed_esi+loc_ecx);
			return -1;
		}
		if (pushed_esi[loc_ecx] == '\xe8' || pushed_esi[loc_ecx] == '\xe9')
		{
			char *adr = (pushed_esi + loc_ecx + 1);
			loc_ecx++;
			if (!CLI_ISCONTAINED(dest, dsize, adr, 4))
			{
				cli_dbgmsg("Upack: callfixerr\n");
				return -1;
			}
			if ((cli_readint32(adr)&0xff) != searchval)
				continue;
			cli_writeint32(adr, EC32(CE32((uint32_t)(cli_readint32(adr)&0xffffff00)))-loc_ecx-4);
			loc_ecx += 4;
			save3--;
		} else 
			loc_ecx++;
	}

	section.raw = 0;
	section.rva = va;
	section.rsz = end_edi-loc_edi;
	section.vsz = end_edi-loc_edi;

	/* bb#11282 - prevent dest+va/dest from passing an invalid dereference to cli_rebuildpe */
	/* check should trigger on broken PE files where the section exists outside of the file */
	if ((!upack && ((va + section.rsz) > dsize)) || (upack && (section.rsz > dsize))) {
		cli_dbgmsg("Upack: Rebuilt section exceeds allocated buffer; breaks cli_rebuildpe() bb#11282\n");
		return 0;
	}

	if (!cli_rebuildpe(dest + (upack?0:va), &section, 1, base, original_ep, 0, 0, file)) {
		cli_dbgmsg("Upack: Rebuilding failed\n");
		return 0;
	}
	return 1;
}


int unupack399(char *bs, uint32_t bl, uint32_t init_eax, char *init_ebx, uint32_t init_ecx, char *init_edi, char *end_edi, uint32_t shlsize, char *paddr)
{
	struct lzmastate p;
	uint32_t loc_eax, ret, loc_al, loc_ecx = init_ecx, loc_ebp, eax_copy = init_eax, temp, i, jakas_kopia;
	uint32_t state[6], temp_ebp;
	char *loc_edx, *loc_ebx = init_ebx, *loc_edi = init_edi, *loc_ebp8, *edi_copy;
	p.p0 = paddr;
	p.p1 = cli_readint32(init_ebx);
	p.p2 = cli_readint32(init_ebx + 4);

	cli_dbgmsg("\n\tp0: %p\n\tp1: %08x\n\tp2: %08x\n", p.p0, p.p1, p.p2);
	for (i = 0; i<6; i++) {
		state[i] = cli_readint32(loc_ebx + (i<<2));
		cli_dbgmsg("state[%d] = %08x\n", i, state[i]);
	}
	do {
		loc_eax = eax_copy;
		loc_edx = loc_ebx + (loc_eax<<2) + 0x58;

		if ((ret = lzma_upack_esi_00(&p, loc_edx, bs, bl)))
		{
			/* loc_483927 */
			loc_al = loc_eax&0xff;
			loc_al = ((loc_al + 0xf9) > 0xff)?(3+8):8;
			loc_eax = (loc_eax&0xffffff00)|(loc_al&0xff);
			loc_ebp = state[2];
			loc_ecx = (loc_ecx&0xffffff00)|0x30;
			loc_edx += loc_ecx;
			/* *(uint32_t *)(loc_ebx + 14) = loc_ebp; ???? */
			if (!(ret = lzma_upack_esi_00(&p, loc_edx, bs, bl))) {
				/* loc_48397c */
				loc_eax--;
				/*
				temp_ebp = loc_ebp; loc_ebp = cli_readint32(loc_ebx+0x0c); cli_writeint32(loc_ebx+0x0c, temp_ebp);
				temp_ebp = loc_ebp; loc_ebp = cli_readint32(loc_ebx+0x10); cli_writeint32(loc_ebx+0x10, temp_ebp);
				*/
				temp_ebp = loc_ebp;
				loc_ebp = state[4];
				state[4] = state[3];
				state[3] = temp_ebp;
				eax_copy = loc_eax;
				loc_edx = loc_ebx + 0xbc0;
				state[5] = loc_ebp;
				if (lzma_upack_esi_54(&p, loc_eax, &loc_ecx, &loc_edx, &temp, bs, bl) == 0xffffffff)
					return -1;
				loc_ecx = 3;
				jakas_kopia = temp;
				loc_eax = temp-1;
				if (loc_eax >= loc_ecx)
					loc_eax = loc_ecx;
				loc_ecx = 0x40;
				loc_eax <<= 6; /* ecx=0x40, mul cl */
				loc_ebp8 = loc_ebx + ((loc_eax<<2) + 0x378);
				if (lzma_upack_esi_50(&p, 1, loc_ecx, &loc_edx, loc_ebp8, &loc_eax, bs, bl) == 0xffffffff)
					return -1;
				loc_ebp = loc_eax;
				if ((loc_eax&0xff) >= 4)
				{
					/* loc_4839af */
					loc_ebp = 2 + (loc_eax&1);
					loc_eax >>= 1;
					loc_eax--;
					temp_ebp = loc_eax; loc_eax = loc_ecx; loc_ecx = temp_ebp;
					loc_ebp <<= (loc_ecx&0xff);
					loc_edx = loc_ebx + (loc_ebp<<2) + 0x178;
					if ((loc_ecx&0xff) > 5)
					{
						/* loc_4839c6 */
						loc_ecx = (loc_ecx&0xffffff00)|(((loc_ecx&0xff)-4)&0xff);
						loc_eax = 0;
						do {
							uint32_t temp_edx;
							/* compare with lzma_upack_esi_00 */
							/* do not put in one statement because of difference in signedness */
							if (!CLI_ISCONTAINED(bs, bl, p.p0, 4))
								return -1;
							temp_edx = cli_readint32((char *)p.p0);
							temp_edx = EC32(CE32(temp_edx));
							p.p1 >>= 1;
							temp_edx -= p.p2;
							loc_eax <<= 1;
							if (temp_edx >= p.p1)
							{
								temp_edx = p.p1;
								loc_eax++;
								p.p2 += temp_edx;
							}
							if(((p.p1)&0xff000000) == 0)
							{
								p.p2 <<= 8;
								p.p1 <<= 8;
								p.p0++;
							}
						} while (--loc_ecx);
						/* loc_4839e8 */
						loc_ecx = (loc_ecx&0xffffff00)|4;
						loc_eax <<= 4;
						loc_ebp += loc_eax;
						loc_edx = loc_ebx + 0x18;
					}
					/* loc4839f1 */
					loc_eax = 1;
					loc_eax <<= (loc_ecx&0xff);
					loc_ebp8 = loc_edx;
					temp_ebp = loc_ecx; loc_ecx = loc_eax; loc_eax = temp_ebp;
					if (lzma_upack_esi_50(&p, 1, loc_ecx, &loc_edx, loc_ebp8, &loc_eax, bs, bl) == 0xffffffff)
						return -1;
					/* cdq, loc_edx = (loc_eax&0x80000000)?0xffffffff:0; */
					loc_ecx = temp_ebp;
					temp_ebp = CLI_SRS((int32_t)loc_eax, 31); /* thx, desp */
					/* loc_483a00 */
					do {
						temp_ebp += temp_ebp;
						temp_ebp += (loc_eax&1);
						loc_eax >>= 1;
					} while (--loc_ecx);
					loc_ebp += temp_ebp;
					/* loc_483a06 */
				}
				/* loc_483a09 */
				loc_ebp++;
				loc_ecx = jakas_kopia;
			} else {
				/* loc_48393a */
				loc_edx += loc_ecx;
				if ((ret = lzma_upack_esi_00(&p, loc_edx, bs, bl))) {
					/* loc_483954 */
					loc_edx += 0x60;
					if ((ret = lzma_upack_esi_00(&p, loc_edx, bs, bl))) {
						/* loc_48395e */
						loc_edx += loc_ecx;
						ret = lzma_upack_esi_00(&p, loc_edx, bs, bl);
						temp_ebp = loc_ebp;
						loc_ebp = state[4];
						state[4] = state[3];
						state[3] = temp_ebp;
						if (ret)
						{
							temp_ebp = loc_ebp; loc_ebp = state[5]; state[5] = temp_ebp;
						}
					} else {
						temp_ebp = loc_ebp; loc_ebp = state[3]; state[3] = temp_ebp;
					}
				} else {
					/* loc_483940 */
					loc_edx += loc_ecx;
					if ((ret = lzma_upack_esi_00(&p, loc_edx, bs, bl))) {
					} else {
						/* loc_483946 */
						loc_eax |= 1;
						eax_copy = loc_eax;
						edi_copy = loc_edi;
						edi_copy -= state[2];
						loc_ecx = (loc_ecx&0xffffff00)|0x80;
						if (!CLI_ISCONTAINED(bs, bl, edi_copy, 1) || !CLI_ISCONTAINED(bs, bl, loc_edi, 1))
							return -1;
						loc_al = (*(uint8_t *)edi_copy)&0xff;
						/* loc_483922 */
						/* ok jmp to 483a19 */
						/* loc_483a19 */
						*loc_edi++ = loc_al;
						continue;
					}
				}
				/* loc_48396a */
				eax_copy = loc_eax;
				loc_edx = loc_ebx + 0x778;
				if (lzma_upack_esi_54(&p, loc_eax, &loc_ecx, &loc_edx, &temp, bs, bl) == 0xffffffff)
					return -1;
				loc_eax = loc_ecx;
				loc_ecx = temp;
			}
			/* loc_483a0b */
			if (!CLI_ISCONTAINED(bs, bl, loc_edi, loc_ecx) || !CLI_ISCONTAINED(bs, bl, loc_edi-loc_ebp, loc_ecx+1))
				return -1;
			state[2] = loc_ebp;
			for (i=0; i<loc_ecx; i++, loc_edi++)
				*loc_edi = *(loc_edi - loc_ebp);
			loc_eax = (loc_eax&0xffffff00)|*(uint8_t *)(loc_edi - loc_ebp);
			loc_ecx = 0x80;
		} else {
			/* loc_4838d8 */
			do {
				if ( (loc_al = (loc_eax&0xff)) + 0xfd > 0xff)
					loc_al -= 3; /* 0x100 - 0xfd = 3 */
				else
					loc_al = 0;
				loc_eax = (loc_eax&0xffffff00)|loc_al;
			} while (loc_al >= 7);
			/* loc_4838e2 */
			eax_copy = loc_eax;
			if (loc_edi > init_edi && loc_edi < bl+bs)
			{
				loc_ebp = (*(uint8_t *)(loc_edi - 1)) >> shlsize;
			} else {
				loc_ebp = 0;
			}
			loc_ebp *= (int)0x300; /* XXX */
			loc_ebp8 = loc_ebx + ((loc_ebp<<2) + 0x1008);
			/* XXX save edi */
			edi_copy = loc_edi;

			loc_eax = (loc_eax&0xffffff00)|1;
			if (loc_ecx) {
				uint8_t loc_cl = loc_ecx&0xff;
				loc_edi -= state[2];
				if (!CLI_ISCONTAINED(bs, bl, loc_edi, 1))
					return -1;
				do {
					loc_eax = (loc_eax&0xffff00ff)|((*loc_edi & loc_cl)?0x200:0x100);

					loc_edx = loc_ebp8 + (loc_eax<<2);
					ret = lzma_upack_esi_00(&p, loc_edx, bs, bl);
					loc_al = loc_eax&0xff;
					loc_al += loc_al;
					loc_al += ret;
					loc_al &= 0xff;
					loc_eax = (loc_eax&0xffffff00)|loc_al;
					loc_cl >>= 1;
					if (loc_cl) {
						uint8_t loc_ah = (loc_eax>>8)&0xff;
						loc_ah -= loc_al;
						loc_ah &= 1;
						if (!loc_ah)
						{
							loc_eax = (loc_eax&0xffff0000)|(loc_ah<<8)|loc_al;
							/* loc_483918, loc_48391a */
							if (lzma_upack_esi_50(&p, loc_eax, 0x100, &loc_edx, loc_ebp8, &loc_eax, bs, bl) == 0xffffffff)
								return -1;
							break;
						}
					} else
						break;
				} while(1);
			} else {
				/* loc_48391a */
				loc_ecx = (loc_ecx&0xffff00ff)|0x100;
				if (lzma_upack_esi_50(&p, loc_eax, loc_ecx, &loc_edx, loc_ebp8, &loc_eax, bs, bl) == 0xffffffff)
					return -1;
			}
			/* loc_48391f */
			loc_ecx = 0;
			loc_edi = edi_copy;
		}
		/* loc_483a19 */
		/* 2GiM: i think this one is not properly checked, 2aCaB: true */
		if (!CLI_ISCONTAINED(bs, bl, loc_edi, 1))
			return -1;
		*loc_edi++ = (loc_eax&0xff);
	} while (loc_edi < end_edi);

	return 1;
}
