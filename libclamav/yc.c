/*
 *  Copyright (C) 2005 Ivan Zlatev <pumqara@gmail.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
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

/* Decrypts files, protected by Y0da Cryptor 1.3 */

/* aCaB:
 * 13/01/2006 - merged standalone unpacker into libclamav
 * 14/01/2006 - major rewrite and bugfix
 */
 

#include <string.h>

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include "cltypes.h"
#include "pe.h"
#include "others.h"
#include "yc.h"

#define EC16(x) le16_to_host(x) /* Convert little endian to host */

/* ========================================================================== */
/* "Emulates" the poly decryptors */

static int yc_poly_emulator(char* decryptor_offset, char* code, unsigned int ecx)
{

  /* 
     This is the instruction set of the poly code.
     Numbers stand for example only.

     2C 05            SUB AL,5
     2AC1             SUB AL,CL
     34 10            XOR AL,10
     32C1             XOR AL,CL
     FEC8             DEC AL
     04 10            ADD AL,10
     02C1             ADD AL,CL
     C0C0 06          ROL AL,6
     C0C8 05          ROR AL,5
     D2C8             ROR AL,CL
     D2C0             ROL AL,CL

  */
  unsigned char al;
  unsigned char cl = ecx & 0xff;
  unsigned int j,i;

  for(i=0;i<ecx;i++) /* Byte looper - Decrypts every byte and write it back */
    {
      al = code[i];

      for(j=0;j<0x30;j++)   /* Poly Decryptor "Emulator" */
	{
	  switch(decryptor_offset[j])
	    {

	    case '\xEB':	/* JMP short */
	      j++;
	      j = j + decryptor_offset[j];
	      break;

	    case '\xFE':	/* DEC  AL */
	      al--;
	      j++;
	      break;

	    case '\x2A':	/* SUB AL,CL */
	      al = al - cl;
	      j++;
	      break;

	    case '\x02':	/* ADD AL,CL */
	      al = al + cl;
	      j++;
	      break
		;
	    case '\x32':	/* XOR AL,CL */
	      al = al ^ cl;
	      j++;
	      break;
	      ;
	    case '\x04':	/* ADD AL,num */
	      j++;
	      al = al + decryptor_offset[j];
	      break;
	      ;
	    case '\x34':	/* XOR AL,num */
	      j++;
	      al = al ^ decryptor_offset[j];
	      break;

	    case '\x2C':	/* SUB AL,num */
	      j++;
	      al = al - decryptor_offset[j];
	      break;

			
	    case '\xC0':
	      j++;
	      if(decryptor_offset[j]=='\xC0') /* ROL AL,num */
		{
		  j++;
		  CLI_ROL(al,decryptor_offset[j]);
		}
	      else			/* ROR AL,num */
		{
		  j++;
		  CLI_ROR(al,decryptor_offset[j]);
		}
	      break;

	    case '\xD2':
	      j++;
	      if(decryptor_offset[j]=='\xC8') /* ROR AL,CL */
		{
		  j++;
		  CLI_ROR(al,cl);
		}
	      else			/* ROL AL,CL */
		{
		  j++;
		  CLI_ROL(al,cl);
		}
	      break;

	    case '\x90':
	    case '\xf8':
	    case '\xf9':
	      break;

	    default:
	      cli_dbgmsg("yC: Unhandled opcode %x\n", (unsigned char)decryptor_offset[j]);
	      return 1;
	    }
	}
      cl--;
      code[i] = al;
    }
  return 0;

}


/* ========================================================================== */
/* Main routine which calls all others */

int yc_decrypt(char *fbuf, unsigned int filesize, struct cli_exe_section *sections, unsigned int sectcount, uint32_t peoffset, int desc)
{
  uint32_t ycsect = sections[sectcount].raw;
  unsigned int i;
  struct pe_image_file_hdr *pe = (struct pe_image_file_hdr*) (fbuf + peoffset);
  char *sname = (char *)pe + EC16(pe->SizeOfOptionalHeader) + 0x18;

  /* 

  First layer (decryptor of the section decryptor) in last section 

  Start offset for analyze: Start of yC Section + 0x93
  End offset for analyze: Start of yC Section + 0xC3
  Lenght to decrypt - ECX = 0xB97

  */
  cli_dbgmsg("yC: decrypting decryptor on sect %d\n", sectcount); 
  if (yc_poly_emulator(fbuf + ycsect + 0x93, fbuf + ycsect + 0xc6 ,0xB97))
    return 1;
  filesize-=sections[sectcount].ursz;

  /* 

  Second layer (decryptor of the sections) in last section 

  Start offset for analyze: Start of yC Section + 0x457
  End offset for analyze: Start of yC Section + 0x487
  Lenght to decrypt - ECX = Raw Size of Section

  */


  /* Loop through all sections and decrypt them... */
  for(i=0;i<sectcount;i++)
    {
      uint32_t name = (uint32_t) cli_readint32(sname+i*0x28);
      if ( !sections[i].raw ||
	   !sections[i].rsz ||
	   name == 0x63727372 || /* rsrc */
	   name == 0x7273722E || /* .rsr */
	   name == 0x6F6C6572 || /* relo */
	   name == 0x6C65722E || /* .rel */
	   name == 0x6164652E || /* .eda */
	   name == 0x6164722E || /* .rda */
	   name == 0x6164692E || /* .ida */
	   name == 0x736C742E || /* .tls */
	   (name&0xffff) == 0x4379  /* yC */
	) continue;
      cli_dbgmsg("yC: decrypting sect%d\n",i); 
      if (yc_poly_emulator(fbuf + ycsect + 0x457, fbuf + sections[i].raw, sections[i].ursz))
	return 1;
    }

  /* Remove yC section */
  pe->NumberOfSections=EC16(sectcount);

  /* Remove IMPORT_DIRECTORY information */
  memset((char *)pe + sizeof(struct pe_image_file_hdr) + 0x68, 0, 8);

  /* OEP resolving */
  /* OEP = DWORD PTR [ Start of yC section+ A0F] */
  cli_writeint32((char *)pe + sizeof(struct pe_image_file_hdr) + 16, cli_readint32(fbuf + ycsect + 0xa0f));

  /* Fix SizeOfImage */
  cli_writeint32((char *)pe + sizeof(struct pe_image_file_hdr) + 0x38, cli_readint32((char *)pe + sizeof(struct pe_image_file_hdr) + 0x38) - sections[sectcount].vsz);

  if (cli_writen(desc, fbuf, filesize)==-1) {
    cli_dbgmsg("yC: Cannot write unpacked file\n");
    return 1;
  }
  return 0;
}
