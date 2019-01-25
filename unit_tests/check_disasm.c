/*
 *  Unit tests for JS normalizer.
 *
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2008-2013 Sourcefire, Inc.
 *
 *  Authors: aCaB <acab@clamav.net>
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

#include <check.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>

#include "../libclamav/clamav.h"
#include "../libclamav/others.h"
#include "../libclamav/disasm.h"
#include "checks.h"

START_TEST (test_disasm_basic) {
  char file[]="disasmXXXXXX";
  int fd = mkstemp(file), ref;
  uint8_t buf[] = {
    /* m00/rm000 - add [eax], al */
    0x00, 0x00,
    /* m00/rm011 - add [ebx], edi */
    0x01, 0x3b,
    /* m00/rm100/ss00/idx010/b100 - or [edx*1+esp], dh */
    0x08, 0x34, 0x14,
    /* m00/rm100/ss00/idx100/b001 - or [0*1+ecx], edi */
    0x09, 0x3c, 0x21,
    /* m00/rm100/ss00/idx010/b101 - adc [edx*1+0x42614361], ah */
    0x10, 0x24, 0x15, 0x61, 0x43, 0x61, 0x42,
    /* m00/rm100/ss10/idx111/b110 - adc [edi*4+esi], ecx */
    0x11, 0x0c, 0xbe,
    /* m00/rm101 - sbb [0xaaccaabb], dl */
    0x18, 0x15, 0xbb, 0xaa, 0xcc, 0xaa,
    /* m01/rm001 - sbb [ecx+0xffffffff], esp */
    0x19, 0x61, 0xff,
    /* m10/rm100/ss01/idx110/b010 - and [esi*2+edx+0x0b0a0c0a], ch */
    0x20, 0xac, 0x72, 0x0a, 0x0c, 0x0a, 0x0b,
    /* m10/rm100/ss11/idx011/b101 - and [eax*8+ebp+0xabacabac], ebx */
    0x21, 0x9c, 0xc5, 0xac, 0xab, 0xac, 0xab,
    /* m11/rm100 - sub ah, dh */
    0x28, 0xf4,
    /* m11/rm101 - sub ebp, edx */
    0x29, 0xd5,
    /* addrsize, m00/rm110 - mov [eax-5355], ebp */
    0x67, 0x01, 0x2e, 0xab, 0xac,
    /* add al, 17 */
    0x04, 0x17,
    /* pop es */
    0x07,
    /* push cs */
    0x0e,
    /* adc eax, 0x37333331 */
    0x15, 0x31, 0x33, 0x33, 0x37,
    /* inc esi */
    0x46,
    /* jnc +0x31 */
    0x73, 0x31,
    /* pop [edx] */
    0x8f, 0x02,
    /* nop */
    0x90,
    /* call far 1122:33445566 */
    0x9a, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
    /* mov [11223344], eax */
    0xa2, 0x44, 0x33, 0x22, 0x11,
    /* enter 1122, 33 */
    0xc8, 0x22, 0x11, 0x33,
    /* rcl [ecx], 1 */
    0xd0, 0x11,
    /* sar al, cl */
    0xd2, 0xf8,
    /* push fs */
    0x0f, 0xa0,
    /* mov edx, 12345678 */
    0xba, 0x78, 0x56, 0x34, 0x12,
    /* jmp $ */
    0xe9, 0xfb, 0xff, 0xff, 0xff,
    /* mov eax, cr2 */
    0x0f, 0x20, 0xd0,
    /* mov cr7, edx */
    0x0f, 0x22, 0xda,
    /* mov ecx, dr0 */
    0x0f, 0x21, 0xc1,
    /* mov dr3, ebx */
    0x0f, 0x23, 0xdb,
    /* mov ax, ss */
    0x66, 0x8c, 0xd0,
    /* mov eax, [deadbeef] */
    0xa1, 0xef, 0xbe, 0xad, 0xde,
    /* ficom dword ptr [esi*8+ebx+7f] */
    0xda, 0x54, 0xf3, 0x7f,
    /* fmulp st(3), st(0) */
    0xde, 0xcb,
    
  };
  uint8_t *d;
  off_t size;
  STATBUF st;

  fail_unless(fd!=-1, "mkstemp failed");
  ref = open_testfile("input/disasmref.bin");
  fail_unless(FSTAT(ref, &st)!=-1, "fstat failed");
  disasmbuf(buf, sizeof(buf), fd);
  size = lseek(fd, 0, SEEK_CUR);
  fail_unless_fmt(size==st.st_size, "disasm size mismatch(value %u, expected: %u)", size, st.st_size);
  lseek(fd, 0, SEEK_SET);
  d=malloc(size*2);
  fail_unless_fmt(d!=NULL, "disasm malloc(%u) failed", size);
  fail_unless(read(ref, d, size)==size, "disasm reference read failed");
  fail_unless(read(fd, d+size, size)==size, "disasm read failed");
  close(fd);
  close(ref);
  fail_unless(!memcmp(d, d+size, size), "disasm data doesn't match the reference"); 
  free(d);
  unlink(file);
}
END_TEST


Suite *test_disasm_suite(void)
{
    Suite *s = suite_create("disasm");
    TCase *tc_disasm;
    tc_disasm = tcase_create("disasm");
    suite_add_tcase (s, tc_disasm);
    tcase_add_test(tc_disasm, test_disasm_basic);
    return s;
}

