/*
 *  Unit tests for JS normalizer.
 *
 *  Copyright (C) 2008 Sourcefire, Inc.
 *
 *  Authors: Török Edvin
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
#ifdef HAVE_CHECK

#include <check.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "../libclamav/clamav.h"
#include "../libclamav/others.h"
#include "../libclamav/disasm.h"

START_TEST (test_disasm_basic) {
  char file[]="disasmXXXXXX";
  char ref[]="\xc2\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x02\x00\x00";
  int fd = mkstemp(file);
  uint8_t buf[] = {0x33, 0xc0};
  off_t *d;
  off_t size;
  
  disasmbuf(buf, 2, fd);
  size = lseek(fd, 0, SEEK_CUR);
  fail_unless(size==64, "disasm size");
  lseek(fd, 0, SEEK_SET);
  d=malloc(size);
  fail_unless(d, "disasm malloc");
  fail_unless(read(fd, d, size)==size, "disasm read");
  close(fd);
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


#endif
