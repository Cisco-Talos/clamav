/*
 *  Copyright (C) 2006 aCaB <acab@clamav.net>
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

#ifndef __UNSP_H
#define __UNSP_H

#include "cltypes.h"
#include "others.h"

struct UNSP {
  char *src_curr;
  char *src_end;
  uint32_t bitmap;
  uint32_t oldval;
  int error;
  /* the following are not in the original structure */
  char *table;
  uint32_t tablesz;
};

uint32_t unspack(char *, char *, cli_ctx *, uint32_t, uint32_t, uint32_t, int);
uint32_t very_real_unpack(uint16_t *, uint32_t, uint32_t, uint32_t, uint32_t, char *, uint32_t, char *, uint32_t);
uint32_t get_byte(struct UNSP *);
int getbit_from_table(uint16_t *, struct UNSP *);
uint32_t get_100_bits_from_tablesize(uint16_t *, struct UNSP *, uint32_t);
uint32_t get_100_bits_from_table(uint16_t *, struct UNSP *);
uint32_t get_n_bits_from_table(uint16_t *, uint32_t, struct UNSP *);
uint32_t get_n_bits_from_tablesize(uint16_t *, struct UNSP *, uint32_t);
uint32_t get_bb(uint16_t *, uint32_t, struct UNSP *);
uint32_t get_bitmap(struct UNSP *, uint32_t);

#endif
