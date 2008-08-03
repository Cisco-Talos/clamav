/*
 *  md5 based hashtab
 *
 *  Copyright (C) 2008 Sourcefire, Inc.
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

#ifndef _UNIQ_H
#define _UNIQ_H

#include "cltypes.h"

struct UNIQMD5 {
  struct UNIQMD5 *next;
  uint32_t count;
  uint8_t md5[16];
  char name[33];
};

struct uniq {
  struct UNIQMD5 *md5s;
  uint32_t items;
  uint32_t idx[256];
};

struct uniq *uniq_init(uint32_t);
void uniq_free(struct uniq *);
uint32_t uniq_add(struct uniq *, const char *, uint32_t, char **);
uint32_t uniq_get(struct uniq *, const char *, uint32_t, char **);


#endif
