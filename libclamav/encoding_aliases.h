/*
 *  HTML Entity & Encoding normalization.
 *
 *  Copyright (C) 2006 - 2008 Török Edvin <edwin@clamav.net>
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
 *
 */

#include <hashtab.h>
static struct element aliases_htable_elements[] = {
	{NULL,0,0},
	{NULL,0,0},
	{NULL,0,0},
	{"UTF8", 8, 4},
	{"ISO-10646/UTF-8", 8, 15},
	{NULL,0,0},
	{"UTF-16", 1, 6},
	{"UTF16LE", 7, 7},
	{NULL,0,0},
	{"UTF-32", 0, 6},
	{"10646-1:1993/UCS4", 0, 17},
	{NULL,0,0},
	{"UTF-16LE", 7, 8},
	{NULL,0,0},
	{NULL,0,0},
	{NULL,0,0},
	{"UCS-4LE", 2, 7},
	{"UCS-4", 0, 5},
	{"UCS2", 1, 4},
	{"UTF-16BE", 6, 8},
	{NULL,0,0},
	{"UTF-32LE", 2, 8},
	{NULL,0,0},
	{"UTF16BE", 6, 7},
	{"UTF32", 0, 5},
	{"UTF-32BE", 3, 8},
	{"UTF32LE", 2, 7},
	{NULL,0,0},
	{NULL,0,0},
	{NULL,0,0},
	{NULL,0,0},
	{NULL,0,0},
	{NULL,0,0},
	{"UCS-4BE", 3, 7},
	{"ISO-10646/UCS2", 1, 14},
	{NULL,0,0},
	{"10646-1:1993", 0, 12},
	{"ISO-10646/UCS4", 0, 14},
	{"ISO-10646", 0, 9},
	{"UTF-8", 8, 5},
	{"UTF32BE", 3, 7},
	{"ISO-10646/UTF8", 8, 14},
	{NULL,0,0},
	{NULL,0,0},
	{"UCS4", 0, 4},
	{NULL,0,0},
	{NULL,0,0},
	{NULL,0,0},
	{NULL,0,0},
	{NULL,0,0},
	{NULL,0,0},
	{NULL,0,0},
	{NULL,0,0},
};
const struct hashtable aliases_htable = {
	aliases_htable_elements, 53, 25, 42
};
