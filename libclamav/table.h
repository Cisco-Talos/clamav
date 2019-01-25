/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Nigel Horne
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
 * Hashtable mapping strings to numbers
 */
typedef	struct	tableEntry {
	char	*key;
	struct	tableEntry	*next;
	int	value;
} tableEntry;

typedef struct table {
	tableEntry	*tableHead;
	tableEntry	*tableLast;
	unsigned	int	flags;
} table_t;

#define	TABLE_HAS_DELETED_ENTRIES	0x1

struct	table	*tableCreate(void);
void	tableDestroy(table_t *table);
int	tableInsert(table_t *table, const char *key, int value);
int	tableUpdate(table_t *table, const char *key, int new_value);
int	tableFind(const table_t *table, const char *key);
void	tableRemove(table_t *table, const char *key);
void	tableIterate(table_t *table, void(*callback)(char *key, int value, void *arg), void *arg);
