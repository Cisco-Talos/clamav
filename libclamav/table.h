/*
 *  Copyright (C) 2002 Nigel Horne <njh@bandsman.co.uk>
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

/*
 * Hashtable mapping strings to numbers
 */
typedef	struct	tableEntry {
	char	*key;
	int	value;
	struct	tableEntry	*next;
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
