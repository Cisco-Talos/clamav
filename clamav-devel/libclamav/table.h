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
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
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
} table_t;

struct	table	*tableCreate(void);
void	tableDestroy(table_t *table);
int	tableInsert(table_t *table, const char *key, int value);
int	tableFind(const table_t *table, const char *key);
