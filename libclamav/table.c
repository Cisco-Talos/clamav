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

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#ifndef	CL_DEBUG
#define	NDEBUG	/* map CLAMAV debug onto standard */
#endif

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <assert.h>

#include "table.h"
#include "others.h"

struct table *
tableCreate(void)
{
	return (struct table *)cli_calloc(1, sizeof(struct table));
}

void
tableDestroy(table_t *table)
{
	tableEntry *tableItem;

	assert(table != NULL);

	tableItem = table->tableHead;

	while(tableItem) {
		tableEntry *tableNext = tableItem->next;

		assert(tableItem->key != NULL);

		free(tableItem->key);
		free(tableItem);

		tableItem = tableNext;
	}

	free(table);
}

/*
 * Returns the value, or -1 for failure
 */
int
tableInsert(table_t *table, const char *key, int value)
{
	const int v = tableFind(table, key);

	if(v > 0)	/* duplicate key */
		return (v == value) ? value : -1;	/* allow real dups */

	assert(value != -1);	/* that would confuse us */

	if(table->tableHead == NULL)
		table->tableLast = table->tableHead = (tableEntry *)cli_calloc(1, sizeof(tableEntry));
	else
		table->tableLast = table->tableLast->next =
			(tableEntry *)cli_calloc(1, sizeof(tableEntry));

	if(table->tableLast == NULL)
		return -1;

	table->tableLast->next = NULL;
	table->tableLast->key = strdup(key);
	table->tableLast->value = value;

	return value;
}

/*
 * Returns the value - -1 for not found
 */
int
tableFind(const table_t *table, const char *key)
{
	const tableEntry *tableItem;
#ifdef	CL_DEBUG
	int cost;
#endif

	assert(table != NULL);

	if(key == NULL)
		return -1;	/* not treated as a fatal error */

	if(table->tableHead == NULL)
		return -1;	/* not populated yet */

#ifdef	CL_DEBUG
	cost = 0;
#endif

	for(tableItem = table->tableHead; tableItem; tableItem = tableItem->next) {
#ifdef	CL_DEBUG
		cost++;
#endif
		if(strcasecmp(tableItem->key, key) == 0) {
#ifdef	CL_DEBUG
			cli_dbgmsg("tableFind: Cost of '%s' = %d\n", key, cost);
#endif
			return(tableItem->value);
		}
	}

	return -1;	/* not found */
}
