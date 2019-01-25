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
 *
 * TODO: Allow individual items to be updated or removed
 *
 * It is up to the caller to create a mutex for the table if needed
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdlib.h>
#include <string.h>
#ifdef	HAVE_STRINGS_H
#include <strings.h>
#endif
#include <assert.h>

#include "clamav.h"
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

		if(tableItem->key)
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
		table->tableLast = table->tableHead = (tableEntry *)cli_malloc(sizeof(tableEntry));
	else {
		/*
		 * Re-use deleted items
		 */
		if(table->flags&TABLE_HAS_DELETED_ENTRIES) {
			tableEntry *tableItem;

			assert(table->tableHead != NULL);

			for(tableItem = table->tableHead; tableItem; tableItem = tableItem->next)
				if(tableItem->key == NULL) {
					/* This item has been deleted */
					tableItem->key = cli_strdup(key);
					tableItem->value = value;
					return value;
				}

			table->flags &= ~TABLE_HAS_DELETED_ENTRIES;
		}

		table->tableLast = table->tableLast->next =
			(tableEntry *)cli_malloc(sizeof(tableEntry));
	}

	if(table->tableLast == NULL) {
        cli_dbgmsg("tableInsert: Unable to allocate memory for table\n");
		return -1;
    }

	table->tableLast->next = NULL;
	table->tableLast->key = cli_strdup(key);
	table->tableLast->value = value;

	return value;
}

/*
 * Returns the value - -1 for not found. This means the value of a valid key
 *	can't be -1 :-(
 *
 * Linear search. Since tables are rarely more than 3 or 4 in size, and never
 *	reach double figures, there's no need for optimization
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

#ifdef	CL_DEBUG
	cost = 0;
#endif

	for(tableItem = table->tableHead; tableItem; tableItem = tableItem->next) {
#ifdef	CL_DEBUG
		cost++;
#endif
		if(tableItem->key && (strcasecmp(tableItem->key, key) == 0)) {
#ifdef	CL_DEBUG
			cli_dbgmsg("tableFind: Cost of '%s' = %d\n", key, cost);
#endif
			return tableItem->value;
		}
	}

	return -1;	/* not found */
}

/*
 * Change a value in the table. If the key isn't in the table insert it
 * Returns -1 for error, otherwise the new value
 */
int
tableUpdate(table_t *table, const char *key, int new_value)
{
	tableEntry *tableItem;

	assert(table != NULL);

	if(key == NULL)
		return -1;	/* not treated as a fatal error */

	for(tableItem = table->tableHead; tableItem; tableItem = tableItem->next)
		if(tableItem->key && (strcasecmp(tableItem->key, key) == 0)) {
			tableItem->value = new_value;
			return new_value;
		}

	/* not found */
	return tableInsert(table, key, new_value);
}

/*
 * Remove an item from the table
 */
void
tableRemove(table_t *table, const char *key)
{
	tableEntry *tableItem;

	assert(table != NULL);

	if(key == NULL)
		return;	/* not treated as a fatal error */

	for(tableItem = table->tableHead; tableItem; tableItem = tableItem->next)
		if(tableItem->key && (strcasecmp(tableItem->key, key) == 0)) {
			free(tableItem->key);
			tableItem->key = NULL;
			table->flags |= TABLE_HAS_DELETED_ENTRIES;
			/* don't break, duplicate keys are allowed */
		}
}

void
tableIterate(table_t *table, void(*callback)(char *key, int value, void *arg), void *arg)
{
	tableEntry *tableItem;

	if(table == NULL)
		return;

	for(tableItem = table->tableHead; tableItem; tableItem = tableItem->next)
		if(tableItem->key)	/* check node has not been deleted */
			(*callback)(tableItem->key, tableItem->value, arg);
}
