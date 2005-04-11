#include <string.h>
#include <stdlib.h>

#include "unrar.h"
#include "unrarcmd.h"

void rar_cmd_array_init(rar_cmd_array_t *cmd_a)
{
	cmd_a->array = NULL;
	cmd_a->num_items = 0;
}

void rar_cmd_array_reset(rar_cmd_array_t *cmd_a)
{	
	if (!cmd_a) {
		return;
	}
	if (cmd_a->array) {
		free(cmd_a->array);
	}
	cmd_a->array = NULL;
	cmd_a->num_items = 0;
}

int rar_cmd_array_add(rar_cmd_array_t *cmd_a, int num)
{
	cmd_a->num_items += num;
	cmd_a->array = (struct rarvm_prepared_command *) realloc(cmd_a->array,
			cmd_a->num_items * sizeof(struct rarvm_prepared_command));
	if (cmd_a->array == NULL) {
		return FALSE;
	}
	memset(&cmd_a->array[cmd_a->num_items-1], 0, sizeof(struct rarvm_prepared_command));
	return TRUE;
}
