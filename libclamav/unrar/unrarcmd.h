#ifndef RAR_CMD_ARRAY_H
#define RAR_CMD_ARRAY_H

#include <stdlib.h>

#include "unrarvm.h"

typedef struct rar_cmd_array_tag
{
	struct rarvm_prepared_command *array;
	size_t num_items;
} rar_cmd_array_t;

void rar_cmd_array_init(rar_cmd_array_t *cmd_a);
void rar_cmd_array_reset(rar_cmd_array_t *cmd_a);
int rar_cmd_array_add(rar_cmd_array_t *cmd_a, int num);

#endif
