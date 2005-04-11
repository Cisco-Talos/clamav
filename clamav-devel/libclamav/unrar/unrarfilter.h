#ifndef RAR_FILTER_ARRAY_H
#define RAR_FILTER_ARRAY_H

#include <stdlib.h>

typedef struct rar_filter_array_tag
{
	struct UnpackFilter **array;
	size_t num_items;
} rar_filter_array_t;

void rar_filter_array_init(rar_filter_array_t *filter_a);
void rar_filter_array_reset(rar_filter_array_t *filter_a);
int rar_filter_array_add(rar_filter_array_t *filter_a, int num);
struct UnpackFilter *rar_filter_new();
void rar_filter_delete(struct UnpackFilter *filter);
#endif
