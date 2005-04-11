#ifndef UNRAR20_H
#define UNRAR20_H 1

#define BC20 19
#define DC20 48
#define RC20 28
#define MC20 257
#define NC20 298  /* alphabet = {0, 1, 2, ..., NC - 1} */

void unpack_init_data20(int solid, unpack_data_t *unpack_data);
int rar_unpack20(int fd, int solid, unpack_data_t *unpack_data);

#endif
