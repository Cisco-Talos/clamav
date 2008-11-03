CFLAGS=-O2 -g -Wall -W -Wshadow
CC=gcc
OBJS= clamdtop.o

clamdtop: $(OBJS) Makefile
	$(CC) $(CFLAGS) $(OBJS) -lncurses -o $@

clean:
	rm -f clamdtop $(OBJS)

