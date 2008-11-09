CFLAGS=-O2 -g -Wall -W -Wshadow
CC=gcc
OBJS=clamdtop.o
LDFLAGS=
CPPFLAGS=

ifeq ($(MSYSTEM),MINGW32)
LIBS=-lpdcurses -lws2_32
else
LIBS=-lncurses
endif

clamdtop: $(OBJS) Makefile
	$(CC) $(CPPFLAGS) $(CFLAGS) $(OBJS) -o $@ $(LDFLAGS) $(LIBS)

clean:
	rm -f clamdtop $(OBJS)

