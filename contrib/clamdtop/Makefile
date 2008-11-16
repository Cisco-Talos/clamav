CFLAGS=-g -Wall -W -Wshadow -Wformat=2 -O2 
CC=gcc
OBJS=clamdtop.o
CPPFLAGS=-D_FORTIFY_SOURCE=2
ifeq ($(MSYSTEM),MINGW32)
LIBS=-lpdcurses -lws2_32
else
LIBS=-lncurses
endif

clamdtop: $(OBJS) Makefile
	$(CC) $(OBJS) -o $@ $(LDFLAGS) $(LIBS)

clean:
	rm -f clamdtop $(OBJS)

