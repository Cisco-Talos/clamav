CC=cc

# Solaris needs these:
#CFLAGS=-D_XOPEN_SOURCE=500
#LDFLAGS=-lsocket

CFLAGS=
LDFLAGS=
all: clamd_fdscan

strlcpy.o: strlcpy.c 
	$(CC) $(CFLAGS) -c -o $@ $<

clamd_fdscan.o: clamd_fdscan.c clamd_fdscan.h
	$(CC) $(CFLAGS) -c -o $@ $<

clamd_fdscan: clamd_fdscan.o strlcpy.o
		$(CC) -o $@ clamd_fdscan.o strlcpy.o  
