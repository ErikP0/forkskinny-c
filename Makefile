CC=gcc
CFLAGS=-pedantic -Wall -Wextra -Werror -fomit-frame-pointer -std=c99 -O3

.PHONY: clean

all: libforkskinnyc.a demo.x

OBJS = \
	forkskinny128-cipher.o \
	forkskinny64-cipher.o

forkskinny64-cipher.o: forkskinny-internal.h forkskinny64-cipher.h forkskinny64-cipher.c
forkskinny128-cipher.o: forkskinny-internal.h forkskinny128-cipher.h forkskinny128-cipher.c

demo.x: demo.o libforkskinnyc.a
	$(CC) $(CFLAGS) -o demo.x demo.o libforkskinnyc.a

libforkskinnyc.a: ${OBJS}
	$(AR) -rcs libforkskinnyc.a ${OBJS}

clean:
	rm -f *.o *.x *.a