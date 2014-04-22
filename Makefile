CC = gcc
CFLAGS = -fPIC -O3 -g -ggdb -c -std=gnu99 -I. -pedantic \
		 -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE \
		 -Wall -Werror -Wimplicit -Wunused -Wcomment -Wchar-subscripts -Wuninitialized \
		 -Wreturn-type -Wpointer-arith -Wbad-function-cast

LD = gcc
LDFLAGS = -fPIC -lpthread

SRCS = debug.c in2trace.c threads.c listener.c display.c ipv4.c

OBJS = $(SRCS:.c=.o)
BIN = in2trace

all: $(BIN)

.c.o: %.c
	@(echo CC $<; $(CC) $(CFLAGS) $<)

$(BIN): $(OBJS)
	@(echo LD $@; $(CC) -o $(BIN) $(OBJS) $(LDFLAGS))

clean:
	@(echo CLEAN; rm -f core $(OBJS) $(BIN))

indent:
	@(echo INDENT; indent -linux -l120 -lc120 -ut -sob -c33 -cp33 *.c *.h; rm -f *~)
# DO NOT DELETE
