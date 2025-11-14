EXEC_PROLINK_DEBUG = prolink-debug
EXEC_PROLINK_SHOW = prolink-show

CFLAGS += -W -Wall -O2 -pipe -ansi -std=gnu99 -g
LDFLAGS += 

CC = gcc

PROLINK_DEBUG_SRC=$(prolink-debug.c)
PROLINK_DEBUG_OBJ=$(PROLINK_DEBUG_SRC:.c=.o)

PROLINK_SHOW_SRC=$(prolink-show.c)
PROLINK_SHOW_OBJ=$(PROLINK_SHOW_SRC:.c=.o)

all: $(EXEC_PROLINK_DEBUG) $(EXEC_PROLINK_SHOW)

$(PROLINK_DEBUG): $(PROLINK_DEBUG_OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

$(PROLINK_SHOW): $(PROLINK_SHOW_OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f *.o

mrproper: clean
	rm -f $(EXEC_PROLINK_DEBUG) $(EXEC_PROLINK_SHOW)

