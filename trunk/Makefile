CC	= /usr/bin/gcc
#CFLAGS	= -Wall
CFLAGS	= -Wall -DDEBUG
LDFLAGS	= -lm -lpthread -lmilter -lconfuse


BIN	= date_milter
OBJ	= date_milter.o

all: $(OBJ)
	$(CC) $(CFLAGS) -o $(BIN) $(OBJ) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f $(BIN) $(OBJ)

strip:
	strip $(BIN)
