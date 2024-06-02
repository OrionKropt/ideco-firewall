C=clang

CFLAGS=-Wall

all: out

out: main.o list.o
	$(C) $(CFLAGS) main.o list.o -o out

main.o: main.c
	$(C) $(CFLAGS) -c main.c

list.o: list.c
		$(C) $(CFLAGS) -c list.c

clean:
	rm -rf *.o out
