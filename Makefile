C=clang

CFLAGS=-Wall

all: out

out: main.o
	$(C) $(CFLAGS) main.o -o out

main.o: main.c
	$(C) $(CFLAGS) -c main.c

clean:
	rm -rf *.o out
