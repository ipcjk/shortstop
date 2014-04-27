CC=gcc 
CFLAGS=-O2 -Wall -g

shortstop:  main.o
	$(CC) $(CFLAGS) --static -o shortstop main.o 

clean: 
	rm -f shortstop main.o


