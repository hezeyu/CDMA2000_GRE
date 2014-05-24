objects = main.o file.o panaly.o capture.o skt.o
CFLAGS = -g -Wall -c -D_FILE_OFFSET_BITS=64

edit:$(objects)
	gcc $(objects) -lpcap -lmysqlclient -o main -lpthread

main.o:file.h panaly.h capture.h skt.h
	gcc $(CFLAGS) main.c
file.o:structure.h file.h
	gcc $(CFLAGS) file.c
panaly.o:structure.h panaly.h sql.c
	gcc $(CFLAGS) panaly.c
capture.o:structure.h capture.h
	gcc $(CFLAGS) capture.c
skt.o:structure.h skt.h
	gcc $(CFLAGS) skt.c

.PHONY:clean
clean:
	rm -rf main $(objects)
