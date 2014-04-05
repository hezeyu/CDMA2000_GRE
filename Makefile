objects = main.o file.o panaly.o
CFLAGS = -g -c

edit:$(objects)
	gcc $(objects) -o main -lpthread -lmysqlclient

main.o:file.h panaly.h
	gcc $(CFLAGS) main.c
file.o:structure.h file.h
	gcc $(CFLAGS) file.c
panaly.o:structure.h panaly.h sql.c
	gcc $(CFLAGS) panaly.c

.PHONY:clean
clean:
	rm -rf main $(objects)
