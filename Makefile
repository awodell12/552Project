# Define required macros here
SHELL = /bin/sh

OBJS =  spectre_orig spectre_modified
CFLAGS = -std=c99 -march=native -O0 -pthread
CC = gcc

all: spectre_orig spectre_modified

spectre_orig:${OBJ}
	${CC} ${CFLAGS} -o $@ spectre_orig.c
# -std=c99 -march=native -O0 -pthread spectre_modified.c -o spectr_modified 

spectre_modified:${OBJ}
	${CC} ${CFLAGS} -o $@ spectre_modified.c

clean:
	-rm -f *.o core *.core spectre_orig spectre_modified

.cpp.o:
	${CC} ${CFLAGS} 

