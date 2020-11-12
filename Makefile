# Define required macros here
SHELL = /bin/sh

OBJS =  spectre_orig spectre_modified
CFLAGS = -std=c99 -march=native -O0 -pthread
CC = gcc


spectre_orig:
	${CC} ${CFLAGS} spectre_orig.c -o spectre_orig
# -std=c99 -march=native -O0 -pthread spectre_modified.c -o spectr_modified 

spectre_modified:
	${CC} ${CFLAGS} spectre_modified.c -o spectre_modified

clean:
	-rm -f *.o core *.core

.cpp.o:
	${CC} ${CFLAGS} ${INCLUDES} -c $<