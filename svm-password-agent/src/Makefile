# SPDX-License-Identifier: BSD-3-Clause

CFLAGS = -g 
CC=$(CROSS)gcc$(POSTFIX) $(CFLAGS)

all: esmb-get-file

esmb-get-file: esmb-get-file.o ucall.o
	$(CC) -o esmb-get-file esmb-get-file.o ucall.o

esmb-get-file.o: esmb-get-file.c
	$(CC) -o esmb-get-file.o -c esmb-get-file.c

ucall.o: ucall.S
	$(CC) -o ucall.o -c ucall.S

clean:
	rm -f esmb-get-file esmb-get-file.o ucall.o
