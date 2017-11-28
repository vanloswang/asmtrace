#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#
SHELL   = /bin/sh
CC      = gcc
CFLAGS  = -Wall 
SRCS	= asmtrace.c print.c trace.c disasm*.c
LIBS    = 
PROG    = asmtrace
#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#

none: all

new: clean all

all: 
	@echo "[+] Building x86"
	rm -f *.o
	${CC} ${CFLAGS} -I./libudis86 -I. -m32 -o ${PROG}"-x86" ${SRCS} ./libudis86/libudis86.a
	@echo "[+] Building x86-64"
	rm -f *.o
	${CC} ${CFLAGS} -I./libudis86 -I. -m64 -o ${PROG}"-x86-64" ${SRCS} ./libudis86/libudis86-64.a

clean:
	rm -f ${PROG} *.o *.core
