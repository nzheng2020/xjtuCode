# Makefile for sigBox C++ programs

CC	= g++

OBJ	= main.o pcapParse.o calSupport.o extractCandidate.o subsequenceExtractor.o pktrulesGen.o

#HEADER	= include.h util.h

#canshu?
#LFLAGS  =       -O -lpcap -I/usr/local/include -lpthread
#CFLAGS  =       -O -I/usr/local/include -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE

all : t


t : $(OBJ)
	$(CC)  -o SnorGen  $(OBJ)  -lpthread -Ofast -ffast-math -std=c++11
#	$(CC)  -o SnorGen  $(OBJ) $(LFLAGS)


# %.o: %.cc $(HEADER)
# 	$(CC) $(CFLAGS) -c  $<

clean :
	rm -rf *.o core SnorGen
