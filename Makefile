#Makefile
all: pcap-test

pcap-test: main.o pcap-test.o
        g++ -o pcap-test main.o pcap-test.o

main.o: main.h main.c
        g++ -c -o main.o main.c

pcap-test.o: sum.h sum.cpp
        g++ -c -o pcap-test.o pcap-test.c

clean:
        rm -f pcap-test
        rm -f *.o


