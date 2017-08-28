#Makefile
all: netfilter_test

netfilter_test: netfilter_test.o
	g++ -o netfilter_test netfilter_test.o -lpcap 

netfilter_test.o: netfilter_test.cpp
	g++ -c -o netfilter_test.o netfilter_test.cpp -lpcap

clean:
	rm -f netfilter_test
	rm -f *.o

