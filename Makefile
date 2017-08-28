#Makefile
all: netfilter_test

netfilter_test: netfilter_test.o
	g++ -o netfilter_test netfilter_test.o -lnetfilter_queue 

netfilter_test.o: netfilter_test.cpp
	g++ -c -o netfilter_test.o netfilter_test.cpp -lnetfilter_queue

clean:
	rm -f netfilter_test
	rm -f *.o

