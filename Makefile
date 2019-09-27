all: send_arp

send_arp: main.o
	g++ -Wall -g -o send_arp main.o -lpcap

main.o: main.cpp
	g++ -Wall -g -c -o main.o main.cpp

clean: 
	rm -f *.o