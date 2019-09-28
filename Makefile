all: send_arp

send_arp: main.o module.o
	g++ -Wall -g -o send_arp main.o module.o -lpcap

main.o: main.cpp
	g++ -Wall -g -c -o main.o main.cpp

module.o: module.cpp
	g++ -Wall -g -c -o module.o module.cpp

clean: 
	rm -f *.o
	rm send_arp