CC=gcc
Target=arp_spoofing

arp_spoofing: main.o arp.o pcap.o
	$(CC) main.o arp.o pcap.o -o $(Target) -lpcap -lnet -lpthread

main.o: main.c arph.h pcaph.h
	$(CC) main.c -c -o main.o -lpthread

arp.o: arph.c arph.h
	$(CC) arph.c -c -o arp.o -lnet

pcap.o: pcaph.c pcaph.h
	$(CC) pcaph.c -c -o pcap.o -lpcap

clean:
	rm -f *.o
	rm -f $(Target)