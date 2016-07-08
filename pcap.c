#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
        u_char ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

void get_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void printMac(const u_char *packet);

int main(int argc, char *argv[]){
	pcap_t *handle;
	char *dev=NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	char filter_exp[]="";
	struct bpf_program fp;
	bpf_u_int32 mask;
	bpf_u_int32 net;
	struct pcap_pkthdr header;
	const u_char *packet;

	dev = pcap_lookupdev(errbuf);
	if(dev == NULL){
		fprintf(stderr, "device : %s\n", dev);
		return 2;
	}

	if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1){
		fprintf(stderr, "mask Dev : %s\n", dev);
		net=0;
		mask=0;
	}

	printf("[+] Dev: %s\n", dev);

	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if(handle == NULL){
		fprintf(stderr, "can't open dev %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	pcap_compile(handle, &fp, filter_exp, 0, net);

	pcap_loop(handle, -1, get_packet, NULL);

	pcap_freecode(&fp);
	pcap_close(handle);

	printf("[+]complete\n");

	return 0;
}


void printMac(const u_char *packet){
	int cnt=0;

	for(cnt=0; cnt < 6; cnt++){
		printf("%.2x", packet[cnt]);
		if(cnt != 5) printf(":");
	}
	printf("\n");
}

void get_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
	static int cnt=1;

	const struct sniff_ethernet *ethernet;
	const struct sniff_ip *ip;
	const struct sniff_tcp *tcp;
	const char *payload;

	int size_ip;
	int size_tcp;
	int size_payload;

	ip = (struct sniff_ip *)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if(size_ip < 20){
		printf("[-]wrong IP header len : %u bytes\n", size_ip);
		return;
	}

	switch(ip->ip_p){
		case IPPROTO_TCP:
			printf("\n[+]Protocol	: TCP\n");
			break;
		default:
			return;
	}

	printf("[+]packet number: %d\n", cnt);
	cnt++;

	ethernet = (struct sniff_ethernet *)(packet);

	printf("[+]	From	: %s\n", inet_ntoa(ip->ip_src));
	printf("[+]	To	: %s\n", inet_ntoa(ip->ip_dst));
	
	tcp = (struct sniff_tcp *)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if(size_tcp < 20){
		printf("[-]wrong TCP header len : %u bytes\n", size_tcp);
		return;
	}

	printf("[+]	Src port: %d\n", ntohs(tcp->th_sport));
	printf("[+]	Dst port: %d\n", ntohs(tcp->th_dport));

	printf("[+]	Dst MAC	: ");
	printMac(ethernet->ether_dhost);
	printf("[+]	Src MAC	: ");
	printMac(ethernet->ether_shost);

	return;
}

