#ifndef _PCAPH
#define _PCAPH

#include <pcap.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include "arph.h"

#define TIMEOUT             1000
#define DELIM               "."
#define SIZE_ETHERNET       14
/* Ethernet header */
struct sniff_ethernet {
        u_char ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};
extern struct arpArgument arpArgv;
void *get_packet();

#endif