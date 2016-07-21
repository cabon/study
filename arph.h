#ifndef _ARPH
#define _ARPH

#include <arpa/inet.h>
#include <libnet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <libnet.h>
#include <stdint.h>
#include <unistd.h>

#define MAC_LEN             6
#define IP_LEN              4

#define ARP_REQUEST         1   /* ARP Request             */ 
#define ARP_REPLY           2   /* ARP Reply               */ 
typedef struct arphdr { 
    u_int16_t htype;            /* Hardware Type           */ 
    u_int16_t ptype;            /* Protocol Type           */ 
    u_char hlen;                /* Hardware Address Length */ 
    u_char plen;                /* Protocol Address Length */ 
    u_int16_t oper;             /* Operation Code          */ 
    u_char sha[MAC_LEN];        /* Sender hardware address */ 
    u_char spa[IP_LEN];         /* Sender IP address       */ 
    u_char tha[MAC_LEN];        /* Target hardware address */ 
    u_char tpa[IP_LEN];         /* Target IP address       */ 
}arphdr_t;

struct arpArgument{
    int arpop;
    char *senderIp;
    char *gwAddr;
    u_int8_t senderMac[MAC_LEN];
};
extern struct arpArgument arpArgv;
void printMac(const u_char *mac);
void *arpRequest();
#endif