#include "arph.h"

void *arpRequest(){
    libnet_t *lc;
    char errbuf[LIBNET_ERRBUF_SIZE];
    u_int32_t sender_ip_addr, my_ip_addr;
    u_int8_t mac_broadcast_addr[MAC_LEN]={0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    u_int8_t mac_zero_addr[MAC_LEN]={0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    struct libnet_ether_addr *my_mac_addr;
    int writeBytes;
    int i=0;

    lc=libnet_init(LIBNET_LINK, NULL, errbuf);
    if( lc == NULL){
        fprintf(stderr, "libnet_init() failed: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    if(arpArgv.arpop == ARP_REQUEST){
        my_ip_addr = libnet_get_ipaddr4(lc);
    }else{
        char tmp[BUFSIZ];
        memset(tmp, '\0', sizeof(tmp));

        FILE *pipe = popen("ip route show default | awk '/default/ {print $3}'", "r");
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
        printf("[+] Set own ip to gateway\n\n");

        my_ip_addr = libnet_name2addr4(lc, tmp, LIBNET_DONT_RESOLVE);
    }

    if(my_ip_addr != -1){
        printf("[+] Own ip\t: %s\n", libnet_addr2name4(my_ip_addr, LIBNET_DONT_RESOLVE));
    }else{
        fprintf(stderr, "[-] Get ip: %s\n", libnet_geterror(lc));
        libnet_destroy(lc);
        exit(EXIT_FAILURE);
    }

    my_mac_addr = libnet_get_hwaddr(lc);
    if(my_mac_addr != NULL){
        printf("[+] Own mac\t: ");
        printMac(my_mac_addr->ether_addr_octet);
    }else{
        fprintf(stderr, "[-] Get mac: %s\n", libnet_geterror(lc));
        libnet_destroy(lc);
        exit(EXIT_FAILURE);
    }
  
    // set target ip
    sender_ip_addr = libnet_name2addr4(lc, arpArgv.senderIp, LIBNET_DONT_RESOLVE);
    if(sender_ip_addr != -1){
        printf("[+] Sender ip\t: %s\n", libnet_addr2name4(sender_ip_addr, LIBNET_DONT_RESOLVE));
    }else{
        fprintf(stderr, "[-] Get senderIp: %s\n", libnet_geterror(lc));
        libnet_destroy(lc);
        exit(EXIT_FAILURE);
    }

    printf("[+] Sender Mac\t: ");
    printMac(arpArgv.senderMac);

    // build arp hdr
    if(libnet_autobuild_arp(arpArgv.arpop, my_mac_addr->ether_addr_octet,\
                (u_int8_t *)(&my_ip_addr), mac_zero_addr,\
                (u_int8_t *)(&sender_ip_addr), lc) != -1){
            printf("[+] Build ARP header\n");
    }else{
        fprintf(stderr, "[-] Build ARP header: %s\n", libnet_geterror(lc));
        libnet_destroy(lc);
        exit(EXIT_FAILURE);
    }

    // build eth hdr
    if(libnet_autobuild_ethernet(arpArgv.senderMac, ETHERTYPE_ARP, lc) != -1){
        printf("[+] Build ETH header\n");
    }else{
        fprintf(stderr, "[-] Build ETH header: %s\n", libnet_geterror(lc));
        libnet_destroy(lc);
        exit(EXIT_FAILURE);
    }
    
    for(i=0; i<ARP_REPLY; i++){
        // write packet
        writeBytes = libnet_write(lc);
        if(writeBytes != -1){
            printf("[+] Send ARP request: %dbytes written\n", writeBytes);
        }else{
            fprintf(stderr, "[-] Write packet: %s\n", libnet_geterror(lc));
        }
        sleep(1);
    }

    memset(&arpArgv.gwAddr, '\x00', sizeof(arpArgv.gwAddr));
    free(arpArgv.gwAddr);
    libnet_destroy(lc);
}


void printMac(const u_char *mac){
    int cnt=0;
    printf("%02X:%02X:%02X:%02X:%02X:%02X\n",\
                mac[0],\
                mac[1],\
                mac[2],\
                mac[3],\
                mac[4],\
                mac[5]);
}