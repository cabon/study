#include "arph.h"
#include "pcaph.h"
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

struct arpArgument arpArgv;

int main(int argc, char *argv[]){

    pthread_t p_thread[3];
    int thr_id;
    int status;
    int i=0;

    if(argc < 2){
        fprintf(stderr, "[-] Usage: %s <target_ip>\n", argv[0]);
        return 1;
    }
    
    arpArgv.arpop=ARP_REQUEST;
    arpArgv.senderIp=argv[1];
    for(i=0; i<MAC_LEN; i++)
        arpArgv.senderMac[i]=0xff;

   if((pthread_create(&p_thread[0], NULL, &arpRequest, NULL))<0){
        fprintf(stderr, "[-] Create thread: get_packet\n");
        return 1;
    }

    if((pthread_create(&p_thread[1], NULL, &get_packet, NULL))<0){
        fprintf(stderr, "[-] Create thread: arpRequest\n");
        return 1;
    }

    if((pthread_create(&p_thread[2], NULL, &relay_packet, NULL))<0){
        fprintf(stderr, "[-] Create thread: relay_packet\n");
        return 1;
    }
    
    pthread_join(p_thread[0], (void **)&status);
    printf("[+] Return getPacket thread: %d\n", status);

    pthread_join(p_thread[1], (void **)&status);
    printf("[+] Return arpRequest thread: %d\n", status);

    pthread_join(p_thread[2], (void **)&status);
    printf("[+] Return relayPacket thread: %d\n", status);

    return 0;
}