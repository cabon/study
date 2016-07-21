#include "arph.h"
#include "pcaph.h"
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

int valid_digit(char *ip_str);
int is_valid_ip(char *ip_str);

struct arpArgument arpArgv;

int main(int argc, char *argv[]){

    pthread_t p_thread[2];
    int thr_id;
    int status;
    int i=0;

    if(argc < 2){
        fprintf(stderr, "[-] Usage: %s <target_ip>\n", argv[0]);
        return 1;
    }
/*
    if(!(is_valid_ip(argv[1]))){
        fprintf(stderr, "[-] Invalid ip address: %s\n", argv[1]);
        return 1;
    }
*/
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
    
    pthread_join(p_thread[0], (void **)&status);
    printf("[+] Return thread 0: %d\n", status);

    pthread_join(p_thread[1], (void **)&status);
    printf("[+] Return thread 1: %d\n", status);

    return 0;
}

int valid_digit(char *ip_str){
    while (*ip_str) {
        if (*ip_str >= '0' && *ip_str <= '9')
            ++ip_str;
        else
            return 0;
    }
    return 1;
}

int is_valid_ip(char *ip_str){
    int i, num, dots = 0;
    char *ptr;

    if (ip_str == NULL)
        return 0;
 
    // See following link for strtok()
    // http://pubs.opengroup.org/onlinepubs/009695399/functions/strtok_r.html
    ptr = strtok(ip_str, DELIM);
 
    if (ptr == NULL)
        return 0;
 
    while (ptr) {
 
        /* after parsing string, it must contain only digits */
        if (!valid_digit(ptr))
            return 0;
 
        num = atoi(ptr);
 
        /* check for valid IP */
        if (num >= 0 && num <= 255) {
            /* parse remaining string */
            ptr = strtok(NULL, DELIM);
            if (ptr != NULL)
                ++dots;
        } else
            return 0;
    }
 
    /* valid IP string must contain 3 dots */
    if (dots != 3)
        return 0;
    return 1;
}