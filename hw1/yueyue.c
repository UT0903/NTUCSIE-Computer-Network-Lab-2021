#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<errno.h>
#include<netinet/in.h>
#include<netinet/ip.h>
#include<netinet/ip_icmp.h>
#include<arpa/inet.h>
#include<netdb.h>
#include<sys/time.h>

char *DNSLookup(char *host){
    // TODO
}

unsigned short checksum(unsigned short *buf, int bufsz){
    unsigned long sum = 0xffff;

    while(bufsz > 1){
        sum += *buf;
        buf++;
        bufsz -= 2;
    }

    if(bufsz == 1)
        sum += *(unsigned char*)buf;

    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);

    return ~sum;
}


int main(int argc, char *argv[]){
    char *dest = argv[1];
    char *ip = DNSLookup(dest);
    if(ip == NULL){
        printf("traceroute: unknown host %s\n", dest);
        exit(1);
    }
    int icmpfd;
    if((icmpfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0){
        printf("Can not open socket with error number %d\n", errno);
        exit(1);
    }
    
    struct sockaddr_in sendAddr;
    sendAddr.sin_port = htons (7);
    sendAddr.sin_family = AF_INET;
    inet_pton(AF_INET, ip, &(sendAddr.sin_addr));
    
    // Set timeout
    // TODO
    struct timeval timeout;      
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;

    if (setsockopt (icmpfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,
                sizeof(timeout)) < 0)
        error("setsockopt failed\n");

    if (setsockopt (icmpfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout,
                sizeof(timeout)) < 0)
        error("setsockopt failed\n");


    int finish = 0; // if the packet reaches the destination
    int maxHop = 64; // maximum hops
    struct icmp sendICMP; 
    struct timeval begin, end; // used to record RTT
    int seq = 0; // increasing sequence number for icmp packet
    int count = 3; // sending count for each ttl
    printf("traceroute to %s (%s), %d hops max\n", dest, ip, maxHop);
    memset(&sendICMP, 0, sizeof(sendICMP));
    for(int h = 1; h < maxHop; h++){
        // Set TTL
        // TODO
        setsockopt(icmpfd, IPPROTO_IP, IP_TTL, &h, sizeof(h));
        
        for(int c = 0; c < count; c++){
            // Set ICMP Header
            // TODO
            sendICMP.icmp_code = 0;
            sendICMP.icmp_type = ICMP_ECHO;
            sendICMP.icmp_hun.ih_idseq.icd_id = 5566;
            sendICMP.icmp_hun.ih_idseq.icd_seq = seq;
            // Checksum
            // TODO
            sendICMP.icmp_cksum = 0;
            sendICMP.icmp_cksum = checksum((unsigned short *)&sendICMP, sizeof(sendICMP));
            // Send the icmp packet to destination
            // TODO
            gettimeofday(&begin, NULL);
            sendto(icmpfd, &sendICMP, sizeof(sendICMP), NULL, &sendAddr, sizeof(sendAddr));
            
            // Recive ICMP reply, need to check the identifier and sequence number
            struct ip *recvIP;
            struct icmp *recvICMP;
            struct sockaddr_in recvAddr;
            u_int8_t icmpType;
            unsigned int recvLength = sizeof(recvAddr);
            char recvBuf[1500];
            char hostname[4][128];
            char srcIP[4][32];
            float interval[4] = {};
            memset(&recvAddr, 0, sizeof(struct sockaddr_in));
            // TODO
            // recvfrom(icmpfd, recvBuf, sizeof(recvBuf), 0, &recvAddr, recvLength);
            // recvIP = (struct ip *)recvBuf;
            // recvICMP = (struct icmp *) (recvBuf + recvIP->ip_hl * 4);
            // icmpType = recvICMP -> icmp_type;
            // if(icmpType == ICMP_TIMXCEED) {
            //     printf("TimeOut\n");
            //     continue;
            // }

            // Get source hostname and ip address 
            getnameinfo((struct sockaddr *)&recvAddr, sizeof(recvAddr), hostname[c], sizeof(hostname[c]), NULL, 0, 0); 
            strcpy(srcIP[c], inet_ntoa(recvIP->ip_src));
            if(icmpType == 0){
                finish = 1;
            }

            // Print the result
            // TODO
        }    
        if(finish){
            break;
        }
    }
    close(icmpfd);
    return 0;
}
