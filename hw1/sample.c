#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include<netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/time.h>

#define RECV_TIMEOUT    3

#define MOD_ICMP        0
#define MOD_UDP         1
#define MOD_TCP         2

void DNSLookup(char *host, char *ip){
    struct addrinfo hint, *result, *p;
    memset(&hint, 0, sizeof(hint));
    hint.ai_family = AF_UNSPEC;
    hint.ai_socktype = SOCK_STREAM;
    char ipstr[INET6_ADDRSTRLEN];
    if((getaddrinfo(host, NULL, &hint, &result)) != 0){
        strcpy(ip, "unknown");
    } else {
        for (p = result; p != NULL; p = p->ai_next) {
            void *addr;
            if (p->ai_family == AF_INET) { // IPv4
                struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
                addr = &(ipv4->sin_addr);
                inet_ntop(p->ai_family, addr, ipstr, sizeof(ipstr));
            } else { // IPv6
                continue;
            }
        }
        strcpy(ip, ipstr);
    }
}

unsigned short checksum(void *b, int len) {
    unsigned short *buf = b; 
    unsigned int sum = 0; 
    unsigned short result; 
  
    for ( sum = 0; len > 1; len -= 2 ) 
        sum += *buf++; 
    if ( len == 1 ) 
        sum += *(unsigned char*)buf; 
    sum = (sum >> 16) + (sum & 0xFFFF); 
    sum += (sum >> 16); 
    result = ~sum; 
    return result; 
} 

int main(int argc, char *argv[]){
    // invalid arguments
    if (argc == 1 || argc > 3) {
        puts("[Usage] sudo ./traceroute <destination> [--udp | --tcp]");
        exit(1);
    }

    // parse option
    int mode = MOD_ICMP;
    if (argc == 3) {
        if (strstr(argv[2], "udp") != NULL)
            mode = MOD_UDP;
        if (strstr(argv[2], "tcp") != NULL)
            mode = MOD_TCP;
    }

    // parse destinaiton
    char *dest = argv[1];
    char *ip = malloc(INET6_ADDRSTRLEN);
    DNSLookup(dest, ip);
    if(strcmp(ip, "unknown") == 0){
        printf("traceroute: unknown host %s\n", dest);
        exit(1);
    }
    
    struct sockaddr_in sendAddr;
    if (mode == MOD_ICMP) {
        sendAddr.sin_port = htons (7);
    } else {
        sendAddr.sin_port = htons (33434);
    }
    sendAddr.sin_family = AF_INET;
    inet_pton(AF_INET, ip, &(sendAddr.sin_addr));

    // Set timeout
    struct timeval timeout;
    timeout.tv_sec = RECV_TIMEOUT;
    timeout.tv_usec = 0;

    int icmpfd, udpfd, tcpfd;
    if((icmpfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0){
        perror("Can not open ICMP socket");
        exit(1);
    }
    setsockopt(icmpfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    if (mode == MOD_UDP) {
        /* udp packet */
        if ((udpfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
            perror("Can not open udp socket");
            exit(1);
        }
    } else {
        /* tcp packet */
        if ((tcpfd = socket(AF_INET, SOCK_RAW , IPPROTO_TCP)) < 0) {
            perror("Can not open tdp socket");
            exit(1);
        }
    }

    int finish = 0; // if the packet reaches the destination
    int maxHop = 30; // maximum hops
    struct icmp sendICMP; 
    struct tcphdr tcph;
    struct timeval begin, end; // used to record RTT
    int seq = 0; // increasing sequence number for icmp packet
    int count = 3; // sending count for each ttl
    int res;
    printf("traceroute to %s (%s), %d hops max\n", dest, ip, maxHop);
    for(int h = 1; h <= maxHop; h++) {

        char hostname[4][128];
        char srcIP[4][32];
        float interval[4] = {};
        int is_timeout = 0;
        for(int c = 0; c < count; c++){

            if (mode == MOD_ICMP) {
                // Set TTL
                setsockopt(icmpfd, IPPROTO_IP, IP_TTL, &h, sizeof(h));
                // Set ICMP Header
                sendICMP.icmp_type = 8;
                sendICMP.icmp_code = 0;
                sendICMP.icmp_hun.ih_idseq.icd_id = 20358;
                sendICMP.icmp_hun.ih_idseq.icd_seq = seq++;
                sendICMP.icmp_cksum = checksum(&sendICMP, sizeof(sendICMP));
                if (sendto(icmpfd, &sendICMP, sizeof(sendICMP), 0, (struct sockaddr *)&sendAddr, sizeof(sendAddr)) < 0)
                    perror("Falied to send ICMP packet");
            } else if (mode == MOD_UDP) {
                /* udp */
                setsockopt(udpfd, IPPROTO_IP, IP_TTL, &h, sizeof(h));
                char data;
                if (sendto(udpfd, &data, sizeof(data), 0, (struct sockaddr *)&sendAddr, sizeof(sendAddr)) < 0)
                    perror("Falied to send UDP packet");
            } else {
                /* tcp */
                setsockopt(tcpfd, IPPROTO_IP, IP_TTL, &h, sizeof(h));
                tcph.source = htons (43591);
                tcph.dest = htons (33534);
                tcph.seq = htonl(1105024978);
                tcph.ack_seq = 0;
                tcph.doff = sizeof(struct tcphdr) / 4;
                tcph.fin=0;
                tcph.syn=1;
                tcph.rst=0;
                tcph.psh=0;
                tcph.ack=0;
                tcph.urg=0;
                tcph.window = htons (14600);
                tcph.check = 0;
                tcph.urg_ptr = 0;
                // char data;
                if (sendto(tcpfd, &tcph, sizeof(struct tcphdr), 0, (struct sockaddr *)&sendAddr, sizeof(sendAddr)) < 0) {
                    perror("Falied to send TCP packet");
                }
            }
            gettimeofday(&begin, NULL);
        
            // Recive ICMP reply, need to check the identifier and sequence number
            struct ip *recvIP;
            struct icmp *recvICMP;
            struct sockaddr_in recvAddr;
            u_int8_t icmpType;
            unsigned int recvLength = sizeof(recvAddr);
            char recvBuf[1500];
            memset(&recvAddr, 0, sizeof(struct sockaddr_in));
            memset(&recvBuf, 0, 1500);
            memset(&recvICMP, 0, sizeof(struct icmp));
            res = recvfrom(icmpfd, &recvBuf, sizeof(recvBuf), 0, (struct sockaddr *)&recvAddr, &recvLength);
            gettimeofday(&end, NULL);
            
            if (res < 0) {
                if (errno == EAGAIN) {
                    is_timeout = 1;
                    continue;
                } else {
                    perror("Failed to receive response");
                    exit(1);
                }
            } else {
                interval[c] =  1000 * (end.tv_sec - begin.tv_sec) + 0.001 * (end.tv_usec - begin.tv_usec);
            }

            // Get source hostname and ip address
            int ip_hlen;
            short ip_datalen;
            recvIP = (struct ip*)recvBuf;
            ip_hlen = recvIP->ip_hl << 2;  
            ip_datalen = ntohs(recvIP->ip_len) - ip_hlen;  
            recvICMP = (struct icmp *)(recvBuf + ip_hlen); 
            struct icmp *recvICMP_inner = (struct icmp *) (recvBuf + ip_hlen + sizeof(struct icmp));
            icmpType = recvICMP->icmp_type;

            if (mode == MOD_ICMP) {
                if (icmpType == 0)
                    finish = 1;
                // else
                    // recvICMP = (struct icmp *) (recvBuf + ip_hlen + sizeof(struct icmp));
                if(res >= 0 && recvICMP->icmp_hun.ih_idseq.icd_id != 20358 && recvICMP_inner->icmp_hun.ih_idseq.icd_id != 20358) {
                    puts("ICMP id incorrect");
                    exit(0);
                }
            } else if (mode == MOD_UDP) {
                if (icmpType == 3)
                    finish = 1;
                /* receive udp */
            } else {
                if (icmpType == 3)
                    finish = 1;
                /* receive tcp */
            }
            getnameinfo((struct sockaddr *)&recvAddr, sizeof(recvAddr), hostname[c], sizeof(hostname[c]), NULL, 0, 0); 
            strcpy(srcIP[c], inet_ntoa(recvIP->ip_src));
            memset(&sendICMP, 0, sizeof(struct icmp));
        }    

        // Print the result
        if (is_timeout) {
            printf("%2d * * *\n", h);
        } else {
            printf("%2d %s (%s) ", h, hostname[0], srcIP[0] );
            for (int c = 0; c < count; c++)
                printf("%.3f ms%c", interval[c], "\n "[c<count-1]);

            if(finish){
                break;
            }
        }
        
    }
    close(icmpfd);
    return 0;
}
