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
    struct hostent *ghbn = gethostbyname(host);//change the domain name
    //printf("in\n");
    if (!ghbn) {
        fprintf(stderr, "Can't recolve host name\n");
        exit(1);
    }
    return (char *)inet_ntoa(*(struct in_addr *)ghbn->h_addr);
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

void Print_Format(int idx, char hostname[3][128], char srcIP[3][32], int usec_info[3]){
    char *prev_name = "";
    fprintf(stderr, "%d", idx);
    for(int i = 0; i < 3; i++){
        if(strcmp(prev_name, hostname[i]) == 0){
            //printf("fuuuck\n");
            fprintf(stderr, " %f ms", (double)usec_info[i] / 1000.0);
        }
        else{
            if(strcmp("no", hostname[i]) == 0){
                strcpy(hostname[i], srcIP[i]);
            }
            fprintf(stderr, " %s (%s) %f ms", hostname[i], srcIP[i], (double)usec_info[i] / 1000.0);
            prev_name = hostname[i];
        }
    }
    fprintf(stderr, "\n");
}
int main(int argc, char *argv[]){
    char *dest = argv[1];
    //fprintf(stderr, "%s\n", argv[1]);
    char *ip = DNSLookup(dest);
    if(ip == NULL){
        printf("traceroute: unknown host %s\n", dest);
        exit(1);
    }
    int icmpfd;
    if((icmpfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0){
        printf("Can not open socket\n");
        exit(1);
    }
    
    struct sockaddr_in sendAddr, recvAddr;
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
        perror("setsockopt failed\n");

    if (setsockopt (icmpfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout,
                sizeof(timeout)) < 0)
        perror("setsockopt failed\n");


    int finish = 0; // if the packet reaches the destination
    int maxHop = 64; // maximum hops
    struct icmp sendICMP; 
    struct timeval begin, end; // used to record RTT
    int seq = 0; // increasing sequence number for icmp packet
    int count = 3; // sending count for each ttl
    printf("traceroute to %s (%s), %d hops max\n", dest, ip, maxHop);
    memset(&sendICMP, 0, sizeof(sendICMP));
    for(int h = 1; h < maxHop; h++){
        setsockopt(icmpfd, IPPROTO_IP, IP_TTL, &h, sizeof(h));
        //fprintf(stderr, "ok");
        char srcIP[count][32];
        char hostname[count][128];
        int usec_info[count];
        for(int c = 0; c < count; c++){
            // Set ICMP Header
            // TODO
            sendICMP.icmp_code = 0;
            sendICMP.icmp_type = ICMP_ECHO;
            sendICMP.icmp_hun.ih_idseq.icd_id = 5566;
            sendICMP.icmp_hun.ih_idseq.icd_seq = seq;
            // Checksum
            // TODO
            sendICMP.icmp_cksum = checksum((unsigned short *)&sendICMP, sizeof(sendICMP));
            // Send the icmp packet to destination
            // TODO
            gettimeofday(&begin, NULL);
            sendto(icmpfd, (char*)&sendICMP, sizeof(sendICMP), 0, (const struct sockaddr *)&sendAddr, sizeof(sendAddr));
            fprintf(stderr, "send hop: %d, c: %d\n", h, c+1);
            // Recive ICMP reply, need to check the identifier and sequence number
            struct ip *recvIP;
            struct icmp *recvICMP;
            
            u_int8_t icmpType;
            char recvBuf[1500];
            
            
            float interval[4] = {};
            // TODO
            memset(&recvAddr, 0, sizeof(struct sockaddr_in));
            recvfrom(icmpfd, recvBuf, sizeof(recvBuf), 0, &recvAddr, sizeof(recvAddr));
            fprintf(stderr, "recv hop: %d, c: %d\n", h, c+1);
            recvIP = (struct ip *)recvBuf;
            recvICMP = (struct icmp *) (recvBuf + recvIP->ip_hl * 4);
            icmpType = recvICMP -> icmp_type;
            if(icmpType == ICMP_TIMXCEED) {
                //printf("TimeOut\n");
                gettimeofday(&end, NULL);
                usec_info[c] = (end.tv_sec - begin.tv_sec)*1000000 + (end.tv_usec - begin.tv_usec);
            }

            // Get source hostname and ip address 
            int ret = 0;
            if(ret = getnameinfo((struct sockaddr *)&recvAddr, sizeof(recvAddr), (char *)&hostname[c], sizeof(hostname[c]), NULL, 0, 0) < 0){
                //fprintf(stderr, "ret error\n");
                strcpy(hostname[c], "no");
            }
            strcpy(srcIP[c], inet_ntoa(recvIP->ip_src));
            if(icmpType == 0){
                finish = 1;
            }
            // Print the result
            // TODO
        }

        Print_Format(h, hostname, srcIP, usec_info);

        if(finish){
            break;
        }
    }
    close(icmpfd);
    return 0;
}