#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<errno.h>
#include<netinet/in.h>
#include<netinet/ip.h>
#include<netinet/tcp.h>
#include<netinet/ip_icmp.h>
#include<arpa/inet.h>
#include<netdb.h>
#include<sys/time.h>

enum {ICMP, UDP, TCP}; 

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

void set_tcp_header(struct tcphdr *tcph, int source_port){
    tcph->source = htons ( source_port );
    tcph->dest = htons (30000);
    tcph->seq = htonl(1105024978);
    tcph->ack_seq = 0;
    tcph->doff = sizeof(struct tcphdr) / 4;     //Size of tcp header
    tcph->fin=0;
    tcph->syn=1;
    tcph->rst=0;
    tcph->psh=0;
    tcph->ack=0;
    tcph->urg=0;
    //tcph->res1=0;
    tcph->window = htons (14600); // maximum allowed window size
    tcph->check = 0; //if you set a checksum to zero, your kernel's IP stack should fill in the correct checksum during transmission
    tcph->urg_ptr = 0;
}
void set_ip_header(struct iphdr *iph, char *datagram, int ttl, char* source_ip, char *target_ip){
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof (struct ip) + sizeof (struct tcphdr);
    iph->id = htons (54321);    //Id of this packet
    iph->frag_off = htons(16384);
    iph->ttl = ttl;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = inet_addr ( source_ip );   //Spoof the source ip address
    iph->daddr = inet_addr ( target_ip );
    
    iph->check = checksum ((unsigned short *) datagram, iph->tot_len >> 1);
}

void Print_Format(int idx, char hostname[3][128], char srcIP[3][32], int usec_info[3]){
    char *prev_name = "";
    fprintf(stderr, "%2d", idx);
    for(int i = 0; i < 3; i++){
        //printf("%d\n", usec_info[i]);
        if(strcmp(prev_name, hostname[i]) == 0){
            
            fprintf(stderr, " %.3f ms", ((double)usec_info[i] / 1000.0 < 0)?0:((double)usec_info[i] / 1000.0));
        }
        else{
            fprintf(stderr, " %s (%s) %.3f ms", hostname[i], srcIP[i], ((double)usec_info[i] / 1000.0 < 0)?0:((double)usec_info[i] / 1000.0));
            prev_name = hostname[i];
        }
    }
    fprintf(stderr, "\n");
}

int get_local_ip ( char * buffer){
    int sock = socket ( AF_INET, SOCK_DGRAM, 0);

    const char* kGoogleDnsIp = "8.8.8.8";
    int dns_port = 53;

    struct sockaddr_in serv;

    memset( &serv, 0, sizeof(serv) );
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = inet_addr(kGoogleDnsIp);
    serv.sin_port = htons( dns_port );

    int err = connect( sock , (const struct sockaddr*) &serv , sizeof(serv) );

    struct sockaddr_in name;
    socklen_t namelen = sizeof(name);
    err = getsockname(sock, (struct sockaddr*) &name, &namelen);

    const char *p = inet_ntop(AF_INET, &name.sin_addr, buffer, 100);

    close(sock);
}

int main(int argc, char *argv[]){

    // Usage: ./traceroute [protocol] [destination]
    char *protocol = argv[1];
    char *dest = argv[2];

    int mode;
    if (!strcmp(protocol, "ICMP")) mode = ICMP;
    else if (!strcmp(protocol, "UDP")) mode = UDP;
    else mode = TCP;

    //fprintf(stderr, "%s\n", argv[1]);
    char *ip = DNSLookup(dest);
    if(ip == NULL){
        printf("traceroute: unknown host %s\n", dest);
        exit(1);
    }
    int icmpfd, udpfd, tcpfd;
    if((icmpfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0){
        printf("Can not open socket\n");
        exit(1);
    }
    if (mode == UDP) {
        if ((udpfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
            perror("Can not open udp socket");
            exit(1);
        }
    } else if (mode == TCP) {
        if((tcpfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
            printf("Can not open socket\n");
            exit(1);
        }
    }

    
    struct sockaddr_in sendAddr, recvAddr;
    sendAddr.sin_port = (mode == ICMP) ? htons(7) : htons(30000);
    sendAddr.sin_family = AF_INET;
    inet_pton(AF_INET, ip, &(sendAddr.sin_addr));
    
    // Set timeout
    // TODO
    struct timeval timeout;      
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;

    if (setsockopt (icmpfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
        perror("setsockopt failed\n");



    int finish = 0; // if the packet reaches the destination
    int maxHop = 64; // maximum hops
    struct icmp sendICMP; 
    struct timeval begin, end; // used to record RTT
    int seq = 0; // increasing sequence number for icmp packet
    int count = 3; // sending count for each ttl
    printf("traceroute to %s (%s), %d hops max\n", dest, ip, maxHop);
    
    for(int h = 1; h < maxHop; h++){
        
        //fprintf(stderr, "ok");
        char srcIP[count][32];
        char hostname[count][128];
        int usec_info[count];
        int noRespond = 0;
        for(int c = 0; c < count; c++){
            // Set ICMP Header
            // TODO
            if (mode == ICMP) {
                setsockopt(icmpfd, IPPROTO_IP, IP_TTL, &h, sizeof(h));
                memset(&sendICMP, 0, sizeof(sendICMP));
                sendICMP.icmp_code = 0;
                sendICMP.icmp_type = ICMP_ECHO;
                sendICMP.icmp_hun.ih_idseq.icd_id = 5566;
                sendICMP.icmp_hun.ih_idseq.icd_seq = seq;
                sendICMP.icmp_cksum = checksum((unsigned short *)&sendICMP, sizeof(sendICMP));
                sendto(icmpfd, (char*)&sendICMP, sizeof(sendICMP), 0, (const struct sockaddr *)&sendAddr, sizeof(sendAddr));
            }
            else if (mode == UDP) {
                setsockopt(udpfd, IPPROTO_IP, IP_TTL, &h, sizeof(h));
                char empty_packet;
                sendto(udpfd, (char*)&empty_packet, sizeof(empty_packet), 0, (struct sockaddr *)&sendAddr, sizeof(sendAddr));
            } else {
                // TODO
                setsockopt(tcpfd, IPPROTO_IP, IP_TTL, &h, sizeof(h));
                char datagram[4096];
                struct iphdr *iph = (struct iphdr *) datagram;
                struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
                char src_ip[32];
                get_local_ip(src_ip);
                set_ip_header(iph, datagram, h, src_ip, ip);
                set_tcp_header(tcph, 43591);
                tcph->check = checksum((unsigned short *)&tcph, sizeof(tcph));

                if (sendto(tcpfd, datagram , sizeof(struct iphdr) + sizeof(struct tcphdr) , 0 , (struct sockaddr *) &sendAddr, sizeof (sendAddr)) < 0){
                    printf ("Error sending syn packet. Error number : %d . Error message : %s \n" , errno , strerror(errno));
                    exit(1);
                }
            }

            gettimeofday(&begin, NULL);

            struct ip *recvIP;
            struct icmp *recvICMP;
            
            u_int8_t icmpType;
            char recvBuf[1500] = {};
            
            
            float interval[4] = {};
            memset(&recvAddr, 0, sizeof(struct sockaddr_in));
            int recv_size = sizeof(recvAddr);
            if(recvfrom(icmpfd, recvBuf, sizeof(recvBuf), 0,  &recvAddr, &recv_size) < 0){
                fprintf(stderr, "%2d * * *\n", h);
                noRespond = 1;
                break;
            }
            
            recvIP = (struct ip *)recvBuf;
            recvICMP = (struct icmp *) (recvBuf + recvIP->ip_hl * 4);
            icmpType = recvICMP -> icmp_type;
            if(icmpType == ICMP_TIMXCEED) {
                gettimeofday(&end, NULL);
                //fprintf(stderr, "stderr %ld %ld %ld %ld", begin.tv_sec, begin.tv_usec, end.tv_sec, end.tv_usec);
                usec_info[c] = (end.tv_sec - begin.tv_sec)*1000000 + (end.tv_usec - begin.tv_usec);
            }
            else if (icmpType == ICMP_UNREACH) {
                fprintf(stderr, "Unreachable\n");
            }
            else if(icmpType == ICMP_ECHOREPLY){
                if(recvICMP -> icmp_hun.ih_idseq.icd_id != 5566) {
                    printf("Different ID\n");
                }
                if(recvICMP -> icmp_hun.ih_idseq.icd_seq != 0) {
                    printf("Different Sequence Number\n");
                }
                gettimeofday(&end, NULL);
                //fprintf(stderr, "stderr %ld %ld %ld %ld", begin.tv_sec, begin.tv_usec, end.tv_sec, end.tv_usec);
                usec_info[c] = (end.tv_sec - begin.tv_sec)*1000000 + (end.tv_usec - begin.tv_usec);
                finish = 1;
            }
            // Get source hostname and ip address
            strcpy(srcIP[c], inet_ntoa(recvIP->ip_src));
            int ret = 0;
            if(ret = getnameinfo((struct sockaddr *)&recvAddr, sizeof(recvAddr), (char *)&hostname[c], sizeof(hostname[c]), NULL, 0, 0) < 0){
                //fprintf(stderr, "ret error\n");
                strcpy(hostname[c], srcIP[c]);
            }
            //fprintf(stderr, "recv hop: %d, c: %d\n", h, c+1);
            
        }
        if(!noRespond) Print_Format(h, hostname, srcIP, usec_info);

        if(finish){
            break;
        }
    }
    close(icmpfd);
    if (mode == UDP) close(udpfd);
    else if (mode == TCP) close(tcpfd);
    return 0;
}