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
unsigned short TCPCheckSum(unsigned short *buffer, int size){
    unsigned long cksum=0;
    while(size >1)
    {
        cksum+=*buffer++;
        size -=sizeof(unsigned short);
    }
    if(size)
        cksum += *(unsigned char*)buffer;

    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >>16);
    return (unsigned short)(~cksum);
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
    char *dest = argv[1];
    //fprintf(stderr, "%s\n", argv[1]);
    char *ip = DNSLookup(dest);
    if(ip == NULL){
        printf("traceroute: unknown host %s\n", dest);
        exit(1);
    }
    fprintf(stderr, "dest ip: %s\n", ip);
    int fd;
    if((fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0){
        printf("Can not open socket\n");
        exit(1);
    }
    struct sockaddr_in sendAddr;
    sendAddr.sin_port = htons (30000);
    sendAddr.sin_family = AF_INET;
    inet_pton(AF_INET, ip, &(sendAddr.sin_addr));
    //TCP header
    char datagram[4096];
    int ttl = 31;
    struct iphdr *iph = (struct iphdr *) datagram;
    struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
    char src_ip[32];
    get_local_ip(src_ip);
    set_ip_header(iph, datagram, ttl, src_ip, ip);
    set_tcp_header(tcph, 43591);
    tcph->check = checksum((unsigned short *)&tcph, sizeof(tcph));
    // Set timeout
    // TODO
    struct timeval timeout = {3, 0};

    int one = 1;
    if (setsockopt (fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof (one)) < 0){
        printf ("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n" , errno , strerror(errno));
        exit(0);
    }

    if (setsockopt (fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
        perror("setsockopt failed\n");

    /*int h = 1;
    if(setsockopt(fd, IPPROTO_IP, IP_TTL, &h, sizeof(h)) < 0)
        perror("setsockopt failed\n");
    */
    if (sendto(fd, datagram , sizeof(struct tcphdr) , 0 , (struct sockaddr *) &sendAddr, sizeof (sendAddr)) < 0){
            printf ("Error sending syn packet. Error number : %d . Error message : %s \n" , errno , strerror(errno));
            exit(0);
    }
    close(fd);
    return 0;
}