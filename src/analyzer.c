#include <pcap.h>
#include <stdio.h>
#include <stdlib.h> // for exit()
#include <string.h> //for memset

#include <sys/socket.h>
#include <arpa/inet.h> // for inet_ntoa()
#include <netinet/udp.h>   //Provides declarations for udp header
#include <netinet/tcp.h>   //Provides declarations for tcp header
//#include <netinet/ip.h>    //Provides declarations for ip header

#include "analyzer.h"

void decode_ethernet(const u_char *header_start)
{
    int i;
    struct ether_hdr *eth;
    eth = (struct ether_hdr *)header_start;

    printf("[[  Layer 2 :: Ethernet Header  ]]\n");
    printf("[ Source: %02x", eth->ether_src_addr[0]);
    for (i = 1; i < ETHER_ADDR_LEN; i++)
        printf(":%02x", eth->ether_src_addr[i]);

    printf("\tDest: %02x", eth->ether_dest_addr[0]);
    for (i = 1; i < ETHER_ADDR_LEN; i++)
        printf(":%02x", eth->ether_dest_addr[i]);
    printf("\tTYpe: %hu ]\n", eth->ether_type);
}
u_int decode_ip(const u_char * header_start)
{
    const struct ip_hdr *iph;
    struct sockaddr_in src, dest;

    iph = (const struct ip_hdr *)header_start;
    memset(&src, 0, sizeof(src));
    src.sin_addr.s_addr = iph->ip_src_addr;
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->ip_dest_addr;

    printf("\t((  Layet 3 ::: IP Header   ))\n");
    printf("\t(  TTL : %d\n", (unsigned int)iph->ip_ttl);
    printf("\t(  Source %s\t", inet_ntoa(src.sin_addr));
    printf("Dest: %s )\n", inet_ntoa(dest.sin_addr));
    printf("\t(  Type: %u\t", (u_int) iph->ip_type);
    printf("ID: %hu\tLength: %hu )\n", ntohs(iph->ip_id), ntohs(iph->ip_len));

    if (iph->ip_type == 6) //tcp 
    	    return decode_tcp(header_start + sizeof(struct ip_hdr));
    return decode_udp(header_start + sizeof(struct ip_hdr));
}

u_int decode_tcp(const u_char *header_start)
{
    u_int header_size;
    const struct tcp_hdr *tcph;
    tcph = (const struct tcp_hdr *)header_start;
    header_size =  4 * tcph->tcp_offset;

    printf("\t\t{{   Layer 4 :::: TCP Header   }}\n");
    printf("\t\t{  Src Port: %hu\t", ntohs(tcph->tcp_src_port));
    printf("Dst Port: %hu }\n", ntohs(tcph->tcp_dest_port));
    printf("\t\t{  Seq #: %u\t", ntohl(tcph->tcp_seq));
    printf("Ack #: %u }\n", ntohl(tcph->tcp_ack));
    printf("\t\t{  Header Size: %u\tFlags: ", header_size);
    if (tcph->tcp_flags & TCP_FIN)
        printf("FIN ");
    if (tcph->tcp_flags & TCP_RST)
        printf("RST ");
    if (tcph->tcp_flags & TCP_PUSH)
        printf("PUSH ");
    if (tcph->tcp_flags & TCP_ACK)
        printf("ACK ");
    if (tcph->tcp_flags & TCP_URG)
        printf("URG ");
    printf(" }\n");
    
    return header_size;
}

u_int decode_udp(const u_char *header_start)
{
    u_int header_size;

    struct udphdr *udph = (struct udphdr*)header_start;
    header_size =  header_start + sizeof(struct udphdr);
    printf("\t\t{{   Layer 4 :::: UDP Header   }}\n");
    printf("\t\t{  Src Port: %hu\t", ntohs(udph->source));
    printf("Dst Port: %hu }\n", ntohs(udph->dest));
    printf(" }\n");
    return header_size;
}

void dump(const unsigned char *buffer, const unsigned int length)
{
    unsigned char byte;
    unsigned int i, j;

    for (i = 0; i < length; i++) {
        byte = buffer[i];
        /* Display byte in hex */
        printf("%02x ", buffer[i]);
        if (((i % 16) == 15) || (i == length - 1)) {
            for (j = 0; j < 15 - (i%16); ++j)
                printf("    ");
            printf("| ");
            /* Display printable bytes from line */
            for (j = i-(i%16); j <= i; ++j) {
                byte = buffer[j];
                /* outside printable char range */
                if ((byte > 31) && (byte < 127)) 
                    printf("%c", byte);
                else
                    printf(".");
            }
            /* End of the dump line (each line is 16 bytes) */
            printf("\n"); 
        }
    }
}
