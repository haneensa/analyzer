#define MAXBYTES2CAPTURE 2048 


struct commands {
    char *protocol;
    char *filter;
    int is_filtered;
    char *filename;
    char *device;
};

/*  Ethernet frame header, org defined in: /usr/include/if_ether.h */

#define ETHER_ADDR_LEN 6
#define ETHER_HDR_LEN 14

struct ether_hdr {
    unsigned char ether_dest_addr[ETHER_ADDR_LEN];  // Destination MAC address
    unsigned char ether_src_addr[ETHER_ADDR_LEN];   // Source MAC address 
    unsigned short ether_type;                      // Type of Ethernet packet
};

/* IP Header, defined in: /usr/include/netinet/ip.h */
/* 20 bytes */
struct ip_hdr {
    unsigned char ip_version_and_header_length;     // Version and header length
    unsigned char ip_tos;                           // Type of service
    unsigned short ip_len;                          // Total length
    unsigned short ip_id;                           //  Identification number 
    unsigned short ip_frag_offset;
    unsigned char ip_ttl;
    unsigned char ip_type;
    unsigned short ip_checksum;
    unsigned int ip_src_addr;
    unsigned int ip_dest_addr;
};

/* TCP Header, defined in: /usr/include/netinet/tcp.h */
/* 32 bit aligned, data offset tells us how many 4 bytes in words in the header */
struct tcp_hdr {
    unsigned short tcp_src_port;                // Source TCP port
    unsigned short tcp_dest_port;               // Destination TCP port
    unsigned int tcp_seq;                       // TCP sequence number
    unsigned int tcp_ack;                       // TCP acknowledgement number
    unsigned char reserved:4;                   // 4 bits from the 6 bits of reserved space
    unsigned char tcp_offset:4;
    unsigned char tcp_flags;
#define TCP_FIN    0x01
#define TCP_SYN    0x02
#define TCP_RST    0x04
#define TCP_PUSH   0x08
#define TCP_ACK    0x010
#define TCP_URG    0x020
    unsigned short tcp_window;
    unsigned short tcp_checksum;
    unsigned short tcp_urgent;
};

void decode_ethernet(const u_char *header_start);
u_int decode_ip(const u_char *);
u_int decode_tcp(const u_char *);
void dump(const unsigned char *, const unsigned int);
u_int decode_udp(const u_char *);
