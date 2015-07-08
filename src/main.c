#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>

#include "analyzer.h"

void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void map_protocol2filter(struct commands *);
struct commands *parser(int, char **);

int main(int argc, char *argv[] )
{ 
    char errbuf[PCAP_ERRBUF_SIZE];
    char *device; 
    pcap_t *pcap_handle;            /* Pointer to the device that will be sniffed. */
    struct bpf_program filter;      /* Plcae to store the BPF filter program */
    bpf_u_int32 netaddr =0, mask = 0;
    struct commands *coms;
    

    /* Get the name of the first device suitable for capture */ 
    if (argc < 2) {
        if ((device = pcap_lookupdev(errbuf)) == NULL) {
            fprintf(stderr, "ERROR: %s\n", errbuf);
            return -1;
        }
    } else {
        coms = parser(argc, argv);
        device = coms->device;
    }

    printf("Opening device %s\n", device); 
    pcap_handle = pcap_open_live(device, MAXBYTES2CAPTURE, 0, 512, errbuf);
    if (pcap_handle == NULL) {
        fprintf(stderr, "ERROR: %s\n", errbuf);
        return -1;
    }
    
    if (argc > 2 && coms->is_filtered == 1) {
        pcap_lookupnet(device, &netaddr, &mask, errbuf);
        pcap_compile(pcap_handle, &filter, coms->filter, 1, mask);
        pcap_setfilter(pcap_handle, &filter);
    }

    pcap_loop(pcap_handle, -1, process_packet, NULL);
    pcap_close(pcap_handle);
    
    return 0; 
} 

void
process_packet(u_char *user_args, const struct pcap_pkthdr *cap_header, const u_char *packet)
{
    int header_length, total_header_size, pkt_data_len;
    u_char *pkt_data;

    printf("==== Got a %d byte packet ====\n", cap_header->len);

    decode_ethernet(packet);
    header_length = decode_ip(packet + ETHER_HDR_LEN);

    total_header_size = ETHER_HDR_LEN + sizeof(struct ip_hdr) + header_length;
    pkt_data = (u_char *)packet + total_header_size; 
    pkt_data_len = cap_header->len - total_header_size;

    if (pkt_data_len > 0) {
        printf("\t\t\t%u bytes of packet data\n", pkt_data_len);
        dump(pkt_data, pkt_data_len);
    } else {
        printf("\t\t\tNo Packet Data\n");
    }
}

struct commands *parser(int argc, char *argv[])
{
    struct commands *coms = (struct commands *)malloc(sizeof(struct commands));
    int i;

    for (i = 1; i < argc ; ++i) {
        if (strncmp(argv[i], "--interface", 9) == 0) {
           if (i+1 < argc) {
                coms->device = malloc(50);
                coms->device = argv[++i];
                printf("device = %s\n", coms->device);
           }
        }
        if (strncmp(argv[i], "--protocol", 10) == 0) {
           if (i+1 < argc) {
               // check if it's valid
                coms->protocol = malloc(50);
                coms->protocol = argv[++i];
                printf("protocol = %s\n", coms->protocol);
                map_protocol2filter(coms);
                printf("proto->filter = %s\n", coms->filter);
           }
        }
        if (strncmp(argv[i], "--filter", 8) == 0) {
           if (i+1 < argc) {
                coms->filter = malloc(100);
                coms->filter = argv[++i];
                coms->is_filtered = 1;
                printf("filter = %s\n", coms->filter);
           }
        }
        if (strncmp(argv[i], "--log", 5) == 0) {
           if (i+1 < argc) {
                coms->filename = malloc(100);
                coms->filename = argv[++i];
                printf("filename = %s\n", coms->filename);
           }
        }
    }

    return coms;
}

void map_protocol2filter(struct commands *coms)
{
    coms->is_filtered = 1;
    if (strncmp(coms->protocol, "http", 4) == 0) 
        coms->filter = "tcp and (dst port 80 or dst port 8080)";
    else if (strncmp(coms->protocol, "tcp", 3) == 0)
        coms->filter = "tcp";
    else if (strncmp(coms->protocol, "udp", 3) == 0)
        coms->filter = "udp";
    else if (strncmp(coms->protocol, "https", 5) == 0)
        coms->filter = "tcp and (dst port 443)";
    else if (strncmp(coms->protocol, "ssh", 3) == 0)
        coms->filter = "dst port 22";
    else if (strncmp(coms->protocol, "telnet", 6) == 0)
        coms->filter = "dst port 23";
    else if (strncmp(coms->protocol, "smtp", 5) == 0)
        coms->filter = "dst port 25";
    else if (strncmp(coms->protocol, "icmp", 4) == 0)
        coms->filter = "icmp[icmptype] != icmp-echo and icmp[icmptype] !+ icmp-echoreply";
    else
        coms->is_filtered = 0;
    
    return;
}
