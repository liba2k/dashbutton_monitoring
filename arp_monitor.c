
#define APP_NAME        "ARP monitor"
#define APP_DESC        "ARP monitor using libpcap"
#define APP_COPYRIGHT   "Copyright (c) 2017"
#define APP_DISCLAIMER  "THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM."
#include <sys/stat.h>
#include <unistd.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN  6

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

struct sniff_arp_eth_ipv4 {
        u_short hw_type;
        u_short protocol_type;
        u_char  hw_size;
        u_char  protocol_size;
        u_short opcode;
        u_char  sendr_mac[ETHER_ADDR_LEN];    /* source host address */
        u_long  sendr_ip;
        u_char  target_mac[ETHER_ADDR_LEN];    /* source host address */
        u_long  target_ip;
};


void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void
print_hex_ascii_line(const u_char *payload, int len, int offset);

void
print_app_banner(void);

void
print_app_usage(void);

/*
 * app name/banner
 */
void
print_app_banner(void)
{

    printf("%s - %s\n", APP_NAME, APP_DESC);
    printf("%s\n", APP_COPYRIGHT);
    printf("%s\n", APP_DISCLAIMER);
    printf("\n");

return;
}

/*
 * print help text
 */
void
print_app_usage(void)
{

    printf("Usage: %s [interface]\n", APP_NAME);
    printf("\n");
    printf("Options:\n");
    printf("    interface    Listen on <interface> for packets.\n");
    printf("\n");

return;
}

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

    int i;
    int gap;
    const u_char *ch;

    /* offset */
    printf("%05d   ", offset);
    
    /* hex */
    ch = payload;
    for(i = 0; i < len; i++) {
        printf("%02x ", *ch);
        ch++;
        /* print extra space after 8th byte for visual aid */
        if (i == 7)
            printf(" ");
    }
    /* print space to handle line less than 8 bytes */
    if (len < 8)
        printf(" ");
    
    /* fill hex gap with spaces if not full line */
    if (len < 16) {
        gap = 16 - len;
        for (i = 0; i < gap; i++) {
            printf("   ");
        }
    }
    printf("   ");
    
    /* ascii (if printable) */
    ch = payload;
    for(i = 0; i < len; i++) {
        if (isprint(*ch))
            printf("%c", *ch);
        else
            printf(".");
        ch++;
    }

    printf("\n");

return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len)
{

    int len_rem = len;
    int line_width = 16;            /* number of bytes per line */
    int line_len;
    int offset = 0;                 /* zero-based offset counter */
    const u_char *ch = payload;

    if (len <= 0)
        return;

    /* data fits on one line */
    if (len <= line_width) {
        print_hex_ascii_line(ch, len, offset);
        return;
    }

    /* data spans multiple lines */
    for ( ;; ) {
        /* compute current line length */
        line_len = line_width % len_rem;
        /* print line */
        print_hex_ascii_line(ch, line_len, offset);
        /* compute total remaining */
        len_rem = len_rem - line_len;
        /* shift pointer to remaining bytes to print */
        ch = ch + line_len;
        /* add offset */
        offset = offset + line_width;
        /* check if we have line width chars or less */
        if (len_rem <= line_width) {
            /* print last line and get out */
            print_hex_ascii_line(ch, len_rem, offset);
            break;
        }
    }

return;
}

int file_exist(char *filename)
{
  struct stat   buffer;   
  return (stat (filename, &buffer) == 0);
}

/*
 * dissect/print packet
 */
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

    static int count = 1;                   /* packet counter */
    
    /* declare pointers to packet headers */
    const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
    const struct sniff_arp_eth_ipv4 *arp;
    const struct sniff_ip *ip;              /* The IP header */
    const struct sniff_tcp *tcp;            /* The TCP header */
    const char *payload;                    /* Packet payload */

    int size_ip;
    int size_tcp;
    int size_payload;
    
    // printf("\nPacket number %d:\n", count);
    count++;
    
    /* define ethernet header */
    ethernet = (struct sniff_ethernet*)(packet);
    // printf("%x\n", ethernet->ether_type);
    if (ethernet->ether_type == 0x0608) //arp
    {
        arp = (struct sniff_arp_eth_ipv4*)(packet + SIZE_ETHERNET);
        // printf("%x %x %x\n", ntohs(arp->hw_type), ntohs(arp->protocol_type), ntohl(arp->sendr_ip));
        if (ntohs(arp->hw_type) != 1 || ntohs(arp->protocol_type) != 0x800)
            return; // not Ethernet IPv4
        // if (ntohl(arp->sendr_ip) != 0)
        //     return; // not ARP Probe
        char filename[1024];
        snprintf(filename, sizeof(filename), "/opt/buttons/%02x_%02x_%02x_%02x_%02x_%02x", 
            ethernet->ether_shost[0], ethernet->ether_shost[1], ethernet->ether_shost[2], 
            ethernet->ether_shost[3], ethernet->ether_shost[4], ethernet->ether_shost[5]);
        printf("Checking %s\n", filename);

        if (file_exist(filename))
        {
            int pid = fork();
            if (pid == 0){
                execlp("/bin/sh","/bin/sh","-c",filename,NULL);
            }
        }
        
    }

return;
}

int main(int argc, char **argv)
{

    char *dev = NULL;           /* capture device name */
    char errbuf[PCAP_ERRBUF_SIZE];      /* error buffer */
    pcap_t *handle;             /* packet capture handle */

    char filter_exp[] = "arp";       /* filter expression [3] */
    struct bpf_program fp;          /* compiled filter program (expression) */
    bpf_u_int32 mask;           /* subnet mask */
    bpf_u_int32 net;            /* ip */
    int num_packets = -1;           /* number of packets to capture */

    print_app_banner();
    signal(SIGCHLD, SIG_IGN);

    /* check for capture device name on command-line */
    if (argc == 2) {
        dev = argv[1];
    }
    else if (argc > 2) {
        fprintf(stderr, "error: unrecognized command-line options\n\n");
        print_app_usage();
        exit(EXIT_FAILURE);
    }
    else {
        /* find a capture device if not specified on command-line */
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
            fprintf(stderr, "Couldn't find default device: %s\n",
                errbuf);
            exit(EXIT_FAILURE);
        }
    }
    
    /* get network number and mask associated with capture device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
            dev, errbuf);
        net = 0;
        mask = 0;
    }

    /* print capture info */
    printf("Device: %s\n", dev);
    printf("Number of packets: %d\n", num_packets);
    printf("Filter expression: %s\n", filter_exp);

    /* open capture device */
    handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit(EXIT_FAILURE);
    }

    /* make sure we're capturing on an Ethernet device [2] */
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "%s is not an Ethernet\n", dev);
        exit(EXIT_FAILURE);
    }

    /* compile the filter expression */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n",
            filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    /* apply the compiled filter */
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n",
            filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    /* now we can set our callback function */
    pcap_loop(handle, num_packets, got_packet, NULL);

    /* cleanup */
    pcap_freecode(&fp);
    pcap_close(handle);

    printf("\nCapture complete.\n");

return 0;
}
