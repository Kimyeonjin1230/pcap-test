#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
//#include "libnet.h"
#define LIBNET_H
#define __LIBNET_HEADERS_H
#define ETHER_ADDR_LEN 6
#define ETHERTYPE_IP            0x0800  /* IP protocol */

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;


Param param = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

struct libnet_ethernet_hdr
{
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
};


struct libnet_ipv4_hdr
{
#if (LIBNET_LIL_ENDIAN)
    u_int8_t ip_hl,ip_v;      /* header length */        /* version */
#endif
#if (LIBNET_BIG_ENDIAN)
    u_int8_t ip_v:4,       /* version */
           ip_hl:4;        /* header length */
#endif
 u_int8_t ip_tos;       /* type of service */


    u_int16_t ip_len;         /* total length */
    u_int16_t ip_id;          /* identification */
    u_int16_t ip_off;

#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
#endif
    u_int8_t ip_ttl;          /* time to live */
    u_int8_t ip_p;            /* protocol */
    u_int16_t ip_sum;         /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};

struct libnet_tcp_hdr
{
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int32_t th_seq;          /* sequence number */
    u_int32_t th_ack;          /* acknowledgement number */
#if (LIBNET_LIL_ENDIAN)
    u_int8_t th_x2, th_off:4;           /* (unused) */
                /* data offset */
#endif
#if (LIBNET_BIG_ENDIAN)
    u_int8_t th_off,  th_x2:4;          /* data offset */
                /* (unused) */
#endif
    u_int8_t  th_flags;       /* control flags */
#ifndef TH_FIN
#define TH_FIN    0x01      /* finished send data */
#endif
#ifndef TH_SYN
#define TH_SYN    0x02      /* synchronize sequence numbers */
#endif
#ifndef TH_RST
#define TH_RST    0x04      /* reset the connection */
#endif
#ifndef TH_PUSH
#define TH_PUSH   0x08      /* push data to the app layer */
#endif
#ifndef TH_ACK
#define TH_ACK    0x10      /* acknowledge */
#endif
#ifndef TH_URG
#define TH_URG    0x20      /* urgent! */
#endif
#ifndef TH_ECE
#define TH_ECE    0x40
#endif
#ifndef TH_CWR
#define TH_CWR    0x80
#endif
    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
};




int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf); //device, snaplen, PROMISCUOUS, 1000, errbuf


    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf); //param.dev_ : interface
        return -1;
    }

//error
    while (true) {
        struct pcap_pkthdr* header;
        struct libnet_ethernet_hdr *ethernet;
        struct libnet_ipv4_hdr *ipv4;
        struct libnet_tcp_hdr *tcp;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        printf("%u bytes captured\n", header->caplen); //byte 단위

        ethernet = (struct libnet_ethernet_hdr *)packet;
        if (ntohs(ethernet->ether_type) != ETHERTYPE_IP) continue;
        //printf("type = %04x \n", ntohs(ethernet->ether_type));

        ipv4 = (struct libnet_ipv4_hdr *) (packet+sizeof(*ethernet));

         printf("IP : %x\n", ipv4->ip_p );

        if (ipv4->ip_p != IPPROTO_TCP) continue;


        printf("Src mac add : ");
        for (int i=0; i<ETHER_ADDR_LEN; i++){
            if(i == ETHER_ADDR_LEN-1){
                printf("%02X\n", ethernet->ether_shost[i]);
            }
            else {
                printf("%02X", ethernet->ether_dhost[i]);
            }
        }
        printf("Dst mac add : ");
        for (int i=0; i<ETHER_ADDR_LEN; i++){
            if(i == ETHER_ADDR_LEN-1){
                printf ("%02X:\n,", ethernet->ether_dhost[i]);
            }
            else{
                printf("%02X:", ethernet->ether_dhost[i]);
            }
        }




        printf("proto = %d \n", ipv4->ip_p);

        printf("<IPv4>\n");
        u_int8_t ip1, ip2, ip3, ip4;
        uint32_t sip = ntohl(ipv4->ip_src.s_addr);
        uint32_t dip = ntohl(ipv4->ip_dst.s_addr);


        printf("src IP address : ");

        ip1 = (sip & 0xff000000) >> 24;
        ip2 = (sip & 0x00ff0000) >> 16;
        ip3 = (sip & 0x0000ff00) >> 8;
        ip4 = (sip & 0x000000ff);
        printf("%d.%d.%d.%d\n",ip1,ip2,ip3,ip4);

        printf("dst IP address : ");
        ip1 = (dip & 0xff000000) >> 24;
        ip2 = (dip & 0x00ff0000) >> 16;
        ip3 = (dip & 0x0000ff00) >> 8;
        ip4 = (dip & 0x000000ff);
        printf("%d.%d.%d.%d\n",ip1,ip2,ip3,ip4);



        tcp = (struct libnet_tcp_hdr *) (packet+sizeof(*ethernet)+sizeof(*ipv4));

        printf("Source PORT : ");
        printf("%d\n",ntohs(tcp->th_sport));
        printf("Destination PORT : ");
        printf("%d\n",ntohs(tcp->th_dport));


//        u_int32_t hsize = 14 + sizeof(ipv4->ip_hl * 4) + sizeof(tcp->th_off * 4);


//        printf("Payload(Data) : ");
//        for(int i=hsize; i<hsize+8 && i<header->caplen; i++){
//            printf("0x%02X", packet[i]);
//        }
        printf("\n\n");
    }
    pcap_close(pcap);
}


