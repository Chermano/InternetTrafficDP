#include "stdio.h"
#include "string.h"
#include "winsock2.h"   //need winsock for inet_ntoa and ntohs methods

#define HAVE_REMOTE
#include "pcap.h"   //Winpcap :)

#pragma comment(lib , "ws2_32.lib") //For winsock
#pragma comment(lib , "wpcap.lib") //For winpcap

//some packet processing functions
void ProcessPacket(u_char*, int, int); //This will decide how to digest
void sortTCPpacket(u_char*, int);
void sortUDPpacket(u_char*, int);
int inarray(u_int);

// Set the packing to a 1 byte boundary
//#include "pshpack1.h"
//Ethernet Header
typedef struct ethernet_header
{
	UCHAR dest[6];
	UCHAR source[6];
	USHORT type;
}   ETHER_HDR, *PETHER_HDR, FAR * LPETHER_HDR, ETHERHeader;

//Ip header (v4)
typedef struct ip_hdr
{
	unsigned char ip_header_len : 4; // 4-bit header length (in 32-bit words) normally=5 (Means 20 Bytes may be 24 also)
	unsigned char ip_version : 4; // 4-bit IPv4 version
	unsigned char ip_tos; // IP type of service
	unsigned short ip_total_length; // Total length
	unsigned short ip_id; // Unique identifier

	unsigned char ip_frag_offset : 5; // Fragment offset field

	unsigned char ip_more_fragment : 1;
	unsigned char ip_dont_fragment : 1;
	unsigned char ip_reserved_zero : 1;

	unsigned char ip_frag_offset1; //fragment offset

	unsigned char ip_ttl; // Time to live
	unsigned char ip_protocol; // Protocol(TCP,UDP etc)
	unsigned short ip_checksum; // IP checksum
	unsigned int ip_srcaddr; // Source address
	unsigned int ip_destaddr; // Source address
} IPV4_HDR;

//UDP header
typedef struct udp_hdr
{
	unsigned short source_port; // Source port no.
	unsigned short dest_port; // Dest. port no.
	unsigned short udp_length; // Udp packet length
	unsigned short udp_checksum; // Udp checksum (optional)
} UDP_HDR;

// TCP header
typedef struct tcp_header
{
	unsigned short source_port; // source port
	unsigned short dest_port; // destination port
	unsigned int sequence; // sequence number - 32 bits
	unsigned int acknowledge; // acknowledgement number - 32 bits

	unsigned char ns : 1; //Nonce Sum Flag Added in RFC 3540.
	unsigned char reserved_part1 : 3; //according to rfc
	unsigned char data_offset : 4; /*The number of 32-bit words in the TCP header.
								   This indicates where the data begins.
								   The length of the TCP header is always a multiple
								   of 32 bits.*/

	unsigned char fin : 1; //Finish Flag
	unsigned char syn : 1; //Synchronise Flag
	unsigned char rst : 1; //Reset Flag
	unsigned char psh : 1; //Push Flag
	unsigned char ack : 1; //Acknowledgement Flag
	unsigned char urg : 1; //Urgent Flag

	unsigned char ecn : 1; //ECN-Echo Flag
	unsigned char cwr : 1; //Congestion Window Reduced Flag

	////////////////////////////////

	unsigned short window; // window
	unsigned short checksum; // checksum
	unsigned short urgent_pointer; // urgent pointer
} TCP_HDR;

typedef struct icmp_hdr
{
	BYTE type; // ICMP Error type
	BYTE code; // Type sub code
	USHORT checksum;
	USHORT id;
	USHORT seq;
} ICMP_HDR;
// Restore the byte boundary back to the previous value
//#include <poppack.h>

FILE *logfile;
int tcp = 0, udp = 0, icmp = 0, others = 0, igmp = 0, total = 0, i, j;
struct sockaddr_in source, dest;
char hex[2];

//Its free!
ETHER_HDR *ethhdr;
IPV4_HDR *iphdr;
TCP_HDR *tcpheader;
UDP_HDR *udpheader;
ICMP_HDR *icmpheader;
u_char *data;
u_int ignlist[100];
u_int games = 0;
u_int files = 0;
u_int skype = 0;
int counter = 0;

int main()
{
	u_int i, res, inum;
	u_char errbuf[PCAP_ERRBUF_SIZE], buffer[100];
	u_char *pkt_data;
	struct tm tbreak;
	pcap_if_t *alldevs, *d;
	pcap_t *fp;
	struct pcap_pkthdr *header;
	struct bpf_program filtptr;		/* The compiled filter expression */
	char filter_exp[24] = "dst host ";	/* The filter expression */
	char filter_ip[15];
	bpf_u_int32 mask;		/* The netmask of our sniffing device */
	bpf_u_int32 net;		/* The IP of our sniffing device */



	/* The user didn't provide a packet source: Retrieve the local device list */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
		return -1;
	}

	i = 0;
	/* Print the list */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s\n    ", ++i, d->name);

		if (d->description)
		{
			printf(" (%s)\n", d->description);
		}
		else
		{
			printf(" (No description available)\n");
		}
	}

	if (i == 0)
	{
		fprintf(stderr, "No interfaces found! Exiting.\n");
		return -1;
	}

	printf("Enter the interface number you would like to sniff : ");
	scanf_s("%d", &inum);


	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i< inum - 1; d = d->next, i++);

	/* Open the device */
	if ((fp = pcap_open(d->name,
		100 /*snaplen*/,
		PCAP_OPENFLAG_PROMISCUOUS /*flags*/,
		20 /*read timeout*/,
		NULL /* remote authentication */,
		errbuf)
		) == NULL)
	{
		fprintf(stderr, "\nError opening adapter\n");
		return -1;
	}

	printf("Please enter your IP: ");
	scanf("%s", filter_ip);
	strcat(filter_exp, filter_ip);



	pcap_lookupnet(d, &net, &mask, errbuf);
	if (pcap_compile(fp, &filtptr, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(fp));
		return(2);
	}
	if (pcap_setfilter(fp, &filtptr) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(fp));
		return(2);
	}

	//read packets in a loop :)
	while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0)
	{
		if (res == 0)
		{
			// Timeout elapsed
			continue;
		}
		
		ProcessPacket(pkt_data, header->caplen, header->len);
	}

	if (res == -1)
	{
		fprintf(stderr, "Error reading the packets: %s\n", pcap_geterr(fp));
		return -1;
	}

	return 0;
}

void ProcessPacket(u_char* Buffer, int Size, int pktlen)
{
	//Ethernet header
	ethhdr = (ETHER_HDR *)Buffer;
	++total;

	//Ip packets
	if (ntohs(ethhdr->type) == 0x0800)
	{
		//ip header
		iphdr = (IPV4_HDR *)(Buffer + sizeof(ETHER_HDR));

		switch (iphdr->ip_protocol) //Check the Protocol and do accordingly...
		{
		case 6: //TCP Protocol
			tcp++;
			sortTCPpacket(Buffer, pktlen);
			break;

		case 17: //UDP Protocol
			udp++;
			sortUDPpacket(Buffer, pktlen);
			break;
		}
	}

	printf("Games : %d Files : %d Skype : %d TCP : %d UDP : %d\r", games, files, skype, tcp, udp);
}







void sortTCPpacket(u_char* Buffer, int size)
{
	u_char srcaddr;
	int iphdrlen = 0;

	iphdr = (IPV4_HDR *)(Buffer + sizeof(ETHER_HDR));
	iphdrlen = iphdr->ip_header_len * 4;

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iphdr->ip_srcaddr;
	srcaddr = inet_ntoa(source.sin_addr);


	if ((size == 1514) || (size == 1434))
	{
		
		if (counter == 100)
			return;
		if (inarray(iphdr->ip_srcaddr) == 0)
		{
			ignlist[counter] = iphdr->ip_srcaddr;
			counter++;
			files++;
		}

	}
}

void sortUDPpacket(u_char* Buffer, int size)
{
	u_char srcaddr;
	int iphdrlen = 0;

	iphdr = (IPV4_HDR *)(Buffer + sizeof(ETHER_HDR));
	iphdrlen = iphdr->ip_header_len * 4;
	udpheader = (UDP_HDR*)(Buffer + iphdrlen + sizeof(ETHER_HDR));

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iphdr->ip_srcaddr;
	srcaddr = inet_ntoa(source.sin_addr);


	if (((size == 66) || (size == 76)) && ntohs(udpheader->source_port) != 53)
	{
		if (counter == 100)
			return;
		if (inarray(iphdr->ip_srcaddr) == 0)
		{
			ignlist[counter] = iphdr->ip_srcaddr;
			counter++;
			games++;
		}

	}
	else if ((ntohs(udpheader->source_port) > 1024) && (size >150) && (size < 300))
	{
		if (counter == 100)
			return;
		if (inarray(iphdr->ip_srcaddr) == 0)
		{
			ignlist[counter] = iphdr->ip_srcaddr;
			counter++;
			skype++;
		}
	}
}

int inarray(u_int addr)
{
	int ret = 0;
	for (int i = 0; i < counter; i++)
	{
		if (addr == ignlist[i])
			ret = 1;
	}
	return ret;
}
