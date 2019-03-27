#ifndef pcaptest_pcap_h
#define pcaptest_pcap_h

#define u_char unsigned char
#define u_short unsigned short
#define u_int unsigned int
typedef struct MAC_FRAME_HEADER
{
 char dmacaddr[6];    //目的mac地址
 char smacaddr[6];    //源mac地址
 short int pro_type;
}mac_header;
typedef struct ip_header
{
	u_char ver_ihl;
	u_char tos;
	u_short tlen;
	u_short id;
	u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    u_char  ttl;            // Time to live
    u_char  proto;          // Protocol
    u_short crc;            // Header checksum
    u_int  saddr;      // Source address
    u_int  daddr;      // Destination address
} ip_header;

//UDP header
typedef struct udp_header
{
	u_short sport;
	u_short dport;
	u_short len;  //ÊýŸÝ°ü³€¶È
	u_short crc;  //Ð£ÑéºÍ
}udp_header;

//tcp header
typedef struct tcp_header
{
	 u_short source_port;
	 u_short  destination_port;
	 u_int seq_number;  //ÐòÁÐºÅ
	 u_int ack_number; //È·ÈÏºÅ
	 u_short info_ctrl;//Ç°4Î»£ºTCPÍ·³€¶È£»ÖÐ6Î»£º±£Áô£»ºó6Î»£º±êÖŸÎ»
   u_short window;// Ž°¿ÚŽóÐ¡
	 u_short checksum;// ŒìÑéºÍ
	 u_short urgent_pointer; // œôŒ±ÊýŸÝÆ«ÒÆÁ¿
}tcp_header;


typedef struct pcap_file_header {
	u_int magic;
	u_short version_major;
	u_short version_minor;
	u_int thiszone;
	u_int sigfigs;
	u_int snaplen;
	u_int linktype;
}pcap_file_header;



typedef struct  timestamp{
	u_int timestamp_s;
	u_int timestamp_ms;
}timestamp;

typedef struct pcap_header{
	timestamp ts;
	u_int capture_len;
	u_int len;
}pcap_header;


#endif
