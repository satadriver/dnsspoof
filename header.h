
/*
 * header.h
 *
 *  Created on: Apr 29, 2016
 *      Author: jiaziyi
 */

/* Copyright (C) 1991,92,93,95,96,97,98,99,2000 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

#ifdef _WIN32
#define u_int16_t   unsigned short
#define u_int32_t   unsigned int
#define u_int8_t    unsigned char
#endif

//typedef struct mystructs {
//    uint16_t seg1 : 4;
//    uint16_t seg2 : 4;
//    uint16_t seg3 : 4;
//    uint16_t seg4 : 4;
//} mystructs;

#ifndef HEADER_H_
#define HEADER_H_



//#define __BYTE_ORDER __LITTLE_ENDIAN


//TCP header

//	0                   1                   2                   3
//	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|          Source Port          |       Destination Port        |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                        Sequence Number                        |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                    Acknowledgment Number                      |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|  Data |           |U|A|P|R|S|F|                               |
//	| Offset| Reserved  |R|C|S|S|Y|I|            Window             |
//	|       |           |G|K|H|T|N|N|                               |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|           Checksum            |         Urgent Pointer        |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                    Options                    |    Padding    |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                             data                              |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//



//ipv4 header

//	0                   1                   2                   3
//	  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	 |Version|  IHL  |Type of Service|          Total Length         |
//	 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	 |         Identification        |Flags|      Fragment Offset    |
//	 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	 |  Time to Live |    Protocol   |         Header Checksum       |
//	 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	 |                       Source Address                          |
//	 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	 |                    Destination Address                        |
//	 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	 |                    Options                    |    Padding    |
//	 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+










//ethernet header


#define ETH_ALEN	6		/* Octets in one ethernet addr	 */

#ifdef __linux__

struct ethhdr {
	unsigned char	h_dest[ETH_ALEN];	/* destination eth addr	*/
	unsigned char	h_source[ETH_ALEN];	/* source ether addr	*/
	unsigned short	h_proto;		/* packet type ID field	*/
} __attribute__((packed));


struct iphdr6
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int vlc;
    //unsigned int label : 20;
    //unsigned int class : 8;
    //unsigned int version : 4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned int vlc;
    //unsigned int version : 4;
    //unsigned int class : 8;
    //unsigned int label : 20;
#else
# error	"Please fix <bits/endian.h>"
#endif

    u_int16_t pll;

    u_int8_t next;

    u_int8_t ttl;

    u_char sip[16];
    u_char dip[16];
}__attribute__((packed));

struct iphdr
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ihl : 4;
    unsigned int version : 4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned int version : 4;
    unsigned int ihl : 4;
#else
# error	"Please fix <bits/endian.h>"
#endif
    u_int8_t tos;
    u_int16_t tot_len;
    u_int16_t id;
    u_int16_t frag_off;
    u_int8_t ttl;
    u_int8_t protocol;
    u_int16_t check;
    u_int32_t saddr;
    u_int32_t daddr;
    /*The options start here. */
}__attribute__((packed));

struct tcphdr
{
    u_int16_t source;
    u_int16_t dest;
    u_int32_t seq;
    u_int32_t ack_seq;
#  if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int16_t res1 : 4;
    u_int16_t doff : 4;
    u_int16_t fin : 1;
    u_int16_t syn : 1;
    u_int16_t rst : 1;
    u_int16_t psh : 1;
    u_int16_t ack : 1;
    u_int16_t urg : 1;
    u_int16_t res2 : 2;
#  elif __BYTE_ORDER == __BIG_ENDIAN
    u_int16_t doff : 4;
    u_int16_t res1 : 4;
    u_int16_t res2 : 2;
    u_int16_t urg : 1;
    u_int16_t ack : 1;
    u_int16_t psh : 1;
    u_int16_t rst : 1;
    u_int16_t syn : 1;
    u_int16_t fin : 1;
#  else
#   error "Adjust your <bits/endian.h> defines"
#  endif
    u_int16_t window;
    u_int16_t check;
    u_int16_t urg_ptr;
}__attribute__((packed));

struct udphdr {
    u_int16_t	source;
    u_int16_t	dest;
    u_int16_t	len;
    u_int16_t	check;
}__attribute__((packed));

struct icmphdr
{
    u_int8_t type;		/* message type */
    u_int8_t code;		/* type sub-code */
    u_int16_t checksum;
    union
    {
        struct
        {
            u_int16_t	id;
            u_int16_t	sequence;
        } echo;			/* echo datagram */
        u_int32_t	gateway;	/* gateway address */
        struct
        {
            u_int16_t	_unused;
            u_int16_t	mtu;
        } frag;			/* path mtu discovery */
    } un;
}__attribute__((packed));

struct pseudo_udp_header
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t udp_length;
}__attribute__((packed));

struct pseudo_udp_header6
{
    unsigned char saddr[16];
    unsigned char daddr[16];
    int ulpl;
    unsigned char pad[3];
    unsigned char protocol;
}
__attribute__((packed));

#else

#pragma pack(push, 1)

struct ethhdr {
    unsigned char	h_dest[ETH_ALEN];	/* destination eth addr	*/
    unsigned char	h_source[ETH_ALEN];	/* source ether addr	*/
    unsigned short	h_proto;		/* packet type ID field	*/
} ;
#pragma pack(pop)
#pragma pack(push, 1)
struct iphdr6
{
#if __BYTE_ORDER ==__LITTLE_ENDIAN 
    unsigned int vlc;
    //unsigned int label : 20;
    //unsigned int class : 8;
    //unsigned int version : 4;
#elif __BYTE_ORDER ==  __BIG_ENDIAN
    //unsigned int label : 20;
    //unsigned int class : 8;
    //unsigned int version : 4;
    unsigned int vlc;
#else
# error	"Please fix <bits/endian.h>"
#endif

    u_int16_t pll;

    u_int8_t next;

    u_int8_t ttl;

    u_char sip[16];
    u_char dip[16];
};
#pragma pack(pop)

#pragma pack( 1)
typedef struct iphdr
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned char ihl : 4;
    unsigned char version : 4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned int version : 4;
    unsigned int ihl : 4;
#else
# error	"Please fix <bits/endian.h>"
#endif
    u_int8_t tos;
    u_int16_t tot_len;
    u_int16_t id;
    u_int16_t frag_off;
    u_int8_t ttl;
    u_int8_t protocol;
    u_int16_t check;
    u_int32_t saddr;
    u_int32_t daddr;
    /*The options start here. */
}iphdr;
#pragma pack()

#pragma pack(push, 1)
struct tcphdr
{
    u_int16_t source;
    u_int16_t dest;
    u_int32_t seq;
    u_int32_t ack_seq;
#  if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int16_t res1 : 4;
    u_int16_t doff : 4;
    u_int16_t fin : 1;
    u_int16_t syn : 1;
    u_int16_t rst : 1;
    u_int16_t psh : 1;
    u_int16_t ack : 1;
    u_int16_t urg : 1;
    u_int16_t res2 : 2;
#  elif __BYTE_ORDER == __BIG_ENDIAN
    u_int16_t doff : 4;
    u_int16_t res1 : 4;
    u_int16_t res2 : 2;
    u_int16_t urg : 1;
    u_int16_t ack : 1;
    u_int16_t psh : 1;
    u_int16_t rst : 1;
    u_int16_t syn : 1;
    u_int16_t fin : 1;
#  else
#   error "Adjust your <bits/endian.h> defines"
#  endif
    u_int16_t window;
    u_int16_t check;
    u_int16_t urg_ptr;
};
#pragma pack(pop)
#pragma pack(push, 1)
struct udphdr {
    u_int16_t	source;
    u_int16_t	dest;
    u_int16_t	len;
    u_int16_t	check;
};
#pragma pack(pop)
#pragma pack(push, 1)
struct icmphdr
{
    u_int8_t type;		/* message type */
    u_int8_t code;		/* type sub-code */
    u_int16_t checksum;
    union
    {
        struct
        {
            u_int16_t	id;
            u_int16_t	sequence;
        } echo;			/* echo datagram */
        u_int32_t	gateway;	/* gateway address */
        struct
        {
            u_int16_t	_unused;
            u_int16_t	mtu;
        } frag;			/* path mtu discovery */
    } un;
};
#pragma pack(pop)
#pragma pack(push, 1)
struct pseudo_udp_header
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t udp_length;
};

#pragma pack(pop)
#pragma pack(push, 1)
struct pseudo_udp_header6
{
    unsigned char saddr[16];
    unsigned char daddr[16];
    int ulpl;
    unsigned char pad[3];
    unsigned char protocol;
};

#pragma pack(pop)

#endif


//ICMP header
//	0                   1                   2                   3
//	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|     Type      |     Code      |          Checksum             |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//                ...



#define ICMP_ECHOREPLY		0	/* Echo Reply			*/
#define ICMP_DEST_UNREACH	3	/* Destination Unreachable	*/
#define ICMP_SOURCE_QUENCH	4	/* Source Quench		*/
#define ICMP_REDIRECT		5	/* Redirect (change route)	*/
#define ICMP_ECHO		8	/* Echo Request			*/
#define ICMP_TIME_EXCEEDED	11	/* Time Exceeded		*/
#define ICMP_PARAMETERPROB	12	/* Parameter Problem		*/
#define ICMP_TIMESTAMP		13	/* Timestamp Request		*/
#define ICMP_TIMESTAMPREPLY	14	/* Timestamp Reply		*/
#define ICMP_INFO_REQUEST	15	/* Information Request		*/
#define ICMP_INFO_REPLY		16	/* Information Reply		*/
#define ICMP_ADDRESS		17	/* Address Mask Request		*/
#define ICMP_ADDRESSREPLY	18	/* Address Mask Reply		*/
#define NR_ICMP_TYPES		18

//udp header
//
//	  0      7 8     15 16    23 24    31
//	 +--------+--------+--------+--------+
//	 |     Source      |   Destination   |
//	 |      Port       |      Port       |
//	 +--------+--------+--------+--------+
//	 |                 |                 |
//	 |     Length      |    Checksum     |
//	 +--------+--------+--------+--------+
//	 |
//	 |          data octets ...
//	 +---------------- ...



/*
    pseudo udp header needed for udp header checksum calculation
*/



/*
 * checksum calculation
 */
unsigned short checksum(unsigned short *ptr, int nbytes);

struct sockaddr_in source,dest;
FILE *logfile;

void process_ip_packet(const u_char * , int);
void print_ip_packet(const u_char * , int);
void print_tcp_packet(const u_char *  , int );
void print_udp_packet(const u_char * , int);
void print_icmp_packet(const u_char * , int );
void PrintData (const u_char * , int);

#endif /* HEADER_H_ */
