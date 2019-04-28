
#ifndef __PACKET_H_
#define __PACKET_H_

#include <stdint.h>

typedef struct {
	/* Ethernet header */
	uint8_t	h_dest[6];	    /* destination ether addr */
	uint8_t	h_source[6];	/* source ether addr */
	uint16_t h_proto;		/* packet type ID field */

	/* ARP packet */
	uint16_t ar_hrd;	    /* hardware type (must be ARPHRD_ETHER) */
	uint16_t ar_pro;	    /* protocol type (must be ETH_P_IP) */
	uint8_t	ar_hln;	    /* hardware address length (must be 6) */
	uint8_t	ar_pln;	    /* protocol address length (must be 4) */
	uint16_t ar_op;	    /* ARP opcode */
	uint8_t	ar_sha[6];	/* sender's hardware address */
	uint8_t	ar_sip[4];	/* sender's IP address */
	uint8_t	ar_tha[6];	/* target's hardware address */
	uint8_t	ar_tip[4];	/* target's IP address */
} __attribute__ ((packed)) arp_packet_t;

typedef struct {
	uint16_t trans_id;
	uint16_t flags;
	uint16_t questions;
	uint16_t answers;
	uint16_t authority_RRs;
	uint16_t additional_RRs;
	uint8_t name[34];			// mangled
	uint16_t query_type;
	uint16_t query_class;
} __attribute__ ((packed)) ns_name_query;

typedef struct {
    uint16_t trans_id;
    uint16_t flags;
    uint16_t questions;
    uint16_t answers;
    uint16_t authority_RRs;
    uint16_t additional_RRs;
    uint8_t name[34];           // mangled
    uint16_t ans_type;
    uint16_t ans_class;
    uint32_t ttl;
    uint16_t length;
    uint8_t name_num;
} __attribute__ ((packed)) ns_nbtstat_resp_hdr;

struct arp_sock {
    int sockfd;
    char *device;
    struct sockaddr_ll eth_in;
    arp_packet_t arp;
};

#define NS_HDR_LEN (sizeof(ns_nbtstat_resp_hdr))

#endif
