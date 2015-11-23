/** *************************************************************************
 *
 *  Copyright (c) 2015
 *  @author Peter Gazdik, xgazdi03@stud.fit.vutbr.cz
 *
 ************************************************************************** */

#ifndef HEADERS_H
#define HEADERS_H

#include <pcap.h>
#include <netinet/ip.h>
#include <stdint.h>

/**
  * Ethernet header
  */

#define ETH_ADDR_LEN 6
#define ETH_HEADER_LEN 14

typedef struct eth_header {
  // Destination host address
  uint8_t eth_dst;
  // Source host address
  uint8_t eth_src;
  // Type of next level protocol
  uint16_t eth_type;
} eth_header;

/**
  * IPv4 header
  */
typedef struct ipv4_header {
  // Version (4 bits) and header length (4 bits)
  uint8_t ip_vhl;
  // Type of Service
  uint8_t ip_tos;
  // Total length
  uint16_t ip_length;
  // Identification
  uint16_t ip_id;
  // Flags and Fragment offset
  uint16_t ip_offset;
  // Time to Live
  uint8_t ip_ttl;
  // Next level protocol
  uint8_t ip_protocol;
  // Header checksum
  uint16_t ip_checksum;
  // Source and destination address
  struct in_addr ip_src, ip_dst;
} ipv4_header;

/**
 * @brief ipv4_getLength extract header length from 'ip_vhl'
 * @param header IPv4 header
 * @return length of IP header
 */
int ipv4_getLength(const ipv4_header *header)
{
    return (header->ip_vhl & 0x0f) * 4;
}


/**
 * @brief ip_getVersion
 * @param header IPv4 header
 * @return version of IP packet
 */
uint8_t ip_getVersion(const ipv4_header *header)
{
    return header->ip_vhl >> 4;
}


/**
  * IPv6 header
  */

#define IPV6_HEADER_LEN 40

typedef struct ipv6_header {
  // Identification
  uint32_t ip_meta;
  // Payload length
  uint16_t ip_length;
  // Next header type
  uint8_t ip_nexthdr;
  // Time to Live (Hop limit)
  uint8_t ip_ttl;
  // Source and destination address
  struct in6_addr ip_src, ip_dst;
} ipv6_header;

/**
  * UDP header
  */

#define UDP_HEADER_LEN 8

typedef struct udp_header {
    // Source port
    uint16_t udp_src;
    // Destination port
    uint16_t udp_dest;
    // Total length
    uint16_t udp_length;
    // Checksum
    uint16_t udp_sum;
} udp_header;


#endif // HEADERS_H
