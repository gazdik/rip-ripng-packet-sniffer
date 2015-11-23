/** *************************************************************************
 *
 *  Copyright (c) 2015
 *  @author Peter Gazdik, xgazdi03@stud.fit.vutbr.cz
 *
 ************************************************************************** */

#ifndef SNIFFER_H
#define SNIFFER_H

#include "rip.h"

/**
 * @brief sniffer_start Start sniffing
 * @param interface Name of interface to sniff on
 */
void sniffer_start(char *interface);
/**
 * @brief parse_rip Parse only RIPv1 and RIPv2
 */
void parse_rip(rip_header* rip_hdr, struct in_addr *src_addr, int packet_length);
/**
 * @brief parse_ripng Parse only RIPng
 */
void parse_ripng(rip_header* rip_hdr, struct in6_addr *src_addr, int packet_length);
/**
 * @brief parse_packet Parse RIP and RIPng packet
 */
void parse_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

#endif // SNIFFER_H
