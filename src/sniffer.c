/** *************************************************************************
 *
 *  Copyright (c) 2015
 *  @author Peter Gazdik, xgazdi03@stud.fit.vutbr.cz
 *
 ************************************************************************** */

#include "sniffer.h"

#include <pcap.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <arpa/inet.h>

#include "headers.h"
#include "print.h"

#define PCAP_SNAPLEN 500
#define PROMISC_MOD 1
#define PCAP_TIMEOUT 500

void parse_rip(rip_header* rip_hdr, struct in_addr *src_addr, int packet_length)
{
  if (packet_length < RIP_HEADER_LEN) {
    fprintf(stderr, "Invalid RIP packet length\n");
    return;
  }

  // Print packet header
  print_header(rip_hdr, src_addr);

  rip_entry *entry = (rip_entry *) ((u_char *) rip_hdr + RIP_HEADER_LEN);

  // Process packet entries
  for (packet_length -= RIP_HEADER_LEN;
       packet_length >= RIP_ENTRY_LEN;
       packet_length -= RIP_ENTRY_LEN)
  {
    if (entry->rip_afi == 0xFFFF) {
      // Print authentication part
      print_authentication(entry);
    }
    else {
      // Print metric
      print_metric(entry, rip_hdr->rip_version);
    }

    entry = (rip_entry *) ((u_char *) entry + RIP_ENTRY_LEN);
  }
}

void parse_ripng(rip_header* rip_hdr, struct in6_addr *src_addr, int packet_length)
{
  if (packet_length < RIP_HEADER_LEN) {
    fprintf(stderr, "Invalid RIP packet length\n");
    return;
  }

  // Print packet header
  print_ngheader(rip_hdr, src_addr);

  ripng_entry *entry = (ripng_entry *) ((u_char *) rip_hdr + RIP_HEADER_LEN);

  // Process packet entries
  for (packet_length -= RIP_HEADER_LEN;
       packet_length >= RIP_ENTRY_LEN;
       packet_length -= RIP_ENTRY_LEN)
  {
    if (entry->metric == 0xFF) {
      // Print authetication part
      print_nghop(entry);
    }
    else {
      // Print metric
      print_ngmetric(entry);
    }
    entry = (ripng_entry *) ((u_char *) entry + RIP_ENTRY_LEN);
  }

}


void parse_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  // Unused parameters
  (void) args;
  (void) header;

  ipv4_header *ip_hdr;
  udp_header *udp_hdr;
  rip_header *rip_hdr;


  ip_hdr = (ipv4_header *) (packet + ETH_HEADER_LEN);

  // Determine version of IP packet
  if (ip_getVersion(ip_hdr) == 4) {
    // Address of source
    struct in_addr src_addr = ip_hdr->ip_src;

    udp_hdr = (udp_header *) (packet + ETH_HEADER_LEN + ipv4_getLength(ip_hdr));

    // Length of RIP packet
    int rip_legth = ntohs(udp_hdr->udp_length) - UDP_HEADER_LEN;

    rip_hdr = (rip_header *) (packet + ETH_HEADER_LEN + ipv4_getLength(ip_hdr)
                              + UDP_HEADER_LEN);

    // Parse RIP packet
    parse_rip(rip_hdr, &src_addr, rip_legth);
  }
  else {
    // Typecast IP header to v6
    struct ipv6_header *ip6_hdr = (ipv6_header *) (ip_hdr);

    // Address of source
    struct in6_addr src_addr = ip6_hdr->ip_src;

    udp_hdr = (udp_header *) (packet + ETH_HEADER_LEN + IPV6_HEADER_LEN);

    // Length of RIP packet
    int rip_length = ntohs(udp_hdr->udp_length) - UDP_HEADER_LEN;

    rip_hdr = (rip_header *) (packet + ETH_HEADER_LEN + IPV6_HEADER_LEN
                              + UDP_HEADER_LEN);

    // Parse RIPng packet
    parse_ripng(rip_hdr, &src_addr, rip_length);


  }
}

void sniffer_start(char *interface)
{
  char errbuf[PCAP_ERRBUF_SIZE];  // Error string
  pcap_t *handler;                // Session handle

  char filter_exp[] =             // The filter expression
          "portrange 520-521 and udp";
//          "portrange 520 and udp";
  struct bpf_program filter;      // The compiled expression

  bpf_u_int32 mask;               // The netmask of sniffing device
  bpf_u_int32 net;                // The IP of sniffing device


  // If interface is pcap file => TEST MODE
  if (strstr(interface, ".pcap") != NULL) {
    handler = pcap_open_offline(interface, errbuf);
  }
  else {
    // Get the IP and netmask of device
    if (pcap_lookupnet(interface, &net, &mask, errbuf) < 0) {
        fprintf(stderr, "Can't get network number for interface %s\n", interface);
        exit(EXIT_FAILURE);
    }

    // Open interface for sniffing
    handler = pcap_open_live(interface, PCAP_SNAPLEN, PROMISC_MOD,
                             PCAP_TIMEOUT, errbuf);
    if (handler == NULL) {
        fprintf(stderr, "Could'nt open interface %s: %s\n", interface, errbuf);
        exit(EXIT_FAILURE);
    }

    // Compile and set the filter
    if (pcap_compile(handler, &filter, filter_exp, 0, net) < 0) {
        fprintf(stderr, "Couldn't parse this filter %s: %s\n",
                filter_exp, pcap_geterr(handler));
        exit(EXIT_FAILURE);
    }

    if (pcap_setfilter(handler, &filter) < 0) {
        fprintf(stderr, "Couldn't install this filter %s: %s\n",
                filter_exp, pcap_geterr(handler));
        exit(EXIT_FAILURE);
    }
  }

  // cnt = 0 => Infinity loop
  pcap_loop(handler, 0, parse_packet, NULL);

  pcap_close(handler);
}
