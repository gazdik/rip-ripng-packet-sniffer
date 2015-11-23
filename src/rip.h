/** *************************************************************************
 *
 *  Copyright (c) 2015
 *  @author Peter Gazdik, xgazdi03@stud.fit.vutbr.cz
 *
 ************************************************************************** */

#ifndef RIP_H
#define RIP_H

#include <pcap.h>
#include <netinet/ip.h>
#include <stdint.h>

/**
  * RIP Header
  */

#define RIP_HEADER_LEN 4
#define RIP_REQUEST 1
#define RIP_RESPONSE 2
#define RIP_RIPV1 1
#define RIP_RIPV2 2
#define RIP_SIMPLEPASS 2
#define RIP_PASS_LEN 16
#define RIP_PORT 520
#define RIPNG_PORT 521


typedef struct rip_header {
  // Command field
  // 1 - request, 2 - response
  uint8_t rip_command;
  // Version of RIP protocol
  uint8_t rip_version;
  // Must be zero
  uint16_t rip_zeroes;
} rip_header;

/**
  * RIP Entry
  */

#define RIP_ENTRY_LEN 20

typedef struct rip_entry {
  // Address family identifier
  uint16_t rip_afi;
  // Route Tag
  uint16_t rip_routeTag;
  union data {
    struct {
        u_char rip_auth[16];
    };
    struct {
      // IPv4 address
      struct in_addr rip_ip;
      // Subnet mask
      struct in_addr rip_mask;
      // Next Hop
      struct in_addr rip_hop;
      // Metric <= 16
      uint32_t rip_metric;
    };
  } data;
} rip_entry;

typedef struct ripng_entry {
  // IPv6 prefix
  struct in6_addr prefix;
  // Route tag
  uint16_t routeTag;
  // Prefix length
  uint8_t prefLength;
  // Metric
  uint8_t metric;
} ripng_entry;

typedef struct ripv2_simple {
  rip_header header;
  rip_entry metric;
} ripv2_simple;

typedef struct ripv2_auth {
  rip_header header;
  rip_entry auth;
  rip_entry metric;
} ripv2_auth;

#endif // RIP_H
