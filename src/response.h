/** *************************************************************************
 *
 *  Copyright (c) 2015
 *  @author Peter Gazdik, xgazdi03@stud.fit.vutbr.cz
 *
 ************************************************************************** */

#ifndef RESPONSE_H
#define RESPONSE_H

#include <netinet/ip.h>
#include <stdint.h>
#include <stdio.h>

#define PASS_LEN 17
#define BUFFSIZE 256


typedef struct response_args {
  char interface[BUFFSIZE];
  struct in_addr address,
      netmask,
      nexthop;
  uint32_t metric;
  uint16_t tag;
  char password[PASS_LEN];
} response_args;

/**
 * @brief response_send Send RIPv2 Response message
 * @param args cmd arguments
 */
void response_send(response_args *args);

/**
 * @brief set_packet create RIP packet and set all values to it
 * @param args cmd arguments
 * @param packet_size
 * @return pointer to RIP packet
 */
u_char *set_packet(const response_args *args, size_t *packet_size);

#endif // RESPONSE_H

