/** *************************************************************************
 *
 *  Copyright (c) 2015
 *  @author Peter Gazdik, xgazdi03@stud.fit.vutbr.cz
 *
 ************************************************************************** */

#include "response.h"
#include "rip.h"

// bool
#include <stdbool.h>
// malloc, free
#include <stdlib.h>
// memcpy
#include <string.h>
// sockets
#include <sys/socket.h>
// inet_* functions
#include <arpa/inet.h>
// close
#include <unistd.h>


u_char *set_packet(const response_args *args, size_t *packet_size)
{
  u_char *rip_packet;

  bool auth = (args->password[0] != 0);

  // Allocate memory block of size depends on whether authetication is set or not
  if (auth) {
    *packet_size = RIP_HEADER_LEN + 2 * RIP_ENTRY_LEN;
  } else {
    *packet_size = RIP_HEADER_LEN + RIP_ENTRY_LEN;
  }
  rip_packet = (u_char *) malloc(*packet_size);

  rip_header header;
  header.rip_command = RIP_RESPONSE;
  header.rip_version = RIP_RIPV2;
  header.rip_zeroes = 0;

  memcpy(rip_packet, &header, RIP_HEADER_LEN);

  rip_entry entry;

  // Set authentication entry
  if (auth) {
    entry.rip_afi = htons(0xFFFF);
    entry.rip_routeTag = htons(RIP_SIMPLEPASS);
    memcpy(&entry.data.rip_auth, args->password, RIP_PASS_LEN);

    memcpy(rip_packet + RIP_HEADER_LEN, &entry, RIP_ENTRY_LEN);
  }

  entry.rip_afi = htons(AF_INET);
  entry.rip_routeTag = htons(args->tag);
  entry.data.rip_ip = args->address;
  entry.data.rip_mask = args->netmask;
  entry.data.rip_hop = args->nexthop;
  entry.data.rip_metric = htonl(args->metric);

  if (auth) {
    memcpy(rip_packet + RIP_HEADER_LEN + RIP_ENTRY_LEN, &entry, RIP_ENTRY_LEN);
  } else {
    memcpy(rip_packet + RIP_HEADER_LEN, &entry, RIP_ENTRY_LEN);
  }

  return rip_packet;
}

void response_send(response_args *args)
{
  u_char *rip_packet;
  size_t packet_size;

  rip_packet = set_packet(args, &packet_size);

  int sockfd;
  struct sockaddr_in my_addr, dest_addr;

  sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

  int flag = 1;
  setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(int));
  setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &flag, sizeof(int));

  if (args->interface[0] != 0)
    setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE,
               args->interface, strlen(args->interface));


  bzero(&my_addr, sizeof(my_addr));
  my_addr.sin_family = AF_INET;
  my_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  my_addr.sin_port = htons(RIP_PORT);

  if (bind(sockfd, (struct sockaddr *) &my_addr, sizeof(my_addr))) {
    fprintf(stderr, "Cannot bind socket\n");
  }

  bzero(&dest_addr, sizeof(dest_addr));
  dest_addr.sin_family = AF_INET;
  inet_aton("224.0.0.9", &dest_addr.sin_addr);
  dest_addr.sin_port = htons(RIP_PORT);

  sendto(sockfd, rip_packet, packet_size, 0, (struct sockaddr *) &dest_addr,
         sizeof(dest_addr));

  close(sockfd);
}
