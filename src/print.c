/** *************************************************************************
 *
 *  Copyright (c) 2015
 *  @author Peter Gazdik, xgazdi03@stud.fit.vutbr.cz
 *
 ************************************************************************** */


#include "print.h"

#include <stdio.h>
#include <time.h>
#include <string.h>
#include <arpa/inet.h>

#define SHORT_BUFFER 10
#define PASS_BUFFER 17

void print_header(rip_header *header, struct in_addr *src_addr)
{
  time_t now;
  struct tm * timeinfo;
  char c_now[SHORT_BUFFER];

  // Get current time
  time(&now);
  timeinfo = localtime(&now);
  strftime(c_now, SHORT_BUFFER, "%T", timeinfo);

  char c_version[SHORT_BUFFER];
  char c_command[SHORT_BUFFER];
  char *c_from = inet_ntoa(*src_addr);

  switch ((int) header->rip_version) {
    case 1:
      strcpy(c_version, "RIPv1");
      break;
    case 2:
      strcpy(c_version, "RIPv2");
      break;
    default:
      fprintf(stderr, "Invalid RIP version\n");
      return;
  }

  switch((int) header->rip_command) {
    case 1:
      strcpy(c_command, "Request");
      break;
    case 2:
      strcpy(c_command, "Response");
      break;
    default:
      fprintf(stderr, "Invalid RIP command\n");
      return;
  }

  // Print header
  printf("\n[%s] %s from %s\n\tCommand: %s (%d)\n", c_now, c_version, c_from,
         c_command, (int) header->rip_command);
}

void print_authentication(rip_entry *entry)
{
  char c_type[] = "Simple password";
  char c_password[PASS_BUFFER];
  c_password[PASS_BUFFER - 1] = 0;
  memcpy(c_password, entry->data.rip_auth, PASS_BUFFER - 1);

  if (ntohs(entry->rip_routeTag) != RIP_SIMPLEPASS) {
    fprintf(stderr, "Invalid type of authentification\n");
    return;
  }

  printf("\t====== AUTHENTICATION ======\n"
         "\tAuthentication type: %s\n"
         "\tPassword: %s\n", c_type, c_password);
}

void print_metric(rip_entry *entry, uint8_t version)
{
  char ip_addr[INET_ADDRSTRLEN];
  strcpy(ip_addr, inet_ntoa(entry->data.rip_ip));
  char mask[INET_ADDRSTRLEN];
  strcpy(mask, inet_ntoa(entry->data.rip_mask));
  char nextHop[INET_ADDRSTRLEN];
  strcpy(nextHop, inet_ntoa(entry->data.rip_hop));
  char afi[SHORT_BUFFER] = "unknown";

  if (ntohs(entry->rip_afi) == AF_INET) {
    strcpy(afi, "IP");
  }

  printf("\t========== ENTRY ===========\n"
         "\tRoute Tag: %d\n"
         "\tAddress Family Identifier: %s (%d)\n",
         (int) ntohs(entry->rip_routeTag),
         afi, (int) ntohs(entry->rip_afi));

  if (ntohs(entry->rip_afi) == AF_INET) {
    printf("\tIP Address: %s\n", ip_addr);

    if(version == 2) {
      printf("\tNetmask: %s\n\tNext Hop: %s\n",
           mask, nextHop);
    }
  }

  printf("\tMetric: %d\n", (int) ntohl(entry->data.rip_metric));
}

void print_ngheader(rip_header *header, struct in6_addr *src_addr)
{
  time_t now;
  struct tm * timeinfo;
  char c_now[SHORT_BUFFER];

  // Get current time
  time(&now);
  timeinfo = localtime(&now);
  strftime(c_now, SHORT_BUFFER, "%T", timeinfo);

  char c_command[9];
  char c_from[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET6, src_addr, c_from, sizeof(c_from));

  if (header->rip_version != 1) {
    fprintf(stderr, "Invalid RIP version\n");
    return;
  }

  switch((int) header->rip_command) {
    case 1:
      strcpy(c_command, "Request");
      break;
    case 2:
      strcpy(c_command, "Response");
      break;
    default:
      fprintf(stderr, "Invalid RIP command\n");
      return;
  }

  // Print header
  printf("\n[%s] RIPng from %s\n\tCommand: %s (%d)\n", c_now, c_from,
         c_command, (int) header->rip_command);

}

void print_ngmetric(ripng_entry *entry)
{
  char ip_addr[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET6, &entry->prefix, ip_addr, sizeof(ip_addr));

  printf("\t========== ENTRY ===========\n"
         "\tRoute Tag: %d\n\tIPv6 Prefix: %s\n"
         "\tPrefix Length: %d\n\tMetric: %d\n",
         (int) ntohs(entry->routeTag),
         ip_addr, (int) entry->prefLength,
         (int) entry->metric);
}

void print_nghop(ripng_entry *entry)
{
  char ip_addr[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET6, &entry->prefix, ip_addr, sizeof(ip_addr));

  printf("\tNext Hop: %s\n", ip_addr);

}
