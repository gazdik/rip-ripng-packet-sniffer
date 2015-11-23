/** *************************************************************************
 *
 *  Copyright (c) 2015
 *  @author Peter Gazdik, xgazdi03@stud.fit.vutbr.cz
 *
 ************************************************************************** */

#include <stdio.h>
// exit, ...
#include <stdlib.h>
// getopt
#include <unistd.h>
// inet_* functions
#include <arpa/inet.h>
// bzero
#include <strings.h>
// strcpy, ...
#include <string.h>

#include "response.h"


void display_usage()
{
  printf("./myripresponse {-i <interface>} -r <IPv4>/[8-30]\n"
         "\t{-n <IPv4>} {-m [0-16]} {-t [0-65535]} {-p <password>}\n"
         "\n\tTODO\n");
}

struct in_addr prefix_to_addr(unsigned int prefix)
{
  if ((prefix < 8) || (prefix > 30)) {
    fprintf(stderr, "Invalid prefix length.\n");
    exit(EXIT_FAILURE);
  }

  struct in_addr addr;
  addr.s_addr = (0xFFFFFFFFu >> (32 - prefix));

  return addr;
}


int main(int argc, char *argv[])
{
  int opt;
  response_args args;

  // Set default values
  bzero(args.interface, BUFFSIZE);
  args.address.s_addr = INADDR_ANY;
  args.netmask.s_addr = INADDR_ANY;
  args.metric = 1;
  inet_aton("0.0.0.0", &args.nexthop);
  args.tag = 0;
  bzero(args.password, PASS_LEN);

  while((opt = getopt(argc, argv, "i:r:m:n:t:p:")) != -1) {
    switch (opt) {
      case 'i':
        strcpy(args.interface, optarg);
        break;
      case 'r': ;
        char * addr = strtok(optarg, "/");
        if (!inet_aton(addr, &args.address)) {
          fprintf(stderr, "Invalid format of IP address.\n");
          exit(EXIT_FAILURE);
        }

        char * prefix = strtok(NULL, "/");
        if (prefix == NULL) {
          fprintf(stderr, "Missing prefix length.\n");
          exit(EXIT_FAILURE);
        }

        args.netmask = prefix_to_addr(strtoul(prefix, NULL, 0));
        break;
      case 'm': ;
        int metric = atoi(optarg);
        if (metric < 0 || metric > 16) {
          fprintf(stderr, "Metric is out of range.\n");
          exit(EXIT_FAILURE);
        }

        args.metric = metric;

        break;
      case 't': ;
        int tag = atoi(optarg);

        if (tag < 0 || tag > 65535) {
          fprintf(stderr, "Route tag is out of range.\n");
          exit(EXIT_FAILURE);
        }

        args.tag = tag;

        break;
      case 'p':
        if (strlen(optarg) > 16) {
          fprintf(stderr, "Password is too long\n");
          exit(EXIT_FAILURE);
        }

        strcpy(args.password, optarg);
        break;
      case 'n':
        if (!inet_aton(optarg, &args.nexthop)) {
          fprintf(stderr, "Invalid format of Next Hop address\n");
          exit(EXIT_FAILURE);
        }
      default:
        break;
    }
  }

  if (args.address.s_addr == INADDR_ANY ||
      args.netmask.s_addr == INADDR_ANY) {
    display_usage();
    exit(EXIT_FAILURE);
  }

/*
  printf("IP: %s\n", inet_ntoa(args.address));
  printf("Mask: %s\n", inet_ntoa(args.netmask));
  printf("Hop: %s\n", inet_ntoa(args.nexthop));
  printf("Interface: %s\n", args.interface);
  printf("Metric: %d\n", (int) args.metric);
  printf("Route tag: %d\n", (int) args.tag);
  printf("Password: %s\n", args.password);
*/

  response_send(&args);
}

