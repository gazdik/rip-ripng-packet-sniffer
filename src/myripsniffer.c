/** *************************************************************************
 *
 *  Copyright (c) 2015
 *  @author Peter Gazdik, xgazdi03@stud.fit.vutbr.cz
 *
 ************************************************************************** */

#include <stdio.h>
#include <stdlib.h>
// getopt
#include <unistd.h>
#include "sniffer.h"

void display_usage()
{
  printf("./myripsniffer -i <interface>\n"
    "-i: <interface> Interface for packet sniffing.\n");
}

int main(int argc, char *argv[])
{
  char *interface = NULL;
  int opt;

  // Process arguments
  while((opt = getopt(argc, argv, "i:")) != -1) {
    switch (opt) {
      case 'i':
        interface = optarg;
        break;
      default:
        break;
    }
  }

  // If arguments missing display help message
  if (interface == NULL) {
    display_usage();
    exit(EXIT_FAILURE);
  }

  sniffer_start(interface);

  exit(EXIT_SUCCESS);
}

