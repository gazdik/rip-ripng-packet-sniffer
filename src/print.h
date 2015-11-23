/** *************************************************************************
 *
 *  Copyright (c) 2015
 *  @author Peter Gazdik, xgazdi03@stud.fit.vutbr.cz
 *
 ************************************************************************** */

#ifndef PRINT_H
#define PRINT_H

#include "rip.h"

/**
 * @brief print_header Print RIPv1 and RIPv2 header
 */
void print_header(rip_header *header, struct in_addr *src_addr);
/**
 * @brief print_ngheader Print RIPng header
 */
void print_ngheader(rip_header *header, struct in6_addr *src_addr);
/**
 * @brief print_authentication Print RIPv2 authentication entry
 */
void print_authentication(rip_entry *entry);
/**
 * @brief print_metric Print RIPv1 and RIPv2 metric entry
 */
void print_metric(rip_entry *entry, uint8_t version);
/**
 * @brief print_ngmetric Print RIPng metric entry
 */
void print_ngmetric(ripng_entry *entry);
/**
 * @brief print_nghop Print RIPng Next Hop entry
 */
void print_nghop(ripng_entry *entry);



#endif // PRINT_H

