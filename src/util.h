#ifndef _UTIL_H_
#define _UTIL_H_

#include <stdbool.h>
#include <stdint.h>

#include "def.h"

bool ip_match     (const uint8_t ip1[IP_SIZE], const uint8_t ip2[IP_SIZE]);
bool to_bin_mac   (char mac_str[MAC_STRING_LEN], uint8_t mac_bin[MAC_SIZE]);
bool is_valid_mac (char mac[MAC_STRING_LEN]);

void print_ip        (FILE *f, uint8_t ip[IP_SIZE]);
void print_mac       (FILE *f, uint8_t mac[MAC_SIZE]);
void print_packet    (ARPPacket *packet);
void print_host_info (Host *h);


inline __attribute__((always_inline))
uint64_t time_delta(struct timespec *t1, struct timespec *t2)
{
    return (((t1->tv_sec * 1000000000) + t1->tv_nsec) -
            ((t2->tv_sec * 1000000000) + t2->tv_nsec)) / 1000000;
}

#endif
