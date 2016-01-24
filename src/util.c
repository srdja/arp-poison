#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "util.h"


bool ip_match(const uint8_t ip1[4], const uint8_t ip2[4])
{
    for (int i = 0; i < 4; i++) {
        if (ip1[i] != ip2[i])
            return false;
    }
    return true;
}


static bool is_hex(char c)
{
    return (c >= '0' && c <= '9') ||
           (c >= 'a' && c <= 'f') ||
           (c >= 'A' && c <= 'F');
}


bool is_valid_mac(char mac[MAC_STRING_LEN])
{
    for (int i = 0; i < MAC_STRING_LEN - 3;) {
        if (!is_hex(mac[i++]) ||
            !is_hex(mac[i++]) ||
            mac[i++] != ':')
            return false;
    }
    if (!is_hex(mac[MAC_STRING_LEN - 3]) ||
        !is_hex(mac[MAC_STRING_LEN - 2]))
        return false;;

    return true;
}


bool to_bin_mac(char mac_str[MAC_STRING_LEN], uint8_t mac_bin[MAC_SIZE])
{
    int stat = sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                      &mac_bin[0],
                      &mac_bin[1],
                      &mac_bin[2],
                      &mac_bin[3],
                      &mac_bin[4],
                      &mac_bin[5]);
    return stat == 6;
}


void print_ip(FILE *f, uint8_t ip[IP_SIZE])
{
    struct in_addr address;
    memcpy(&address, ip, IP_SIZE);
    fprintf(f, "%s", inet_ntoa(address));
}


void print_mac(FILE *f, uint8_t mac[MAC_SIZE])
{
    for (int i = 0; i < MAC_SIZE - 1; i++) {
        fprintf(f, "%02x:", mac[i]);
    }
    fprintf(f, "%02x", mac[1]);
}


void print_packet(ARPPacket *p)
{
    fprintf(stdout, "Sending spoof from ");
    print_mac(stdout, p->src_mac);
    fprintf(stdout, " to ");
    print_mac(stdout, p->des_mac);
    fprintf(stdout, " as ");
    print_ip(stdout, p->src_ip);
    fprintf(stdout, "\n");
}


void print_host_info(Host *h)
{
    fprintf(stdout, "Host: IP = ");
    print_ip(stdout, h->ip);
    fprintf(stdout, " MAC = ");
    print_mac(stdout, h->mac);
    fprintf(stdout, "\n");
}
