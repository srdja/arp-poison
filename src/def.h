#ifndef _DEF_H_
#define _DEF_H_

#include <stdint.h>
#include <unistd.h>
#include <stdbool.h>

#include <pcap.h>
#include <arpa/inet.h>

#include <netinet/in.h>
#include <net/if.h>
#include <net/ethernet.h>

#include <sys/ioctl.h>
#include <sys/socket.h>


#define PCAP_NETMASK_UNKNOWN 0xffffffff
#define ERROR_BUFF_LEN 2048

#define ARPOP_REQUEST htons(1)
#define ARPOP_REPLY   htons(2)

#define HTYPE_ETHERNET htons(1)
#define ETHER_TYPE_ARP 0x0806

#define MAC_SIZE 6
#define IP_SIZE  4
#define IP_STRING_LEN  16 + 1
#define MAC_STRING_LEN 17 + 1


typedef struct __attribute__((packed)) ethernet_header {
    uint8_t  target_addr[MAC_SIZE];
    uint8_t  sender_addr[MAC_SIZE];
    uint16_t protocol;
} EthernetHeader;


typedef struct __attribute__((packed)) arp_header {
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t  hardware_addr_len;
    uint8_t  protocol_addr_len;
    uint16_t operation;
    uint8_t  sender_hardware_addr[MAC_SIZE];
    uint8_t  sender_protocol_addr[IP_SIZE];
    uint8_t  target_hardware_addr[MAC_SIZE];
    uint8_t  target_protocol_addr[IP_SIZE];
} ARPHeader;


#define ETH_HEADER_LEN sizeof(EthernetHeader)
#define ARP_HEADER_LEN sizeof(ARPHeader)

#define TARGETS 2


enum target {
    T1 = 0,
    T2 = 1
};


typedef struct host {
    uint8_t mac[MAC_SIZE];
    uint8_t ip [IP_SIZE];
} Host;


typedef struct packet {
    uint8_t  des_mac[MAC_SIZE];
    uint8_t  src_mac[MAC_SIZE];
    uint8_t  des_ip[IP_SIZE];
    uint8_t  src_ip[IP_SIZE];
    uint16_t operation;
} ARPPacket;


typedef enum acp_stat_e {
    ACP_SUCCESS,
    ACP_ERR_TIMEOUT,
    ACP_ERR_SOCKET_ACCESS,
    ACP_ERR_MAC_RESOLVE,
    ACP_ERR_IP_RESOLVE,
    ACP_ERR_PCAP,
    ACP_ERR_PTHREAD
} ACP_STATUS;


extern bool verbose;

#endif
