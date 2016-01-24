#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

#include "resolve.h"
#include "util.h"


static const uint8_t broadcast_addr[MAC_SIZE] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};


/**
 * Resolves the MAC and IP address of a local device.
 *
 * @param[in] dev the device whose address is being resolved
 * @param[out] address output Host struct into which the result is stored
 *
 * @return ACP_SUCCES on success, ACP_ERR_MAC_RESOLVE if them MAC address of the
 * local device could not be resolved or ACP_ERR_IP_RESOLVE if the IP address of
 * the device could not be resolved.
 */
ACP_STATUS resolve_local(char *dev, Host *address)
{
    int status = ACP_SUCCESS;
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    if (sock < 0) {
        status = ACP_ERR_SOCKET_ACCESS;
        goto EXIT;
    }
    struct ifreq ifr = {0};
    size_t name_len  = strnlen(dev, sizeof(ifr.ifr_name));

    memcpy(&ifr.ifr_name, dev, name_len);

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        status = ACP_ERR_MAC_RESOLVE;
        goto CLEANUP;
    }
    memcpy(address->mac, ifr.ifr_hwaddr.sa_data, MAC_SIZE);

    memset(&ifr, 0, sizeof(ifr));
    memcpy(&ifr.ifr_name, dev, name_len);

    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
        status = ACP_ERR_IP_RESOLVE;
        goto CLEANUP;
    }

    memcpy(address->ip,
           &(((struct sockaddr_in *) (&ifr.ifr_addr))->sin_addr.s_addr),
           IP_SIZE);

CLEANUP:
    close(sock);
EXIT:
    return status;
}


/**
 * Writes a broadcast ARP request packet to the buffer pbuff.
 *
 * @param[in] pbuff
 * @param[in] sender_ip
 * @param[in] target_ip
 * @param[in] sender_mac
 */
static void write_request_packet(uint8_t *pbuff,
                                 uint8_t sender_ip[IP_SIZE],
                                 uint8_t target_ip[IP_SIZE],
                                 uint8_t sender_mac[MAC_SIZE])
{
    EthernetHeader eth_h;

    memcpy(&eth_h.target_addr, broadcast_addr, MAC_SIZE);
    memcpy(&eth_h.sender_addr, sender_mac, MAC_SIZE);
    eth_h.protocol = htons(ETHER_TYPE_ARP);

    ARPHeader arp_h;

    arp_h.hardware_type = htons(1);
    arp_h.protocol_type = htons(ETH_P_IP);
    arp_h.hardware_addr_len = 6;
    arp_h.protocol_addr_len = 4;
    arp_h.operation = ARPOP_REQUEST;

    memcpy(&arp_h.sender_hardware_addr, sender_mac, MAC_SIZE);
    memcpy(&arp_h.sender_protocol_addr, sender_ip,  IP_SIZE);
    memcpy(&arp_h.target_protocol_addr, target_ip,  IP_SIZE);

    memset(&arp_h.target_hardware_addr, 0, MAC_SIZE);

    // Write headers to buffer
    memcpy(pbuff, &eth_h, ETH_HEADER_LEN);
    memcpy(pbuff + ETH_HEADER_LEN, &arp_h, ARP_HEADER_LEN);
}


typedef struct thread_share {
    pthread_mutex_t lock;
    bool resolved;
    pcap_t *pcap_h;
    Host remote;
} ThreadShare;


/**
 * Reply thread entry function
 */
static void *get_reply(void *arg)
{
    ThreadShare *share = arg;
    struct pcap_pkthdr *header;
    const u_char *pack_data;

    int ct;
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &ct);

    int status;
    while (((status = pcap_next_ex(share->pcap_h, &header, &pack_data)) >= 0)) {
        const ARPHeader *arp_h = (const ARPHeader*) (pack_data + ETH_HEADER_LEN);

        if (arp_h->operation != ARPOP_REPLY)
            continue;

        pthread_mutex_lock(&share->lock);
        if (ip_match(arp_h->sender_protocol_addr, share->remote.ip)) {
            memcpy(share->remote.mac, arp_h->sender_hardware_addr, MAC_SIZE);
            share->resolved = true;
            pthread_mutex_unlock(&share->lock);
            break;
        }
        pthread_mutex_unlock(&share->lock);
    }
    return (void*) ((uintptr_t) status);
}


/**
 * Shared state between the main thread and the reply thread.
 */
ThreadShare share;


/**
 * Resolves the MAC address of a remote host and returns a status.
 *
 * @param[in] pcap pcap handle
 * @param[in] local host representing the local machine
 * @param[in] remote the remote host whose MAC adddress is being resolved
 * @param[in] timeout resolve timeout in miliseconds
 *
 * @return ACP_SUCCESS or ACP_ERR_PTHREAD
 */
ACP_STATUS resolve_remote_mac(pcap_t *pcap, Host *local, Host *remote, uint64_t timeout)
{
    /* The resolve response specific timeout is separate from the pcap timeout.
       Pcap timeout is set for all incomming packets, and since the pcap_next_ex
       function is blocking, the response timer has to run on a separate thread. In
       this case the pcap reply listener runs on a spawned reply thread, while
       response timer runs on the main thread. */

    size_t  pack_len = ETH_HEADER_LEN + ARP_HEADER_LEN;
    uint8_t pack_buff[pack_len];

    write_request_packet(pack_buff,
                         local->ip,
                         remote->ip,
                         local->mac);

    /* Send the request packet. */
    pcap_inject(pcap, (uint8_t*) pack_buff, pack_len);

    /* Prepare the state shared between the main thread and
       the reply thread */
    memset(&share, 0, sizeof(ThreadShare));
    share.pcap_h   = pcap;
    share.resolved = false;
    memcpy(&share.remote, remote, sizeof(Host));

    if (pthread_mutex_init(&share.lock, NULL))
        return ACP_ERR_PTHREAD;

    pthread_t reply_thread;
    if (pthread_create(&reply_thread, NULL, get_reply, &share) != 0)
        return ACP_ERR_PTHREAD;

    /* Initialize the response timeout timer. */
    struct timespec start_time;
    struct timespec end_time;
    clock_gettime(CLOCK_MONOTONIC, &start_time);
    clock_gettime(CLOCK_MONOTONIC, &end_time);

    while ((time_delta(&end_time, &start_time) < timeout) && !share.resolved) {
        usleep(16 * 1000);
        clock_gettime(CLOCK_MONOTONIC, &end_time);
    }

    /* Cancel the reply thread now that the resolve timer has
       expired */
    pthread_cancel(reply_thread);
    pthread_join(reply_thread, NULL);
    pthread_mutex_destroy(&share.lock);

    /*  */
    if (!share.resolved)
        return ACP_ERR_TIMEOUT;

    memcpy(&remote->mac, &share.remote.mac, sizeof(MAC_SIZE));

    return ACP_SUCCESS;
}
