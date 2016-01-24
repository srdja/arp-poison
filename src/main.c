#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <getopt.h>
#include <pthread.h>

#include "def.h"
#include "util.h"
#include "resolve.h"
#include "spoof.h"

#define PROGRAM "acp"

pthread_t quit_thread;

pcap_t *pcap_h;
char error_buff[ERROR_BUFF_LEN];

/* Packet filter pattern (ARP)*/
char *filter_exp = "ether proto 0x0806";

/* Compiled packet filter. */
struct bpf_program filter;


Host targets[TARGETS];
Host local_addr;
bool verbose = false;


void print_usage(void)
{
    printf("Usage: %s [OPTIONS]... [IP1][IP2] ...(optional)[MAC1][MAC2]\n\n", PROGRAM);
    printf("NOTE: If the MAC addresses are not specified, they are resolved.\n\n");
    printf(" -h, --help             print this help message\n");
    printf(" -v, --verbose          verbose output\n");
    printf(" -i, --interface        interface to use. If none is specified, the default interface is used\n");
    printf(" -g, --gratuitous       if set the spoof replies will be sent as gratuitous replies\n");
    printf(" -r, --resolve-timeout  MAC address resolution timeout in miliseconds \n");
    printf(" -s, --sniff-timeout    traffic sniffing timeout in miliseconds\n");

    exit(0);
}


void handle_init_pcap(char *device, int pcap_timeout)
{
    if (!(pcap_h = pcap_open_live(device, 1500, 0, pcap_timeout, error_buff))) {
        fprintf(stderr, "Could not open pcap on device %s\n", device);
        exit(1);
    }

    if (pcap_datalink(pcap_h) != DLT_EN10MB) {
        fprintf(stderr, "Device %s doesn't support ethernet headers\n", device);
        exit(1);
    }

    if (pcap_compile(pcap_h, &filter, filter_exp, 1, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "%s", pcap_geterr(pcap_h));
        exit(1);
    }

    if (pcap_setfilter(pcap_h, &filter) == -1) {
        fprintf(stderr, "%s", pcap_geterr(pcap_h));
        exit(1);
    }

    pcap_setdirection(pcap_h, PCAP_D_IN);
}


void handle_remote_resolve(enum target T, int timeout) {
    if (verbose) {
        fprintf(stdout, "Resolving ");
        print_ip(stdout, targets[T].ip);
        fprintf(stdout, "...\n");
    }

    switch (resolve_remote_mac(pcap_h, &local_addr, &targets[T], timeout)) {
    case ACP_ERR_TIMEOUT:
        fprintf(stderr, "Unable to resolve the MAC address of host at ");
        print_ip(stderr, targets[T].ip);
        fprintf(stderr, ". Request timed out.\n");
        exit(1);
    case ACP_ERR_PTHREAD:
        fprintf(stderr, "something else");
        exit(1);
    default:
        break;
    }
}


void handle_local_resolve(char *dev, Host *local) {
    switch (resolve_local(dev, local)) {
    case ACP_ERR_SOCKET_ACCESS:
        fprintf(stderr, "Cannot open a raw socket. Must be root.\n");
        exit(1);
    case ACP_ERR_MAC_RESOLVE:
        fprintf(stderr, "Cannot get the MAC address of interface %s\n", dev);
        exit(1);
    case ACP_ERR_IP_RESOLVE:
        fprintf(stderr, "Cannot get the IP address of interface %s\n", dev);
        exit(1);
    default: break;
    }
}


void *quit_key(__attribute__((unused)) void *var)
{
    while (getchar() != 'q');
    exit(0);

    return NULL; /* Unreachable */
}


struct option long_options[] = {
    {"help",            no_argument,       NULL, 'h'},
    {"verbose",         no_argument,       NULL, 'v'},
    {"gratuitous",      no_argument,       NULL, 'g'},
    {"interface",       required_argument, NULL, 'i'},
    {"resolve-timeout", required_argument, NULL, 'r'},
    {"sniff-timeout",   required_argument, NULL, 's'},
    {0, 0, 0, 0}
};


int main(int argc, char **argv)
{
    int   sniff_timeout   = 5000;
    int   resolve_timeout = 5000;
    bool  gratuitous      = false;
    char *device          = NULL;

    int c;
    while ((c = getopt_long(argc, argv, "hvgi:r:s:", long_options, NULL)) != -1) {
        switch (c) {
        case 'h': print_usage();
        case 'v': verbose = true;
                  break;
        case 'i': device = optarg;
                  break;
        case 'g': gratuitous = true;
                  break;
        case 'r': resolve_timeout = strtol(optarg, NULL, 10);
                  break;
        case 's': sniff_timeout = strtol(optarg, NULL, 10);
                  break;
        case '?': printf("See 'acp --help' for more information\n");
                  return 1;
        }
    }

    // init quit key
    if (pthread_create(&quit_thread, NULL, quit_key, NULL)) {
        fprintf(stderr, "Unable to create the quit key thread\n");
        return 1;
    }

    /* If no device is specified use the default one */
    if (!device) {
        device = pcap_lookupdev(error_buff);
        // check for pcap error
    }

    /* Get device information */
    handle_local_resolve(device, &local_addr);


    handle_init_pcap(device, sniff_timeout);


    char  ip1[IP_STRING_LEN];
    char  ip2[IP_STRING_LEN];
    char mac1[MAC_STRING_LEN];
    char mac2[MAC_STRING_LEN];

    int options_index  = optind;
    int remaining_args = argc - options_index;

    size_t ip1_len  = 0;
    size_t ip2_len  = 0;
    if (remaining_args == 2) {
        if ((ip1_len = strlen(argv[options_index])) > IP_STRING_LEN - 1 ||
            (ip2_len = strlen(argv[options_index + 1])) > IP_STRING_LEN - 1)
        {
            // descriptive error
            print_usage();
        }

        strncpy(ip1, argv[options_index], IP_STRING_LEN);
        strncpy(ip2, argv[options_index + 1], IP_STRING_LEN);

        if (!inet_pton(AF_INET, ip1, &targets[T1].ip) ||
            !inet_pton(AF_INET, ip2, &targets[T2].ip))
        {
            // descriptive error....
            print_usage();
        }

        handle_remote_resolve(T1, resolve_timeout);
//        sleep(15);
        handle_remote_resolve(T2, resolve_timeout);
    } else if (remaining_args == 4) {
        if ((ip1_len = strlen(argv[options_index])) > (IP_STRING_LEN - 1) ||
            (ip2_len = strlen(argv[options_index + 1])) > (IP_STRING_LEN - 1) ||
            strlen(argv[options_index + 2]) != (MAC_STRING_LEN - 1) ||
            strlen(argv[options_index + 3]) != (MAC_STRING_LEN - 1))
        {
            print_usage();
        }

        strncpy(ip1, argv[options_index], IP_STRING_LEN);
        strncpy(ip2, argv[options_index + 1], IP_STRING_LEN);
        strncpy(mac1, argv[options_index + 2], MAC_STRING_LEN);
        strncpy(mac2, argv[options_index + 3], MAC_STRING_LEN);

        if (!inet_pton(AF_INET, ip1, &targets[T1].ip) ||
            !inet_pton(AF_INET, ip2, &targets[T2].ip) ||
            !is_valid_mac(mac1) ||
            !is_valid_mac(mac2))
        {
            print_usage();
        }

        to_bin_mac(mac1, targets[T1].mac);
        to_bin_mac(mac2, targets[T2].mac);
    } else {
        print_usage();
    }

    if (verbose) {
        print_host_info(&local_addr);
        print_host_info(&targets[T1]);
        print_host_info(&targets[T2]);
    }

    spoof_init(pcap_h, targets, &local_addr, gratuitous);
    spoof_run();

    pcap_close(pcap_h);
    return 0;
}
