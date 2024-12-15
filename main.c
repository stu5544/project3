#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <unistd.h>
#include <signal.h>
#include <stdbool.h>

#define LOG_FILE "arp_defense.log"

// Function prototypes
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkt_header, const u_char *packet);
void log_event(const char *event_type, const char *ip, const char *mac);
void broadcast_arp_response(const char *iface, const char *ip, const char *mac);

// Global variables
bool running = true;

void handle_signal(int signal) {
    if (signal == SIGINT) {
        printf("\nStopping ARP Spoofing Defense System...\n");
        running = false;
    }
}

int main(int argc, char *argv[]) {
    char *dev, errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // Find available devices
    pcap_if_t *alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return 1;
    }

    // Select the first device
    dev = alldevs->name;
    printf("Using device: %s\n", dev);

    // Open the device for live capture
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening device: %s\n", errbuf);
        pcap_freealldevs(alldevs);
        return 1;
    }

    // Free device list
    pcap_freealldevs(alldevs);

    // Set signal handler for clean exit
    signal(SIGINT, handle_signal);

    // Set filter for ARP packets
    struct bpf_program filter;
    if (pcap_compile(handle, &filter, "arp", 0, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(handle, &filter) == -1) {
        fprintf(stderr, "Error setting filter: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }

    printf("Starting ARP monitoring... Press Ctrl+C to stop.\n");

    // Start packet processing loop
    while (running) {
        pcap_dispatch(handle, -1, packet_handler, NULL);
    }

    // Cleanup
    pcap_close(handle);

    return 0;
}

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkt_header, const u_char *packet) {
    struct ether_header *eth_header = (struct ether_header *) packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_ARP) return;

    struct ether_arp *arp_packet = (struct ether_arp *) (packet + sizeof(struct ether_header));
    char sender_ip[INET_ADDRSTRLEN], sender_mac[18];

    inet_ntop(AF_INET, arp_packet->arp_spa, sender_ip, INET_ADDRSTRLEN);
    snprintf(sender_mac, sizeof(sender_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
             arp_packet->arp_sha[0], arp_packet->arp_sha[1], arp_packet->arp_sha[2],
             arp_packet->arp_sha[3], arp_packet->arp_sha[4], arp_packet->arp_sha[5]);

    // Simple ARP Spoofing Detection: If MAC is 00:00:00:00:00:00 (invalid MAC)
    if (strcmp(sender_mac, "00:00:00:00:00:00") == 0) {
        printf("[ALERT] ARP spoofing detected from IP: %s MAC: %s\n", sender_ip, sender_mac);
        log_event("spoofing_detected", sender_ip, sender_mac);

        // Broadcast ARP response with the correct MAC
        const char *correct_mac = "08:00:27:b0:a5:10"; // Example correct MAC
        broadcast_arp_response((char *)user_data, sender_ip, correct_mac);

        printf("[INFO] ARP response broadcasted to correct IP-MAC pair\n");
    }
}

void log_event(const char *event_type, const char *ip, const char *mac) {
    FILE *log = fopen(LOG_FILE, "a");
    if (!log) return;

    fprintf(log, "{\"event_type\": \"%s\", \"ip\": \"%s\", \"mac\": \"%s\"}\n", event_type, ip, mac);
    fclose(log);
}

void broadcast_arp_response(const char *iface, const char *ip, const char *mac) {
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sockfd < 0) {
        perror("Socket creation failed");
        return;
    }

    unsigned char buffer[42];
    memset(buffer, 0, sizeof(buffer));

    struct ether_header *eth = (struct ether_header *) buffer;
    struct ether_arp *arp = (struct ether_arp *) (buffer + sizeof(struct ether_header));

    // Set Ethernet header
    memset(eth->ether_dhost, 0xff, ETH_ALEN); // Broadcast
    sscanf(mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &eth->ether_shost[0], &eth->ether_shost[1], &eth->ether_shost[2],
           &eth->ether_shost[3], &eth->ether_shost[4], &eth->ether_shost[5]);
    eth->ether_type = htons(ETHERTYPE_ARP);

    // Set ARP packet
    arp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp->ea_hdr.ar_pro = htons(ETHERTYPE_IP);
    arp->ea_hdr.ar_hln = ETH_ALEN;
    arp->ea_hdr.ar_pln = 4;
    arp->ea_hdr.ar_op = htons(ARPOP_REPLY);
    sscanf(mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &arp->arp_sha[0], &arp->arp_sha[1], &arp->arp_sha[2],
           &arp->arp_sha[3], &arp->arp_sha[4], &arp->arp_sha[5]);
    inet_pton(AF_INET, ip, arp->arp_spa);
    memset(arp->arp_tha, 0xff, ETH_ALEN); // Broadcast target hardware address
    inet_pton(AF_INET, ip, arp->arp_tpa);

    struct sockaddr_ll socket_address = {0};
    socket_address.sll_ifindex = if_nametoindex(iface);
    socket_address.sll_halen = ETH_ALEN;
    memset(socket_address.sll_addr, 0xff, ETH_ALEN);

    // Send ARP response
    if (sendto(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *) &socket_address, sizeof(socket_address)) < 0) {
        perror("Failed to send ARP response");
    }

    close(sockfd);
}
