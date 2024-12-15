#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <json-c/json.h>
#include <unistd.h>
#include <signal.h>
#include <stdbool.h>        // Fix: Include stdbool.h for bool type
#include <sys/socket.h>
#include <net/if.h>
#include <linux/if_packet.h>  // Fix: Include this for sockaddr_ll and if_nametoindex

#define BINDING_FILE "ip_mac_bindings.json"
#define LOG_FILE "arp_defense.log"

// Function prototypes
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkt_header, const u_char *packet);
void load_bindings(const char *filename);
bool is_valid_binding(const char *ip, const char *mac);
void log_event(const char *event_type, const char *ip, const char *mac, const char *reason);
void broadcast_arp_response(const char *iface, const char *ip, const char *mac);
void setup_firewall_rule(const char *ip);

// Global variables
struct json_object *bindings = NULL;
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

    // Load IP-MAC bindings
    load_bindings(BINDING_FILE);

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

    // Start capturing packets
    printf("Starting ARP monitoring... Press Ctrl+C to stop.\n");
    while (running) {
        pcap_loop(handle, 0, packet_handler, (u_char *)dev);
    }

    // Cleanup and close pcap handle
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

    printf("[DEBUG] Captured ARP packet: IP = %s, MAC = %s\n", sender_ip, sender_mac);

    if (!is_valid_binding(sender_ip, sender_mac)) {
        printf("[ALERT] Spoofing detected from IP: %s MAC: %s\n", sender_ip, sender_mac);
        log_event("spoofing_detected", sender_ip, sender_mac, "Invalid MAC for IP");
        setup_firewall_rule(sender_ip);

        // Use correct MAC address for the ARP response
        const char *correct_mac = "08:00:27:b0:a5:10";
        broadcast_arp_response((char *)user_data, sender_ip, correct_mac);

        printf("[INFO] ARP response broadcasted to correct IP-MAC pair\n");
    }
}

void load_bindings(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Error opening bindings file");
        exit(1);
    }

    fseek(file, 0, SEEK_END);
    long length = ftell(file);
    fseek(file, 0, SEEK_SET);

    char *content = malloc(length + 1);  // Ensure enough space for null terminator
    if (!content) {
        perror("Memory allocation failed");
        fclose(file);
        exit(1);
    }

    fread(content, 1, length, file);
    content[length] = '\0';  // Ensure the string is null-terminated
    fclose(file);

    bindings = json_tokener_parse(content);
    free(content);

    if (!bindings) {
        fprintf(stderr, "Error parsing bindings file\n");
        exit(1);
    }

    // Log the bindings loaded for debugging purposes
    printf("[INFO] Loaded IP-MAC bindings: %s\n", json_object_to_json_string(bindings));
}

bool is_valid_binding(const char *ip, const char *mac) {
    struct json_object *value;
    if (json_object_object_get_ex(bindings, ip, &value)) {
        const char *expected_mac = json_object_get_string(value);
        return strcmp(mac, expected_mac) == 0;
    }
    return false;
}

void log_event(const char *event_type, const char *ip, const char *mac, const char *reason) {
    FILE *log = fopen(LOG_FILE, "a");
    if (!log) return;

    struct json_object *log_entry = json_object_new_object();
    json_object_object_add(log_entry, "event_type", json_object_new_string(event_type));
    json_object_object_add(log_entry, "ip", json_object_new_string(ip));
    json_object_object_add(log_entry, "mac", json_object_new_string(mac));
    json_object_object_add(log_entry, "reason", json_object_new_string(reason));

    fprintf(log, "%s\n", json_object_to_json_string(log_entry));
    fclose(log);
    json_object_put(log_entry);
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
    memcpy(arp->arp_tha, eth->ether_dhost, ETH_ALEN);
    inet_pton(AF_INET, ip, arp->arp_tpa);

    // Send ARP response
    struct sockaddr_ll sa = {0};
    sa.sll_protocol = htons(ETH_P_ARP);
    sa.sll_ifindex = if_nametoindex(iface);
    sendto(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&sa, sizeof(sa));

    close(sockfd);
}

void setup_firewall_rule(const char *ip) {
    char command[256];
    snprintf(command, sizeof(command), "sudo iptables -A INPUT -s %s -j DROP", ip);
    system(command);
}
