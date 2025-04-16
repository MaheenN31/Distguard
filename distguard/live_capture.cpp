#define HAVE_REMOTE
#define WPCAP
#include <winsock2.h>
#include <windows.h>
#include <pcap.h>
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <functional>
#include "shared.h"
#include "rules.h"

// Ethernet header structure
struct ether_header
{
    u_char ether_dhost[6]; // Destination host address
    u_char ether_shost[6]; // Source host address
    u_short ether_type;    // Protocol type
};

// IP header structure
struct ip_header
{
    u_char ip_vhl;                 // Version and header length
    u_char ip_tos;                 // Type of service
    u_short ip_len;                // Total length
    u_short ip_id;                 // Identification
    u_short ip_off;                // Fragment offset field
    u_char ip_ttl;                 // Time to live
    u_char ip_p;                   // Protocol
    u_short ip_sum;                // Checksum
    struct in_addr ip_src, ip_dst; // Source and dest address
};

// TCP header structure
struct tcp_header
{
    u_short th_sport; // Source port
    u_short th_dport; // Destination port
    u_int th_seq;     // Sequence number
    u_int th_ack;     // Acknowledgement number
    u_char th_offx2;  // Data offset and reserved
    u_char th_flags;  // Flags
    u_short th_win;   // Window
    u_short th_sum;   // Checksum
    u_short th_urp;   // Urgent pointer
};

// Packet processing callback function
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    TrafficAnalyzer *analyzer = reinterpret_cast<TrafficAnalyzer *>(user_data);

    // Define Ethernet header
    const ether_header *eth_header = reinterpret_cast<const ether_header *>(packet);

    // Skip non-IP packets
    if (ntohs(eth_header->ether_type) != 0x0800)
    {
        return;
    }

    // Define IP header
    const ip_header *ip_hdr = reinterpret_cast<const ip_header *>(packet + sizeof(ether_header));

    // Calculate IP header length
    int ip_header_len = (ip_hdr->ip_vhl & 0x0f) * 4;

    // Skip non-TCP packets
    if (ip_hdr->ip_p != 6)
    { // 6 is the protocol number for TCP
        return;
    }

    // Define TCP header
    const tcp_header *tcp_hdr = reinterpret_cast<const tcp_header *>(packet + sizeof(ether_header) + ip_header_len);

    // Create Packet structure for analysis
    Packet pkt;

    // Convert IP addresses to strings
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_hdr->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_hdr->ip_dst), dst_ip, INET_ADDRSTRLEN);

    pkt.src_ip = src_ip;
    pkt.dst_ip = dst_ip;
    pkt.port = ntohs(tcp_hdr->th_dport);

    // Extract payload (simplistic approach)
    int payload_offset = sizeof(ether_header) + ip_header_len + ((tcp_hdr->th_offx2 >> 4) * 4);
    int payload_length = pkthdr->len - payload_offset;

    if (payload_length > 0)
    {
        // Copy up to 100 bytes of payload (to avoid huge buffers)
        int bytes_to_copy = payload_length > 100 ? 100 : payload_length;
        std::string payload(reinterpret_cast<const char *>(packet + payload_offset), bytes_to_copy);
        pkt.payload = payload;
    }
    else
    {
        pkt.payload = "[No Data]";
    }

    // Analyze the packet
    std::pair<bool, std::string> result = analyzer->analyze(pkt);

    // If it's malicious, print details
    if (result.first)
    {
        std::cout << "\n[ALERT] " << result.second << std::endl;
        std::cout << "  Source IP: " << pkt.src_ip << std::endl;
        std::cout << "  Dest IP: " << pkt.dst_ip << std::endl;
        std::cout << "  Port: " << pkt.port << std::endl;
        std::cout << "------------------------------------------" << std::endl;
    }
}

int main4()
{
    // Variables
    pcap_if_t *alldevs;
    pcap_if_t *device;
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    int device_count = 0;
    std::atomic<bool> running{true};

    // Find all available devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        return 1;
    }

    // Print list of devices
    std::cout << "Available network interfaces:" << std::endl;
    for (device = alldevs; device != nullptr; device = device->next)
    {
        std::cout << ++device_count << ". " << device->name;
        if (device->description)
        {
            std::cout << " (" << device->description << ")";
        }
        else
        {
            std::cout << " (No description available)";
        }
        std::cout << std::endl;
    }

    if (device_count == 0)
    {
        std::cout << "No interfaces found! Make sure Npcap is installed and you have permission." << std::endl;
        return 1;
    }

    // Ask user to select a device
    int selection;
    std::cout << "Enter the interface number (1-" << device_count << "): ";
    std::cin >> selection;

    if (selection < 1 || selection > device_count)
    {
        std::cout << "Invalid interface number!" << std::endl;
        pcap_freealldevs(alldevs);
        return 1;
    }

    // Jump to the selected device
    device = alldevs;
    for (int i = 0; i < selection - 1; i++)
    {
        device = device->next;
    }

    // Open the selected device
    handle = pcap_open_live(device->name, 65536, 1, 1000, errbuf);
    if (handle == nullptr)
    {
        std::cerr << "Could not open device: " << errbuf << std::endl;
        pcap_freealldevs(alldevs);
        return 1;
    }

    // Check if it's an Ethernet device
    if (device == nullptr || pcap_datalink(handle) != DLT_EN10MB)
    {
        std::cerr << "This program only works with Ethernet adapters." << std::endl;
        pcap_close(handle);
        pcap_freealldevs(alldevs);
        return 1;
    }

    // Create a TrafficAnalyzer instance
    TrafficAnalyzer analyzer;

    // Set up filter to capture only TCP packets
    struct bpf_program fcode;
    char filter[] = "tcp";
    if (pcap_compile(handle, &fcode, filter, 1, PCAP_NETMASK_UNKNOWN) < 0)
    {
        std::cerr << "Could not parse filter: " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        pcap_freealldevs(alldevs);
        return 1;
    }

    if (pcap_setfilter(handle, &fcode) < 0)
    {
        std::cerr << "Could not install filter: " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        pcap_freealldevs(alldevs);
        return 1;
    }

    // Free device list since we don't need it anymore
    pcap_freealldevs(alldevs);

    // Create a separate thread for keyboard input
    std::thread input_thread([&running]()
                             {
        std::cout << "Live capture started. Press Enter to stop..." << std::endl;
        std::cin.get(); // Clear previous Enter from device selection
        std::cin.get(); // Wait for Enter key
        running = false; });

    std::cout << "Starting traffic capture and analysis on selected interface..." << std::endl;
    std::cout << "Analyzing packets in real-time. Suspicious traffic will be flagged." << std::endl;

    // Start packet capture loop
    while (running)
    {
        struct pcap_pkthdr *header;
        const u_char *packet;
        int res = pcap_next_ex(handle, &header, &packet);

        if (res == 0)
        {
            // Timeout elapsed
            continue;
        }
        else if (res == -1)
        {
            // Error occurred
            std::cerr << "Error reading packets: " << pcap_geterr(handle) << std::endl;
            break;
        }
        else if (res == -2)
        {
            // End of pcap file (not applicable for live capture)
            break;
        }

        // Process the packet
        packet_handler(reinterpret_cast<u_char *>(&analyzer), header, packet);
    }

    // Cleanup
    input_thread.join();
    pcap_close(handle);

    std::cout << "Capture stopped." << std::endl;
    return 0;
}