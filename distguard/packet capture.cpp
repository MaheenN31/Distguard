#include <pcap.h>
#include <iostream>

int main3()
{
    // Declare variables
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Find all network devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        return 1;
    }

    std::cout << "Available Network Devices:" << std::endl;
    int deviceIndex = 0;

    // Loop through the list of devices and print them
    for (pcap_if_t* dev = alldevs; dev != nullptr; dev = dev->next)
    {
        std::cout << deviceIndex++ << ". " << dev->name << " - "
            << (dev->description ? dev->description : "No description") << std::endl;
    }

    // Ask user to select a device for packet capture
    std::cout << "Select a device by number: ";
    int choice;
    std::cin >> choice;

    // Select the chosen device
    pcap_if_t* selected_device = alldevs;
    for (int i = 0; i < choice; ++i)
    {
        selected_device = selected_device->next;
    }

    // Open the selected device for packet capturing
    pcap_t* handle = pcap_open_live(selected_device->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr)
    {
        std::cerr << "Error opening device: " << errbuf << std::endl;
        return 1;
    }

    std::cout << "Capturing packets on device: " << selected_device->name << std::endl;

    // Capture one packet and display its length
    struct pcap_pkthdr header;
    const u_char* packet;
    packet = pcap_next(handle, &header);

    std::cout << "Captured a packet with length: " << header.len << " bytes" << std::endl;

    // Close the handle
    pcap_close(handle);

    // Free the device list
    pcap_freealldevs(alldevs);

    return 0;
}
