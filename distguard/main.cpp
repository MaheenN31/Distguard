#include <iostream>
#include <string>
#include "traffic_simulator.h"
#include "rules.h"

// Forward declarations for the different entry points
int main1(); // child_node.cpp
int main2(); // main_node.cpp
int main3(); // packet_capture.cpp
int main4(); // live_capture.cpp - Real-time traffic analysis
int main6(); // dashboard.cpp - GUI Dashboard

// New traffic simulator entry point
int main5()
{
    std::cout << "Running Traffic Simulator..." << std::endl;
    std::cout << "How many packets would you like to generate? ";

    int count;
    std::cin >> count;

    if (count <= 0) {
        std::cout << "Invalid number of packets. Using default (100)." << std::endl;
        count = 100;
    }

    std::cout << "Generating " << count << " packets..." << std::endl;

    // Generate simulated traffic
    std::vector<Packet> packets = TrafficSimulator::generateTraffic(count);

    std::cout << "Generated " << packets.size() << " packets. Analyzing..." << std::endl;

    // Analyze the simulated packets
    TrafficAnalyzer analyzer;
    int malicious_count = 0;

    std::cout << "\n====== Traffic Analysis Results ======\n" << std::endl;

    for (const auto& packet : packets) {
        // Analyze each packet
        std::pair<bool, std::string> result = analyzer.analyze(packet);

        // If it's malicious, print details
        if (result.first) {
            malicious_count++;
            std::cout << "\n[ALERT] " << result.second << std::endl;
            std::cout << "  Source IP: " << packet.src_ip << std::endl;
            std::cout << "  Dest IP: " << packet.dst_ip << std::endl;
            std::cout << "  Port: " << packet.port << std::endl;
            std::cout << "------------------------------------------" << std::endl;
        }
    }

    std::cout << "\n====== Summary ======" << std::endl;
    std::cout << "Total packets: " << packets.size() << std::endl;
    std::cout << "Malicious packets: " << malicious_count << std::endl;
    std::cout << "Detection rate: " << (float)malicious_count / packets.size() * 100 << "%" << std::endl;

    std::cout << "\nPress Enter to return to the main menu...";
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    std::cin.get();

    return 0;
}

int main()
{
    while (true) {
        std::cout << "\nTrafficAnalyzer - Select a module to run:" << std::endl;
        std::cout << "1. Child Node (Network Traffic Analyzer)" << std::endl;
        std::cout << "2. Main Node (Traffic Distribution Server)" << std::endl;
        std::cout << "3. Packet Capture (Basic Network Monitoring)" << std::endl;
        std::cout << "4. Live Traffic Analysis (Real-time Detection)" << std::endl;
        std::cout << "5. Traffic Simulator (Generate and Analyze Test Traffic)" << std::endl;
        std::cout << "6. Dashboard (Graphical Interface)" << std::endl;
        std::cout << "0. Exit" << std::endl;
        std::cout << "Choice: ";

        int choice;
        std::cin >> choice;

        switch (choice)
        {
        case 0:
            return 0;
        case 1:
            main1();
            break;
        case 2:
            main2();
            break;
        case 3:
            main3();
            break;
        case 4:
            main4();
            break;
        case 5:
            main5();
            break;
        case 6:
            main6();
            break;
        default:
            std::cout << "Invalid choice!" << std::endl;
        }
    }

    return 0;
}