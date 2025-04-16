#include <iostream>
#include <string>

// Forward declarations for the different entry points
int main1(); // child_node.cpp
int main2(); // main_node.cpp
int main3(); // packet_capture.cpp
int main4(); // live_capture.cpp - Real-time traffic analysis

int main()
{
    std::cout << "TrafficAnalyzer - Select a module to run:" << std::endl;
    std::cout << "1. Child Node (Network Traffic Analyzer)" << std::endl;
    std::cout << "2. Main Node (Traffic Distribution Server)" << std::endl;
    std::cout << "3. Packet Capture (Basic Network Monitoring)" << std::endl;
    std::cout << "4. Live Traffic Analysis (Real-time Detection)" << std::endl;
    std::cout << "Choice: ";

    int choice;
    std::cin >> choice;

    switch (choice)
    {
    case 1:
        return main1();
    case 2:
        return main2();
    case 3:
        return main3();
    case 4:
        return main4();
    default:
        std::cout << "Invalid choice!" << std::endl;
        return 1;
    }
}