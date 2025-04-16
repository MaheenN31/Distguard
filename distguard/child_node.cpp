#include <iostream>
#include <boost/asio.hpp>
#include <string>
#include <vector>
#include <sstream>
#include "shared.h"
#include "rules.h"

using boost::asio::ip::tcp;

int main1() {
    const std::string server_ip = "127.0.0.1";
    const int server_port = 5555;

    try {
        boost::asio::io_context io_context;
        tcp::socket socket(io_context);
        socket.connect(tcp::endpoint(boost::asio::ip::make_address(server_ip), server_port));

        std::cout << "[ChildNode] Connected to Main Node at " << server_ip << ":" << server_port << std::endl;

        // Read incoming data
        boost::asio::streambuf buffer;
        std::istream is(&buffer);
        std::vector<Packet> packets;

        while (true) {
            boost::asio::read_until(socket, buffer, "\n");
            std::string line;
            std::getline(is, line);

            if (line == "END") break;

            if (!line.empty()) {
                std::cout << "[ChildNode] Received packet: " << line << std::endl;
                packets.push_back(Packet::deserialize(line));
            }
        }

        std::cout << "[ChildNode] Received " << packets.size() << " packets. Analyzing..." << std::endl;

        // Analyze packets
        TrafficAnalyzer analyzer;
        int malicious_count = 0;
        std::ostringstream result;

        for (const auto& pkt : packets) {
            std::pair<bool, std::string> analysis = analyzer.analyze(pkt);
            if (analysis.first) {
                ++malicious_count;
                result << "[!] Malicious: " << analysis.second << " | Src: " << pkt.src_ip << "\n";
            }
        }

        std::ostringstream final_response;
        final_response << "Total: " << packets.size()
            << ", Malicious: " << malicious_count
            << "\n" << result.str();

        std::string result_str = final_response.str();

        boost::asio::write(socket, boost::asio::buffer(result_str + "\n"));

        std::cout << "[ChildNode] Sent analysis result back to Main Node.\n" << std::endl;

    }
    catch (std::exception& e) {
        std::cerr << "[ChildNode] Exception: " << e.what() << std::endl;
    }

    return 0;
}