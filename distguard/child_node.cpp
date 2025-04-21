#include <iostream>
#include <boost/asio.hpp>
#include <string>
#include <vector>
#include <sstream>
#include "shared.h"
#include "rules.h"

using boost::asio::ip::tcp;

// Function for regular batch processing mode
int process_batch_mode()
{
    const std::string server_ip = "127.0.0.1";
    const int server_port = 5555;

    try
    {
        boost::asio::io_context io_context;
        tcp::socket socket(io_context);
        socket.connect(tcp::endpoint(boost::asio::ip::make_address(server_ip), server_port));

        std::cout << "[ChildNode] Connected to Main Node at " << server_ip << ":" << server_port << std::endl;

        // Read incoming data
        boost::asio::streambuf buffer;
        std::istream is(&buffer);
        std::vector<Packet> packets;

        while (true)
        {
            boost::asio::read_until(socket, buffer, "\n");
            std::string line;
            std::getline(is, line);

            if (line == "END")
                break;

            if (!line.empty())
            {
                std::cout << "[ChildNode] Received packet: " << line << std::endl;
                packets.push_back(Packet::deserialize(line));
            }
        }

        std::cout << "[ChildNode] Received " << packets.size() << " packets. Analyzing..." << std::endl;

        // Analyze packets
        TrafficAnalyzer analyzer;
        int malicious_count = 0;
        std::ostringstream result;

        for (const auto& pkt : packets)
        {
            std::pair<bool, std::string> analysis = analyzer.analyze(pkt);
            if (analysis.first)
            {
                ++malicious_count;
                result << "\n[ALERT] " << analysis.second 
                       << "\n  Source IP: " << pkt.src_ip 
                       << "\n  Dest IP: " << pkt.dst_ip 
                       << "\n  Port: " << pkt.port 
                       << "\n------------------------------------------\n";
            }
        }

        std::ostringstream final_response;
        final_response << "Total Packets: " << packets.size()
                      << " | Malicious: " << malicious_count;
        
        if (malicious_count > 0) {
            final_response << "\nDetailed Alerts:";
            final_response << result.str();
        }

        // Send the response with proper message termination
        std::string result_str = final_response.str();
        boost::asio::streambuf response_buf;
        std::ostream os(&response_buf);
        os << result_str << "\n\n";
        boost::asio::write(socket, response_buf);

        std::cout << "[ChildNode] Sent analysis result back to Main Node.\n"
            << std::endl;
    }
    catch (std::exception& e)
    {
        std::cerr << "[ChildNode] Exception: " << e.what() << std::endl;
    }

    return 0;
}

// Function for continuous live capture analysis mode
int process_live_capture_mode()
{
    const std::string server_ip = "127.0.0.1";
    const int server_port = 5555;

    try
    {
        boost::asio::io_context io_context;
        tcp::socket socket(io_context);

        std::cout << "[WorkerNode] Connecting to main node at " << server_ip << ":" << server_port << std::endl;
        socket.connect(tcp::endpoint(boost::asio::ip::make_address(server_ip), server_port));
        std::cout << "[WorkerNode] Connected to main node." << std::endl;

        // Create analyzer
        TrafficAnalyzer analyzer;

        // Process packets in continuous mode
        while (true)
        {
            // Storage for the current batch
            std::vector<Packet> packets;

            // Read incoming packets until END marker
            boost::asio::streambuf buffer;
            std::istream is(&buffer);

            while (true)
            {
                boost::asio::read_until(socket, buffer, "\n");
                std::string line;
                std::getline(is, line);

                if (line == "END")
                    break;

                if (!line.empty())
                {
                    packets.push_back(Packet::deserialize(line));
                }
            }

            if (packets.empty())
            {
                // Main node is likely shutting down or connection was lost
                std::cout << "[WorkerNode] Received empty batch, exiting..." << std::endl;
                break;
            }

            // Analyze packets
            int malicious_count = 0;
            std::ostringstream result;

            for (const auto& pkt : packets)
            {
                std::pair<bool, std::string> analysis = analyzer.analyze(pkt);
                if (analysis.first)
                {
                    ++malicious_count;
                    result << "\n[ALERT] " << analysis.second 
                           << "\n  Source IP: " << pkt.src_ip 
                           << "\n  Dest IP: " << pkt.dst_ip 
                           << "\n  Port: " << pkt.port 
                           << "\n------------------------------------------\n";
                }
            }

            // Send results back
            std::ostringstream final_response;
            final_response << "Total Packets: " << packets.size()
                          << " | Malicious: " << malicious_count;
            
            if (malicious_count > 0) {
                final_response << "\nDetailed Alerts:";
                final_response << result.str();
            }

            // Send the response with proper message termination
            std::string result_str = final_response.str();
            boost::asio::streambuf response_buf;
            std::ostream os(&response_buf);
            os << result_str << "\n\n";
            boost::asio::write(socket, response_buf);
        }
    }
    catch (std::exception& e)
    {
        std::cerr << "[WorkerNode] Exception: " << e.what() << std::endl;
    }

    return 0;
}

int main1()
{
    std::cout << "Select child node mode:" << std::endl;
    std::cout << "1. Batch processing (original mode)" << std::endl;
    std::cout << "2. Live capture worker node" << std::endl;
    std::cout << "Mode: ";

    int mode;
    std::cin >> mode;

    if (mode == 2)
    {
        return process_live_capture_mode();
    }
    else
    {
        return process_batch_mode();
    }
}