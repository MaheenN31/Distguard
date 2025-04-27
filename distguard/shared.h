#ifndef SHARED_H
#define SHARED_H

#include <string>
#include <vector>
#include <sstream>
#include <iostream>

// used to send packets over tcp as text
struct Packet
{
    std::string src_ip;
    std::string dst_ip;
    int port = 0;
    std::string payload;
    uint8_t flags = 0; // TCP flags (SYN, ACK, etc.)
    uint32_t seq = 0;  // TCP sequence number

    std::string serialize() const
    {
        return src_ip + "|" + dst_ip + "|" + std::to_string(port) + "|" +
               std::to_string(flags) + "|" + std::to_string(seq) + "|" + payload;
    }

    static Packet deserialize(const std::string& data)
    {
        std::stringstream ss(data);
        Packet packet;
        std::getline(ss, packet.src_ip, '|');
        std::getline(ss, packet.dst_ip, '|');

        std::string port_str;
        std::getline(ss, port_str, '|');

        // Add error handling for stoi conversion
        try
        {
            if (!port_str.empty())
            {
                packet.port = std::stoi(port_str);
            }
            else
            {
                packet.port = 0; // Default port if empty
            }
        }
        catch (const std::exception& e)
        {
            std::cerr << "Error parsing port: " << e.what() << ", input: '" << port_str << "'" << std::endl;
            packet.port = 0; // Default to 0 on error
        }

        // Parse TCP flags
        std::string flags_str;
        std::getline(ss, flags_str, '|');
        try
        {
            if (!flags_str.empty())
            {
                packet.flags = std::stoi(flags_str);
            }
        }
        catch (const std::exception &e)
        {
            std::cerr << "Error parsing TCP flags: " << e.what() << std::endl;
            packet.flags = 0;
        }

        // Parse sequence number
        std::string seq_str;
        std::getline(ss, seq_str, '|');
        try
        {
            if (!seq_str.empty())
            {
                packet.seq = std::stoul(seq_str);
            }
        }
        catch (const std::exception &e)
        {
            std::cerr << "Error parsing sequence number: " << e.what() << std::endl;
            packet.seq = 0;
        }

        std::getline(ss, packet.payload, '|');
        return packet;
    }
};

#endif // SHARED_H