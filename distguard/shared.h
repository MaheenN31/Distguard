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
    int src_port = 0;
    uint32_t tcp_seq = 0;
    std::string payload;
    uint8_t tcp_flags = 0;

    std::string serialize() const
    {
        // Format: [Packet] sourceIP -> destIP:port [flags] seq=seqNum info
        std::stringstream ss;
        ss << "[Packet] " << src_ip << " -> " << dst_ip << ":" << port
           << " [" << std::to_string(tcp_flags) << "] seq=" << tcp_seq << " " << payload;
        return ss.str();
    }

    static Packet deserialize(const std::string &data)
    {
        Packet packet;

        // Try to parse the new format first
        if (data.find("[Packet]") != std::string::npos)
        {
            std::stringstream ss(data);
            std::string token;

            // Skip [Packet]
            ss >> token;

            // Get source IP
            ss >> packet.src_ip;

            // Skip ->
            ss >> token;

            // Get destination IP and port
            std::string dest;
            ss >> dest;
            size_t colon_pos = dest.find(':');
            if (colon_pos != std::string::npos)
            {
                packet.dst_ip = dest.substr(0, colon_pos);
                packet.port = std::stoi(dest.substr(colon_pos + 1));
            }

            // Skip [
            ss >> token;

            // Get flags
            ss >> token;
            packet.tcp_flags = static_cast<uint8_t>(std::stoi(token));

            // Skip ]
            ss >> token;

            // Get seq
            ss >> token;
            size_t eq_pos = token.find('=');
            if (eq_pos != std::string::npos)
            {
                packet.tcp_seq = std::stoul(token.substr(eq_pos + 1));
            }

            // Get remaining as payload
            std::getline(ss, packet.payload);
            if (!packet.payload.empty() && packet.payload[0] == ' ')
            {
                packet.payload = packet.payload.substr(1);
            }
        }
        // Try to parse the old format
        else
        {
            std::stringstream ss(data);
            std::string temp;

            std::getline(ss, packet.src_ip, ',');
            std::getline(ss, packet.dst_ip, ',');

            std::getline(ss, temp, ',');
            packet.src_port = std::stoi(temp);

            std::getline(ss, temp, ',');
            packet.port = std::stoi(temp);

            std::getline(ss, temp, ',');
            packet.tcp_seq = std::stoul(temp);

            std::getline(ss, temp, ',');
            packet.tcp_flags = static_cast<uint8_t>(std::stoi(temp));

            std::getline(ss, packet.payload);
        }

        return packet;
    }
};

#endif // SHARED_H