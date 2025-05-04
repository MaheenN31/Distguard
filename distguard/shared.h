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
        return src_ip + "," + dst_ip + "," + 
               std::to_string(src_port) + "," +
               std::to_string(port) + "," + 
               std::to_string(tcp_seq) + "," +
               std::to_string(tcp_flags) + "," + 
               payload;
    }

    static Packet deserialize(const std::string& data)
    {
        std::stringstream ss(data);
        Packet packet;
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
        return packet;
    }
};

#endif // SHARED_H