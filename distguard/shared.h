#ifndef SHARED_H
#define SHARED_H

#include <string>
#include <vector>
#include <sstream>

// used to send packets over tcp as text
struct Packet
{
    std::string src_ip;
    std::string dst_ip;
    int port = 0;
    std::string payload;

    std::string serialize() const
    {
        return src_ip + "|" + dst_ip + "|" + std::to_string(port) + "|" + payload;
    }

    static Packet deserialize(const std::string &data)
    {
        std::stringstream ss(data);
        Packet packet;
        std::getline(ss, packet.src_ip, '|');
        std::getline(ss, packet.dst_ip, '|');
        std::string port_str;
        std::getline(ss, port_str, '|');
        packet.port = std::stoi(port_str);
        std::getline(ss, packet.payload, '|');
        return packet;
    }
};

#endif // SHARED_H