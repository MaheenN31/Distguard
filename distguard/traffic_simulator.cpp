#include "traffic_simulator.h"
#include <random>
#include <ctime>

std::vector<Packet> TrafficSimulator::generateTraffic(int count) {
    std::vector<Packet> packets;
    std::vector<std::string> ip_pool = {
        "192.168.1.10", "192.168.1.15", "10.0.0.2", "10.0.0.5", "172.16.0.3"
    };
    std::vector<std::string> payloads = {
        "normal data", "request info", "GET /index.html", "hello world", "malware download",
        "exploit attempt", "update virus", "safe data", "trojan detected", "nothing suspicious"
    };
    std::vector<int> ports = { 80, 443, 21, 23, 6667, 31337, 22, 25 };

    std::mt19937 rng(static_cast<unsigned>(time(nullptr)));
    std::uniform_int_distribution<> ip_dist(0, ip_pool.size() - 1);
    std::uniform_int_distribution<> port_dist(0, ports.size() - 1);
    std::uniform_int_distribution<> payload_dist(0, payloads.size() - 1);

    for (int i = 0; i < count; ++i) {
        Packet pkt;
        pkt.src_ip = ip_pool[ip_dist(rng)];
        pkt.dst_ip = "192.168.0.1";
        pkt.port = ports[port_dist(rng)];
        pkt.payload = payloads[payload_dist(rng)];
        packets.push_back(pkt);
    }

    return packets;
}