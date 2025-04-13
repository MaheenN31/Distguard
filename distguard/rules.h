#ifndef RULES_H
#define RULES_H

#include "shared.h"
#include <unordered_map>
#include <unordered_set>
#include <string>
#include <chrono>

class TrafficAnalyzer {
private:
    std::unordered_map<std::string, int> ipCounter;
    std::unordered_set<int> suspiciousPorts = { 23, 6667, 31337 }; // Telnet, IRC, known malicious
    std::vector<std::string> maliciousKeywords = { "malware", "exploit", "virus", "trojan" };

public:
    std::pair<bool, std::string> analyze(const Packet& packet)//Returns true if packet is malicious along with a reason.
    {
        // Track IP frequency
        ipCounter[packet.src_ip]++;
        if (ipCounter[packet.src_ip] > 10) {
            return { true, "Too many packets from same IP (" + packet.src_ip + ")" };
        }

        // Suspicious port check
        if (suspiciousPorts.count(packet.port)) {
            return { true, "Suspicious destination port: " + std::to_string(packet.port) };
        }

        // Payload signature scan
        for (const auto& keyword : maliciousKeywords) {
            if (packet.payload.find(keyword) != std::string::npos) {
                return { true, "Payload contains malicious keyword: " + keyword };
            }
        }

        return { false, "Traffic is normal" };
    }
};

#endif // RULES_H

