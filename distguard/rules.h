#ifndef RULES_H
#define RULES_H

#include "shared.h"
#include <unordered_map>
#include <unordered_set>
#include <string>
#include <chrono>
#include <regex>
#include <map>
#include <ctime>

class TrafficAnalyzer
{
private:
    // IP frequency monitoring
    std::unordered_map<std::string, int> ipCounter;
    std::unordered_map<std::string, std::time_t> ipFirstSeen;

    // Port-based detection
    std::unordered_set<int> suspiciousPorts = {
        23,    // Telnet
        6667,  // IRC (often used by botnets)
        31337, // Back Orifice
        4444,  // Metasploit default
        5554,  // Sasser worm
        9996,  // Common botnet port
        1080   // SOCKS proxy (often misconfigured)
    };

    // Content-based detection
    std::vector<std::string> maliciousKeywords = {
        "malware", "exploit", "virus", "trojan", "botnet", "backdoor",
        "shell", "phish", "ransomware", "password", "credentials",
        "admin", "root", "cmd.exe", "powershell", "base64", "/bin/sh"};

    // Regular expressions for pattern matching
    std::vector<std::regex> patterns = {
        std::regex("(?:eval|exec|system)\\s*\\(.*\\)"),                    // Command execution
        std::regex("(?:select|union|insert|update|delete)\\s+.*\\s+from"), // SQL operations
        std::regex("(?:\\/\\.\\.\\/|\\.\\.\\/\\.\\.\\/|\\.\\.\\\\)"),      // Directory traversal
        std::regex("<\\s*script.*>.*<\\s*\\/\\s*script\\s*>")              // Script injection
    };

    // Port scan detection
    std::map<std::string, std::unordered_set<int>> ipPortsScanned;

    // Session tracking for stateful analysis
    struct Session
    {
        std::time_t startTime;
        int packetCount;
        int byteCount;
    };
    std::map<std::string, Session> sessions; // Key is "srcIP:dstIP:port"

    // Helper function to create session key
    std::string createSessionKey(const Packet &packet)
    {
        return packet.src_ip + ":" + packet.dst_ip + ":" + std::to_string(packet.port);
    }

public:
    std::pair<bool, std::string> analyze(const Packet &packet)
    {
        std::time_t currentTime = std::time(nullptr);

        // Update IP tracking
        if (ipCounter.find(packet.src_ip) == ipCounter.end())
        {
            ipFirstSeen[packet.src_ip] = currentTime;
        }
        ipCounter[packet.src_ip]++;

        // Update port scan detection
        ipPortsScanned[packet.src_ip].insert(packet.port);

        // Update session tracking
        std::string sessionKey = createSessionKey(packet);
        if (sessions.find(sessionKey) == sessions.end())
        {
            sessions[sessionKey] = {currentTime, 1, static_cast<int>(packet.payload.size())};
        }
        else
        {
            sessions[sessionKey].packetCount++;
            sessions[sessionKey].byteCount += static_cast<int>(packet.payload.size());
        }

        // 1. Rate limiting detection (too many packets from same IP in short time)
        if (ipCounter[packet.src_ip] > 30 &&
            (currentTime - ipFirstSeen[packet.src_ip]) < 60)
        { // 30+ packets in 60 seconds
            return {true, "Possible DoS attack - high packet rate from " + packet.src_ip};
        }

        // 2. Port scan detection (accessing many different ports)
        if (ipPortsScanned[packet.src_ip].size() > 15)
        {
            return {true, "Possible port scan from " + packet.src_ip};
        }

        // 3. Suspicious port check
        if (suspiciousPorts.count(packet.port))
        {
            return {true, "Suspicious destination port: " + std::to_string(packet.port)};
        }

        // 4. Excessive session volume
        Session &session = sessions[sessionKey];
        if (session.packetCount > 100 && (currentTime - session.startTime) < 30)
        {
            return {true, "Excessive traffic in session from " + packet.src_ip};
        }

        // 5. Payload signature scan
        for (const auto &keyword : maliciousKeywords)
        {
            if (packet.payload.find(keyword) != std::string::npos)
            {
                return {true, "Payload contains malicious keyword: " + keyword};
            }
        }

        // 6. Pattern-based detection using regex
        for (size_t i = 0; i < patterns.size(); i++)
        {
            if (std::regex_search(packet.payload, patterns[i]))
            {
                std::string patternType;
                switch (i)
                {
                case 0:
                    patternType = "command execution";
                    break;
                case 1:
                    patternType = "SQL operation";
                    break;
                case 2:
                    patternType = "directory traversal";
                    break;
                case 3:
                    patternType = "script injection";
                    break;
                default:
                    patternType = "suspicious pattern";
                    break;
                }
                return {true, "Detected potential " + patternType + " attempt"};
            }
        }

        // Clean up old entries periodically (every ~100 packets per source IP)
        if (ipCounter[packet.src_ip] % 100 == 0)
        {
            auto it = sessions.begin();
            while (it != sessions.end())
            {
                if (currentTime - it->second.startTime > 300)
                { // 5 minutes old
                    it = sessions.erase(it);
                }
                else
                {
                    ++it;
                }
            }
        }

        return {false, "Traffic is normal"};
    }

    // Method to reset the analyzer state
    void reset()
    {
        ipCounter.clear();
        ipFirstSeen.clear();
        ipPortsScanned.clear();
        sessions.clear();
    }
};

#endif // RULES_H