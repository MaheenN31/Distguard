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

class TrafficAnalyzer{
private:
    // IP frequency monitoring
    std::unordered_map<std::string, int> ipCounter;
    std::unordered_map<std::string, std::time_t> ipFirstSeen;
    std::unordered_map<std::string, int> ipByteCounter;

    // Port-based detection
    std::unordered_set<int> suspiciousPorts = {
        23,    // Telnet
        6667,  // IRC (often used by botnets)
        31337, // Back Orifice
        4444,  // Metasploit default
        5554,  // Sasser worm
        9996,  // Common botnet port
        1080,  // SOCKS proxy (often misconfigured)
        3389,  // RDP
        445,   // SMB
        135,   // RPC
        139    // NetBIOS
    };

    // Content-based detection-checks payload
    std::vector<std::string> maliciousKeywords = {
        "malware", "exploit", "virus", "trojan", "botnet", "backdoor",
        "shell", "phish", "ransomware", "password", "credentials",
        "admin", "root", "cmd.exe", "powershell", "base64", "/bin/sh",
        "exec(", "eval(", "system(", "SELECT", "UNION", "DROP TABLE",
        "<script>", "alert(", "document.cookie", "wget ", "curl ",
        "nc ", "netcat", ".exe", ".dll", ".sh", "chmod +x"
    };

    // Regular expressions for pattern matching
    std::vector<std::regex> patterns = {
        std::regex("(?:eval|exec|system)\\s*\\(.*\\)"),                    // Command execution
        std::regex("(?:select|union|insert|update|delete)\\s+.*\\s+from"), // SQL operations
        std::regex("(?:\\/\\.\\.\\/|\\.\\.\\/\\.\\.\\/|\\.\\.\\\\)"),      // Directory traversal
        std::regex("<\\s*script.*>.*<\\s*\\/\\s*script\\s*>"),             // Script injection
        std::regex("(?:wget|curl)\\s+(?:http|ftp)"),                       // Download attempts
        std::regex("(?:bash|sh|ksh)\\s+-[ci]"),                           // Shell command execution
        std::regex("(?:nc|netcat)\\s+-[e]"),                              // Netcat backdoor
        std::regex("\\b(?:pass(?:word)?|admin|root)\\s*="),               // Credential exposure
        std::regex("\\b(?:0x|\\\\x)[0-9a-fA-F]+"),                        // Shellcode patterns
        std::regex("\\b(?:chmod|chown)\\s+[0-7]{3,4}")                    // Permission changes
    };

    // Port scan detection
    std::map<std::string, std::unordered_set<int>> ipPortsScanned;
    std::map<std::string, std::time_t> lastPortScan;

    // Session tracking for stateful analysis
    struct Session {
        std::time_t startTime;
        int packetCount;
        int byteCount;
        std::unordered_set<int> uniquePorts;
        int suspiciousPatternCount;
    };
    std::map<std::string, Session> sessions;

    // Helper function to create session key
    std::string createSessionKey(const Packet& packet) {
        return packet.src_ip + ":" + packet.dst_ip + ":" + std::to_string(packet.port);
    }

public:
    std::pair<bool, std::string> analyze(const Packet& packet) {
        std::time_t currentTime = std::time(nullptr);

        // Update IP tracking
        if (ipCounter.find(packet.src_ip) == ipCounter.end()) {
            ipFirstSeen[packet.src_ip] = currentTime;
            ipByteCounter[packet.src_ip] = 0;
        }
        ipCounter[packet.src_ip]++;
        ipByteCounter[packet.src_ip] += packet.payload.size();

        // Update port scan detection
        ipPortsScanned[packet.src_ip].insert(packet.port);
        
        // Update session tracking
        std::string sessionKey = createSessionKey(packet);
        if (sessions.find(sessionKey) == sessions.end()) {
            sessions[sessionKey] = { currentTime, 1, static_cast<int>(packet.payload.size()), 
                                   {packet.port}, 0 };
        } else {
            Session& session = sessions[sessionKey];
            session.packetCount++;
            session.byteCount += static_cast<int>(packet.payload.size());
            session.uniquePorts.insert(packet.port);
        }

        // 1. Rate limiting detection (adjusted thresholds)
        if (ipCounter[packet.src_ip] > 50 && 
            (currentTime - ipFirstSeen[packet.src_ip]) < 30) { // 50+ packets in 30 seconds
            return { true, "Possible DoS attack - high packet rate from " + packet.src_ip };
        }

        // 2. Port scan detection (with time window)
        if (ipPortsScanned[packet.src_ip].size() > 10) {
            auto lastScan = lastPortScan.find(packet.src_ip);
            if (lastScan == lastPortScan.end() || 
                (currentTime - lastScan->second) > 300) { // Reset after 5 minutes
                lastPortScan[packet.src_ip] = currentTime;
                return { true, "Possible port scan detected from " + packet.src_ip };
            }
        }

        // 3. Suspicious port check
        if (suspiciousPorts.count(packet.port)) {
            return { true, "Connection attempt to suspicious port " + std::to_string(packet.port) };
        }

        // 4. Session analysis
        Session& session = sessions[sessionKey];
        if (session.packetCount > 100 && (currentTime - session.startTime) < 60) {
            return { true, "High-volume session detected from " + packet.src_ip };
        }

        // 5. Payload size anomaly
        if (ipByteCounter[packet.src_ip] > 1000000 && // 1MB
            (currentTime - ipFirstSeen[packet.src_ip]) < 60) {
            return { true, "Abnormal data volume from " + packet.src_ip };
        }

        // 6. Payload signature scan
        for (const auto& keyword : maliciousKeywords) {
            if (packet.payload.find(keyword) != std::string::npos) {
                return { true, "Suspicious content detected: " + keyword };
            }
        }

        // 7. Pattern-based detection using regex
        for (size_t i = 0; i < patterns.size(); i++) {
            if (std::regex_search(packet.payload, patterns[i])) {
                std::string patternType;
                switch (i) {
                    case 0: patternType = "command execution"; break;
                    case 1: patternType = "SQL injection"; break;
                    case 2: patternType = "directory traversal"; break;
                    case 3: patternType = "script injection"; break;
                    case 4: patternType = "suspicious download"; break;
                    case 5: patternType = "shell command"; break;
                    case 6: patternType = "reverse shell attempt"; break;
                    case 7: patternType = "credential exposure"; break;
                    case 8: patternType = "possible shellcode"; break;
                    case 9: patternType = "suspicious file operation"; break;
                    default: patternType = "suspicious pattern"; break;
                }
                session.suspiciousPatternCount++;
                return { true, "Detected potential " + patternType + " attempt" };
            }
        }

        // Clean up old entries periodically
        if (ipCounter[packet.src_ip] % 100 == 0) {
            auto it = sessions.begin();
            while (it != sessions.end()) {
                if (currentTime - it->second.startTime > 300) { // 5 minutes old
                    it = sessions.erase(it);
                } else {
                    ++it;
                }
            }
        }

        return { false, "Traffic is normal" };
    }

    // Method to reset the analyzer state
    void reset() {
        ipCounter.clear();
        ipFirstSeen.clear();
        ipPortsScanned.clear();
        sessions.clear();
        ipByteCounter.clear();
        lastPortScan.clear();
    }
};

#endif // RULES_H