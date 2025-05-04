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
        "nc ", "netcat", ".exe", ".dll", ".sh", "chmod +x"};

    // Regular expressions for pattern matching
    std::vector<std::regex> patterns = {
        std::regex("(?:eval|exec|system)\\s*\\(.*\\)"),                    // Command execution
        std::regex("(?:select|union|insert|update|delete)\\s+.*\\s+from"), // SQL operations
        std::regex("(?:\\/\\.\\.\\/|\\.\\.\\/\\.\\.\\/|\\.\\.\\\\)"),      // Directory traversal
        std::regex("<\\s*script.*>.*<\\s*\\/\\s*script\\s*>"),             // Script injection
        std::regex("(?:wget|curl)\\s+(?:http|ftp)"),                       // Download attempts
        std::regex("(?:bash|sh|ksh)\\s+-[ci]"),                            // Shell command execution
        std::regex("(?:nc|netcat)\\s+-[e]"),                               // Netcat backdoor
        std::regex("\\b(?:pass(?:word)?|admin|root)\\s*="),                // Credential exposure
        std::regex("\\b(?:0x|\\\\x)[0-9a-fA-F]+"),                         // Shellcode patterns
        std::regex("\\b(?:chmod|chown)\\s+[0-7]{3,4}")                     // Permission changes
    };

    // Port scan detection
    std::map<std::string, std::unordered_set<int>> ipPortsScanned;
    std::map<std::string, std::time_t> lastPortScan;

    // Session tracking for stateful analysis
    struct Session
    {
        std::time_t startTime;
        int packetCount;
        int byteCount;
        std::unordered_set<int> uniquePorts;
        int suspiciousPatternCount;
    };
    std::map<std::string, Session> sessions;

    // SYN flood detection
    struct SynTracker
    {
        std::time_t first_syn;
        int syn_count;
        std::unordered_set<std::string> source_ips;
    };
    std::map<std::string, SynTracker> syn_flood_trackers; // key: dst_ip:dst_port

    // ACK flood detection
    struct AckTracker
    {
        std::time_t first_ack;
        int ack_count;
        std::unordered_set<std::string> source_ips;
    };
    std::map<std::string, AckTracker> ack_flood_trackers;

    // TCP replay detection
    struct Segment
    {
        std::string data_hash;
        std::time_t time_seen;
        int count;
    };
    std::map<std::string, std::map<uint32_t, Segment>> tcp_segments;

    // IP spoofing detection
    struct IPProfile
    {
        std::unordered_set<int> typical_ports;
        std::unordered_set<std::string> typical_payloads;
        std::time_t first_seen;
        std::time_t last_seen;
    };
    std::map<std::string, IPProfile> ip_profiles;

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
            ipByteCounter[packet.src_ip] = 0;
        }
        ipCounter[packet.src_ip]++;
        ipByteCounter[packet.src_ip] += packet.payload.size();

        // Update port scan detection
        ipPortsScanned[packet.src_ip].insert(packet.port);

        // Update session tracking
        std::string sessionKey = createSessionKey(packet);
        if (sessions.find(sessionKey) == sessions.end())
        {
            sessions[sessionKey] = {currentTime, 1, static_cast<int>(packet.payload.size()), {packet.port}, 0};
        }
        else
        {
            Session &session = sessions[sessionKey];
            session.packetCount++;
            session.byteCount += static_cast<int>(packet.payload.size());
            session.uniquePorts.insert(packet.port);
        }

        // 1. Rate limiting detection (adjusted thresholds)
        if (ipCounter[packet.src_ip] > 50 &&
            (currentTime - ipFirstSeen[packet.src_ip]) < 30)
        { // 50+ packets in 30 seconds
            return {true, "Possible DoS attack - high packet rate from " + packet.src_ip};
        }

        // 2. Port scan detection (with time window)
        if (ipPortsScanned[packet.src_ip].size() > 10)
        {
            auto lastScan = lastPortScan.find(packet.src_ip);
            if (lastScan == lastPortScan.end() ||
                (currentTime - lastScan->second) > 300)
            { // Reset after 5 minutes
                lastPortScan[packet.src_ip] = currentTime;
                return {true, "Possible port scan detected from " + packet.src_ip};
            }
        }

        // 3. Suspicious port check
        if (suspiciousPorts.count(packet.port))
        {
            return {true, "Connection attempt to suspicious port " + std::to_string(packet.port)};
        }

        // 4. Session analysis
        Session &session = sessions[sessionKey];
        if (session.packetCount > 100 && (currentTime - session.startTime) < 60)
        {
            return {true, "High-volume session detected from " + packet.src_ip};
        }

        // 5. Payload size anomaly
        if (ipByteCounter[packet.src_ip] > 1000000 && // 1MB
            (currentTime - ipFirstSeen[packet.src_ip]) < 60)
        {
            return {true, "Abnormal data volume from " + packet.src_ip};
        }

        // 6. Payload signature scan
        for (const auto &keyword : maliciousKeywords)
        {
            if (packet.payload.find(keyword) != std::string::npos)
            {
                return {true, "Suspicious content detected: " + keyword};
            }
        }

        // 7. Pattern-based detection using regex
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
                    patternType = "SQL injection";
                    break;
                case 2:
                    patternType = "directory traversal";
                    break;
                case 3:
                    patternType = "script injection";
                    break;
                case 4:
                    patternType = "suspicious download";
                    break;
                case 5:
                    patternType = "shell command";
                    break;
                case 6:
                    patternType = "reverse shell attempt";
                    break;
                case 7:
                    patternType = "credential exposure";
                    break;
                case 8:
                    patternType = "possible shellcode";
                    break;
                case 9:
                    patternType = "suspicious file operation";
                    break;
                default:
                    patternType = "suspicious pattern";
                    break;
                }
                session.suspiciousPatternCount++;
                return {true, "Detected potential " + patternType + " attempt"};
            }
        }

        // SYN flood detection (New)
        if ((packet.tcp_flags & 0x02) && !(packet.tcp_flags & 0x10))
        { // SYN=1, ACK=0
            std::string target = packet.dst_ip + ":" + std::to_string(packet.port);

            if (syn_flood_trackers.find(target) == syn_flood_trackers.end())
            {
                syn_flood_trackers[target] = {currentTime, 1, {packet.src_ip}};
            }
            else
            {
                SynTracker &tracker = syn_flood_trackers[target];
                tracker.syn_count++;
                tracker.source_ips.insert(packet.src_ip);

                // If more than 50 SYN packets to same target within 5 seconds from 10+ sources
                if (tracker.syn_count > 50 &&
                    (currentTime - tracker.first_syn <= 5) &&
                    tracker.source_ips.size() >= 10)
                {

                    // Reset tracker to avoid repeated alerts
                    tracker = {currentTime, 0, {}};

                    return {true, "SYN flood attack detected targeting " + target};
                }

                // Reset counter after 10 seconds to avoid false positives during normal traffic spikes
                if (currentTime - tracker.first_syn > 10)
                {
                    tracker = {currentTime, 1, {packet.src_ip}};
                }
            }
        }

        // ACK flood detection
        if ((packet.tcp_flags & 0x10) && !(packet.tcp_flags & 0x02))
        { // ACK=1, SYN=0
            std::string target = packet.dst_ip + ":" + std::to_string(packet.port);

            if (ack_flood_trackers.find(target) == ack_flood_trackers.end())
            {
                ack_flood_trackers[target] = {currentTime, 1, {packet.src_ip}};
            }
            else
            {
                AckTracker &tracker = ack_flood_trackers[target];
                tracker.ack_count++;
                tracker.source_ips.insert(packet.src_ip);

                // If more than 100 ACK packets to same target within 3 seconds from multiple sources
                if (tracker.ack_count > 100 &&
                    (currentTime - tracker.first_ack <= 3) &&
                    tracker.source_ips.size() >= 5)
                {

                    // Reset tracker to avoid repeated alerts
                    tracker = {currentTime, 0, {}};
                    return {true, "ACK flood attack detected targeting " + target};
                }

                // Reset counter after 5 seconds
                if (currentTime - tracker.first_ack > 5)
                {
                    tracker = {currentTime, 1, {packet.src_ip}};
                }
            }
        }

        // TCP replay detection
        std::string connection = packet.src_ip + ":" + std::to_string(packet.src_port) + "->" +
                                 packet.dst_ip + ":" + std::to_string(packet.port);

        // Calculate a simple hash of payload
        std::string data_hash = std::to_string(std::hash<std::string>{}(packet.payload));
        uint32_t seq_num = packet.tcp_seq;

        if (tcp_segments[connection].find(seq_num) == tcp_segments[connection].end())
        {
            // First time seeing this segment
            tcp_segments[connection][seq_num] = {data_hash, currentTime, 1};
        }
        else
        {
            Segment &seg = tcp_segments[connection][seq_num];

            // If we see the same segment with same hash
            if (seg.data_hash == data_hash)
            {
                seg.count++;

                // If we see same segment 3+ times within 2 seconds
                if (seg.count >= 3 && (currentTime - seg.time_seen <= 2))
                {
                    return {true, "TCP replay attack detected on connection " + connection};
                }
            }
            else
            {
                // Different payload for same sequence - could be legitimate retransmission
                seg.data_hash = data_hash;
                seg.time_seen = currentTime;
            }
        }

        // IP spoofing detection
        // Learning phase - build IP profiles
        if (ip_profiles.find(packet.src_ip) == ip_profiles.end())
        {
            // New IP
            IPProfile profile;
            profile.typical_ports.insert(packet.port);
            profile.typical_payloads.insert(packet.payload.substr(0, 20)); // just use prefix
            profile.first_seen = currentTime;
            profile.last_seen = currentTime;
            ip_profiles[packet.src_ip] = profile;
        }
        else
        {
            // Update existing profile
            IPProfile &profile = ip_profiles[packet.src_ip];
            profile.typical_ports.insert(packet.port);
            profile.typical_payloads.insert(packet.payload.substr(0, 20));
            profile.last_seen = currentTime;

            // Detection phase - after we've seen an IP for at least 10 seconds
            if (currentTime - profile.first_seen > 10)
            {
                // Check for sudden behavior changes that suggest spoofing
                bool suspicious = false;

                // If this IP suddenly uses many ports in short time
                if (profile.typical_ports.size() < 5 &&
                    ipPortsScanned[packet.src_ip].size() > 20 &&
                    (currentTime - lastPortScan[packet.src_ip] < 5))
                {
                    suspicious = true;
                }

                // If the IP is sending traffic patterns very different from its history
                if (profile.typical_payloads.size() >= 3)
                {
                    // Check if current payload matches any known pattern
                    bool matches_profile = false;
                    std::string payload_prefix = packet.payload.substr(0, 20);

                    for (const auto &known_payload : profile.typical_payloads)
                    {
                        if (payload_prefix.find(known_payload) != std::string::npos ||
                            known_payload.find(payload_prefix) != std::string::npos)
                        {
                            matches_profile = true;
                            break;
                        }
                    }

                    if (!matches_profile && packet.payload.size() > 10)
                    {
                        suspicious = true;
                    }
                }

                if (suspicious)
                {
                    return {true, "Potential IP spoofing detected from " + packet.src_ip};
                }
            }
        }

        // Clean up old entries periodically
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
        ipByteCounter.clear();
        lastPortScan.clear();
        syn_flood_trackers.clear();
        ack_flood_trackers.clear();
        tcp_segments.clear();
        ip_profiles.clear();
    }
};

#endif // RULES_H