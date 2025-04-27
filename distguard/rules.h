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
#include <deque>
#include <algorithm>

// TCP Flags
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20
#define TCP_ECE 0x40
#define TCP_CWR 0x80

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

    // Content-based detection
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

    // SYN Flood detection
    struct SynFloodData
    {
        std::time_t firstSeen;
        int synCount;
        int ackCount;
        int halfOpenCount; // Connections in SYN_RECEIVED state
    };
    std::map<std::string, SynFloodData> synFloodTracker;

    // TCP Replay detection
    struct SequenceData
    {
        std::deque<uint32_t> recentSequences;
        std::time_t lastSeen;
    };
    std::map<std::string, SequenceData> sequenceTracker;

    // IP Spoofing detection
    std::map<std::string, std::unordered_set<std::string>> sourceTargetMap;
    std::map<std::string, int> unusualSourceCount;

    // ACK Flood detection
    struct AckFloodData
    {
        std::time_t firstSeen;
        int ackCount;
        int establishedConnections;
    };
    std::map<std::string, AckFloodData> ackFloodTracker;

    // Session tracking for stateful analysis
    struct Session
    {
        std::time_t startTime;
        int packetCount;
        int byteCount;
        uint8_t flags;    // Cumulative TCP flags seen in this session
        bool established; // Whether a full TCP handshake has been observed
        std::unordered_set<int> uniquePorts;
        int suspiciousPatternCount;
    };
    std::map<std::string, Session> sessions;

    // Helper function to create session key
    std::string createSessionKey(const Packet &packet)
    {
        return packet.src_ip + ":" + packet.dst_ip + ":" + std::to_string(packet.port);
    }

    // Helper function to create connection key (bidirectional)
    std::string createConnectionKey(const std::string &ip1, const std::string &ip2)
    {
        return ip1 < ip2 ? ip1 + ":" + ip2 : ip2 + ":" + ip1;
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
            sessions[sessionKey] = {currentTime, 1, static_cast<int>(packet.payload.size()), 0, false, {packet.port}, 0};
        }
        else
        {
            Session &session = sessions[sessionKey];
            session.packetCount++;
            session.byteCount += static_cast<int>(packet.payload.size());
            session.uniquePorts.insert(packet.port);
        }

        // Extract TCP flags if available in the packet
        uint8_t tcpFlags = 0;
        if (packet.flags > 0)
        {
            tcpFlags = packet.flags;
            sessions[sessionKey].flags |= tcpFlags;

            // Check for established connection (SYN and ACK seen)
            if ((sessions[sessionKey].flags & TCP_SYN) && (sessions[sessionKey].flags & TCP_ACK))
            {
                sessions[sessionKey].established = true;
            }
        }

        // 1. SYN Flood Detection
        if (tcpFlags & TCP_SYN)
        {
            std::string srcIp = packet.src_ip;
            if (synFloodTracker.find(srcIp) == synFloodTracker.end())
            {
                synFloodTracker[srcIp] = {currentTime, 1, 0, 1};
            }
            else
            {
                synFloodTracker[srcIp].synCount++;
                synFloodTracker[srcIp].halfOpenCount++;
            }

            // Check for SYN flood pattern
            SynFloodData &data = synFloodTracker[srcIp];
            if (data.synCount > 30 && (currentTime - data.firstSeen) < 60 &&
                data.synCount > 3 * data.ackCount)
            {
                return {true, "Possible SYN flood attack from " + srcIp};
            }
        }

        // When we see an ACK, decrement half-open count and update ACK count
        if (tcpFlags & TCP_ACK)
        {
            std::string srcIp = packet.src_ip;
            if (synFloodTracker.find(srcIp) != synFloodTracker.end())
            {
                SynFloodData &data = synFloodTracker[srcIp];
                data.ackCount++;
                if (data.halfOpenCount > 0)
                {
                    data.halfOpenCount--;
                }
            }

            // 4. ACK Flood Detection
            if (synFloodTracker.find(srcIp) == synFloodTracker.end())
            {
                ackFloodTracker[srcIp] = {currentTime, 1, 0};
            }
            else
            {
                ackFloodTracker[srcIp].ackCount++;
                if (sessions[sessionKey].established)
                {
                    ackFloodTracker[srcIp].establishedConnections++;
                }
            }

            // Check for ACK flood pattern
            AckFloodData &ackData = ackFloodTracker[srcIp];
            if (ackData.ackCount > 50 && (currentTime - ackData.firstSeen) < 60 &&
                ackData.ackCount > 5 * ackData.establishedConnections)
            {
                return {true, "Possible ACK flood attack from " + srcIp};
            }
        }

        // 2. TCP Replay Attack Detection
        if (packet.seq > 0)
        { // Check if sequence number is available
            std::string connKey = createConnectionKey(packet.src_ip, packet.dst_ip);

            if (sequenceTracker.find(connKey) == sequenceTracker.end())
            {
                SequenceData newData;
                newData.recentSequences.push_back(packet.seq);
                newData.lastSeen = currentTime;
                sequenceTracker[connKey] = newData;
            }
            else
            {
                SequenceData &seqData = sequenceTracker[connKey];

                // Check for sequence number reuse within a short time window
                if (std::find(seqData.recentSequences.begin(), seqData.recentSequences.end(), packet.seq) != seqData.recentSequences.end())
                {
                    return {true, "Possible TCP replay attack detected - duplicate sequence number"};
                }

                // Store the sequence number for future reference
                seqData.recentSequences.push_back(packet.seq);
                seqData.lastSeen = currentTime;

                // Keep only the last 100 sequence numbers to prevent memory bloat
                if (seqData.recentSequences.size() > 100)
                {
                    seqData.recentSequences.pop_front();
                }
            }
        }

        // 3. IP Spoofing Detection
        std::string targetIp = packet.dst_ip;

        // Track IPs communicating with specific targets
        sourceTargetMap[targetIp].insert(packet.src_ip);

        // Check for unusual number of source IPs for a target (potential spoofing)
        if (sourceTargetMap[targetIp].size() > 30 &&
            (currentTime - ipFirstSeen[packet.src_ip]) < 60)
        {
            // Increment unusual source counter
            unusualSourceCount[targetIp]++;

            // If we see a consistent pattern of many sources to one target in a short time
            if (unusualSourceCount[targetIp] > 10)
            {
                return {true, "Possible IP spoofing attack - many sources targeting " + targetIp};
            }
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

        // Clean up old entries periodically (every ~100 packets per source IP)
        if (ipCounter[packet.src_ip] % 100 == 0)
        {
            // Clean up sessions
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

            // Clean up sequence trackers
            auto seqIt = sequenceTracker.begin();
            while (seqIt != sequenceTracker.end())
            {
                if (currentTime - seqIt->second.lastSeen > 300)
                { // 5 minutes old
                    seqIt = sequenceTracker.erase(seqIt);
                }
                else
                {
                    ++seqIt;
                }
            }

            // Clean up SYN flood and ACK flood trackers
            auto synIt = synFloodTracker.begin();
            while (synIt != synFloodTracker.end())
            {
                if (currentTime - synIt->second.firstSeen > 300)
                { // 5 minutes old
                    synIt = synFloodTracker.erase(synIt);
                }
                else
                {
                    ++synIt;
                }
            }

            auto ackIt = ackFloodTracker.begin();
            while (ackIt != ackFloodTracker.end())
            {
                if (currentTime - ackIt->second.firstSeen > 300)
                { // 5 minutes old
                    ackIt = ackFloodTracker.erase(ackIt);
                }
                else
                {
                    ++ackIt;
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
        synFloodTracker.clear();
        sequenceTracker.clear();
        sourceTargetMap.clear();
        unusualSourceCount.clear();
        ackFloodTracker.clear();
    }
};

#endif // RULES_H