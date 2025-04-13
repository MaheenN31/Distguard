// main_node/main_node.cpp
#include <iostream>
#include <boost/asio.hpp>
#include <thread>
#include <vector>
#include <mutex>
#include "shared.h"
#include "traffic_simulator.h"

using boost::asio::ip::tcp;
using namespace std;

mutex cout_mutex;

void handle_client(tcp::socket socket, const std::vector<Packet>& traffic_chunk, int client_id)//Each handle_client runs in a separate thread
{
    try {
        boost::asio::streambuf buf;
        ostream os(&buf);

        {
            lock_guard<mutex> lock(cout_mutex);
            cout << "[MainNode] Sending " << traffic_chunk.size() << " packets to Client " << client_id << "..." << endl;
        }

        for (const auto& pkt : traffic_chunk) {
            std::string data = pkt.serialize() + "\n";
            os << data;
        }
        os << "END\n";
        boost::asio::write(socket, buf);

        {
            lock_guard<mutex> lock(cout_mutex);
            cout << "[MainNode] Packets sent to Client " << client_id << ". Awaiting response..." << endl;
        }

        boost::asio::streambuf response_buf;
        boost::asio::read_until(socket, response_buf, "\n");
        istream is(&response_buf);
        string response;
        getline(is, response);

        {
            lock_guard<mutex> lock(cout_mutex);
            cout << "[Client " << client_id << " Response] " << response << endl;
        }

    }
    catch (exception& e) {
        lock_guard<mutex> lock(cout_mutex);
        cerr << "[MainNode] Client handler exception: " << e.what() << endl;
    }
}

int main() {
    const int port = 5555;
    const int num_clients = 3;
    const int packets_per_client = 10;

    try {
        boost::asio::io_context io_context;
        tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), port));

        cout << "[MainNode] Waiting for clients on port " << port << "..." << endl;

        vector<tcp::socket> client_sockets;
        for (int i = 0; i < num_clients; ++i) {
            tcp::socket socket(io_context);
            acceptor.accept(socket);
            cout << "[MainNode] Client " << (i + 1) << " connected." << endl;
            client_sockets.push_back(std::move(socket));
        }

        // Generate traffic
        auto traffic = TrafficSimulator::generateTraffic(num_clients * packets_per_client);

        // Distribute to clients
        vector<thread> client_threads;
        for (int i = 0; i < num_clients; ++i) {
            vector<Packet> chunk(traffic.begin() + i * packets_per_client,
                traffic.begin() + (i + 1) * packets_per_client);
            client_threads.emplace_back(handle_client, std::move(client_sockets[i]), chunk, i + 1);
        }

        for (auto& t : client_threads) {
            t.join();
        }

        cout << "[MainNode] All client responses received." << endl;

    }
    catch (exception& e) {
        cerr << "[MainNode] Exception: " << e.what() << endl;
    }

    return 0;
}
