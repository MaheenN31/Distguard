#ifndef TRAFFIC_SIMULATOR_H
#define TRAFFIC_SIMULATOR_H

#include "shared.h"
#include <vector>

class TrafficSimulator {
public:
    static std::vector<Packet> generateTraffic(int count);
};

#endif // TRAFFIC_SIMULATOR_H