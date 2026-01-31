#ifndef OPTICAL_ROUTING_HELPER_H
#define OPTICAL_ROUTING_HELPER_H

#include <unordered_map>
#include <vector>
#include <fstream>
#include <iostream>
#include <string>
#include "json.hpp"

#include "ns3/node-container.h"
#include "ns3/qbb-net-device.h"

using json = nlohmann::json;

struct Step {
    int step;
    // Topology is a list of lists of integers: [[0,1,1], [1,2,1]...]
    std::vector<std::vector<int>> topology; 
};

struct SimulationData {
    std::vector<Step> steps;
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(Step, step, topology)
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(SimulationData, steps)

namespace ns3 {

class OpticalRoutingHelper 
{
  public:
    inline static std::unordered_map<int, std::vector<int>> next_hop_node_ids;
    inline static std::unordered_map<int, std::vector<int>> next_hop_node_ids_antiClock;
    inline static std::vector<int> step_bw_multiplier;
    inline static int stepId = -1;
    inline static bool swing = false;
    inline static int numPhaseSteps = 0;
    inline static uint64_t initialBW = 0;
    inline static NodeContainer* n = nullptr;

    static void setSwing(int n);
    static void update_next_hop_node_ids();
    static int GetDirection(uint32_t id);
    static bool read_optical_routing_config(const std::string optical_routing_configuration, bool isSwing, NodeContainer& n);
    static void update_nic_rates(double multiplier);
    static uint64_t get_first_nic_rate();
  };

} // namespace ns3

#endif /* OPTICAL_ROUTING_HELPER_H */