#ifndef OPTICAL_ROUTING_HELPER_H
#define OPTICAL_ROUTING_HELPER_H

#include <unordered_map>
#include <vector>
#include <fstream>
#include "json.hpp"
#include <iostream>
#include <string>

using namespace std;
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
    inline static std::unordered_map<int,std::vector<int>> next_hop_node_ids;
    inline static std::unordered_map<int,std::vector<int>> next_hop_node_ids_antiClock;
    inline static int stepId = -1;

    inline static bool swing = 0;
    inline static int numPhaseSteps = 0;

    static void setSwing(int n){
      swing = 1;
      numPhaseSteps = n; // log n
    }

    static void update_next_hop_node_ids() {
      stepId++;
    }

    static int GetDirection(uint32_t id){
      if (swing){
        if (id%2){
          if (stepId < numPhaseSteps){
            if(stepId%2)
              return 1;
            else
              return 0;
          }
          else{
            if(stepId%2)
              return 0;
            else
              return 1;
          }
        }
        else{
          if (stepId < numPhaseSteps){
            if(stepId%2)
              return 0;
            else
              return 1;
          }
          else{
            if(stepId%2)
              return 1;
            else
              return 0;
          }
        }
      }
      else{
        return 1;
      }
    }

    static bool read_optical_routing_config(string optical_routing_configuration) {
      ifstream inFile;
      inFile.open(optical_routing_configuration);
      if (!inFile) {
          std::cout << "Unable to open file: " << optical_routing_configuration << std::endl;
          fflush(stdout);
          return false;
      }
      json j;
      try {
          inFile >> j;
      } catch (json::parse_error& e) {
          std::cout << "Parse error: " << e.what() << std::endl;
          return 1;
      }
      SimulationData data = j.get<SimulationData>();
      int step, srcNode, dstNode;
      for (const auto& s : data.steps) {
        for (const auto& topo : s.topology) {
          srcNode = topo[0];
          dstNode = topo[1];
          next_hop_node_ids[srcNode].push_back(dstNode);
          next_hop_node_ids_antiClock[dstNode].push_back(srcNode);
        }
      }
      // string skip;
      // std::getline(inFile, skip);
      // std::getline(inFile, skip);
      // // Find the size of each dimension.
      // string step, srcNode, dstNode;
      // while (inFile >> step >> srcNode >> dstNode) {
      //     next_hop_node_ids[stoi(srcNode)].push_back(stoi(dstNode));
      //     next_hop_node_ids_antiClock[stoi(dstNode)].push_back(stoi(srcNode));
      // }
      inFile.close();
      return true;
  }
};

} // namespace ns3

#endif /* OPTICAL_ROUTING_HELPER_H */