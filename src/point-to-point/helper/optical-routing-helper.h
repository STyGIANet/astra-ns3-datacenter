#ifndef OPTICAL_ROUTING_HELPER_H
#define OPTICAL_ROUTING_HELPER_H

#include <unordered_map>
#include <vector>
#include <fstream>
#include <iostream>
#include <string>

using namespace std;

namespace ns3 {

class OpticalRoutingHelper 
{
  public:
    inline static std::unordered_map<int,std::vector<int>> next_hop_node_ids;
    inline static int stepId = -1;

    static void update_next_hop_node_ids() {
      stepId++;
    }

    static bool read_optical_routing_config(string optical_routing_configuration) {
      ifstream inFile;
      inFile.open(optical_routing_configuration);
      if (!inFile) {
          cerr << "Unable to open file: " << optical_routing_configuration << endl;
          fflush(stdout);
          return false;
      }

      // Find the size of each dimension.
      string step, srcNode, dstNode;
      while (inFile >> step >> srcNode >> dstNode) {
          next_hop_node_ids[stoi(srcNode)].push_back(stoi(dstNode));
      }
      inFile.close();
      return true;
  }
};

} // namespace ns3

#endif /* OPTICAL_ROUTING_HELPER_H */