#include "optical-routing-helper.h"
#include "ns3/abort.h"
#include "ns3/config.h"
#include "ns3/log.h"
#include "ns3/names.h"
#include <cmath>

namespace ns3 {

NS_LOG_COMPONENT_DEFINE("OpticalRoutingHelper");

void OpticalRoutingHelper::setSwing(int n) {
  swing = true;
  numPhaseSteps = n;
}

uint64_t OpticalRoutingHelper::get_first_nic_rate() {
    for (uint32_t i = 0; i < n->GetN(); i++)
      if (n->Get(i)->GetNodeType() == 0)
          return DynamicCast<QbbNetDevice>(n->Get(i)->GetDevice(1))->GetDataRate().GetBitRate();
}

void OpticalRoutingHelper::update_nic_rates(double multiplier) {
    for (uint32_t i = 0; i < n->GetN(); i++) {
        for (uint32_t j = 1; j < n->Get(i)->GetNDevices(); j++) { // the first one is the icmp interface skip over
            DataRate currentBw = DynamicCast<QbbNetDevice>(n->Get(i)->GetDevice(j))->GetDataRate();
            currentBw *= multiplier;
            DynamicCast<QbbNetDevice>(n->Get(i)->GetDevice(j))->SetDataRate(currentBw);
        }
    }
}

void OpticalRoutingHelper::update_next_hop_node_ids() {
  stepId++;
  if (!swing) return;
  uint64_t currentBW = get_first_nic_rate();
  if (step_bw_multiplier[stepId] == 1) { 
    if (initialBW == currentBW) {
        //do nothing
    } else {
        if (initialBW * 2 == currentBW) {
            // everything was doubled revert back to original values
            // todo
            update_nic_rates(0.5);
        } else {
            std::cout << "Unknown option-> Please check something is wrong" << std::endl;
            exit(1);
        }
    }
  } else if (step_bw_multiplier[stepId] == 2) {
    if (initialBW == currentBW) {
        // double everything
        // todo
        update_nic_rates(2);
    } else {
        if (initialBW * 2 == currentBW) {
            // it has already been doubled from last step
            // do nothing
        } else {
            std::cout << "Unknown option-> Please check something is wrong" << std::endl;
            exit(1);
        }
    }
  }
}

int OpticalRoutingHelper::GetDirection(uint32_t id){
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



bool OpticalRoutingHelper::read_optical_routing_config(const std::string optical_routing_configuration, bool isSwing, NodeContainer& nContainer) {
  n = &nContainer;
  std::ifstream inFile(optical_routing_configuration);
  if (!inFile) {
    std::cout << "Unable to open optical routing file: " << optical_routing_configuration << std::endl;
    std::flush(std::cout);
    return false;
  }
  
  json j;
  try {
    inFile >> j;
  } catch (const json::parse_error& e) {
    std::cout << "Parse error: " << e.what() << std::endl;
    inFile.close();
    return false;
  }

  SimulationData data = j.get<SimulationData>();
  
  //! Warning: might give incorrect resuif the original file uses different bws for each link
  if (isSwing) {
      initialBW = get_first_nic_rate();
  }
  for (const auto& s : data.steps) {
    if (isSwing) {
      if (s.topology.empty() || s.topology[0].size() < 3) {
        std::cout << "Invalid topology format in configuration file" << std::endl;
        inFile.close();
        return false;
      }

      int links = s.topology[0][2];
      
      if (links == 1) {
        // Base static ring configuration
        int nodes = 0;
        
        if (!j.contains("collective")) {
          std::cout << "Missing 'collective' field in configuration" << std::endl;
          inFile.close();
          return false;
        }
        
        std::string collective = j["collective"];
        
        if (collective == "all-reduce-swing-nd") {
          nodes = static_cast<int>(std::pow(2, data.steps.size() / 2));
        } else if (collective == "all-gather-swing-nd" || collective == "reduce-scatter-swing-nd") {
          nodes = static_cast<int>(std::pow(2, data.steps.size()));
        } else {
          std::cout << "Invalid collective for Swing algorithm: " << collective 
                    << ". Options are: all-reduce-swing-nd, all-gather-swing-nd, "
                    << "and reduce-scatter-swing-nd" << std::endl;
          inFile.close();
          return false;
        }
        
        for (int i = 0; i < nodes; i++) {
          next_hop_node_ids[i].push_back((i + 1) % nodes);
          next_hop_node_ids_antiClock[i].push_back((i - 1 + nodes) % nodes);
        }
        step_bw_multiplier.push_back(1);
      } else if (links == 2) {
        // Direct connect configuration
        for (const auto& topo : s.topology) {
          int srcNode = topo[0];
          int dstNode = topo[1];
          next_hop_node_ids[srcNode].push_back(dstNode);
          next_hop_node_ids_antiClock[dstNode].push_back(srcNode);
        }
        step_bw_multiplier.push_back(2);
      } else {
        std::cout << "Swing in astra sim supports max 2 ports (found " << links << " ports)" << std::endl;
        inFile.close();
        return false;
      }
    } else {
      // Non-swing collective
      for (const auto& topo : s.topology) {      
        int srcNode = topo[0];
        int dstNode = topo[1];
        next_hop_node_ids[srcNode].push_back(dstNode);
        next_hop_node_ids_antiClock[dstNode].push_back(srcNode);
      }
    }
  }
  
  inFile.close();
  return true;
}

} // namespace ns3