#ifndef OCS_NODE_H
#define OCS_NODE_H

#include "ns3/node.h"
#include "ns3/net-device.h"
#include "ns3/packet.h"
#include "ns3/nstime.h"
#include <unordered_map>

namespace ns3 {

class OCSNode : public Node {
public:
  static TypeId GetTypeId (void);
  OCSNode();

  // Set a single port mapping and check sanity (symmetric and valid)
  void SetPortMapping(uint32_t inputPort, uint32_t outputPort);

  // Reconfiguration process: drop packets during reconfiguration and then update port mapping.
  void Reconfigure(const std::unordered_map<uint32_t, uint32_t>& newMapping);
  void CompleteReconfiguration(const std::unordered_map<uint32_t, uint32_t>& newMapping);

  // Packet forwarding: if reconfiguration is active, drop packets.
  bool ReceiveFromDevice(Ptr<NetDevice> device, Ptr<Packet> packet);

protected:
  virtual void DoInitialize (void) override;

private:
  // Check that the port mapping is symmetric:
  // For each valid mapping, m_portMap[m_portMap[i]] must equal i and mapped ports must be within [0, m_radix-1] or unmapped (-1).
  bool CheckPortMapping() const;

  std::unordered_map<uint32_t, uint32_t> m_portMap; // key: input port, value: output port
  Time m_reconfigTime;  // Time required for reconfiguring paths
  uint32_t m_radix;     // Number of switch ports
  bool m_inReconfig;    // True if reconfiguration is in progress
};

} // namespace ns3

#endif // OCS_NODE_H
