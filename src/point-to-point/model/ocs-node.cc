#include "ocs-node.h"
#include "ns3/log.h"
#include "ns3/simulator.h"
#include "ns3/nstime.h"
#include "ns3/uinteger.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE("OCSNode");

TypeId OCSNode::GetTypeId (void)
{
  static TypeId tid = TypeId("ns3::OCSNode")
    .SetParent<Node>()
    .AddConstructor<OCSNode>()
    .AddAttribute("ReconfigTime",
                  "Time required for reconfiguring paths in nanoseconds.",
                  TimeValue(NanoSeconds(1000000)), // default: 1ms
                  MakeTimeAccessor(&OCSNode::m_reconfigTime),
                  MakeTimeChecker())
    .AddAttribute("Radix",
                  "Number of switch ports.",
                  UintegerValue(8), // default value: 8
                  MakeUintegerAccessor(&OCSNode::m_radix),
                  MakeUintegerChecker<uint32_t>());
  return tid;
}

OCSNode::OCSNode()
  : m_inReconfig(false)
{}

void OCSNode::DoInitialize()
{
  Node::DoInitialize();

  m_portMap.clear();
  for (uint32_t i = 0; i < m_radix; i++) {
    m_portMap[i] = static_cast<uint32_t>(-1); // -1 indicates unmapped.
  }
  NS_LOG_INFO("OCSNode initialized with radix = " << m_radix);
}

void OCSNode::SetPortMapping(uint32_t inputPort, uint32_t outputPort)
{
  m_portMap[inputPort] = outputPort;
  NS_LOG_INFO("Configured port mapping: " << inputPort << " -> " << outputPort);
  if (!CheckPortMapping()) {
    NS_LOG_ERROR("OCSNode: Port mapping sanity check failed");
    // TODO Handle error
  }
}

bool OCSNode::CheckPortMapping() const
{
  for (uint32_t i = 0; i < m_radix; i++) {
    auto it = m_portMap.find(i);
    if (it == m_portMap.end())
      continue;
    uint32_t mappedPort = it->second;
    // Check that mappedPort is either -1 (or rather UINTMAX, unmapped) or within a valid range.
    if (mappedPort != static_cast<uint32_t>(-1) && mappedPort >= m_radix) {
      NS_LOG_ERROR("Invalid mapping: port " << i << " maps to invalid port " << mappedPort);
      return false;
    }
    // Check symmetric mapping: if port i maps to port j, then port j must map back to i.
    if (mappedPort != static_cast<uint32_t>(-1)) {
      auto it2 = m_portMap.find(mappedPort);
      if (it2 == m_portMap.end() || it2->second != i) {
        NS_LOG_ERROR("Mapping not symmetric: port " << i << " maps to " << mappedPort
                      << " but reverse mapping is not " << i);
        return false;
      }
    }
  }
  NS_LOG_INFO("Port mapping passed sanity check");
  return true;
}

bool OCSNode::ReceiveFromDevice(Ptr<NetDevice> device, Ptr<Packet> packet)
{
  if (m_inReconfig) {
    NS_LOG_WARN("OCSNode is reconfiguring; dropping packet");
    return false;
  }

  uint32_t inPort = device->GetIfIndex();
  auto it = m_portMap.find(inPort);
  if (it != m_portMap.end()) {
    uint32_t outPort = it->second;
    Ptr<NetDevice> outDevice = GetDevice(outPort);
    if (outDevice) {
      NS_LOG_INFO("OCSNode forwarding packet from port " << inPort << " to " << outPort);
      outDevice->Send(packet, outDevice->GetAddress(), 0);
      return true;
    }
  }
  NS_LOG_WARN("No mapping found for input port " << inPort << "; dropping packet");
  return false;
}

void OCSNode::Reconfigure(const std::unordered_map<uint32_t, uint32_t>& newMapping)
{
  NS_LOG_INFO("Starting reconfiguration. All packets during reconfiguration will be lost.");
  m_inReconfig = true;
  // Schedule completion of reconfiguration after m_reconfigTime.
  Simulator::Schedule(m_reconfigTime, &OCSNode::CompleteReconfiguration, this, newMapping);
}

void OCSNode::CompleteReconfiguration(const std::unordered_map<uint32_t, uint32_t>& newMapping)
{
  for (const auto& entry : newMapping) {
    uint32_t inPort = entry.first;
    uint32_t outPort = entry.second;
    m_portMap[inPort] = outPort;
    NS_LOG_INFO("Reconfigured port mapping: " << inPort << " -> " << outPort);
  }
  if (!CheckPortMapping()) {
    NS_LOG_ERROR("New port mapping failed sanity check");
  } else {
    NS_LOG_INFO("Reconfiguration completed successfully.");
  }
  m_inReconfig = false;
}

} // namespace ns3
