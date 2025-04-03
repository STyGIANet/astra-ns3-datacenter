
#include "ns3/log.h"
#include "ns3/simulator.h"
#include "ns3/nstime.h"
#include "ns3/uinteger.h"
#include "ns3/node.h"
#include "ocs-node.h"
#include "ocs-net-device.h"


NS_LOG_COMPONENT_DEFINE("OCSNode");
namespace ns3 {

NS_OBJECT_ENSURE_REGISTERED (OCSNode);

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
{
  m_node_type = 3; // node type 3 for OCSNode
}

void OCSNode::DoInitialize()
{
  Node::DoInitialize();
  NS_LOG_INFO("OCSNode: Set node type to : " << m_node_type);
  NS_LOG_INFO("OCSNode initialized with radix = " << m_radix);
}

void OCSNode::SetPortConnection(uint32_t inputPort, uint32_t outputPort)
{
  m_portMap[inputPort] = outputPort;
  NS_LOG_INFO("Configured port mapping: " << inputPort << " -> " << outputPort);
  if (!CheckPortMapping()) {
    // TODO Handle error
  }
}

void OCSNode::SetPortMap(const std::unordered_map<uint32_t, uint32_t>& newMapping){
  NS_LOG_FUNCTION(this << &newMapping);

  if (newMapping.size() != m_radix){
    NS_LOG_WARN("Size of PortMap passed to OCSNode::SetPortMap != Radix - some entries are missing or superflous.");
    return; //don't set to this new wrong port map
  }
  
  // TODO: maybe there's a better way for a deep copy 
  for (const auto& entry : newMapping) {
    uint32_t inPort = entry.first;
    uint32_t outPort = entry.second;
    m_portMap[inPort] = outPort;
    NS_LOG_LOGIC("Reconfigured port mapping: " << inPort << " -> " << outPort);
  }
}

bool OCSNode::CheckPortMapping() const
{
  NS_LOG_FUNCTION_NOARGS();

  for (uint32_t i = 0; i < m_radix; i++) {
    auto it = m_portMap.find(i);
    if (it == m_portMap.end())
      continue;
    uint32_t mappedPort = it->second;
    // Check that mappedPort is either -1 (or rather UINTMAX) meaning unmapped or within a valid range.
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
  NS_LOG_LOGIC("Port mapping passed sanity check");
  return true;
}

bool OCSNode::ReceiveFromDevice(Ptr<NetDevice> device, Ptr<Packet> packet)
{
  NS_LOG_FUNCTION(this << device << packet);
  if (m_inReconfig) {
    NS_LOG_WARN("OCSNode is reconfiguring; dropping packet");
    return false;
  }

  // the m_devices vector has an additional loopback at index 0 from the InternetStackHelper,
  // so we shift index as portNum + 1
  uint32_t inPort = device->GetIfIndex() - 1;
  auto it = m_portMap.find(inPort);
  if (it != m_portMap.end()) {
    size_t outPort = static_cast<size_t> (it->second);

    // same shift as for inPort
    if ( outPort + 1 >= m_devices.size() ){
      NS_LOG_WARN("OCSNode tried to send via port that doesn't have a NetDevice. Not Transmitting");
      return false;
    }
    Ptr<OCSNetDevice> outDevice = DynamicCast<OCSNetDevice>( GetDevice(outPort + 1) );
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
  NS_LOG_FUNCTION(this << &newMapping);

  NS_LOG_INFO("Starting reconfiguration. All packets during reconfiguration will be lost.");
  m_inReconfig = true;
  
  // Schedule completion of reconfiguration after m_reconfigTime.
  Simulator::Schedule(m_reconfigTime, &OCSNode::CompleteReconfiguration, this, newMapping);
}

void OCSNode::CompleteReconfiguration(const std::unordered_map<uint32_t, uint32_t>& newMapping)
{
  NS_LOG_FUNCTION(this << &newMapping);
  SetPortMap(newMapping);

  if (!CheckPortMapping()) {
    NS_LOG_ERROR("New port mapping failed sanity check");
  } else {
    NS_LOG_INFO("Reconfiguration completed successfully.");
  }
  m_inReconfig = false;
}

bool OCSNode::VerifyDevicePortNum(Ptr<NetDevice> dev, uint32_t portNum){
  NS_LOG_FUNCTION(this << dev << portNum);

  // Check range [0,radix]
  bool result = (portNum >= 0 && portNum < m_radix);

  // Check that the devices own interface number == portNum (set by Node->AddDevice)
  // index shift due to loopback at index 0 of the Node's interfaces
  result = result && (DynamicCast<OCSNetDevice>(dev)->GetIfIndex() == portNum + 1);

  // Check that this node's index for the given NetDevice == portNum + 1
  result = result && (GetDevice(portNum + 1) == dev);

  return result;
}

} // namespace ns3
