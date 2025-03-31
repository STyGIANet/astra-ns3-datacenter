
//#include "ns3/point-to-point-net-device.h"
#include "ns3/point-to-point-channel.h"
#include "ns3/node.h"
#include "ns3/packet.h"
#include "ns3/simulator.h"
#include "ns3/log.h"
#include "ns3/net-device.h"
//#include <iostream>
//#include <fstream>
#include "qbb-net-device.h"
#include "ocs-net-device.h"
#include "ocs-channel.h"



NS_LOG_COMPONENT_DEFINE ("OCSChannel");

namespace ns3 {

NS_OBJECT_ENSURE_REGISTERED (OCSChannel);

TypeId
OCSChannel::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::OCSChannel")
    .SetParent<PointToPointChannel> ()
    .AddConstructor<OCSChannel> ()
  ;
  return tid;
}

OCSChannel::OCSChannel()
  : PointToPointChannel ()
{
  NS_LOG_FUNCTION_NOARGS ();
  m_nDevices = 0;
}


bool
OCSChannel::TransmitStart (Ptr<Packet> p, Ptr<NetDevice> src, Time txTime)
{
  NS_LOG_FUNCTION (this << p << src << txTime);
  NS_LOG_LOGIC ("UID is " << p->GetUid () << ")");

  NS_ASSERT (m_link[0].m_state != INITIALIZING);
  NS_ASSERT (m_link[1].m_state != INITIALIZING);

  // Determine which link corresponds to the source device.
  uint32_t wire = (src == m_link[0].m_src) ? 0 : 1;

  Ptr<NetDevice> dst = m_link[wire].m_dst;
  uint32_t context = dst->GetNode()->GetId();
  Time deliveryTime = txTime + m_delay;

  // Explicitly check the type of destination device and call its Receive function.
  if (DynamicCast<QbbNetDevice> (dst))
    {
      Ptr<QbbNetDevice> qbbDst = DynamicCast<QbbNetDevice> (dst);
      Simulator::ScheduleWithContext (context,
                                      deliveryTime,
                                      &QbbNetDevice::Receive,
                                      qbbDst,
                                      p);
    }
  else if (DynamicCast<OCSNetDevice> (dst))
    {
      Ptr<OCSNetDevice> ocsDst = DynamicCast<OCSNetDevice> (dst);
      Simulator::ScheduleWithContext (context,
                                      deliveryTime,
                                      &OCSNetDevice::Receive,
                                      ocsDst,
                                      p);
    }
  else
    {
      NS_FATAL_ERROR ("Unknown NetDevice type attached to OCSChannel");
    }

  return true;
}

// make GetDelay() public for OCSChannel 
// (is protected in PointToPointChannel)
Time
OCSChannel::GetDelay() const
{
    return m_delay;
}

} // namespace ns3
