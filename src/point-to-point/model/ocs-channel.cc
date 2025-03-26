
#include "ns3/point-to-point-net-device.h"
#include "ns3/point-to-point-channel.h"
#include "ns3/node.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/packet.h"
#include "ns3/simulator.h"
#include "ns3/log.h"
#include "ns3/net-device.h"
#include <iostream>
#include <fstream>
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
    //.AddAttribute ("Delay", "Transmission delay through the channel",
    //               TimeValue (Seconds (0)),
    //               MakeTimeAccessor (&OCSChannel::m_delay),
    //               MakeTimeChecker ())
    .AddTraceSource ("TxRxOCS",
                     "Trace source indicating transmission of packet from the channel, used by the Animation interface.",
                     MakeTraceSourceAccessor (&OCSChannel::m_txrxOCS),
                     "ns3::Packet::TracedCallback")
  ;
  return tid;
}

OCSChannel::OCSChannel()
  : PointToPointChannel (), m_nDevices(0)
{
  NS_LOG_FUNCTION_NOARGS ();
}

// void
// OCSChannel::Attach (Ptr<QbbNetDevice> device)
// {
//   NS_LOG_FUNCTION (this << device);
//   NS_ASSERT_MSG (m_nDevices < N_DEVICES, "Only two devices permitted");
//   NS_ASSERT (device);

//   m_link[m_nDevices++].m_src = device;
//   // When both devices are attached, complete the link configuration.
//   if (m_nDevices == N_DEVICES)
//     {
//       m_link[0].m_dst = m_link[1].m_src;
//       m_link[1].m_dst = m_link[0].m_src;
//       m_link[0].m_state = IDLE;
//       m_link[1].m_state = IDLE;
//     }
// }

void
OCSChannel::Attach (Ptr<NetDevice> device)
{
  NS_LOG_FUNCTION (this << device);
  NS_ASSERT_MSG (m_nDevices < N_DEVICES, "Only two devices permitted");
  NS_ASSERT (device);

  m_link[m_nDevices++].m_src = device;
  // When both devices are attached, complete the link configuration.
  if (m_nDevices == N_DEVICES)
    {
      m_link[0].m_dst = m_link[1].m_src;
      m_link[1].m_dst = m_link[0].m_src;
      m_link[0].m_state = IDLE;
      m_link[1].m_state = IDLE;
    }
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


  // Schedule the reception on the destination device after (txTime + m_delay).
  //Simulator::ScheduleWithContext (m_link[wire].m_dst->GetNode ()->GetId (),
  //                                txTime + m_delay,
  //                                &NetDevice::Receive, // Call generic Receive()
   //                               m_link[wire].m_dst, p);

  // Call the trace source for animation.
  m_txrxOCS (p, src, m_link[wire].m_dst, txTime, txTime + m_delay);
  return true;
}

std::size_t
OCSChannel::GetNDevices (void) const
{
  NS_LOG_FUNCTION_NOARGS ();
  return m_nDevices;
}

Ptr<NetDevice>
OCSChannel::GetDevice (std::size_t i) const
{
  NS_LOG_FUNCTION_NOARGS ();
  NS_ASSERT (i < static_cast<std::size_t>(N_DEVICES));
  return m_link[i].m_src;
}

Time
OCSChannel::GetDelay (void) const
{
  return m_delay;
}

Ptr<NetDevice>
OCSChannel::GetSource (uint32_t i) const
{
  return m_link[i].m_src;
}

Ptr<NetDevice>
OCSChannel::GetDestination (uint32_t i) const
{
  return m_link[i].m_dst;
}

bool
OCSChannel::IsInitialized (void) const
{
  NS_ASSERT (m_link[0].m_state != INITIALIZING);
  NS_ASSERT (m_link[1].m_state != INITIALIZING);
  return true;
}

} // namespace ns3
