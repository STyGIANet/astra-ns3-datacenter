/*
 * OCSNetDevice implementation.
 *
 * This implementation is based on the point-to-point net device but modified for an
 * optical circuit switch. In an OCS, the device does no packet-level processing:
 * it does not add headers, queue packets, have a transmission delay, or perform PFC.
 * Instead, when Send() is called the packet is immediately transmitted on the channel.
 *
 * All forwarding and port mapping decisions are handled at the OCSNode level.
 *
 */

#include "ocs-node.h"
#include "ocs-channel.h"
#include "ocs-net-device.h"

#include "ns3/log.h"
#include "ns3/simulator.h"
#include "ns3/uinteger.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/pointer.h"
#include "ns3/error-model.h"
#include "point-to-point-net-device.h"



namespace ns3 {

NS_LOG_COMPONENT_DEFINE("OCSNetDevice");

NS_OBJECT_ENSURE_REGISTERED(OCSNetDevice);

TypeId
OCSNetDevice::GetTypeId(void)
{
    static TypeId tid = 
    TypeId("ns3::OCSNetDevice")
        .SetParent<PointToPointNetDevice>()
        .AddConstructor<OCSNetDevice>();
    return tid;
}

OCSNetDevice::OCSNetDevice ()
{
  NS_LOG_FUNCTION(this);
}

OCSNetDevice::~OCSNetDevice ()
{
  NS_LOG_FUNCTION(this);
}

void
OCSNetDevice::DoDispose()
{
    NS_LOG_FUNCTION(this);
    m_node = nullptr;
    m_channel = nullptr;
    m_receiveErrorModel = nullptr;
    NetDevice::DoDispose();
}

bool
OCSNetDevice::Send (Ptr<Packet> packet, const Address &dest, uint16_t protocolNumber)
{
  NS_LOG_FUNCTION (this << packet << dest << protocolNumber);
  NS_LOG_LOGIC("p=" << packet << ", dest=" << &dest);
  NS_LOG_LOGIC("UID is " << packet->GetUid());

  // If the link is down, drop the packet.
  if (!IsLinkUp())
    {
      // maybe TODO: some drop trace 
      NS_LOG_WARN ("OCSNetDevice: Link is down. Dropping packet.");
      return false;
    }

  // For an optical circuit switch, we do not add headers or queue the packet.
  // Instead, we immediately forward the packet on the channel.

  // In the point-to-point device, transmission is initiated by TransmitStart,
  // which also schedules a TransmitComplete event after a calculated delay.
  // Here we override that behavior by setting a zero transmission time.
    Time txTime = NanoSeconds(0);
    bool result;
    if (DynamicCast<OCSChannel>(m_channel))
    {
        result = (DynamicCast<OCSChannel>(m_channel))->TransmitStart(packet, this, txTime);
    }
    else
    {
        NS_FATAL_ERROR("Unknown Channel type attached to OCSNetDevice");
    }
    // result = m_channel->TransmitStart(packet, this, txTime);

    // Optical reflection is essentially instantaneous, so schedule transmit complete immediately.
    Simulator::ScheduleNow(&OCSNetDevice::TransmitComplete, this);

    return result;
}

void
OCSNetDevice::TransmitComplete()
{
    NS_LOG_FUNCTION(this);
    // In the base device, TransmitComplete notifies the end of a packet transmission.
    // Here this is only a log intially, and placeholder for possible further functionality

    //NS_LOG_INFO("TransmitComplete on OCSNetDevice"); // only for very intial tests
    // m_macTxEndTrace(m_currentPkt);

    // No further packet dequeuing occurs as this device is not using a transmit queue.
}

bool
OCSNetDevice::Attach(Ptr<OCSChannel> ch)
{
    NS_LOG_FUNCTION(this << &ch);

    m_channel = ch;

    // this cast is hack-y and should be replaced
    m_channel->Attach(this);

    NotifyLinkUp();
    return true;
}


void
OCSNetDevice::Receive(Ptr<Packet> packet)
{
    NS_LOG_FUNCTION(this << packet);

    // Check for packet corruption using the receive error model.
    if (m_receiveErrorModel && m_receiveErrorModel->IsCorrupt(packet))
    {
        //m_phyRxDropTrace(packet);
        return;
    }
    else
    {
        // Call trace hooks as in the base class.
        m_snifferTrace(packet);
        m_promiscSnifferTrace(packet);


        // In the base device, we would strip headers (ProcessHeader),
        // but in OCS, we don't process packet-level details.
        // Instead, simply forward the packet to the parent OCSNode to
        // send on outgoing port according to OCS config, e.g. "reflect".

        Ptr<Node> node = GetNode();
        Ptr<OCSNode> ocsNode = DynamicCast<OCSNode>(node);
        if (ocsNode)
        {
            //NS_LOG_INFO("OCSNetDevice forwarding packet to parent OCSNode");
            bool result = ocsNode->ReceiveFromDevice(Ptr<NetDevice>(this), packet);
            if (!result)
            {
                NS_LOG_WARN("OCSNode failed to process the packet; dropping it.");
            }
        }
        else
        {
            NS_LOG_ERROR("OCSNetDevice not attached to an OCSNode; dropping packet.");
        }

        // Optionally, call higher-level receive callback here if needed:
        // m_rxCallback(this, packet, protocol, GetRemote());
    }
}

void
OCSNetDevice::SetIfIndex(const uint32_t index)
{
    NS_LOG_FUNCTION(this);
    m_ifIndex = index;
}

uint32_t
OCSNetDevice::GetIfIndex() const
{
    return m_ifIndex;
}

Ptr<Channel>
OCSNetDevice::GetChannel() const
{
    return m_channel;
}

// OCS doesn't need addresses, similar to PointToPoint, were it says:
// This is a point-to-point device, so we really don't need any kind of address
// information.  However, the base class NetDevice wants us to define the
// methods to get and set the address.  Rather than be rude and assert, we let
// clients get and set the address, but simply ignore them.


// use ppp as a basis for simplicity of modeling
// two devices connected by direct link
bool
OCSNetDevice::IsPointToPoint() const
{
    NS_LOG_FUNCTION(this);
    return true;
}

// doesnt allow/use MAC-spoofing
bool
OCSNetDevice::IsBridge() const
{
    NS_LOG_FUNCTION(this);
    return false;
}

// Not supported
bool
OCSNetDevice::SendFrom(Ptr<Packet> packet,
                                const Address& source,
                                const Address& dest,
                                uint16_t protocolNumber)
{
    NS_LOG_FUNCTION(this << packet << source << dest << protocolNumber);
    NS_LOG_WARN ("OCSNetDevice: SendFrom was called but not supported on this NetDevice Type");
    return false;
}

void
OCSNetDevice::DoMpiReceive(Ptr<Packet> p)
{
    NS_LOG_WARN ("OCSNetDevice: DoMpiReceive called but MPI not fully implemented for OCSNetDevice.");
    NS_LOG_FUNCTION(this << p);
    Receive(p);
}

Address
OCSNetDevice::GetRemote() const
{
    NS_LOG_FUNCTION(this);
    NS_ASSERT(m_channel->GetNDevices() == 2);
    for (std::size_t i = 0; i < m_channel->GetNDevices(); ++i)
    {
        Ptr<NetDevice> tmp = m_channel->GetDevice(i);
        if (tmp != this)
        {
            return tmp->GetAddress();
        }
    }
    NS_ASSERT(false);
    // quiet compiler.
    return Address();
}

} // namespace ns3
