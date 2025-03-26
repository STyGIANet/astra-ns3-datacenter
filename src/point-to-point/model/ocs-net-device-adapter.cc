#include "ocs-net-device-adapter.h"
#include "ns3/log.h"
#include "ns3/simulator.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("OcsNetDeviceAdapter");

TypeId
OcsNetDeviceAdapter::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::OcsNetDeviceAdapter")
    .SetParent<QbbNetDevice> ()
    .AddConstructor<OcsNetDeviceAdapter> ();
  return tid;
}

OcsNetDeviceAdapter::OcsNetDeviceAdapter ()
{
  NS_LOG_FUNCTION (this);
  // m_ocsDevice is null. It must be set via SetOcsNetDevice().
}

OcsNetDeviceAdapter::~OcsNetDeviceAdapter ()
{
  NS_LOG_FUNCTION (this);
}

void
OcsNetDeviceAdapter::SetOcsNetDevice (Ptr<OCSNetDevice> device)
{
  NS_LOG_FUNCTION (this << device);
  m_ocsDevice = device;
}

Ptr<OCSNetDevice>
OcsNetDeviceAdapter::GetOcsNetDevice () const
{
  return m_ocsDevice;
}

bool
OcsNetDeviceAdapter::Send (Ptr<Packet> packet, const Address &dest, uint16_t protocolNumber)
{
  NS_LOG_FUNCTION (this << packet << dest << protocolNumber);
  if (m_ocsDevice)
    {
      // Delegate sending to the underlying OCSNetDevice.
      return m_ocsDevice->Send (packet, dest, protocolNumber);
    }
  NS_LOG_ERROR ("No underlying OCSNetDevice set in adapter.");
  return false;
}

bool
OcsNetDeviceAdapter::Attach (Ptr<QbbChannel> channel)
{
  NS_LOG_FUNCTION (this << channel);
  if (m_ocsDevice)
    {
      // Delegate channel attachment to the underlying OCSNetDevice.
      // This assumes that m_ocsDevice->Attach() can accept a QbbChannel.
      return m_ocsDevice->Attach (channel);
    }
  NS_LOG_ERROR ("No underlying OCSNetDevice set in adapter.");
  return false;
}

Ptr<Channel>
OcsNetDeviceAdapter::GetChannel (void) const
{
  NS_LOG_FUNCTION (this);
  if (m_ocsDevice)
    {
      return m_ocsDevice->GetChannel();
    }
  return Ptr<Channel>();
}

} // namespace ns3
