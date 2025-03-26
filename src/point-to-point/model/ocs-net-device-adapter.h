#ifndef OCS_NET_DEVICE_ADAPTER_H
#define OCS_NET_DEVICE_ADAPTER_H

#include "ns3/qbb-net-device.h"       // Base class for devices with PFC support
#include "ocs-net-device.h"           // Your simple OCSNetDevice implementation

namespace ns3 {

class OcsNetDeviceAdapter : public QbbNetDevice
{
public:
  static TypeId GetTypeId (void);
  OcsNetDeviceAdapter ();
  virtual ~OcsNetDeviceAdapter ();

  /**
   * \brief Set the underlying OCSNetDevice that this adapter wraps.
   * \param device The OCSNetDevice pointer.
   */
  void SetOcsNetDevice (Ptr<OCSNetDevice> device);

  /**
   * \brief Get the underlying OCSNetDevice.
   * \return The OCSNetDevice pointer.
   */
  Ptr<OCSNetDevice> GetOcsNetDevice () const;

  // Override virtual functions expected by QbbChannel
  virtual bool Send (Ptr<Packet> packet, const Address &dest, uint16_t protocolNumber) override;
  virtual bool Attach (Ptr<QbbChannel> channel) override;
  virtual Ptr<Channel> GetChannel (void) const override;

private:
  Ptr<OCSNetDevice> m_ocsDevice;  // The underlying OCS device
};

} // namespace ns3

#endif /* OCS_NET_DEVICE_ADAPTER_H */
