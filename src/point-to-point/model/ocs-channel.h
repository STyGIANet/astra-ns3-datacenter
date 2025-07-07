#ifndef OCS_CHANNEL_H
#define OCS_CHANNEL_H

#include <list>
#include "ns3/channel.h"
#include "ns3/point-to-point-channel.h"
#include "point-to-point-net-device.h"
#include "ns3/ptr.h"
#include "ns3/nstime.h"
#include "ns3/data-rate.h"
#include "ns3/traced-callback.h"

namespace ns3 {

class NetDevice;  // Use generic NetDevice instead of OCSNetDevice
class Packet;

/**
 * \ingroup point-to-point
 * \brief Simple Point To Point Channel supporting heterogeneous NetDevices.
 *
 * This class represents a very simple point-to-point channel.
 * There can be a maximum of two NetDevices attached.
 */
class OCSChannel : public PointToPointChannel
{
public:
  static TypeId GetTypeId (void);

  /**
   * \brief Create a OCSChannel with zero delay by default.
   */
  OCSChannel ();

  /**
   * \brief Transmit a packet over this channel.
   * \param p Packet to transmit.
   * \param src Source NetDevice.
   * \param txTime Transmit time to apply.
   * \returns true if successful.
   */
  virtual bool TransmitStart (Ptr<Packet> p, Ptr<NetDevice> src, Time txTime);

  /**
   * \brief Get the delay associated with this channel
   * \returns Time delay
   */
  Time GetDelay() const;

  // Get the other device connected to this channel
  Ptr<NetDevice> GetOtherDev(Ptr<NetDevice> src);

};

} // namespace ns3

#endif /* OCS_CHANNEL_H */

