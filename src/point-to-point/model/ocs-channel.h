#ifndef OCS_CHANNEL_H
#define OCS_CHANNEL_H

#include <list>
#include "ns3/channel.h"
#include "ns3/point-to-point-channel.h"
//#include "qbb-net-device.h"
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
   * \brief Create a OCSChannel with zero transmission delay by default.
   */
  OCSChannel ();

  /**
   * \brief Attach a given NetDevice to this channel.
   * \param device pointer to the NetDevice to attach to the channel.
   */
  //void Attach (Ptr<QbbNetDevice> device);
  void Attach (Ptr<NetDevice> device);

  /**
   * \brief Transmit a packet over this channel.
   * \param p Packet to transmit.
   * \param src Source NetDevice.
   * \param txTime Transmit time to apply.
   * \returns true if successful.
   */
  virtual bool TransmitStart (Ptr<Packet> p, Ptr<NetDevice> src, Time txTime);

  /**
   * \brief Get number of devices on this channel.
   * \returns number of devices on this channel.
   */
  virtual std::size_t GetNDevices (void) const;

  /**
   * \brief Get the NetDevice corresponding to index i on this channel.
   * \param i Index number of the device requested.
   * \returns Ptr to NetDevice requested.
   */
  virtual Ptr<NetDevice> GetDevice (std::size_t i) const;

  /**
   * \brief Get the delay associated with this channel.
   * \returns Time delay.
   */
  Time GetDelay (void) const;

protected:
  /*
   * \brief Check to make sure the link is initialized
   * \returns true if initialized, asserts otherwise
   */
  bool IsInitialized (void) const;  

  /**
   * \brief Get the source NetDevice for link i.
   * \param i Index number.
   * \returns Ptr to source NetDevice.
   */
  Ptr<NetDevice> GetSource (uint32_t i) const;

  /**
   * \brief Get the destination NetDevice for link i.
   * \param i Index number.
   * \returns Ptr to destination NetDevice.
   */
  Ptr<NetDevice> GetDestination (uint32_t i) const;

private:
  static const int N_DEVICES = 2;
  Time          m_delay;
  int32_t       m_nDevices;

  /**
   * Trace source for packet transmission animation events.
   */
  TracedCallback<Ptr<const Packet>, Ptr<NetDevice>, Ptr<NetDevice>, Time, Time> m_txrxOCS;

  enum WireState
  {
    INITIALIZING,
    IDLE,
    TRANSMITTING,
    PROPAGATING
  };

  class Link
  {
  public:
    Link() : m_state(INITIALIZING), m_src(0), m_dst(0) {}
    WireState              m_state;
    Ptr<NetDevice> m_src;
    Ptr<NetDevice> m_dst;
  };

  Link    m_link[N_DEVICES];
};

} // namespace ns3

#endif /* OCS_CHANNEL_H */

