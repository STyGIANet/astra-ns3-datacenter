/*
/ TODO 
*/

#ifndef OCS_NET_DEVICE_H
#define OCS_NET_DEVICE_H

#include "ns3/net-device.h"
#include "ns3/point-to-point-net-device.h"
#include "ns3/node.h"
#include "ns3/packet.h"
#include "ns3/ptr.h"
#include "ns3/traced-callback.h"

#include "ocs-node.h"
#include "ocs-channel.h"

#include <cstring>

namespace ns3
{

class OCSChannel;
class ErrorModel;


class OCSNetDevice : public PointToPointNetDevice
{
  public:
    static TypeId GetTypeId();

    OCSNetDevice();
    ~OCSNetDevice() override;

    // Delete copy constructor and assignment operator to avoid misuse
    OCSNetDevice& operator=(const OCSNetDevice&) = delete;
    OCSNetDevice(const OCSNetDevice&) = delete;

    /**
     * Receive a packet from a connected OCSChannel.
     *
     * The OCSNetDevice receives packets from its connected channel
     * and forwards to the OCSNode.  This is the public method
     * used by the channel to indicate that the last bit of a packet has
     * arrived at the device.
     *
     * \param p Ptr to the received packet.
     */
    void Receive(Ptr<Packet> p);

    // Methods are documented in ns3::NetDevice* and ns3::PointToPointNetDevice

    bool Attach(Ptr<OCSChannel> ch);

    void SetIfIndex(const uint32_t index) override;
    uint32_t GetIfIndex() const override;

    Ptr<Channel> GetChannel() const override;

    bool IsPointToPoint() const override;
    bool IsBridge() const override;

    bool Send(Ptr<Packet> packet, const Address& dest, uint16_t protocolNumber) override;
    bool SendFrom(Ptr<Packet> packet,
                  const Address& source,
                  const Address& dest,
                  uint16_t protocolNumber) override;


  protected:
    /**
     * \brief Handler for MPI receive event
     *
     * \param p Packet received
     */
    // TODO
    void DoMpiReceive(Ptr<Packet> p);

    void DoDispose() override;

    /**
     * \returns the address of the remote device connected to this device
     * through the ocs channel.
     */
    Address GetRemote() const;

    void TransmitComplete();

    /**
     * Unused because we don't have a transmission delay in OCS, simply for compatibility.
     * Usually: the data rate that the Net Device uses to simulate packet transmission delay.
     */
    DataRate m_bps;

    /**
     * InterframeGap unused: OCS reflects exactly in the manner
     * that packets arrive
     */
    // Time m_tInterframeGap;

    /**
     * The OCSChannel to which this OCSNetDevice has been
     * attached.
     */
    Ptr<OCSChannel> m_channel;

    // OCS doesn't have a queue
    //Ptr<Queue<Packet>> m_queue;

    // TODO traces and deciding which ones are useful, see PointToPoint NetDevice

    uint32_t m_ifIndex;                                  //!< Index of the interface
    };

} // namespace ns3

#endif /* OCS_NET_DEVICE_H */
