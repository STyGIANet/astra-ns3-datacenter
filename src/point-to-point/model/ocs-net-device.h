/*
/ TODO 
*/

#ifndef OCS_NET_DEVICE_H
#define OCS_NET_DEVICE_H

#include "ns3/address.h"
#include "ns3/callback.h"
#include "ns3/data-rate.h"
#include "ns3/mac48-address.h"
#include "ns3/net-device.h"
#include "ns3/node.h"
#include "ns3/nstime.h"
#include "ns3/packet.h"
#include "ns3/ptr.h"
//#include "ns3/queue-fwd.h"
#include "ns3/traced-callback.h"

#include "ocs-node.h"
#include "ocs-channel.h"

#include <cstring>

namespace ns3
{

class OCSChannel;
class ErrorModel;


//class OCSNetDevice : public NetDevice
class OCSNetDevice : public NetDevice
{
  public:
    static TypeId GetTypeId();

    OCSNetDevice();
    ~OCSNetDevice() override;

    // Delete copy constructor and assignment operator to avoid misuse
    OCSNetDevice& operator=(const OCSNetDevice&) = delete;
    OCSNetDevice(const OCSNetDevice&) = delete;

    void SetDataRate(DataRate bps);
    DataRate GetDataRate();

    /**
     * Attach the device to a channel.
     *
     * \param ch Ptr to the channel to which this object is being attached.
     * \return true if the operation was successful (always true actually)
     */
    bool Attach(Ptr<OCSChannel> ch);

    /**
     * Attach a receive ErrorModel to the OCSNetDevice.
     *
     * The OCSNetDevice may optionally include an ErrorModel in
     * the packet receive chain.
     *
     * \param em Ptr to the ErrorModel.
     */
    void SetReceiveErrorModel(Ptr<ErrorModel> em);

    /**
     * Receive a packet from a connected OCSChannel.
     *
     * The OCSNetDevice receives packets from its connected channel
     * and forwards them up the protocol stack.  This is the public method
     * used by the channel to indicate that the last bit of a packet has
     * arrived at the device.
     *
     * \param p Ptr to the received packet.
     */
    void Receive(Ptr<Packet> p);

    // The remaining methods are documented in ns3::NetDevice*

    void SetIfIndex(const uint32_t index) override;
    uint32_t GetIfIndex() const override;

    Ptr<Channel> GetChannel() const override;

    void SetAddress(Address address) override;
    Address GetAddress() const override;

    bool SetMtu(const uint16_t mtu) override;
    uint16_t GetMtu() const override;

    bool IsLinkUp() const override;

    void AddLinkChangeCallback(Callback<void> callback) override;

    bool IsBroadcast() const override;
    Address GetBroadcast() const override;

    bool IsMulticast() const override;
    Address GetMulticast(Ipv4Address multicastGroup) const override;

    bool IsPointToPoint() const override;
    bool IsBridge() const override;

    bool Send(Ptr<Packet> packet, const Address& dest, uint16_t protocolNumber) override;
    bool SendFrom(Ptr<Packet> packet,
                  const Address& source,
                  const Address& dest,
                  uint16_t protocolNumber) override;

    Ptr<Node> GetNode() const override;
    void SetNode(Ptr<Node> node) override;

    bool NeedsArp() const override;

    void SetReceiveCallback(NetDevice::ReceiveCallback cb) override;
    void SetPromiscReceiveCallback(NetDevice::PromiscReceiveCallback cb) override;

    Address GetMulticast(Ipv6Address addr) const override;

    bool SupportsSendFrom() const override;

  protected:
    /**
     * \brief Handler for MPI receive event
     *
     * \param p Packet received
     */
    void DoMpiReceive(Ptr<Packet> p);

    /**
     * \brief Dispose of the object
     */
    void DoDispose() override;

    /**
     * \returns the address of the remote device connected to this device
     * through the point to point channel.
     */
    Address GetRemote() const;


    /**
     * Stop Sending a Packet Down the Wire and Begin the Interframe Gap.
     *
     * The TransmitComplete method is used internally to finish the process
     * of sending a packet out on the channel.
     */
    void TransmitComplete();

    /**
     * \brief Make the link up and running
     *
     * It calls also the linkChange callback.
     */
    void NotifyLinkUp();

    /**
     * Unused, simply for compatibility.
     * The data rate that the Net Device uses to simulate packet transmission
     * timing.
     */
    // not required because we don't have a transmission delay
    DataRate m_bps;

    /**
     * The interframe gap that the Net Device uses to throttle packet
     * transmission
     */
    // OCS reflects exactly in the manner that packets arrive
    // Time m_tInterframeGap;

    /**
     * The PointToPointChannel to which this OCSNetDevice has been
     * attached.
     */
    Ptr<OCSChannel> m_channel;

    /**
     * The Queue which this OCSNetDevice uses as a packet source.
     * Management of this Queue has been delegated to the OCSNetDevice
     * and it has the responsibility for deletion.
     * \see class DropTailQueue
     */
    // OCS doesn't have a queue
    //Ptr<Queue<Packet>> m_queue;

    /**
     * Error model for receive packet events
     */
    Ptr<ErrorModel> m_receiveErrorModel;

    // TODO traces and deciding which ones are usefull
    /**
     * The trace source fired when packets come into the "top" of the device
     * at the L3/L2 transition, before being queued for transmission.
     */
    //TracedCallback<Ptr<const Packet>> m_macTxTrace;

    /**
     * The trace source fired when packets coming into the "top" of the device
     * at the L3/L2 transition are dropped before being queued for transmission.
     */
    //TracedCallback<Ptr<const Packet>> m_macTxDropTrace;

    /**
     * The trace source fired for packets successfully received by the device
     * immediately before being forwarded up to higher layers (at the L2/L3
     * transition).  This is a promiscuous trace (which doesn't mean a lot here
     * in the point-to-point device).
     */
    // TracedCallback<Ptr<const Packet>> m_macPromiscRxTrace;

    /**
     * The trace source fired for packets successfully received by the device
     * immediately before being forwarded up to higher layers (at the L2/L3
     * transition).  This is a non-promiscuous trace (which doesn't mean a lot
     * here in the point-to-point device).
     */
    //TracedCallback<Ptr<const Packet>> m_macRxTrace;

    /**
     * The trace source fired for packets successfully received by the device
     * but are dropped before being forwarded up to higher layers (at the L2/L3
     * transition).
     */
    //TracedCallback<Ptr<const Packet>> m_macRxDropTrace;

    /**
     * The trace source fired when a packet begins the transmission process on
     * the medium.
     */
    //TracedCallback<Ptr<const Packet>> m_phyTxBeginTrace;

    /**
     * The trace source fired when a packet ends the transmission process on
     * the medium.
     */
    //TracedCallback<Ptr<const Packet>> m_phyTxEndTrace;

    /**
     * The trace source fired when the phy layer drops a packet before it tries
     * to transmit it.
     */
    //TracedCallback<Ptr<const Packet>> m_phyTxDropTrace;

    /**
     * The trace source fired when a packet begins the reception process from
     * the medium -- when the simulated first bit(s) arrive.
     */
    //TracedCallback<Ptr<const Packet>> m_phyRxBeginTrace;

    /**
     * The trace source fired when a packet ends the reception process from
     * the medium.
     */
    //TracedCallback<Ptr<const Packet>> m_phyRxEndTrace;

    /**
     * The trace source fired when the phy layer drops a packet it has received.
     * This happens if the receiver is not enabled or the error model is active
     * and indicates that the packet is corrupt.
     */
    // TracedCallback<Ptr<const Packet>> m_phyRxDropTrace;

    /**
     * A trace source that emulates a non-promiscuous protocol sniffer connected
     * to the device.  Unlike your average everyday sniffer, this trace source
     * will not fire on PACKET_OTHERHOST events.
     *
     * On the transmit size, this trace hook will fire after a packet is dequeued
     * from the device queue for transmission.  In Linux, for example, this would
     * correspond to the point just before a device \c hard_start_xmit where
     * \c dev_queue_xmit_nit is called to dispatch the packet to the PF_PACKET
     * ETH_P_ALL handlers.
     *
     * On the receive side, this trace hook will fire when a packet is received,
     * just before the receive callback is executed.  In Linux, for example,
     * this would correspond to the point at which the packet is dispatched to
     * packet sniffers in \c netif_receive_skb.
     */
    TracedCallback<Ptr<const Packet>> m_snifferTrace;

    /**
     * A trace source that emulates a promiscuous mode protocol sniffer connected
     * to the device.  This trace source fire on packets destined for any host
     * just like your average everyday packet sniffer.
     *
     * On the transmit size, this trace hook will fire after a packet is dequeued
     * from the device queue for transmission.  In Linux, for example, this would
     * correspond to the point just before a device \c hard_start_xmit where
     * \c dev_queue_xmit_nit is called to dispatch the packet to the PF_PACKET
     * ETH_P_ALL handlers.
     *
     * On the receive side, this trace hook will fire when a packet is received,
     * just before the receive callback is executed.  In Linux, for example,
     * this would correspond to the point at which the packet is dispatched to
     * packet sniffers in \c netif_receive_skb.
     */
    TracedCallback<Ptr<const Packet>> m_promiscSnifferTrace;

    Ptr<Node> m_node;                                    //!< Node owning this NetDevice
    Mac48Address m_address;                              //!< Mac48Address of this NetDevice
    NetDevice::ReceiveCallback m_rxCallback;             //!< Receive callback
    NetDevice::PromiscReceiveCallback m_promiscCallback; //!< Receive callback
                                                         //   (promisc data)
    uint32_t m_ifIndex;                                  //!< Index of the interface
    bool m_linkUp;                                       //!< Identify if the link is up or not
    TracedCallback<> m_linkChangeCallbacks;              //!< Callback for the link change event

    static const uint16_t DEFAULT_MTU = 1500; //!< Default MTU

    /**
     * \brief The Maximum Transmission Unit
     *
     * This corresponds to the maximum
     * number of bytes that can be transmitted as seen from higher layers.
     * This corresponds to the 1500 byte MTU size often seen on IP over
     * Ethernet.
     */
    uint32_t m_mtu;

    /**
     * \brief PPP to Ethernet protocol number mapping
     * \param protocol A PPP protocol number
     * \return The corresponding Ethernet protocol number
     */
    static uint16_t PppToEther(uint16_t protocol);

    /**
     * \brief Ethernet to PPP protocol number mapping
     * \param protocol An Ethernet protocol number
     * \return The corresponding PPP protocol number
     */
    static uint16_t EtherToPpp(uint16_t protocol);
};

} // namespace ns3

#endif /* OCS_NET_DEVICE_H */
