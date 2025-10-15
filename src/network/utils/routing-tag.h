/*
 * Copyright (c) 2008 INRIA
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author: Mathieu Lacage <mathieu.lacage@sophia.inria.fr>
 */
#ifndef ROUTING_TAG_H
#define ROUTING_TAG_H

#include "ns3/tag.h"

namespace ns3
{
/**
 *
 * \brief Tag used to allow routing in an optical switch
 *
 * This tag is added by each source node when a packet is created,
 * and it is then used to route the packet to the final destination
 * node
 */
class RoutingTag : public Tag
{
  public:
    /**
     * \brief Get the type ID.
     * \return the object TypeId
     */
    static TypeId GetTypeId();
    TypeId GetInstanceTypeId() const override;
    uint32_t GetSerializedSize() const override;
    void Serialize(TagBuffer buf) const override;
    void Deserialize(TagBuffer buf) override;
    void Print(std::ostream& os) const override;
    RoutingTag();

    /**
     * Constructs a RoutingTag
     *
     * \param sid
     * \param did
     * \param nextHopPortId
     */
    RoutingTag(uint32_t sid, uint32_t did, uint32_t nextHopPortId);
    /**
     * Sets the source node id
     * \param id the next hop port id
     */
    void SetSrcId(uint32_t id);
    /**
     * Gets the destination node id
     * \returns destination node id for this tag
     */
    uint32_t GetSrcId() const;
    /**
     * Sets the destination node id for the route
     * \param id the destination node id
     */
    void SetDestId(uint32_t id);
    /**
     * Gets the destination node id
     * \returns destination node id for this tag
     */
    uint32_t GetDestId() const;
    /**
     * Sets the next hop for the route
     * \param id the next hop port id
     */
    void SetNextHopPortId(uint32_t id);
    /**
     * Gets the hop port id
     * \returns current hop port id
     */
    uint32_t GetNextHopPortId() const;
    /**
     * Calculates the next hop node
     * \param id current node id
     * \returns hop port id allocated
     */
    // uint32_t AllocateNextHopId(uint32_t id);

    uint32_t GetDirection(){
      return m_direction;
    }

    void SetDirection(uint32_t direction){
      m_direction = direction;
    }

  private:
    uint32_t m_sid; //!< Id of the source node
    uint32_t m_did; //!< Id of the destination node
    uint32_t m_nextHopPortId; //!< Id of the port to route the packet to
    uint32_t m_direction;
};

} // namespace ns3

#endif /* ROUTING_TAG_H */
