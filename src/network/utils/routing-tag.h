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
     * Constructs a RoutingTag with the given next hop port id
     *
     * \param id the next hop port id
     */
    RoutingTag(uint32_t id);
    /**
     * Sets the next hop for the route
     * \param id the next hop port id
     */
    void SetNextHopPortId(uint32_t id);
    /**
     * Gets the hop port id for the tag
     * \returns current hop port id for this tag
     */
    uint32_t GetNextHopPortId() const;
    /**
     * Calculates the next hop node
     * \param id current node id
     * \returns hop port id allocated
     */
    // uint32_t AllocateNextHopId(uint32_t id);

  private:
    uint32_t m_nextHopPortId; //!< Id of the port to route the packet to
};

} // namespace ns3

#endif /* ROUTING_TAG_H */
