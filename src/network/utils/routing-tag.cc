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
#include "routing-tag.h"

#include "ns3/log.h"

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("RoutingTag");

NS_OBJECT_ENSURE_REGISTERED(RoutingTag);

TypeId
RoutingTag::GetTypeId()
{
    static TypeId tid = TypeId("ns3::RoutingTag")
                            .SetParent<Tag>()
                            .SetGroupName("Network")
                            .AddConstructor<RoutingTag>();
    return tid;
}

TypeId
RoutingTag::GetInstanceTypeId() const
{
    return GetTypeId();
}

uint32_t
RoutingTag::GetSerializedSize() const
{
    NS_LOG_FUNCTION(this);
    return 4;
}

void
RoutingTag::Serialize(TagBuffer buf) const
{
    NS_LOG_FUNCTION(this << &buf);
    buf.WriteU32(m_nextHopPortId);
}

void
RoutingTag::Deserialize(TagBuffer buf)
{
    NS_LOG_FUNCTION(this << &buf);
    m_nextHopPortId = buf.ReadU32();
}

void
RoutingTag::Print(std::ostream& os) const
{
    NS_LOG_FUNCTION(this << &os);
    os << "NextHopPortId=" << m_nextHopPortId;
}

RoutingTag::RoutingTag()
    : Tag()
{
    NS_LOG_FUNCTION(this);
}

RoutingTag::RoutingTag(uint32_t id)
    : Tag(),
      m_nextHopPortId(id)
{
    NS_LOG_FUNCTION(this << id);
}

void
RoutingTag::SetNextHopPortId(uint32_t id)
{
    NS_LOG_FUNCTION(this << id);
    m_nextHopPortId = id;
}

uint32_t
RoutingTag::GetNextHopPortId() const
{
    NS_LOG_FUNCTION(this);
    return m_nextHopPortId;
}

// uint32_t
// RoutingTag::AllocateNextHopId(uint32_t id)
// {
//     NS_LOG_FUNCTION(this << id);
//     return ++id;
// }

} // namespace ns3
