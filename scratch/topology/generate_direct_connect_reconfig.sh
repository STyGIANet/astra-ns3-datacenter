#!/bin/bash

# Check if a number of nodes is given
if [ -z "$1" ]; then
  echo "Usage: $0 <numNodes>"
  exit 1
fi

numNodes=$1
filename="ocs_static_ring_${numNodes}_nodes.json"

cat > "$filename" <<EOF
{
  "switch_id": $numNodes,
  "reconfig_time_ns": 1,
  "demand_aware": false,
  "configs": [
    {
      "start_time": 0,
      "port_mapping": {
        "0": 7,
        "1": 4,
        "2": 5,
        "3": 6,
        "4": 1,
        "5": 2,
        "6": 3,
        "7": 0
      }
    }
  ]
}
EOF

