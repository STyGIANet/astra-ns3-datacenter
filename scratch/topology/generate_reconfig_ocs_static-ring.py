import json
import argparse

def generate_symmetric_ring_reconfiguration(node_count, switch_id, reconfig_time_ns=1):
    # Convention:
    # Each node connects two ports: TX and RX
    # TX ports: 0 to (n-1), RX ports: n to (2n-1)
    port_mapping = {}

    for i in range(node_count):
        tx_port = i
        rx_port = node_count + (i+1) % node_count  # next node's RX
        port_mapping[str(tx_port)] = rx_port
        port_mapping[str(rx_port)] = tx_port  # reverse mapping

    reconfig_json = {
        "switch_id": switch_id,
        "reconfig_time_ns": reconfig_time_ns,
        "demand_aware": False,
        "configs": [
            {
                "start_time": 0,
                "port_mapping": port_mapping
            }
        ]
    }
    return reconfig_json

def main():
    parser = argparse.ArgumentParser(description="Generate symmetric OCS reconfiguration file for ring topology.")
    parser.add_argument("--nodes", type=int, required=True, help="Number of compute nodes.")
    parser.add_argument("--switch-id", type=int, required=True, help="ID of the OCS switch (typically == node count).")
    parser.add_argument("--output", type=str, default="reconfig.json", help="Output JSON filename.")
    args = parser.parse_args()

    reconfig = generate_symmetric_ring_reconfiguration(args.nodes, args.switch_id)
    with open(args.output, "w") as f:
        json.dump(reconfig, f, indent=2)

    print(f"Reconfiguration written to {args.output}")

if __name__ == "__main__":
    main()

