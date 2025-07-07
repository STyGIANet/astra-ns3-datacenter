import json
import argparse

def generate_ring_topology(node_count, bandwidth, latency):
    ocs_id = node_count
    topology = {
        "format": "OCS",
        "version": "0.1",
        "node_num": node_count + 1,
        "t1l": 0,
        "t2l": 0,
        "podTors": 1,
        "allTors": 1,
        "switches": [
            {"id": node_count, "type": "OCS", "radix": node_count*2}
        ],
        "links": []
    }

    for i in range(node_count*2):

        link = {
            "from": i % node_count,
            "to": ocs_id,
            "switchport": i,
            "bandwidth": bandwidth,
            "latency": latency,
            "error_rate": 0
        }
        topology["links"].append(link)

    return topology

def main():
    parser = argparse.ArgumentParser(description="Generate JSON topology for a directly connected ring.")
    parser.add_argument("--nodes", type=int, required=True, help="Number of nodes in the ring (excluding the switch).")
    parser.add_argument("--bandwidth", type=str, required=True, help="Link bandwidth (e.g., '1Gbps').")
    parser.add_argument("--latency", type=str, required=True, help="Link latency (e.g., '10.0005s').")
    parser.add_argument("--output", type=str, default="topology.json", help="Output JSON file.")

    args = parser.parse_args()

    topology = generate_ring_topology(args.nodes, args.bandwidth, args.latency)

    with open(args.output, "w") as f:
        json.dump(topology, f, indent=2)

    print(f"Topology written to {args.output}")

if __name__ == "__main__":
    main()

