import json
import argparse
import math
import sys

def generate_symmetric_ring_reconfiguration(node_count, switch_id, reconfig_time_ns, demand_aware, reconfig_schedule):
    # Each node connects two ports: TX and RX
    port_mapping = {}
    for i in range(node_count):
        tx_port = i
        rx_port = node_count + (i+1) % node_count  # next node's RX
        port_mapping[str(tx_port)] = rx_port
        port_mapping[str(rx_port)] = tx_port

    reconfig_json = {
        "switch_id": switch_id,
        "reconfig_time_ns": reconfig_time_ns,
        "demand_aware": demand_aware,
        "configs": [
            {
                "start_time": 0,
                "port_mapping": port_mapping
            }
        ]
    }

    if demand_aware:
        reconfig_json["reconfig_per_round"] = reconfig_schedule

    return reconfig_json

def main():
    parser = argparse.ArgumentParser(description="Generate symmetric OCS reconfiguration file for ring topology.")
    parser.add_argument("--nodes", type=int, required=True, help="Number of compute nodes.")
    parser.add_argument("--switch-id", type=int, required=True, help="ID of the OCS switch (typically == node count).")
    parser.add_argument("--reconfig-delay", type=int, required=True, help="Reconfiguration delay in ns.")
    parser.add_argument("--demand-aware", type=str.lower, choices=["true", "false"], required=True, help="Set demand-aware mode (true or false).")
    parser.add_argument("--reconfig-schedule", type=str, help="Comma-separated reconfiguration schedule (e.g. false,true,true).")
    parser.add_argument("--output", type=str, default="reconfig.json", help="Output JSON filename.")
    args = parser.parse_args()

    reconfig_schedule = []
    if args.demand_aware:
        if not args.reconfig_schedule:
            print("Error: --reconfig-schedule is required when --demand-aware is set.")
            sys.exit(1)
        try:
            reconfig_schedule = [s.strip().lower() == 'true' for s in args.reconfig_schedule.split(',')]
        except Exception as e:
            print(f"Error parsing schedule: {e}")
            sys.exit(1)

        expected_lengths = [int(math.log2(args.nodes)), int(2 * math.log2(args.nodes))]
        if len(reconfig_schedule) not in expected_lengths:
            print(f"Error: schedule length must be log2({args.nodes}) or 2*log2({args.nodes}). Got {len(reconfig_schedule)}.")
            sys.exit(2)

    demand_aware_bool = args.demand_aware == "true"
    reconfig = generate_symmetric_ring_reconfiguration(
        node_count=args.nodes,
        switch_id=args.switch_id,
        reconfig_time_ns=args.reconfig_delay,
        demand_aware=demand_aware_bool,
        reconfig_schedule=reconfig_schedule
    )

    with open(args.output, "w") as f:
        json.dump(reconfig, f, indent=2)

    print(f"Reconfiguration written to {args.output}")

if __name__ == "__main__":
    main()

