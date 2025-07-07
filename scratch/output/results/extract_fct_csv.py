import os
import re
import argparse
import pandas as pd
from collections import defaultdict

def parse_filename(fname):
    # Example: 54_original_routing_ring_8n_100000B_1Gbps_500ns_fct.txt
    pattern = r"^(\d+)_([a-zA-Z0-9\-]+)_routing_ring_(\d+)n_(\d+)B_([0-9]+[GM]bps)_([0-9]+ns)_fct\.txt$"    
    match = re.match(pattern, fname)
    if not match:
        raise ValueError(f"Filename '{fname}' does not match expected pattern")
    return {
        "test_id": int(match.group(1)),
        "routing_strategy": match.group(2),
        "num_nodes": int(match.group(3)),
        "workload_size": int(match.group(4)),
        "bandwidth": match.group(5),
        "prop_delay": match.group(6)
    }

def parse_file(fname):
    metadata = parse_filename(fname)
    df = pd.read_csv(fname, delim_whitespace=True, header=None, names=[
        "sip", "dip", "sport", "dport", "size(B)", "start_time", "fct(ns)",
        "standalone_fct(ns)", "end_time", "src", "dst", "maxQps", "tag"
    ])

    grouped = defaultdict(list)
    for _, row in df.iterrows():
        grouped[row["size(B)"]].append(row)

    rows = []
    for round_idx, size in enumerate(sorted(grouped.keys())):
        round_flows = grouped[size]
        max_flow = max(round_flows, key=lambda row: row["fct(ns)"])
        rows.append({
            **metadata,
            "round": round_idx,
            "round_size": int(size),
            "max_fct": int(max_flow["fct(ns)"]),
            "src_of_max_fct": int(max_flow["src"]),
            "dst_of_max_fct": int(max_flow["dst"])
        })
    return rows

def main():
    parser = argparse.ArgumentParser(description="Extract max FCT per round into CSV.")
    parser.add_argument("--files", nargs="*", help="Explicit list of *_fct.txt files to parse.")
    parser.add_argument("--out", default="fct_summary.csv", help="Output CSV filename")
    args = parser.parse_args()

    if args.files:
        files = args.files
    else:
        files = [f for f in os.listdir(".") if f.endswith("_fct.txt")]

    all_rows = []
    for f in sorted(files):
        try:
            rows = parse_file(f)
            all_rows.extend(rows)
            print("Extracted data from " + f + "to csv.")
        except Exception as e:
            print(f"Skipping {f}: {e}")

    if all_rows:
        df = pd.DataFrame(all_rows)
        df.to_csv(args.out, index=False)
        print(f"✅ Wrote CSV to {args.out} with {len(df)} entries.")
    else:
        print("⚠️ No valid entries found.")

if __name__ == "__main__":
    main()

