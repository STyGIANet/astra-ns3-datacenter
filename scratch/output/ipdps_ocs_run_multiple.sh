#!/bin/bash
set -e

if [ -z "$1" ]; then
  echo "Usage: $0 <cmd> [--log]"
  exit 1
fi
cmd="$1"
log=0
if [ "$2" == "--log" ]; then
  log=1
fi

# ========== CONFIGURATION ==========
routingStrategy="halvingDoubling"
bandwidthStrs=("800Gbps" "800Gbps") # "800Gbps" "800Gbps" "800Gbps" "800Gbps" "800Gbps" "800Gbps")
#bandwidthStrs=("800Gbps" "800Gbps" "800Gbps" "800Gbps" "800Gbps" "800Gbps" "800Gbps" "800Gbps")
propDelays=("300ns" "500ns") #("2ns" "5ns" "10ns" "50ns" "100ns" "200ns" "300ns" "500ns") # these are half of per hop prop delay because there's two links between nodes
#propDelays=("4ns" "4ns" "4ns" "4ns" "4ns" "4ns" "4ns" "4ns") # these are half of per hop prop delay because there's two links between nodes
numNodesList=(32) #(16,256)
workloadSizes=("128000000") # "256000000" "512000000" "1000000000")
#workloadSizes=("32" "32000" "64000" "128000" "256000" "512000" "1000000" "2000000" "4000000") # "16000000") #"32000000")
operation="REDUCESCATTER"
endpointDelays=(0) #(1 4 16 64 128 512 1024) # removed 2,8,32,256
algo="halvingDoubling"

## reconfig
demandAware="true"
schedules=("true,true,true,true,true" "false,true,true,true,true" "false,false,true,true,true" "false,false,false,true,true" "false,false,false,false,true" "false,false,false,false,false")
#("false,false,false,false,false")

#("true,true,true,true,true,true,true,true" "false,true,true,true,true,true,true,true" "false,false,true,true,true,true,true,true" "false,false,false,true,true,true,true,true" "false,false,false,false,true,true,true,true" "false,false,false,false,false,true,true,true" "false,false,false,false,false,false,true,true" "false,false,false,false,false,false,false,true" "false,false,false,false,false,false,false,false")
#("true,true,true,true" "false,true,true,true" "false,false,true,true" "false,false,false,true" "false,false,false,false")
#("true,true,true,true,true,true,true,true" "true,true,true,true,true,true,true,false" "true,true,true,true,true,true,false,false" "true,true,true,true,true,false,false,false" "true,true,true,true,false,false,false,false" "true,true,true,false,false,false,false,false" "true,true,false,false,false,false,false,false" "true,false,false,false,false,false,false,false" "false,false,false,false,false,false,false,false")
#("false,false,false,false")
#("false,false,false,false,false,false,false,false") 

#("true,true,true,true,true,true,true,true,true" "true,true,true,true,true,true,true,true,false" "true,true,true,true,true,true,true,false,false" "true,true,true,true,true,true,false,false,false" "true,true,true,true,true,false,false,false,false"  "true,true,true,true,false,false,false,false,false" "true,true,true,false,false,false,false,false,false" "true,true,false,false,false,false,false,false,false"  "true,false,false,false,false,false,false,false,false" "false,false,false,false,false,false,false,false,false")
	# "false,true,true,true" "false,false,true,true" "false,false,false,true" "false,false,false,false")
reconfigDelays=("100" "200") #("100" "200" "500" "1000" "2000" "4000" "10000")
#reconfigDelay="100"

# Directories
astraDir="/app/astra-sim"
topoDir="${astraDir}/extern/network_backend/ns-3/scratch/topology"
configDir="${astraDir}/extern/network_backend/ns-3/scratch/config"
systemDir="${astraDir}/examples/ns3"
genWorkloadDir="${astraDir}/examples/text_converter/text_workloads"
generalOutputDir="${astraDir}/extern/network_backend/ns-3/scratch/output"
buildDir="${astraDir}/build/astra_ns3"
mkdir -p "${generalOutputDir}/results/logs"

# ========== LOOP ==========

    for workloadBytes in "${workloadSizes[@]}"; do
      for reconfigDelay in "${reconfigDelays[@]}"; do
        for schedule in "${schedules[@]}"; do
		    for endpointDelay in "${endpointDelays[@]}"; do
		    testIteration="r101_${algo}_${endpointDelay}epd_${schedule}_${reconfigDelay}reconf_"

        for i in "${!bandwidthStrs[@]}"; do
            bandwidthStr="${bandwidthStrs[$i]}"
            propDelay="${propDelays[$i]}"

            for numNodes in "${numNodesList[@]}"; do

        # Filenames
        topoFile="ocs_connected_${numNodes}_nodes_${bandwidthStr}_${propDelay}.json"
        reconfigFile="ocs_demandAware_${numNodes}_nodes_${schedule}_${reconfigDelay}ns_${propDelay}.json"
        configFile="config_ocs_static_${routingStrategy}_${numNodes}_${bandwidthStr}_${propDelay}.txt"
        logicalTopoFile="sample_${numNodes}nodes_1D.json"
        workloadFile="${operation}${workloadBytes}B_${numNodes}/${operation}${workloadBytes}B_${numNodes}"
        systemFile="system_${algo}_${endpointDelay}ns.json"
        thisOutputDir="results"
        logName="${testIteration}_${numNodes}n_${workloadBytes}B_${bandwidthStr}_${propDelay}.log"
        fctName="${testIteration}_${numNodes}n_${workloadBytes}B_${bandwidthStr}_${propDelay}_fct.txt"

        echo ""
        echo "=== Running: ${schedule} | ${numNodes} nodes | ${bandwidthStr} | ${propDelay} | ${workloadBytes}B ==="
        echo ""

        # --- Generate topology ---
        cd "${topoDir}" || exit 1
        python generate_ocs_connect.py \
          --nodes ${numNodes} --bandwidth ${bandwidthStr} --latency ${propDelay} --output ./${topoFile}

        # --- Reconfig schedule ---
        python generate_reconfig_ocs_static-ring.py --nodes ${numNodes} --switch-id ${numNodes} --reconfig-delay ${reconfigDelay} --demand-aware ${demandAware} --reconfig-schedule ${schedule} --output ./${reconfigFile} # is called static ring because intial topo is ring, but a reconfig schedule can be provided

        # --- Config file ---
        cd "${configDir}" || exit 2
        cat > "$configFile" <<EOF
ENABLE_QCN 1
USE_DYNAMIC_PFC_THRESHOLD 1
PACKET_PAYLOAD_SIZE 1000

TOPOLOGY_FILE ../../scratch/topology/${topoFile}
TOPOLOGY_FILE_FORMAT json
RECONFIG_FILE ../../scratch/topology/${reconfigFile}
RING_ROUTING_STRATEGY ${routingStrategy}

FLOW_FILE ../../scratch/output/flow.txt
TRACE_FILE ../../scratch/output/trace.txt
TRACE_OUTPUT_FILE ../../scratch/output/mix.tr
FCT_OUTPUT_FILE ../../scratch/output/fct.txt
PFC_OUTPUT_FILE ../../scratch/output/pfc.txt
QLEN_MON_FILE ../../scratch/output/qlen.txt
QLEN_MON_START 0
QLEN_MON_END 20000

SIMULATOR_STOP_TIME 40000000000000.00

CC_MODE 1
ALPHA_RESUME_INTERVAL 1
RATE_DECREASE_INTERVAL 4
CLAMP_TARGET_RATE 0
RP_TIMER 900
EWMA_GAIN 0.00390625
FAST_RECOVERY_TIMES 1
RATE_AI 50Mb/s
RATE_HAI 100Mb/s
MIN_RATE 100Mb/s
DCTCP_RATE_AI 1000Mb/s

ERROR_RATE_PER_LINK 0.0000
L2_CHUNK_SIZE 0
L2_ACK_INTERVAL 1
L2_BACK_TO_ZERO 0

HAS_WIN 0
GLOBAL_T 0
VAR_WIN 1
FAST_REACT 1
U_TARGET 0.95
MI_THRESH 0
INT_MULTI 1
MULTI_RATE 0
SAMPLE_FEEDBACK 0
PINT_LOG_BASE 1.05
PINT_PROB 1.0
NIC_TOTAL_PAUSE_TIME 0

RATE_BOUND 1
ACK_HIGH_PRIO 0
LINK_DOWN 0 0 0
ENABLE_TRACE 1

KMAX_MAP 6 25000000000 400 40000000000 800 100000000000 1600 200000000000 2400 400000000000 3200 2400000000000 3200
KMIN_MAP 6 25000000000 100 40000000000 200 100000000000 400 200000000000 600 400000000000 800 2400000000000 800
PMAX_MAP 6 25000000000 0.2 40000000000 0.2 100000000000 0.2 200000000000 0.2 400000000000 0.2 2400000000000 0.2

BUFFER_SIZE 32
RTO 100000000000
EOF
        
# --- Logical topology and system file with algo+endpoint delay---
        cd "${systemDir}" || exit 3
        [ -f "$logicalTopoFile" ] || ./generate_logical_topo.sh ${numNodes}
        [ -f "$systemFile" ] || ./generate_system.sh ${endpointDelay} ${algo}

        # --- Workload ---
        cd "${genWorkloadDir}" || exit 4
        ./generate_allgather.sh ${workloadBytes} ${numNodes} ${operation}

        # --- Verification ---
        echo ""
        echo "Verifying files..."
        echo ""
        missing=0
        for file in \
          "${topoDir}/${topoFile}" \
          "${topoDir}/${reconfigFile}" \
          "${configDir}/${configFile}" \
          "${systemDir}/${logicalTopoFile}" \
          "${systemDir}/${systemFile}" \
          "${genWorkloadDir}/${workloadFile}.0.et"; do
            [ -f "$file" ] && echo "[OK] $file" || { echo "[MISSING] $file"; missing=1; }
        done
        [ "$missing" -eq 1 ] && echo "!! Missing files, skipping run." && continue

        # --- Run simulation ---
        cd "${buildDir}" || exit 6
        echo "Running Simulation..."
        echo "Start time: $(date)"
        if [ "$log" -eq 0 ]; then
          ./build_with_files.sh \
            --workload "${genWorkloadDir}/${workloadFile}" \
            --logical-topology "${systemDir}/${logicalTopoFile}" \
            --network "${configDir}/${configFile}" \
            --system "${systemDir}/${systemFile}" \
            ${cmd}
        else
          ./build_with_files.sh \
            --workload "${genWorkloadDir}/${workloadFile}" \
            --logical-topology "${systemDir}/${logicalTopoFile}" \
            --network "${configDir}/${configFile}" \
            --system "${systemDir}/${systemFile}" \
            ${cmd} > "${logName}" 2>&1
        fi
        echo "End time: $(date)"
        echo ""

        # --- Archive results ---
        cd "${generalOutputDir}" || exit 7
        mkdir -p "${thisOutputDir}"
        [ -f fct.txt ] && mv fct.txt "${thisOutputDir}/${fctName}" || { echo "Missing fct.txt"; continue; }
        [ "$log" -eq 1 ] && mv "${buildDir}/${logName}" "${thisOutputDir}/logs/${logName}"

        echo ""
        echo "=== Done: ${schedule} | ${numNodes} | ${bandwidthStr} | ${propDelay} | ${workloadBytes}B ==="
        echo ""

      done
    done
  done
done
done
done
