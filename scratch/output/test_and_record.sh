#!/bin/bash

set -e

# Direct connect ring topologies

testIteration="Test_53" # prefix in outputDir

numNodes=16
bandwidthStr="1Gbps"
propDelay="500ns"
workloadBytes="10000"

# cmd is mandatory arg
if [ -z "$1" ]; then
  echo "Usage: $0 <cmd> [--log]"
  exit 1
fi

cmd="$1" # cmd to pass to build script, --run, --debug, --clean 
log=0  # default: logging off

#bool, write simulation output to log
if [ "$2" == "--log" ]; then
  log=1
fi

# input dirs
astraDir="/app/astra-sim"
topoDir="${astraDir}/extern/network_backend/ns-3/scratch/topology"
configDir="${astraDir}/extern/network_backend/ns-3/scratch/config"
systemDir="${astraDir}/examples/ns3"
genWorkloadDir="${astraDir}/examples/text_converter/text_workloads"
generalOutputDir="${astraDir}/extern/network_backend/ns-3/scratch/output"
buildDir="${astraDir}/build/astra_ns3"

# generated input files
topoFile="direct_connect_ring_${numNodes}_nodes_${bandwidthStr}_${propDelay}.json"
reconfigFile="ocs_static_ring_${numNodes}_nodes.json"
configFile="config_ocs_static_${numNodes}_${bandwidthStr}_${propDelay}.txt"
logicalTopoFile="sample_${numNodes}nodes_1D.json"
workloadFile="AllGather${workloadBytes}B_${numNodes}/AllGather${workloadBytes}B_${numNodes}" # used for build script and verification that workload was successfully generated

# outputdirs
thisOutputDir="results"
#thisOutputDir="${testIteration}_ring_${numNodes}n_${workloadBytes}B_${bandwidthStr}_${propDelay}"
logName="${testIteration}_ring_${numNodes}n_${workloadBytes}B_${bandwidthStr}_${propDelay}.log"

# generate topo
cd ${topoDir} || exit 1

if [ ! -f "$topoFile" ]; then
    python generate_direct_connect_ring.py --nodes ${numNodes} --bandwidth ${bandwidthStr} --latency ${propDelay} --output ./${topoFile}
fi

# generate reconfig schedule, we only need to make sure the switchId is the correct OCSNode ID - the rest is not used because it's a direct connect topology
if [ ! -f "$reconfigFile" ]; then
  ./generate_direct_connect_reconfig.sh "$numNodes"
fi

# generate config that references the two above
cd ${configDir} || exit 2

if [ ! -f "$configFile" ]; then
cat > "$configFile" <<EOF
ENABLE_QCN 1
USE_DYNAMIC_PFC_THRESHOLD 1

PACKET_PAYLOAD_SIZE 1000

TOPOLOGY_FILE ../../scratch/topology/${topoFile}
TOPOLOGY_FILE_FORMAT json
RECONFIG_FILE ../../scratch/topology/${reconfigFile}
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
fi

# generate logical topo

cd ${systemDir} || exit 3

if [ ! -f "$logicalTopoFile" ]; then
    ./generate_logical_topo.sh ${numNodes}
fi

# generate workload
cd ${genWorkloadDir} || exit 4
if [ ! -d "AllGather${workloadBytes}B_${numNodes}" ]; then
    ./generate_allgather.sh ${workloadBytes} ${numNodes}
fi


# check that everything we just generated exists
# Final verification
echo ""
echo "Verifying generated files..."
echo ""

missing=0

for file in \
  "${topoDir}/${topoFile}" \
  "${topoDir}/${reconfigFile}" \
  "${configDir}/${configFile}" \
  "${systemDir}/${logicalTopoFile}" \
  "${genWorkloadDir}/${workloadFile}.0.et"
do
  if [ -f "$file" ]; then
    echo "[OK] $file"
  else
    echo "[MISSING] $file"
    missing=1
  fi
done

echo ""

if [ "$missing" -eq 1 ]; then
  echo "!! One or more required files are missing. !!"
  exit 5
else
  echo "All required files successfully generated."
fi


cd ${buildDir} || exit 6
# call build with params and record log

if [ "$log" -eq 0 ]; then
	echo ""
	echo "Running Simulation. Not logging"
	echo ""

	./build_with_files.sh \
	--workload "${genWorkloadDir}/${workloadFile}" \
        --logical-topology "${systemDir}/${logicalTopoFile}" \
        --network "${configDir}/${configFile}" \
        ${cmd}
else
	echo ""
	echo "Running Simulation. Logging to ${generalOutputDir}/${thisOutputDir}/${logName}"
	echo ""
	
	./build_with_files.sh \
        --workload "${genWorkloadDir}/${workloadFile}" \
        --logical-topology "${systemDir}/${logicalTopoFile}" \
        --network "${configDir}/${configFile}" \
        ${cmd} > ${logName} 2>&1
fi

# make result dir
cd $generalOutputDir || exit 7
mkdir -p ${thisOutputDir}

# move fct into result dir 
if [ -f "fct.txt" ]; then
    mv fct.txt ${generalOutputDir}/${thisOutputDir}/"${testIteration}_ring_${numNodes}n_${workloadBytes}B_${bandwidthStr}_${propDelay}_fct.txt"
else
    echo "Error: no fct.txt found"
    exit 8
fi

# copy log into result dir
if [ -f ${buildDir}/${logName} ]; then
    mv ${buildDir}/${logName} ${generalOutputDir}/${thisOutputDir}/logs/${logName}
else
    echo "Error: fct found but no log found"
    exit 9
fi

# run extract max fct python
# cat the contents of result file
