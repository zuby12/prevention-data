#!/bin/bash
# 
set -euo pipefail

# Commands
# ./setup.sh cleanup        - This will clean up all nodes, remove all capture files etc.
# ./setup.sh restore "131.170.68.137"       - This will restore the ports on the attacked node.
# ./setup.sh                - This will run the complete script, including the attack on 137 node.

GETHHOME=~/geth
GETHPROJ=~/geth_project
NODECHECK=~/geth_project/nodecheck
OUTPUT_DIR=~/geth_project/output
timeout_opts="--signal=TERM --kill-after=15s"
#dummy
captures=$OUTPUT_DIR/captures
# mkdir -p $GETHHOME
#OLDKEY=a7a5effa521e21b9a1c93009dfe47699014bc05aed222efc2f3e9bd50357ecbe4867666df9fcd145dc8ebcd8c574b7598c9287795466307c2f5ee6f5c716f9d4
ENKEY=391363071e3e65a4fe82cfc77050b8b7ec05e0dceecda2d8e4c684b313c9e9b34277a443ff4c78053b63a253f1091eaf7a8429afb750c8949f72f8a32018c8ef

ACCOUNT="0xB9475142b47d0DDeA65a6b5734C3e5Da2ea65Db4"
TO_ACCOUNT="0x7F28C17E10fC04a63D52E4064290740253Fbb566"
BLOCK="latest"
# ATTACHPARAMETER="rpc:http://192.168.50.135:8545"
# ATTACHPARAMETER2="http://192.168.50.135:8546"
ATTACHPARAMETER="rpc:http://131.170.68.135:8545"
ATTACHPARAMETER2="http://131.170.68.135:8546"
echo "Work1234" > $GETHPROJ/password.txt

declare -A ip_map

# Add IP mappings
extip="131.170.68.135"
netrestrict="131.170.0.0/16"

# ip_map["131.170.68.135"]="192.168.50.135"
# ip_map["131.170.68.136"]="192.168.51.136"
# ip_map["131.170.68.137"]="192.168.52.137"
# ip_map["131.170.68.138"]="192.168.53.138"
ip_map["131.170.68.135"]="131.170.68.135"
ip_map["131.170.68.136"]="131.170.68.136"
ip_map["131.170.68.137"]="131.170.68.137"
ip_map["131.170.68.138"]="131.170.68.138"
# ip_map["131.170.68.135"]=$(host eth1f.neteng.local | cut -f4 -d' ')
# ip_map["131.170.68.136"]=$(host eth2f.neteng.local | cut -f4 -d' ')
# ip_map["131.170.68.137"]=$(host eth3f.neteng.local | cut -f4 -d' ')
# ip_map["131.170.68.138"]=$(host eth4f.neteng.local | cut -f4 -d' ')


cat <<EOF > $GETHHOME/genesis.json
{
  "config": {
    "chainId": 12345,
    "homesteadBlock": 0,
    "eip150Block": 0,
    "eip155Block": 0,
    "eip158Block": 0,
    "byzantiumBlock": 0,
    "constantinopleBlock": 0,
    "petersburgBlock": 0,
    "istanbulBlock": 0,
    "berlinBlock": 0,
    "clique": {
      "period": 5,
      "epoch": 30000
    }
  },
  "difficulty": "1",
  "gasLimit": "8000000",
  "extradata": "0x0000000000000000000000000000000000000000000000000000000000000000B9475142b47d0DDeA65a6b5734C3e5Da2ea65Db47F28C17E10fC04a63D52E4064290740253Fbb56600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
  "alloc": {
    "B9475142b47d0DDeA65a6b5734C3e5Da2ea65Db4": { "balance": "300000000000000000000000" },
    "7F28C17E10fC04a63D52E4064290740253Fbb566": { "balance": "400000000000000000000000" }
  }
}
EOF

run_geth() {
    local ip=$1
    local iter=$2
    local bootip=$3
    echo "Source===>CMD: ssh -q -t -o IdentitiesOnly=yes -i ~/.ssh/id_ed25519 phdadmin@$ip <<EOF
nohup timeout $timeout_opts $timeout geth --datadir ${GETHPROJ}/data --nat=extip:${ip_map["$ip"]} --networkid 12345 --port 30303 --http --http.addr $ip --http.corsdomain '*' --http.vhosts '*' --http.api admin,eth,miner,net,txpool,personal,web3 --allow-insecure-unlock --bootnodes enode://${ENKEY}@$bootip:30303 --netrestrict $netrestrict >> ${OUTPUT_DIR}/output.txt 2>&1 &
" >>  ${OUTPUT_DIR}/output.txt

    ssh -q -t -o IdentitiesOnly=yes -i ~/.ssh/id_ed25519 phdadmin@$ip <<EOF
echo "_________ Running $iter of geth __________" >> ${OUTPUT_DIR}/output.txt
echo "CMD: nohup timeout $timeout_opts $timeout geth --datadir ${GETHPROJ}/data --nat=extip:${ip_map["$ip"]} --networkid 12345 --port 30303 --http --http.addr $ip --http.corsdomain '*' --http.vhosts '*' --http.api admin,eth,miner,net,txpool,personal,web3 --allow-insecure-unlock --bootnodes enode://${ENKEY}@$bootip:30303 --netrestrict $netrestrict" >> ${OUTPUT_DIR}/output.txt
nohup timeout $timeout_opts $timeout geth --datadir ${GETHPROJ}/data --nat=extip:${ip_map["$ip"]} --networkid 12345 --port 30303 --http --http.addr $ip --http.corsdomain '*' --http.vhosts '*' --http.api admin,eth,miner,net,txpool,personal,web3 --allow-insecure-unlock --bootnodes enode://${ENKEY}@$bootip:30303 --netrestrict $netrestrict >> ${OUTPUT_DIR}/output.txt 2>&1 &
nohup python3 $NODECHECK/../capture.py $timeout ${OUTPUT_DIR} $iter &
nohup timeout $timeout_opts $timeout make -C $GETHPROJ/eth-guard run1 &


EOF

# nohup python3 $NODECHECK/trust_node.py --timeout=$timeout --iteration=$iter > ${OUTPUT_DIR}/trust_node.log 2>&1 &
}

run_attack() {
    local ip=$1
    local target=$2

    # block ports on the target machine i.e. 137
    ssh -q -t -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -i ~/.ssh/id_ed25519 "phdadmin@$target" <<EOF
set -e
sudo -n ufw --force enable >/dev/null 2>&1 || true
sudo -n ufw deny in  proto tcp to any port 30303 >/dev/null 2>&1 || true
sudo -n ufw deny in  proto udp to any port 30303 >/dev/null 2>&1 || true
sudo -n ufw deny out proto tcp to any port 30303 >/dev/null 2>&1 || true
sudo -n ufw deny out proto udp to any port 30303 >/dev/null 2>&1 || true
sudo -n ufw reload >/dev/null 2>&1 || true
EOF

# run the attach script on 139.
ssh -q -t -o IdentitiesOnly=yes -i ~/.ssh/id_ed25519 phdadmin@$ip <<EOF
nohup python3 $GETHPROJ/hulk.py $target > /dev/null 2>&1 &
EOF

ssh -q -t -o IdentitiesOnly=yes -i ~/.ssh/id_ed25519 phdadmin@$ip <<EOF
nohup python3 $GETHPROJ/lgtda_attacker.py --rpc http://$target:8546 --chain-id 12345 \
    --keys $GETHPROJ/keys.txt --tps 400 --duration $timeout --data-bytes 120000 --mode eoatx
EOF

# ssh -q -o IdentitiesOnly=yes -i ~/.ssh/id_ed25519 administrator@131.170.68.236 <<EOF
# cd /home/administrator; nohup ./rotate_firewall_ip_ethALL.sh >/dev/null 2>&1 &
# EOF

}

restore_ports() {
  local target="$1"
  ssh -q -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -i ~/.ssh/id_ed25519 "phdadmin@$target" bash -s <<'EOF'
set -e
sudo -n ufw --force enable >/dev/null 2>&1 || true

# Keep deleting only DENY rules for 30303 (v4/v6, IN/OUT), refreshing after each delete
while true; do
  num="$(sudo -n ufw status numbered \
          | awk '/30303/ && /DENY/ { gsub(/\[|\]/,"",$1); print $1; exit }')"
  [ -z "$num" ] && break
  sudo -n ufw --force delete "$num"
done

# Re-allow for your /16, both TCP+UDP, IN+OUT
sudo -n ufw allow in  proto tcp to any port 30303
sudo -n ufw allow in  proto udp to any port 30303
sudo -n ufw allow out proto tcp to any port 30303
sudo -n ufw allow out proto udp to any port 30303
sudo -n ufw reload >/dev/null 2>&1 || true

# Show final state for 30303
# sudo -n ufw status | grep -E '30303' || true
EOF
}





run_setup() {
    local ip=$1
for iter in $(seq 1 $iters); do
    clear
    echo "$(date) => running iteration: $iter"
    cd $GETHHOME
    echo "  Run geth on 135"
    echo "" >> ${OUTPUT_DIR}/output.txt
    echo "" >> ${OUTPUT_DIR}/output.txt
    echo "_________ Running $iter of geth __________" >> ${OUTPUT_DIR}/output.txt
    echo "CMD: nohup timeout $timeout_opts  $timeout geth --datadir ${GETHPROJ}/data --nat=extip:${ip_map["$extip"]}  --networkid 12345 \
        --port 30303 --http --http.addr 0.0.0.0 --http.corsdomain '*' \
        --http.vhosts '*' --http.api admin,eth,miner,net,txpool,personal,web3 \
        --allow-insecure-unlock --bootnodes enode://${ENKEY}@$ip:30303 \
        --netrestrict $netrestrict --unlock $ACCOUNT \
        --password $GETHHOME/password.txt --mine \
        --miner.etherbase $ACCOUNT >> ${OUTPUT_DIR}/output.txt"

    nohup timeout $timeout_opts $timeout geth --datadir ${GETHPROJ}/data --nat=extip:${ip_map["$extip"]} --networkid 12345 \
        --port 30303 --http --http.addr 0.0.0.0 --http.corsdomain '*' \
        --http.vhosts '*' --http.api admin,eth,miner,net,txpool,personal,web3 \
        --allow-insecure-unlock --bootnodes enode://${ENKEY}@$ip:30303 \
        --netrestrict $netrestrict --unlock $ACCOUNT \
        --password $GETHHOME/password.txt --mine \
        --miner.etherbase $ACCOUNT >> ${OUTPUT_DIR}/output.txt 2>&1 &

    echo "Run capture.py: nohup python3 $NODECHECK/../capture.py $timeout $captures $iter &"
    nohup python3 $NODECHECK/../capture.py $timeout $captures $iter &

    # echo "Run trust_node.py"
    # nohup python3 $NODECHECK/trust_node.py --timeout=$timeout > ${OUTPUT_DIR}/trust_node.log 2>&1 &
    nohup timeout $timeout_opts $timeout make -C $GETHPROJ/eth-guard run1 &
    # nohup timeout $timeout_opts $timeout make -C $GETHPROJ/eth-guard run-metrics &
    # nohup timeout $timeout_opts $timeout make -C $GETHPROJ/eth-guard run-proxy &
    # nohup timeout $timeout_opts $timeout make -C $GETHPROJ/eth-guard run-proxy-instrumented &
    # nohup timeout $timeout_opts $timeout make -C $GETHPROJ/eth-guard run-mtd-fixed &

    echo "Sleep for 5 sec..."
    sleep 5

    echo "Getting Balance: "
    geth attach $ATTACHPARAMETER <<EOF | grep "Data: " | sed "s/Data: //"
balance=web3.fromWei(eth.getBalance("$ACCOUNT"), "ether");
console.log("Data: '$ACCOUNT' at '$BLOCK' has " + balance + " ETH");
EOF
    

    # if [[ $((iter % 4)) -eq 0 ]]; then
        echo "Sending transaction: "
        python3 $GETHPROJ/send_tx_via_proxy.py "$ACCOUNT" "$TO_ACCOUNT" "$ATTACHPARAMETER2"
#         geth attach $ATTACHPARAMETER <<EOF | grep "Data: " | sed "s/Data: //"
# eth.sendTransaction({from: "$ACCOUNT", to: "$TO_ACCOUNT", value: web3.toWei(100, "ether"), gas: 21000, gasPrice: "20000000000"});
# EOF
    # fi

    echo "  Run on 136"
    run_geth "131.170.68.136" $iter "$ip" &

    echo "  Run on 137"
    run_geth "131.170.68.137" $iter "$ip" &

    echo "  Run on 138"
    run_geth "131.170.68.138" $iter "$ip" &

#    echo "  Run on 138"
#    run_geth "131.170.68.139" $iter "$ip" &

    echo "  Run attack from 139, on 137"
   run_attack "131.170.68.139" "131.170.68.137" &

    if [[ $iter -ne $iters ]]; then
        echo "Wait for next run."
        sleep $((timeout + 60))
    else
        echo "Wait for all background jobs to complete."
        wait # Wait for all background jobs to complete
    fi

# uncomment if needs to restore the attacked node after every iteration.
    restore_ports "131.170.68.137" &

done

    echo "All Done."
    exit
}

cleanUp()
{
    cmd="set +e;
    pkill -9 geth;
    pkill -9 -f trust_node.py;
    pkill -9 -f capture.py;
    pkill -9 -f hulk.py;
    pkill -9 tshark;
    pkill -9 dumpcap;
    pkill -9 uvicorn;
    pkill -9 python3;
    rm -f ${OUTPUT_DIR}/captures/*;
    rm -f $GETHHOME/nohup.out;
    rm -f ${OUTPUT_DIR}/output.txt;
    rm -f ${OUTPUT_DIR}/hulk.txt;
    "

    echo "Clean up 135"
    eval "$cmd"

    echo "Clean up 136"
    ssh -q -t -o IdentitiesOnly=yes -i ~/.ssh/id_ed25519 phdadmin@131.170.68.136 "bash -s" <<< "$cmd"

    
    echo "Clean up 137"
    ssh -q -t -o IdentitiesOnly=yes -i ~/.ssh/id_ed25519 phdadmin@131.170.68.137 "bash -s" <<< "$cmd"
    restore_ports "131.170.68.137"

    echo "Clean up 138"
    ssh -q -t -o IdentitiesOnly=yes -i ~/.ssh/id_ed25519 phdadmin@131.170.68.138 "bash -s" <<< "$cmd"

    echo "Clean up 139"
    ssh -q -t -o IdentitiesOnly=yes -i ~/.ssh/id_ed25519 phdadmin@131.170.68.139 "bash -s" <<< "$cmd"
}

setup_init() {
    cmd=$(cat <<'EOF'
        set +e
        echo "[INFO] Cleaning existing geth data..."
        rm -rf ~/geth/data/geth ~/geth/data/ancient
        echo "[INFO] Initializing with genesis.json..."
        geth --datadir ~/geth/data init ~/geth/genesis.json
EOF
    )

    echo "[Local] Running on 135..."
    eval "$cmd"

    for host in 136 137 138 139; do
        echo "[Remote] Running on 131.170.68.$host..."
        ssh -q -t -o IdentitiesOnly=yes -i ~/.ssh/id_ed25519 "phdadmin@131.170.68.$host" "$cmd"
    done
}

if [[ "$1" = "init" ]]; then
    setup_init
    exit;
fi

if [[ "$1" = "cleanup" ]]; then
    cleanUp
    exit;
fi

if [[ "$1" = "restore" ]]; then
    restore_ports $2
    exit;
fi

if [[ -z "$1" ]]; then
    echo "Iterations not provided!"
    exit 1
fi  

if [[ -z "$2" ]]; then
    echo "Timeout not provided!"
    exit 1
fi

# init vars
iters=$1
ntime=$2 # in minutes
timeout=$((60 * $ntime))

run_setup ${ip_map["131.170.68.135"]}
