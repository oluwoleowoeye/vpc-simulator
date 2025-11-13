#!/bin/bash
# vpcctl.sh - Comprehensive CLI for all VPC, Peering, Security Group, and NAT requirements.
# Note: This script requires 'jq' and must be run with 'sudo'.

# --- Configuration Variables ---
POLICY_FILE="vpc_security_policies.json"
VPC_NAME_DEFAULT="vpc0"
VPC_CIDR_DEFAULT="10.0.0.0/16"
VPC_ROUTER_IP_DEFAULT="10.0.0.1/16"
EXTERNAL_IFACE="eth0"  # Change this to your internet-facing interface

# Stop execution if any command fails
set -e

# --- Setup and Logging Functions ---

LOG_FILE="./vpcctl.log"

function log_activity() {
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    local activity="$1"
    echo "[$timestamp] $activity" | tee -a "$LOG_FILE"
}

# Clear log on script start
> "$LOG_FILE"
log_activity "START: vpcctl tool initialization (Full Requirements Mode)."

# Ensure we have root privileges
if [ "$(id -u)" -ne 0 ]; then
    echo "❌ This script must be run with sudo or as root."
    exit 1
fi

# --------------------------------------------------------------------------
# --- Core Networking Functions ---
# --------------------------------------------------------------------------

# Function to check if VPC bridge exists
function vpc_exists() {
    local vpc_name=$1
    ip link show dev "$vpc_name" > /dev/null 2>&1
}

# Function to check if subnet namespace exists
function subnet_exists() {
    local subnet_name=$1
    ip netns show | grep -q "^$subnet_name$"
}

# Function to check if VPC peering exists
function peering_exists() {
    local vpc_a=$1
    local vpc_b=$2
    ip link show dev "${vpc_a}-to-${vpc_b}" > /dev/null 2>&1 || ip link show dev "${vpc_b}-to-${vpc_a}" > /dev/null 2>&1
}

# Function to create the VPC (Linux Bridge and Router IP) - IDEMPOTENT
function create_vpc() {
    local vpc_name=$1
    local vpc_router_ip=$2
    local vpc_cidr=$3

    # Check if VPC already exists
    if vpc_exists "$vpc_name"; then
        echo "✅ VPC **$vpc_name** already exists."
        log_activity "INFO: VPC $vpc_name already exists, skipping creation."
        return 0
    fi

    log_activity "ACTION: Creating VPC router $vpc_name ($vpc_router_ip) with CIDR $vpc_cidr."
    echo "➡️ Creating VPC Router: **$vpc_name** with IP **$vpc_router_ip**"

    if ! brctl addbr "$vpc_name"; then
        echo "❌ Error: Could not create bridge $vpc_name."
        return 1
    fi

    ip addr add "$vpc_router_ip" dev "$vpc_name"
    ip link set dev "$vpc_name" up
    
    # Enable IP forwarding and disable RPF (Reverse Path Filtering - Critical for internal routing)
    echo 1 > /proc/sys/net/ipv4/ip_forward
    sudo sysctl -w net.ipv4.conf.all.rp_filter=0
    
    # Set default FORWARD policy to DROP (Enforce security by default)
    sudo iptables -P FORWARD DROP 
    
    log_activity "SUCCESS: VPC creation complete. RPF disabled. FORWARD policy is DROP."
    echo "✅ VPC **$vpc_name** created and restrictive routing policy enabled."
    return 0
}

# Function to enable NAT for a VPC (Internet Gateway simulation) - IDEMPOTENT
function enable_nat() {
    local vpc_name=$1
    local vpc_cidr=$2
    
    log_activity "ACTION: Enabling NAT for VPC $vpc_name ($vpc_cidr) via $EXTERNAL_IFACE."
    echo "➡️ Enabling NAT for **$vpc_name** via **$EXTERNAL_IFACE**"

    # Check if NAT rule already exists
    if ! iptables -t nat -C POSTROUTING -s "$vpc_cidr" -o "$EXTERNAL_IFACE" -j MASQUERADE 2>/dev/null; then
        # 1. Apply the MASQUERADE rule 
        sudo iptables -t nat -A POSTROUTING -s "$vpc_cidr" -o "$EXTERNAL_IFACE" -j MASQUERADE
        log_activity "SUCCESS: MASQUERADE NAT rule added for $vpc_cidr."
    else
        log_activity "INFO: MASQUERADE NAT rule for $vpc_cidr already exists."
    fi

    # Check and add forward rules if they don't exist
    if ! iptables -C FORWARD -i "$vpc_name" -o "$EXTERNAL_IFACE" -j ACCEPT 2>/dev/null; then
        sudo iptables -A FORWARD -i "$vpc_name" -o "$EXTERNAL_IFACE" -j ACCEPT
    fi

    if ! iptables -C FORWARD -i "$EXTERNAL_IFACE" -o "$vpc_name" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; then
        sudo iptables -A FORWARD -i "$EXTERNAL_IFACE" -o "$vpc_name" -m state --state RELATED,ESTABLISHED -j ACCEPT
    fi
    
    log_activity "SUCCESS: NAT enabled for VPC $vpc_name via $EXTERNAL_IFACE."
    echo "✅ NAT enabled for **$vpc_name**. Public subnets can now access internet."
    return 0
}

# Function to apply JSON-based security policy - IDEMPOTENT
function apply_security_policy() {
    local subnet_name=$1

    echo "➡️ Applying Security Group policy for **$subnet_name**..."
    log_activity "SECURITY: Applying policy for $subnet_name from $POLICY_FILE."
    
    local policy_json=$(jq --arg name "$subnet_name" '.[] | select(.name == $name)' "$POLICY_FILE")

    if [ -z "$policy_json" ]; then
        echo "❌ Warning: No security policy found for $subnet_name."
        log_activity "WARNING: No security policy found for $subnet_name."
        return 0
    fi

    # Clear existing rules first to ensure idempotency
    ip netns exec "$subnet_name" iptables -F INPUT
    ip netns exec "$subnet_name" iptables -F OUTPUT

    # 2. Process Ingress Rules (INPUT chain)
    echo "$policy_json" | jq -c '.ingress[]' | while read rule; do
        
        local port=$(echo "$rule" | jq -r '.port'); local protocol=$(echo "$rule" | jq -r '.protocol')
        local source=$(echo "$rule" | jq -r '.source // "0.0.0.0/0"'); local action_raw=$(echo "$rule" | jq -r '.action | ascii_upcase')

        # Translate ALLOW/DENY to ACCEPT/DROP
        if [ "$action_raw" == "ALLOW" ]; then local action="ACCEPT";
        elif [ "$action_raw" == "DENY" ]; then local action="DROP";
        else local action="DROP"; fi
        
        local cmd="ip netns exec $subnet_name iptables -A INPUT -p $protocol -s $source -j $action"

        if [ "$port" != "all" ]; then cmd="$cmd --dport $port"; fi

        log_activity "RULE-INGRESS: Executing $cmd"; $cmd
        
    done 

    # 3. Process Egress Rules (OUTPUT chain)
    echo "$policy_json" | jq -c '.egress[]' | while read rule; do
        
        local port=$(echo "$rule" | jq -r '.port'); local protocol=$(echo "$rule" | jq -r '.protocol')
        local destination=$(echo "$rule" | jq -r '.destination // "0.0.0.0/0"'); local action_raw=$(echo "$rule" | jq -r '.action | ascii_upcase')

        # Translate ALLOW/DENY to ACCEPT/DROP
        if [ "$action_raw" == "ALLOW" ]; then local action="ACCEPT";
        elif [ "$action_raw" == "DENY" ]; then local action="DROP";
        else local action="DROP"; fi

        local cmd="ip netns exec $subnet_name iptables -A OUTPUT -p $protocol -d $destination -j $action"

        if [ "$port" != "all" ]; then cmd="$cmd --dport $port"; fi

        log_activity "RULE-EGRESS: Executing $cmd"; $cmd
        
    done 
    echo "✅ Security policy applied successfully."
}

# Function to add a subnet (Network Namespace) - IDEMPOTENT
function add_subnet() {
    local subnet_name=$1; local subnet_cidr=$2; local status=$3; local vpc_name=$4
    
    # Check if subnet already exists
    if subnet_exists "$subnet_name"; then
        echo "✅ Subnet **$subnet_name** already exists."
        log_activity "INFO: Subnet $subnet_name already exists, reapplying configuration."
        
        # Reapply security policy on existing subnet
        apply_security_policy "$subnet_name"
        return 0
    fi

    # Check if VPC exists
    if ! vpc_exists "$vpc_name"; then
        echo "❌ Error: VPC $vpc_name does not exist. Create it first."
        return 1
    fi

    log_activity "ACTION: Adding subnet $subnet_name ($subnet_cidr) under $vpc_name with status $status."
    
    local gateway_ip=$(echo $subnet_cidr | awk -F'.' '{print $1"."$2"."$3".1"}')
    local namespace_ip=$(echo $subnet_cidr | awk -F'.' '{print $1"."$2"."$3".10"}')  # Use .10 to avoid IP conflicts
    local cidr_mask=$(echo $subnet_cidr | cut -d'/' -f2)
    #local short_name=$(echo "$subnet_name" | awk -F'_' '{print $1}' | cut -c1-4)
    #local ns_veth="ns-${short_name}"; local vpc_veth="${vpc_name}-${short_name}" 
    local ns_veth="ns-$(echo $subnet_name | cut -d'_' -f1)"
    local vpc_veth="${vpc_name}-$(echo $subnet_name | cut -d'_' -f1)"
    echo "➡️ Adding Subnet: **$subnet_name** (**$subnet_cidr**) under **$vpc_name** as **$status**"
    
    # 1. Create the Network Namespace and set DROP policies
    ip netns add "$subnet_name"
    ip netns exec "$subnet_name" iptables -P INPUT DROP
    ip netns exec "$subnet_name" iptables -P OUTPUT DROP
    log_activity "SECURITY: Default IPTables policies for $subnet_name set to DROP (Deny by default)."

    # 2. VETH Setup
    ip link add name "$vpc_veth" type veth peer name "$ns_veth"
    brctl addif "$vpc_name" "$vpc_veth"; ip link set "$vpc_veth" up
    ip link set "$ns_veth" netns "$subnet_name"
    
    # 3. Configure NS Interfaces and Routing
    ip netns exec "$subnet_name" ip link set dev lo up
    ip netns exec "$subnet_name" ip link set dev "$ns_veth" up
    ip netns exec "$subnet_name" ip addr add "$namespace_ip/$cidr_mask" dev "$ns_veth"
    ip netns exec "$subnet_name" ip route add default via "$gateway_ip" dev "$ns_veth"

    # 4. Add gateway IP to bridge (avoid conflicts by checking first)
    if ! ip addr show dev "$vpc_name" | grep -q "$gateway_ip/$cidr_mask"; then
        ip addr add "$gateway_ip/$cidr_mask" dev "$vpc_name"
    fi

    # 5. Apply Security Policy from JSON
    apply_security_policy "$subnet_name"

    # 6. Configure subnet based on status (public/private)
#    if [ "$status" == "public" ]; then
#        echo "    - Configuring as **PUBLIC** subnet with internet access."
        # Public subnets get internet access via NAT
#        local subnet_cidr_full="$gateway_ip/$cidr_mask"
#        if ! iptables -C FORWARD -s "$subnet_cidr_full" -j ACCEPT 2>/dev/null; then
#            sudo iptables -A FORWARD -s "$subnet_cidr_full" -j ACCEPT
#        fi
#        log_activity "CONFIG: Subnet $subnet_name configured as PUBLIC with internet access."

    if [ "$status" == "public" ]; then
        echo "    - Configuring as **PUBLIC** subnet with internet access."
    # Public subnets get internet access via NAT (rules already in NAT function)
    # No additional FORWARD rules needed here
        log_activity "CONFIG: Subnet $subnet_name configured as PUBLIC with internet access."        
#    elif [ "$status" == "private" ]; then
#        echo "    - Configuring as **PRIVATE** subnet (internal-only)."
        # Private subnets remain isolated
        log_activity "CONFIG: Subnet $subnet_name configured as PRIVATE (internal-only)."
#    fi

#    log_activity "SUCCESS: Subnet $subnet_name creation complete."
#    echo "✅ Subnet **$subnet_name** added as $status."
     elif [ "$status" == "private" ]; then
         echo "    - Configuring as **PRIVATE** subnet (internal-only)."
    # Private subnets can only communicate within VPC
         local subnet_network=$(echo $subnet_cidr | cut -d'/' -f1 | awk -F'.' '{print $1"."$2"."$3".0"}')
         local subnet_cidr_full="$subnet_network/$cidr_mask"
    
    # Allow communication within the VPC (10.0.0.0/16)
         sudo iptables -A FORWARD -s "$subnet_cidr_full" -d 10.0.0.0/16 -j ACCEPT
         sudo iptables -A FORWARD -d "$subnet_cidr_full" -s 10.0.0.0/16 -j ACCEPT
    
    # Explicitly block internet access
         sudo iptables -A FORWARD -s "$subnet_cidr_full" -o eth0 -j DROP
         log_activity "CONFIG: Subnet $subnet_name configured as PRIVATE (internal-only)."
      fi
    return 0
}

# Function for VPC Peering (Inter-VPC Communication) - IDEMPOTENT
function peer_vpcs() {
    local vpc_a=$1; local vpc_a_cidr=$2
    local vpc_b=$3; local vpc_b_cidr=$4
    
    # Check if peering already exists
    if peering_exists "$vpc_a" "$vpc_b"; then
        echo "✅ Peering between **$vpc_a** and **$vpc_b** already exists."
        log_activity "INFO: Peering between $vpc_a and $vpc_b already exists."
        return 0
    fi

    # Check if both VPCs exist
    if ! vpc_exists "$vpc_a"; then
        echo "❌ Error: VPC $vpc_a does not exist."
        return 1
    fi
    if ! vpc_exists "$vpc_b"; then
        echo "❌ Error: VPC $vpc_b does not exist."
        return 1
    fi

    local veth_a="${vpc_a}-to-${vpc_b}"; local veth_b="${vpc_b}-to-${vpc_a}"

    echo "➡️ Establishing Peering between **$vpc_a** and **$vpc_b**"
    log_activity "ACTION: Setting up VPC Peering between $vpc_a ($vpc_a_cidr) and $vpc_b ($vpc_b_cidr)."

    # 1. Create the VETH pair
    ip link add name "$veth_a" type veth peer name "$veth_b"

    # 2. Connect each end to its respective VPC bridge
    brctl addif "$vpc_a" "$veth_a"; brctl addif "$vpc_b" "$veth_b"
    ip link set "$veth_a" up; ip link set "$veth_b" up

    # 3. Add static routes (IDEMPOTENT - remove existing routes first)
    echo "    - Configuring static routes..."
    log_activity "ROUTING: Configuring static routes for peering."
    
    # Remove any existing routes for these CIDRs
    ip route show | grep "$vpc_b_cidr" | while read route; do
        sudo ip route del $vpc_b_cidr 2>/dev/null || true
    done
    ip route show | grep "$vpc_a_cidr" | while read route; do
        sudo ip route del $vpc_a_cidr 2>/dev/null || true
    done
    
    # Add the explicit peering routes using the VETH interfaces
    sudo ip route add "$vpc_b_cidr" dev "$veth_a"
    sudo ip route add "$vpc_a_cidr" dev "$veth_b"

    # 4. Remove any existing peering rules to ensure clean state
    remove_peering_rules "$vpc_a_cidr" "$vpc_b_cidr"

    # 5. Implement Security Filtering
    # Rule 1: Allow RELATED/ESTABLISHED traffic back across the peer.
    sudo iptables -A FORWARD -i "$veth_a" -o "$veth_b" -m state --state RELATED,ESTABLISHED -j ACCEPT
    sudo iptables -A FORWARD -i "$veth_b" -o "$veth_a" -m state --state RELATED,ESTABLISHED -j ACCEPT

    # Rule 2: Allow ICMP for connectivity testing
    sudo iptables -A FORWARD -s "$vpc_a_cidr" -d "$vpc_b_cidr" -p icmp -j ACCEPT
    sudo iptables -A FORWARD -s "$vpc_b_cidr" -d "$vpc_a_cidr" -p icmp -j ACCEPT

    # Rule 3: Default DROP for other traffic (configurable)
    sudo iptables -A FORWARD -s "$vpc_a_cidr" -d "$vpc_b_cidr" -j DROP
    sudo iptables -A FORWARD -s "$vpc_b_cidr" -d "$vpc_a_cidr" -j DROP
    
    log_activity "SUCCESS: VPC Peering established between $vpc_a and $vpc_b."
    echo "✅ Peering established. ICMP allowed for testing, other traffic blocked."
}

# Helper function to remove existing peering rules
function remove_peering_rules() {
    local cidr_a=$1
    local cidr_b=$2
    
    # Remove existing forward rules for these CIDRs
    while sudo iptables -C FORWARD -s "$cidr_a" -d "$cidr_b" -j ACCEPT 2>/dev/null; do
        sudo iptables -D FORWARD -s "$cidr_a" -d "$cidr_b" -j ACCEPT
    done
    while sudo iptables -C FORWARD -s "$cidr_b" -d "$cidr_a" -j ACCEPT 2>/dev/null; do
        sudo iptables -D FORWARD -s "$cidr_b" -d "$cidr_a" -j ACCEPT
    done
    while sudo iptables -C FORWARD -s "$cidr_a" -d "$cidr_b" -j DROP 2>/dev/null; do
        sudo iptables -D FORWARD -s "$cidr_a" -d "$cidr_b" -j DROP
    done
    while sudo iptables -C FORWARD -s "$cidr_b" -d "$cidr_a" -j DROP 2>/dev/null; do
        sudo iptables -D FORWARD -s "$cidr_b" -d "$cidr_a" -j DROP
    done
}

# Function to test connectivity from a subnet to the VPC Router
function test_connectivity() {
    local subnet_name=$1
    local target_ip=$2

    if [ -z "$target_ip" ]; then
        # Use the gateway IP for this subnet
        local gateway_ip=$(sudo ip netns exec "$subnet_name" ip route show default | awk '{print $3}')
        target_ip="$gateway_ip"
    fi

    echo "--- **Testing Connectivity from $subnet_name to $target_ip** ---"
    if ip netns exec "$subnet_name" ping -c 3 "$target_ip" > /dev/null 2>&1; then
        echo "✅ Ping successful. Subnet connected to target."
    else
        echo "❌ Ping failed. Check firewall and routing configuration."
        return 1
    fi
}

# Function to test internet connectivity from a subnet
function test_internet_connectivity() {
    local subnet_name=$1
    local test_host="8.8.8.8"  # Google DNS

    echo "--- **Testing Internet Connectivity from $subnet_name** ---"
    if ip netns exec "$subnet_name" ping -c 3 "$test_host" > /dev/null 2>&1; then
        echo "✅ Internet connectivity successful. Subnet has outbound access."
    else
        echo "❌ Internet connectivity failed. Check NAT configuration."
        return 1
    fi
}

# Function to test connectivity between two subnets
function test_subnet_to_subnet() {
    local source_ns=$1
    local dest_ns=$2

    # Get the IP of the destination namespace
    local dest_ip=$(sudo ip netns exec "$dest_ns" ip addr show | grep -oP 'inet \K10\.[0-9.]+' | head -1)

    echo "--- **Testing Inter-Subnet Connectivity: $source_ns -> $dest_ns ($dest_ip)** ---"
    if ip netns exec "$source_ns" ping -c 3 "$dest_ip" > /dev/null 2>&1; then
        echo "✅ Inter-subnet ping successful."
    else
        echo "❌ Inter-subnet ping failed. Check routing and security policies."
        return 1
    fi
}

# Function to clean up the entire VPC environment (Teardown) - IDEMPOTENT
function clean() {
    log_activity "ACTION: Initiating cleanup of VPC environment."
    echo "➡️ Cleaning up all VPCs and subnets..."

    # 1. Bring down and delete all VPC bridges
    for vpc in $(ip link show | grep -oP 'vpc\d+' | sort -u); do
        if ip link show dev "$vpc" > /dev/null 2>&1; then
            ip link set dev "$vpc" down 2>/dev/null || true
            brctl delbr "$vpc" 2>/dev/null || true
            log_activity "DELETION: Bridge $vpc deleted."
        fi
    done

    # 2. Remove all network namespaces
    for ns in $(ip netns list | awk '{print $1}'); do
        ip netns del "$ns" 2>/dev/null || true
        log_activity "DELETION: Namespace $ns deleted."
    done
    
    # 3. Clean up any orphaned VETH pairs
    for veth in $(ip link show | grep -oE '(vpc[^-]*-to-[^-]*|ns-[^:@]*)' | sort -u); do
        if ip link show "$veth" > /dev/null 2>&1; then
            ip link delete "$veth" 2>/dev/null || true
        fi
    done

    # 4. Flush all specific iptables rules (NAT and FORWARD)
    sudo iptables -t nat -F 2>/dev/null || true
    sudo iptables -F FORWARD 2>/dev/null || true
    
    # 5. Reset FORWARD policy to ACCEPT and restore RPF
    sudo iptables -P FORWARD ACCEPT 2>/dev/null || true
    sudo sysctl -w net.ipv4.conf.all.rp_filter=1 2>/dev/null || true

    # 6. Clean up any remaining routes
    for route in $(ip route show | grep -E "10\.0\.0\.0/16|10\.10\.0\.0/16" | awk '{print $1}'); do
        sudo ip route del "$route" 2>/dev/null || true
    done

    log_activity "SUCCESS: Cleanup complete."
    echo "✅ Cleanup complete."
}

# --------------------------------------------------------------------------
# --- Main Logic / CLI Interface ---
# --------------------------------------------------------------------------

case "$1" in
    create)
        if [ "$2" == "vpc" ] && [ ! -z "$3" ] && [ ! -z "$4" ] && [ ! -z "$5" ]; then
            create_vpc "$3" "$4" "$5"
        elif [ "$2" == "vpc" ]; then
            create_vpc "$VPC_NAME_DEFAULT" "$VPC_ROUTER_IP_DEFAULT" "$VPC_CIDR_DEFAULT"
        else
            echo "Usage: sudo ./vpcctl.sh create vpc <name> <router_ip/mask> <cidr>"
        fi
        ;;
        
    add)
        if [ "$2" == "subnet" ] && [ ! -z "$3" ] && [ ! -z "$4" ] && [ ! -z "$5" ] && [ ! -z "$6" ]; then
            if [ "$5" == "public" ] || [ "$5" == "private" ]; then
                add_subnet "$3" "$4" "$5" "$6"
            else
                echo "❌ Status must be 'public' or 'private'."
                echo "Usage: sudo ./vpcctl.sh add subnet <name> <cidr> <status> <vpc_name>"
            fi
        else
            echo "Usage: sudo ./vpcctl.sh add subnet <name> <cidr> <status> <vpc_name>"
        fi
        ;;

    enable)
        if [ "$2" == "nat" ] && [ ! -z "$3" ] && [ ! -z "$4" ]; then
            enable_nat "$3" "$4"
        elif [ "$2" == "nat" ]; then
            enable_nat "$VPC_NAME_DEFAULT" "$VPC_CIDR_DEFAULT"
        else
            echo "Usage: sudo ./vpcctl.sh enable nat [<vpc_name> <vpc_cidr>]"
        fi
        ;;

    peer)
        if [ "$2" == "vpcs" ] && [ ! -z "$3" ] && [ ! -z "$4" ] && [ ! -z "$5" ] && [ ! -z "$6" ]; then
            peer_vpcs "$3" "$4" "$5" "$6"
        else
            echo "Usage: sudo ./vpcctl.sh peer vpcs <vpc_a_name> <vpc_a_cidr> <vpc_b_name> <vpc_b_cidr>"
        fi
        ;;
        
    test)
        if [ "$2" == "subnet" ] && [ ! -z "$3" ]; then
            test_connectivity "$3"
        elif [ "$2" == "internet" ] && [ ! -z "$3" ]; then
            test_internet_connectivity "$3"
        elif [ "$2" == "subnet_to_subnet" ] && [ ! -z "$3" ] && [ ! -z "$4" ]; then
            test_subnet_to_subnet "$3" "$4"
        else
            echo "Usage: sudo ./vpcctl.sh test subnet <subnet_name>"
            echo "       sudo ./vpcctl.sh test internet <subnet_name>"
            echo "       sudo ./vpcctl.sh test subnet_to_subnet <source_ns> <dest_ns>"
        fi
        ;;

    clean)
        clean
        ;;

    *)
        echo "Usage: sudo ./vpcctl.sh <command>"
        echo "Commands:"
        echo "  create vpc [<name> <router_ip/mask> <cidr>]"
        echo "  add subnet <name> <cidr> <status> <vpc_name>"
        echo "  enable nat [<vpc_name> <vpc_cidr>]"
        echo "  peer vpcs <vpc_a_name> <vpc_a_cidr> <vpc_b_name> <vpc_b_cidr>"
        echo "  test subnet <subnet_name>"
        echo "  test internet <subnet_name>"
        echo "  test subnet_to_subnet <source_ns> <dest_ns>"
        echo "  clean"
        ;;
esac
