#!/bin/bash

set -x

# Function for ssh command with disabled host key checking
ssh_nohost() {
    ssh -o "StrictHostKeyChecking no" "$@"
}

is_swarm_manager() {
    username=$1
    hostname=$2
    output=$(ssh_nohost -n "$username@$hostname" "docker info --format '{{.Swarm.LocalNodeState}}'")
    if [ "$output" = "active" ]; then
        return 0
    else
        return 1
    fi
}

# Function to install Docker & ufw and setup firewall rules
setup_host() {
    username=$1
    hostname=$2

    # Update and install necessary packages
    ssh_nohost -n "$username@$hostname" "sudo apt-get update && \
        sudo apt-get install -y docker.io ufw"

    # Add user to docker group
    ssh_nohost -n "$username@$hostname" "sudo usermod -aG docker $username"

    # Set UFW rules
    ssh_nohost -n "$username@$hostname" "sudo ufw allow 22/tcp && \
        sudo ufw allow 2376/tcp && \
        sudo ufw allow 2377/tcp && \
        sudo ufw allow 7946/tcp && \
        sudo ufw allow 7946/udp && \
        sudo ufw allow 4789/udp && \
        sudo ufw --force enable"

    # Check if Docker rules already exist and if not, add them
    # source: https://github.com/chaifeng/ufw-docker
    check_docker_rules="sudo grep -q '# BEGIN UFW AND DOCKER' /etc/ufw/after.rules"
    if ! ssh_nohost -n "$username@$hostname" "$check_docker_rules"; then
        docker_ufw_rules=$(cat <<EOL
# BEGIN UFW AND DOCKER
*filter
:ufw-user-forward - [0:0]
:ufw-docker-logging-deny - [0:0]
:DOCKER-USER - [0:0]
-A DOCKER-USER -j ufw-user-forward

-A DOCKER-USER -j RETURN -s 10.0.0.0/8
-A DOCKER-USER -j RETURN -s 172.16.0.0/12
-A DOCKER-USER -j RETURN -s 192.168.0.0/16
-A DOCKER-USER -j RETURN -i tailscale0

-A DOCKER-USER -p udp -m udp --sport 53 --dport 1024:65535 -j RETURN

-A DOCKER-USER -j ufw-docker-logging-deny -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -d 192.168.0.0/16
-A DOCKER-USER -j ufw-docker-logging-deny -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -d 10.0.0.0/8
-A DOCKER-USER -j ufw-docker-logging-deny -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -d 172.16.0.0/12
-A DOCKER-USER -j ufw-docker-logging-deny -p udp -m udp --dport 0:32767 -d 192.168.0.0/16
-A DOCKER-USER -j ufw-docker-logging-deny -p udp -m udp --dport 0:32767 -d 10.0.0.0/8
-A DOCKER-USER -j ufw-docker-logging-deny -p udp -m udp --dport 0:32767 -d 172.16.0.0/12

-A DOCKER-USER -j RETURN

-A ufw-docker-logging-deny -m limit --limit 3/min --limit-burst 10 -j LOG --log-prefix "[UFW DOCKER BLOCK] "
-A ufw-docker-logging-deny -j DROP

COMMIT
# END UFW AND DOCKER
EOL
)
        ssh_nohost -n "$username@$hostname" "echo \"$docker_ufw_rules\" | sudo tee -a /etc/ufw/after.rules"
    fi
}

# Function to setup Docker Swarm
setup_swarm() {
    username=$1
    hostname=$2
    public_ipv4=$3
    roles=$4

    echo "Setting up $hostname"
    if [[ "${roles[@]}" =~ "manager" ]]; then
        if is_swarm_manager $username $hostname; then
            read -p "$hostname is already a part of a swarm. Do you want to use this swarm? (y/n) " choice
            case "$choice" in
                y|Y) 
                    # Get the existing token
                    SWARM_TOKEN=$(ssh_nohost -n "$username@$hostname" "docker swarm join-token -q worker")
                    ;;
                n|N)
                    echo "Exiting script."
                    exit 0
                    ;;
                *)
                    echo "Invalid choice. Exiting."
                    exit 1
                    ;;
            esac
        else
            SWARM_TOKEN=$(ssh_nohost -n "$username@$hostname" "docker swarm init --advertise-addr $public_ipv4" | awk -F ' ' '/docker swarm join --token/ {print $5}')
        fi

        echo "Swarm token: $SWARM_TOKEN"
        if [ -z "$SWARM_TOKEN" ]; then
            echo "Swarm token is empty, exiting..."
            exit -1
        fi
    else
        join_output=$(ssh_nohost -n "$username@$hostname" "docker swarm join --advertise-addr $public_ipv4 --token $SWARM_TOKEN ${SWARM_MANAGER#*@}:2377")
    fi

    NODE_ID=$(ssh_nohost -n "$username@$hostname" "docker info --format '{{.Swarm.NodeID}}'")
    echo "Node ID: $NODE_ID"

    for role in "${roles[@]}"; do
        echo "Setting up $hostname as $role host"
        ssh_nohost -n "$SWARM_MANAGER" "docker node update --label-add $role=true $NODE_ID"
    done
}

# Function to install Docker & ufw, setup firewall rules and Docker Swarm on a host
setup() {
    username=$1
    hostname=$2
    public_ipv4=$3
    roles=$4
    echo "Setting up $username@$hostname"
    setup_host $username $hostname
    setup_swarm $username $hostname $public_ipv4 "${roles[@]}"
}

# Main part of the script
HOST_FILE=$1

# Check if host file exists
if [ ! -f "$HOST_FILE" ]; then
    echo "File $HOST_FILE does not exist."
    exit 1
fi

# Read the JSON host file
JSON_CONTENT=$(< "$HOST_FILE")

# Parse the JSON host file
num_nodes=$(echo "$JSON_CONTENT" | jq '.nodes | length')

# Iterate over nodes in the host file
for (( i=0; i<$num_nodes; i++ )); do
    # Get node data
    username=$(echo "$JSON_CONTENT" | jq -r ".nodes[$i].username")
    hostname=$(echo "$JSON_CONTENT" | jq -r ".nodes[$i].hostname")
    public_ipv4=$(echo "$JSON_CONTENT" | jq -r ".nodes[$i].public_ipv4")
    roles=($(echo "$JSON_CONTENT" | jq -r ".nodes[$i].roles[]"))

    # Print node information
    echo "Node info: Username - $username, Hostname - $hostname, Public IPv4 - $public_ipv4, Roles - ${roles[@]}"

    # Set the first host as Swarm manager and setup it synchronously
    if [ -z "$SWARM_MANAGER" ]; then
        SWARM_MANAGER="$username@$hostname"
        setup $username $hostname $public_ipv4 "${roles[@]}"
    else
        # Setup each host in the background to speed up the process
        setup $username $hostname $public_ipv4 "${roles[@]}" &
    fi
done

# Wait for all background processes to finish
wait
