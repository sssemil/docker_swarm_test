#!/bin/bash

set -x

# Stack name (ex. test)
STACK_NAME=$1

# Hosts file path (received as parameter)
HOSTS_FILE_PATH=$2

# Docker Compose file path
DOCKER_COMPOSE_FILE_PATH=$3

# Remote directory to store Docker Compose file
REMOTE_DIR="~/docker"

# Function for ssh command with disabled host key checking
ssh_nohost() {
    ssh -o "StrictHostKeyChecking no" "$@"
}

# Check if Docker Compose file exists
if [ ! -f "$DOCKER_COMPOSE_FILE_PATH" ]; then
    echo "File $DOCKER_COMPOSE_FILE_PATH does not exist."
    exit 1
fi

# Check if hosts file exists
if [ ! -f "$HOSTS_FILE_PATH" ]; then
    echo "File $HOSTS_FILE_PATH does not exist."
    exit 1
fi

# Get the manager node's hostname from the JSON file
MANAGER_NODE=$(jq '.nodes[] | select(.roles[] | contains("manager"))' $HOSTS_FILE_PATH)
SSH_USERNAME=$(echo $MANAGER_NODE | jq -r '.username')
MANAGER_HOSTNAME=$(echo $MANAGER_NODE | jq -r '.hostname')

# Ensure remote directory exists
ssh_nohost "$SSH_USERNAME@$MANAGER_HOSTNAME" "mkdir -p $REMOTE_DIR"

# Copy the Docker Compose file to the manager node
scp -o "StrictHostKeyChecking no" "$DOCKER_COMPOSE_FILE_PATH" "$SSH_USERNAME@$MANAGER_HOSTNAME:$REMOTE_DIR"

# Deploy the stack to the swarm on the manager node
ssh_nohost "$SSH_USERNAME@$MANAGER_HOSTNAME" "docker stack deploy --with-registry-auth --compose-file $REMOTE_DIR/\$(basename $DOCKER_COMPOSE_FILE_PATH) $STACK_NAME"
