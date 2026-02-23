#!/bin/bash
set -e

echo "======================================"
echo "Kimera Test Cluster Teardown"
echo "======================================"

# Check if cluster exists
if ! kind get clusters 2>/dev/null | grep -q "^kimera-test$"; then
    echo "Cluster 'kimera-test' does not exist"
    exit 0
fi

echo "This will delete the 'kimera-test' cluster and all its resources"
read -p "Are you sure? (y/n) " -n 1 -r
echo

if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Deleting cluster..."
    kind delete cluster --name kimera-test
    echo "Cluster deleted successfully"
else
    echo "Teardown cancelled"
    exit 1
fi
