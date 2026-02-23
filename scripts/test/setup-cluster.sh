#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CONFIG_FILE="${PROJECT_ROOT}/config/kind/test-cluster.yaml"

echo "======================================"
echo "Kimera Test Cluster Setup"
echo "======================================"

# Check if kind is installed
if ! command -v kind &> /dev/null; then
    echo "Error: kind is not installed"
    echo "Install from: https://kind.sigs.k8s.io/docs/user/quick-start/#installation"
    exit 1
fi

# Check if cluster already exists
if kind get clusters 2>/dev/null | grep -q "^kimera-test$"; then
    echo "Cluster 'kimera-test' already exists"
    read -p "Do you want to delete and recreate it? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Deleting existing cluster..."
        kind delete cluster --name kimera-test
    else
        echo "Using existing cluster"
        kubectl cluster-info --context kind-kimera-test
        exit 0
    fi
fi

# Create the cluster
echo "Creating kind cluster from ${CONFIG_FILE}..."
kind create cluster --config="${CONFIG_FILE}"

# Wait for cluster to be ready
echo "Waiting for cluster to be ready..."
kubectl wait --for=condition=Ready nodes --all --timeout=300s

# Display cluster info
echo ""
echo "======================================"
echo "Cluster created successfully!"
echo "======================================"
kubectl cluster-info --context kind-kimera-test
echo ""
kubectl get nodes
echo ""
echo "To use this cluster:"
echo "  kubectl cluster-info --context kind-kimera-test"
echo ""
echo "To deploy test workloads:"
echo "  ./scripts/test/deploy-vulnerable-app.sh"
