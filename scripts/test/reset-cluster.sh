#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "======================================"
echo "Resetting Kimera Test Cluster"
echo "======================================"

# Check if cluster exists
if ! kind get clusters 2>/dev/null | grep -q "^kimera-test$"; then
    echo "Error: Cluster 'kimera-test' does not exist"
    echo "Run ./scripts/test/setup-cluster.sh first"
    exit 1
fi

# Set context
kubectl config use-context kind-kimera-test

# Delete test namespaces (which deletes all resources)
echo "Deleting test namespaces and all resources..."
kubectl delete namespace test-vulnerable --ignore-not-found=true
kubectl delete namespace test-secure --ignore-not-found=true

# Wait a moment for cleanup
echo "Waiting for cleanup to complete..."
sleep 3

# Redeploy clean workloads
echo ""
echo "Redeploying test workloads..."
"${SCRIPT_DIR}/deploy-vulnerable-app.sh"

echo ""
echo "======================================"
echo "Cluster reset complete!"
echo "======================================"
