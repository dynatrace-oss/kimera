#!/usr/bin/env bash
# Tear down the kimera lab cluster
set -euo pipefail

CLUSTER_NAME="kimera-lab"

echo "[kimera-lab] Deleting cluster '${CLUSTER_NAME}'..."
kind delete cluster --name "${CLUSTER_NAME}" 2>/dev/null || true
echo "[kimera-lab] Cluster deleted."
