#!/usr/bin/env bash
# ============================================================================
# Kimera Test Cluster Setup
# ============================================================================
# Creates a kind cluster with layered security controls for testing
# validate-control and the full kimera lifecycle.
#
# Components:
#   - kind cluster (3 nodes: 1 control-plane + 2 workers)
#   - Cilium CNI (NetworkPolicy enforcement)
#   - Kyverno (admission controller with baseline policies)
#   - Google Online Boutique (realistic 11-service microservices app)
#   - Intentional security gaps for kimera to discover
#
# Usage:
#   ./scripts/test-cluster/setup.sh          # Full setup
#   ./scripts/test-cluster/setup.sh --quick  # Skip Online Boutique
#   ./scripts/test-cluster/teardown.sh       # Cleanup
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLUSTER_NAME="kimera-lab"
NAMESPACE="demo"
QUICK_MODE="${1:-}"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log()  { echo -e "${GREEN}[kimera-lab]${NC} $*"; }
warn() { echo -e "${YELLOW}[kimera-lab]${NC} $*"; }
err()  { echo -e "${RED}[kimera-lab]${NC} $*" >&2; }

# ── Prerequisites ──────────────────────────────────────────────────────────

check_prerequisites() {
    local missing=()
    for cmd in kind kubectl helm docker; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done

    if [ ${#missing[@]} -gt 0 ]; then
        err "Missing prerequisites: ${missing[*]}"
        echo ""
        echo "Install with:"
        echo "  brew install kind kubectl helm"
        echo "  # Docker Desktop must be running"
        exit 1
    fi

    if ! docker info &>/dev/null; then
        err "Docker is not running. Start Docker Desktop first."
        exit 1
    fi

    log "Prerequisites OK: kind, kubectl, helm, docker"
}

# ── kind Cluster ───────────────────────────────────────────────────────────

create_cluster() {
    if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
        warn "Cluster '${CLUSTER_NAME}' already exists. Delete with: kind delete cluster --name ${CLUSTER_NAME}"
        return 0
    fi

    log "Creating kind cluster '${CLUSTER_NAME}'..."

    # Cilium requires disabling the default CNI
    cat <<EOF | kind create cluster --name "${CLUSTER_NAME}" --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: ${CLUSTER_NAME}
nodes:
- role: control-plane
  kubeadmConfigPatches:
  - |
    kind: InitConfiguration
    nodeRegistration:
      kubeletExtraArgs:
        node-labels: "ingress-ready=true"
  - |
    kind: ClusterConfiguration
    apiServer:
      extraArgs:
        enable-admission-plugins: "NodeRestriction,PodSecurity"
- role: worker
- role: worker
networking:
  disableDefaultCNI: true    # Cilium will handle CNI
  podSubnet: "10.244.0.0/16"
  serviceSubnet: "10.96.0.0/16"
EOF

    log "Cluster created. Waiting for API server..."
    kubectl wait --for=condition=Ready node --all --timeout=120s 2>/dev/null || true
}

# ── Cilium CNI ─────────────────────────────────────────────────────────────

install_cilium() {
    if kubectl get daemonset cilium -n kube-system &>/dev/null; then
        log "Cilium already installed"
        return 0
    fi

    log "Installing Cilium (NetworkPolicy enforcement)..."

    helm repo add cilium https://helm.cilium.io/ 2>/dev/null || true
    helm repo update cilium

    helm install cilium cilium/cilium \
        --namespace kube-system \
        --set image.pullPolicy=IfNotPresent \
        --set ipam.mode=kubernetes \
        --set kubeProxyReplacement=false \
        --set securityContext.capabilities.ciliumAgent="{CHOWN,KILL,NET_ADMIN,NET_RAW,IPC_LOCK,SYS_ADMIN,SYS_RESOURCE,DAC_OVERRIDE,FOWNER,SETGID,SETUID}" \
        --set securityContext.capabilities.cleanCiliumState="{NET_ADMIN,SYS_ADMIN,SYS_RESOURCE}" \
        --set cgroup.autoMount.enabled=false \
        --set cgroup.hostRoot=/sys/fs/cgroup \
        --set policyEnforcementMode=default \
        --wait \
        --timeout 300s

    log "Waiting for Cilium pods..."
    kubectl wait --for=condition=Ready pod -l app.kubernetes.io/name=cilium-agent \
        -n kube-system --timeout=180s

    log "Cilium installed with NetworkPolicy enforcement enabled"
}

# ── Kyverno Admission Controller ───────────────────────────────────────────

install_kyverno() {
    if kubectl get deployment kyverno-admission-controller -n kyverno &>/dev/null; then
        log "Kyverno already installed"
        return 0
    fi

    log "Installing Kyverno (admission controller)..."

    helm repo add kyverno https://kyverno.github.io/kyverno/ 2>/dev/null || true
    helm repo update kyverno

    helm install kyverno kyverno/kyverno \
        --namespace kyverno \
        --create-namespace \
        --set admissionController.replicas=1 \
        --set backgroundController.replicas=1 \
        --set cleanupController.replicas=1 \
        --set reportsController.replicas=1 \
        --wait \
        --timeout 300s

    log "Waiting for Kyverno pods..."
    kubectl wait --for=condition=Ready pod -l app.kubernetes.io/instance=kyverno \
        -n kyverno --timeout=180s

    log "Kyverno installed"
}

apply_kyverno_policies() {
    log "Applying Kyverno security policies..."

    # Policy 1: Disallow privileged containers
    cat <<'EOF' | kubectl apply -f -
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-privileged-containers
  annotations:
    policies.kyverno.io/title: Disallow Privileged Containers
    policies.kyverno.io/category: Pod Security Standards (Baseline)
    policies.kyverno.io/severity: high
spec:
  validationFailureAction: Enforce
  background: true
  rules:
  - name: privileged-containers
    match:
      any:
      - resources:
          kinds: [Pod]
          namespaces: ["demo"]
    validate:
      message: "Privileged mode is disallowed in the demo namespace."
      pattern:
        spec:
          containers:
          - =(securityContext):
              =(privileged): "false"
EOF

    # Policy 2: Require resource limits
    cat <<'EOF' | kubectl apply -f -
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-resource-limits
  annotations:
    policies.kyverno.io/title: Require Resource Limits
    policies.kyverno.io/severity: medium
spec:
  validationFailureAction: Enforce
  background: true
  rules:
  - name: require-limits
    match:
      any:
      - resources:
          kinds: [Pod]
          namespaces: ["demo"]
    validate:
      message: "Resource limits are required for all containers in the demo namespace."
      pattern:
        spec:
          containers:
          - resources:
              limits:
                memory: "?*"
                cpu: "?*"
EOF

    # Policy 3: Disallow host namespaces
    cat <<'EOF' | kubectl apply -f -
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-host-namespaces
  annotations:
    policies.kyverno.io/title: Disallow Host Namespaces
    policies.kyverno.io/severity: high
spec:
  validationFailureAction: Enforce
  background: true
  rules:
  - name: host-namespaces
    match:
      any:
      - resources:
          kinds: [Pod]
          namespaces: ["demo"]
    validate:
      message: "Host namespace sharing is disallowed in the demo namespace."
      pattern:
        spec:
          =(hostPID): "false"
          =(hostIPC): "false"
          =(hostNetwork): "false"
EOF

    # NOTE: Intentional gap — no policy blocks SYS_ADMIN capability without
    # privileged mode. Kimera's validate-control should discover this.

    log "Applied 3 Kyverno policies (with intentional gap for SYS_ADMIN caps)"
}

# ── Demo Namespace + Workloads ─────────────────────────────────────────────

create_demo_namespace() {
    log "Creating demo namespace..."

    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Namespace
metadata:
  name: ${NAMESPACE}
  labels:
    app.kubernetes.io/managed-by: kimera-lab
EOF
}

deploy_workloads() {
    log "Deploying demo workloads..."

    # Simple multi-service setup that's fast to deploy
    # (Online Boutique is optional via --quick flag)

    # Service 1: Frontend (nginx)
    cat <<'EOF' | kubectl apply -n demo -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: frontend
  labels:
    app: frontend
spec:
  replicas: 1
  selector:
    matchLabels:
      app: frontend
  template:
    metadata:
      labels:
        app: frontend
    spec:
      containers:
      - name: frontend
        image: nginx:1.27-alpine
        ports:
        - containerPort: 80
        resources:
          limits:
            cpu: 100m
            memory: 128Mi
          requests:
            cpu: 50m
            memory: 64Mi
---
apiVersion: v1
kind: Service
metadata:
  name: frontend
spec:
  selector:
    app: frontend
  ports:
  - port: 80
    targetPort: 80
EOF

    # Service 2: API (busybox simulating an API server)
    cat <<'EOF' | kubectl apply -n demo -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-server
  labels:
    app: api-server
spec:
  replicas: 1
  selector:
    matchLabels:
      app: api-server
  template:
    metadata:
      labels:
        app: api-server
    spec:
      containers:
      - name: api
        image: busybox:1.36
        command: ["sh", "-c", "while true; do echo -e 'HTTP/1.1 200 OK\r\n\r\nOK' | nc -l -p 8080; done"]
        ports:
        - containerPort: 8080
        resources:
          limits:
            cpu: 50m
            memory: 64Mi
          requests:
            cpu: 25m
            memory: 32Mi
---
apiVersion: v1
kind: Service
metadata:
  name: api-server
spec:
  selector:
    app: api-server
  ports:
  - port: 8080
    targetPort: 8080
EOF

    # Service 3: Redis (data store)
    cat <<'EOF' | kubectl apply -n demo -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: redis
  labels:
    app: redis
spec:
  replicas: 1
  selector:
    matchLabels:
      app: redis
  template:
    metadata:
      labels:
        app: redis
    spec:
      containers:
      - name: redis
        image: redis:7-alpine
        ports:
        - containerPort: 6379
        resources:
          limits:
            cpu: 100m
            memory: 128Mi
          requests:
            cpu: 50m
            memory: 64Mi
---
apiVersion: v1
kind: Service
metadata:
  name: redis
spec:
  selector:
    app: redis
  ports:
  - port: 6379
    targetPort: 6379
EOF

    log "Waiting for workloads to be ready..."
    kubectl wait --for=condition=Available deployment --all -n demo --timeout=120s

    log "Demo workloads deployed: frontend, api-server, redis"
}

# ── Intentional Security Gaps ──────────────────────────────────────────────

create_security_gaps() {
    log "Creating intentional security gaps for kimera to discover..."

    # Gap 1: Overpermissive ServiceAccount
    cat <<'EOF' | kubectl apply -n demo -f -
apiVersion: v1
kind: ServiceAccount
metadata:
  name: overpermissive-sa
  labels:
    app.kubernetes.io/managed-by: kimera-lab
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: overpermissive-role
  labels:
    app.kubernetes.io/managed-by: kimera-lab
rules:
- apiGroups: [""]
  resources: ["secrets", "configmaps", "pods", "pods/exec"]
  verbs: ["*"]
- apiGroups: ["apps"]
  resources: ["deployments"]
  verbs: ["*"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: overpermissive-binding
  labels:
    app.kubernetes.io/managed-by: kimera-lab
subjects:
- kind: ServiceAccount
  name: overpermissive-sa
  namespace: demo
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: overpermissive-role
EOF

    # Gap 2: Partial NetworkPolicies (frontend allows ingress but no default-deny)
    cat <<'EOF' | kubectl apply -n demo -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-frontend-ingress
  labels:
    app.kubernetes.io/managed-by: kimera-lab
spec:
  podSelector:
    matchLabels:
      app: frontend
  policyTypes:
  - Ingress
  ingress:
  - from: []
    ports:
    - port: 80
      protocol: TCP
EOF
    # NOTE: No default-deny, no egress policy, no redis isolation.
    # Kimera should find: no default-deny, redis reachable from frontend, cloud metadata reachable.

    log "Security gaps created:"
    log "  • Overpermissive SA with secrets/* and pods/exec/*"
    log "  • Partial NetworkPolicy (no default-deny, no egress restrictions)"
    log "  • No Kyverno policy for SYS_ADMIN capability"
}

# ── Deploy Online Boutique (optional) ─────────────────────────────────────

deploy_online_boutique() {
    if [ "$QUICK_MODE" = "--quick" ]; then
        log "Skipping Online Boutique (--quick mode)"
        return 0
    fi

    log "Deploying Google Online Boutique (11 microservices)..."

    kubectl create namespace boutique 2>/dev/null || true

    kubectl apply -n boutique \
        -f https://raw.githubusercontent.com/GoogleCloudPlatform/microservices-demo/main/release/kubernetes-manifests.yaml

    log "Waiting for Online Boutique pods (this may take 2-3 minutes)..."
    kubectl wait --for=condition=Available deployment --all -n boutique --timeout=300s || {
        warn "Some Online Boutique deployments not ready yet. Continuing..."
    }

    log "Online Boutique deployed in 'boutique' namespace"
}

# ── Summary ────────────────────────────────────────────────────────────────

print_summary() {
    echo ""
    echo "════════════════════════════════════════════════════════════════"
    echo "  Kimera Lab Cluster Ready"
    echo "════════════════════════════════════════════════════════════════"
    echo ""
    echo "  Cluster:     ${CLUSTER_NAME}"
    echo "  Namespaces:  demo (workloads + security gaps)"
    echo "               kyverno (admission controller)"
    echo "               kube-system (Cilium CNI)"
    echo ""
    echo "  Security controls installed:"
    echo "    ✓ Cilium CNI (NetworkPolicy enforcement)"
    echo "    ✓ Kyverno (3 policies: no-privileged, require-limits, no-host-ns)"
    echo ""
    echo "  Intentional gaps for kimera to find:"
    echo "    ✗ No default-deny NetworkPolicy"
    echo "    ✗ Cloud metadata endpoint (169.254.169.254) reachable"
    echo "    ✗ Overpermissive ServiceAccount (secrets/*, pods/exec/*)"
    echo "    ✗ No Kyverno policy for SYS_ADMIN capability"
    echo "    ✗ Redis reachable from all pods (no ingress restriction)"
    echo ""
    echo "  Quick start:"
    echo "    kimera -n demo assess"
    echo "    kimera -n demo validate-control --type all"
    echo "    kimera -n demo validate-control --type admission"
    echo "    kimera -n demo validate-control --type network-policy"
    echo "    kimera -n demo validate-control --type rbac"
    echo ""
    echo "  Teardown:"
    echo "    kind delete cluster --name ${CLUSTER_NAME}"
    echo ""
    echo "════════════════════════════════════════════════════════════════"
}

# ── Main ───────────────────────────────────────────────────────────────────

main() {
    check_prerequisites
    create_cluster
    install_cilium
    install_kyverno
    apply_kyverno_policies
    create_demo_namespace
    deploy_workloads
    create_security_gaps
    deploy_online_boutique
    print_summary
}

main "$@"
