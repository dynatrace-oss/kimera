#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

echo "======================================"
echo "Deploying Vulnerable Test Workloads"
echo "======================================"

# Check if cluster exists
if ! kind get clusters 2>/dev/null | grep -q "^kimera-test$"; then
    echo "Error: Cluster 'kimera-test' does not exist"
    echo "Run ./scripts/test/setup-cluster.sh first"
    exit 1
fi

# Set context
kubectl config use-context kind-kimera-test

# Create test namespaces
echo "Creating test namespaces..."
kubectl create namespace test-vulnerable --dry-run=client -o yaml | kubectl apply -f -
kubectl create namespace test-secure --dry-run=client -o yaml | kubectl apply -f -

# Deploy vulnerable workloads
echo "Deploying vulnerable test applications..."

# 1. Privileged container (test-vulnerable)
cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: privileged-app
  namespace: test-vulnerable
  labels:
    app: privileged-app
    test-type: privileged
spec:
  replicas: 1
  selector:
    matchLabels:
      app: privileged-app
  template:
    metadata:
      labels:
        app: privileged-app
    spec:
      containers:
      - name: app
        image: nginx:alpine
        securityContext:
          privileged: true
        resources:
          requests:
            memory: "64Mi"
            cpu: "100m"
          limits:
            memory: "128Mi"
            cpu: "200m"
---
apiVersion: v1
kind: Service
metadata:
  name: privileged-app
  namespace: test-vulnerable
spec:
  selector:
    app: privileged-app
  ports:
  - port: 80
    targetPort: 80
EOF

# 2. Dangerous capabilities (test-vulnerable)
cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: dangerous-caps-app
  namespace: test-vulnerable
  labels:
    app: dangerous-caps-app
    test-type: capabilities
spec:
  replicas: 1
  selector:
    matchLabels:
      app: dangerous-caps-app
  template:
    metadata:
      labels:
        app: dangerous-caps-app
    spec:
      containers:
      - name: app
        image: nginx:alpine
        securityContext:
          capabilities:
            add:
              - SYS_ADMIN
              - NET_ADMIN
              - SYS_PTRACE
        resources:
          requests:
            memory: "64Mi"
            cpu: "100m"
          limits:
            memory: "128Mi"
            cpu: "200m"
---
apiVersion: v1
kind: Service
metadata:
  name: dangerous-caps-app
  namespace: test-vulnerable
spec:
  selector:
    app: dangerous-caps-app
  ports:
  - port: 80
    targetPort: 80
EOF

# 3. Host namespace sharing (test-vulnerable)
cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: host-namespace-app
  namespace: test-vulnerable
  labels:
    app: host-namespace-app
    test-type: host-namespace
spec:
  replicas: 1
  selector:
    matchLabels:
      app: host-namespace-app
  template:
    metadata:
      labels:
        app: host-namespace-app
    spec:
      hostPID: true
      hostNetwork: true
      hostIPC: true
      containers:
      - name: app
        image: nginx:alpine
        resources:
          requests:
            memory: "64Mi"
            cpu: "100m"
          limits:
            memory: "128Mi"
            cpu: "200m"
---
apiVersion: v1
kind: Service
metadata:
  name: host-namespace-app
  namespace: test-vulnerable
spec:
  selector:
    app: host-namespace-app
  ports:
  - port: 80
    targetPort: 80
EOF

# 4. Missing resource limits (test-vulnerable)
cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: no-limits-app
  namespace: test-vulnerable
  labels:
    app: no-limits-app
    test-type: no-limits
spec:
  replicas: 1
  selector:
    matchLabels:
      app: no-limits-app
  template:
    metadata:
      labels:
        app: no-limits-app
    spec:
      containers:
      - name: app
        image: nginx:alpine
---
apiVersion: v1
kind: Service
metadata:
  name: no-limits-app
  namespace: test-vulnerable
spec:
  selector:
    app: no-limits-app
  ports:
  - port: 80
    targetPort: 80
EOF

# 5. Secure deployment (test-secure)
cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secure-app
  namespace: test-secure
  labels:
    app: secure-app
    test-type: secure
spec:
  replicas: 1
  selector:
    matchLabels:
      app: secure-app
  template:
    metadata:
      labels:
        app: secure-app
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: app
        image: nginx:alpine
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          runAsNonRoot: true
          runAsUser: 1000
          capabilities:
            drop:
              - ALL
        resources:
          requests:
            memory: "64Mi"
            cpu: "100m"
          limits:
            memory: "128Mi"
            cpu: "200m"
        volumeMounts:
        - name: cache
          mountPath: /var/cache/nginx
        - name: run
          mountPath: /var/run
      volumes:
      - name: cache
        emptyDir: {}
      - name: run
        emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: secure-app
  namespace: test-secure
spec:
  selector:
    app: secure-app
  ports:
  - port: 80
    targetPort: 80
EOF

# Wait for deployments to be ready
echo ""
echo "Waiting for deployments to be ready..."
kubectl wait --for=condition=available --timeout=300s \
  deployment/privileged-app \
  deployment/dangerous-caps-app \
  deployment/host-namespace-app \
  deployment/no-limits-app \
  -n test-vulnerable

kubectl wait --for=condition=available --timeout=300s \
  deployment/secure-app \
  -n test-secure

echo ""
echo "======================================"
echo "Deployment complete!"
echo "======================================"
echo ""
echo "Vulnerable workloads (test-vulnerable namespace):"
kubectl get deployments,pods,services -n test-vulnerable
echo ""
echo "Secure workloads (test-secure namespace):"
kubectl get deployments,pods,services -n test-secure
echo ""
echo "To test the toolkit:"
echo "  k8s-exploit assess --namespace test-vulnerable"
echo "  k8s-exploit exploit privileged-containers --namespace test-vulnerable"
