# Running YARA Operator Locally

This guide walks you through running the complete YARA Operator system on your local machine.

## Prerequisites

- Go 1.21+
- Docker
- kubectl
- A local Kubernetes cluster (minikube, kind, or k3d)

## Quick Start

### 1. Start a Local Kubernetes Cluster

**Using minikube:**
```bash
minikube start
```

**Using kind:**
```bash
kind create cluster --name yara
```

**Using k3d:**
```bash
k3d cluster create yara
```

### 2. Clone and Setup

```bash
git clone https://github.com/your-org/yara-operator.git
cd yara-operator
go mod tidy
```

### 3. Install CRDs

```bash
make install
```

Verify CRDs are installed:
```bash
kubectl get crds | grep yara
```

Expected output:
```
yararules.yara.security.io    2024-01-15T10:00:00Z
yarascans.yara.security.io    2024-01-15T10:00:00Z
```

### 4. Start the Operator (Terminal 1)

```bash
make run
```

You should see:
```
INFO    setup   starting manager
INFO    Starting Controller     {"controller": "yararule"}
INFO    Starting Controller     {"controller": "yarascan"}
```

Keep this terminal running.

### 5. Start the API Server (Terminal 2)

Open a new terminal:
```bash
make run-api
```

You should see:
```
YARA API Server starting on :8090
```

Keep this terminal running.

### 6. Start the Frontend (Terminal 3)

Open another terminal:
```bash
cd docs
python3 -m http.server 8085
```

Or with Node.js:
```bash
npx serve -p 8085 docs
```

### 7. Access the Application

| Service | URL |
|---------|-----|
| Frontend | http://localhost:8085 |
| API | http://localhost:8090 |
| API Health | http://localhost:8090/health |

When the frontend prompts for an API URL, enter: `http://localhost:8090`

---

## Loading Sample Rules

Apply the built-in security rules:

```bash
# Container security rules (cryptominers, webshells, etc.)
kubectl apply -f config/samples/container_rules.yaml

# Generic detection rules
kubectl apply -f config/samples/yararule_sample.yaml
```

Verify rules are loaded:
```bash
kubectl get yararules
```

Expected output:
```
NAME                        STATUS   AGE
detect-cryptominer          Valid    10s
detect-webshell             Valid    10s
detect-reverse-shell        Valid    10s
detect-container-escape     Valid    10s
detect-hardcoded-secrets    Valid    10s
detect-vulnerable-packages  Valid    10s
detect-malicious-strings    Valid    10s
```

---

## Running Scans

### Via the Frontend

1. Open http://localhost:8085
2. Select the **Container Image** tab
3. Enter an image like `nginx:alpine` or click a preset
4. Click **Start Scan**
5. View results in the **Scan Results** section

### Via kubectl

**Scan a container image:**
```bash
kubectl apply -f - <<EOF
apiVersion: yara.security.io/v1alpha1
kind: YaraScan
metadata:
  name: scan-nginx
spec:
  target:
    type: image
    value: nginx:alpine
  timeout: 300
EOF
```

**Watch scan progress:**
```bash
kubectl get yarascans -w
```

**View scan results:**
```bash
kubectl describe yarascan scan-nginx
```

**Get JSON results:**
```bash
kubectl get yarascan scan-nginx -o jsonpath='{.status}' | jq
```

### Via the API

**Scan text content:**
```bash
curl -X POST http://localhost:8090/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{
    "text": "This contains malware patterns for testing",
    "rules": ["rule test { strings: $a = \"malware\" condition: $a }"]
  }'
```

**Scan a container image:**
```bash
curl -X POST http://localhost:8090/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{
    "image": "python:3.11-slim",
    "ruleNames": ["detect-cryptominer", "detect-hardcoded-secrets"]
  }'
```

**List all scans:**
```bash
curl http://localhost:8090/api/v1/scans | jq
```

**Get scan details:**
```bash
curl http://localhost:8090/api/v1/scans/scan-nginx | jq
```

**List all rules:**
```bash
curl http://localhost:8090/api/v1/rules | jq
```

---

## All-in-One Start Script

Create a script to start everything at once:

```bash
cat > start-local.sh << 'SCRIPT'
#!/bin/bash
set -e

echo "=========================================="
echo "  YARA Operator - Local Development"
echo "=========================================="

cd "$(dirname "$0")"

# Check prerequisites
command -v kubectl >/dev/null 2>&1 || { echo "kubectl required"; exit 1; }
command -v go >/dev/null 2>&1 || { echo "go required"; exit 1; }

# Check cluster connection
if ! kubectl cluster-info &>/dev/null; then
    echo "No Kubernetes cluster found. Starting minikube..."
    minikube start
fi

# Install CRDs
echo "[1/4] Installing CRDs..."
make install

# Apply sample rules
echo "[2/4] Applying sample rules..."
kubectl apply -f config/samples/container_rules.yaml 2>/dev/null || true
kubectl apply -f config/samples/yararule_sample.yaml 2>/dev/null || true

# Start operator
echo "[3/4] Starting operator..."
make run &
OPERATOR_PID=$!
sleep 3

# Start API
echo "[4/4] Starting API server..."
make run-api &
API_PID=$!
sleep 2

# Start frontend
echo "[5/5] Starting frontend..."
cd docs && python3 -m http.server 8085 &
FRONTEND_PID=$!
cd ..

echo ""
echo "=========================================="
echo "  All services running!"
echo "=========================================="
echo ""
echo "  Frontend:  http://localhost:8085"
echo "  API:       http://localhost:8090"
echo ""
echo "  Press Ctrl+C to stop all services"
echo "=========================================="

cleanup() {
    echo ""
    echo "Shutting down..."
    kill $OPERATOR_PID $API_PID $FRONTEND_PID 2>/dev/null
    exit 0
}

trap cleanup INT TERM
wait
SCRIPT

chmod +x start-local.sh
```

Run with:
```bash
./start-local.sh
```

---

## Troubleshooting

### CRDs not found

```bash
# Reinstall CRDs
make install

# Verify
kubectl get crds | grep yara
```

### Operator fails to start

```bash
# Check if cluster is accessible
kubectl cluster-info

# Check for port conflicts
lsof -i :8080
lsof -i :8081
```

### API connection refused

```bash
# Check if API is running
curl http://localhost:8090/health

# Check logs
# (in the API terminal)
```

### Scans stuck in Pending

```bash
# Check operator logs for errors
# (in the operator terminal)

# Verify rules exist
kubectl get yararules

# Check scan status
kubectl describe yarascan <scan-name>
```

### Image scan fails

```bash
# Check if image exists
docker pull nginx:alpine

# Check operator logs for registry errors
# (in the operator terminal)
```

---

## Development Workflow

### Rebuild after code changes

```bash
# Stop running services (Ctrl+C)

# Rebuild
make build
make build-api

# Restart
make run        # Terminal 1
make run-api    # Terminal 2
```

### Run tests

```bash
make test
```

### Format code

```bash
make fmt
```

### Update CRDs after type changes

```bash
# If you modify api/v1alpha1/types.go:
# 1. Update zz_generated.deepcopy.go
# 2. Reinstall CRDs
make install
```

---

## Cleanup

### Delete all scans

```bash
kubectl delete yarascans --all
```

### Delete all rules

```bash
kubectl delete yararules --all
```

### Uninstall CRDs

```bash
make uninstall
```

### Delete cluster

```bash
# minikube
minikube delete

# kind
kind delete cluster --name yara

# k3d
k3d cluster delete yara
```

