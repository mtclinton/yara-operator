# YARA Operator

A Kubernetes-native operator for scanning container images and data for vulnerabilities, secrets, and malware using YARA rules.

[![Go Version](https://img.shields.io/badge/Go-1.21-00ADD8?style=flat&logo=go)](https://golang.org)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-1.25+-326CE5?style=flat&logo=kubernetes)](https://kubernetes.io)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

## Overview

The YARA Operator provides comprehensive security scanning for container images and data:

- **Container Image Scanning** — Scan images from Docker Hub, GHCR, Quay.io, and other registries
- **Vulnerability Detection** — Detect known CVEs including Log4Shell, Spring4Shell, and Shellshock
- **Secret Detection** — Find exposed API keys, passwords, tokens, and private keys
- **Malware Detection** — Identify cryptominers, webshells, backdoors, and reverse shells
- **Risk Scoring** — Receive actionable risk scores from 0-100 based on findings
- **Kubernetes Native** — Declarative CRDs for automated security scanning workflows
- **Web Dashboard** — GitHub Pages frontend for browser-based scanning

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     GitHub Pages (Frontend)                      │
│                     yara.yourdomain.com                         │
│                              │                                   │
│                         Cloudflare                               │
│                        (DNS + SSL)                               │
└──────────────────────────────┬──────────────────────────────────┘
                               │ HTTPS
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Kubernetes Cluster                          │
│                                                                  │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐       │
│  │  YARA API    │◄───│   Ingress    │◄───│   Internet   │       │
│  │   Server     │    │  Controller  │    │              │       │
│  └──────┬───────┘    └──────────────┘    └──────────────┘       │
│         │                                                        │
│         ▼                                                        │
│  ┌──────────────┐    ┌──────────────┐                           │
│  │    YARA      │───►│  YaraRule    │                           │
│  │  Operator    │    │  YaraScan    │                           │
│  │  Controller  │    │    CRDs      │                           │
│  └──────────────┘    └──────────────┘                           │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- Kubernetes cluster (v1.25+)
- kubectl configured
- Helm 3.x
- Domain with Cloudflare DNS (optional, for web frontend)

### 1. Install CRDs

```bash
kubectl apply -f config/crd/bases/
```

### 2. Deploy with Helm

```bash
kubectl create namespace yara-system

helm install yara-operator ./charts/yara-operator \
  --namespace yara-system \
  --set api.ingress.hosts[0].host=yara-api.yourdomain.com \
  --set api.ingress.tls[0].hosts[0]=yara-api.yourdomain.com
```

### 3. Apply Security Rules

```bash
kubectl apply -f config/samples/container_rules.yaml -n yara-system
kubectl apply -f config/samples/yararule_sample.yaml -n yara-system
```

### 4. Scan a Container Image

```bash
kubectl apply -f - <<EOF
apiVersion: yara.security.io/v1alpha1
kind: YaraScan
metadata:
  name: scan-nginx
  namespace: yara-system
spec:
  target:
    type: image
    value: nginx:latest
EOF
```

### 5. View Results

```bash
# Get scan status
kubectl get yarascans -n yara-system

# Get scan summary
kubectl get yarascan scan-nginx -n yara-system -o jsonpath='{.status.message}'

# Get vulnerability details
kubectl get yarascan scan-nginx -n yara-system -o jsonpath='{.status.imageResult.vulnerabilities}' | jq

# Get risk score
kubectl get yarascan scan-nginx -n yara-system -o jsonpath='{.status.summary.riskScore}'
```

## Container Image Scanning

### Supported Registries

| Registry | Example |
|----------|---------|
| Docker Hub | `nginx:latest`, `python:3.11-slim` |
| GitHub Container Registry | `ghcr.io/owner/image:tag` |
| Quay.io | `quay.io/prometheus/prometheus:latest` |
| Google Container Registry | `gcr.io/project/image:tag` |

### Example Scan Configuration

```yaml
apiVersion: yara.security.io/v1alpha1
kind: YaraScan
metadata:
  name: scan-python-image
spec:
  target:
    type: image
    value: python:3.11-slim
    scanLayers: true
  ruleNames:
    - detect-cryptominer
    - detect-webshell
    - detect-hardcoded-secrets
    - detect-vulnerable-packages
  timeout: 600
```

### Built-in Detection Rules

| Rule | Detection Target |
|------|------------------|
| `detect-cryptominer` | XMRig, mining pools, wallet addresses |
| `detect-webshell` | C99, R57, WSO shells, PHP backdoors |
| `detect-reverse-shell` | Bash, Python, Perl, Netcat reverse shells |
| `detect-container-escape` | Docker socket access, cgroup escapes |
| `detect-hardcoded-secrets` | AWS keys, GitHub tokens, private keys |
| `detect-vulnerable-packages` | Log4Shell, Spring4Shell, Shellshock |
| `detect-supply-chain-attack` | Typosquatting, malicious install scripts |

### Scan Results

Image scans return:

- **Risk Score** (0-100): Aggregate security rating
- **Vulnerabilities**: Identified CVEs with severity classification
- **Secrets**: Exposed credentials and API keys
- **Malware Indicators**: Cryptominers, backdoors, webshells
- **Layer Analysis**: Findings mapped to individual image layers

## Custom Resource Definitions

### YaraRule

Define reusable YARA rules:

```yaml
apiVersion: yara.security.io/v1alpha1
kind: YaraRule
metadata:
  name: detect-malware
  labels:
    category: malware
spec:
  name: detect_malware
  description: Detects common malware patterns
  tags:
    - malware
    - security
  enabled: true
  content: |
    rule detect_malware {
        strings:
            $a = "malicious_payload"
            $b = { 4D 5A 90 00 }
        condition:
            any of them
    }
```

### YaraScan

Execute scans against various targets:

```yaml
apiVersion: yara.security.io/v1alpha1
kind: YaraScan
metadata:
  name: scan-config
spec:
  target:
    type: configmap
    value: my-config
    key: app.yaml
  ruleNames:
    - detect-malware
  timeout: 300
```

### Target Types

| Type | Description | Example |
|------|-------------|---------|
| `image` | Container image from registry | `nginx:latest` |
| `data` | Base64 encoded data | `SGVsbG8gV29ybGQ=` |
| `url` | Remote file URL | `https://example.com/file.bin` |
| `configmap` | Kubernetes ConfigMap | `my-configmap` |
| `secret` | Kubernetes Secret | `my-secret` |

## API Reference

### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/scans` | List all scans |
| `POST` | `/api/v1/scans` | Create a new scan |
| `GET` | `/api/v1/scans/{id}` | Get scan details |
| `DELETE` | `/api/v1/scans/{id}` | Delete a scan |
| `GET` | `/api/v1/rules` | List all rules |
| `POST` | `/api/v1/rules` | Create a new rule |
| `GET` | `/api/v1/rules/{name}` | Get rule details |
| `DELETE` | `/api/v1/rules/{name}` | Delete a rule |

### Create Image Scan

```bash
curl -X POST https://yara-api.example.com/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{
    "image": "nginx:latest",
    "ruleNames": ["detect-cryptominer", "detect-webshell"]
  }'
```

### Create Text Scan

```bash
curl -X POST https://yara-api.example.com/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{
    "text": "Content to scan...",
    "ruleNames": ["detect-malware"]
  }'
```

### Response Format

```json
{
  "id": "api-scan-abc123",
  "status": "Completed",
  "targetType": "image",
  "startTime": "2024-01-15T10:30:00Z",
  "endTime": "2024-01-15T10:32:15Z",
  "matchCount": 3,
  "vulnerabilityCount": 5,
  "secretsCount": 2,
  "scannedBytes": 157286400,
  "summary": {
    "critical": 1,
    "high": 2,
    "medium": 3,
    "low": 1,
    "riskScore": 65
  },
  "imageResult": {
    "image": "nginx:latest",
    "digest": "sha256:abc123...",
    "size": 157286400,
    "malwareDetected": false,
    "vulnerabilities": [...],
    "secretsFound": [...],
    "layers": [...]
  },
  "message": "Critical issues found. Risk Score: 65/100."
}
```

## GitHub Pages Setup

### Enable GitHub Pages

1. Fork or clone this repository
2. Navigate to **Settings** → **Pages**
3. Set **Source** to `Deploy from a branch`
4. Select `main` branch and `/docs` folder
5. Click **Save**

### Configure Custom Domain with Cloudflare

1. Add a CNAME record in Cloudflare DNS:
   - Type: `CNAME`
   - Name: `yara`
   - Target: `yourusername.github.io`
   - Proxy: Enabled

2. Update `/docs/CNAME` with your domain

3. Configure SSL/TLS in Cloudflare:
   - Set encryption mode to **Full (strict)**
   - Enable **Always Use HTTPS**

See [CLOUDFLARE_SETUP.md](CLOUDFLARE_SETUP.md) for detailed instructions.

## Running Locally

For a complete guide on running the operator locally for development, see [docs/runLocally.md](docs/runLocally.md).

## Development

### Build

```bash
make build        # Build operator binary
make build-api    # Build API server binary
```

### Run Locally

```bash
make run          # Run operator (requires kubeconfig)
make run-api      # Run API server
```

### Docker Images

```bash
make docker-build      # Build operator image
make docker-build-api  # Build API image
make docker-push       # Push operator image
make docker-push-api   # Push API image
```

### Testing

```bash
make test
```

## Configuration

### Helm Values

| Parameter | Description | Default |
|-----------|-------------|---------|
| `operator.replicaCount` | Operator replicas | `1` |
| `operator.image.repository` | Operator image | `ghcr.io/yara-operator/operator` |
| `api.enabled` | Enable API server | `true` |
| `api.replicaCount` | API server replicas | `2` |
| `api.ingress.enabled` | Enable Ingress | `true` |
| `api.ingress.hosts[0].host` | API hostname | `yara-api.example.com` |
| `namespace` | Deployment namespace | `yara-system` |

## Security Considerations

1. **CORS**: The API allows all origins by default. Restrict this in production environments.
2. **Authentication**: Add authentication middleware for production deployments.
3. **RBAC**: The operator requires read access to Secrets and ConfigMaps for scanning.
4. **Network Policies**: Consider implementing network policies to restrict traffic flow.

## Troubleshooting

### Scan Stuck in Pending State

```bash
kubectl get pods -n yara-system
kubectl logs -n yara-system deployment/yara-operator-controller
```

### API Not Accessible

```bash
kubectl get ingress -n yara-system
kubectl get svc -n yara-system
kubectl describe ingress -n yara-system
```

### Image Scan Timeout

Increase the timeout in the YaraScan spec or check network connectivity to the container registry.

## License

Apache License 2.0 — See [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome. Please read the [Contributing Guide](CONTRIBUTING.md) before submitting pull requests.
