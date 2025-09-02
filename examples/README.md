# Examples

This directory contains example scripts demonstrating how to use the K8s Exploit Toolkit programmatically.

## Available Examples

### `basic_usage.py`

Demonstrates the fundamental programmatic workflow:

```python
# Initialize toolkit components
from k8s_exploit_toolkit.core.client import K8sClient
from k8s_exploit_toolkit.container.assessment.scanner import SecurityScanner

# Connect to cluster and run assessment
client = K8sClient()
scanner = SecurityScanner(client)
results = scanner.assess_deployment("my-app")
```

**Run the example:**

```bash
python examples/basic_usage.py
```

## Integration Examples

### Python Integration

```python
from k8s_exploit_toolkit import ExploitToolkit

# Initialize toolkit
toolkit = ExploitToolkit()

# Assess security posture
assessment = toolkit.assess()

# Apply specific vulnerability for testing
toolkit.make_vulnerable("my-deployment", "privileged")

# Apply security fixes
toolkit.secure()
```

### Custom Scripting

```python
# Custom vulnerability detection
from k8s_exploit_toolkit.container.assessment import Scanner

scanner = Scanner()
vulnerabilities = scanner.scan_namespace("production")

for vuln in vulnerabilities:
    print(f"Found {vuln.type} in {vuln.deployment}")
```

## Prerequisites

- Python 3.9+
- kubectl configured with cluster access
- k8s-exploit-toolkit installed (see installation methods below)

## Running Examples

1. **Ensure cluster access**: `kubectl cluster-info`
2. **Install dependencies**:
   - With Poetry: `poetry install && poetry shell`
   - With pip: `pip install -e .`
3. **Run examples**: `python examples/basic_usage.py`

⚠️ **Note**: Only run on test clusters you own or have permission to modify.
