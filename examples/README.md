# Examples

This directory contains example scripts demonstrating how to use Kimera programmatically.

## Available Examples

### `basic_usage.py`

Demonstrates the fundamental programmatic workflow:

```python
from kimera.application.config.loader import ConfigLoader
from kimera.container.assessment.scanner import SecurityScanner
from kimera.container.core.k8s_client import K8sClient
from kimera.container.core.logger import SecurityLogger, setup_logger

loader = ConfigLoader()
config = loader.load(overrides={"kubernetes": {"namespace": "unguard"}})
logger = SecurityLogger(setup_logger("example", debug=True))

k8s_client = K8sClient(namespace=config.namespace, logger=logger)
scanner = SecurityScanner(k8s_client, logger)
scanner.assess_all_services(["my-deployment"])
```

**Run the example:**

```bash
python examples/basic_usage.py
```

## Prerequisites

- Python 3.13+
- kubectl configured with cluster access
- Kimera installed (see installation methods below)

## Running Examples

1. **Ensure cluster access**: `kubectl cluster-info`
2. **Install dependencies**:
   - With uv: `uv sync`
   - With pip: `pip install -e .`
3. **Run examples**: `python examples/basic_usage.py`

Warning: Only run on test clusters you own or have permission to modify.
