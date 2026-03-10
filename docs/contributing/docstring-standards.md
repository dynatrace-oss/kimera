# Docstring Standards

This document defines the docstring standards for the Kimera (k8s-exploit-toolkit) project.

## Guiding Principles

1. **Concise over verbose** - Be clear but brief
2. **Human-quality** - Write naturally, not like AI-generated text
3. **Imperative mood** - Use "Execute exploit" not "Executes exploit"
4. **Technical accuracy** - Focus on what matters, skip the obvious
5. **No marketing language** - Avoid superlatives and promotional tone

## Google Style Format

We use Google-style docstrings for consistency and tooling compatibility.

### Module Docstrings

Every module should start with a one-line summary.

```python
"""Security scanner for Kubernetes container configurations."""
```

For complex modules, add a longer description:

```python
"""Security scanner for Kubernetes container configurations.

This module provides vulnerability scanning for container security contexts,
detecting misconfigurations like privileged containers, dangerous capabilities,
and missing security policies.
"""
```

### Class Docstrings

Classes should have:
- One-line summary (imperative: "Manage X" not "Manages X")
- Optional extended description
- Attributes section only if non-obvious

**Good:**

```python
class PrivilegedContainerExploit:
    """Demonstrate privileged container escape to host.

    Attributes:
        namespace: Target Kubernetes namespace
        service_name: Target service name
    """

    def __init__(self, namespace: str, service_name: str):
        self.namespace = namespace
        self.service_name = service_name
```

**Bad (too verbose):**

```python
class PrivilegedContainerExploit:
    """This class provides functionality for demonstrating how a privileged
    container can be exploited to escape container isolation and gain access
    to the host system. It implements various techniques for privilege
    escalation and provides detailed reporting of the attack chain.

    This exploit is designed for educational purposes and should only be
    used in authorized testing environments...
    (continues for 10+ more lines)
    """
```

### Function/Method Docstrings

Methods should have:
- One-line summary (imperative mood)
- Args section (only if parameters aren't self-explanatory)
- Returns section (if return value isn't obvious)
- Raises section (for expected exceptions)

**Good:**

```python
def execute_exploit(self, target: str) -> ExploitResult:
    """Execute exploit against target service.

    Args:
        target: Service name to exploit

    Returns:
        Result with success status and evidence

    Raises:
        ExploitError: If target not found or execution fails
    """
    pass
```

**Good (simple case, minimal docs):**

```python
def get_namespace(self) -> str:
    """Return the target namespace."""
    return self.namespace
```

**Bad (stating the obvious):**

```python
def get_namespace(self) -> str:
    """Get the namespace attribute.

    This function retrieves the namespace attribute from the instance
    and returns it to the caller.

    Returns:
        str: The namespace string that was set during initialization
    """
    return self.namespace
```

## Sections

### Args

Use when parameters aren't self-explanatory:

```python
"""
Args:
    namespace: Target Kubernetes namespace
    timeout: Operation timeout in seconds
    dry_run: Preview changes without applying them
"""
```

Skip for obvious parameters:

```python
# Not needed:
"""
Args:
    name: The name (obvious from parameter)
"""
```

### Returns

Use when return value needs explanation:

```python
"""
Returns:
    Dict mapping service names to vulnerability counts
"""
```

Skip for obvious returns:

```python
# Not needed:
"""
Returns:
    bool: True or False (obvious from return type hint)
"""
```

### Raises

Document expected exceptions:

```python
"""
Raises:
    ValidationError: If configuration is invalid
    KubernetesError: If cluster communication fails
"""
```

### Examples

Only include examples when they add real value:

```python
"""Apply security fix to deployment.

Example:
    >>> fixer = SecurityFixer()
    >>> result = fixer.apply(deployment, SecurityPolicy.STRICT)
    >>> print(result.status)
    'secured'
"""
```

Don't include trivial examples:

```python
# Bad:
"""Get the name.

Example:
    >>> obj.get_name()
    'my-name'
"""
```

## Type Hints

Use type hints instead of documenting types in docstrings:

**Good:**

```python
def process_deployment(deployment: V1Deployment) -> List[Vulnerability]:
    """Scan deployment for vulnerabilities."""
    pass
```

**Bad:**

```python
def process_deployment(deployment):
    """Scan deployment for vulnerabilities.

    Args:
        deployment (V1Deployment): The deployment to scan

    Returns:
        List[Vulnerability]: List of found vulnerabilities
    """
    pass
```

## Common Patterns

### Property Getters/Setters

Keep them minimal:

```python
@property
def namespace(self) -> str:
    """Target namespace."""
    return self._namespace
```

### Private Methods

Still document them, but can be terser:

```python
def _validate_config(self, config: dict) -> bool:
    """Validate configuration schema."""
    pass
```

### Test Functions

Be descriptive about what you're testing:

```python
def test_privileged_container_detected():
    """Test scanner detects privileged containers."""
    pass
```

## Red Flags (What to Avoid)

### Too Verbose

```python
# Bad:
"""This function is responsible for executing the vulnerability
assessment process by iterating through all deployments in the
specified namespace and checking each container's security context
for potential misconfigurations that could lead to security issues."""

# Good:
"""Scan deployments in namespace for container security issues."""
```

### AI-Generated Feel

```python
# Bad:
"""This powerful and comprehensive function enables users to
seamlessly execute sophisticated exploit demonstrations while
maintaining full observability and traceability."""

# Good:
"""Execute exploit and return results."""
```

### Repeating Code

```python
# Bad:
def check_privileged(self) -> bool:
    """Check if privileged is set to True.

    Returns:
        bool: True if privileged is True, False otherwise
    """
    return self.privileged

# Good:
def check_privileged(self) -> bool:
    """Check if container runs in privileged mode."""
    return self.privileged
```

### Over-Documentation

```python
# Bad - parameter is self-explanatory:
def set_namespace(self, namespace: str) -> None:
    """Set the namespace.

    Args:
        namespace: The namespace string to set as the target namespace

    Returns:
        None: This function returns nothing

    Example:
        >>> obj.set_namespace("default")
    """
    self.namespace = namespace

# Good:
def set_namespace(self, namespace: str) -> None:
    """Set target namespace."""
    self.namespace = namespace
```

## Verification

Use these tools to check docstring quality:

```bash
# Check coverage
uv run pydocstyle k8s_exploit_toolkit/

# Check in pre-commit
pre-commit run --all-files
```

## Summary

- **Be concise** - Say more with less
- **Be clear** - Focus on the "why" not the "what"
- **Be natural** - Write like a human, not an AI
- **Be selective** - Not everything needs extensive documentation
- **Be technical** - Accuracy over marketing

Good docstrings help developers understand code quickly without wading through unnecessary text.
