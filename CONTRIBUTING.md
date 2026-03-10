# Contributing to K8s Exploit Toolkit

Thank you for your interest in contributing to the K8s Exploit Toolkit! This document provides guidelines and information for contributors.

## Code of Conduct

This project adheres to a code of conduct. By participating, you are expected to uphold this code.

## Security First

As this is a security-focused project, please keep in mind:

- All contributions must be for **educational and defensive purposes only**
- Include proper documentation explaining the security implications
- Follow responsible disclosure practices

## How to Contribute

### Reporting Bugs

1. **Search existing issues** to avoid duplicates
2. **Use the bug report template** when creating new issues
3. **Provide detailed information**:
   - Kubernetes version
   - Python version
   - Complete error messages
   - Steps to reproduce

### Suggesting Features

1. **Check existing feature requests** first
2. **Create a detailed proposal** including:
   - Educational value
   - Security relevance
   - Implementation approach
   - Potential risks

### Development Setup

1. **Fork and clone** the repository:

   ```bash
   git clone https://github.com/yourusername/k8s-exploit-toolkit
   cd k8s-exploit-toolkit
   ```

2. **Install uv** (if not already installed):

   ```bash
   curl -LsSf https://astral.sh/uv/install.sh | sh
   ```

3. **Install dependencies**:

   ```bash
   uv sync
   ```

4. **Run tests** to ensure everything works:

   ```bash
   uv run pytest
   ```

### Coding Standards

- **Follow PEP 8** style guidelines
- **Use type hints** where appropriate
- **Write comprehensive docstrings** for all public functions
- **Add unit tests** for new functionality
- **Update documentation** as needed

### Adding New Exploits

When adding new container security exploits:

1. **Educational Focus**: Ensure the exploit teaches important security concepts
2. **Safety First**: Include proper safety mechanisms and warnings
3. **Documentation**: Provide clear explanations of the vulnerability
4. **Remediation**: Always include corresponding security fixes
5. **Testing**: Add comprehensive test coverage

Example structure:

```python
class NewExploit(BaseExploit):
    name = "Descriptive Exploit Name"
    risk_level = "HIGH"  # LOW, MEDIUM, HIGH, CRITICAL
    vulnerability_type = "container-security"
    description = "Clear explanation of what this demonstrates"

    def get_vulnerable_patch(self) -> List[Dict]:
        """Return JSON patches to make service vulnerable."""
        pass

    def get_secure_patch(self) -> List[Dict]:
        """Return JSON patches to secure the service."""
        pass

    def run_exploit(self) -> ExploitResult:
        """Demonstrate the security vulnerability safely."""
        pass
```

### Documentation Guidelines

- **Use clear, concise language**
- **Include practical examples**
- **Explain security implications**
- **Provide remediation steps**
- **Update README if needed**

### Testing

Run the full test suite before submitting:

```bash
# Unit tests
uv run pytest tests/

# Integration tests (requires K8s cluster)
uv run pytest tests/integration/

# Code coverage
uv run pytest --cov=k8s_exploit_toolkit

# Code quality checks
uv run black k8s_exploit_toolkit/
uv run ruff check k8s_exploit_toolkit/
uv run mypy k8s_exploit_toolkit/
```

### Submitting Changes

1. **Create a feature branch**:

   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** following the guidelines above

3. **Commit with descriptive messages**:

   ```bash
   git commit -m "feat: add new privilege escalation demo

   - Implement container escape demonstration
   - Add corresponding security remediation
   - Include comprehensive documentation"
   ```

4. **Push to your fork**:

   ```bash
   git push origin feature/your-feature-name
   ```

5. **Create a Pull Request** with:
   - Clear title and description
   - Reference to any related issues
   - Screenshots or demo output if applicable

### Pull Request Guidelines

- **Keep changes focused** - one feature/fix per PR
- **Update tests** for any new functionality
- **Update documentation** if needed
- **Ensure CI passes** before requesting review
- **Be responsive** to reviewer feedback

## Project Structure

```txt
k8s-exploit-toolkit/
├── k8s_exploit_toolkit/        # Main package
│   ├── container/              # Container security modules
│   │   ├── assessment/         # Security assessment tools
│   │   ├── exploits/           # Exploit implementations
│   │   ├── remediations/       # Security fix implementations
│   │   └── core/              # Shared utilities
│   └── cli.py                 # Command-line interface
├── tests/                     # Test suite
│   ├── unit/                  # Unit tests
│   └── integration/           # Integration tests
├── docs/                      # Documentation
└── examples/                  # Usage examples
```

## Recognition

Contributors will be acknowledged in:

- CHANGELOG.md for significant contributions
- Project documentation where appropriate
- Special thanks in release notes

## Getting Help

- **GitHub Issues**: For bugs and feature requests
- **GitHub Discussions**: For questions and general discussion
- **Security Issues**: Please report privately via email

## Legal Considerations

By contributing, you agree that:

- Your contributions will be licensed under the Apache 2.0 License
- You have the right to contribute the code
- Your contributions are for educational and defensive purposes only
