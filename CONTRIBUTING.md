# Contributing to Super Scripts

Thank you for your interest in contributing to Super Scripts! This document provides guidelines and best practices for contributing to the project.

## How to Contribute

### Reporting Issues
- Use the GitHub issue tracker to report bugs
- Include detailed reproduction steps
- Specify your environment (OS, Python version, etc.)
- Provide relevant error messages and logs

### Suggesting Features
- Check existing issues to avoid duplicates
- Clearly describe the feature and its benefits
- Explain the use case and target audience
- Consider implementation complexity and maintenance

### Code Contributions

1. **Fork the repository**
2. **Create a feature branch** (`git checkout -b feature/your-feature-name`)
3. **Make your changes** following the guidelines below
4. **Test your changes** thoroughly
5. **Commit with clear messages**
6. **Push to your branch**
7. **Create a Pull Request**

## Script Organization

### Directory Structure
Place scripts in the appropriate category:
- `security/` - Security testing and penetration testing tools
- `network/` - Network utilities and monitoring
- `system/` - System administration and maintenance
- `development/` - Development workflow utilities
- `automation/` - General automation and batch processing
- `web/` - Web scraping and API utilities

### File Naming
- Use descriptive, lowercase names with underscores: `port_scanner.py`
- Avoid abbreviations unless they're widely understood
- Include the main functionality in the name

## Code Standards

### Python Guidelines
- **Python 3.6+** compatibility
- Follow **PEP 8** style guidelines
- Use **type hints** where appropriate
- Include comprehensive **docstrings**

### Script Structure
```python
#!/usr/bin/env python3
"""
Script description and purpose.

Author: Your Name
Date: YYYY-MM-DD
Version: 1.0.0
"""

import argparse
import sys
from pathlib import Path

# Configuration constants at the top
DEFAULT_CONFIG = "config.ini"
OUTPUT_DIR = Path.home() / "script_output"

def main():
    """Main function with argument parsing."""
    parser = argparse.ArgumentParser(description="Script description")
    parser.add_argument("target", help="Target description")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()
    
    # Implementation here

if __name__ == "__main__":
    main()
```

### Error Handling
- Use try/except blocks for potential failure points
- Provide meaningful error messages
- Log errors appropriately
- Exit with appropriate exit codes

### Safety Features
- **Confirmation prompts** for destructive operations
- **Dry-run modes** for preview functionality
- **Input validation** and sanitization
- **Rate limiting** for network operations

## 🛡️ Security Considerations

### Security Scripts
- Include explicit **authorization checks**
- Add **confirmation prompts** before scanning
- Implement **rate limiting** to avoid overwhelming targets
- Provide **legal disclaimers** in documentation

## Documentation Requirements

### Script Documentation
Each script must include:
- **Purpose and functionality** description
- **Prerequisites** and dependencies
- **Usage examples** with common scenarios
- **Parameter descriptions**
- **Output format** explanation
- **Safety warnings** where applicable

### README Updates
- Add new scripts to the appropriate category README
- Update the main README if adding new categories
- Include installation instructions for dependencies
- Provide troubleshooting information

### Code Comments
- Comment complex algorithms and logic
- Explain non-obvious design decisions
- Document configuration parameters
- Include references to external resources

## Testing Guidelines

### Before Submitting
- **Test in multiple environments** (different OS, Python versions)
- **Verify all dependencies** are documented
- **Test error conditions** and edge cases
- **Run with various input parameters**
- **Check for resource leaks** (files, connections)

### Test Data
- Use **safe test targets** (localhost, test domains)
- Avoid **real production systems** in examples
- Include **sample configuration files**
- Provide **test datasets** where appropriate

## Pull Request Process

### Before Creating PR
1. Ensure your code follows all guidelines above
2. Test thoroughly in your environment
3. Update relevant documentation
4. Check that all files are properly committed

### PR Description
Include:
- **Summary** of changes
- **Motivation** for the change
- **Testing** performed
- **Breaking changes** if any
- **Related issues** (use "Fixes #123")

### Review Process
- Maintainers will review code quality and security
- Address feedback promptly and thoroughly
- Be patient during the review process
- Update documentation based on feedback

##  Important Notes

### Legal and Ethical
- Ensure contributions comply with applicable laws
- Only include tools for legitimate purposes
- Respect intellectual property rights
- Follow responsible disclosure practices

### Quality Standards
- Maintain high code quality standards
- Prioritize security and safety
- Focus on user experience and usability
- Consider long-term maintenance implications

## Getting Help

### Communication
- **GitHub Discussions** for general questions
- **GitHub Issues** for bugs and feature requests
- **Email maintainers** for security-sensitive topics

### Resources
- Check existing documentation first
- Review similar scripts for patterns
- Read category-specific guidelines
- Consult Python best practices guides

---

**Thank you for contributing to Super Scripts! Your contributions help make security testing and automation more accessible to everyone.**