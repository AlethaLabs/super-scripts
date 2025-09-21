# Security Scripts

This directory contains scripts focused on security testing, penetration testing, and security assessment tools.

## ⚠️ Important Security Notice

**These tools are for authorized security testing only.**
- Always ensure you have explicit written permission before testing any target
- Use these tools only on systems you own or have explicit authorization to test
- Be aware of your organization's policies and applicable laws
- These scripts can be detected by security monitoring systems

## Available Scripts

### `enum_fuzz_chain.py`
Automated enumeration script that chains together multiple reconnaissance tools for comprehensive target assessment.

**Features:**
- Subdomain discovery (subfinder/amass)
- Port scanning (nmap)
- Directory fuzzing (ffuf)
- Parameter fuzzing
- Organized timestamped output

**Usage:**
```bash
python3 enum_fuzz_chain.py example.com
python3 enum_fuzz_chain.py example.com --full -w /path/to/wordlist.txt
```

**Prerequisites:**
- `nmap` - Network scanner
- `ffuf` - Web fuzzer
- `subfinder` or `amass` (optional, for subdomain discovery)

## General Prerequisites

Most security scripts in this directory require:
- Linux/Unix environment
- Root/sudo privileges for some network operations
- Network connectivity
- Target authorization and scope documentation

## Best Practices

1. **Authorization**: Always obtain written permission before testing
2. **Documentation**: Keep detailed logs of all testing activities
3. **Timing**: Use appropriate delays to avoid overwhelming targets
4. **Scope**: Stay within defined testing boundaries
5. **Cleanup**: Remove any test files or artifacts after testing
6. **Reporting**: Document findings responsibly and securely

## Contributing

When adding new security scripts:
- Include comprehensive documentation
- Add appropriate warning messages
- Implement confirmation prompts for destructive operations
- Follow responsible disclosure principles
- Test scripts in isolated environments first

## Resources

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [Penetration Testing Execution Standard](http://www.pentest-standard.org/)

## Disclaimer

The authors and contributors are not responsible for any misuse of these tools. Users are solely responsible for ensuring their use complies with applicable laws and regulations.