# Super Scripts 🚀

A comprehensive collection of utility scripts organized by category, designed to streamline security testing, system administration, development workflows, and automation tasks.

## Repository Structure

```
super-scripts/
├── recon/           # Security assesment and discovery
├── More to come ...
```

## Script Categories

### [Recon](./recon/)
Tools for security assessment, and vulnerability research.
- **Enumeration Chain**: Automated reconnaissance and enumeration
- **Port Scanning**: Network service discovery(using nmap of course!)
- **Web Fuzzing**: Directory and parameter fuzzing(ffuf ftw)

## Quick Start

1. **Clone the repository:**
   ```bash
   git clone https://github.com/c3r35/super-scripts.git
   cd super-scripts
   ```

2. **Navigate to a category:**
   ```bash
   cd recon 
   ```

3. **Read the category README:**
   ```bash
   cat README.md
   ```

4. **Run a script:**
   ```bash
   python3 script_name.py --help
   ```

## Prerequisites

General requirements across most scripts:
- **Python 3.6+**
- **Appropriate permissions** (some scripts require sudo/root)
- **Category-specific tools** (detailed in each category's README)

## Important Notes

### Security Scripts
- **Authorization required**: Only use on systems you own or have explicit permission to test
- **Legal compliance**: Ensure all usage complies with applicable laws and regulations
- **Ethical usage**: Follow responsible disclosure practices

## Contributing

We welcome contributions! Please:

1. **Fork the repository**
2. **Create a feature branch** (`git checkout -b feature/new-script`)
3. **Follow the category conventions** (see individual README files)
4. **Add comprehensive documentation**
5. **Include error handling and safety checks**
6. **Test thoroughly**
7. **Submit a pull request**

See [CONTRIBUTING.md](./CONTRIBUTING.md) for detailed guidelines.

## Documentation

- **[Installation Guide](./docs/installation.md)** - Detailed setup instructions
- **[Usage Examples](./docs/usage-examples.md)** - Common use cases and examples
- **[Troubleshooting](./docs/troubleshooting.md)** - Common issues and solutions
- **Category READMEs** - Specific documentation for each script category

## Security & Legal

**This repository contains powerful tools that can affect system security and functionality.**

- **Use responsibly**: Only use these tools on systems you own or have explicit authorization to test
- **Legal compliance**: Users are responsible for ensuring compliance with all applicable laws
- **No warranty**: Tools are provided "as-is" without any guarantees
- **Educational purpose**: Intended for learning and authorized security testing only

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Thanks to all the open-source security and development tools that make these scripts possible
- Inspired by the need for organized, reusable utility scripts
- Built for the security and development community

## Support

- **Issues**: Report bugs and request features via [GitHub Issues]
- **Discussions**: Join conversations in [GitHub Discussions]  
- **Documentation**: Check category READMEs and docs/ directory

---

**⭐ Star this repository if you find it useful!**