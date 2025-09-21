#!/usr/bin/env python3
"""
Automated Enumeration Chain Script

This script performs a comprehensive enumeration workflow for web application security testing.
It combines subdomain enumeration, port scanning, directory fuzzing, and parameter discovery
in a single automated workflow.

Features:
- Subdomain enumeration using subfinder or amass
- Port scanning with nmap (quick and full scans)
- Directory/file fuzzing with ffuf
- Parameter discovery and testing
- Organized output structure with timestamps

Requirements:
- Python 3.6+
- nmap (sudo apt install nmap)
- ffuf (go install github.com/ffuf/ffuf@latest)
- subfinder (recommended) or amass for subdomain enumeration
- curl for connectivity testing

Usage Examples:
    # Basic enumeration
    python3 enumeration_chain.py example.com

    # With custom wordlist and thread count
    python3 enumeration_chain.py example.com -w /path/to/wordlist.txt -t 100

    # Full enumeration including comprehensive port scan
    python3 enumeration_chain.py example.com --full

Output Structure:
    ~/enumeration_results/
    └── target_YYYYMMDD_HHMMSS/
        ├── subdomains.txt           # Discovered subdomains
        ├── targets_urls.txt         # HTTP/HTTPS URLs for fuzzing
        ├── param_values.txt         # Parameter testing wordlist
        ├── nmap_quick.*             # Quick port scan results
        ├── nmap_full.*              # Full port scan results (if --full)
        ├── ffuf/                    # Directory fuzzing results
        │   ├── *.json               # FFUF JSON outputs
        │   └── *.log                # FFUF log files
        └── ffuf_params/             # Parameter fuzzing results
            ├── *.json               # Parameter test results
            └── *.log                # Parameter test logs

Author: Aletha Labs
License: MIT - Use responsibly and only on authorized targets
"""

import argparse
import subprocess
import os
import sys
import time
import shutil
from datetime import datetime
from pathlib import Path

# --- Configuration ---
# Common ports to scan during quick enumeration - focuses on web services and common admin ports
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 5900, 8080]

# Default number of concurrent threads for FFUF directory fuzzing
DEFAULT_FFUF_THREADS = 50

# Default wordlists for directory/file discovery (checked in order of preference)
DEFAULT_WORDLIST = ["/usr/share/wordlists/dirb/common.txt",
                    "/usr/share/seclists/Discovery/Web-Content/common.txt"]

# Common parameter names to test for functionality discovery and potential vulnerabilities
COMMON_PARAMS = ["id", "page", "lang", "user", "search", "q", "query", "file", "dir", "path", "view", "item", "cat", "category"
                 , "type", "sort", "order", "filter", "login", "session", "token", "next", "redirect", "return", "ref", 
                    "referrer"]

# Base output directory - results will be saved to timestamped subdirectories
OUT_BASE = Path.home() / "enumeration_results"

# --- Helper Functions ---
def cmd_exists(cmd):
    return shutil.which(cmd) is not None

# Run a command with optional output
def run(cmd, capture=False, check=False, cwd=None):
    if capture:
        return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=check, cwd=cwd)
    else:
        return subprocess.run(cmd, check=check, cwd=cwd)

# Ensure we have a valid wordlist to use for directory fuzzing    
def ensure_wordlist(provided):
    if provided:
        p = Path(provided)
        if not p.is_file():
            print(f"[!] Wordlist {provided} not found.")
            sys.exit(1)
        return [str(p)]
    for wl in DEFAULT_WORDLIST:
        if Path(wl).is_file():
            return [wl]
    print("[!]No default wordlist found. Please provide a valid wordlist.")
    sys.exit(1)

# Create a parameter-specific wordlist with common vulnerability indicators
def create_param_wordlist(out_dir):
    """
    Create a parameter-specific wordlist for better testing.
    
    Generates a wordlist containing values commonly used to test web application
    parameters for various vulnerabilities including SQL injection, XSS, path
    traversal, and command injection.
    
    Args:
        out_dir (Path): Output directory where wordlist will be created
        
    Returns:
        str: Path to the created parameter wordlist file
    """
    param_wordlist = out_dir / "param_values.txt"
    
    # Common parameter values that often reveal functionality
    param_values = [
        # Numeric tests
        "1", "0", "-1", "999", "1000",
        # Boolean tests  
        "true", "false", "yes", "no", "on", "off",
        # Path traversal indicators
        "../", "..\\", "../../../../etc/passwd",
        # SQL injection indicators
        "'", '"', "1'", "admin'--", 
        # XSS indicators
        "<script>", "javascript:", "alert(1)",
        # Command injection
        "|whoami", ";whoami", "`whoami`",
        # Common IDs and usernames
        "admin", "user", "test", "guest", "root",
        # File extensions
        ".php", ".jsp", ".asp", ".txt", ".log",
        # Common words that might trigger errors or different responses
        "error", "debug", "test", "config", "backup",
        # Empty and special values
        "", " ", "%20", "%00", "null",
    ]
    
    with open(param_wordlist, "w") as f:
        for value in param_values:
            f.write(value + "\n")
    
    return str(param_wordlist)

def main():
    """
    Main enumeration workflow orchestrator.
    
    Executes a comprehensive enumeration chain including:
    1. Subdomain enumeration (subfinder/amass)
    2. Port scanning (nmap quick + optional full scan)
    3. Directory/file fuzzing (ffuf)
    4. Parameter discovery and testing
    
    All results are saved to timestamped output directories with organized structure.
    """
    parser = argparse.ArgumentParser(
        description="Automated Enumeration Chain Script - Comprehensive web application security testing workflow",
        epilog="""
Examples:
  %(prog)s example.com                           # Basic enumeration with auto scope detection
  %(prog)s test.example.com --scope strict       # Only enumerate *.test.example.com
  %(prog)s test.example.com --scope broad        # Enumerate all *.example.com subdomains
  %(prog)s example.com -w /path/to/wordlist.txt  # Use custom wordlist for directory fuzzing
  %(prog)s example.com -t 100 --full             # High-speed scanning with full port enumeration
  
Output:
  Results are saved to ~/enumeration_results/TARGET_TIMESTAMP/ with organized subdirectories
  for each enumeration phase. Check the logs for detailed information and errors.
  
Security Notice:
  Only use this tool against targets you own or have explicit permission to test.
  Unauthorized scanning may be illegal in your jurisdiction.
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("target", help="Target IP address or domain name (e.g., example.com, 192.168.1.1)")
    parser.add_argument("-w", "--wordlist", 
                       help="Custom wordlist file for directory/file fuzzing (default: system wordlists)")
    parser.add_argument("-t", "--threads", type=int, default=DEFAULT_FFUF_THREADS,
                       help=f"Number of concurrent threads for FFUF fuzzing (default: {DEFAULT_FFUF_THREADS})")
    parser.add_argument("--full", action="store_true", 
                       help="Run comprehensive enumeration including full port scan (-p-) - slower but more thorough")
    parser.add_argument("--scope", choices=["auto", "broad", "strict"], default="auto",
                       help="""Enumeration scope control:
  'auto' - smart detection based on target (default)
  'broad' - enumerate all subdomains of root domain (e.g., *.uber.com for test.uber.com)
  'strict' - only enumerate under target domain (e.g., *.test.uber.com for test.uber.com)
  Use 'broad' for unrestricted assessments, 'strict' for scoped penetration tests""")
    args = parser.parse_args()

    target = args.target.strip()
    wordlist = ensure_wordlist(args.wordlist)
    threads = args.threads

    # Detect if target is already a subdomain
    target_parts = target.split('.')
    is_subdomain = len(target_parts) > 2
    parent_domain = '.'.join(target_parts[-2:]) if is_subdomain else target
    
    # Determine enumeration scope
    scope_mode = args.scope
    if scope_mode == "auto":
        # Auto-detect: if it's a subdomain, use strict scope; if root domain, use broad
        scope_mode = "strict" if is_subdomain else "broad"
    
    print(f"[*] Starting enumeration on {target}")
    if scope_mode == "strict":
        if is_subdomain:
            print(f"[*] STRICT SCOPE: Only enumerating sub-subdomains under '{target}'")
            print(f"[*] Will find domains like api.{target}, admin.{target}, etc.")
        else:
            print(f"[*] STRICT SCOPE: Only enumerating direct subdomains of '{target}'")
    else:  # broad mode
        if is_subdomain:
            print(f"[*] BROAD SCOPE: Enumerating all subdomains of parent domain '{parent_domain}'")
            print(f"[*] Will find ALL *.{parent_domain} domains (not just under {target})")
        else:
            print(f"[*] BROAD SCOPE: Enumerating all subdomains of '{target}'")
    print(f"[*] Output directory: {OUT_BASE}")
    
    # Ethical testing confirmation - ensure user has authorization
    confirm = input("Make sure you have permission to scan this target and are in scope. Continue? (y/n): ")

    if confirm.lower() != "y":
        print("[!] Aborting...")
        sys.exit(2)

    # Create timestamped output directory for organized results
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = OUT_BASE / f"{target}_{timestamp}"
    out_dir.mkdir(parents=True, exist_ok=True)

    # Verify all required tools are installed before proceeding
    required = ["nmap", "ffuf"]
    missing = [c for c in required if not cmd_exists(c)]
    if missing:
        print(f"[!] Missing required tools: {', '.join(missing)}")
        print("[!] Please install them and try again: Example: sudo apt install nmap, or use go get for ffuf")
        print("[!] Exiting...")
        sys.exit(3)

    # === SUBDOMAIN ENUMERATION PHASE ===
    subdomains_file = out_dir / "subdomains.txt"
    all_subdomains = set()
    
    # Always include the target (whether it's a domain or subdomain)
    all_subdomains.add(target)
    
    # Determine enumeration target and filtering based on scope mode
    if scope_mode == "broad":
        if is_subdomain:
            print(f"[*] Using BROAD scope - enumerating parent domain '{parent_domain}' for all subdomains")
            enumeration_target = parent_domain
            # Also add parent domain to results in broad mode
            all_subdomains.add(parent_domain)
            scope_filter = lambda domain: domain.endswith(f'.{parent_domain}') or domain == parent_domain
        else:
            print(f"[*] Using BROAD scope - enumerating all subdomains of '{target}'")
            enumeration_target = target
            scope_filter = lambda domain: domain.endswith(f'.{target}') or domain == target
    else:  # strict mode
        if is_subdomain:
            print(f"[*] Using STRICT scope - only enumerating sub-subdomains under '{target}'")
            enumeration_target = target
            scope_filter = lambda domain: domain.endswith(f'.{target}') or domain == target
        else:
            print(f"[*] Using STRICT scope - enumerating direct subdomains of '{target}'")
            enumeration_target = target
            scope_filter = lambda domain: domain.endswith(f'.{target}') or domain == target
    
    # Try multiple subdomain enumeration tools for better coverage
    print(f"[*] Starting {scope_mode} subdomain enumeration for {enumeration_target}...")
    
    # Enhanced Subfinder with better configuration
    if cmd_exists("subfinder"):
        print("[*] Running enhanced subfinder...")
        try:
            subfinder_out = out_dir / "subfinder_temp.txt"
            subfinder_cmd = [
                "subfinder",
                "-d", enumeration_target,
                "-o", str(subfinder_out),
                "-all",          # Use all sources
                "-recursive",    # Enable recursive subdomain enumeration
                "-timeout", "30", # 30 second timeout per source
                "-t", "50",      # 50 concurrent threads
                "-v"             # Verbose output
            ]
            
            print(f"[*] Subfinder command: {' '.join(subfinder_cmd)}")
            result = run(subfinder_cmd, capture=True, check=False)
            
            # Show subfinder output for debugging
            if result.stdout:
                print(f"[*] Subfinder stdout: {result.stdout[:300]}...")
            if result.stderr:
                print(f"[*] Subfinder stderr: {result.stderr[:300]}...")
            
            # Read results from subfinder and apply scope filtering
            if subfinder_out.exists():
                with open(subfinder_out, "r") as f:
                    for line in f:
                        subdomain = line.strip()
                        if subdomain and scope_filter(subdomain):
                            all_subdomains.add(subdomain)
                print(f"[+] Subfinder found {len(all_subdomains)} in-scope domains")
            else:
                print("[!] Subfinder output file not created")
                
        except Exception as e:
            print(f"[!] Error running enhanced subfinder: {e}")
    
    # Try assetfinder as additional source
    if cmd_exists("assetfinder"):
        print("[*] Running assetfinder...")
        try:
            assetfinder_cmd = ["assetfinder", "--subs-only", enumeration_target]
            result = run(assetfinder_cmd, capture=True, check=False)
            
            if result.stdout:
                initial_count = len(all_subdomains)
                for line in result.stdout.split('\n'):
                    subdomain = line.strip()
                    if subdomain and scope_filter(subdomain):
                        all_subdomains.add(subdomain)
                new_count = len(all_subdomains) - initial_count
                print(f"[+] Assetfinder added {new_count} new in-scope domains")
            
        except Exception as e:
            print(f"[!] Error running assetfinder: {e}")
    
    # Try findomain as additional source
    if cmd_exists("findomain"):
        print("[*] Running findomain...")
        try:
            findomain_cmd = ["findomain", "-t", enumeration_target, "-u"]
            result = run(findomain_cmd, capture=True, check=False)
            
            if result.stdout:
                initial_count = len(all_subdomains)
                for line in result.stdout.split('\n'):
                    subdomain = line.strip()
                    if subdomain and scope_filter(subdomain):
                        all_subdomains.add(subdomain)
                new_count = len(all_subdomains) - initial_count
                print(f"[+] Findomain added {new_count} new in-scope domains")
            
        except Exception as e:
            print(f"[!] Error running findomain: {e}")
    
    # Fallback to amass if other tools didn't work well
    if len(all_subdomains) <= 1 and cmd_exists("amass"):  # Only original target found
        try:
            print("[*] Running amass as fallback...")
            amass_cmd = [
                "amass", "enum",
                "-d", enumeration_target,
                "-timeout", "5",  # Shorter timeout as fallback
                "-passive",       # Passive only for speed
                "-v"
            ]
            
            print(f"[*] Amass command: {' '.join(amass_cmd)}")
            result = run(amass_cmd, capture=True, check=False)
            
            if result.stdout:
                initial_count = len(all_subdomains)
                for line in result.stdout.split('\n'):
                    subdomain = line.strip()
                    if subdomain and not subdomain.startswith('[') and scope_filter(subdomain):
                        all_subdomains.add(subdomain)
                new_count = len(all_subdomains) - initial_count
                print(f"[+] Amass added {new_count} new in-scope subdomains")
            
        except Exception as e:
            print(f"[!] Error running amass: {e}")
    
    # If still no results, try crt.sh via curl
    if len(all_subdomains) <= 1:
        print(f"[*] Trying crt.sh certificate transparency logs for {enumeration_target}...")
        try:
            crt_cmd = ["curl", "-s", f"https://crt.sh/?q=%25.{enumeration_target}&output=json"]
            result = run(crt_cmd, capture=True, check=False)
            
            if result.stdout and result.stdout.startswith('['):
                import json
                try:
                    crt_data = json.loads(result.stdout)
                    initial_count = len(all_subdomains)
                    for entry in crt_data:
                        if 'name_value' in entry:
                            names = entry['name_value'].split('\n')
                            for name in names:
                                name = name.strip()
                                if name and '*' not in name and scope_filter(name):
                                    all_subdomains.add(name)
                    new_count = len(all_subdomains) - initial_count
                    print(f"[+] crt.sh added {new_count} new in-scope subdomains")
                except json.JSONDecodeError:
                    print("[!] Failed to parse crt.sh response")
        except Exception as e:
            print(f"[!] Error querying crt.sh: {e}")
    
    # Always ensure the original target is included
    all_subdomains.add(target)
    
    # If we're targeting a subdomain and didn't find many results, try brute force
    if is_subdomain and len(all_subdomains) <= 2:
        print(f"[*] Limited results found. Trying brute force for sub-subdomains under {target}...")
        
        # Common subdomain prefixes for brute forcing
        common_prefixes = [
            "api", "admin", "www", "mail", "ftp", "test", "dev", "staging", "prod", "production",
            "demo", "beta", "alpha", "secure", "portal", "app", "web", "mobile", "m", "auth",
            "login", "dashboard", "panel", "control", "manage", "internal", "private", "public",
            "static", "assets", "cdn", "img", "images", "media", "upload", "download", "files",
            "docs", "help", "support", "blog", "news", "forum", "shop", "store", "payment", "pay"
        ]
        
        if cmd_exists("dig") or cmd_exists("nslookup"):
            print(f"[*] Brute forcing common subdomains under {target}...")
            initial_count = len(all_subdomains)
            
            for prefix in common_prefixes:
                test_domain = f"{prefix}.{target}"
                try:
                    # Use dig if available, otherwise nslookup
                    if cmd_exists("dig"):
                        result = run(["dig", "+short", test_domain], capture=True, check=False)
                    else:
                        result = run(["nslookup", test_domain], capture=True, check=False)
                    
                    # If we got an IP address response, the domain exists
                    if result.stdout and result.returncode == 0:
                        output = result.stdout.strip()
                        # Check for IP addresses (basic validation)
                        if any(c.isdigit() for c in output) and '.' in output and not 'not found' in output.lower():
                            if scope_filter(test_domain):
                                all_subdomains.add(test_domain)
                                print(f"[+] Found: {test_domain}")
                    
                    # Small delay to be polite
                    time.sleep(0.1)
                    
                except Exception as e:
                    pass  # Silently continue if DNS lookup fails
            
            new_count = len(all_subdomains) - initial_count
            if new_count > 0:
                print(f"[+] Brute force found {new_count} additional subdomains")
            else:
                print(f"[!] Brute force found no additional subdomains")
        else:
            print("[!] Neither dig nor nslookup available for brute force enumeration")
    
    # Write all discovered subdomains to file
    if all_subdomains:
        sorted_subdomains = sorted(all_subdomains)
        with open(subdomains_file, "w") as f:
            f.write("\n".join(sorted_subdomains) + "\n")
        
        total_count = len(all_subdomains)
        discovery_count = total_count - 1  # Subtract the original target
        
        if discovery_count > 0:
            print(f"[+] Total in-scope domains found: {total_count}")
            print(f"[+] Enumeration scope: {scope_mode.upper()} ({'*.'+parent_domain if scope_mode=='broad' and is_subdomain else '*.'+target})")
            discovered_domains = all_subdomains - {target}
            if discovered_domains:
                print(f"[+] Discovered in-scope: {', '.join(sorted(discovered_domains)[:10])}" + 
                      (f" ... and {len(discovered_domains) - 10} more" if len(discovered_domains) > 10 else ""))
        else:
            if is_subdomain:
                print(f"[!] No additional sub-subdomains found under {target}")
                print(f"    This means no domains like api.{target} or admin.{target} were discovered")
                print(f"    The enumeration will focus on the target subdomain: {target}")
            else:
                print(f"[!] No subdomains discovered. Consider:")
                print(f"    - Domain may not have subdomains")
                print(f"    - Installing additional tools: assetfinder, findomain")
                print(f"    - Configuring API keys for subfinder/amass")
                print(f"    - Manual verification with online tools (crt.sh, Shodan)")
    else:
        # Fallback - create file with just target
        with open(subdomains_file, "w") as f:
            f.write(f"{target}\n")
        print("[!] No enumeration tools found or no results - using target domain only")
    
    print(f"[+] Subdomains saved to: {subdomains_file}\n")

    # Clean up temporary files
    temp_files = [out_dir / "subfinder_temp.txt"]
    for temp_file in temp_files:
        if temp_file.exists():
            temp_file.unlink()

    # === PORT SCANNING PHASE ===
    # Quick nmap scan on common HTTP ports (-sT to avoid raw packet privileges requirement)
    nmap_quick_out = out_dir / "nmap_quick"
    print(f"[*] Running nmap quick scan on ports: {COMMON_PORTS}")
    try:
           run(["nmap", "-sT", "-Pn", "-T3", "-p", ",".join(str(p) for p in COMMON_PORTS), "-iL", str(subdomains_file), "-oA", str(nmap_quick_out)], check=True)
    except subprocess.CalledProcessError:
        print("[!] nmap quick scan returned a non-zero exit code (continuing).")
    print(f"[+] nmap quick outputs prefix: {nmap_quick_out}\n")

    # Optional comprehensive port scan - slower but finds non-standard services
    if args.full:
        ans = input("Proceed with full port scan (-p-)? This is slower and more intrusive (yes/no): ").strip().lower()
        if ans == "yes":
            nmap_full_out = out_dir / "nmap_full"
            print("[*] Running nmap full (-p-) with -T3 ...")
            try:
                run(["nmap", "-sT", "-Pn", "-T3", "-p-", "-iL", str(subdomains_file), "-oA", str(nmap_full_out)], check=True)
            except subprocess.CalledProcessError:
                print("[!] nmap full scan returned a non-zero exit code (continuing).")
            print(f"[+] nmap full outputs prefix: {nmap_full_out}\n")
        else:
            print("Skipped full port scan.\n")

    # === URL PREPARATION PHASE ===
    # Build targets_urls.txt (http & https) for comprehensive web testing
    url_file = out_dir / "targets_urls.txt"
    with open(subdomains_file, "r") as f_in, open(url_file, "w") as f_out:
        for ln in f_in:
            host = ln.strip()
            if not host:
                continue
            # Test both HTTP and HTTPS variants
            f_out.write(f"https://{host}\n")
            f_out.write(f"http://{host}\n")
    print(f"[+] Target URLs for fuzzing saved to: {url_file}\n")

    # === DIRECTORY/FILE FUZZING PHASE ===
    # Run ffuf directories per URL sequentially to avoid overwhelming targets
    ffuf_dir = out_dir / "ffuf"
    ffuf_dir.mkdir(exist_ok=True)
    print(f"[*] Starting ffuf directory fuzzing (sequential per URL) using wordlist: {wordlist}")
    with open(url_file, "r") as f:
        for line in f:
            base = line.strip()
            if not base:
                continue
            # Create safe filename from URL for output files
            safe_name = base.replace("://", "_").replace("/", "_").replace(":", "_")
            out_json = ffuf_dir / f"{safe_name}.json"
            out_log = ffuf_dir / f"{safe_name}.log"
            print(f"[ffuf] {base} -> {out_json.name}")
            ffuf_cmd = [
                "ffuf",
                "-u", f"{base}/FUZZ",
                "-w", wordlist[0],
                "-t", str(threads),
                "-mc", "200,301,302,307,403",  # Match interesting HTTP status codes
                "-of", "json",
                "-o", str(out_json)
            ]
            try:
                with open(out_log, "w") as logfh:
                    subprocess.run(ffuf_cmd, stdout=logfh, stderr=subprocess.STDOUT, check=False)
            except Exception as e:
                print(f"[!] ffuf error for {base}: {e}")
            # Polite pause between requests to avoid overwhelming target
            time.sleep(1)
    print(f"[+] ffuf outputs saved in {ffuf_dir}\n")

    # === PARAMETER DISCOVERY PHASE ===
    # Light parameter fuzzing to discover functionality and potential vulnerabilities
    param_out = out_dir / "ffuf_params"
    param_out.mkdir(exist_ok=True)
    print("[*] Running light parameter fuzzing against common parameter names")
    
    # Create parameter-specific wordlist with common vulnerability indicators
    param_wordlist = create_param_wordlist(out_dir)
    print(f"[+] Created parameter testing wordlist: {param_wordlist}")
    
    # First, validate which URLs are actually responding to avoid wasted effort
    live_urls = []
    print("[*] Checking which URLs are live before parameter testing...")
    with open(url_file, "r") as f:
        for line in f:
            base = line.strip()
            if not base:
                continue
            # Quick connectivity check using curl HEAD request
            try:
                result = subprocess.run(["curl", "-s", "-I", "-m", "10", base], 
                                      capture_output=True, text=True, timeout=15)
                if result.returncode == 0 and ("200 OK" in result.stdout or "301" in result.stdout or "302" in result.stdout):
                    live_urls.append(base)
                    print(f"[+] Live: {base}")
                else:
                    print(f"[-] Dead: {base}")
            except (subprocess.TimeoutExpired, Exception) as e:
                print(f"[-] Error checking {base}: {e}")
    
    if not live_urls:
        print("[!] No live URLs found for parameter testing")
    else:
        print(f"[+] Found {len(live_urls)} live URLs for parameter testing")
        
        for base in live_urls:
            # Create filesystem-safe filename from URL
            safe = base.replace("://", "_").replace("/", "_").replace(":", "_").replace("?", "_").replace("&", "_")
            print(f"[*] Parameter testing: {base}")
            
            # Test different parameter patterns to cover various application structures
            test_patterns = [
                f"{base}/?PARAM=test123",  # Simple query param
                f"{base}/index.php?PARAM=test123",  # Common PHP pattern
                f"{base}/search?PARAM=test123",  # Search endpoint
            ]
            
            # Handle URLs that already have query parameters
            if "?" in base:
                test_patterns = [f"{base}&PARAM=test123"]
            
            for pattern_idx, pattern in enumerate(test_patterns):
                for p in COMMON_PARAMS[:5]:  # Limit to top 5 params per pattern for efficiency
                    test_url = pattern.replace("PARAM", p)
                    out_file = param_out / f"{safe}_pattern{pattern_idx}_{p}.json"
                    out_log = param_out / f"{safe}_pattern{pattern_idx}_{p}.log"
                    
                    ffuf_cmd = [
                        "ffuf",
                        "-u", test_url.replace("test123", "FUZZ"),
                        "-w", param_wordlist,  # Use our specialized vulnerability-focused wordlist
                        "-t", "15",  # Reduced threads for politeness
                        "-mc", "200,301,302,307,403,500",  # Include 500 for error-based detection
                        "-ms", "1-50000",  # Size filter to catch responses
                        "-of", "json",
                        "-o", str(out_file),
                        "-s"  # Silent mode but still captures results
                    ]
                    
                    try:
                        with open(out_log, "w") as logfh:
                            result = subprocess.run(ffuf_cmd, stdout=logfh, stderr=logfh, 
                                                  timeout=60, check=False)
                        
                        # Check if we got any interesting results based on file size
                        if out_file.exists() and out_file.stat().st_size > 100:
                            print(f"[+] Potential hits: {p} in pattern {pattern_idx}")
                        
                    except subprocess.TimeoutExpired:
                        print(f"[!] Timeout for {base} param {p} pattern {pattern_idx}")
                    except Exception as e:
                        print(f"[!] Error testing {base} param {p}: {e}")
            
            # Respectful delay between targets to avoid overwhelming services
            time.sleep(2)  # Polite delay between targets
    
    print(f"[+] parameter fuzz outputs: {param_out}\n") 

if __name__ == "__main__":
    main()