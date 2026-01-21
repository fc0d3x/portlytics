#!/usr/bin/env python3
"""
PORTLYTICS - Network Port Analytics & Vulnerability Intelligence
Clean, consolidated version with Nuclei and OSINT integration
"""

import argparse
import socket
import time
import subprocess
import requests
import os
import sys
import threading
from ipaddress import ip_address
from concurrent.futures import ThreadPoolExecutor, as_completed

# Disable SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

# -----------------------------
# Banner
# -----------------------------
BANNER = r"""
██████╗  ██████╗ ██████╗ ████████╗██╗  ██╗   ██╗████████╗██╗ ██████╗███████╗
██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝██║  ╚██╗ ██╔╝╚══██╔══╝██║██╔════╝██╔════╝
██████╔╝██║   ██║██████╔╝   ██║   ██║   ╚████╔╝    ██║   ██║██║     ███████╗
██╔═══╝ ██║   ██║██╔══██╗   ██║   ██║    ╚██╔╝     ██║   ██║██║     ╚════██║
██║     ╚██████╔╝██║  ██║   ██║   ███████╗██║      ██║   ██║╚██████╗███████║
╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝      ╚═╝   ╚═╝ ╚═════╝╚══════╝
Network Port Analytics & Vulnerability Intelligence
"""

# -----------------------------
# Progress Bar
# -----------------------------
class Progress:
    def __init__(self):
        self.last_len = 0
        self._lock = threading.Lock()

    def update(self, pct: float, label: str):
        with self._lock:
            pct = max(0.0, min(100.0, pct))
            bar_len = 34
            filled = int(round((pct / 100.0) * bar_len))
            bar = "█" * filled + "░" * (bar_len - filled)
            msg = f"\r[{bar}] {pct:6.2f}% | {label}"
            pad = max(0, self.last_len - len(msg))
            sys.stdout.write(msg + (" " * pad))
            sys.stdout.flush()
            self.last_len = len(msg)

    def done(self):
        sys.stdout.write("\n")
        sys.stdout.flush()

# -----------------------------
# Scan Profiles
# -----------------------------
PROFILES = {
    "stealth": {
        "timeout": 4.0,
        "workers": 15,
        "delay": (2.0, 6.0),
        "nmap_base": "-sS -Pn -n --max-retries 1",
        "nmap_udp": "-sU",
        "nmap_timing": "-T0",
        "nmap_evasion": "-f --data-length 8 --decoy 8.8.8.8,1.1.1.1,192.0.2.1,ME --spoof-mac 0",
        "description": "Maximum stealth with fragmentation, decoys, timing delays"
    },
    "fast": {
        "timeout": 1.0,
        "workers": 100,
        "delay": None,
        "nmap_base": "-sT -sV -Pn -n",
        "nmap_udp": "-sU",
        "nmap_timing": "-T3",
        "nmap_evasion": "",
        "description": "Balanced speed and reliability"
    },
    "aggressive": {
        "timeout": 0.25,
        "workers": 600,
        "delay": None,
        "nmap_base": "-sS -sV -Pn -n --min-rate 1000",
        "nmap_udp": "-sU",
        "nmap_timing": "-T5",
        "nmap_evasion": "",
        "description": "Maximum speed, no stealth"
    }
}

# -----------------------------
# Confidence Score
# -----------------------------
def confidence_score(product, version, evidence):
    """Calculate confidence score for service detection"""
    score = 0
    product_l = (product or "").lower()
    version_l = (version or "").lower()

    if product:
        score += 30
    if version:
        score += 20
    
    server_hdr = [e for e in evidence if "server:" in e.lower()]
    if server_hdr:
        score += 25
        if product_l and any(product_l in e.lower() for e in server_hdr):
            score += 10
        if version_l and any(version_l in e.lower() for e in server_hdr):
            score += 10
    
    if any("x-powered-by" in e.lower() for e in evidence):
        score += 5
    if any("nmap" in e.lower() for e in evidence):
        score += 10

    score = min(100, score)
    
    if score >= 80:
        return score, "High"
    elif score >= 55:
        return score, "Medium"
    return score, "Low"

# -----------------------------
# CVSS Severity Color Mapping
# -----------------------------
def get_cvss_severity_color(score):
    """Map CVSS score to severity rating and color"""
    # ANSI color codes
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    ORANGE = "\033[33m"
    RED = "\033[91m"
    BOLD_RED = "\033[1;91m"
    RESET = "\033[0m"
    
    # Handle N/A or invalid scores
    if score == "N/A" or score is None:
        return "Unknown", ""
    
    try:
        score_float = float(score)
    except (ValueError, TypeError):
        return "Unknown", ""
    
    if score_float == 0.0:
        return f"{GREEN}None{RESET}", GREEN
    elif 0.1 <= score_float <= 3.9:
        return f"{YELLOW}Low{RESET}", YELLOW
    elif 4.0 <= score_float <= 6.9:
        return f"{ORANGE}Medium{RESET}", ORANGE
    elif 7.0 <= score_float <= 8.9:
        return f"{RED}High{RESET}", RED
    elif 9.0 <= score_float <= 10.0:
        return f"{BOLD_RED}Critical{RESET}", BOLD_RED
    else:
        return "Unknown", ""

# -----------------------------
# NVD CVE Lookup
# -----------------------------
def nvd_lookup(product, version, limit=8):
    """Query NVD (National Vulnerability Database) for CVEs"""
    if not product:
        return []
    
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    query = f"{product} {version}".strip()
    
    try:
        r = requests.get(url, params={"keywordSearch": query, "resultsPerPage": limit}, timeout=12)
        if r.status_code != 200:
            return []
        
        data = r.json()
        cves = []
        
        for v in data.get("vulnerabilities", [])[:limit]:
            cve = v.get("cve", {})
            cve_id = cve.get("id")
            metrics = cve.get("metrics", {})
            
            score = None
            severity = None
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                arr = metrics.get(key)
                if arr and isinstance(arr, list):
                    cv = arr[0].get("cvssData", {})
                    score = cv.get("baseScore")
                    severity = cv.get("baseSeverity") or severity
                    if score:
                        break
            
            cves.append({
                "id": cve_id,
                "score": score or "N/A",
                "severity": severity or "Unknown",
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            })
        
        return cves
    except Exception:
        return []

# -----------------------------
# SearchSploit (ExploitDB)
# -----------------------------
def searchsploit_lookup(query, limit=10):
    """Search ExploitDB using searchsploit"""
    try:
        result = subprocess.run(
            ["searchsploit", "--disable-color", "-w", query],
            capture_output=True,
            text=True,
            timeout=10
        )
        lines = []
        for line in result.stdout.splitlines():
            line_lower = line.lower()
            # Filter out junk lines
            if (line.strip() and 
                not line_lower.startswith("exploit") and 
                not line_lower.startswith("shellcode") and
                "no results" not in line_lower and
                not set(line.strip()) <= {"-", " "}):
                lines.append(line)
        return lines[:limit]
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return []

# -----------------------------
# Metasploit Module Search
# -----------------------------
def metasploit_search(query, limit=10):
    """Search for Metasploit modules using searchsploit"""
    try:
        # SearchSploit can filter for Metasploit modules
        result = subprocess.run(
            ["searchsploit", "--disable-color", "-w", "-m", query],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        modules = []
        for line in result.stdout.splitlines():
            if "metasploit" in line.lower() or "exploit/multi/" in line.lower() or "auxiliary/" in line.lower():
                modules.append(line.strip())
        
        return modules[:limit]
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return []

# -----------------------------
# GitHub Security Advisory (GHSA) Lookup
# -----------------------------
def github_advisory_lookup(product, version=None, limit=8):
    """Search GitHub Security Advisories for vulnerabilities"""
    if not product:
        return []
    
    # GitHub Advisory Database API
    url = "https://api.github.com/advisories"
    query = f"{product} {version}".strip() if version else product
    
    # Check for GitHub token (optional, but increases rate limit)
    github_token = os.environ.get("GITHUB_TOKEN", "").strip()
    headers = {"Accept": "application/vnd.github+json"}
    if github_token:
        headers["Authorization"] = f"Bearer {github_token}"
    
    try:
        params = {
            "keywords": query,
            "per_page": limit,
            "type": "reviewed"
        }
        r = requests.get(url, params=params, headers=headers, timeout=12)
        
        if r.status_code == 403:
            return [{"error": "Rate limited - set GITHUB_TOKEN for higher limits"}]
        if r.status_code != 200:
            return []
        
        advisories = []
        for adv in r.json()[:limit]:
            ghsa_id = adv.get("ghsa_id", "Unknown")
            cve_id = adv.get("cve_id", "N/A")
            severity = adv.get("severity", "Unknown")
            summary = adv.get("summary", "")[:100]
            
            # Map severity to color
            severity_colors = {
                "critical": "\033[1;91m",  # Bold red
                "high": "\033[91m",        # Red
                "medium": "\033[33m",      # Orange
                "low": "\033[93m",         # Yellow
            }
            color = severity_colors.get(severity.lower(), "")
            reset = "\033[0m" if color else ""
            
            advisories.append({
                "ghsa_id": ghsa_id,
                "cve_id": cve_id,
                "severity": f"{color}{severity.capitalize()}{reset}" if color else severity.capitalize(),
                "severity_raw": severity,
                "summary": summary,
                "url": adv.get("html_url", f"https://github.com/advisories/{ghsa_id}")
            })
        
        return advisories
    except Exception:
        return []

# -----------------------------
# GitHub Exploit/PoC Search
# -----------------------------
def github_exploit_search(product, version=None, cve_id=None, limit=8):
    """Search GitHub for exploit code and PoCs"""
    results = []
    
    # Check for GitHub token
    github_token = os.environ.get("GITHUB_TOKEN", "").strip()
    headers = {"Accept": "application/vnd.github+json"}
    if github_token:
        headers["Authorization"] = f"Bearer {github_token}"
    
    # Build search queries
    queries = []
    if cve_id:
        queries.append(f"{cve_id} exploit OR PoC OR proof-of-concept")
    if product:
        base_query = f"{product}"
        if version:
            base_query += f" {version}"
        queries.append(f"{base_query} exploit OR vulnerability OR RCE OR CVE")
    
    try:
        for query in queries[:2]:  # Limit to 2 queries to avoid rate limiting
            url = "https://api.github.com/search/repositories"
            params = {
                "q": query,
                "sort": "stars",
                "order": "desc",
                "per_page": limit
            }
            
            r = requests.get(url, params=params, headers=headers, timeout=12)
            
            if r.status_code == 403:
                return [{"error": "Rate limited - set GITHUB_TOKEN for higher limits"}]
            if r.status_code != 200:
                continue
            
            data = r.json()
            for repo in data.get("items", [])[:limit]:
                # Filter for likely exploit/PoC repos
                name = repo.get("name", "").lower()
                desc = (repo.get("description") or "").lower()
                
                exploit_keywords = ["exploit", "poc", "cve", "vulnerability", "rce", "payload", "shell"]
                if any(kw in name or kw in desc for kw in exploit_keywords):
                    results.append({
                        "name": repo.get("full_name"),
                        "description": (repo.get("description") or "")[:80],
                        "stars": repo.get("stargazers_count", 0),
                        "url": repo.get("html_url"),
                        "updated": repo.get("updated_at", "")[:10]
                    })
            
            # Small delay between requests
            time.sleep(0.5)
        
        # Deduplicate by repo name
        seen = set()
        unique_results = []
        for r in results:
            if r["name"] not in seen:
                seen.add(r["name"])
                unique_results.append(r)
        
        return sorted(unique_results, key=lambda x: x["stars"], reverse=True)[:limit]
    
    except Exception:
        return []

# -----------------------------
# Utilities
# -----------------------------
def is_private_ip(ip: str) -> bool:
    try:
        addr = ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except Exception:
        return False

def resolve_target(target: str) -> str:
    """Resolve hostname to IP address if needed"""
    # Check if it's already a valid IP
    try:
        ip_address(target)
        return target
    except ValueError:
        pass
    
    # Try to resolve as hostname
    try:
        ip = socket.gethostbyname(target)
        print(f"[*] Resolved {target} to {ip}")
        return ip
    except socket.gaierror:
        raise ValueError(f"Cannot resolve hostname: {target}")

def parse_ports(s):
    """Parse port range (e.g., '1-1000' or '80,443,8080')"""
    ports = set()
    for part in s.split(','):
        if '-' in part:
            a, b = map(int, part.split('-'))
            ports.update(range(a, b + 1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 1 <= p <= 65535)

# -----------------------------
# TCP Port Scan
# -----------------------------
def scan_port(ip: str, port: int, timeout: float, delay) -> bool:
    """Scan a single port"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port)) == 0
            if delay:
                if isinstance(delay, tuple):
                    # Random delay between min and max
                    import random
                    time.sleep(random.uniform(delay[0], delay[1]))
                else:
                    time.sleep(delay)
            return result
    except Exception:
        return False

def tcp_scan(ip: str, ports, profile, progress):
    """Scan all ports with progress tracking"""
    open_ports = []
    total = len(ports)
    done = 0
    lock = threading.Lock()

    def probe(p):
        nonlocal done
        result = scan_port(ip, p, profile["timeout"], profile["delay"])
        with lock:
            if result:
                open_ports.append(p)
            done += 1
            pct = (done / total) * 100
            progress.update(pct, f"Port scan {done}/{total}")

    with ThreadPoolExecutor(max_workers=profile["workers"]) as ex:
        ex.map(probe, ports)

    return sorted(open_ports)

# -----------------------------
# UDP Port Scan
# -----------------------------
def udp_scan(ip: str, ports, profile, progress):
    """Scan UDP ports using basic socket probe"""
    open_ports = []
    total = len(ports)
    done = 0
    lock = threading.Lock()

    def probe(p):
        nonlocal done
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(profile["timeout"])
                # Send empty UDP packet
                s.sendto(b'', (ip, p))
                try:
                    # Try to receive response
                    data, addr = s.recvfrom(1024)
                    result = True
                except socket.timeout:
                    # No response might mean open|filtered
                    result = True
                
                with lock:
                    if result:
                        open_ports.append(p)
                    done += 1
                    pct = (done / total) * 100
                    progress.update(pct, f"UDP scan {done}/{total}")
        except Exception:
            with lock:
                done += 1
                pct = (done / total) * 100
                progress.update(pct, f"UDP scan {done}/{total}")

    with ThreadPoolExecutor(max_workers=profile["workers"]) as ex:
        ex.map(probe, ports)

    return sorted(open_ports)

# -----------------------------
# Service Detection (nmap)
# -----------------------------
def detect_services(ip: str, tcp_ports: list, udp_ports: list, progress, profile):
    """Use nmap to detect services and versions"""
    if not NMAP_AVAILABLE:
        print("\n⚠️  python-nmap not installed. Skipping service detection.")
        print("   Install with: pip install python-nmap")
        return {}, {}
    
    tcp_services = {}
    udp_services = {}
    
    # TCP scan
    if tcp_ports:
        try:
            nm = nmap.PortScanner()
            port_arg = ",".join(map(str, tcp_ports))
            nmap_args = f"{profile.get('nmap_base', '-sV')} {profile.get('nmap_timing', '-T3')} {profile.get('nmap_evasion', '')}".strip()
            
            progress.update(0, "TCP service detection...")
            nm.scan(ip, port_arg, arguments=nmap_args)
            progress.update(50, "TCP service detection complete")
            
            tcp = nm[ip].get("tcp", {})
            for p, d in tcp.items():
                tcp_services[p] = {
                    "name": d.get("name", "unknown"),
                    "product": d.get("product", ""),
                    "version": d.get("version", ""),
                    "extrainfo": d.get("extrainfo", "")
                }
        except Exception as e:
            print(f"\n⚠️  TCP service detection failed: {str(e)}")
    
    # UDP scan
    if udp_ports:
        try:
            nm = nmap.PortScanner()
            port_arg = ",".join(map(str, udp_ports))
            nmap_args = f"{profile.get('nmap_udp', '-sU')} -sV {profile.get('nmap_timing', '-T3')}".strip()
            
            progress.update(50, "UDP service detection...")
            nm.scan(ip, port_arg, arguments=nmap_args)
            progress.update(100, "UDP service detection complete")
            
            udp = nm[ip].get("udp", {})
            for p, d in udp.items():
                udp_services[p] = {
                    "name": d.get("name", "unknown"),
                    "product": d.get("product", ""),
                    "version": d.get("version", ""),
                    "extrainfo": d.get("extrainfo", "")
                }
        except Exception as e:
            print(f"\n⚠️  UDP service detection failed: {str(e)}")
    
    return tcp_services, udp_services

# -----------------------------
# Nuclei Scanner
# -----------------------------
def run_nuclei(ip: str, ports: list):
    """Run Nuclei vulnerability scanner on web ports"""
    # Check if nuclei is installed
    try:
        subprocess.run(["nuclei", "-version"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return {"status": "missing", "results": []}

    # Find web ports
    web_ports = [p for p in ports if p in [80, 443, 8080, 8000, 8443]]
    if not web_ports:
        return {"status": "skipped", "results": [], "reason": "No web ports found"}

    # Show Nuclei banner and version
    print()
    try:
        # Run nuclei -version to show the official banner/logo
        result = subprocess.run(["nuclei", "-version"], capture_output=False, text=True)
    except Exception:
        pass
    print("\n[*] Running Nuclei vulnerability scanner...")
    print()
    
    all_results = []

    for port in web_ports:
        proto = "https" if port == 443 else "http"
        url = f"{proto}://{ip}:{port}"
        
        # Progress indicator
        import threading
        stop_indicator = threading.Event()
        
        def show_progress():
            spinner = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
            idx = 0
            start_time = time.time()
            while not stop_indicator.is_set():
                elapsed = int(time.time() - start_time)
                sys.stdout.write(f"\r{spinner[idx % len(spinner)]} Nuclei scanning {url} ... ({elapsed}s elapsed)")
                sys.stdout.flush()
                time.sleep(0.1)
                idx += 1
        
        progress_thread = threading.Thread(target=show_progress)
        progress_thread.daemon = True
        progress_thread.start()
        
        try:
            result = subprocess.run(
                ["nuclei", "-u", url, "-silent"],
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes instead of 2
            )
            
            findings = [line.strip() for line in result.stdout.splitlines() if line.strip()]
            if findings:
                all_results.extend(findings)
        except subprocess.TimeoutExpired:
            all_results.append(f"[{url}] Scan timed out")
        except Exception as e:
            all_results.append(f"[{url}] Error: {str(e)}")
        finally:
            stop_indicator.set()
            progress_thread.join(timeout=1)
            sys.stdout.write("\r" + " " * 80 + "\r")  # Clear the line
            sys.stdout.flush()

    return {"status": "ok", "results": all_results}

# -----------------------------
# Shodan OSINT
# -----------------------------
def shodan_lookup(ip: str):
    """Query Shodan API for IP information"""
    api_key = os.environ.get("SHODAN_API_KEY", "").strip()
    if not api_key:
        return {"status": "missing_key", "error": "SHODAN_API_KEY not set"}

    try:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        data = r.json()

        # Extract key information
        return {
            "status": "ok",
            "org": data.get("org", "Unknown"),
            "isp": data.get("isp", "Unknown"),
            "asn": data.get("asn", "Unknown"),
            "country": data.get("country_name", "Unknown"),
            "city": data.get("city", "Unknown"),
            "ports": data.get("ports", []),
            "vulns": list(data.get("vulns", {}).keys()) if isinstance(data.get("vulns"), dict) else [],
            "tags": data.get("tags", []),
            "last_update": data.get("last_update", "Unknown")
        }
    except requests.exceptions.HTTPError as e:
        return {"status": "error", "error": f"HTTP {e.response.status_code}"}
    except Exception as e:
        return {"status": "error", "error": str(e)}

# -----------------------------
# theHarvester OSINT
# -----------------------------
def run_theharvester(target: str):
    """Run theHarvester for domain reconnaissance"""
    try:
        subprocess.run(["theHarvester", "-h"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return {"status": "missing", "results": []}

    print("[*] Running theHarvester - all sources (this may take 10-15 minutes)...")
    
    try:
        result = subprocess.run(
            ["theHarvester", "-d", target, "-b", "all"],
            capture_output=True,
            text=True,
            timeout=900  # 15 minutes
        )
        
        output = result.stdout.splitlines()
        return {"status": "ok", "results": output}
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "results": []}
    except Exception as e:
        return {"status": "error", "error": str(e)}

# -----------------------------
# Main Scan Function
# -----------------------------
def main():
    # Check for -h first (basic help)
    if len(sys.argv) == 2 and sys.argv[1] == '-h':
        print(BANNER)
        print("\n" + "=" * 70)
        print("BASIC USAGE")
        print("=" * 70)
        print("\nSyntax: portlytics.py <target> <ports> [options]\n")
        print("Examples:")
        print("  portlytics.py 192.168.1.1 1-1000")
        print("  portlytics.py example.com 80,443,8080 --udp")
        print("  portlytics.py target.com 1-65535 --profile stealth")
        print("\nFor detailed help, use: --help")
        print("=" * 70)
        sys.exit(0)
    
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="PORTLYTICS - Network Port Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
SCAN PROFILES:
  stealth      Maximum stealth with fragmentation, decoys, timing delays
               (Timeout: 4.0s, Workers: 15, Delay: 2-6s)
  
  fast         Balanced speed and reliability (DEFAULT)
               (Timeout: 1.0s, Workers: 100, No delay)
  
  aggressive   Maximum speed, no stealth
               (Timeout: 0.25s, Workers: 600, No delay)

EXAMPLES:
  Basic TCP scan:
    portlytics.py 192.168.1.1 1-1000

  TCP + UDP scan with stealth:
    portlytics.py example.com 1-65535 --profile stealth --udp

  Fast scan on common ports:
    portlytics.py target.com 21,22,23,25,53,80,443,445,3306,8080

  Aggressive scan without OSINT:
    portlytics.py 10.0.0.1 1-10000 --profile aggressive --no-osint

  Skip Nuclei vulnerability scan:
    portlytics.py example.com 80,443,8080 --no-nuclei

FEATURES:
  • TCP & UDP port scanning with multi-threading
  • Service detection and version identification (nmap)
  • CVE lookup from National Vulnerability Database (NVD)
  • GitHub Security Advisories (GHSA) lookup
  • GitHub exploit/PoC repository search
  • Color-coded CVSS severity ratings
  • ExploitDB and Metasploit module detection
  • Nuclei vulnerability scanner integration
  • Shodan OSINT (requires SHODAN_API_KEY env variable)
  • theHarvester domain reconnaissance

REQUIREMENTS:
  Required:  python-nmap, requests, urllib3
  Optional:  nmap, nuclei, searchsploit, theHarvester

ENVIRONMENT VARIABLES:
  SHODAN_API_KEY   - Shodan API key for OSINT lookups
  GITHUB_TOKEN     - GitHub token for higher API rate limits (optional)

LEGAL NOTICE:
  Only scan networks you own or have permission to test.
  Unauthorized scanning may be illegal in your jurisdiction.
        """
    )
    
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("ports", help="Port range (e.g., 1-1000 or 80,443,8080)")
    parser.add_argument("--profile", choices=PROFILES.keys(), default="fast",
                        help="Scan profile: stealth, fast, aggressive (default: fast)")
    parser.add_argument("--udp", action="store_true", help="Enable UDP port scanning")
    parser.add_argument("--no-nuclei", action="store_true", help="Skip Nuclei vulnerability scanner")
    parser.add_argument("--no-osint", action="store_true", help="Skip OSINT lookups (Shodan, theHarvester)")
    parser.add_argument("--no-github", action="store_true", help="Skip GitHub lookups (advisories, exploits)")
    
    args = parser.parse_args()

    # Resolve hostname or validate IP
    try:
        target_ip = resolve_target(args.target)
    except ValueError as e:
        print(f"[!] {e}")
        return

    # Parse ports
    try:
        ports = parse_ports(args.ports)
    except Exception as e:
        print(f"[!] Invalid port specification: {e}")
        return

    profile = PROFILES[args.profile]

    # Print scan header
    print("=" * 70)
    print(f"[*] Scanning: {args.target} ({target_ip})")
    print(f"[*] Profile: {args.profile} - {profile['description']}")
    if args.udp:
        print(f"[*] UDP scan: Enabled")
    print("=" * 70)
    print()

    # Stage 1: Port Scan
    progress = Progress()
    tcp_ports = tcp_scan(target_ip, ports, profile, progress)
    progress.done()

    udp_ports = []
    if args.udp:
        print()
        progress_udp = Progress()
        udp_ports = udp_scan(target_ip, ports, profile, progress_udp)
        progress_udp.done()

    if not tcp_ports and not udp_ports:
        print("[!] No open ports found")
        return

    # Stage 2: Service Detection
    print()
    progress2 = Progress()
    tcp_services, udp_services = detect_services(target_ip, tcp_ports, udp_ports, progress2, profile)
    progress2.done()

    # Print results table
    print("\nPORT     STATE  SERVICE       VERSION")
    print("----     -----  -------       -------")

    for port in tcp_ports:
        svc = tcp_services.get(port, {})
        service = svc.get("name", "unknown")
        product = svc.get("product", "")
        version = svc.get("version", "")
        extrainfo = svc.get("extrainfo", "")
        
        # Build version string
        version_parts = [product, version, extrainfo]
        version_display = " ".join(p for p in version_parts if p).strip() or "?"
        
        print(f"{str(port) + '/tcp':<9}open   {service:<13}{version_display}")
    
    for port in udp_ports:
        svc = udp_services.get(port, {})
        service = svc.get("name", "unknown")
        product = svc.get("product", "")
        version = svc.get("version", "")
        extrainfo = svc.get("extrainfo", "")
        
        # Build version string
        version_parts = [product, version, extrainfo]
        version_display = " ".join(p for p in version_parts if p).strip() or "?"
        
        print(f"{str(port) + '/udp':<9}open   {service:<13}{version_display}")
    
    # Detailed analysis for each port
    print("\n" + "=" * 70)
    print("[*] DETAILED SERVICE ANALYSIS")
    print("=" * 70)
    
    all_ports = [(p, 'tcp', tcp_services) for p in tcp_ports] + [(p, 'udp', udp_services) for p in udp_ports]
    
    # Collect CVE IDs for GitHub exploit search
    found_cves = []
    
    for port, proto, services in all_ports:
        svc = services.get(port, {})
        service = svc.get("name", "unknown")
        product = svc.get("product", "")
        version = svc.get("version", "")
        
        print(f"\n[Port {port}/{proto}]")
        print(f"  Service: {service}")
        if product:
            version_str = f"{product} {version}".strip()
            print(f"  Product: {version_str}")
        
        # Build evidence for confidence score
        evidence = []
        if product:
            evidence.append(f"Nmap product: {product}")
        if version:
            evidence.append(f"Nmap version: {version}")
        
        # NVD CVE Lookup
        if product:
            print(f"\n  [CVE - National Vulnerability Database]")
            cves = nvd_lookup(product, version)
            if cves:
                print(f"  Found {len(cves)} CVEs:")
                for cve in cves[:5]:
                    severity_colored, _ = get_cvss_severity_color(cve['score'])
                    print(f"    - {cve['id']} | CVSS: {cve['score']} | Severity: {severity_colored}")
                    print(f"      {cve['url']}")
                    found_cves.append(cve['id'])
            else:
                print(f"  No CVEs found in NVD")
        
        # GitHub Security Advisories
        if product and not args.no_github:
            print(f"\n  [GitHub Security Advisories]")
            advisories = github_advisory_lookup(product, version)
            if advisories:
                if "error" in advisories[0]:
                    print(f"  {advisories[0]['error']}")
                else:
                    print(f"  Found {len(advisories)} advisories:")
                    for adv in advisories[:5]:
                        cve_str = f" ({adv['cve_id']})" if adv['cve_id'] != "N/A" else ""
                        print(f"    - {adv['ghsa_id']}{cve_str} | Severity: {adv['severity']}")
                        if adv['summary']:
                            print(f"      {adv['summary']}")
                        print(f"      {adv['url']}")
            else:
                print(f"  No advisories found")
        
        # GitHub Exploit/PoC Search
        if product and not args.no_github:
            print(f"\n  [GitHub Exploits/PoCs]")
            # Search using product and any CVEs found
            cve_to_search = found_cves[0] if found_cves else None
            exploits = github_exploit_search(product, version, cve_to_search)
            if exploits:
                if "error" in exploits[0]:
                    print(f"  {exploits[0]['error']}")
                else:
                    print(f"  Found {len(exploits)} potential exploits/PoCs:")
                    for exp in exploits[:5]:
                        stars = f"⭐ {exp['stars']}" if exp['stars'] > 0 else ""
                        print(f"    - {exp['name']} {stars}")
                        if exp['description']:
                            print(f"      {exp['description']}")
                        print(f"      {exp['url']}")
            else:
                print(f"  No exploits/PoCs found")
        
        # SearchSploit ExploitDB lookup
        if product:
            print(f"\n  [ExploitDB]")
            exploits = searchsploit_lookup(f"{product} {version}")
            if exploits:
                print(f"  ExploitDB matches: {len(exploits)}")
                for exp in exploits[:3]:
                    print(f"    - {exp[:120]}")
            else:
                # Check if searchsploit is installed
                try:
                    subprocess.run(["which", "searchsploit"], capture_output=True, check=True)
                    print(f"  No exploits found")
                except:
                    print(f"  searchsploit not installed")
        
        # Metasploit Modules (MOST IMPORTANT!)
        if product:
            print(f"\n  [Metasploit Modules]")
            msf_modules = metasploit_search(f"{product} {version}")
            if msf_modules:
                print(f"  Metasploit matches: {len(msf_modules)}")
                for mod in msf_modules[:5]:
                    print(f"    - {mod[:120]}")
            else:
                try:
                    subprocess.run(["which", "searchsploit"], capture_output=True, check=True)
                    print(f"  No Metasploit modules found")
                except:
                    print(f"  searchsploit not installed (needed for MSF search)")
        
        # Confidence score
        score, label = confidence_score(product, version, evidence)
        print(f"\n  Confidence: {label} ({score}/100)")

    # Stage 3: Nuclei Scan (only for TCP web ports)
    if not args.no_nuclei:
        nuclei_result = run_nuclei(target_ip, tcp_ports)
        
        if nuclei_result["status"] == "ok":
            if nuclei_result["results"]:
                print("\n" + "=" * 70)
                print("[*] NUCLEI VULNERABILITY SCAN")
                print("=" * 70)
                for finding in nuclei_result["results"]:
                    print(f"  {finding}")
            else:
                print("\n[*] Nuclei: No vulnerabilities found")
        elif nuclei_result["status"] == "missing":
            print("\n[!] Nuclei not installed - skipping vulnerability scan")
            print("    Install: https://github.com/projectdiscovery/nuclei")
        elif nuclei_result["status"] == "skipped":
            print(f"\n[*] Nuclei: {nuclei_result['reason']}")

    # Stage 4: OSINT Lookups
    if not args.no_osint:
        print("\n" + "=" * 70)
        print("[*] OSINT - Internet Exposure")
        print("=" * 70)

        # Skip OSINT for private IPs
        if is_private_ip(target_ip):
            print("[!] Target is a private IP - skipping public OSINT sources")
        else:
            # Shodan
            print("\n[Shodan Lookup]")
            shodan_data = shodan_lookup(target_ip)
            
            if shodan_data["status"] == "ok":
                print(f"  Organization: {shodan_data['org']}")
                print(f"  ISP: {shodan_data['isp']}")
                print(f"  ASN: {shodan_data['asn']}")
                print(f"  Location: {shodan_data['city']}, {shodan_data['country']}")
                print(f"  Last Update: {shodan_data['last_update']}")
                
                if shodan_data['ports']:
                    print(f"  Historical Ports: {', '.join(map(str, shodan_data['ports'][:20]))}")
                
                if shodan_data['vulns']:
                    print(f"  Known CVEs: {len(shodan_data['vulns'])}")
                    for cve in shodan_data['vulns'][:5]:
                        print(f"    - {cve}")
                
                if shodan_data['tags']:
                    print(f"  Tags: {', '.join(shodan_data['tags'][:10])}")
            elif shodan_data["status"] == "missing_key":
                print("  [!] SHODAN_API_KEY not set (export SHODAN_API_KEY=your_key)")
            else:
                print(f"  [!] Error: {shodan_data.get('error', 'Unknown error')}")

            # theHarvester (for domain targets)
            # Skip for IP addresses
            if not args.target.replace('.', '').isdigit():
                print("\n[theHarvester]")
                harvester_data = run_theharvester(args.target)
                
                if harvester_data["status"] == "ok":
                    results = harvester_data["results"]
                    if results:
                        print(f"  Found {len(results)} entries")
                        for line in results[:20]:
                            if line.strip():
                                print(f"    {line}")
                    else:
                        print("  No results found")
                elif harvester_data["status"] == "missing":
                    print("  [!] theHarvester not installed")
                    print("      Install: https://github.com/laramies/theHarvester")
                elif harvester_data["status"] == "timeout":
                    print("  [!] Scan timed out")
                else:
                    print(f"  [!] Error: {harvester_data.get('error', 'Unknown error')}")
            else:
                print("\n[theHarvester]")
                print("  [!] Skipped (target is an IP address, not a domain)")

    print("\n" + "=" * 70)
    total_ports = len(tcp_ports) + len(udp_ports)
    print(f"[*] Scan complete - {total_ports} open ports found ({len(tcp_ports)} TCP, {len(udp_ports)} UDP)")
    print("=" * 70)

if __name__ == "__main__":
    main()
