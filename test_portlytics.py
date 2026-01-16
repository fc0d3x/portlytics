import socket
from ipaddress import ip_address
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
import nmap
import sys
import time
import subprocess
import argparse

# Function to scan a single port
def scan_port(ip: str, port: int, timeout: float = 0.5, delay: float = 0.5) -> bool:
    """Return True if TCP port is open on ip, with a delay to avoid noise."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port)) == 0
            time.sleep(delay)  # Add delay to slow down the scan
            return result
    except OSError:
        return False

# Function to scan ports concurrently on a single IP
def scan_ports(ip: str, ports: range, timeout: float = 0.5, workers: int = 200, delay: float = 0.5):
    """Scan all ports concurrently; return sorted list of open ports with a delay between scans."""
    open_ports = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(scan_port, ip, p, timeout, delay): p for p in ports}
        for fut in as_completed(futures):
            p = futures[fut]
            if fut.result():
                open_ports.append(p)
    return sorted(open_ports)

# Function to check if HTTP/HTTPS services are accessible
def check_http_service(ip: str, port: int) -> str:
    """Check if the HTTP/HTTPS service is accessible on a given port."""
    url = f"http://{ip}:{port}" if port == 80 else f"https://{ip}:{port}"
    try:
        response = requests.get(url, timeout=3)
        if response.status_code == 200:
            return f"HTTP/HTTPS service on port {port} is accessible."
        else:
            return f"HTTP/HTTPS service on port {port} returned status code {response.status_code}."
    except requests.RequestException:
        return f"HTTP/HTTPS service on port {port} is not accessible."

# Function to use nmap for service detection
def detect_services(ip: str, open_ports: list) -> dict:
    """Use nmap to detect services running on open ports with version information."""
    nm = nmap.PortScanner()
    services = {}
    for port in open_ports:
        try:
            result = nm.scan(ip, str(port), arguments='-sV')  # '-sV' for version detection
            service_info = result['scan'][ip]['tcp'][port]
            services[port] = {
                'service': service_info.get('name', 'Unknown Service'),
                'version': service_info.get('version', 'Unknown Version')
            }
        except KeyError:
            services[port] = {'service': 'Unknown Service', 'version': 'Unknown Version'}
    return services

# Function to check for known vulnerabilities using searchsploit
def check_cve(service, version):
    """Check for known vulnerabilities in the service version using searchsploit."""
    try:
        cve_check = subprocess.check_output(f"searchsploit {service} {version}", shell=True, stderr=subprocess.PIPE)
        return cve_check.decode('utf-8') if cve_check else "No known CVEs found."
    except subprocess.CalledProcessError:
        return "Error checking CVEs."

# Function to attempt weak credential checks (for SSH and FTP)
def check_default_credentials(service, ip, port):
    """Attempt weak credential checks for services like SSH and FTP."""
    if service == "ssh":
        ssh_default_creds = [
            ("root", "root"),  # Default root password
            ("admin", "admin"),  # Default admin password
            ("user", "user")  # Default user password
        ]
        for username, password in ssh_default_creds:
            result = subprocess.run(["sshpass", "-p", password, "ssh", "-o", "StrictHostKeyChecking=no", f"{username}@{ip}", "-p", str(port), "exit"],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode == 0:
                return f"Vulnerable: {username}:{password} on {service} ({ip}:{port})"
        return "No default credentials found for SSH."
    
    if service == "ftp":
        ftp_default_creds = [
            ("anonymous", "anonymous"),  # Common FTP anonymous login
            ("admin", "admin")  # Default FTP admin login
        ]
        for username, password in ftp_default_creds:
            result = subprocess.run(["ftp", "-n", ip],
                                    input=f"user {username} {password}\n", stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode == 0:
                return f"Vulnerable: {username}:{password} on {service} ({ip}:{port})"
        return "No default credentials found for FTP."
    
    return "No weak credentials check implemented for this service."

# Function to perform OS fingerprinting using nmap
def os_fingerprint(ip: str) -> str:
    """Use nmap to fingerprint the OS of the target."""
    nm = nmap.PortScanner()
    try:
        result = nm.scan(ip, arguments='-O')  # '-O' for OS detection
        os_info = result['scan'][ip].get('osmatch', [])
        if os_info:
            return f"OS detected: {os_info[0]['name']}"
        return "OS detection failed."
    except KeyError:
        return "OS detection failed."

# Function to perform Web Application Testing (e.g., open directories, outdated technologies)
def web_app_testing(ip: str, open_ports: list) -> str:
    """Test for common web vulnerabilities such as open directories and outdated technologies."""
    web_vulns = []
    for port in open_ports:
        if port == 80 or port == 443:  # Check for HTTP/HTTPS
            # Example: Check for PHP version or open directories
            url = f"http://{ip}:{port}" if port == 80 else f"https://{ip}:{port}"
            try:
                response = requests.get(url, timeout=5)
                if "php" in response.text.lower():
                    web_vulns.append(f"PHP detected on {url} - Check for outdated versions")
                if 'Index of' in response.text:
                    web_vulns.append(f"Open directory found on {url}")
            except requests.RequestException:
                continue
    return "\n".join(web_vulns) if web_vulns else "No common web vulnerabilities found."

# Main function to run the scan with additional features
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="portlytics Port Scanner with Vulnerability Detection")
    parser.add_argument("target", help="Target IP address to scan")
    parser.add_argument("ports", help="Port range (e.g., 1-65535)", type=str)
    parser.add_argument("--profile", choices=['stealth', 'fast', 'aggressive'], default='fast', help="Scan profile")
    
    args = parser.parse_args()
    
    # Validate the target IP
    try:
        ip_address(args.target)
    except ValueError:
        raise SystemExit(f"Invalid IP: {args.target}")
    
    # Parse the port range
    port_range = args.ports.split('-')
    try:
        start_port = int(port_range[0])
        end_port = int(port_range[1])
    except ValueError:
        raise SystemExit("Invalid port range format. Use 'start-end' (e.g., 1-1000)")
    
    ports = range(start_port, end_port + 1)
    
    # Set scan profile parameters
    if args.profile == 'stealth':
        timeout = 2
        workers = 50
        delay = 1
    elif args.profile == 'aggressive':
        timeout = 0.5
        workers = 500
        delay = 0.2
    else:  # fast profile
        timeout = 1
        workers = 200
        delay = 0.5
    
    print(f"Scanning {args.target} for open ports in the range {ports[0]} to {ports[-1]} using the '{args.profile}' profile...")
    
    # Scan for open ports
    open_ports = scan_ports(args.target, ports, timeout=timeout, workers=workers, delay=delay)
    if open_ports:
        print(f"Open ports found: {open_ports}")
        
        # Service detection
        services = detect_services(args.target, open_ports)
        for port, service_info in services.items():
            service = service_info['service']
            version = service_info['version']
            print(f"Port {port}: {service} {version}")
            
            # CVE detection
            print(check_cve(service, version))
            
            # Check for weak credentials
            print(check_default_credentials(service, args.target, port))
        
        # OS fingerprinting
        print(os_fingerprint(args.target))
        
        # Web application testing
        print(web_app_testing(args.target, open_ports))
    else:
        print(f"No open ports found on {args.target}.")
