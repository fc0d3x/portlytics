<p align="center">
  <h1 align="center">Portlytics</h1>
  <p align="center">
    Advanced Network Port Analytics & Vulnerability Intelligence
  </p>
</p>

Portlytics is a modular network reconnaissance and vulnerability intelligence tool designed to identify exposed services, detect misconfigurations, and surface potential attack vectors across target systems.

It combines port scanning, service and version detection, CVE discovery, credential hygiene checks, OS fingerprinting, and basic web application testing into a single, modular command-line utility.


⚠️ **Legal Notice**

**Portlytics must only be used on systems you own or have explicit authorization to test. Unauthorized scanning or exploitation is illegal.**


## 🚀 Key Features
### 🔍 Network & Port Analytics

Custom TCP port range scanning

Multiple scan profiles:

stealth

fast 

aggressive

## 🧪 Service & Vulnerability Intelligence


Service & version detection

CVE discovery using searchsploit

OS fingerprinting for target profiling


## 🔐 Security Misconfiguration Checks


Weak/default credential checks for:

SSH

FTP

Highlights common operational security issues


## 🌐 Web Application Reconnaissance


HTTP/HTTPS service discovery

Open directory detection

Identifying the technologies used by the website (PHP, frameworks, CMS)


## 👤 Who Is Portlytics For?


### Portlytics is designed for:

*Penetration testers*

*Red team operators*

*Blue team analysts*

*Network & system administrators*

*Cybersecurity students and researchers*


## 📦 Requirements


Python 3.9+


Python Dependencies
```
pip install requests python-nmap
```

System Tools
```
sudo apt install nmap exploitdb sshpass
```

## ⚙️ Installation


```
https://github.com/fc0d3x/portlytics.git

cd portlytics


pip install -r requirements.txt
```


## ▶️ Usage


```
sudo python3 portlytics.py <target_ip> <port_range> --profile <profile>
```

Example

```
python portlytics.py X.X.X.X 1-65535 --profile stealth / fast / aggressive
```
## Scan Profiles:

stealth: Maximum stealth with fragmentation, decoys, and timing delays.

fast: Balanced speed and reliability (default).

aggressive: Maximum speed with no stealth.

## Available Options:

--profile: Select the scan profile (stealth, fast, aggressive).

--udp: Enable UDP port scanning.

--no-osint: Skip OSINT lookups (Shodan, theHarvester).

--no-nuclei: Skip Nuclei vulnerability scanning.

--no-github: Skip GitHub lookups (advisories, exploits).

--no-searchsploit: Skip ExploitDB search (searchsploit).

--no-metaspploit: Skip Metasploit module search.

## Contributing
Contributions are welcome! Please open an issue or submit a pull request.
