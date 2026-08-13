<div align="center">

```text
 _     _                         _             _ _ _      _____           _
| |   (_)_ __  _   ___  __      / \  _   _  __| (_) |_   |_   _|__   ___ | |
| |   | | '_ \| | | \ \/ /____ / _ \| | | |/ _` | | __|____| |/ _ \ / _ \| |
| |___| | | | | |_| |>  <_____/ ___ \ |_| | (_| | | ||_____| | (_) | (_) | |
|_____|_|_| |_|\__,_/_/\_\   /_/   \_\__,_|\__,_|_|\__|    |_|\___/ \___/|_|
```

# 🛡️ Linux Audit Tool v5.0

**A comprehensive Linux security auditing framework that performs 80+ checks across system, network, and port scanning domains — now featuring AI anomaly detection, CVE scanning, and automated remediation.**

[![Version](https://img.shields.io/badge/version-5.0-blue?style=for-the-badge)](https://github.com/MokshSharma2006)
[![Shell](https://img.shields.io/badge/shell-bash-green?style=for-the-badge&logo=gnu-bash)](https://www.gnu.org/software/bash/)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey?style=for-the-badge&logo=linux)](https://kernel.org)

[Features](#-features) • [Demo](#-demo) • [Installation](#-installation) • [Usage](#-usage) • [Checks](#-audit-checks) • [Output](#-output-formats) • [Requirements](#-requirements) • [Contributing](#-contributing)

</div>

---

## 📌 Overview

**Linux Audit Tool v5.0** is an advanced, self-contained Bash script designed for sysadmins, penetration testers, and security engineers. It provides a fast, robust way to audit the security posture of any Linux system. 

Version 5.0 elevates the tool from a static scanner to an intelligent security suite. It now includes **AI-powered anomaly detection** (using scikit-learn), a **CVE vulnerability scanner**, **network topology mapping**, and an **interactive remediation mode** that fixes misconfigurations for you.

---

## ✨ Features

- **🧠 AI-Powered Anomaly Detection** — Learns what's "normal" on your system and flags deviations (unusual ports, new SUID binaries, etc.) using local ML.
- **🛡️ Automatic Remediation Mode** — Interactively fix detected issues (e.g., disable SSH root login, set sticky bits, enable UFW) with user consent and logging.
- **🔍 Vulnerability & CVE Scanner** — Detects known vulnerabilities for installed packages via the OSV API.
- **📡 Network Topology Discovery** — Finds hosts on your local LAN and generates a visual network map (PNG) using `arp-scan` and `graphviz`.
- **📊 Interactive HTML Dashboard** — Risk score, KPI cards, radar charts, severity breakdowns, and a live remediation status view in a single self-contained HTML file.
- **🔥 Systemd Service Security Score** — Profiles and surfaces security scores for all systemd services using `systemd-analyze`.
- **🔐 Baseline Versioning & Diffing** — Save historical baselines and compare two audit reports using `--compare`.
- **80+ Core Security Checks** — User accounts, SSH config, SUID binaries, firewall rules, open ports, kernel hardening, and more.
- **Multi-format Output** — Choose TXT, PDF, or both at runtime (PDF generation via `reportlab` or native system fallbacks).

---

## 🎬 Demo

```text
  ╔═══════════════════════════════════════════════════════════╗
  ║                LINUX SECURITY AUDIT TOOL                  ║
  ║                    Enhanced Version 5.0                   ║
  ╚═══════════════════════════════════════════════════════════╝

Date: Thu Aug 06 18:11:04 IST 2026
Hostname: myserver

[*] Checking for required audit tools...
[+] All core audit tools are present.

Progress: 14% — System Security Audit
[*] 1.1 - Checking: User Accounts
...
Progress: 71% — Vulnerability & CVE Scanner
[*] Scanning for known vulnerabilities (CVE) using OSV API...
...
Progress: 100% — Anomaly Detection (AI/ML)
[!] ANOMALY DETECTED: Current metrics differ from baseline.

[+] HTML dashboard saved: Linux_security_audit_20260806_181104.html
[+] Report saved: Linux_security_audit_20260806_181104.txt

Do you want to run remediation now? (y/n): y
=== RECOMMENDED FIXES (safe, auto-apply) ===
  [1] SSH root login is enabled (PermitRootLogin yes) [open]
  [2] UFW firewall is not active [open]
```

---

## 📦 Installation

Follow these steps to set up the environment and install dependencies:

### Step 1: Create Virtual Environment
```bash
sudo apt update && sudo apt upgrade -y
python3 -m venv venv
source venv/bin/activate
```

### Step 2: Install Dependencies
```bash
sudo apt install git -y
sudo apt install -y enscript ghostscript graphviz cups-client python3-pip
pip install reportlab scikit-learn
```

### Step 3: Program Execution
```bash
git clone https://github.com/MokshSharma2006/Linux_Audit_Tool_V5.0.git
cd Linux_Audit_Tool_V5.0
chmod +x Linux_Audit_Tool_V5.0.sh
sudo ./Linux_Audit_Tool_V5.0.sh
```

---

## 🚀 Usage

### Basic (interactive)

```bash
sudo ./Linux_Audit_Tool_V5.0.sh
```

### Advanced Options

```bash
Usage: ./Linux_Audit_Tool_V5.0.sh [OPTIONS]

Options:
  -h, --help             Show help
  -v, --verbose          Verbose output
  -q, --quiet            Minimal console output
  -f, --format           Output format: txt | pdf | both
  --update               Check for updates and apply
  --compare file1 file2  Compare two audit reports
  --remediate            Enter interactive remediation mode directly
  --scan-network         Run network topology discovery only
  --cve                  Run vulnerability scan only
```

> **Tip:** Always run with `sudo` for a complete audit. Without root, some checks (shadow file, auditd rules, lsof, etc.) will be skipped or limited.

---

## 🔍 Audit Checks

### 1. System Security Audit (checks 1.1 – 1.50)
Covers user accounts, `/etc/shadow`, password aging, sudo configurations, SSH hardening, SUID/SGID files, world-writable files/directories, kernel parameters, auditd, crontabs, and more.

### 2. Network Security Audit (checks 2.1 – 2.22)
Covers network interfaces, listening TCP/UDP services, iptables, UFW/firewalld/nftables rules, routing tables, and interface statistics.

### 3. Port Scanning Analysis (checks 3.1 – 3.8)
Fast top-1000 TCP/UDP port scans, service version detection, OS fingerprinting, and process-to-port mapping (`lsof`).

### 4. Security Summary & Recommendations
Automatically extracts critical findings and provides actionable recommendations.

### 5. Enhanced V5.0 Checks
*   **Systemd Security Scores:** Evaluates the sandboxing/isolation of active services.
*   **OSV Vulnerability Scanner:** Matches installed packages against CVE databases.
*   **Network Topology:** Generates DOT/PNG maps of the local subnet.
*   **AI Anomaly Detection:** Compares current system state against historical baselines using `IsolationForest`.

---

## 📊 Output Formats

### Interactive HTML Dashboard
A standalone, Chart.js-powered HTML file featuring:
- **Risk Score** (0–100) with colour-coded severity.
- **Remediation Tracker** — Live view of fixed vs. open issues.
- **KPI Cards & Radars** — Visual breakdowns of system risks and resource usage.

### TXT Report
Plain text, structured with Unicode box-drawing characters. Saved as `Linux_security_audit_YYYYMMDD_HHMMSS.txt`.

### PDF Report
Generated via Python `reportlab` with a professional cover page and syntax-aware styling. Falls back gracefully to `enscript` or `cupsfilter`.

### Network Map
Generates a `.dot` file and compiles it to `.png` automatically (if `graphviz` is installed).
*Manual generation:* `dot -Tpng /tmp/network_topology_*.dot -o test.png`

---

## 🖥️ Requirements

- **Bash 4.0+**
- **Linux OS** (Debian, Ubuntu, RHEL, CentOS, Fedora, Arch, SUSE)
- **Core Tools** (Auto-installed if missing): `nmap`, `lsof`, `iproute2`, `net-tools`, `auditd`, `arp-scan`, `curl`.
- **Python ML/PDF Tools:** `python3`, `pip`, `reportlab`, `scikit-learn`.
- **Graphing Tools:** `graphviz` (for `dot`).

---

## 📁 Project Structure

```text
Linux_Audit_Tool_V5.0/
├── Linux_Audit_Tool_V5.0.sh    # Main audit script
├── README.md                   # This file
└── baselines/                  # Generated AI baselines (created at runtime)
```

Output files (generated in working directory or `/tmp/`):
```text
Linux_security_audit_YYYYMMDD_HHMMSS.txt
Linux_security_audit_YYYYMMDD_HHMMSS.pdf
Linux_security_audit_YYYYMMDD_HHMMSS.html
network_topology_*.png
```

---

## 🤝 Contributing

Contributions, bug reports, and feature requests are welcome!

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Commit your changes: `git commit -m "Add: your feature description"`
4. Push to the branch: `git push origin feature/your-feature`
5. Open a Pull Request

---

## 👤 Author

**Moksh Sharma**
- GitHub: [@MokshSharma2006](https://github.com/MokshSharma2006)

---

<div align="center">

*Linux Audit Tool v5.0 — For internal use only. Always audit responsibly.*
</div>
