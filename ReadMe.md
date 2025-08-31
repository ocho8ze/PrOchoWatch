# PrOchoWatch

**PrOchoWatch** is a lightweight **Host-based Intrusion Detection System (HIDS)** written in **pure Python (standard library only)**.  
It detects the execution of unauthorized or suspicious processes, monitors the integrity of critical files, and analyzes system logs to generate alerts in near real-time.

---

## 🚀 Features

- **File Integrity Monitoring (FIM)**: Create a baseline and detect file additions, deletions, or modifications in critical directories (`/etc`, `/usr/bin`, etc.).  
- **Log Monitoring**: Continuously monitor system logs (`/var/log/auth.log`) with regex rules (SSH failures, sudo misuse, GTFOBins exploitation, etc.).  
- **Process Monitoring**: Detect suspicious processes (deleted binaries still running, processes started from `/tmp`, blacklisted malware such as cryptominers, fake system daemons).  
- **Alerting**: Unified alerts to console, JSONL file, and application log.  
- **Modes**: Continuous monitoring (service-like) or one-shot scanning.  

---

## 📂 Installation

Clone the repository and navigate into it:

```bash
git clone https://github.com/ocho8sze/PrOchoWatch.git
cd PrOchoWatch

## 🛠️ Usage

Initialize the FIM baseline:
```bash
sudo python3 PrOchoWatch.py --init-baseline

Start continuous monitoring:
sudo python3 PrOchoWatch.py --watch
Run a one-shot scan:
sudo python3 PrOchoWatch.py --scan
📑 Example Alerts
[HIGH] PROC/BLACKLIST: Forbidden process detected: /tmp/xmrig
[HIGH] FIM/MODIFIED: Modification detected in /etc/passwd
[HIGH] LOG/SSH_FAIL: Failed password for invalid user admin from 192.168.1.10