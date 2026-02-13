# 🍯 HoneyManager

**Decoy Intelligence: Automated Threat Classification Through Deception**

HoneyManager is an ultra-lightweight, open-source honeypot management framework designed specifically for home users and Small-to-Medium Businesses (SMBs). It transforms obsolete hardware—old laptops, desktops, Raspberry Pis, or Android devices—into active security sensors that detect both external attacks and internal lateral movement.


## 🎯 Why HoneyManager?

Traditional enterprise security solutions require expensive servers with massive RAM. HoneyManager changes the game:

- **🖥️ Runs on "Worthless" Hardware**: Even a 15-year-old Core 2 Duo laptop with 512MB RAM becomes a modern security appliance
- **🎭 Zero False Positives**: Internal honeypots mean every connection is a confirmed threat (no legitimate device should touch them)
- **🔍 Detects the "Guest Threat"**: Catches infected smartphones or consultant laptops attempting lateral movement on your Wi-Fi
- **🌱 Sustainable Tech**: Repurpose e-waste instead of buying new security appliances

---

## ✨ Key Features

### 🚀 Ultra-Lightweight Architecture
- **RAM Usage**: ~250MB total (compared to 8GB+ for ELK stacks)
- **Storage**: 4GB minimum
- **CPU**: Single-core 1GHz sufficient
- Custom Python analysis engine (no heavy JVM or complex indexing)

### 🎭 Four Honeypot Profiles
1. **SSH/Telnet Trapper (Cowrie)**: Mimics QNAP NAS or OpenWRT routers
   - Captures brute-force attempts, executed commands, downloaded malware hashes
   
2. **Web Camera Simulation (Nginx)**: 5MB Alpine-based container
   - Fake Hikvision camera interface
   - Extracts credentials from POST requests even in encrypted traffic
   
3. **Windows Services (Dionaea)**: SMB/FTP/MS-SQL trap
   - Captures actual malware binaries in isolated containers
   
4. **Custom IoT**: General-purpose Linux IoT simulation
   - Simulates smart fridges, printers with Telnet/FTP/SSH open

### 🔔 Smart Alerting
- **Telegram Integration**: Instant notifications for critical events
- **Severity Levels**: Critical (login attempts), High (port scans), Medium (reconnaissance)
- **High Fidelity**: Near-zero false positives due to internal placement

### 🌐 Professional Networking
- **Macvlan Support**: Containers get real IPs from your router (bypasses NAT overhead)
- **Low CPU Impact**: Direct layer-2 networking reduces virtualization load

---

## 🖥️ System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **CPU** | 1 GHz Single Core | Any modern dual-core |
| **RAM** | 512 MB | 1 GB |
| **Storage** | 4 GB SD Card/HDD | 16 GB SSD |
| **Network** | Ethernet/Wi-Fi | Ethernet preferred |
| **OS** | Linux (RHEL, Ubuntu, Debian, Rocky) | Latest LTS Ubuntu/Debian |

*Tested on: Raspberry Pi Zero W, 2008 Netbooks, Proxmox LXC containers*

---

## 🚀 Quick Start Guide

### 1. Clone Repository
```bash
git clone https://github.com/yourusername/honeymanager.git
cd honeymanager
```

### 2. Configure Environment
```bash
cp .env.example .env
# Edit .env and add your Telegram Bot API key
nano .env
```

### 3. Install Python Dependencies
```bash
pip3 install -r backend/requirements.txt
```

### 4. Create Macvlan Network
*Adjust subnet/gateway to match your router*
```bash
docker network create -d macvlan \
  --subnet=192.168.1.0/24 \
  --gateway=192.168.1.1 \
  -o parent=eth0 \
  macvlan_honeynet
```

### 5. Build & Launch
```bash
docker-compose build

# Terminal 1: Start API
python3 backend/app.py

# Terminal 2: Start Log Watcher
python3 backend/watcher.py
```

### 6. Access Dashboard
Open browser: `http://<your-device-ip>:5000`

### 7. (Optional) Systemd Auto-start
```bash
sudo cp systemd/*.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable honeymanager-api honeymanager-watcher
sudo systemctl start honeymanager-api honeymanager-watcher
```

---

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────┐
│                 HoneyManager Host                   │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────┐  │
│  │   Flask     │  │   SQLite     │  │  Custom  │  │
│  │   Backend   │  │   Database   │  │  Watcher │  │
│  └──────┬──────┘  └──────────────┘  └────┬─────┘  │
│         │                                 │         │
│  ┌──────┴─────────────────────────────────┴─────┐  │
│  │           Docker + Macvlan Network           │  │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐        │  │
│  │  │ Cowrie  │ │ Dionaea │ │  IoT    │        │  │
│  │  │ (SSH)   │ │ (SMB)   │ │ (Multi) │        │  │
│  │  └────┬────┘ └────┬────┘ └────┬────┘        │  │
│  └───────┼──────────┼──────────┼───────────────┘  │
└──────────┼──────────┼──────────┼──────────────────┘
           │          │          │
      Real IPs: 192.168.1.x/24 (Direct from Router)
```

**Core Components:**
- **app.py**: Flask API and web dashboard
- **watcher.py**: Real-time log analysis engine (replaces heavy SIEM)
- **models.py**: SQLite ORM for alerts and events
- **docker_manager.py**: Container orchestration via Docker SDK

---

## 📊 What Gets Detected?

| Threat Type | Example | Severity |
|-------------|---------|----------|
| **Brute Force** | 5+ failed SSH logins in 5 minutes | 🔴 Critical |
| **Lateral Movement** | Guest phone scanning internal IPs | 🔴 Critical |
| **Credential Harvesting** | POST to fake camera login page | 🟠 High |
| **Malware Drops** | Binary uploaded via SMB | 🟠 High |
| **Reconnaissance** | Port scans, service enumeration | 🟡 Medium |

---

## 🔒 Security Notes

⚠️ **Important**: HoneyManager is a **detection** tool, not a prevention system. It intentionally does not block attacker IPs to continue gathering intelligence. Use in conjunction with your firewall.

- All malware samples are captured in isolated Docker containers
- SQLite database is lightweight but not encrypted by default (encrypt your host disk)
- Place honeypots on internal VLANs for best protection

---

## 🛣️ Roadmap & Current Status

🚧 **Active Development Phase**

HoneyManager is currently functional and deployed, but we're rapidly improving it. Here's what's coming:

### ✅ Completed
- [x] Core Flask backend and REST API
- [x] Four honeypot container types
- [x] Telegram alerting system
- [x] Macvlan networking support
- [x] Real-time log watcher
- [x] Web dashboard UI

### 🔄 In Progress
- [ ] Advanced analytics dashboard (attack graphs, trends)
- [ ] Automatic malware sandboxing integration
- [ ] REST API for external SIEM integration


### 📋 Planned Features
- [ ] Machine learning for attack pattern recognition (MITRE ATTACK CATEGORY LABELLING)
- [ ] Automatic threat intelligence feeds (IOC blocking)
- [ ] On the fly labelling using Kafka & Python services
- [ ] Kubernetes support for scaling
- [ ] Web-based configuration wizard


---

## 👀 Follow Us for Updates

> 🔔 **Stay Tuned!** We're constantly improving HoneyManager with new deception techniques, better analytics, and broader device support.


---

## 🙏 Acknowledgments

- [Cowrie](https://github.com/cowrie/cowrie) for the excellent SSH honeypot
- [Dionaea](https://github.com/DinoTools/dionaea) for multi-protocol capture
- Alpine Linux for making 5MB containers possible
- The open-source security community

---
Made with ancestry for analysts who extract contextual threat intelligence from deception through NLP and automated classification.


