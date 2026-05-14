# HoneyManager — Setup Guide

> A step-by-step guide for setting up HoneyManager on a fresh Linux machine.  

---

## What Is This?

HoneyManager is a honeypot orchestration and monitoring platform. It deploys 4 fake devices (a router, an IP camera, a NAS, and an IoT device) as Docker containers, watches their logs for suspicious activity, classifies attacks with Google Gemini AI, and sends real-time alerts to Telegram.

```
┌─────────────────────────────────────────┐
│              Your Machine               │
│                                         │
│  Flask API (port 5000) ◄── Browser UI   │
│  Log Watcher ──► Gemini AI ──► Telegram │
│                                         │
│  Docker containers (honeypots):         │
│    honey_cowrie      192.168.99.215     │
│    honey_webcam      192.168.99.216     │
│    honey_dionaea     192.168.99.217     │
│    honey_custom_iot  192.168.99.218     │
└─────────────────────────────────────────┘
```

---

## Requirements

- **OS:** Linux (Ubuntu, Fedora, Debian, Arch — any modern distro)
- **Docker:** version 20 or newer
- **Python:** 3.9 or newer
- **RAM:** at least 2 GB free
- **Internet connection** (for Docker image pulls on first run)

---

## Step 1 — Install Prerequisites

### 1a. Install Docker (skip if already installed)

**Ubuntu / Debian:**
```bash
sudo apt update
sudo apt install -y docker.io docker-compose
sudo systemctl enable docker
sudo systemctl start docker
```

**Fedora:**
```bash
sudo dnf install -y docker docker-compose
sudo systemctl enable docker
sudo systemctl start docker
```

**Arch:**
```bash
sudo pacman -S docker docker-compose
sudo systemctl enable docker
sudo systemctl start docker
```

### 1b. Add yourself to the Docker group

This lets you run Docker without `sudo` every time:

```bash
sudo usermod -aG docker $USER
```

Then **log out and log back in**, or run this command to apply the group in the current terminal:

```bash
newgrp docker
```

Verify Docker works:
```bash
docker run hello-world
```

You should see a "Hello from Docker!" message. If you do, Docker is working correctly.

### 1c. Install Python 3 (skip if already installed)

```bash
# Ubuntu / Debian
sudo apt install -y python3 python3-pip python3-venv

# Fedora
sudo dnf install -y python3 python3-pip

# Arch
sudo pacman -S python python-pip
```

Check your Python version (must be 3.9 or newer):
```bash
python3 --version
```

---

## Step 2 — Check Your Network

This step helps you make sure the internal Docker subnet (192.168.99.x) does not clash with your home network.

Run these two commands and look at the output:

```bash
ip route
```
```bash
ip a
```

**What to look for:** Find your main network interface (usually `eth0`, `ens3`, `enp3s0`, or `wlan0`) and note which subnet it uses.

Example output of `ip route`:
```
default via 192.168.1.1 dev eth0
192.168.1.0/24 dev eth0 proto kernel
```

In this example the home network uses `192.168.1.x`, which is **different** from `192.168.99.x`.  
This means there is **no conflict** — you can proceed without changes.

> **If your home network uses 192.168.99.x** (very unlikely), you will need to change the subnet in `.env`. See Step 3 for details.

---

## Step 3 — Edit the Configuration Files

You need to update **2 files** with your own paths before running anything.

### 3a. Open the project folder

```bash
cd ~/HoneyManagerFUTUREWORK
```

(Replace `~/HoneyManagerFUTUREWORK` with your actual path if different.)

### 3b. Edit `.env`

Open the file with any text editor. Examples:

The file looks like this:

```
TELEGRAM_BOT_TOKEN=...
TELEGRAM_CHAT_ID=...

MACVLAN_NETWORK=macvlan_honeynet
SUBNET=192.168.99.0/24
GATEWAY=192.168.99.1

FLASK_SECRET_KEY=really_secret_key
FLASK_HOST=0.0.0.0
FLASK_PORT=5000
FLASK_DEBUG=false

LOG_RETENTION_DAYS=30
LOG_PATH=/home/hosafxd/Downloads/.../data/logs          ← CHANGE THIS
DB_PATH=/home/hosafxd/Downloads/.../data/db/alerts.db  ← CHANGE THIS

COWRIE_IP=192.168.99.215
WEBCAM_IP=192.168.99.216
DIONAEA_IP=192.168.99.217
CUSTOM_IOT_IP=192.168.99.218

WHITELIST_IPS=

GEMINI_API_KEY=...
DEEPSEEK_API_KEY=
VIRUSTOTAL_API_KEY=

DIONAEA_BINARIES_PATH=/home/hosafxd/.../dionaea-binaries  ← CHANGE THIS

ADMIN_PASSWORD=1357
```

**You MUST change these 3 lines** to match your own path:

| Line | Replace with |
|------|-------------|
| `LOG_PATH=` | `LOG_PATH=/home/YOUR_USERNAME/HoneyManagerFUTUREWORK/data/logs` |
| `DB_PATH=` | `DB_PATH=/home/YOUR_USERNAME/HoneyManagerFUTUREWORK/data/db/alerts.db` |
| `DIONAEA_BINARIES_PATH=` | `DIONAEA_BINARIES_PATH=/home/YOUR_USERNAME/HoneyManagerFUTUREWORK/data/dionaea-binaries` |

> **How to find YOUR_USERNAME:** run `whoami` in the terminal.  
> Example: if `whoami` prints `alice`, your paths become `/home/alice/HoneyManagerFUTUREWORK/data/logs`

**Optional settings** (the project works without these, but they enable extra features):

| Setting | What it does | How to get one |
|---------|-------------|----------------|
| `GEMINI_API_KEY` | AI-powered attack classification | Google AI Studio → aistudio.google.com (free) |
| `TELEGRAM_BOT_TOKEN` | Real-time Telegram alerts | BotFather on Telegram → `/newbot` |
| `TELEGRAM_CHAT_ID` | Which chat to send alerts to | Message your bot, then check: `https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates` |
| `VIRUSTOTAL_API_KEY` | Hash-check captured malware files | virustotal.com → My API Key (free, 500 req/day) |
| `ADMIN_PASSWORD` | Dashboard login password | Change to anything you want (default: `1357`) |

> **Do not change** SUBNET, GATEWAY, or the honeypot IPs unless you saw a conflict in Step 2.

Save the file: in `nano` press `Ctrl+O` then `Enter`, then `Ctrl+X` to exit.

---

### 3c. Edit `demo_attack.sh`

The demo script also has a hardcoded path that must point to your folder.

Open it:
Find line 9 (near the top of the file):
```bash
BASE="/home/hosafxd/Downloads/DÖNEM6/GRADUATION/HoneyManager (4)/HoneyManager"
```

Change it to your `HoneyManagerFUTUREWORK` folder path:
```bash
BASE="/home/YOUR_USERNAME/HoneyManagerFUTUREWORK"
```

Example (if your username is `alice`):
```bash
BASE="/home/alice/HoneyManagerFUTUREWORK"
```

Save and close (`Ctrl+O`, `Enter`, `Ctrl+X`).

---

## Step 4 — Create the Python Virtual Environment

Make sure you are inside the project folder:

```bash
cd ~/HoneyManagerFUTUREWORK
```

Create the virtual environment:

```bash
python3 -m venv venv
```

Activate it:

```bash
source venv/bin/activate
```

Your terminal prompt will change to show `(venv)` at the beginning — this means the virtual environment is active.

Install the required Python packages:

```bash
pip install -r backend/requirements.txt
```

You should see packages being downloaded and installed. This may take 1–2 minutes.

> **Important:** Every time you open a new terminal to work with HoneyManager, you must run `source venv/bin/activate` again from the project folder. The `(venv)` prefix reminds you it is active.

---

## Step 5 — Start Docker and Launch the Honeypots

### 5a. Make sure Docker is running

```bash
sudo systemctl start docker
```

Verify:
```bash
docker ps
```

If you see a table header (even empty), Docker is running correctly.

### 5b. Go to the project folder

```bash
cd ~/HoneyManagerFUTUREWORK
```

### 5c. Create necessary data directories

```bash
mkdir -p data/logs data/db data/dionaea-binaries
mkdir -p data/logs/cowrie data/logs/dionaea data/logs/web-camera data/logs/custom-iot
```

### 5d. Start the honeypot containers

```bash
docker compose up -d
```

> On older systems it might be `docker-compose up -d` (with a dash).

Docker will:
1. Download required images from the internet (first run only — may take 3–10 minutes depending on your connection)
2. Build the custom Cowrie and Web-Camera images
3. Create the internal network
4. Start all 4 containers in the background

Check that all containers are running:

```bash
docker ps
```

You should see 4 containers:
```
NAMES               STATUS
honey_cowrie        Up X seconds
honey_webcam        Up X seconds
honey_dionaea       Up X seconds
honey_custom_iot    Up X seconds
```

> If a container shows "Exited" or "Restarting", check its logs:  
> `docker logs honey_cowrie`

---

## Step 6 — Start the Backend Services

You need two terminal windows open at the same time.

### Terminal 1 — Flask API

```bash
cd ~/HoneyManagerFUTUREWORK
source venv/bin/activate
python3 backend/app.py
```

You should see output like:
```
* Running on http://0.0.0.0:5000
* Debug mode: off
```

Leave this terminal open and running.

### Terminal 2 — Log Watcher

Open a **new** terminal window/tab, then:

```bash
cd ~/HoneyManagerFUTUREWORK
source venv/bin/activate
python3 backend/watcher.py
```

You should see:
```
INFO - LogWatcher started. Watching: .../data/logs
INFO - Watcher loop running...
```

Leave this terminal open and running too.

---

## Step 7 — Open the Dashboard

Open your web browser and go to:

```
http://localhost:5000
```

You will see a login screen. Use:
- **Password:** `1357` (or whatever you set in `ADMIN_PASSWORD` in `.env`)

The dashboard shows:
- Live alerts table
- Honeypot container statuses
- Alert severity breakdown
- MITRE ATT&CK technique tags

---

## Step 8 — Run the Demo Attack Script

The demo script simulates 50 real attack phases across all 4 honeypots, triggering alerts that appear live on the dashboard.

Open a **third** terminal window:

```bash
cd ~/HoneyManagerFUTUREWORK
bash demo_attack.sh
```

The script will walk through 50 attack phases, showing banners like:
```
╔══════════════════════════════════════════════════════════════╗
║ PHASE 1/50  [T1110]  SSH Brute Force
║ Honeypot: honey_cowrie   Severity: HIGH
╚══════════════════════════════════════════════════════════════╝
```

Watch the dashboard refresh in your browser — alerts should appear within a few seconds of each phase.

The full demo takes about **5–6 minutes** to complete all 50 phases.

---

## Troubleshooting

### "Permission denied" when running Docker

```bash
newgrp docker
```
Then try again. If it still fails, log out and log back in.

### "docker compose: command not found"

Try the older syntax:
```bash
docker-compose up -d
```

### Flask API says "Address already in use"

Port 5000 is already used by another program. Either stop that program, or change `FLASK_PORT=5000` to `FLASK_PORT=5001` in `.env` and then open `http://localhost:5001` instead.

### Containers exit immediately after starting

Check the logs:
```bash
docker logs honey_dionaea
docker logs honey_cowrie
```

The most common cause is the Docker network not existing. The `docker compose up -d` command should create it automatically, but if it doesn't:

```bash
docker network create \
  --driver bridge \
  --subnet 192.168.99.0/24 \
  --gateway 192.168.99.1 \
  macvlan_honeynet
```

Then run `docker compose up -d` again.

### Demo script shows "No such file or directory" for log files

The `BASE` path in `demo_attack.sh` is still the old one. Re-check Step 3c.

### Watcher generates no alerts after demo

The watcher polls log files every 30 seconds. Wait up to 35 seconds after a phase runs. Also confirm the `LOG_PATH` in `.env` matches where Docker writes logs (the `data/logs/` folder inside the project).

---

## Stopping Everything

When you are done:

1. Stop the Flask API: press `Ctrl+C` in Terminal 1
2. Stop the Watcher: press `Ctrl+C` in Terminal 2
3. Stop the Docker containers:

```bash
cd ~/HoneyManagerFUTUREWORK
docker compose down
```

---

## Quick Reference

| What | Command |
|------|---------|
| Start Docker | `sudo systemctl start docker` |
| Start honeypots | `cd ~/HoneyManagerFUTUREWORK && docker compose up -d` |
| Activate venv | `source venv/bin/activate` |
| Start API | `python3 backend/app.py` |
| Start Watcher | `python3 backend/watcher.py` |
| Run demo | `bash demo_attack.sh` |
| See container logs | `docker logs honey_cowrie` |
| Watch watcher output | `tail -f data/logs/watcher.log` |
| Stop honeypots | `docker compose down` |
| Open dashboard | `http://localhost:5000` |
