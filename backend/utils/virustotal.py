"""
VirusTotal API helper — hash and classify Dionaea-captured binaries
"""
import hashlib
import requests
import logging
from pathlib import Path
from typing import Optional, Dict, Tuple

logger = logging.getLogger(__name__)

VT_API_URL = "https://www.virustotal.com/api/v3/files"


def hash_file(file_path: Path) -> str:
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            sha256.update(chunk)
    return sha256.hexdigest()


def query_virustotal(sha256_hash: str, api_key: str) -> Optional[Dict]:
    if not api_key:
        return None
    try:
        response = requests.get(
            f"{VT_API_URL}/{sha256_hash}",
            headers={'x-apikey': api_key},
            timeout=15
        )
        if response.status_code == 200:
            return response.json()
        if response.status_code == 404:
            return None  # Not in VT — still suspicious, caller handles it
        logger.error(f"VirusTotal API error {response.status_code}: {response.text[:200]}")
        return None
    except Exception as e:
        logger.error(f"VirusTotal query failed: {e}")
        return None


def classify_binary(vt_result: Optional[Dict], file_path: Path) -> Tuple[Optional[str], str, str]:
    """
    Returns (mitre_id, severity, description).
    mitre_id is None when the binary appears clean.
    """
    file_name = file_path.name
    file_ext = file_path.suffix.lower()

    if vt_result is None:
        # Unknown to VirusTotal — new or rare sample, still worth alerting
        return 'T1203', 'high', f"Unknown binary captured (not in VirusTotal): {file_name}"

    attrs = vt_result.get('data', {}).get('attributes', {})
    stats = attrs.get('last_analysis_stats', {})
    malicious = stats.get('malicious', 0)
    suspicious = stats.get('suspicious', 0)

    if malicious == 0 and suspicious == 0:
        return None, 'low', f"Binary appears clean: {file_name}"

    threat_label = attrs.get('popular_threat_classification', {}).get('suggested_threat_label', '').lower()
    tags = ' '.join(attrs.get('tags', [])).lower()
    combined = f"{threat_label} {tags}"

    severity = 'critical' if malicious >= 5 else 'high'

    is_rat = any(t in combined for t in ['rat', 'backdoor', 'trojan', 'remote-access', 'remcos', 'asyncrat', 'njrat'])
    is_attachment = file_ext in ('.exe', '.dll', '.doc', '.docx', '.xls', '.xlsm', '.pdf', '.lnk', '.hta')

    if is_rat:
        return (
            'T1219', severity,
            f"RAT/Backdoor captured via SMB: {file_name} — {malicious} VT detections ({threat_label or 'unknown'})"
        )
    if is_attachment:
        return (
            'T1566.001', severity,
            f"Malicious attachment dropped via SMB: {file_name} — {malicious} VT detections"
        )
    return (
        'T1203', severity,
        f"Exploit payload captured: {file_name} — {malicious} VT detections"
    )
