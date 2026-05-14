"""
Network Utilities
Helper functions for IP scanning and verification
"""
import subprocess
import logging
import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from config import config

logger = logging.getLogger(__name__)

def is_ip_reachable(ip: str) -> bool:
    """
    Check if an IP is reachable via ping.
    Returns True if the IP responds (In Use), False if it's unreachable (Free).
    """
    try:
        # Linux için ping komutu: 
        # -c 1 (sadece 1 paket gönder) 
        # -W 1 (sadece 1 saniye bekle, donup kalma)
        result = subprocess.run(
            ['ping', '-c', '1', '-W', '1', ip],
            stdout=subprocess.DEVNULL,  # Terminali kirletmemesi için çıktıları gizle
            stderr=subprocess.DEVNULL
        )
        
        # Eğer dönüş kodu 0 ise ping başarıyla ulaşmış demektir (IP DOLU)
        # 0'dan farklı bir hata kodu döndüyse ulaşılamamıştır (IP BOŞ)
        return result.returncode == 0
        
    except Exception:
        # Herhangi bir sistem hatası olursa IP'yi güvenli say (boş döndür)
        return False

def get_used_ips() -> set:
    """Get set of IPs currently used by Docker containers in the network"""
    from utils.docker_manager import docker_manager
    
    used_ips = set()
    try:
        # Inspect network directly to find ALL containers (not just honeypots)
        network = docker_manager.client.networks.get(config.MACVLAN_NETWORK)
        network.reload()
        
        containers = network.attrs.get('Containers', {})
        for cid, details in containers.items():
            ipv4_cidr = details.get('IPv4Address')
            if ipv4_cidr:
                # Strip CIDR mask (e.g. 192.168.1.100/24 -> 192.168.1.100)
                ip = ipv4_cidr.split('/')[0]
                used_ips.add(ip)
                
    except Exception as e:
        logger.error(f"Error getting used IPs from network: {e}")
        # Fallback to honeypots list if network inspect fails
        try:
            honeypots = docker_manager.list_honeypots()
            for hp in honeypots:
                if hp.get('ip_address') and hp['ip_address'] != 'N/A':
                    used_ips.add(hp['ip_address'])
        except:
            pass
    
    # Add Gateway to used IPs
    if config.GATEWAY:
        used_ips.add(config.GATEWAY)
        
    return used_ips

def find_free_ip(subnet_str: str = None) -> str:
    """
    Find the first available IP in the subnet.
    Scans for IPs that are NOT in Docker and NOT reachable via ping.
    """
    if not subnet_str:
        subnet_str = config.SUBNET
        
    try:
        subnet = ipaddress.ip_network(subnet_str)
        used_ips = get_used_ips()
        
        # Generator for potentially free IPs (skip network and broadcast)
        potential_ips = [str(ip) for ip in subnet.hosts()]
        
        # Remove known used IPs
        candidates = [ip for ip in potential_ips if ip not in used_ips]
        
        logger.info(f"Scanning for free IP in {subnet_str} ({len(candidates)} candidates)...")
        
        # Parallel scan to be faster?
        with ThreadPoolExecutor(max_workers=20) as executor:
            # Check reachability
            results = list(executor.map(lambda ip: (ip, is_ip_reachable(ip)), candidates))
            
            for ip, is_reachable in results:
                if not is_reachable:
                    logger.info(f"Found free IP: {ip}")
                    return ip
                    
        raise Exception("No free IPs found in subnet")
        
    except Exception as e:
        logger.error(f"Error finding free IP: {e}")
        raise
