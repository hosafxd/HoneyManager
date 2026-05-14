"""
Docker Manager - Honeypot Container Orchestration
Uses Docker SDK to manage honeypot containers
"""
import docker
from docker.errors import NotFound, APIError
from typing import List, Dict, Optional, Any
import logging

logger = logging.getLogger(__name__)


class DockerManager:
    """Manages honeypot Docker containers"""

    def __init__(self, network_name: str = 'macvlan_honeynet'):
        self.network_name = network_name
        self.label_prefix = 'honeymanager'
        try:
            self.client = docker.from_env()
        except Exception:
            self.client = None
            print("LOCAL TEST MODE: Docker not found, interface will be simulated.")
    
    def list_honeypots(self) -> List[Dict[str, Any]]:
        """List all honeypot containers managed by HoneyManager"""
        if not self.client:
            return [] 
        try:
            containers = self.client.containers.list(
                all=True,
                filters={'label': f'{self.label_prefix}.type'}
            )
            
            honeypots = []
            for container in containers:
                labels = container.labels
                
                # Get IP address from network
                ip_address = 'N/A'
                try:
                    networks = container.attrs.get('NetworkSettings', {}).get('Networks', {})
                    if self.network_name in networks:
                        ip_address = networks[self.network_name].get('IPAddress', 'N/A')
                except Exception:
                    pass
                
                honeypots.append({
                    'id': container.short_id,
                    'container_id': container.id,
                    'name': container.name,
                    'status': container.status,
                    'ip_address': ip_address,
                    'type': labels.get(f'{self.label_prefix}.type', 'unknown'),
                    'role': labels.get(f'{self.label_prefix}.role', 'unknown'),
                    'ports': labels.get(f'{self.label_prefix}.ports', ''),
                    'image': container.image.tags[0] if container.image.tags else 'unknown'
                })
            
            return honeypots
            
        except Exception as e:
            logger.error(f"Error listing honeypots: {e}")
            return []
    
    def ensure_image(self, image: str, build_path: str = None) -> bool:
        """Check if image exists locally; build from build_path if not."""
        try:
            self.client.images.get(image)
            return True
        except Exception:
            pass

        if not build_path:
            return False

        import os
        if not os.path.isdir(build_path):
            logger.error(f"Build path not found: {build_path}")
            return False

        logger.info(f"Image '{image}' not found locally — building from {build_path}")
        try:
            _, logs = self.client.images.build(path=build_path, tag=image, rm=True)
            for chunk in logs:
                if 'stream' in chunk:
                    line = chunk['stream'].strip()
                    if line:
                        logger.info(f"[build] {line}")
            logger.info(f"Built image: {image}")
            return True
        except Exception as e:
            logger.error(f"Failed to build image '{image}': {e}")
            return False

    def create_honeypot(
        self,
        name: str,
        ip_address: str,
        honeypot_type: str,
        image: str,
        role: str = 'generic',
        ports: str = '',
        log_path: str = '/var/log/honeypot',
        host_log_path: str = None,
        extra_volumes: Dict = None,
        entrypoint: List[str] = None,
        build_path: str = None
    ) -> Dict[str, Any]:
        """Create and start a new honeypot container"""
        
        container_name = f"honey_{name}"
        
        # Check if container already exists
        try:
            existing = self.client.containers.get(container_name)
            return {
                'success': False,
                'error': f'Container {container_name} already exists',
                'container_id': existing.short_id
            }
        except NotFound:
            pass
        
        # Prepare volumes
        volumes = {}
        if host_log_path:
            volumes[host_log_path] = {'bind': log_path, 'mode': 'rw'}
        if extra_volumes:
            volumes.update(extra_volumes)
        
        # Labels for management
        labels = {
            f'{self.label_prefix}.type': honeypot_type,
            f'{self.label_prefix}.role': role,
            f'{self.label_prefix}.ports': ports,
            f'{self.label_prefix}.managed': 'true'
        }
        
        # Build image locally if not available
        if not self.ensure_image(image, build_path):
            return {'success': False, 'error': f"Image '{image}' not found and could not be built"}

        try:
            # Create network config
            networking_config = self.client.api.create_networking_config({
                self.network_name: self.client.api.create_endpoint_config(
                    ipv4_address=ip_address
                )
            })
            
            # Create container
            container = self.client.containers.run(
                image=image,
                name=container_name,
                hostname=name.replace('_', '-'),
                detach=True,
                network=self.network_name,
                volumes=volumes if volumes else None,
                labels=labels,
                entrypoint=entrypoint,
                restart_policy={'Name': 'unless-stopped'}
            )
            
            # Disconnect from default and connect with specific IP
            try:
                self.client.networks.get(self.network_name).disconnect(container)
            except:
                pass
            
            self.client.networks.get(self.network_name).connect(
                container,
                ipv4_address=ip_address
            )
            
            logger.info(f"Created honeypot: {container_name} ({ip_address})")
            
            return {
                'success': True,
                'container_id': container.short_id,
                'name': container_name,
                'ip_address': ip_address,
                'status': container.status
            }
            
        except APIError as e:
            logger.error(f"Docker API error: {e}")
            return {'success': False, 'error': str(e)}
        except Exception as e:
            logger.error(f"Error creating honeypot: {e}")
            return {'success': False, 'error': str(e)}
    
    def delete_honeypot(self, container_id: str, force: bool = True) -> Dict[str, Any]:
        """Stop and remove a honeypot container"""
        try:
            container = self.client.containers.get(container_id)
            container_name = container.name
            
            # Stop if running
            if container.status == 'running':
                container.stop(timeout=10)
            
            # Remove container
            container.remove(force=force)
            
            logger.info(f"Deleted honeypot: {container_name}")
            return {'success': True, 'name': container_name}
            
        except NotFound:
            return {'success': False, 'error': 'Container not found'}
        except Exception as e:
            logger.error(f"Error deleting honeypot: {e}")
            return {'success': False, 'error': str(e)}
    
    def start_honeypot(self, container_id: str) -> Dict[str, Any]:
        """Start a stopped honeypot"""
        try:
            container = self.client.containers.get(container_id)
            container.start()
            return {'success': True, 'status': 'running'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def stop_honeypot(self, container_id: str) -> Dict[str, Any]:
        """Stop a running honeypot"""
        try:
            container = self.client.containers.get(container_id)
            container.stop(timeout=10)
            return {'success': True, 'status': 'stopped'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def get_container_logs(self, container_id: str, tail: int = 100) -> str:
        """Get container logs"""
        try:
            container = self.client.containers.get(container_id)
            return container.logs(tail=tail).decode('utf-8')
        except Exception as e:
            return f"Error: {e}"
    
    def check_ip_available(self, ip_address: str) -> bool:
        """Check if IP address is available (not used by another container)"""
        try:
            network = self.client.networks.get(self.network_name)
            for container_id, container_info in network.attrs.get('Containers', {}).items():
                if container_info.get('IPv4Address', '').startswith(ip_address):
                    return False
            return True
        except Exception:
            return True  # Assume available if can't check


# Singleton instance
docker_manager = DockerManager()
