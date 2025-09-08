"""
Network and socket handling for HaLow AT Command Tool
"""

import socket
import select
import platform
import struct
from typing import Optional, Tuple, List, Dict
from .constants import NETAT_PORT, NETAT_BUFF_SIZE, SO_BINDTODEVICE

# Import netifaces with fallback
try:
    import netifaces
    NETIFACES_AVAILABLE = True
except ImportError:
    NETIFACES_AVAILABLE = False


class NetworkInterface:
    """Handles network interface operations"""
    
    @staticmethod
    def get_platform_info() -> Dict[str, str]:
        """Get platform information"""
        return {
            'system': platform.system(),
            'release': platform.release(),
            'version': platform.version(),
            'machine': platform.machine(),
            'python': platform.python_version()
        }
    
    @staticmethod
    def list_interfaces() -> List[Dict[str, any]]:
        """List available network interfaces"""
        interfaces = []
        
        if not NETIFACES_AVAILABLE:
            print("netifaces library not available. Install with: pip install netifaces")
            return interfaces
            
        try:
            for iface in netifaces.interfaces():
                info = {'name': iface, 'addresses': []}
                
                # Get IPv4 addresses
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    for addr in addrs[netifaces.AF_INET]:
                        info['addresses'].append({
                            'type': 'IPv4',
                            'addr': addr.get('addr', ''),
                            'netmask': addr.get('netmask', '')
                        })
                
                # Get MAC addresses
                if netifaces.AF_LINK in addrs:
                    for addr in addrs[netifaces.AF_LINK]:
                        mac = addr.get('addr', '')
                        if mac:
                            info['mac'] = mac
                            
                interfaces.append(info)
                
        except Exception as e:
            print(f"Error listing interfaces: {e}")
            
        return interfaces
    
    @staticmethod
    def get_interface_ip(ifname: str) -> Optional[str]:
        """Get IP address of an interface"""
        if not NETIFACES_AVAILABLE:
            return None
            
        try:
            addrs = netifaces.ifaddresses(ifname)
            if netifaces.AF_INET in addrs:
                return addrs[netifaces.AF_INET][0]['addr']
        except:
            pass
        return None
    
    @staticmethod
    def print_interfaces():
        """Print available network interfaces"""
        info = NetworkInterface.get_platform_info()
        print(f"\nPlatform: {info['system']} {info['release']}")
        print(f"Python: {info['python']}")
        
        interfaces = NetworkInterface.list_interfaces()
        
        if not interfaces:
            print("\nNo network interfaces found or netifaces not installed")
            return
            
        print("\nAvailable network interfaces:")
        print("-" * 60)
        
        for iface in interfaces:
            print(f"\nInterface: {iface['name']}")
            if 'mac' in iface:
                print(f"  MAC: {iface['mac']}")
            for addr in iface['addresses']:
                print(f"  {addr['type']}: {addr['addr']}")
                if 'netmask' in addr:
                    print(f"    Netmask: {addr['netmask']}")


class SocketManager:
    """Manages UDP socket operations"""
    
    def __init__(self, port: int = NETAT_PORT):
        self.port = port
        self.sock = None
        self.bound_interface = None
        
    def create_socket(self) -> bool:
        """Create UDP socket"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            
            # Platform-specific options
            if platform.system() == 'Linux':
                try:
                    self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                except:
                    pass
                    
            return True
            
        except Exception as e:
            print(f"Error creating socket: {e}")
            return False
    
    def bind_to_interface(self, ifname: str, allow_any: bool = False) -> bool:
        """
        Bind socket to a specific interface
        
        Args:
            ifname: Interface name or IP address
            allow_any: Allow fallback to any interface
            
        Returns:
            True if binding successful
        """
        if not self.sock:
            return False
            
        # Try multiple binding methods
        methods = [
            self._bind_linux_specific,
            self._bind_by_ip,
            self._bind_any if allow_any else None
        ]
        
        for method in methods:
            if method and method(ifname):
                return True
                
        return False
    
    def _bind_linux_specific(self, ifname: str) -> bool:
        """Try Linux-specific SO_BINDTODEVICE"""
        if platform.system() != 'Linux':
            return False
            
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, 
                               ifname.encode() + b'\0')
            self.sock.bind(('', self.port))
            self.bound_interface = ifname
            print(f"Bound to interface {ifname} using SO_BINDTODEVICE")
            return True
        except Exception as e:
            if "Protocol not available" not in str(e):
                print(f"SO_BINDTODEVICE failed: {e}")
            return False
    
    def _bind_by_ip(self, ifname: str) -> bool:
        """Try binding by IP address"""
        try:
            # Check if it's already an IP
            socket.inet_aton(ifname)
            ip = ifname
        except:
            # Try to get IP from interface name
            ip = NetworkInterface.get_interface_ip(ifname)
            if not ip:
                return False
                
        try:
            self.sock.bind((ip, self.port))
            self.bound_interface = f"{ifname} ({ip})"
            print(f"Bound to {self.bound_interface}")
            return True
        except Exception as e:
            print(f"IP binding failed for {ip}: {e}")
            return False
    
    def _bind_any(self, ifname: str) -> bool:
        """Fallback to binding to any interface"""
        try:
            self.sock.bind(('0.0.0.0', self.port))
            self.bound_interface = "any (0.0.0.0)"
            print(f"Warning: Bound to all interfaces (0.0.0.0)")
            print(f"Original interface {ifname} binding failed")
            return True
        except Exception as e:
            print(f"Fallback binding failed: {e}")
            return False
    
    def send(self, data: bytes, addr: Tuple[str, int] = None) -> int:
        """
        Send data via socket
        
        Args:
            data: Data to send
            addr: Optional destination address
            
        Returns:
            Number of bytes sent
        """
        if not self.sock:
            return 0
            
        try:
            if addr:
                return self.sock.sendto(data, addr)
            else:
                # Broadcast
                return self.sock.sendto(data, ('255.255.255.255', self.port))
        except Exception as e:
            print(f"Send error: {e}")
            return 0
    
    def receive(self, timeout: float = 2.0) -> Tuple[Optional[bytes], Optional[Tuple]]:
        """
        Receive data from socket with timeout
        
        Args:
            timeout: Receive timeout in seconds
            
        Returns:
            Tuple of (data, address) or (None, None) on timeout
        """
        if not self.sock:
            return None, None
            
        try:
            # Use select for timeout
            ready = select.select([self.sock], [], [], timeout)
            
            if ready[0]:
                data, addr = self.sock.recvfrom(NETAT_BUFF_SIZE)
                return data, addr
            else:
                return None, None
                
        except Exception as e:
            print(f"Receive error: {e}")
            return None, None
    
    def close(self):
        """Close the socket"""
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
            self.sock = None
            self.bound_interface = None


def create_broadcast_socket(port: int = NETAT_PORT) -> Optional[socket.socket]:
    """
    Create a broadcast-capable UDP socket
    
    Args:
        port: Port to bind to
        
    Returns:
        Socket object or None on failure
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        return sock
    except Exception as e:
        print(f"Error creating broadcast socket: {e}")
        return None