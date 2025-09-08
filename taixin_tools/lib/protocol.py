"""
Packet protocol handling for HaLow AT Command Tool
"""

import struct
import random
from typing import Optional, Tuple, Dict, Any
from .constants import WnbCommand, HEADER_SIZE, AT_TERMINATOR, MACSTR, MAC2STR


class WnbNetatCmd:
    """
    WiFi HaLow Network Bridge Protocol Packet Structure
    
    Packet format:
    - Command (1 byte): Command type
    - Length (2 bytes): Data length
    - Destination MAC (6 bytes): Target device MAC
    - Source MAC (6 bytes): Source device MAC  
    - Data (variable): Command data
    """
    
    def __init__(self, cmd: int, dest_mac: bytes = None, src_mac: bytes = None, data: bytes = b''):
        self.cmd = cmd
        self.dest_mac = dest_mac or b'\xff' * 6  # Broadcast by default
        self.src_mac = src_mac or b'\x00' * 6
        self.data = data
        self.cookie = random.randint(0, 0xFFFF)  # For request-response correlation
        
    def pack(self) -> bytes:
        """Pack the command into a byte string"""
        # Ensure data ends with CR+LF for AT commands
        if self.cmd == WnbCommand.AT_REQ and not self.data.endswith(AT_TERMINATOR.encode()):
            self.data += AT_TERMINATOR.encode()
            
        data_len = len(self.data)
        
        # Pack header: cmd(1) + len(2) + dest_mac(6) + src_mac(6)
        header = struct.pack('<BH', self.cmd, data_len)
        header += self.dest_mac[:6]
        header += self.src_mac[:6]
        
        return header + self.data
    
    @classmethod
    def unpack(cls, data: bytes) -> Optional['WnbNetatCmd']:
        """Unpack a byte string into a command object"""
        if len(data) < HEADER_SIZE:
            return None
            
        # Unpack header
        cmd, data_len = struct.unpack('<BH', data[:3])
        dest_mac = data[3:9]
        src_mac = data[9:15]
        
        # Extract data payload
        payload = data[15:15 + data_len] if data_len > 0 else b''
        
        obj = cls(cmd, dest_mac, src_mac, payload)
        return obj
    
    def get_command_name(self) -> str:
        """Get human-readable command name"""
        try:
            return WnbCommand(self.cmd).name
        except ValueError:
            return f"UNKNOWN({self.cmd})"
    
    def __str__(self) -> str:
        dest_str = MACSTR % MAC2STR(self.dest_mac)
        src_str = MACSTR % MAC2STR(self.src_mac)
        return f"Cmd={self.get_command_name()}, Dest={dest_str}, Src={src_str}, DataLen={len(self.data)}"


class EthernetFrame:
    """
    Ethernet frame structure for packet analysis
    """
    
    def __init__(self, data: bytes):
        self.raw_data = data
        self.valid = False
        
        if len(data) >= 14:  # Minimum Ethernet header size
            self.dest_mac = data[0:6]
            self.src_mac = data[6:12]
            self.ether_type = struct.unpack('>H', data[12:14])[0]
            self.payload = data[14:]
            self.valid = True
    
    def is_ipv4(self) -> bool:
        return self.ether_type == 0x0800
    
    def is_ipv6(self) -> bool:
        return self.ether_type == 0x86DD
    
    def __str__(self) -> str:
        if not self.valid:
            return "Invalid Ethernet frame"
        
        dest_str = MACSTR % MAC2STR(self.dest_mac)
        src_str = MACSTR % MAC2STR(self.src_mac)
        return f"Ethernet: {src_str} -> {dest_str}, Type=0x{self.ether_type:04x}"


def parse_at_response(data: bytes) -> Dict[str, Any]:
    """
    Parse AT command response data
    
    Expected format:
    +COMMAND:value
    OK/ERROR
    
    Args:
        data: Raw response data
        
    Returns:
        Dictionary with parsed response
    """
    result = {
        'raw': data,
        'text': '',
        'status': 'UNKNOWN',
        'values': {}
    }
    
    try:
        # Decode response
        text = data.decode('utf-8', errors='ignore').strip()
        result['text'] = text
        
        lines = text.split('\n')
        
        for line in lines:
            line = line.strip()
            
            # Check for OK/ERROR status
            if line == 'OK':
                result['status'] = 'OK'
            elif line.startswith('ERROR'):
                result['status'] = 'ERROR'
                if ':' in line:
                    result['error_code'] = line.split(':')[1].strip()
            
            # Parse +COMMAND:value format
            elif line.startswith('+'):
                if ':' in line:
                    cmd_part, value_part = line.split(':', 1)
                    cmd_name = cmd_part[1:].strip()  # Remove '+' prefix
                    result['values'][cmd_name] = value_part.strip()
                else:
                    # Handle commands without values
                    cmd_name = line[1:].strip()
                    result['values'][cmd_name] = True
                    
    except Exception as e:
        result['parse_error'] = str(e)
    
    return result


def create_scan_packet() -> bytes:
    """Create a scan packet to discover HaLow devices"""
    cmd = WnbNetatCmd(WnbCommand.SCAN_REQ)
    return cmd.pack()


def create_at_packet(at_command: str, dest_mac: bytes = None) -> bytes:
    """
    Create an AT command packet
    
    Args:
        at_command: AT command string
        dest_mac: Optional destination MAC address
        
    Returns:
        Packed packet bytes
    """
    # Ensure command is properly formatted
    if not at_command.upper().startswith('AT'):
        at_command = 'AT+' + at_command
        
    cmd = WnbNetatCmd(
        cmd=WnbCommand.AT_REQ,
        dest_mac=dest_mac,
        data=at_command.encode()
    )
    return cmd.pack()


def create_data_packet(data: bytes, dest_mac: bytes = None) -> bytes:
    """
    Create a data transmission packet
    
    Args:
        data: Data to send
        dest_mac: Optional destination MAC address
        
    Returns:
        Packed packet bytes
    """
    cmd = WnbNetatCmd(
        cmd=WnbCommand.DATA_REQ,
        dest_mac=dest_mac,
        data=data
    )
    return cmd.pack()