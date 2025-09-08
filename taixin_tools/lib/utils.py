"""
Utility functions for HaLow AT Command Tool
"""

import random
import binascii
from typing import Optional


def random_bytes(length: int) -> bytes:
    """Generate random bytes"""
    return bytes(random.randint(0, 255) for _ in range(length))


def mac_str_to_bytes(mac_str: str) -> bytes:
    """
    Convert MAC address string to bytes
    
    Args:
        mac_str: MAC address like "aa:bb:cc:dd:ee:ff"
        
    Returns:
        6-byte MAC address
    """
    mac_str = mac_str.replace(':', '').replace('-', '')
    return bytes.fromhex(mac_str)


def bytes_to_mac_str(mac_bytes: bytes) -> str:
    """
    Convert MAC bytes to string
    
    Args:
        mac_bytes: 6-byte MAC address
        
    Returns:
        MAC string like "aa:bb:cc:dd:ee:ff"
    """
    return ':'.join(f'{b:02x}' for b in mac_bytes)


def hex_to_bytes(hex_str: str) -> Optional[bytes]:
    """
    Convert hex string to bytes
    
    Args:
        hex_str: Hex string (with or without spaces)
        
    Returns:
        Bytes or None if invalid
    """
    try:
        hex_str = hex_str.replace(' ', '').replace('0x', '')
        return bytes.fromhex(hex_str)
    except:
        return None


def bytes_to_hex(data: bytes, separator: str = ' ') -> str:
    """
    Convert bytes to hex string
    
    Args:
        data: Binary data
        separator: Separator between bytes
        
    Returns:
        Hex string
    """
    return separator.join(f'{b:02x}' for b in data)


def format_packet_display(data: bytes, width: int = 16) -> str:
    """
    Format binary data for display
    
    Args:
        data: Binary data
        width: Number of bytes per line
        
    Returns:
        Formatted string with hex and ASCII
    """
    lines = []
    
    for i in range(0, len(data), width):
        chunk = data[i:i+width]
        
        # Hex part
        hex_str = ' '.join(f'{b:02x}' for b in chunk)
        hex_str = hex_str.ljust(width * 3 - 1)
        
        # ASCII part
        ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        
        lines.append(f"{i:04x}: {hex_str}  {ascii_str}")
        
    return '\n'.join(lines)


def validate_ip_address(ip_str: str) -> bool:
    """
    Validate IP address format
    
    Args:
        ip_str: IP address string
        
    Returns:
        True if valid IP address
    """
    parts = ip_str.split('.')
    if len(parts) != 4:
        return False
        
    try:
        for part in parts:
            num = int(part)
            if num < 0 or num > 255:
                return False
        return True
    except:
        return False


def password_to_hex(password: str) -> str:
    """
    Convert password string to hex for AT+PSK command
    
    Args:
        password: Plain text password
        
    Returns:
        Hex encoded password
    """
    return password.encode('utf-8').hex()


def parse_key_value_response(response: str) -> dict:
    """
    Parse key:value response format
    
    Args:
        response: Response string with key:value pairs
        
    Returns:
        Dictionary of parsed values
    """
    result = {}
    lines = response.split('\n')
    
    for line in lines:
        line = line.strip()
        if ':' in line:
            key, value = line.split(':', 1)
            result[key.strip()] = value.strip()
            
    return result