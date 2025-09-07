#!/usr/bin/env python3
"""
AT Command Configuration Tool for Taixin TX-AH-R WiFi HaLow Modules
====================================================================
This tool enables communication with WiFi HaLow (802.11ah) modules using AT commands
over UDP broadcast protocol. It provides a command-line interface for configuring
and controlling HaLow modules.

Based on the manufacturer's protocol specification for network-based AT command tools.

Author: pylibnetat contributors
License: See LICENSE file
Version: 4.0
"""

import socket
import struct
import random
import time
import select
import sys
import platform
import argparse
import logging
import json
import os
import threading
import queue
import binascii
from typing import Optional, Tuple, Union, Dict, List, Any
from datetime import datetime
from enum import IntEnum

# ============================================================================
# CONSTANTS AND CONFIGURATION
# ============================================================================

# Network configuration
NETAT_BUFF_SIZE = 2048  # Increased buffer for larger responses
NETAT_PORT = 56789      # UDP port for AT command communication

# Protocol command identifiers
class WnbCommand(IntEnum):
    """WiFi HaLow Network Bridge Protocol Commands"""
    SCAN_REQ = 1   # Request to scan for devices
    SCAN_RESP = 2  # Response from device scan
    AT_REQ = 3     # AT command request
    AT_RESP = 4    # AT command response
    DATA_REQ = 5   # Data transmission request
    DATA_RESP = 6  # Data transmission response

# MAC address formatting helpers
MAC2STR = lambda a: (a[0] & 0xff, a[1] & 0xff, a[2] & 0xff, 
                     a[3] & 0xff, a[4] & 0xff, a[5] & 0xff)
MACSTR = "%02x:%02x:%02x:%02x:%02x:%02x"

# Platform-specific socket options
SO_BINDTODEVICE = 25  # Linux socket option for binding to specific interface

# AT Command termination characters
AT_TERMINATOR = "\r\n"  # CR+LF as per documentation

# ============================================================================
# LOGGING CONFIGURATION
# ============================================================================

class ColoredFormatter(logging.Formatter):
    """Custom formatter with colors for terminal output"""
    
    COLORS = {
        'DEBUG': '\033[36m',    # Cyan
        'INFO': '\033[32m',     # Green
        'WARNING': '\033[33m',  # Yellow
        'ERROR': '\033[31m',    # Red
        'CRITICAL': '\033[35m', # Magenta
        'PACKET': '\033[34m',   # Blue
        'RESET': '\033[0m'      # Reset
    }
    
    def format(self, record):
        if hasattr(record, 'packet'):
            record.levelname = 'PACKET'
        color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
        record.levelname = f"{color}{record.levelname}{self.COLORS['RESET']}"
        return super().format(record)

def setup_logging(debug: bool = False, verbose: bool = False):
    """
    Configure logging based on debug and verbose flags.
    
    Args:
        debug: If True, sets logging level to DEBUG
        verbose: If True, enables packet-level logging
    """
    level = logging.DEBUG if debug else logging.INFO
    
    # Create logger
    logger = logging.getLogger(__name__)
    logger.setLevel(level)
    
    # Clear existing handlers
    logger.handlers = []
    
    # Create console handler
    handler = logging.StreamHandler()
    handler.setLevel(level)
    
    # Set formatter
    if sys.stdout.isatty():  # Use colors if terminal
        formatter = ColoredFormatter(
            '%(asctime)s - %(levelname)s - %(funcName)s - %(message)s',
            datefmt='%H:%M:%S'
        )
    else:
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(funcName)s - %(message)s'
        )
    
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    
    # Add packet logger if verbose
    if verbose:
        logger.packet = lambda msg: logger.log(35, msg, extra={'packet': True})
    else:
        logger.packet = lambda msg: None
    
    return logger

logger = setup_logging()

# ============================================================================
# PROTOCOL CLASSES
# ============================================================================

class WnbNetatCmd:
    """
    Represents a WiFi HaLow AT command packet structure.
    
    Packet format:
    - cmd (1 byte): Command type identifier
    - len (2 bytes): Length of data payload (big-endian)
    - dest (6 bytes): Destination MAC address
    - src (6 bytes): Source MAC address
    - data (variable): Command data payload
    
    Total header size: 15 bytes
    """
    
    HEADER_SIZE = 15
    
    def __init__(self):
        self.cmd = 0
        self.len = 0
        self.dest = b'\x00\x00\x00\x00\x00\x00'
        self.src = b'\x00\x00\x00\x00\x00\x00'
        self.data = b''
    
    def __bytes__(self):
        """Convert command to bytes for transmission."""
        len_bytes = struct.pack('>H', len(self.data))
        return bytes([self.cmd]) + len_bytes + self.dest + self.src + self.data
    
    @classmethod
    def from_bytes(cls, data: bytes):
        """Parse packet from bytes."""
        if len(data) < cls.HEADER_SIZE:
            return None
        
        cmd = cls()
        cmd.cmd = data[0]
        cmd.len = struct.unpack('>H', data[1:3])[0]
        cmd.dest = data[3:9]
        cmd.src = data[9:15]
        cmd.data = data[15:15+cmd.len] if len(data) >= 15+cmd.len else data[15:]
        return cmd
    
    def __str__(self):
        """String representation for debugging."""
        cmd_name = WnbCommand(self.cmd).name if self.cmd in WnbCommand.__members__.values() else f"UNKNOWN({self.cmd})"
        return (f"WnbNetatCmd(cmd={cmd_name}, len={len(self.data)}, "
                f"dest={self.dest.hex()}, src={self.src.hex()}, "
                f"data={self.data[:50]}{'...' if len(self.data) > 50 else ''})")
    
    def to_hex_dump(self):
        """Generate detailed hex dump for packet analysis."""
        packet = bytes(self)
        lines = []
        lines.append("=" * 60)
        lines.append(f"Packet Analysis (Total: {len(packet)} bytes)")
        lines.append("=" * 60)
        lines.append(f"CMD:  0x{self.cmd:02x} ({WnbCommand(self.cmd).name if self.cmd in WnbCommand.__members__.values() else 'UNKNOWN'})")
        lines.append(f"LEN:  0x{struct.pack('>H', len(self.data)).hex()} ({len(self.data)} bytes)")
        lines.append(f"DEST: {self.dest.hex()} ({':'.join(f'{b:02x}' for b in self.dest)})")
        lines.append(f"SRC:  {self.src.hex()} ({':'.join(f'{b:02x}' for b in self.src)})")
        
        if self.data:
            lines.append(f"\nDATA ({len(self.data)} bytes):")
            # Hex dump of data
            for i in range(0, len(self.data), 16):
                chunk = self.data[i:i+16]
                hex_str = ' '.join(f'{b:02x}' for b in chunk)
                ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
                lines.append(f"  {i:04x}: {hex_str:<48} |{ascii_str}|")
            
            # Try to decode as string
            try:
                decoded = self.data.decode('utf-8', errors='ignore').strip()
                if decoded:
                    lines.append(f"\nDecoded: {decoded}")
            except:
                pass
        
        lines.append("=" * 60)
        return '\n'.join(lines)


class EthernetFrame:
    """
    Ethernet frame header for 1-to-many mode data transmission.
    
    Frame format (14 bytes):
    - Destination MAC (6 bytes)
    - Source MAC (6 bytes)
    - Protocol Type (2 bytes)
    """
    
    HEADER_SIZE = 14
    
    def __init__(self, dest_mac: bytes = None, src_mac: bytes = None, proto: int = 0x9999):
        self.dest_mac = dest_mac or b'\xff\xff\xff\xff\xff\xff'  # Broadcast by default
        self.src_mac = src_mac or b'\x00\x00\x00\x00\x00\x00'    # Zero by default
        self.proto = proto
    
    def __bytes__(self):
        """Convert to bytes."""
        return self.dest_mac + self.src_mac + struct.pack('>H', self.proto)
    
    @classmethod
    def from_bytes(cls, data: bytes):
        """Parse from bytes."""
        if len(data) < cls.HEADER_SIZE:
            return None
        frame = cls()
        frame.dest_mac = data[0:6]
        frame.src_mac = data[6:12]
        frame.proto = struct.unpack('>H', data[12:14])[0]
        return frame


class NetatMgr:
    """
    Manager class for handling network AT command communication.
    
    Attributes:
        sock: UDP socket for communication
        dest: Destination MAC address (default: broadcast)
        cookie: Random identifier for matching requests/responses
        interface: Network interface name
        debug: Debug mode flag
        verbose: Verbose packet logging
        packet_capture: Enable packet capture to file
        device_map: Mapping of device IDs to MAC addresses
    """
    
    def __init__(self, debug: bool = False, verbose: bool = False):
        self.sock = None
        self.dest = b'\xff\xff\xff\xff\xff\xff'  # Broadcast MAC
        self.cookie = b'\x00\x00\x00\x00\x00\x00'
        self.interface = None
        self.debug = debug
        self.verbose = verbose
        self.bind_method = None
        self.packet_capture = None
        self.device_map = {}  # Device ID to MAC mapping for 1-to-many mode
        self.response_queue = queue.Queue()
        self.sniffer_thread = None
        self.running = False
        self.last_response = None
        self.mode = 'one-to-one'  # Default mode
    
    def start_packet_capture(self, filename: str):
        """Start capturing packets to file."""
        self.packet_capture = open(filename, 'ab')
        logger.info(f"Started packet capture to {filename}")
    
    def stop_packet_capture(self):
        """Stop packet capture."""
        if self.packet_capture:
            self.packet_capture.close()
            self.packet_capture = None
            logger.info("Stopped packet capture")
    
    def capture_packet(self, direction: str, data: bytes, addr: tuple = None):
        """Capture packet to file if enabled."""
        if self.packet_capture:
            timestamp = datetime.now().isoformat()
            entry = {
                'timestamp': timestamp,
                'direction': direction,
                'addr': str(addr) if addr else None,
                'data': binascii.hexlify(data).decode(),
                'size': len(data)
            }
            self.packet_capture.write(json.dumps(entry).encode() + b'\n')
            self.packet_capture.flush()

# Global instance
libnetat = None

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def random_bytes(length: int) -> bytes:
    """Generate random bytes for use as cookies/identifiers."""
    return bytes([random.randint(0, 255) for _ in range(length)])


def mac_str_to_bytes(mac_str: str) -> bytes:
    """Convert MAC address string to bytes."""
    parts = mac_str.replace(':', '').replace('-', '')
    return bytes.fromhex(parts)


def get_platform_info() -> dict:
    """Get detailed platform information for debugging."""
    return {
        'system': platform.system(),
        'release': platform.release(),
        'version': platform.version(),
        'machine': platform.machine(),
        'python_version': platform.python_version()
    }


def list_network_interfaces():
    """List available network interfaces on the system."""
    logger.info("Available network interfaces:")
    
    try:
        import netifaces
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:
                for addr in addrs[netifaces.AF_INET]:
                    logger.info(f"  {iface}: {addr.get('addr', 'N/A')}")
    except ImportError:
        logger.info("  Install 'netifaces' package for interface listing: pip install netifaces")
        # Fallback method
        if platform.system() != 'Windows':
            import subprocess
            try:
                if platform.system() == 'Darwin':  # macOS
                    result = subprocess.run(['ifconfig'], capture_output=True, text=True)
                else:  # Linux
                    result = subprocess.run(['ip', 'addr'], capture_output=True, text=True)
                logger.info("System network interfaces:")
                for line in result.stdout.split('\n'):
                    if 'inet ' in line or ': ' in line:
                        logger.info(f"  {line.strip()}")
            except Exception as e:
                logger.error(f"Could not list interfaces: {e}")

# ============================================================================
# SOCKET OPERATIONS
# ============================================================================

def sock_send(sock: socket.socket, data: bytes, addr: tuple = None) -> int:
    """
    Send data via UDP.
    
    Args:
        sock: UDP socket to send through
        data: Bytes to send
        addr: Optional specific address, otherwise broadcast
    
    Returns:
        Number of bytes sent
    """
    global libnetat
    
    dest = addr or ('<broadcast>', NETAT_PORT)
    logger.debug(f"Sending {len(data)} bytes to {dest}")
    
    if libnetat and libnetat.verbose:
        cmd = WnbNetatCmd.from_bytes(data)
        if cmd:
            logger.packet(f"TX Packet:\n{cmd.to_hex_dump()}")
        else:
            logger.packet(f"TX Raw ({len(data)} bytes): {data.hex()}")
    
    try:
        sent = sock.sendto(data, dest)
        logger.debug(f"Successfully sent {sent} bytes")
        
        # Capture packet
        if libnetat:
            libnetat.capture_packet('TX', data, dest)
        
        return sent
    except Exception as e:
        logger.error(f"Failed to send data: {e}")
        return 0


def sock_recv(sock: socket.socket, timeout: float) -> Tuple[Optional[bytes], Optional[tuple]]:
    """
    Receive data from socket with timeout.
    
    Args:
        sock: UDP socket to receive from
        timeout: Timeout in seconds
    
    Returns:
        Tuple of (data, address) or (None, None) on timeout
    """
    global libnetat
    
    logger.debug(f"Waiting for data with timeout={timeout}s")
    
    try:
        rlist, _, _ = select.select([sock], [], [], timeout)
        if sock in rlist:
            data, addr = sock.recvfrom(NETAT_BUFF_SIZE)
            logger.debug(f"Received {len(data)} bytes from {addr}")
            
            if libnetat and libnetat.verbose:
                cmd = WnbNetatCmd.from_bytes(data)
                if cmd:
                    logger.packet(f"RX Packet from {addr}:\n{cmd.to_hex_dump()}")
                else:
                    logger.packet(f"RX Raw ({len(data)} bytes): {data.hex()}")
            
            # Capture packet
            if libnetat:
                libnetat.capture_packet('RX', data, addr)
            
            return data, addr
    except Exception as e:
        logger.error(f"Error receiving data: {e}")
    
    logger.debug("Receive timeout - no data")
    return None, None

# ============================================================================
# PROTOCOL OPERATIONS
# ============================================================================

def netat_scan():
    """Send a broadcast scan request to discover HaLow devices."""
    global libnetat
    logger.info("Scanning for HaLow devices...")
    
    scan = WnbNetatCmd()
    libnetat.cookie = random_bytes(6)
    scan.cmd = WnbCommand.SCAN_REQ
    scan.dest = b'\xff\xff\xff\xff\xff\xff'  # Broadcast to all
    scan.src = libnetat.cookie
    scan.data = b''  # Empty data for scan
    
    logger.debug(f"Scan packet: {scan}")
    sock_send(libnetat.sock, bytes(scan))


def netat_send_at(atcmd: str):
    """
    Send an AT command to the target device.
    
    Args:
        atcmd: AT command string to send
    """
    global libnetat
    logger.info(f"Sending AT command: {atcmd}")
    
    # Ensure proper termination
    if not atcmd.endswith(AT_TERMINATOR):
        atcmd += AT_TERMINATOR
    
    cmd = WnbNetatCmd()
    libnetat.cookie = random_bytes(6)
    cmd.cmd = WnbCommand.AT_REQ
    cmd.dest = libnetat.dest
    cmd.src = libnetat.cookie
    cmd.data = atcmd.encode('utf-8')
    
    logger.debug(f"AT command packet: {cmd}")
    sock_send(libnetat.sock, bytes(cmd))


def netat_send_data(data: bytes, dest_mac: bytes = None):
    """
    Send data using AT+TXDATA protocol.
    
    Args:
        data: Raw data to send
        dest_mac: Destination MAC for 1-to-many mode
    """
    global libnetat
    
    if libnetat.mode == 'one-to-many' and dest_mac:
        # Add Ethernet frame header
        frame = EthernetFrame(dest_mac=dest_mac)
        data = bytes(frame) + data
        logger.debug(f"Added Ethernet frame header: {frame}")
    
    # Send using AT+TXDATA command
    atcmd = f"AT+TXDATA={len(data)}"
    netat_send_at(atcmd)
    time.sleep(0.1)  # Wait for OK response
    
    # Send actual data
    cmd = WnbNetatCmd()
    cmd.cmd = WnbCommand.DATA_REQ
    cmd.dest = libnetat.dest
    cmd.src = libnetat.cookie
    cmd.data = data
    
    sock_send(libnetat.sock, bytes(cmd))


def parse_at_response(data: bytes) -> Dict[str, Any]:
    """
    Parse AT command response.
    
    Expected formats:
    - +COMMAND:value
    - OK
    - ERROR
    - +RXDATA:length\\r\\n<data>
    """
    try:
        text = data.decode('utf-8', errors='ignore').strip()
        result = {
            'raw': text,
            'success': False,
            'command': None,
            'value': None,
            'data': None
        }
        
        lines = text.split('\r\n')
        for line in lines:
            line = line.strip()
            if line == 'OK':
                result['success'] = True
            elif line == 'ERROR':
                result['success'] = False
            elif line.startswith('+'):
                # Parse +COMMAND:value format
                if ':' in line:
                    parts = line[1:].split(':', 1)
                    result['command'] = parts[0]
                    result['value'] = parts[1] if len(parts) > 1 else ''
                    
                    # Special handling for RXDATA
                    if result['command'] == 'RXDATA':
                        try:
                            length = int(result['value'])
                            # Data follows after the command line
                            data_start = text.index('\r\n', text.index('+RXDATA')) + 2
                            result['data'] = data[data_start:data_start+length]
                        except:
                            pass
        
        return result
    except Exception as e:
        logger.error(f"Error parsing AT response: {e}")
        return {'raw': data.hex(), 'success': False}


def netat_recv(timeout: float = 2.0) -> Optional[Dict[str, Any]]:
    """
    Receive and process responses from HaLow devices.
    
    Args:
        timeout: Timeout in seconds to wait for response
    
    Returns:
        Parsed response dictionary or None
    """
    global libnetat
    responses = []
    start_time = time.time()
    
    while time.time() - start_time < timeout:
        remaining = timeout - (time.time() - start_time)
        if remaining <= 0:
            break
            
        data, addr = sock_recv(libnetat.sock, remaining)
        if data:
            cmd = WnbNetatCmd.from_bytes(data)
            if not cmd:
                logger.warning(f"Invalid packet received: {data.hex()}")
                continue
            
            logger.debug(f"Parsed packet: {cmd}")
            
            # Check if response matches our cookie
            if cmd.dest == libnetat.cookie:
                logger.info(f"Received matching response (cmd={WnbCommand(cmd.cmd).name if cmd.cmd in WnbCommand.__members__.values() else cmd.cmd})")
                
                if cmd.cmd == WnbCommand.SCAN_RESP:
                    libnetat.dest = cmd.src
                    logger.info(f"Device found at MAC: {':'.join(f'{b:02x}' for b in cmd.src)}")
                    responses.append({'type': 'scan', 'mac': cmd.src.hex()})
                    
                elif cmd.cmd == WnbCommand.AT_RESP:
                    response = parse_at_response(cmd.data)
                    logger.info(f"AT response: {response}")
                    responses.append(response)
                    libnetat.last_response = response
                    
                    # Print formatted response
                    if response.get('command'):
                        print(f"+{response['command']}:{response.get('value', '')}")
                    if response.get('success'):
                        print("OK")
                    elif 'ERROR' in response.get('raw', ''):
                        print("ERROR")
                    
                elif cmd.cmd == WnbCommand.DATA_RESP:
                    logger.info(f"Data response received: {len(cmd.data)} bytes")
                    responses.append({'type': 'data', 'data': cmd.data})
            else:
                logger.debug(f"Cookie mismatch: {cmd.dest.hex()} != {libnetat.cookie.hex()}")
    
    return responses[0] if responses else None

# ============================================================================
# AT COMMAND HELPERS
# ============================================================================

class ATCommands:
    """Common AT command shortcuts and helpers."""
    
    @staticmethod
    def set_mode(mode: str) -> bool:
        """Set device mode (ap/sta/group/apsta)."""
        logger.info(f"Setting mode to {mode}")
        netat_send_at(f"AT+MODE={mode}")
        response = netat_recv()
        return response and response.get('success')
    
    @staticmethod
    def set_ssid(ssid: str) -> bool:
        """Set SSID (max 32 characters)."""
        if len(ssid) > 32:
            logger.error("SSID too long (max 32 characters)")
            return False
        logger.info(f"Setting SSID to {ssid}")
        netat_send_at(f"AT+SSID={ssid}")
        response = netat_recv()
        return response and response.get('success')
    
    @staticmethod
    def set_encryption(mode: str) -> bool:
        """Set encryption mode (WPA-PSK/NONE)."""
        logger.info(f"Setting encryption to {mode}")
        netat_send_at(f"AT+KEYMGMT={mode}")
        response = netat_recv()
        return response and response.get('success')
    
    @staticmethod
    def set_password(psk: str) -> bool:
        """Set encryption password (64 hex characters)."""
        if len(psk) != 64:
            logger.error("PSK must be exactly 64 hex characters")
            return False
        logger.info("Setting encryption password")
        netat_send_at(f"AT+PSK={psk}")
        response = netat_recv()
        return response and response.get('success')
    
    @staticmethod
    def set_bandwidth(bw: int) -> bool:
        """Set BSS bandwidth (1/2/4/8 MHz)."""
        if bw not in [1, 2, 4, 8]:
            logger.error("Invalid bandwidth (must be 1, 2, 4, or 8)")
            return False
        logger.info(f"Setting bandwidth to {bw}MHz")
        netat_send_at(f"AT+BSS_BW={bw}")
        response = netat_recv()
        return response and response.get('success')
    
    @staticmethod
    def set_frequency_range(start: int, end: int) -> bool:
        """Set frequency range (value = frequency * 10)."""
        logger.info(f"Setting frequency range: {start/10}MHz - {end/10}MHz")
        netat_send_at(f"AT+FREQ_RANGE={start},{end}")
        response = netat_recv()
        return response and response.get('success')
    
    @staticmethod
    def get_rssi(index: int = None, mac: str = None) -> Optional[int]:
        """Get RSSI value."""
        if mac:
            netat_send_at(f"AT+RSSI={mac}")
        elif index:
            netat_send_at(f"AT+RSSI={index}")
        else:
            netat_send_at("AT+RSSI")
        
        response = netat_recv()
        if response and response.get('command') == 'RSSI':
            try:
                return int(response.get('value', '0'))
            except:
                pass
        return None
    
    @staticmethod
    def get_connection_state() -> str:
        """Get connection state."""
        netat_send_at("AT+CONN_STATE")
        response = netat_recv()
        if response:
            if 'CONNECTED' in response.get('raw', ''):
                return 'CONNECTED'
            elif 'DISCONNECT' in response.get('raw', ''):
                return 'DISCONNECTED'
        return 'UNKNOWN'
    
    @staticmethod
    def start_pairing() -> bool:
        """Start pairing process."""
        logger.info("Starting pairing")
        netat_send_at("AT+PAIR=1")
        response = netat_recv()
        return response and response.get('success')
    
    @staticmethod
    def stop_pairing() -> bool:
        """Stop pairing process."""
        logger.info("Stopping pairing")
        netat_send_at("AT+PAIR=0")
        response = netat_recv()
        return response and response.get('success')
    
    @staticmethod
    def quick_setup_ap(ssid: str, password: str = None, bandwidth: int = 8):
        """Quick setup for AP mode."""
        logger.info("Quick AP setup")
        success = True
        
        # Set frequency range (908-924 MHz as example)
        success &= ATCommands.set_frequency_range(9080, 9240)
        
        # Set bandwidth
        success &= ATCommands.set_bandwidth(bandwidth)
        
        # Set SSID
        success &= ATCommands.set_ssid(ssid)
        
        # Set encryption
        if password:
            success &= ATCommands.set_encryption("WPA-PSK")
            # Convert password to 64 hex chars (simplified - should use proper PSK generation)
            psk = password.encode().hex().ljust(64, '0')[:64]
            success &= ATCommands.set_password(psk)
        else:
            success &= ATCommands.set_encryption("NONE")
        
        # Set mode
        success &= ATCommands.set_mode("ap")
        
        return success
    
    @staticmethod
    def quick_setup_sta(ssid: str, password: str = None):
        """Quick setup for STA mode."""
        logger.info("Quick STA setup")
        success = True
        
        # Set SSID
        success &= ATCommands.set_ssid(ssid)
        
        # Set encryption
        if password:
            success &= ATCommands.set_encryption("WPA-PSK")
            # Convert password to 64 hex chars (simplified - should use proper PSK generation)
            psk = password.encode().hex().ljust(64, '0')[:64]
            success &= ATCommands.set_password(psk)
        else:
            success &= ATCommands.set_encryption("NONE")
        
        # Set mode
        success &= ATCommands.set_mode("sta")
        
        return success

# ============================================================================
# INITIALIZATION FUNCTIONS
# ============================================================================

def bind_socket_linux(sock: socket.socket, ifname: str) -> bool:
    """Bind socket to interface on Linux systems."""
    try:
        logger.debug(f"Trying SO_BINDTODEVICE for interface {ifname}")
        req = struct.pack('16s', ifname.encode('utf-8'))
        sock.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, req)
        logger.info(f"Successfully bound to {ifname} using SO_BINDTODEVICE")
        return True
    except PermissionError:
        logger.warning("SO_BINDTODEVICE requires root privileges")
    except Exception as e:
        logger.debug(f"SO_BINDTODEVICE failed: {e}")
    return False


def bind_socket_generic(sock: socket.socket, ifname: str) -> bool:
    """Generic socket binding method that works across platforms."""
    # Try binding to specific IP if provided
    if '.' in ifname:
        try:
            logger.debug(f"Binding to IP address: {ifname}")
            sock.bind((ifname, NETAT_PORT))
            logger.info(f"Successfully bound to {ifname}:{NETAT_PORT}")
            return True
        except Exception as e:
            logger.error(f"Failed to bind to {ifname}: {e}")
            return False
    
    # Get IP from interface name
    try:
        import netifaces
        logger.debug(f"Looking up IP for interface {ifname}")
        addrs = netifaces.ifaddresses(ifname)
        if netifaces.AF_INET in addrs:
            ip = addrs[netifaces.AF_INET][0]['addr']
            logger.debug(f"Found IP {ip} for interface {ifname}")
            sock.bind((ip, NETAT_PORT))
            logger.info(f"Successfully bound to {ip}:{NETAT_PORT} (interface {ifname})")
            return True
    except ImportError:
        logger.warning("netifaces not installed, cannot lookup interface IP")
        logger.info("Install with: pip install netifaces")
    except Exception as e:
        logger.debug(f"Interface IP lookup failed: {e}")
    
    return False


def libnetat_init(ifname: str, allow_any: bool = False) -> int:
    """Initialize the AT command manager with network configuration."""
    global libnetat
    
    logger.info("="*60)
    logger.info("HaLow AT Command Interface v4.0")
    logger.info("="*60)
    logger.info(f"Platform: {get_platform_info()}")
    logger.info(f"Interface: {ifname}")
    logger.info("="*60)
    
    # Reset destination to broadcast
    libnetat.dest = b'\xff\xff\xff\xff\xff\xff'
    libnetat.interface = ifname
    
    try:
        # Create UDP socket
        logger.debug("Creating UDP socket")
        libnetat.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # Enable broadcast
        logger.debug("Enabling broadcast mode")
        libnetat.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        
        # Set socket to non-blocking
        libnetat.sock.setblocking(False)
        
        # Platform-specific binding
        bound = False
        system = platform.system()
        
        if system == 'Linux':
            bound = bind_socket_linux(libnetat.sock, ifname)
            if bound:
                libnetat.bind_method = "SO_BINDTODEVICE"
        
        if not bound:
            bound = bind_socket_generic(libnetat.sock, ifname)
            if bound:
                libnetat.bind_method = "IP_BINDING"
        
        if not bound and allow_any:
            logger.warning(f"Could not bind to {ifname}, binding to all interfaces")
            try:
                libnetat.sock.bind(('0.0.0.0', NETAT_PORT))
                logger.info(f"Successfully bound to 0.0.0.0:{NETAT_PORT} (all interfaces)")
                libnetat.bind_method = "ANY_INTERFACE"
                bound = True
            except Exception as e:
                logger.error(f"Failed to bind to any interface: {e}")
        
        if not bound:
            logger.error(f"Failed to bind socket to {ifname}")
            logger.info("\nTroubleshooting tips:")
            logger.info("1. Check if the interface exists: ifconfig or ip addr")
            logger.info("2. Try using the IP address instead of interface name")
            logger.info("3. On Linux, try running with sudo for interface binding")
            logger.info("4. Use --any flag to bind to all interfaces")
            logger.info("5. Check if port 56789 is already in use")
            libnetat.sock.close()
            return -1
        
        logger.info(f"Socket initialized (method: {libnetat.bind_method})")
        
        # Initial device scan
        logger.info("Performing initial device scan...")
        netat_scan()
        netat_recv(1)
        
        if libnetat.dest[0] & 0x1:  # Still broadcast address
            logger.warning("No devices found in initial scan")
            logger.info("Device will be scanned when sending first command")
        else:
            logger.info(f"Device detected: {':'.join(f'{b:02x}' for b in libnetat.dest)}")
        
        return 0
        
    except Exception as e:
        logger.error(f"Initialization failed: {e}")
        if libnetat.sock:
            libnetat.sock.close()
        return -1


def libnetat_send(atcmd: str) -> int:
    """Send an AT command and receive response."""
    global libnetat
    
    if libnetat.sock is None:
        logger.error("libnetat is not initialized!")
        return -1
    
    # Check if we need to scan for device
    if libnetat.dest[0] & 0x1:  # Broadcast/multicast address
        logger.info("Scanning for device...")
        netat_scan()
        response = netat_recv(1)
        
        if not response or libnetat.dest[0] & 0x1:
            logger.error("No HaLow device detected!")
            logger.info("\nTroubleshooting:")
            logger.info("1. Check if the HaLow module is powered on")
            logger.info("2. Verify network connectivity")
            logger.info("3. Ensure you're on the same network segment")
            logger.info("4. Check firewall settings for UDP port 56789")
            return -1
    
    # Send AT command
    netat_send_at(atcmd)
    
    # Receive response
    response = netat_recv(2)
    
    if not response:
        logger.warning("No response received")
    
    return 0

# ============================================================================
# RAW PACKET MODE
# ============================================================================

def raw_packet_mode():
    """Interactive raw packet mode for testing."""
    global libnetat
    
    print("\n" + "="*60)
    print("RAW PACKET MODE")
    print("="*60)
    print("Commands:")
    print("  hex <data>    - Send raw hex data")
    print("  cmd <c> <data> - Send with command byte")
    print("  scan          - Send scan request")
    print("  recv          - Receive packets")
    print("  exit          - Exit raw mode")
    print("="*60 + "\n")
    
    while True:
        try:
            cmd = input("RAW> ").strip()
            
            if not cmd:
                continue
            
            if cmd == 'exit':
                break
            
            elif cmd == 'scan':
                netat_scan()
                netat_recv(1)
            
            elif cmd == 'recv':
                print("Receiving for 5 seconds...")
                netat_recv(5)
            
            elif cmd.startswith('hex '):
                hex_data = cmd[4:].replace(' ', '')
                try:
                    data = bytes.fromhex(hex_data)
                    sock_send(libnetat.sock, data)
                except ValueError:
                    print("Invalid hex data")
            
            elif cmd.startswith('cmd '):
                parts = cmd.split(' ', 2)
                if len(parts) >= 2:
                    try:
                        cmd_byte = int(parts[1])
                        data = parts[2].encode() if len(parts) > 2 else b''
                        
                        packet = WnbNetatCmd()
                        packet.cmd = cmd_byte
                        packet.dest = libnetat.dest
                        packet.src = libnetat.cookie
                        packet.data = data
                        
                        sock_send(libnetat.sock, bytes(packet))
                    except ValueError:
                        print("Invalid command byte")
            
            else:
                print("Unknown command")
                
        except KeyboardInterrupt:
            print("\nExiting raw mode")
            break
        except Exception as e:
            logger.error(f"Error in raw mode: {e}")

# ============================================================================
# SERIAL PORT SUPPORT
# ============================================================================

def serial_mode(port: str, baudrate: int = 115200):
    """Serial port mode for direct UART communication."""
    try:
        import serial
    except ImportError:
        logger.error("PySerial not installed. Install with: pip install pyserial")
        return -1
    
    logger.info(f"Opening serial port {port} at {baudrate} baud")
    
    try:
        ser = serial.Serial(
            port=port,
            baudrate=baudrate,
            bytesize=8,
            parity='N',
            stopbits=1,
            timeout=1,
            rtscts=False,
            dsrdtr=False
        )
        
        # Set new line mode
        ser.write(b'\r\n')
        time.sleep(0.1)
        
        # Test with AT+
        ser.write(b'AT+\r\n')
        time.sleep(0.5)
        response = ser.read(ser.in_waiting)
        if response:
            logger.info(f"Serial response: {response.decode('utf-8', errors='ignore')}")
        
        print("\n" + "="*60)
        print(f"Serial Mode - {port} @ {baudrate}")
        print("="*60)
        print("Enter AT commands (e.g., 'AT+GMR')")
        print("Type 'exit' to quit")
        print("="*60 + "\n")
        
        # Start reader thread
        def serial_reader():
            while ser.is_open:
                if ser.in_waiting:
                    data = ser.read(ser.in_waiting)
                    print(data.decode('utf-8', errors='ignore'), end='')
                time.sleep(0.01)
        
        import threading
        reader = threading.Thread(target=serial_reader, daemon=True)
        reader.start()
        
        # Main loop
        while True:
            try:
                cmd = input()
                if cmd.lower() == 'exit':
                    break
                
                # Send command with proper termination
                if not cmd.endswith('\r\n'):
                    cmd += '\r\n'
                ser.write(cmd.encode())
                
            except KeyboardInterrupt:
                break
        
        ser.close()
        logger.info("Serial port closed")
        
    except Exception as e:
        logger.error(f"Serial port error: {e}")
        return -1
    
    return 0

# ============================================================================
# MAIN PROGRAM
# ============================================================================

def main():
    """Main entry point for the AT command tool."""
    global libnetat, logger
    
    parser = argparse.ArgumentParser(
        description='AT Command Configuration Tool for Taixin TX-AH-R WiFi HaLow Modules',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s eth0                    # Use eth0 interface
  %(prog)s 192.168.1.100          # Bind to specific IP
  %(prog)s en0 --debug            # macOS with debug output
  %(prog)s wlan0 --any            # Allow fallback to any interface
  %(prog)s --list                 # List available interfaces
  %(prog)s --serial COM3          # Use serial port (Windows)
  %(prog)s --serial /dev/ttyUSB0  # Use serial port (Linux/Mac)
  %(prog)s eth0 --raw             # Raw packet mode
  %(prog)s eth0 --capture packets.json  # Capture packets
  
AT Command Examples:
  AT+MODE?                # Query current mode
  AT+MODE=ap              # Set AP mode
  AT+SSID=test_network   # Set SSID
  AT+KEYMGMT=NONE        # Disable encryption
  AT+BSS_BW=8            # Set 8MHz bandwidth
  AT+RSSI                # Get signal strength
  AT+CONN_STATE          # Check connection
        """
    )
    
    parser.add_argument('interface', nargs='?', 
                        help='Network interface name or IP address')
    parser.add_argument('--debug', '-d', action='store_true',
                        help='Enable debug output')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Enable verbose packet logging')
    parser.add_argument('--any', '-a', action='store_true',
                        help='Allow binding to any interface if specific binding fails')
    parser.add_argument('--list', '-l', action='store_true',
                        help='List available network interfaces and exit')
    parser.add_argument('--timeout', '-t', type=float, default=2.0,
                        help='Response timeout in seconds (default: 2.0)')
    parser.add_argument('--capture', '-c', metavar='FILE',
                        help='Capture packets to file')
    parser.add_argument('--raw', '-r', action='store_true',
                        help='Enter raw packet mode')
    parser.add_argument('--serial', '-s', metavar='PORT',
                        help='Use serial port instead of network')
    parser.add_argument('--baudrate', '-b', type=int, default=115200,
                        help='Serial baudrate (default: 115200)')
    parser.add_argument('--mode', '-m', choices=['one-to-one', 'one-to-many'],
                        default='one-to-one',
                        help='Communication mode (default: one-to-one)')
    parser.add_argument('--quick-ap', metavar='SSID',
                        help='Quick AP setup with SSID')
    parser.add_argument('--quick-sta', metavar='SSID',
                        help='Quick STA setup with SSID')
    parser.add_argument('--password', '-p',
                        help='Password for quick setup')
    
    args = parser.parse_args()
    
    # Setup logging
    logger = setup_logging(args.debug, args.verbose)
    
    # List interfaces if requested
    if args.list:
        list_network_interfaces()
        return 0
    
    # Serial mode
    if args.serial:
        return serial_mode(args.serial, args.baudrate)
    
    # Check interface argument
    if not args.interface:
        parser.print_help()
        print("\nError: Please specify a network interface or use --list to see available interfaces")
        return -1
    
    # Initialize manager
    libnetat = NetatMgr(debug=args.debug, verbose=args.verbose)
    libnetat.mode = args.mode
    
    # Start packet capture if requested
    if args.capture:
        libnetat.start_packet_capture(args.capture)
    
    # Initialize network
    if libnetat_init(args.interface, args.any) != 0:
        logger.error(f"Failed to initialize with interface: {args.interface}")
        return -1
    
    # Quick setup modes
    if args.quick_ap:
        logger.info(f"Performing quick AP setup: {args.quick_ap}")
        if ATCommands.quick_setup_ap(args.quick_ap, args.password):
            logger.info("Quick AP setup successful")
        else:
            logger.error("Quick AP setup failed")
        return 0
    
    if args.quick_sta:
        logger.info(f"Performing quick STA setup: {args.quick_sta}")
        if ATCommands.quick_setup_sta(args.quick_sta, args.password):
            logger.info("Quick STA setup successful")
        else:
            logger.error("Quick STA setup failed")
        return 0
    
    # Raw packet mode
    if args.raw:
        raw_packet_mode()
        return 0
    
    print("\n" + "="*60)
    print("HaLow AT Command Interface Ready")
    print("="*60)
    print("Enter AT commands (e.g., 'AT+GMR' for version)")
    print("Type 'help' for command list, 'quit' to exit")
    print("="*60 + "\n")
    
    # Main command loop
    while True:
        try:
            input_cmd = input("> ").strip()
            
            if not input_cmd:
                continue
            
            if input_cmd.lower() in ['quit', 'exit', 'q']:
                logger.info("Exiting...")
                break
            
            if input_cmd.lower() == 'scan':
                netat_scan()
                netat_recv(args.timeout)
                continue
            
            if input_cmd.lower() == 'raw':
                raw_packet_mode()
                continue
            
            if input_cmd.lower() == 'help':
                print("\nAvailable commands:")
                print("  AT+<cmd>      - Send AT command")
                print("  scan          - Scan for HaLow devices")
                print("  raw           - Enter raw packet mode")
                print("  rssi          - Get signal strength")
                print("  status        - Get connection status")
                print("  pair          - Start pairing")
                print("  unpair        - Stop pairing")
                print("  help          - Show this help")
                print("  quit/exit     - Exit the program")
                print("\nCommon AT commands:")
                print("  AT+           - Test command")
                print("  AT+MODE?      - Query mode")
                print("  AT+MODE=ap/sta - Set mode")
                print("  AT+SSID?      - Query SSID")
                print("  AT+SSID=name  - Set SSID")
                print("  AT+KEYMGMT?   - Query encryption")
                print("  AT+PSK=hex    - Set password")
                print("  AT+BSS_BW=8   - Set bandwidth")
                print("  AT+RSSI       - Get signal")
                print("  AT+CONN_STATE - Connection status")
                print("  AT+WNBCFG     - View all config")
                print("  AT+LOADDEF=1  - Factory reset")
                continue
            
            # Shortcuts
            if input_cmd.lower() == 'rssi':
                rssi = ATCommands.get_rssi()
                if rssi is not None:
                    print(f"RSSI: {rssi} dBm")
                continue
            
            if input_cmd.lower() == 'status':
                state = ATCommands.get_connection_state()
                print(f"Connection: {state}")
                continue
            
            if input_cmd.lower() == 'pair':
                if ATCommands.start_pairing():
                    print("Pairing started")
                continue
            
            if input_cmd.lower() == 'unpair':
                if ATCommands.stop_pairing():
                    print("Pairing stopped")
                continue
            
            # Send AT command
            if input_cmd.upper().startswith("AT"):
                libnetat_send(input_cmd)
            else:
                print("Commands should start with 'AT' or use shortcuts. Type 'help' for more info.")
                
        except KeyboardInterrupt:
            logger.info("\nInterrupted by user")
            break
        except Exception as e:
            logger.error(f"Error in main loop: {e}")
            if args.debug:
                import traceback
                traceback.print_exc()
    
    # Cleanup
    if libnetat:
        libnetat.stop_packet_capture()
        if libnetat.sock:
            libnetat.sock.close()
    
    return 0


if __name__ == "__main__":
    sys.exit(main())