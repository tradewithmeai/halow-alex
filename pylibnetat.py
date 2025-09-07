#!/usr/bin/env python3
"""
AT Command Configuration Tool for Taixin TX-AH-R WiFi HaLow Modules
====================================================================
This tool enables communication with WiFi HaLow modules using AT commands
over UDP broadcast protocol. It provides a command-line interface for
sending AT commands and receiving responses from the modules.

Author: pylibnetat contributors
License: See LICENSE file
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
from typing import Optional, Tuple, Union

# ============================================================================
# CONSTANTS AND CONFIGURATION
# ============================================================================

# Network configuration
NETAT_BUFF_SIZE = 1024  # Buffer size for receiving data
NETAT_PORT = 56789      # UDP port for AT command communication

# Protocol command identifiers
WNB_NETAT_CMD_SCAN_REQ = 1   # Request to scan for devices
WNB_NETAT_CMD_SCAN_RESP = 2  # Response from device scan
WNB_NETAT_CMD_AT_REQ = 3     # AT command request
WNB_NETAT_CMD_AT_RESP = 4    # AT command response

# MAC address formatting helpers
MAC2STR = lambda a: (a[0] & 0xff, a[1] & 0xff, a[2] & 0xff, 
                     a[3] & 0xff, a[4] & 0xff, a[5] & 0xff)
MACSTR = "%02x:%02x:%02x:%02x:%02x:%02x"

# Platform-specific socket options
SO_BINDTODEVICE = 25  # Linux socket option for binding to specific interface

# ============================================================================
# LOGGING CONFIGURATION
# ============================================================================

def setup_logging(debug: bool = False):
    """
    Configure logging based on debug flag.
    
    Args:
        debug: If True, sets logging level to DEBUG, otherwise INFO
    """
    level = logging.DEBUG if debug else logging.INFO
    format_str = '%(asctime)s - %(levelname)s - %(funcName)s - %(message)s'
    logging.basicConfig(level=level, format=format_str)
    return logging.getLogger(__name__)

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
    """
    
    def __init__(self):
        self.cmd = 0
        self.len = b'\x00\x00'
        self.dest = b'\x00\x00\x00\x00\x00\x00'
        self.src = b'\x00\x00\x00\x00\x00\x00'
        self.data = b''
    
    def __bytes__(self):
        """Convert command to bytes for transmission."""
        return bytes([self.cmd]) + self.len + self.dest + self.src + self.data
    
    def __str__(self):
        """String representation for debugging."""
        return (f"WnbNetatCmd(cmd={self.cmd}, len={struct.unpack('>H', self.len)[0]}, "
                f"dest={self.dest.hex()}, src={self.src.hex()}, "
                f"data={self.data[:20]}{'...' if len(self.data) > 20 else ''})")


class NetatMgr:
    """
    Manager class for handling network AT command communication.
    
    Attributes:
        sock: UDP socket for communication
        dest: Destination MAC address (default: broadcast)
        cookie: Random identifier for matching requests/responses
        recvbuf: Buffer for receiving data
        interface: Network interface name
        debug: Debug mode flag
    """
    
    def __init__(self, debug: bool = False):
        self.sock = None
        self.dest = b'\xff\xff\xff\xff\xff\xff'  # Broadcast MAC
        self.cookie = b'\x00\x00\x00\x00\x00\x00'
        self.recvbuf = bytearray(NETAT_BUFF_SIZE)
        self.interface = None
        self.debug = debug
        self.bind_method = None  # Track which binding method worked

# Global instance
libnetat = None

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def random_bytes(length: int) -> bytes:
    """
    Generate random bytes for use as cookies/identifiers.
    
    Args:
        length: Number of random bytes to generate
    
    Returns:
        Bytes object with random values
    """
    return bytes([random.randint(0, 255) for _ in range(length)])


def get_platform_info() -> dict:
    """
    Get detailed platform information for debugging.
    
    Returns:
        Dictionary containing platform details
    """
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

def sock_send(sock: socket.socket, data: bytes) -> int:
    """
    Send data via UDP broadcast.
    
    Args:
        sock: UDP socket to send through
        data: Bytes to send
    
    Returns:
        Number of bytes sent
    """
    dest = ('<broadcast>', NETAT_PORT)
    logger.debug(f"Sending {len(data)} bytes to {dest}")
    logger.debug(f"Data hex: {data.hex()}")
    
    try:
        sent = sock.sendto(data, dest)
        logger.debug(f"Successfully sent {sent} bytes")
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
    logger.debug(f"Waiting for data with timeout={timeout}s")
    
    try:
        rlist, _, _ = select.select([sock], [], [], timeout)
        if sock in rlist:
            data, addr = sock.recvfrom(NETAT_BUFF_SIZE)
            logger.debug(f"Received {len(data)} bytes from {addr}")
            logger.debug(f"Data hex: {data.hex()[:100]}...")
            return data, addr
    except Exception as e:
        logger.error(f"Error receiving data: {e}")
    
    logger.debug("Receive timeout - no data")
    return None, None

# ============================================================================
# PROTOCOL OPERATIONS
# ============================================================================

def netat_scan():
    """
    Send a broadcast scan request to discover HaLow devices.
    
    This function broadcasts a scan request packet with a random cookie
    identifier. Devices should respond with their MAC address.
    """
    global libnetat
    logger.info("Scanning for HaLow devices...")
    
    scan = WnbNetatCmd()
    libnetat.cookie = random_bytes(6)
    scan.cmd = WNB_NETAT_CMD_SCAN_REQ
    scan.dest = b'\xff\xff\xff\xff\xff\xff'  # Broadcast to all
    scan.src = libnetat.cookie
    
    logger.debug(f"Scan packet: {scan}")
    sock_send(libnetat.sock, bytes(scan))


def netat_send(atcmd: str):
    """
    Send an AT command to the target device.
    
    Args:
        atcmd: AT command string to send
    """
    global libnetat
    logger.info(f"Sending AT command: {atcmd}")
    
    cmd = WnbNetatCmd()
    libnetat.cookie = random_bytes(6)
    cmd.cmd = WNB_NETAT_CMD_AT_REQ
    cmd.len = struct.pack('>H', len(atcmd))
    cmd.dest = libnetat.dest
    cmd.src = libnetat.cookie
    cmd.data = atcmd.encode('utf-8')
    
    logger.debug(f"AT command packet: {cmd}")
    sock_send(libnetat.sock, bytes(cmd))


def netat_recv(buff: Optional[bytearray], timeout: float) -> int:
    """
    Receive and process responses from HaLow devices.
    
    Args:
        buff: Buffer to store received data (None to print directly)
        timeout: Timeout in seconds to wait for response
    
    Returns:
        Number of bytes received
    """
    global libnetat
    off = 0
    cmd = WnbNetatCmd()
    
    logger.debug(f"Waiting for response (timeout={timeout}s)")
    
    while True:
        data, addr = sock_recv(libnetat.sock, timeout)
        if data:
            cmd_len = len(data)
            logger.debug(f"Processing {cmd_len} bytes from {addr}")
            
            if cmd_len >= 15:  # Minimum packet size (header without data)
                cmd_bytes = bytearray(data)
                cmd.cmd = cmd_bytes[0]
                cmd.len = cmd_bytes[1:3]
                cmd.dest = bytes(cmd_bytes[3:9])
                cmd.src = bytes(cmd_bytes[9:15])
                cmd.data = bytes(cmd_bytes[15:]) if cmd_len > 15 else b''
                
                logger.debug(f"Parsed packet: {cmd}")
                logger.debug(f"Checking cookie match: {cmd.dest.hex()} == {libnetat.cookie.hex()}")
                
                if cmd.dest == libnetat.cookie:
                    logger.info(f"Received matching response (cmd={cmd.cmd})")
                    
                    if cmd.cmd == WNB_NETAT_CMD_SCAN_RESP:
                        libnetat.dest = cmd.src
                        logger.info(f"Device found at MAC: {cmd.src.hex()}")
                        
                    elif cmd.cmd == WNB_NETAT_CMD_AT_RESP:
                        logger.debug(f"AT response data: {cmd.data}")
                        if buff is not None:
                            # Store in buffer
                            data_len = len(cmd.data)
                            if off + data_len <= len(buff):
                                buff[off:off + data_len] = cmd.data
                                off += data_len
                            else:
                                logger.warning("Buffer overflow, truncating response")
                                remaining = len(buff) - off
                                buff[off:] = cmd.data[:remaining]
                                off = len(buff)
                        else:
                            # Print directly
                            try:
                                response = cmd.data.decode('utf-8', errors='replace')
                                print(response)
                            except Exception as e:
                                logger.error(f"Error decoding response: {e}")
                                print(f"Raw response: {cmd.data.hex()}")
                else:
                    logger.debug(f"Cookie mismatch, ignoring packet")
            else:
                logger.warning(f"Packet too small ({cmd_len} bytes), ignoring")
                break
        else:
            logger.debug("No more data to receive")
            break
    
    if buff and off > 0:
        # Null-terminate the buffer
        if off < len(buff):
            buff[off] = 0
        logger.info(f"Total received: {off} bytes")
    
    return off

# ============================================================================
# INITIALIZATION FUNCTIONS
# ============================================================================

def bind_socket_linux(sock: socket.socket, ifname: str) -> bool:
    """
    Bind socket to interface on Linux systems.
    
    Args:
        sock: Socket to bind
        ifname: Interface name
    
    Returns:
        True if successful, False otherwise
    """
    try:
        # Method 1: SO_BINDTODEVICE (requires root on Linux)
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
    """
    Generic socket binding method that works across platforms.
    
    Args:
        sock: Socket to bind
        ifname: Interface name or IP address
    
    Returns:
        True if successful, False otherwise
    """
    # Method 2: Try binding to specific IP if provided
    if '.' in ifname:  # Looks like an IP address
        try:
            logger.debug(f"Binding to IP address: {ifname}")
            sock.bind((ifname, NETAT_PORT))
            logger.info(f"Successfully bound to {ifname}:{NETAT_PORT}")
            return True
        except Exception as e:
            logger.error(f"Failed to bind to {ifname}: {e}")
            return False
    
    # Method 3: Get IP from interface name
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
    """
    Initialize the AT command manager with network configuration.
    
    Args:
        ifname: Network interface name or IP address
        allow_any: If True, bind to any interface if specific binding fails
    
    Returns:
        0 on success, -1 on failure
    """
    global libnetat
    
    logger.info("="*60)
    logger.info("Initializing HaLow AT command interface")
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
        
        # Set socket to non-blocking for better control
        libnetat.sock.setblocking(False)
        
        # Platform-specific binding
        bound = False
        system = platform.system()
        
        if system == 'Linux':
            # Try Linux-specific binding first
            bound = bind_socket_linux(libnetat.sock, ifname)
            if bound:
                libnetat.bind_method = "SO_BINDTODEVICE"
        
        if not bound:
            # Try generic binding
            bound = bind_socket_generic(libnetat.sock, ifname)
            if bound:
                libnetat.bind_method = "IP_BINDING"
        
        if not bound and allow_any:
            # Fall back to binding to any interface
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
        
        logger.info(f"Socket initialized successfully (method: {libnetat.bind_method})")
        
        # Initial device scan
        logger.info("Performing initial device scan...")
        netat_scan()
        netat_recv(None, 1)
        
        if libnetat.dest[0] & 0x1:  # Still broadcast address
            logger.warning("No devices found in initial scan")
            logger.info("Device will be scanned when sending first command")
        else:
            logger.info(f"Device detected: {libnetat.dest.hex()}")
        
        return 0
        
    except Exception as e:
        logger.error(f"Initialization failed: {e}")
        if libnetat.sock:
            libnetat.sock.close()
        return -1


def libnetat_send(atcmd: str) -> int:
    """
    Send an AT command and receive response.
    
    Args:
        atcmd: AT command string to send
    
    Returns:
        0 on success, -1 on failure
    """
    global libnetat
    
    if libnetat.sock is None:
        logger.error("libnetat is not initialized!")
        return -1
    
    # Check if we need to scan for device
    if libnetat.dest[0] & 0x1:  # Broadcast/multicast address
        logger.info("Scanning for device...")
        netat_scan()
        netat_recv(None, 1)
    
    if libnetat.dest[0] & 0x1:  # Still no device
        logger.error("No HaLow device detected!")
        logger.info("\nTroubleshooting:")
        logger.info("1. Check if the HaLow module is powered on")
        logger.info("2. Verify network connectivity")
        logger.info("3. Ensure you're on the same network segment")
        logger.info("4. Check firewall settings for UDP port 56789")
        return -1
    
    # Send AT command
    netat_send(atcmd)
    
    # Receive response
    response_buff = bytearray(1024)
    bytes_received = netat_recv(response_buff, 2)
    
    if bytes_received > 0:
        try:
            response = response_buff[:bytes_received].decode('utf-8', errors='replace')
            print(f"\nResponse:\n{response}")
        except Exception as e:
            logger.error(f"Error decoding response: {e}")
            print(f"Raw response: {response_buff[:bytes_received].hex()}")
    else:
        logger.warning("No response received")
    
    return 0

# ============================================================================
# MAIN PROGRAM
# ============================================================================

def main():
    """Main entry point for the AT command tool."""
    global libnetat
    
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
        """
    )
    
    parser.add_argument('interface', nargs='?', 
                        help='Network interface name or IP address')
    parser.add_argument('--debug', '-d', action='store_true',
                        help='Enable debug output')
    parser.add_argument('--any', '-a', action='store_true',
                        help='Allow binding to any interface if specific binding fails')
    parser.add_argument('--list', '-l', action='store_true',
                        help='List available network interfaces and exit')
    parser.add_argument('--timeout', '-t', type=float, default=2.0,
                        help='Response timeout in seconds (default: 2.0)')
    
    args = parser.parse_args()
    
    # Setup logging
    global logger
    logger = setup_logging(args.debug)
    
    # List interfaces if requested
    if args.list:
        list_network_interfaces()
        return 0
    
    # Check interface argument
    if not args.interface:
        parser.print_help()
        print("\nError: Please specify a network interface or use --list to see available interfaces")
        return -1
    
    # Initialize manager
    libnetat = NetatMgr(debug=args.debug)
    
    # Initialize network
    if libnetat_init(args.interface, args.any) != 0:
        logger.error(f"Failed to initialize with interface: {args.interface}")
        return -1
    
    print("\n" + "="*60)
    print("HaLow AT Command Interface Ready")
    print("="*60)
    print("Enter AT commands (e.g., 'AT+GMR' for version)")
    print("Type 'quit' or 'exit' to terminate")
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
                logger.info("Scanning for devices...")
                netat_scan()
                netat_recv(None, args.timeout)
                continue
            
            if input_cmd.lower() == 'help':
                print("\nAvailable commands:")
                print("  AT+<cmd>  - Send AT command")
                print("  scan      - Scan for HaLow devices")
                print("  help      - Show this help")
                print("  quit/exit - Exit the program")
                print("\nCommon AT commands:")
                print("  AT+GMR    - Get module version")
                print("  AT+RST    - Reset module")
                print("  AT+CWMODE - Get/Set WiFi mode")
                print("  AT+CWLAP  - List access points")
                continue
            
            # Send AT command
            if input_cmd.upper().startswith("AT"):
                libnetat_send(input_cmd)
            else:
                print("Commands should start with 'AT'. Type 'help' for more info.")
                
        except KeyboardInterrupt:
            logger.info("\nInterrupted by user")
            break
        except Exception as e:
            logger.error(f"Error in main loop: {e}")
            if args.debug:
                import traceback
                traceback.print_exc()
    
    # Cleanup
    if libnetat and libnetat.sock:
        libnetat.sock.close()
    
    return 0


if __name__ == "__main__":
    sys.exit(main())