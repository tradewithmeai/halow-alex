"""
Protocol constants and definitions for HaLow AT Command Tool
"""

from enum import IntEnum

# Network configuration
NETAT_BUFF_SIZE = 2048  # Buffer size for UDP packets
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

# Platform-specific socket options
SO_BINDTODEVICE = 25  # Linux socket option for binding to specific interface

# AT Command termination characters
AT_TERMINATOR = "\r\n"  # CR+LF as per documentation

# MAC address formatting
MAC2STR = lambda a: (a[0] & 0xff, a[1] & 0xff, a[2] & 0xff, 
                     a[3] & 0xff, a[4] & 0xff, a[5] & 0xff)
MACSTR = "%02x:%02x:%02x:%02x:%02x:%02x"

# Default timeouts
DEFAULT_TIMEOUT = 2.0  # Default response timeout in seconds
SCAN_TIMEOUT = 3.0     # Timeout for device scanning

# Packet structure sizes
HEADER_SIZE = 15       # Command(1) + Length(2) + Dest MAC(6) + Src MAC(6)
MAX_DATA_SIZE = 1400   # Maximum data payload size