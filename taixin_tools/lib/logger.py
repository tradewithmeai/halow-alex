"""
Logging utilities for HaLow AT Command Tool
"""

import logging
import json
from datetime import datetime
from typing import Any, Dict, Optional


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


def setup_logging(debug: bool = False, verbose: bool = False) -> logging.Logger:
    """
    Configure logging based on debug and verbose flags.
    
    Args:
        debug: If True, sets logging level to DEBUG
        verbose: If True, enables packet-level logging
        
    Returns:
        Configured logger instance
    """
    level = logging.DEBUG if debug else logging.INFO
    
    # Create logger
    logger = logging.getLogger('halow')
    logger.setLevel(level)
    
    # Remove existing handlers
    logger.handlers = []
    
    # Create console handler
    handler = logging.StreamHandler()
    handler.setLevel(level)
    
    # Set formatter
    if debug or verbose:
        formatter = ColoredFormatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%H:%M:%S'
        )
    else:
        formatter = ColoredFormatter('%(levelname)s: %(message)s')
    
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    
    # Disable propagation to root logger
    logger.propagate = False
    
    return logger


class PacketLogger:
    """Handles packet capture and logging to files"""
    
    def __init__(self, filename: Optional[str] = None):
        self.filename = filename
        self.packets = []
        self.enabled = filename is not None
        
    def log_packet(self, packet_type: str, data: bytes, 
                   src_addr: Optional[tuple] = None,
                   parsed: Optional[Dict[str, Any]] = None):
        """Log a packet for analysis"""
        if not self.enabled:
            return
            
        packet_info = {
            'timestamp': datetime.now().isoformat(),
            'type': packet_type,
            'data_hex': data.hex(),
            'data_len': len(data),
        }
        
        if src_addr:
            packet_info['src_addr'] = f"{src_addr[0]}:{src_addr[1]}"
        
        if parsed:
            packet_info['parsed'] = parsed
            
        self.packets.append(packet_info)
        
    def save(self):
        """Save captured packets to file"""
        if self.enabled and self.packets:
            with open(self.filename, 'w') as f:
                json.dump(self.packets, f, indent=2)
            return len(self.packets)
        return 0


def log_hex_dump(logger: logging.Logger, data: bytes, prefix: str = ""):
    """
    Log a hex dump of binary data
    
    Args:
        logger: Logger instance to use
        data: Binary data to dump
        prefix: Optional prefix for each line
    """
    if not logger.isEnabledFor(logging.DEBUG):
        return
        
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_str = ' '.join(f'{b:02x}' for b in chunk)
        ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        logger.debug(f"{prefix}{i:04x}: {hex_str:<48} {ascii_str}")