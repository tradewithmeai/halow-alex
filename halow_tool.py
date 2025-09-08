#!/usr/bin/env python3
"""
HaLow AT Command Tool - Refactored Main Entry Point
====================================================

This tool enables communication with WiFi HaLow (802.11ah) modules using AT commands
over UDP broadcast protocol or serial connection.

Author: HaLow Tool Contributors
License: See LICENSE file
Version: 4.1 (Refactored)
"""

import argparse
import sys
import os

# Add the package to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from taixin_tools.lib.logger import setup_logging
from taixin_tools.lib.network import NetworkInterface
from taixin_tools.lib.serial_comm import run_serial_mode, print_serial_ports
from taixin_tools.lib.manager import HaLowManager
from taixin_tools.lib.interactive import ATCommandMode, RawPacketMode


def create_argument_parser():
    """Create and configure argument parser"""
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
    
    # Positional argument
    parser.add_argument('interface', nargs='?', 
                        help='Network interface name or IP address')
    
    # Debug options
    parser.add_argument('--debug', '-d', action='store_true',
                        help='Enable debug output')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Enable verbose packet logging')
    
    # Network options
    parser.add_argument('--any', '-a', action='store_true',
                        help='Allow binding to any interface if specific binding fails')
    parser.add_argument('--list', '-l', action='store_true',
                        help='List available network interfaces and exit')
    parser.add_argument('--timeout', '-t', type=float, default=2.0,
                        help='Response timeout in seconds (default: 2.0)')
    
    # Serial options
    parser.add_argument('--serial', '-s', metavar='PORT',
                        help='Use serial port instead of network')
    parser.add_argument('--serial-list', action='store_true',
                        help='List available serial ports and exit')
    parser.add_argument('--baudrate', '-b', type=int, default=115200,
                        help='Serial baudrate (default: 115200)')
    
    # Operation modes
    parser.add_argument('--raw', '-r', action='store_true',
                        help='Enter raw packet mode')
    parser.add_argument('--mode', '-m', choices=['one-to-one', 'one-to-many'],
                        default='one-to-one',
                        help='Communication mode (default: one-to-one)')
    
    # Packet capture
    parser.add_argument('--capture', '-c', metavar='FILE',
                        help='Capture packets to file')
    
    # Quick setup
    parser.add_argument('--quick-ap', metavar='SSID',
                        help='Quick AP setup with SSID')
    parser.add_argument('--quick-sta', metavar='SSID',
                        help='Quick STA setup with SSID')
    parser.add_argument('--password', '-p',
                        help='Password for quick setup')
    
    return parser


def handle_interface_list():
    """Handle --list option"""
    NetworkInterface.print_interfaces()
    return 0


def handle_serial_list():
    """Handle --serial-list option"""
    print_serial_ports()
    return 0


def handle_serial_mode(port: str, baudrate: int):
    """Handle serial communication mode"""
    return run_serial_mode(port, baudrate)


def handle_network_mode(args, logger):
    """Handle network communication mode"""
    # Check interface argument
    if not args.interface:
        print("Error: Please specify a network interface or use --list to see available interfaces")
        return -1
    
    # Initialize manager
    manager = HaLowManager(debug=args.debug, verbose=args.verbose, logger=logger)
    manager.mode = args.mode
    
    # Start packet capture if requested
    if args.capture:
        manager.start_packet_capture(args.capture)
        logger.info(f"Packet capture enabled: {args.capture}")
    
    # Initialize network
    if not manager.initialize(args.interface, args.any):
        logger.error(f"Failed to initialize with interface: {args.interface}")
        return -1
    
    try:
        # Quick setup modes
        if args.quick_ap:
            logger.info(f"Performing quick AP setup: {args.quick_ap}")
            success = manager.quick_setup_ap(args.quick_ap, args.password)
            logger.info("Quick AP setup successful" if success else "Quick AP setup failed")
            return 0 if success else -1
        
        if args.quick_sta:
            logger.info(f"Performing quick STA setup: {args.quick_sta}")
            success = manager.quick_setup_sta(args.quick_sta, args.password)
            logger.info("Quick STA setup successful" if success else "Quick STA setup failed")
            return 0 if success else -1
        
        # Raw packet mode
        if args.raw:
            raw_mode = RawPacketMode(manager)
            raw_mode.run()
            return 0
        
        # Interactive AT command mode
        interactive_mode = ATCommandMode(manager)
        interactive_mode.run()
        return 0
        
    finally:
        manager.cleanup()


def main():
    """Main entry point"""
    parser = create_argument_parser()
    args = parser.parse_args()
    
    # Handle list operations first
    if args.list:
        return handle_interface_list()
        
    if args.serial_list:
        return handle_serial_list()
    
    # Setup logging
    logger = setup_logging(args.debug, args.verbose)
    
    # Serial mode
    if args.serial:
        return handle_serial_mode(args.serial, args.baudrate)
    
    # Network mode
    return handle_network_mode(args, logger)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)