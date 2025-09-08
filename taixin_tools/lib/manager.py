"""
Main manager class that coordinates all HaLow operations
"""

import time
import random
from typing import Optional, Dict, Any, Tuple
from .network import SocketManager
from .protocol import WnbNetatCmd, parse_at_response, create_scan_packet, create_at_packet
from .logger import PacketLogger, log_hex_dump
from .constants import WnbCommand, DEFAULT_TIMEOUT, MACSTR, MAC2STR
from .at_commands import ATCommandSet, ATCommandHelper


class HaLowManager:
    """Main manager class for HaLow AT command operations"""
    
    def __init__(self, debug: bool = False, verbose: bool = False, logger=None):
        self.debug = debug
        self.verbose = verbose
        self.logger = logger
        self.socket_mgr = SocketManager()
        self.packet_logger = None
        self.mode = 'one-to-one'
        self.device_macs = {}  # Store discovered device MACs
        self.last_cookie = 0
        
    def initialize(self, interface: str, allow_any: bool = False) -> bool:
        """
        Initialize network connection
        
        Args:
            interface: Network interface name or IP
            allow_any: Allow fallback to any interface
            
        Returns:
            True if successful
        """
        # Create socket
        if not self.socket_mgr.create_socket():
            return False
            
        # Bind to interface
        if not self.socket_mgr.bind_to_interface(interface, allow_any):
            self.socket_mgr.close()
            return False
            
        if self.logger:
            self.logger.info(f"Initialized on {self.socket_mgr.bound_interface}")
            
        return True
    
    def start_packet_capture(self, filename: str):
        """Start capturing packets to file"""
        self.packet_logger = PacketLogger(filename)
        if self.logger:
            self.logger.info(f"Packet capture started: {filename}")
    
    def stop_packet_capture(self):
        """Stop packet capture and save"""
        if self.packet_logger:
            count = self.packet_logger.save()
            if count and self.logger:
                self.logger.info(f"Saved {count} packets to {self.packet_logger.filename}")
            self.packet_logger = None
    
    def scan_devices(self) -> bool:
        """
        Scan for HaLow devices
        
        Returns:
            True if scan packet sent successfully
        """
        packet = create_scan_packet()
        
        if self.verbose and self.logger:
            self.logger.debug("Sending scan packet")
            log_hex_dump(self.logger, packet, "TX: ")
            
        sent = self.socket_mgr.send(packet)
        
        if self.packet_logger:
            self.packet_logger.log_packet('SCAN_REQ', packet)
            
        return sent > 0
    
    def send_at_command(self, command: str, dest_mac: bytes = None) -> bool:
        """
        Send an AT command
        
        Args:
            command: AT command string
            dest_mac: Optional destination MAC
            
        Returns:
            True if sent successfully
        """
        # Generate cookie for correlation
        self.last_cookie = random.randint(1, 0xFFFF)
        
        # Create packet
        packet = create_at_packet(command, dest_mac)
        
        if self.verbose and self.logger:
            self.logger.debug(f"Sending AT command: {command}")
            log_hex_dump(self.logger, packet, "TX: ")
            
        # Send packet
        sent = self.socket_mgr.send(packet)
        
        if self.packet_logger:
            self.packet_logger.log_packet('AT_REQ', packet, 
                                         parsed={'command': command})
            
        if sent > 0:
            # Wait for and process response
            response = self.receive_response()
            if response:
                self._process_response(response)
                return True
                
        return False
    
    def receive_response(self, timeout: float = DEFAULT_TIMEOUT) -> Optional[Dict[str, Any]]:
        """
        Receive and parse response
        
        Args:
            timeout: Receive timeout
            
        Returns:
            Parsed response or None
        """
        data, addr = self.socket_mgr.receive(timeout)
        
        if not data:
            if self.logger:
                self.logger.debug("No response received (timeout)")
            return None
            
        if self.verbose and self.logger:
            self.logger.debug(f"Received {len(data)} bytes from {addr}")
            log_hex_dump(self.logger, data, "RX: ")
            
        # Parse packet
        packet = WnbNetatCmd.unpack(data)
        if not packet:
            if self.logger:
                self.logger.warning("Failed to parse packet")
            return None
            
        # Log packet
        if self.packet_logger:
            self.packet_logger.log_packet(
                packet.get_command_name(), 
                data, 
                addr,
                {'cmd': packet.cmd, 'data_len': len(packet.data)}
            )
            
        # Create response dict
        response = {
            'packet': packet,
            'addr': addr,
            'raw_data': data
        }
        
        # Parse AT response if applicable
        if packet.cmd == WnbCommand.AT_RESP:
            response['parsed'] = parse_at_response(packet.data)
            
        return response
    
    def _process_response(self, response: Dict[str, Any]):
        """Process and display response"""
        packet = response['packet']
        
        if self.logger:
            # Display packet info
            self.logger.info(f"Response: {packet}")
            
            # Display source MAC if not broadcast
            src_mac = packet.src_mac
            if src_mac != b'\x00' * 6:
                mac_str = MACSTR % MAC2STR(src_mac)
                self.logger.info(f"Device MAC: {mac_str}")
                
                # Store device MAC for one-to-many mode
                self.device_macs[mac_str] = src_mac
        
        # Handle different response types
        if packet.cmd == WnbCommand.SCAN_RESP:
            self._handle_scan_response(packet, response['addr'])
        elif packet.cmd == WnbCommand.AT_RESP:
            self._handle_at_response(packet, response.get('parsed'))
            
    def _handle_scan_response(self, packet: WnbNetatCmd, addr: Tuple):
        """Handle device scan response"""
        mac_str = MACSTR % MAC2STR(packet.src_mac)
        
        print(f"\nDiscovered device:")
        print(f"  MAC: {mac_str}")
        print(f"  IP: {addr[0]}:{addr[1]}")
        
        if packet.data:
            try:
                info = packet.data.decode('utf-8', errors='ignore')
                print(f"  Info: {info}")
            except:
                pass
                
    def _handle_at_response(self, packet: WnbNetatCmd, parsed: Optional[Dict]):
        """Handle AT command response"""
        if not parsed:
            print("Response: [Unable to parse]")
            return
            
        # Display response text
        if parsed.get('text'):
            print(f"< {parsed['text']}")
            
        # Display parsed values
        if parsed.get('values'):
            for key, value in parsed['values'].items():
                print(f"  {key}: {value}")
                
        # Display status
        if parsed.get('status') != 'UNKNOWN':
            if parsed['status'] == 'ERROR' and 'error_code' in parsed:
                print(f"Status: {parsed['status']} ({parsed['error_code']})")
            else:
                print(f"Status: {parsed['status']}")
    
    def execute_command_sequence(self, commands: list) -> bool:
        """
        Execute a sequence of AT commands
        
        Args:
            commands: List of AT command strings
            
        Returns:
            True if all commands succeeded
        """
        for cmd in commands:
            print(f"> {cmd}")
            if not self.send_at_command(cmd):
                return False
            time.sleep(0.5)  # Small delay between commands
            
        return True
    
    def quick_setup_ap(self, ssid: str, password: Optional[str] = None) -> bool:
        """Quick AP mode setup"""
        commands = ATCommandHelper.get_quick_ap_commands(ssid, password)
        return self.execute_command_sequence(commands)
    
    def quick_setup_sta(self, ssid: str, password: Optional[str] = None) -> bool:
        """Quick station mode setup"""
        commands = ATCommandHelper.get_quick_sta_commands(ssid, password)
        return self.execute_command_sequence(commands)
    
    def get_rssi(self) -> Optional[int]:
        """Get current RSSI value"""
        if self.send_at_command(ATCommandSet.RSSI):
            # Parse from last response
            # This would need access to the last response
            return None
        return None
    
    def get_connection_state(self) -> str:
        """Get connection state"""
        if self.send_at_command(ATCommandSet.CONN_STATE):
            # Parse from last response
            return "Unknown"
        return "Error"
    
    def cleanup(self):
        """Clean up resources"""
        self.stop_packet_capture()
        self.socket_mgr.close()