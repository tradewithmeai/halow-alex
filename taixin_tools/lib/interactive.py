"""
Interactive modes for HaLow AT Command Tool
"""

import sys
import binascii
from typing import Optional
from .utils import hex_to_bytes, format_packet_display
from .protocol import WnbNetatCmd
from .at_commands import ATCommandInfo


class InteractiveMode:
    """Base class for interactive modes"""
    
    def __init__(self, manager):
        self.manager = manager
        self.running = True
        
    def run(self):
        """Run the interactive mode"""
        raise NotImplementedError
        
    def stop(self):
        """Stop the interactive mode"""
        self.running = False


class RawPacketMode(InteractiveMode):
    """Raw packet mode for protocol testing"""
    
    def run(self):
        """Run raw packet mode"""
        print("\n" + "=" * 60)
        print("RAW PACKET MODE")
        print("=" * 60)
        print("Enter hex bytes to send (e.g., '01 00 02 ff ff ...')")
        print("Commands:")
        print("  scan    - Send scan packet")
        print("  at <cmd> - Send AT command packet")
        print("  recv    - Receive packet")
        print("  help    - Show this help")
        print("  quit    - Exit raw mode")
        print("=" * 60)
        print()
        
        while self.running:
            try:
                user_input = input("raw> ").strip()
                
                if not user_input:
                    continue
                    
                cmd = user_input.lower()
                
                if cmd in ['quit', 'exit', 'q']:
                    break
                    
                elif cmd == 'help':
                    self.show_help()
                    
                elif cmd == 'scan':
                    self.send_scan()
                    
                elif cmd.startswith('at '):
                    at_cmd = user_input[3:].strip()
                    self.send_at(at_cmd)
                    
                elif cmd == 'recv':
                    self.receive_packet()
                    
                else:
                    # Try to parse as hex
                    self.send_hex(user_input)
                    
            except KeyboardInterrupt:
                print("\nExiting raw mode")
                break
            except Exception as e:
                print(f"Error: {e}")
    
    def show_help(self):
        """Show raw mode help"""
        print("\nRaw Packet Mode Commands:")
        print("  Hex input   - Send raw hex bytes (e.g., '03 00 05 ...')")
        print("  scan        - Send device scan packet")
        print("  at <cmd>    - Send AT command packet")
        print("  recv        - Wait for and display received packet")
        print("  help        - Show this help")
        print("  quit        - Exit raw mode")
        print()
        print("Packet Structure (15-byte header + data):")
        print("  Byte 0:     Command (1=scan_req, 3=at_req, etc.)")
        print("  Bytes 1-2:  Data length (little-endian)")
        print("  Bytes 3-8:  Destination MAC")
        print("  Bytes 9-14: Source MAC")
        print("  Bytes 15+:  Data payload")
        print()
    
    def send_scan(self):
        """Send scan packet"""
        packet = WnbNetatCmd(cmd=1)  # SCAN_REQ
        data = packet.pack()
        
        print(f"Sending scan packet ({len(data)} bytes):")
        print(format_packet_display(data))
        
        sent = self.manager.socket_mgr.send(data)
        print(f"Sent {sent} bytes")
        
        # Auto receive response
        self.receive_packet(timeout=3.0)
    
    def send_at(self, at_cmd: str):
        """Send AT command packet"""
        if not at_cmd.upper().startswith('AT'):
            at_cmd = 'AT+' + at_cmd
            
        packet = WnbNetatCmd(cmd=3, data=at_cmd.encode())  # AT_REQ
        data = packet.pack()
        
        print(f"Sending AT command: {at_cmd}")
        print(f"Packet ({len(data)} bytes):")
        print(format_packet_display(data))
        
        sent = self.manager.socket_mgr.send(data)
        print(f"Sent {sent} bytes")
        
        # Auto receive response
        self.receive_packet()
    
    def send_hex(self, hex_input: str):
        """Send raw hex bytes"""
        data = hex_to_bytes(hex_input)
        if not data:
            print("Invalid hex input")
            return
            
        print(f"Sending {len(data)} bytes:")
        print(format_packet_display(data))
        
        sent = self.manager.socket_mgr.send(data)
        print(f"Sent {sent} bytes")
        
        # Try to parse as packet
        packet = WnbNetatCmd.unpack(data)
        if packet:
            print(f"Parsed as: {packet}")
    
    def receive_packet(self, timeout: float = 2.0):
        """Receive and display packet"""
        print(f"Waiting for packet (timeout={timeout}s)...")
        
        data, addr = self.manager.socket_mgr.receive(timeout)
        
        if not data:
            print("No packet received (timeout)")
            return
            
        print(f"\nReceived {len(data)} bytes from {addr}:")
        print(format_packet_display(data))
        
        # Try to parse
        packet = WnbNetatCmd.unpack(data)
        if packet:
            print(f"Parsed as: {packet}")
            
            if packet.data:
                try:
                    text = packet.data.decode('utf-8', errors='ignore')
                    print(f"Data (text): {text}")
                except:
                    pass


class ATCommandMode(InteractiveMode):
    """Main AT command interactive mode"""
    
    def run(self):
        """Run AT command mode"""
        self.show_banner()
        
        while self.running:
            try:
                user_input = input("> ").strip()
                
                if not user_input:
                    continue
                    
                self.process_command(user_input)
                
            except KeyboardInterrupt:
                print("\nInterrupted by user")
                break
            except Exception as e:
                print(f"Error: {e}")
                if self.manager.debug:
                    import traceback
                    traceback.print_exc()
    
    def show_banner(self):
        """Show welcome banner"""
        print("\n" + "=" * 60)
        print("HaLow AT Command Interface Ready")
        print("=" * 60)
        print("Enter AT commands (e.g., 'AT+GMR' for version)")
        print("Type 'help' for command list, 'quit' to exit")
        print("=" * 60 + "\n")
    
    def process_command(self, cmd: str):
        """Process user command"""
        cmd_lower = cmd.lower()
        
        # Exit commands
        if cmd_lower in ['quit', 'exit', 'q']:
            print("Exiting...")
            self.stop()
            return
            
        # Help command
        if cmd_lower == 'help':
            ATCommandInfo.print_help()
            return
            
        # Scan command
        if cmd_lower == 'scan':
            self.manager.scan_devices()
            self.manager.receive_response(timeout=3.0)
            return
            
        # Raw mode
        if cmd_lower == 'raw':
            raw_mode = RawPacketMode(self.manager)
            raw_mode.run()
            return
            
        # RSSI shortcut
        if cmd_lower == 'rssi':
            rssi = self.manager.get_rssi()
            if rssi is not None:
                print(f"RSSI: {rssi} dBm")
            return
            
        # Status shortcut
        if cmd_lower == 'status':
            state = self.manager.get_connection_state()
            print(f"Connection: {state}")
            return
            
        # Pairing shortcuts
        if cmd_lower == 'pair':
            if self.manager.send_at_command("AT+PAIR=1"):
                print("Pairing started")
            return
            
        if cmd_lower == 'unpair':
            if self.manager.send_at_command("AT+PAIR=0"):
                print("Pairing stopped")
            return
            
        # AT commands
        if cmd.upper().startswith("AT"):
            self.manager.send_at_command(cmd)
        else:
            print("Commands should start with 'AT' or use shortcuts.")
            print("Type 'help' for more info.")