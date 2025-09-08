"""
Serial communication module for HaLow AT Command Tool
"""

import sys
import time
import threading
import queue
from typing import Optional
from .constants import AT_TERMINATOR

# Import serial library with proper error handling
try:
    import serial
    import serial.tools.list_ports
    SERIAL_AVAILABLE = True
except ImportError:
    SERIAL_AVAILABLE = False
    print("Warning: PySerial not installed. Serial port support disabled.")
    print("Install with: pip install pyserial")


class SerialHandler:
    """Handles serial port communication for AT commands"""
    
    def __init__(self, port: str, baudrate: int = 115200):
        if not SERIAL_AVAILABLE:
            raise ImportError("PySerial library not available")
            
        self.port = port
        self.baudrate = baudrate
        self.serial = None
        self.read_thread = None
        self.write_queue = queue.Queue()
        self.running = False
        
    def connect(self) -> bool:
        """Connect to the serial port"""
        try:
            self.serial = serial.Serial(
                port=self.port,
                baudrate=self.baudrate,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
                timeout=0.1,
                write_timeout=1.0
            )
            
            # Clear buffers
            self.serial.reset_input_buffer()
            self.serial.reset_output_buffer()
            
            # Start read thread
            self.running = True
            self.read_thread = threading.Thread(target=self._read_loop, daemon=True)
            self.read_thread.start()
            
            return True
            
        except Exception as e:
            print(f"Error opening serial port {self.port}: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from serial port"""
        self.running = False
        if self.read_thread:
            self.read_thread.join(timeout=1)
        if self.serial and self.serial.is_open:
            self.serial.close()
    
    def send_command(self, command: str) -> bool:
        """Send an AT command via serial"""
        if not self.serial or not self.serial.is_open:
            return False
            
        try:
            # Ensure proper termination
            if not command.endswith(AT_TERMINATOR):
                command += AT_TERMINATOR
                
            self.serial.write(command.encode())
            self.serial.flush()
            return True
            
        except Exception as e:
            print(f"Error sending command: {e}")
            return False
    
    def _read_loop(self):
        """Background thread for reading serial data"""
        buffer = b''
        
        while self.running and self.serial and self.serial.is_open:
            try:
                # Read available data
                if self.serial.in_waiting:
                    data = self.serial.read(self.serial.in_waiting)
                    buffer += data
                    
                    # Check for complete lines
                    while b'\n' in buffer:
                        line, buffer = buffer.split(b'\n', 1)
                        line = line.strip()
                        if line:
                            # Display the response
                            try:
                                text = line.decode('utf-8', errors='ignore')
                                print(f"< {text}")
                            except:
                                print(f"< [Raw bytes: {line.hex()}]")
                else:
                    time.sleep(0.01)
                    
            except Exception as e:
                if self.running:
                    print(f"Serial read error: {e}")
                break


def list_serial_ports():
    """List available serial ports"""
    if not SERIAL_AVAILABLE:
        print("PySerial not installed. Cannot list serial ports.")
        return []
        
    ports = []
    for port in serial.tools.list_ports.comports():
        ports.append({
            'device': port.device,
            'description': port.description,
            'hwid': port.hwid
        })
        
    return ports


def print_serial_ports():
    """Print available serial ports to console"""
    ports = list_serial_ports()
    
    if not ports:
        print("No serial ports found")
        return
        
    print("\nAvailable serial ports:")
    print("-" * 50)
    
    for i, port in enumerate(ports, 1):
        print(f"{i}. {port['device']}")
        print(f"   Description: {port['description']}")
        print(f"   Hardware ID: {port['hwid']}")
        print()


def run_serial_mode(port: str, baudrate: int = 115200):
    """
    Run interactive serial mode
    
    Args:
        port: Serial port path
        baudrate: Baud rate
    """
    if not SERIAL_AVAILABLE:
        print("PySerial library not installed. Please install with: pip install pyserial")
        return -1
        
    print(f"\nConnecting to {port} at {baudrate} baud...")
    
    handler = SerialHandler(port, baudrate)
    if not handler.connect():
        return -1
        
    print("Serial connection established!")
    print("=" * 60)
    print("Serial AT Command Interface")
    print("=" * 60)
    print("Enter AT commands (e.g., 'AT+GMR' for version)")
    print("Type 'quit' to exit")
    print("=" * 60)
    print()
    
    try:
        while True:
            try:
                cmd = input("> ").strip()
                
                if not cmd:
                    continue
                    
                if cmd.lower() in ['quit', 'exit', 'q']:
                    break
                    
                # Send the command
                if cmd.upper().startswith('AT'):
                    handler.send_command(cmd)
                    # Give device time to respond
                    time.sleep(0.5)
                else:
                    print("Commands should start with 'AT'")
                    
            except KeyboardInterrupt:
                print("\nInterrupted")
                break
                
    finally:
        handler.disconnect()
        print("Serial connection closed")
        
    return 0