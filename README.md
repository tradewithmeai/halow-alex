# HaLow AT Command Configuration Tool v4.0

Advanced AT command configuration app for Taixin TX-AH-R WiFi HaLow Modules/devices with comprehensive debugging, packet analysis, and reverse engineering capabilities.

## 🚀 New Features in v4.0

- **📡 Packet Analysis Mode** - Detailed hex dumps and protocol inspection
- **🔧 Raw Packet Mode** - Direct packet crafting and testing
- **📊 Packet Capture** - Save all communications for analysis
- **🎯 Serial Port Support** - Direct UART communication fallback
- **⚡ Quick Setup Commands** - Instant AP/STA configuration
- **🔍 Verbose Debugging** - Comprehensive packet-level logging
- **💡 AT Command Helpers** - Built-in shortcuts for common operations
- **🌈 Colored Terminal Output** - Enhanced readability

## 📖 Overview
This tool enables communication with WiFi HaLow (802.11ah) modules using AT commands over UDP broadcast protocol OR serial UART. Based on the manufacturer's protocol specification, it provides multiple communication methods with extensive debugging capabilities for troubleshooting and reverse engineering.

## ⚙️ Installation

### Prerequisites
- Python 3.6 or higher
- Network interface connected to HaLow module OR serial connection

### Basic Installation
```bash
git clone https://github.com/tradewithmeai/halow-alex.git
cd halow-alex
python pylibnetat.py --help
```

### Optional Dependencies
For enhanced functionality:
```bash
# Network interface discovery
pip install netifaces

# Serial port communication
pip install pyserial
```

## 🎮 Usage Examples

### Quick Start Commands
```bash
# List available network interfaces
python pylibnetat.py --list

# Basic connection with debug output
python pylibnetat.py en7 --debug --verbose

# Quick AP setup
python pylibnetat.py en7 --quick-ap "MyHaLowAP" --password "mypassword"

# Serial port mode
python pylibnetat.py --serial /dev/ttyUSB0

# Raw packet analysis mode
python pylibnetat.py en7 --raw --capture packets.json
```

### Network Communication
```bash
# Interface binding (macOS/Linux)
python pylibnetat.py en7 --debug

# IP address binding (all platforms)
python pylibnetat.py 192.168.1.100 --debug

# Fallback to any interface
python pylibnetat.py en7 --any --verbose

# Packet capture for analysis
python pylibnetat.py en7 --capture debug.json --verbose
```

### Serial Communication
```bash
# Windows
python pylibnetat.py --serial COM3 --baudrate 115200

# Linux/macOS
python pylibnetat.py --serial /dev/ttyUSB0 --baudrate 115200
```

## 📋 Command Reference

### Command-Line Options
- `interface` - Network interface name or IP address
- `--debug, -d` - Enable debug output
- `--verbose, -v` - Enable verbose packet logging with hex dumps
- `--any, -a` - Allow binding to any interface if specific binding fails
- `--list, -l` - List available network interfaces
- `--timeout, -t` - Response timeout in seconds (default: 2.0)
- `--capture, -c FILE` - Capture all packets to JSON file
- `--raw, -r` - Enter raw packet mode for testing
- `--serial, -s PORT` - Use serial port instead of network
- `--baudrate, -b` - Serial port baud rate (default: 115200)
- `--mode, -m` - Communication mode: one-to-one/one-to-many
- `--quick-ap SSID` - Quick AP setup with specified SSID
- `--quick-sta SSID` - Quick STA setup with specified SSID  
- `--password, -p` - Password for quick setup

### Interactive Commands
Once connected:
- `AT+<cmd>` - Send AT command to module
- `scan` - Scan for HaLow devices
- `raw` - Enter raw packet mode
- `rssi` - Get signal strength quickly
- `status` - Get connection status
- `pair` - Start pairing process
- `unpair` - Stop pairing process
- `help` - Show command help
- `quit/exit` - Exit the program

### Common AT Commands
Based on manufacturer documentation:

#### Basic Configuration
- `AT+` - Test command (should echo back)
- `AT+MODE?` - Query current mode
- `AT+MODE=ap/sta/group/apsta` - Set operating mode
- `AT+SSID?` - Query current SSID
- `AT+SSID=network_name` - Set SSID (max 32 chars)
- `AT+KEYMGMT?` - Query encryption mode
- `AT+KEYMGMT=WPA-PSK/NONE` - Set encryption mode
- `AT+PSK=<64_hex_chars>` - Set WPA password (64 hex characters)

#### Network Settings
- `AT+BSS_BW=1/2/4/8` - Set bandwidth (MHz)
- `AT+FREQ_RANGE=start,end` - Set frequency range (freq*10)
- `AT+CHAN_LIST=freq1,freq2,...` - Set specific frequency list
- `AT+TXPOWER=6-20` - Set transmit power (dBm)
- `AT+ACKTMO=value` - Set ACK timeout (microseconds)

#### Status & Control
- `AT+RSSI` - Get signal strength
- `AT+RSSI=index/mac_addr` - Get RSSI from specific device
- `AT+CONN_STATE` - Get connection status
- `AT+WNBCFG` - View all device configuration
- `AT+PAIR=1/0` - Start/stop pairing mode

#### Data Transmission
- `AT+TXDATA=length[,bw,mcs,priority]` - Send data command
- `AT+JOINGROUP=mac_addr,AID` - Join multicast group

#### Advanced/Debug
- `AT+FWUPG` - Enter firmware upgrade mode
- `AT+LOADDEF=1` - Factory reset
- `AT+ROAM=0/1` - Enable/disable roaming

## 🧪 Testing Instructions for Remote Debugging

### Method 1: Network Interface Testing
```bash
# Step 1: List interfaces
python pylibnetat.py --list

# Step 2: Try direct IP binding with full debug
python pylibnetat.py 192.168.1.100 --debug --verbose --capture debug.json

# Step 3: Try interface with fallback
python pylibnetat.py en7 --any --debug --verbose

# Step 4: Test basic AT commands
> AT+
> AT+MODE?
> AT+WNBCFG
```

### Method 2: Serial Port Testing
```bash
# Step 1: Find serial ports
# macOS: ls /dev/tty.*
# Linux: ls /dev/ttyUSB* /dev/ttyACM*
# Windows: Check Device Manager

# Step 2: Connect via serial
python pylibnetat.py --serial /dev/ttyUSB0 --debug

# Step 3: Test basic commands
AT+
AT+MODE?
AT+SSID?
```

### Method 3: Raw Packet Analysis
```bash
# Step 1: Start in raw mode with capture
python pylibnetat.py en7 --raw --capture raw_packets.json --verbose

# Step 2: Send different packet types
RAW> scan
RAW> hex 0100000000000000000000000000000000000000
RAW> cmd 1 
RAW> recv

# Step 3: Analyze captured packets
# Check the JSON file for packet structure
```

### Method 4: Protocol Reverse Engineering
```bash
# Capture all traffic for analysis
python pylibnetat.py en7 --capture full_session.json --verbose --debug

# Run commands and analyze responses
> scan
> AT+
> AT+MODE?
> AT+WNBCFG

# The JSON file will contain:
# - Packet timestamps
# - Direction (TX/RX)
# - Hex dumps of all data
# - Parsed packet analysis
```

## 🔧 Troubleshooting Guide

### Common Issues and Solutions

#### "Protocol not available" Error
1. **Use IP address instead of interface name**
   ```bash
   python pylibnetat.py 192.168.1.100 --debug
   ```

2. **Try the --any flag**
   ```bash
   python pylibnetat.py en7 --any --debug
   ```

3. **Use serial port as fallback**
   ```bash
   python pylibnetat.py --serial /dev/ttyUSB0
   ```

#### No Device Found
1. **Check power and connections**
   - Ensure HaLow module is powered on
   - Verify network cable connections

2. **Check network configuration**
   - Ensure same network segment
   - Test with: `ping <module_ip>`

3. **Check firewall settings**
   - Allow UDP port 56789
   - macOS: System Preferences → Security & Privacy → Firewall
   - Linux: `sudo ufw allow 56789/udp`
   - Windows: Windows Defender Firewall

4. **Try different interfaces**
   ```bash
   python pylibnetat.py --list
   # Try each interface listed
   ```

#### No Response to AT Commands
1. **Enable verbose logging**
   ```bash
   python pylibnetat.py en7 --debug --verbose
   ```

2. **Try basic test command**
   ```bash
   > AT+
   # Should receive echo response
   ```

3. **Check packet capture**
   ```bash
   python pylibnetat.py en7 --capture debug.json --verbose
   # Examine JSON file for actual packets sent/received
   ```

4. **Use raw packet mode**
   ```bash
   > raw
   RAW> scan
   RAW> recv
   # Look for any response packets
   ```

### Debug Output Analysis

#### Successful Connection
Look for these messages:
```
Socket initialized (method: IP_BINDING)
Device found at MAC: xx:xx:xx:xx:xx:xx
+COMMAND:value
OK
```

#### Network Issues
```
Failed to bind to interface
No devices found in initial scan
No response received
```

#### Protocol Issues
```
Invalid packet received
Cookie mismatch
Error parsing AT response
```

## 📊 Packet Analysis

### Packet Structure
Based on manufacturer documentation:
```
Packet Format (15+ bytes):
+-----+-----+-----+-----+-----+-----+
| CMD | LEN | DEST MAC  |  SRC MAC  | DATA...
+-----+-----+-----+-----+-----+-----+
  1     2        6           6       variable

CMD: 1=SCAN_REQ, 2=SCAN_RESP, 3=AT_REQ, 4=AT_RESP
LEN: Data length (big-endian)
DEST: Destination MAC (6 bytes)
SRC: Source MAC/Cookie (6 bytes)  
DATA: AT command or response
```

### Hex Dump Example
```
============================================================
Packet Analysis (Total: 23 bytes)
============================================================
CMD:  0x03 (AT_REQ)
LEN:  0x0008 (8 bytes)
DEST: ffffffffffff (ff:ff:ff:ff:ff:ff)
SRC:  a1b2c3d4e5f6 (a1:b2:c3:d4:e5:f6)

DATA (8 bytes):
  0000: 41 54 2b 4d 4f 44 45 3f                         |AT+MODE?|

Decoded: AT+MODE?
============================================================
```

## 🛡️ Security Notes

- This tool is for legitimate device configuration only
- AT commands can modify device settings permanently
- Use `AT+LOADDEF=1` to restore factory defaults if needed
- Packet capture files may contain sensitive configuration data
- Serial connections may require appropriate permissions

## 📁 File Structure

```
halow-alex/
├── pylibnetat.py          # Main application (v4.0)
├── README.md              # This documentation
├── LICENSE                # License file
└── examples/              # Example configurations
    ├── debug.json         # Sample packet capture
    └── setup_scripts/     # Automated setup examples
```

## 🔄 Protocol Compatibility

This implementation is based on:
- Taixin TX-AH-R WiFi HaLow module documentation
- Network AT command protocol (UDP port 56789)
- Serial UART protocol (115200 baud, 8N1)
- Manufacturer's netat.exe equivalent functionality

## 📝 Version History

### v4.0 (Latest)
- Added comprehensive packet analysis and debugging
- Implemented raw packet mode for protocol testing
- Added serial port communication support
- Enhanced AT command parsing and response handling
- Added packet capture functionality
- Implemented Ethernet frame support for data transmission
- Added colored terminal output and verbose logging
- Created AT command helper shortcuts

### v3.0 (Previous)
- Fixed cross-platform socket binding issues
- Added multiple network interface binding methods
- Improved error handling and debugging output

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Test your changes thoroughly
4. Submit a pull request with detailed description

## 📞 Support

For issues and questions:
1. Check the troubleshooting section above
2. Enable `--debug --verbose` and capture output
3. Use `--capture` to save packet traces
4. Open an issue at https://github.com/tradewithmeai/halow-alex

Include in your report:
- Operating system and version
- Python version
- Full command line used
- Complete debug output
- Packet capture file (if available)

## 📄 License

See LICENSE file for details.

---

*This tool provides the functionality equivalent to the manufacturer's netat.exe but with enhanced debugging, analysis, and cross-platform support for WiFi HaLow module configuration.*