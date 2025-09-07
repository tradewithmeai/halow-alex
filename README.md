# HaLow AT Command Configuration Tool

AT command configuration app for Taixin TX-AH-R WiFi HaLow Modules/devices

## Overview
This tool enables communication with WiFi HaLow (802.11ah) modules using AT commands over UDP broadcast protocol. It provides a command-line interface for configuring and controlling HaLow modules.

## Features
- Cross-platform support (Linux, macOS, Windows)
- Multiple network binding methods
- Comprehensive debugging and logging
- Automatic device discovery via broadcast
- Interactive AT command interface
- Detailed error messages and troubleshooting

## Installation

### Prerequisites
- Python 3.6 or higher
- Network interface connected to HaLow module

### Basic Installation
```bash
git clone https://github.com/tradewithmeai/halow-alex.git
cd halow-alex
python pylibnetat.py --help
```

### Optional Dependencies
For better network interface discovery:
```bash
pip install netifaces
```

## Usage

### Quick Start
```bash
# List available network interfaces
python pylibnetat.py --list

# Connect using interface name
python pylibnetat.py eth0

# Connect using IP address
python pylibnetat.py 192.168.1.100

# Connect with debug output
python pylibnetat.py eth0 --debug

# Allow fallback to any interface
python pylibnetat.py eth0 --any
```

### Command-Line Options
- `interface` - Network interface name or IP address
- `--debug, -d` - Enable detailed debug output
- `--any, -a` - Allow binding to any interface if specific binding fails
- `--list, -l` - List available network interfaces
- `--timeout, -t` - Response timeout in seconds (default: 2.0)

### Interactive Commands
Once connected, you can use:
- `AT+<cmd>` - Send AT command to module
- `scan` - Scan for HaLow devices
- `help` - Show available commands
- `quit/exit` - Exit the program

### Common AT Commands
- `AT+GMR` - Get module firmware version
- `AT+RST` - Reset module
- `AT+CWMODE` - Get/Set WiFi mode
- `AT+CWLAP` - List available access points
- `AT+CWJAP` - Join access point
- `AT+CIFSR` - Get IP address

## Testing Instructions for Your Friend

### 1. Initial Setup
```bash
# Clone the repository
git clone https://github.com/tradewithmeai/halow-alex.git
cd halow-alex

# Install optional dependencies (recommended)
pip install netifaces
```

### 2. Find the Correct Network Interface
```bash
# List all network interfaces
python pylibnetat.py --list

# On macOS, interfaces are usually: en0, en1, en7, etc.
# On Linux: eth0, wlan0, etc.
# On Windows: use IP address instead
```

### 3. Test Connection Methods

#### Method A: Direct Interface Binding (macOS/Linux)
```bash
# Try with the interface that's connected to the HaLow module
python pylibnetat.py en7 --debug
```

#### Method B: IP Address Binding (All Platforms)
```bash
# Find your IP address on the network with the HaLow module
# Then use it directly
python pylibnetat.py 192.168.1.100 --debug
```

#### Method C: Any Interface Binding (Fallback)
```bash
# This binds to all interfaces (0.0.0.0)
python pylibnetat.py en7 --any --debug
```

### 4. Troubleshooting Steps

If you get "Protocol not available" error:
1. **Use IP address instead of interface name**
   ```bash
   python pylibnetat.py 192.168.1.100 --debug
   ```

2. **Try the --any flag**
   ```bash
   python pylibnetat.py en7 --any --debug
   ```

3. **Check firewall settings**
   - Ensure UDP port 56789 is not blocked
   - On macOS: System Preferences → Security & Privacy → Firewall
   - On Linux: `sudo ufw allow 56789/udp`

4. **Verify network connectivity**
   ```bash
   # Check if you can ping the HaLow module
   ping <module_ip>
   
   # Check if port is already in use
   netstat -an | grep 56789
   ```

5. **Run with elevated privileges (Linux only)**
   ```bash
   sudo python pylibnetat.py eth0 --debug
   ```

### 5. Debug Output Analysis
With `--debug` flag, you'll see:
- Platform information
- Socket binding attempts and methods
- Packet transmission details (hex dumps)
- Response parsing information
- Cookie matching for request/response correlation

### 6. Expected Behavior
1. **Successful connection:**
   - "Socket initialized successfully" message
   - "HaLow AT Command Interface Ready" prompt
   - Can type AT commands

2. **Device found:**
   - "Device found at MAC: xxxxxxxxxxxx" message
   - AT commands receive responses

3. **No device found:**
   - "No devices found in initial scan" warning
   - Commands will trigger automatic scanning

### 7. Network Requirements
- HaLow module and computer must be on same network segment
- UDP broadcast must be enabled on the network
- Port 56789 must be available and not blocked

### 8. Report Issues
If problems persist, please provide:
1. Complete output with `--debug` flag
2. Operating system and version
3. Network configuration (interface name, IP)
4. HaLow module model and firmware version (if known)

## Protocol Details
- **Port:** UDP 56789
- **Discovery:** UDP broadcast scan
- **Packet Format:**
  - Command byte (1)
  - Length (2 bytes, big-endian)
  - Destination MAC (6 bytes)
  - Source MAC/Cookie (6 bytes)
  - Data payload (variable)

## License
See LICENSE file for details.

## Contributing
Issues and pull requests welcome at https://github.com/tradewithmeai/halow-alex