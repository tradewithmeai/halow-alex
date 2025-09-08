"""
AT command definitions and helpers for HaLow modules
"""

from typing import Optional, Dict, List


class ATCommandSet:
    """Standard AT commands for HaLow modules"""
    
    # Basic commands
    TEST = "AT"                    # Test command
    VERSION = "AT+GMR"             # Get firmware version
    RESET = "AT+RST"              # Reset module
    FACTORY_RESET = "AT+LOADDEF=1" # Factory reset
    
    # Mode commands
    MODE_QUERY = "AT+MODE?"        # Query current mode
    MODE_AP = "AT+MODE=ap"         # Set AP mode
    MODE_STA = "AT+MODE=sta"       # Set station mode
    
    # Network configuration
    SSID_QUERY = "AT+SSID?"        # Query SSID
    SSID_SET = "AT+SSID="          # Set SSID (append name)
    
    # Security
    KEYMGMT_QUERY = "AT+KEYMGMT?"  # Query key management
    KEYMGMT_NONE = "AT+KEYMGMT=NONE"     # No encryption
    KEYMGMT_WPA2 = "AT+KEYMGMT=WPA2PSK"  # WPA2-PSK
    PSK_SET = "AT+PSK="            # Set password (hex)
    
    # Radio configuration
    BSS_BW_QUERY = "AT+BSS_BW?"    # Query bandwidth
    BSS_BW_1 = "AT+BSS_BW=1"       # 1MHz bandwidth
    BSS_BW_2 = "AT+BSS_BW=2"       # 2MHz bandwidth
    BSS_BW_4 = "AT+BSS_BW=4"       # 4MHz bandwidth
    BSS_BW_8 = "AT+BSS_BW=8"       # 8MHz bandwidth
    
    # Status commands
    RSSI = "AT+RSSI"               # Get signal strength
    CONN_STATE = "AT+CONN_STATE"   # Connection status
    IP_QUERY = "AT+IP?"            # Query IP address
    MAC_QUERY = "AT+MAC?"          # Query MAC address
    
    # Channel configuration
    CHANNEL_QUERY = "AT+CHANNEL?"   # Query channel
    CHANNEL_SET = "AT+CHANNEL="     # Set channel
    
    # Advanced configuration
    WNBCFG = "AT+WNBCFG"           # View all configuration
    PAIR_START = "AT+PAIR=1"       # Start pairing
    PAIR_STOP = "AT+PAIR=0"        # Stop pairing
    
    # Power management
    TX_POWER_QUERY = "AT+TXPOWER?" # Query TX power
    TX_POWER_SET = "AT+TXPOWER="   # Set TX power


class ATCommandHelper:
    """Helper functions for AT commands"""
    
    @staticmethod
    def format_command(cmd: str, value: str = None) -> str:
        """
        Format an AT command with optional value
        
        Args:
            cmd: Base command
            value: Optional value to append
            
        Returns:
            Formatted command string
        """
        if value is not None:
            return f"{cmd}{value}"
        return cmd
    
    @staticmethod
    def set_ssid(ssid: str) -> str:
        """Create command to set SSID"""
        return ATCommandHelper.format_command(ATCommandSet.SSID_SET, ssid)
    
    @staticmethod
    def set_channel(channel: int) -> str:
        """Create command to set channel"""
        return ATCommandHelper.format_command(ATCommandSet.CHANNEL_SET, str(channel))
    
    @staticmethod
    def set_bandwidth(bandwidth: int) -> str:
        """Create command to set bandwidth (1, 2, 4, or 8 MHz)"""
        if bandwidth not in [1, 2, 4, 8]:
            raise ValueError("Bandwidth must be 1, 2, 4, or 8 MHz")
        return f"AT+BSS_BW={bandwidth}"
    
    @staticmethod
    def set_tx_power(power: int) -> str:
        """Create command to set TX power"""
        return ATCommandHelper.format_command(ATCommandSet.TX_POWER_SET, str(power))
    
    @staticmethod
    def set_password_hex(password: str) -> str:
        """
        Create command to set password as hex string
        
        Args:
            password: Password string to convert to hex
            
        Returns:
            AT command with hex-encoded password
        """
        hex_pwd = password.encode().hex()
        return ATCommandHelper.format_command(ATCommandSet.PSK_SET, hex_pwd)
    
    @staticmethod
    def parse_rssi(response: str) -> Optional[int]:
        """
        Parse RSSI value from response
        
        Args:
            response: AT command response
            
        Returns:
            RSSI value in dBm or None
        """
        if 'RSSI' in response:
            try:
                # Extract numeric value
                parts = response.split(':')
                if len(parts) > 1:
                    value = parts[1].strip()
                    # Remove any units
                    value = value.replace('dBm', '').strip()
                    return int(value)
            except:
                pass
        return None
    
    @staticmethod
    def parse_connection_state(response: str) -> str:
        """
        Parse connection state from response
        
        Args:
            response: AT command response
            
        Returns:
            Connection state string
        """
        if 'CONN_STATE' in response:
            parts = response.split(':')
            if len(parts) > 1:
                return parts[1].strip()
        return "Unknown"
    
    @staticmethod
    def get_quick_ap_commands(ssid: str, password: Optional[str] = None) -> List[str]:
        """
        Get command sequence for quick AP setup
        
        Args:
            ssid: Network name
            password: Optional password
            
        Returns:
            List of AT commands
        """
        commands = [
            ATCommandSet.MODE_AP,
            ATCommandHelper.set_ssid(ssid),
        ]
        
        if password:
            commands.append(ATCommandSet.KEYMGMT_WPA2)
            commands.append(ATCommandHelper.set_password_hex(password))
        else:
            commands.append(ATCommandSet.KEYMGMT_NONE)
            
        commands.extend([
            ATCommandSet.BSS_BW_8,  # Default to 8MHz
            ATCommandSet.RESET       # Apply settings
        ])
        
        return commands
    
    @staticmethod
    def get_quick_sta_commands(ssid: str, password: Optional[str] = None) -> List[str]:
        """
        Get command sequence for quick station setup
        
        Args:
            ssid: Network to connect to
            password: Optional password
            
        Returns:
            List of AT commands
        """
        commands = [
            ATCommandSet.MODE_STA,
            ATCommandHelper.set_ssid(ssid),
        ]
        
        if password:
            commands.append(ATCommandSet.KEYMGMT_WPA2)
            commands.append(ATCommandHelper.set_password_hex(password))
        else:
            commands.append(ATCommandSet.KEYMGMT_NONE)
            
        commands.append(ATCommandSet.RESET)  # Apply settings
        
        return commands


class ATCommandInfo:
    """Information about AT commands for help system"""
    
    COMMAND_HELP = {
        'AT': 'Test command - check if module is responding',
        'AT+GMR': 'Get firmware version',
        'AT+RST': 'Reset the module',
        'AT+LOADDEF=1': 'Factory reset - restore default settings',
        
        'AT+MODE?': 'Query current mode (AP/STA)',
        'AT+MODE=ap': 'Set Access Point mode',
        'AT+MODE=sta': 'Set Station mode',
        
        'AT+SSID?': 'Query current SSID',
        'AT+SSID=name': 'Set network name',
        
        'AT+KEYMGMT?': 'Query encryption type',
        'AT+KEYMGMT=NONE': 'Disable encryption',
        'AT+KEYMGMT=WPA2PSK': 'Enable WPA2-PSK encryption',
        'AT+PSK=hex': 'Set password (in hex format)',
        
        'AT+BSS_BW?': 'Query bandwidth setting',
        'AT+BSS_BW=1': 'Set 1MHz bandwidth',
        'AT+BSS_BW=2': 'Set 2MHz bandwidth',
        'AT+BSS_BW=4': 'Set 4MHz bandwidth',
        'AT+BSS_BW=8': 'Set 8MHz bandwidth',
        
        'AT+RSSI': 'Get signal strength in dBm',
        'AT+CONN_STATE': 'Check connection status',
        'AT+IP?': 'Query IP address',
        'AT+MAC?': 'Query MAC address',
        
        'AT+CHANNEL?': 'Query current channel',
        'AT+CHANNEL=n': 'Set channel number',
        
        'AT+WNBCFG': 'View all configuration settings',
        'AT+PAIR=1': 'Start WPS pairing',
        'AT+PAIR=0': 'Stop WPS pairing',
        
        'AT+TXPOWER?': 'Query transmit power',
        'AT+TXPOWER=n': 'Set transmit power',
    }
    
    SHORTCUTS = {
        'scan': 'Scan for HaLow devices on the network',
        'rssi': 'Get current signal strength',
        'status': 'Get connection status',
        'pair': 'Start WPS pairing mode',
        'unpair': 'Stop WPS pairing mode',
        'help': 'Show available commands',
        'quit': 'Exit the program',
    }
    
    @staticmethod
    def print_help():
        """Print command help to console"""
        print("\n" + "=" * 60)
        print("AT COMMAND REFERENCE")
        print("=" * 60)
        
        print("\nSHORTCUTS:")
        print("-" * 40)
        for cmd, desc in ATCommandInfo.SHORTCUTS.items():
            print(f"  {cmd:<10} - {desc}")
        
        print("\nBASIC COMMANDS:")
        print("-" * 40)
        for cmd in ['AT', 'AT+GMR', 'AT+RST', 'AT+LOADDEF=1']:
            if cmd in ATCommandInfo.COMMAND_HELP:
                print(f"  {cmd:<20} - {ATCommandInfo.COMMAND_HELP[cmd]}")
        
        print("\nMODE CONFIGURATION:")
        print("-" * 40)
        for cmd in ['AT+MODE?', 'AT+MODE=ap', 'AT+MODE=sta']:
            if cmd in ATCommandInfo.COMMAND_HELP:
                print(f"  {cmd:<20} - {ATCommandInfo.COMMAND_HELP[cmd]}")
        
        print("\nNETWORK SETTINGS:")
        print("-" * 40)
        for cmd in ['AT+SSID?', 'AT+SSID=name', 'AT+CHANNEL?', 'AT+CHANNEL=n']:
            if cmd in ATCommandInfo.COMMAND_HELP:
                print(f"  {cmd:<20} - {ATCommandInfo.COMMAND_HELP[cmd]}")
        
        print("\nSECURITY:")
        print("-" * 40)
        for cmd in ['AT+KEYMGMT?', 'AT+KEYMGMT=NONE', 'AT+KEYMGMT=WPA2PSK', 'AT+PSK=hex']:
            if cmd in ATCommandInfo.COMMAND_HELP:
                print(f"  {cmd:<20} - {ATCommandInfo.COMMAND_HELP[cmd]}")
        
        print("\nRADIO SETTINGS:")
        print("-" * 40)
        for cmd in ['AT+BSS_BW?', 'AT+BSS_BW=8', 'AT+TXPOWER?', 'AT+TXPOWER=n']:
            if cmd in ATCommandInfo.COMMAND_HELP:
                print(f"  {cmd:<20} - {ATCommandInfo.COMMAND_HELP[cmd]}")
        
        print("\nSTATUS COMMANDS:")
        print("-" * 40)
        for cmd in ['AT+RSSI', 'AT+CONN_STATE', 'AT+IP?', 'AT+MAC?', 'AT+WNBCFG']:
            if cmd in ATCommandInfo.COMMAND_HELP:
                print(f"  {cmd:<20} - {ATCommandInfo.COMMAND_HELP[cmd]}")
        
        print("\n" + "=" * 60)