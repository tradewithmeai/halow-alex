#!/usr/bin/env python3
"""
Quick test script for refactored HaLow tool modules
"""

import sys
import os

# Add the package to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_imports():
    """Test that all modules can be imported"""
    print("Testing module imports...")
    
    try:
        from taixin_tools.lib.constants import WnbCommand, NETAT_PORT
        print("[PASS] Constants module imported")
        
        from taixin_tools.lib.logger import setup_logging, ColoredFormatter
        print("[PASS] Logger module imported")
        
        from taixin_tools.lib.protocol import WnbNetatCmd, parse_at_response
        print("[PASS] Protocol module imported")
        
        from taixin_tools.lib.network import SocketManager, NetworkInterface
        print("[PASS] Network module imported")
        
        from taixin_tools.lib.serial_comm import SerialHandler
        print("[PASS] Serial communication module imported")
        
        from taixin_tools.lib.at_commands import ATCommandSet, ATCommandHelper
        print("[PASS] AT commands module imported")
        
        from taixin_tools.lib.utils import random_bytes, mac_str_to_bytes
        print("[PASS] Utils module imported")
        
        from taixin_tools.lib.manager import HaLowManager
        print("[PASS] Manager module imported")
        
        from taixin_tools.lib.interactive import ATCommandMode, RawPacketMode
        print("[PASS] Interactive modules imported")
        
        return True
        
    except ImportError as e:
        print(f"[FAIL] Import failed: {e}")
        return False


def test_protocol():
    """Test protocol packet creation and parsing"""
    print("\nTesting protocol functionality...")
    
    from taixin_tools.lib.protocol import WnbNetatCmd, create_scan_packet, create_at_packet
    from taixin_tools.lib.constants import WnbCommand
    
    try:
        # Test scan packet
        scan_data = create_scan_packet()
        print(f"[PASS] Scan packet created ({len(scan_data)} bytes)")
        
        # Test AT packet
        at_data = create_at_packet("AT+GMR")
        print(f"[PASS] AT packet created ({len(at_data)} bytes)")
        
        # Test packet parsing
        packet = WnbNetatCmd.unpack(at_data)
        if packet and packet.cmd == WnbCommand.AT_REQ:
            print("[PASS] Packet parsing works")
        else:
            print("[FAIL] Packet parsing failed")
            return False
            
        return True
        
    except Exception as e:
        print(f"[FAIL] Protocol test failed: {e}")
        return False


def test_at_commands():
    """Test AT command helpers"""
    print("\nTesting AT command functionality...")
    
    from taixin_tools.lib.at_commands import ATCommandHelper, ATCommandSet
    
    try:
        # Test SSID command
        ssid_cmd = ATCommandHelper.set_ssid("TestNetwork")
        expected = "AT+SSID=TestNetwork"
        if ssid_cmd == expected:
            print("[PASS] SSID command generation works")
        else:
            print(f"[FAIL] SSID command mismatch: {ssid_cmd} != {expected}")
            return False
            
        # Test quick AP commands
        ap_commands = ATCommandHelper.get_quick_ap_commands("MyAP", "password123")
        if len(ap_commands) > 0:
            print(f"[PASS] Quick AP commands generated ({len(ap_commands)} commands)")
        else:
            print("[FAIL] Quick AP command generation failed")
            return False
            
        return True
        
    except Exception as e:
        print(f"[FAIL] AT command test failed: {e}")
        return False


def test_utilities():
    """Test utility functions"""
    print("\nTesting utility functions...")
    
    from taixin_tools.lib.utils import mac_str_to_bytes, bytes_to_mac_str, hex_to_bytes
    
    try:
        # Test MAC address conversion
        mac_str = "aa:bb:cc:dd:ee:ff"
        mac_bytes = mac_str_to_bytes(mac_str)
        mac_back = bytes_to_mac_str(mac_bytes)
        
        if mac_back == mac_str:
            print("[PASS] MAC address conversion works")
        else:
            print(f"[FAIL] MAC conversion failed: {mac_str} != {mac_back}")
            return False
            
        # Test hex conversion
        hex_str = "deadbeef"
        hex_bytes = hex_to_bytes(hex_str)
        if hex_bytes and len(hex_bytes) == 4:
            print("[PASS] Hex conversion works")
        else:
            print("[FAIL] Hex conversion failed")
            return False
            
        return True
        
    except Exception as e:
        print(f"[FAIL] Utility test failed: {e}")
        return False


def main():
    """Run all tests"""
    print("HaLow Tool Refactored - Module Test Suite")
    print("=" * 50)
    
    tests = [
        test_imports,
        test_protocol,
        test_at_commands,
        test_utilities
    ]
    
    passed = 0
    
    for test in tests:
        if test():
            passed += 1
        else:
            break
            
    print("\n" + "=" * 50)
    print(f"Test Results: {passed}/{len(tests)} tests passed")
    
    if passed == len(tests):
        print("[PASS] All tests passed! Refactored code is working correctly.")
        return 0
    else:
        print("[FAIL] Some tests failed. Please check the code.")
        return 1


if __name__ == "__main__":
    sys.exit(main())