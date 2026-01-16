import pytest
from portlytics import scan_port, scan_ports

# Test that scan_port works with a known open port
def test_scan_port_open():
    # Replace 'localhost' with a known IP address and '80' with a known open port
    assert scan_port("127.0.0.1", 80) == True

# Test that scan_port works with a known closed port
def test_scan_port_closed():
    assert scan_port("127.0.0.1", 9999) == False

# Test the scan_ports function
def test_scan_ports():
    open_ports = scan_ports("127.0.0.1", range(1, 100))  # scan a range of ports
    assert isinstance(open_ports, list)  # Check that it's a list
    assert all(isinstance(port, int) for port in open_ports)  # Check that all elements are integers
