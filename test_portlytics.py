# test_portlytics.py
import pytest
from portlytics import scan_port, scan_ports

def test_scan_port_open():
    # Replace `127.0.0.1` with the actual IP and `80` with an open port on your system
    assert scan_port("127.0.0.1", 80) == True

def test_scan_port_closed():
    # Replace `127.0.0.1` with the actual IP and `9999` with a closed port
    assert scan_port("127.0.0.1", 9999) == False

def test_scan_ports():
    open_ports = scan_ports("127.0.0.1", range(1, 100))  # scan a range of ports
    assert isinstance(open_ports, list)  # Check that it's a list
    assert all(isinstance(port, int) for port in open_ports)  # Check that all elements are integers
