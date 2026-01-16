from unittest.mock import patch
from portlytics import scan_port

def test_scan_port_open():
    with patch("socket.socket.connect_ex", return_value=0):
        assert scan_port("127.0.0.1", 80) is True

def test_scan_port_closed():
    with patch("socket.socket.connect_ex", return_value=1):
        assert scan_port("127.0.0.1", 80) is False
