#!/usr/bin/env python3
"""
Unit tests for MiniShark CLI
"""

import unittest
import socket
import struct
import json
from datetime import datetime
from unittest.mock import patch, MagicMock
from minishark import Packet, PacketAnalyzer, MiniShark

class TestMiniShark(unittest.TestCase):
    """Test suite for MiniShark functionality"""

    def setUp(self):
        """Set up test environment"""
        self.analyzer = PacketAnalyzer(data_bytes=60)
        self.minishark = MiniShark(data_bytes=60)

    def test_packet_dataclass(self):
        """Test Packet dataclass creation"""
        packet = Packet(
            timestamp="12:00:00.000",
            protocol="TCP",
            source_ip="192.168.1.1",
            dest_ip="8.8.8.8",
            source_port=12345,
            dest_port=80,
            size=100,
            data="deadbeef",
            info="SYN,ACK"
        )
        self.assertEqual(packet.protocol, "TCP")
        self.assertEqual(packet.source_ip, "192.168.1.1")
        self.assertEqual(packet.dest_ip, "8.8.8.8")
        self.assertEqual(packet.source_port, 12345)
        self.assertEqual(packet.dest_port, 80)
        self.assertEqual(packet.size, 100)
        self.assertEqual(packet.info, "SYN,ACK")

    def test_parse_ethernet_header(self):
        """Test Ethernet header parsing"""
        data = b'\x00' * 12 + struct.pack('!H', 0x0800)  # IPv4
        eth_protocol, remaining = self.analyzer.parse_ethernet_header(data)
        self.assertEqual(eth_protocol, 8)
        self.assertEqual(len(remaining), 0)

    def test_parse_ip_header(self):
        """Test IPv4 header parsing"""
        data = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 40, 0, 0, 0, 6, 0, 
                         socket.inet_aton("192.168.1.1"), socket.inet_aton("8.8.8.8"))
        ip_info = self.analyzer.parse_ip_header(data)
        self.assertEqual(ip_info['version'], 4)
        self.assertEqual(ip_info['protocol'], 6)  # TCP
        self.assertEqual(ip_info['source'], "192.168.1.1")
        self.assertEqual(ip_info['destination'], "8.8.8.8")
        self.assertEqual(ip_info['header_length'], 20)

    def test_parse_tcp_header(self):
        """Test TCP header parsing"""
        data = struct.pack('!HHLLBBHHH', 12345, 80, 0, 0, 0x50, 0x12, 0, 0, 0)
        tcp_info = self.analyzer.parse_tcp_header(data)
        self.assertEqual(tcp_info['source_port'], 12345)
        self.assertEqual(tcp_info['dest_port'], 80)
        self.assertEqual(tcp_info['flags'], ['PSH', 'ACK'])

    def test_analyze_packet_tcp(self):
        """Test TCP packet analysis"""
        eth_header = b'\x00' * 12 + struct.pack('!H', 0x0800)
        ip_header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 40, 0, 0, 0, 6, 0, 
                               socket.inet_aton("192.168.1.1"), socket.inet_aton("8.8.8.8"))
        tcp_header = struct.pack('!HHLLBBHHH', 12345, 80, 0, 0, 0x50, 0x12, 0, 0, 0)
        data = eth_header + ip_header + tcp_header
        packet = self.analyzer.analyze_packet(data, len(data))
        self.assertIsNotNone(packet)
        self.assertEqual(packet.protocol, "HTTP")
        self.assertEqual(packet.source_ip, "192.168.1.1")
        self.assertEqual(packet.dest_ip, "8.8.8.8")
        self.assertEqual(packet.source_port, 12345)
        self.assertEqual(packet.dest_port, 80)
        self.assertIn("PSH,ACK", packet.info)

    def test_analyze_packet_filter_protocol(self):
        """Test protocol filtering"""
        self.analyzer.filter_protocol = "udp"
        eth_header = b'\x00' * 12 + struct.pack('!H', 0x0800)
        ip_header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 28, 0, 0, 0, 17, 0, 
                               socket.inet_aton("192.168.1.1"), socket.inet_aton("8.8.8.8"))
        udp_header = struct.pack('!HHHH', 12345, 53, 8, 0)
        data = eth_header + ip_header + udp_header
        packet = self.analyzer.analyze_packet(data, len(data))
        self.assertIsNotNone(packet)
        self.assertEqual(packet.protocol, "DNS")

        self.analyzer.filter_protocol = "tcp"
        packet = self.analyzer.analyze_packet(data, len(data))
        self.assertIsNone(packet)

    def test_analyze_packet_filter_ip(self):
        """Test IP filtering"""
        self.analyzer.filter_ip = "192.168.1.1"
        eth_header = b'\x00' * 12 + struct.pack('!H', 0x0800)
        ip_header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 28, 0, 0, 0, 17, 0, 
                               socket.inet_aton("192.168.1.1"), socket.inet_aton("8.8.8.8"))
        udp_header = struct.pack('!HHHH', 12345, 53, 8, 0)
        data = eth_header + ip_header + udp_header
        packet = self.analyzer.analyze_packet(data, len(data))
        self.assertIsNotNone(packet)

        self.analyzer.filter_ip = "10.0.0.1"
        packet = self.analyzer.analyze_packet(data, len(data))
        self.assertIsNone(packet)

    @patch('socket.socket')
    def test_create_socket_permission_error(self, mock_socket):
        """Test socket creation with permission error"""
        mock_socket.side_effect = PermissionError("Permission denied")
        result = self.minishark.create_socket()
        self.assertFalse(result)

    def test_set_filter_invalid_protocol(self):
        """Test invalid protocol filter"""
        with self.assertRaises(SystemExit):
            self.minishark.set_filter(protocol="INVALID")

    def test_export_packets(self):
        """Test packet export to JSON"""
        packet = Packet(
            timestamp="12:00:00.000",
            protocol="TCP",
            source_ip="192.168.1.1",
            dest_ip="8.8.8.8",
            source_port=12345,
            dest_port=80,
            size=100,
            data="deadbeef",
            info="SYN,ACK"
        )
        self.analyzer.packets = [packet]
        with patch('builtins.open', unittest.mock.mock_open()) as mock_file:
            self.minishark.export_packets("test.json")
            mock_file().write.assert_called_once()
            written_data = mock_file().write.call_args[0][0]
            self.assertIn('"protocol": "TCP"', written_data)
            self.assertIn('"source_ip": "192.168.1.1"', written_data)

if __name__ == '__main__':
    unittest.main()