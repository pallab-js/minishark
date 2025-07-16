#!/usr/bin/env python3
"""
MiniShark CLI - Lightweight Network Packet Analyzer
An improved, cross-platform, and feature-rich command-line packet
capture and analysis tool using Scapy.
"""

import argparse
import json
import logging
import os
import psutil
import socket
import signal
import sys
import threading
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import List, Optional

# Scapy is a powerful packet manipulation library.
# It replaces all the manual struct-based parsing for robustness and simplicity.
from scapy.layers.inet import IP, TCP, UDP, ICMP, Ether
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP
from scapy.packet import Packet as ScapyPacket
from scapy.utils import wrpcap

@dataclass
class Packet:
    """Represents a captured network packet for display and JSON export."""
    timestamp: str
    protocol: str
    source_ip: str
    dest_ip: str
    source_port: Optional[int]
    dest_port: Optional[int]
    size: int
    info: str
    data: str  # Hex representation of raw packet data

class PacketAnalyzer:
    """Core packet analysis functionality, now powered by Scapy."""

    def __init__(self, data_bytes=60):
        self.packets: List[Packet] = []
        self.scapy_packets: List[ScapyPacket] = [] # For PCAP export
        self.packet_lock = threading.Lock()
        self.running = False
        self.filter_protocol: Optional[str] = None
        self.filter_ip: Optional[str] = None
        self.filter_port: Optional[int] = None
        self.data_bytes = data_bytes

    def analyze_packet(self, data: bytes):
        """
        Analyze a raw packet using Scapy and extract information.
        This replaces all previous manual parsing methods.
        """
        try:
            timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
            scapy_pkt = Ether(data)
            size = len(scapy_pkt)
            
            source_ip, dest_ip = "", ""
            source_port, dest_port = None, None
            protocol_name = "UNKNOWN"
            info = ""

            # Layer 2: ARP
            if scapy_pkt.haslayer(ARP):
                protocol_name = "ARP"
                arp_layer = scapy_pkt[ARP]
                source_ip = arp_layer.psrc
                dest_ip = arp_layer.pdst
                info = f"Who has {dest_ip}? Tell {source_ip}" if arp_layer.op == 1 else f"{source_ip} is at {arp_layer.hwsrc}"

            # Layer 3: IP (v4 or v6)
            elif scapy_pkt.haslayer(IP):
                ip_layer = scapy_pkt[IP]
                source_ip = ip_layer.src
                dest_ip = ip_layer.dst
                protocol_name = "IP"
            elif scapy_pkt.haslayer(IPv6):
                ip_layer = scapy_pkt[IPv6]
                source_ip = ip_layer.src
                dest_ip = ip_layer.dst
                protocol_name = "IPv6"
            else: # Not an IP or ARP packet, skip further analysis
                 return None, None
            
            # Layer 4: Transport Protocols (TCP, UDP, ICMP)
            if scapy_pkt.haslayer(TCP):
                tcp_layer = scapy_pkt[TCP]
                protocol_name = "TCP"
                source_port = tcp_layer.sport
                dest_port = tcp_layer.dport
                flags = tcp_layer.flags.flagrepr()
                info = f"[{flags}] {source_port} → {dest_port}"
                if dest_port == 80 or source_port == 80:
                    protocol_name = "HTTP"
                elif dest_port == 443 or source_port == 443:
                    protocol_name = "HTTPS"
            
            elif scapy_pkt.haslayer(UDP):
                udp_layer = scapy_pkt[UDP]
                protocol_name = "UDP"
                source_port = udp_layer.sport
                dest_port = udp_layer.dport
                info = f"{source_port} → {dest_port} Len={udp_layer.len}"
                if dest_port == 53 or source_port == 53:
                    protocol_name = "DNS"
            
            elif scapy_pkt.haslayer(ICMP):
                icmp_layer = scapy_pkt[ICMP]
                protocol_name = "ICMP"
                icmp_types = {0: "Echo Reply", 8: "Echo Request", 3: "Dest Unreachable"}
                icmp_type_name = icmp_types.get(icmp_layer.type, f"Type {icmp_layer.type}")
                info = f"{icmp_type_name} (type={icmp_layer.type}, code={icmp_layer.code})"

            # Apply filters
            if self.filter_protocol and protocol_name.lower() != self.filter_protocol.lower():
                return None, None
            if self.filter_ip and self.filter_ip not in (source_ip, dest_ip):
                return None, None
            if self.filter_port and self.filter_port not in (source_port, dest_port):
                return None, None

            packet = Packet(
                timestamp=timestamp,
                protocol=protocol_name,
                source_ip=source_ip,
                dest_ip=dest_ip,
                source_port=source_port,
                dest_port=dest_port,
                size=size,
                info=info,
                data=data[:self.data_bytes].hex()
            )
            return packet, scapy_pkt
        
        except Exception as e:
            # More specific error logging could be added here if needed
            logging.warning(f"Packet parsing error: {e} - Data: {data.hex()}")
            return None, None

class MiniShark:
    """Main MiniShark CLI application."""

    def __init__(self, data_bytes=60, memory_limit=500 * 1024 * 1024):
        self.analyzer = PacketAnalyzer(data_bytes)
        self.socket = None
        self.capture_thread = None
        self.packet_count = 0
        self.max_packets = 1000
        self.memory_limit = memory_limit
        self.verbose = False
        logging.basicConfig(filename='minishark.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    def create_socket(self):
        """Create a raw socket appropriate for the host OS."""
        try:
            if os.name == 'nt':  # Windows
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                self.socket.bind((socket.gethostbyname(socket.gethostname()), 0))
                self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            else:  # Linux / macOS
                self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            
            # Set socket timeout for graceful shutdown
            self.socket.settimeout(1.0)
            logging.info("Raw socket created successfully.")
            return True
        except PermissionError:
            print("❌ Permission denied. Please run as root or with administrator privileges.")
            logging.error("Permission denied: Must run as root/administrator.")
            return False
        except Exception as e:
            print(f"❌ Failed to create socket: {e}")
            logging.error(f"Failed to create socket: {e}")
            return False

    def capture_packets(self):
        """Main packet capture loop."""
        print("🎯 Starting packet capture... Press Ctrl+C to stop.")
        logging.info("Packet capture started.")
        
        while self.analyzer.running:
            try:
                data, _ = self.socket.recvfrom(65535)
                packet, scapy_pkt = self.analyzer.analyze_packet(data)
                
                if packet and scapy_pkt:
                    with self.analyzer.packet_lock:
                        self.analyzer.packets.append(packet)
                        self.analyzer.scapy_packets.append(scapy_pkt)
                        self.packet_count += 1
                        
                        # Memory management
                        current_mem = psutil.Process().memory_info().rss
                        if current_mem > self.memory_limit:
                            print("\n⚠️ Memory limit reached, trimming oldest packets.")
                            logging.warning(f"Memory limit {self.memory_limit} exceeded. Current: {current_mem}")
                            trim_count = len(self.analyzer.packets) // 2
                            self.analyzer.packets = self.analyzer.packets[trim_count:]
                            self.analyzer.scapy_packets = self.analyzer.scapy_packets[trim_count:]

                        if len(self.analyzer.packets) > self.max_packets:
                            self.analyzer.packets.pop(0)
                            self.analyzer.scapy_packets.pop(0)

                    self.display_packet(packet)

            except socket.timeout:
                continue # Allows checking self.analyzer.running flag
            except OSError: # Socket closed
                if self.analyzer.running:
                     logging.error("Socket error occurred.")
                break
            except KeyboardInterrupt:
                break
    
    def display_packet(self, packet: Packet):
        """Display packet information with colors."""
        color_map = {
            'HTTP': '\033[92m',   # Green
            'HTTPS': '\033[92m',  # Green
            'TCP': '\033[90m',    # Gray
            'UDP': '\033[93m',    # Yellow
            'DNS': '\033[95m',    # Magenta
            'ICMP': '\033[91m',   # Red
            'ARP': '\033[96m',    # Cyan
            'IP': '\033[94m',     # Blue
            'IPv6': '\033[94m'    # Blue
        }
        reset = '\033[0m'
        color = color_map.get(packet.protocol, '')
        
        port_info = f":{packet.source_port} → :{packet.dest_port}" if packet.source_port else ""
        
        print(f"{packet.timestamp} {color}[{packet.protocol:>5}]{reset} "
              f"{packet.source_ip}{port_info} → {packet.dest_ip} "
              f"({packet.size}B) {packet.info}")
        
        if self.verbose:
            print(f"    Data: {packet.data}")
            logging.info(f"Verbose packet data: {packet.data}")

    def start_capture(self, interface=None):
        """Start the packet capture thread."""
        if not self.create_socket():
            return
        
        self.analyzer.running = True
        self.capture_thread = threading.Thread(target=self.capture_packets, daemon=True)
        self.capture_thread.start()
        
        try:
            self.capture_thread.join()
        except KeyboardInterrupt:
            self.stop_capture()

    def stop_capture(self):
        """Stop packet capture gracefully."""
        print(f"\n🛑 Stopping capture... Captured {self.packet_count} packets.")
        logging.info(f"Capture stopped, {self.packet_count} packets captured.")
        self.analyzer.running = False
        if self.socket:
            if os.name == 'nt': # Windows specific cleanup
                self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            self.socket.close()
            logging.info("Socket closed.")
    
    def display_summary(self, chart=False):
        """Display a summary of captured packets."""
        if not self.analyzer.packets:
            print("No packets were captured.")
            logging.info("No packets captured for summary.")
            return
        
        with self.analyzer.packet_lock:
            protocol_counts = {}
            for packet in self.analyzer.packets:
                protocol_counts[packet.protocol] = protocol_counts.get(packet.protocol, 0) + 1
        
        print("\n📊 Capture Summary:")
        print(f"Total packets: {len(self.analyzer.packets)}")
        print("Protocol breakdown:")
        for protocol, count in sorted(protocol_counts.items(), key=lambda item: item[1], reverse=True):
            print(f"  - {protocol}: {count}")
        
        if chart:
            # Chart.js JSON output for rich display in compatible terminals
            chart_data = {
                'type': 'pie',
                'data': {
                    'labels': list(protocol_counts.keys()),
                    'datasets': [{'data': list(protocol_counts.values())}]
                },
                'options': {'title': {'display': True, 'text': 'Protocol Distribution'}}
            }
            print("\n```chartjs\n" + json.dumps(chart_data, indent=2) + "\n```")
            logging.info("Generated protocol distribution chart.")

    def export_json(self, filename: str):
        """Export captured packets to a JSON file."""
        if not self.analyzer.packets:
            print("No packets to export.")
            return
        try:
            with self.analyzer.packet_lock:
                with open(filename, 'w') as f:
                    json.dump([asdict(p) for p in self.analyzer.packets], f, indent=2)
            print(f"✅ Exported {len(self.analyzer.packets)} packets to {filename}")
            logging.info(f"Exported {len(self.analyzer.packets)} packets to {filename}")
        except Exception as e:
            print(f"❌ JSON export failed: {e}")
            logging.error(f"JSON export failed: {e}")
            
    def export_pcap(self, filename: str):
        """Export captured packets to a PCAP file."""
        if not self.analyzer.scapy_packets:
            print("No packets to export.")
            return
        try:
            with self.analyzer.packet_lock:
                wrpcap(filename, self.analyzer.scapy_packets)
            print(f"✅ Exported {len(self.analyzer.scapy_packets)} packets to {filename}")
            logging.info(f"Exported {len(self.analyzer.scapy_packets)} packets to {filename}")
        except Exception as e:
            print(f"❌ PCAP export failed: {e}")
            logging.error(f"PCAP export failed: {e}")

    def set_filter(self, protocol: Optional[str] = None, ip: Optional[str] = None, port: Optional[int] = None):
        """Set packet filters."""
        self.analyzer.filter_protocol = protocol
        self.analyzer.filter_ip = ip
        self.analyzer.filter_port = port
        
        filters = []
        if protocol: filters.append(f"protocol={protocol}")
        if ip: filters.append(f"ip={ip}")
        if port: filters.append(f"port={port}")
        
        if filters:
            print(f"🔍 Filters applied: {', '.join(filters)}")
            logging.info(f"Filters applied: {', '.join(filters)}")

def signal_handler(signum, frame):
    """Handle Ctrl+C to ensure a clean shutdown."""
    print("\n🛑 Ctrl+C detected. Shutting down gracefully...")
    # The main capture loop will handle the shutdown process.
    # We exit here to prevent the main thread from continuing after the capture stops.
    sys.exit(0)

def main():
    """Main entry point for the CLI application."""
    if os.name == 'posix' and os.geteuid() != 0:
        print("❌ This script needs root privileges to create a raw socket on Linux/macOS.")
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description='MiniShark - A lightweight, cross-platform network packet analyzer.',
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('-i', '--interface', help='Network interface to capture from (ignored on Windows).')
    parser.add_argument('-c', '--count', type=int, default=1000, help='Maximum packets to store in memory.')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show detailed hex data for each packet.')
    
    filter_group = parser.add_argument_group('Filtering Options')
    filter_group.add_argument('-fp', '--filter-protocol', help='Filter by protocol (e.g., tcp, udp, arp, icmp).')
    filter_group.add_argument('--filter-ip', help='Filter by a source or destination IP address.')
    filter_group.add_argument('--filter-port', type=int, help='Filter by a source or destination port.')

    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument('-o', '--output', help='Export captured packets to a JSON file.')
    output_group.add_argument('--pcap', help='Export captured packets to a PCAP file.')
    output_group.add_argument('-s', '--summary', action='store_true', help='Show a summary after capture.')
    output_group.add_argument('--chart', action='store_true', help='Generate a protocol distribution chart with summary.')

    args = parser.parse_args()
    
    # Register the signal handler for a clean exit
    signal.signal(signal.SIGINT, signal_handler)
    
    minishark = MiniShark()
    minishark.max_packets = args.count
    minishark.verbose = args.verbose
    
    minishark.set_filter(args.filter_protocol, args.filter_ip, args.filter_port)
    
    print("🦈 MiniShark CLI - Network Packet Analyzer 🦈")
    print("=" * 50)
    logging.info(f"Starting MiniShark with args: {args}")
    
    try:
        minishark.start_capture(args.interface)
    except Exception as e:
        # Catch any final exceptions during startup/shutdown
        logging.critical(f"A critical error occurred: {e}")
    finally:
        # This block will run after the capture loop finishes, even with Ctrl+C
        minishark.stop_capture()
        if args.summary or args.chart:
            minishark.display_summary(args.chart)
        
        if args.output:
            minishark.export_json(args.output)
        
        if args.pcap:
            minishark.export_pcap(args.pcap)
        
        print("\n👋 MiniShark has finished.")

if __name__ == "__main__":
    main()