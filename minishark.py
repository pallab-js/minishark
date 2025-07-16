#!/usr/bin/env python3
"""
MiniShark CLI - Lightweight Network Packet Analyzer
A minimalist command-line packet capture and analysis tool
"""

import socket
import struct
import sys
import time
import argparse
import json
import logging
import os
import psutil
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import List, Optional
import threading
import signal

@dataclass
class Packet:
    """Represents a captured network packet"""
    timestamp: str
    protocol: str
    source_ip: str
    dest_ip: str
    source_port: Optional[int]
    dest_port: Optional[int]
    size: int
    data: str
    info: str

class PacketAnalyzer:
    """Core packet analysis functionality"""
    
    def __init__(self, data_bytes=60):
        self.packets: List[Packet] = []
        self.packet_lock = threading.Lock()
        self.running = False
        self.filter_protocol = None
        self.filter_ip = None
        self.data_bytes = data_bytes
        
    def parse_ethernet_header(self, data):
        """Parse Ethernet header"""
        eth_header = struct.unpack('!6s6sH', data[:14])
        eth_protocol = socket.ntohs(eth_header[2])
        return eth_protocol, data[14:]
    
    def parse_ip_header(self, data):
        """Parse IPv4 header"""
        ip_header = struct.unpack('!BBHHHBBH4s4s', data[:20])
        version_ihl = ip_header[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        protocol = ip_header[6]
        source_addr = socket.inet_ntoa(ip_header[8])
        dest_addr = socket.inet_ntoa(ip_header[9])
        return {
            'version': version,
            'ihl': ihl,
            'protocol': protocol,
            'source': source_addr,
            'destination': dest_addr,
            'header_length': ihl * 4
        }
    
    def parse_ipv6_header(self, data):
        """Parse IPv6 header"""
        ip_header = struct.unpack('!IHBB16s16s', data[:40])
        version = ip_header[0] >> 28
        protocol = ip_header[2]
        source_addr = socket.inet_ntop(socket.AF_INET6, ip_header[3])
        dest_addr = socket.inet_ntop(socket.AF_INET6, ip_header[4])
        return {
            'version': version,
            'protocol': protocol,
            'source': source_addr,
            'destination': dest_addr,
            'header_length': 40
        }
    
    def parse_tcp_header(self, data):
        """Parse TCP header"""
        tcp_header = struct.unpack('!HHLLBBHHH', data[:20])
        source_port = tcp_header[0]
        dest_port = tcp_header[1]
        flags = tcp_header[5]
        flag_names = []
        if flags & 0x01: flag_names.append('FIN')
        if flags & 0x02: flag_names.append('SYN')
        if flags & 0x04: flag_names.append('RST')
        if flags & 0x08: flag_names.append('PSH')
        if flags & 0x10: flag_names.append('ACK')
        if flags & 0x20: flag_names.append('URG')
        return {
            'source_port': source_port,
            'dest_port': dest_port,
            'flags': flag_names
        }
    
    def parse_udp_header(self, data):
        """Parse UDP header"""
        udp_header = struct.unpack('!HHHH', data[:8])
        return {
            'source_port': udp_header[0],
            'dest_port': udp_header[1],
            'length': udp_header[2]
        }
    
    def parse_icmp_header(self, data):
        """Parse ICMP header"""
        icmp_header = struct.unpack('!BBH', data[:4])
        return {
            'type': icmp_header[0],
            'code': icmp_header[1]
        }
    
    def analyze_packet(self, data, size):
        """Analyze a raw packet and extract information"""
        try:
            timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
            eth_protocol, ip_data = self.parse_ethernet_header(data)
            
            source_port = None
            dest_port = None
            info = ""
            protocol_name = "IP"
            ip_info = None
            
            if eth_protocol == 8:  # IPv4
                ip_info = self.parse_ip_header(ip_data)
            elif eth_protocol == 0x86DD:  # IPv6
                ip_info = self.parse_ipv6_header(ip_data)
                protocol_name = "IPv6"
            else:
                return None
                
            protocol_data = ip_data[ip_info['header_length']:]
            
            if ip_info['protocol'] == 6:  # TCP
                protocol_name = "TCP"
                tcp_info = self.parse_tcp_header(protocol_data)
                source_port = tcp_info['source_port']
                dest_port = tcp_info['dest_port']
                flags = ','.join(tcp_info['flags'])
                info = f"[{flags}] {source_port} → {dest_port}"
                if dest_port == 80 or source_port == 80:
                    protocol_name = "HTTP"
                elif dest_port == 443 or source_port == 443:
                    protocol_name = "HTTPS"
                    
            elif ip_info['protocol'] == 17:  # UDP
                protocol_name = "UDP"
                udp_info = self.parse_udp_header(protocol_data)
                source_port = udp_info['source_port']
                dest_port = udp_info['dest_port']
                info = f"{source_port} → {dest_port} Len={udp_info['length']}"
                if dest_port == 53 or source_port == 53:
                    protocol_name = "DNS"
                    info = f"DNS query/response {source_port} → {dest_port}"
                    
            elif ip_info['protocol'] == 1:  # ICMP
                protocol_name = "ICMP"
                icmp_info = self.parse_icmp_header(protocol_data)
                icmp_types = {0: "Echo Reply", 8: "Echo Request", 3: "Dest Unreachable"}
                icmp_type_name = icmp_types.get(icmp_info['type'], f"Type {icmp_info['type']}")
                info = f"{icmp_type_name} (type={icmp_info['type']}, code={icmp_info['code']})"
                
            packet = Packet(
                timestamp=timestamp,
                protocol=protocol_name,
                source_ip=ip_info['source'],
                dest_ip=ip_info['destination'],
                source_port=source_port,
                dest_port=dest_port,
                size=size,
                data=data[:self.data_bytes].hex(),
                info=info
            )
            
            if self.filter_protocol and protocol_name.lower() != self.filter_protocol.lower():
                return None
            if self.filter_ip and (self.filter_ip not in ip_info['source'] and self.filter_ip not in ip_info['destination']):
                return None
                
            return packet
                
        except Exception as e:
            return Packet(
                timestamp=timestamp,
                protocol="UNKNOWN",
                source_ip="",
                dest_ip="",
                source_port=None,
                dest_port=None,
                size=size,
                data=data[:self.data_bytes].hex(),
                info=f"Parse error: {str(e)}"
            )

class MiniShark:
    """Main MiniShark CLI application"""
    
    def __init__(self, data_bytes=60, memory_limit=500*1024*1024):
        self.analyzer = PacketAnalyzer(data_bytes)
        self.socket = None
        self.capture_thread = None
        self.packet_count = 0
        self.max_packets = 1000
        self.memory_limit = memory_limit
        self.verbose = False
        logging.basicConfig(filename='minishark.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    def create_socket(self):
        """Create raw socket for packet capture"""
        try:
            self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            logging.info("Raw socket created successfully")
            return True
        except PermissionError:
            print("❌ Permission denied. Run as root/administrator.")
            logging.error("Permission denied: Must run as root/administrator")
            return False
        except Exception as e:
            print(f"❌ Failed to create socket: {e}")
            logging.error(f"Failed to create socket: {e}")
            return False
    
    def capture_packets(self):
        """Main packet capture loop"""
        print("🎯 Starting packet capture... Press Ctrl+C to stop")
        logging.info("Packet capture started")
        display_counter = 0
        display_interval = 10  # Display every 10th packet to prevent console overload
        
        while self.analyzer.running:
            try:
                data, addr = self.socket.recvfrom(65565)
                packet = self.analyzer.analyze_packet(data, len(data))
                
                if packet:
                    with self.analyzer.packet_lock:
                        self.analyzer.packets.append(packet)
                        self.packet_count += 1
                        
                        # Memory management
                        if psutil.Process().memory_info().rss > self.memory_limit:
                            print("⚠️ Memory limit reached, trimming packet list.")
                            logging.warning("Memory limit reached, trimming packet list")
                            self.analyzer.packets = self.analyzer.packets[-self.max_packets//2:]
                        
                        if len(self.analyzer.packets) > self.max_packets:
                            self.analyzer.packets.pop(0)
                    
                    # Rate-limited display
                    display_counter += 1
                    if display_counter % display_interval == 0:
                        self.display_packet(packet)
                        
            except (socket.timeout, OSError) as e:
                if self.analyzer.running:
                    print(f"❌ Socket error: {e}")
                    logging.error(f"Socket error: {e}")
                break
            except KeyboardInterrupt:
                break
    
    def display_packet(self, packet):
        """Display packet information in a formatted way"""
        color_map = {
            'HTTP': '\033[94m',    # Blue
            'HTTPS': '\033[92m',   # Green
            'TCP': '\033[90m',     # Gray
            'UDP': '\033[93m',     # Yellow
            'DNS': '\033[95m',     # Magenta
            'ICMP': '\033[91m',    # Red
            'IP': '\033[96m',      # Cyan
            'IPv6': '\033[96m'     # Cyan
        }
        reset = '\033[0m'
        color = color_map.get(packet.protocol, reset)
        
        port_info = ""
        if packet.source_port and packet.dest_port:
            port_info = f":{packet.source_port} → :{packet.dest_port}"
        
        print(f"{packet.timestamp} {color}[{packet.protocol:>5}]{reset} "
              f"{packet.source_ip}{port_info} → {packet.dest_ip} "
              f"({packet.size}B) {packet.info}")
        
        if self.verbose:
            print(f"    Data: {packet.data}")
            logging.info(f"Verbose packet data: {packet.data}")
    
    def start_capture(self, interface=None):
        """Start packet capture"""
        if interface and interface not in [i[1] for i in socket.if_nameindex()]:
            print(f"❌ Invalid interface: {interface}")
            logging.error(f"Invalid interface: {interface}")
            return
        
        if not self.create_socket():
            return
        
        self.analyzer.running = True
        self.capture_thread = threading.Thread(target=self.capture_packets)
        self.capture_thread.daemon = True
        self.capture_thread.start()
        
        try:
            self.capture_thread.join()
        except KeyboardInterrupt:
            self.stop_capture()
        finally:
            if self.socket:
                self.socket.close()
                logging.info("Socket closed")
    
    def stop_capture(self):
        """Stop packet capture"""
        print(f"\n🛑 Stopping capture... Captured {self.packet_count} packets")
        logging.info(f"Capture stopped, {self.packet_count} packets captured")
        self.analyzer.running = False
        if self.socket:
            self.socket.close()
            logging.info("Socket closed on stop")
    
    def display_summary(self, chart=False):
        """Display capture summary"""
        if not self.analyzer.packets:
            print("No packets captured.")
            logging.info("No packets captured for summary")
            return
        
        protocol_counts = {}
        with self.analyzer.packet_lock:
            for packet in self.analyzer.packets:
                protocol_counts[packet.protocol] = protocol_counts.get(packet.protocol, 0) + 1
        
        print(f"\n📊 Capture Summary:")
        print(f"Total packets: {len(self.analyzer.packets)}")
        print(f"Protocol breakdown:")
        for protocol, count in sorted(protocol_counts.items()):
            print(f"  {protocol}: {count}")
            logging.info(f"Protocol {protocol}: {count} packets")
        
        if chart:
            chart_data = {
                'type': 'pie',
                'data': {
                    'labels': list(protocol_counts.keys()),
                    'datasets': [{
                        'data': list(protocol_counts.values()),
                        'backgroundColor': ['#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF', '#FF9F40']
                    }]
                },
                'options': {'title': {'display': True, 'text': 'Protocol Distribution'}}
            }
            print("```chartjs\n" + json.dumps(chart_data) + "\n```")
            logging.info("Generated protocol distribution chart")
    
    def export_packets(self, filename):
        """Export captured packets to JSON file"""
        if not self.analyzer.packets:
            print("No packets to export.")
            logging.info("No packets to export")
            return
        
        try:
            with self.analyzer.packet_lock:
                with open(filename, 'w') as f:
                    json.dump([asdict(p) for p in self.analyzer.packets], f, indent=2)
            print(f"✅ Exported {len(self.analyzer.packets)} packets to {filename}")
            logging.info(f"Exported {len(self.analyzer.packets)} packets to {filename}")
        except Exception as e:
            print(f"❌ Export failed: {e}")
            logging.error(f"Export failed: {e}")
    
    def set_filter(self, protocol=None, ip=None):
        """Set packet filters"""
        valid_protocols = {'tcp', 'udp', 'icmp', 'http', 'https', 'dns', 'ipv6'}
        if protocol and protocol.lower() not in valid_protocols:
            print(f"❌ Invalid protocol. Supported: {', '.join(valid_protocols)}")
            logging.error(f"Invalid protocol filter: {protocol}")
            sys.exit(1)
        
        self.analyzer.filter_protocol = protocol
        self.analyzer.filter_ip = ip
        
        filters = []
        if protocol:
            filters.append(f"protocol={protocol}")
        if ip:
            filters.append(f"ip={ip}")
        
        if filters:
            print(f"🔍 Filters applied: {', '.join(filters)}")
            logging.info(f"Filters applied: {', '.join(filters)}")

def signal_handler(signum, frame):
    """Handle Ctrl+C gracefully"""
    print("\n🛑 Shutting down...")
    logging.info("Shutting down via signal handler")
    sys.exit(0)

def main():
    """Main entry point"""
    if os.name == 'posix' and os.geteuid() != 0:
        print("❌ Must run as root/administrator.")
        logging.error("Root privileges required")
        sys.exit(1)
    
    parser = argparse.ArgumentParser(description='MiniShark - Lightweight Network Packet Analyzer')
    parser.add_argument('-i', '--interface', help='Network interface to capture from')
    parser.add_argument('-c', '--count', type=int, default=1000, help='Maximum packets to capture')
    parser.add_argument('-f', '--filter-protocol', help='Filter by protocol (tcp, udp, icmp, etc.)')
    parser.add_argument('--filter-ip', help='Filter by IP address')
    parser.add_argument('-o', '--output', help='Export captured packets to file')
    parser.add_argument('-s', '--summary', action='store_true', help='Show summary after capture')
    parser.add_argument('--chart', action='store_true', help='Generate protocol distribution chart')
    parser.add_argument('--data-bytes', type=int, default=60, help='Bytes of packet data to capture')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show detailed packet information')
    
    args = parser.parse_args()
    
    signal.signal(signal.SIGINT, signal_handler)
    
    minishark = MiniShark(data_bytes=args.data_bytes)
    minishark.max_packets = args.count
    minishark.verbose = args.verbose
    
    if args.filter_protocol or args.filter_ip:
        minishark.set_filter(args.filter_protocol, args.filter_ip)
    
    print("🦈 MiniShark CLI - Lightweight Network Packet Analyzer")
    print("=" * 60)
    logging.info(f"Starting MiniShark with args: {args}")
    
    try:
        minishark.start_capture(args.interface)
    except KeyboardInterrupt:
        minishark.stop_capture()
    
    if args.summary:
        minishark.display_summary(args.chart)
    
    if args.output:
        minishark.export_packets(args.output)

if __name__ == "__main__":
    main()