MiniShark

MiniShark is a lightweight command-line network packet analyzer written in Python. It captures and analyzes network packets in real-time, supporting protocols like TCP, UDP, ICMP, HTTP, HTTPS, DNS, and IPv6. Features include protocol filtering, IP filtering, JSON export, and a visual protocol distribution chart.

Features

Real-time packet capture with color-coded console output
Support for IPv4 and IPv6 packet parsing
Protocol and IP-based filtering
Export captured packets to JSON
Summary statistics with optional Chart.js visualization
Verbose mode for detailed packet data
Memory management to prevent excessive resource usage
Logging to minishark.log for debugging

Prerequisites

Python 3.6+
Root/administrator privileges (required for raw socket access)
Dependencies: psutil (install via pip install psutil)

Installation

Clone the repository:
git clone https://github.com/pallab-js/minishark.git
cd minishark


Install dependencies:
pip install -r requirements.txt


Run as root (e.g., using sudo on Linux):
sudo python minishark.py



Usage
python minishark.py [options]

Options

-i, --interface: Specify network interface (e.g., eth0)
-c, --count: Maximum packets to capture (default: 1000)
-f, --filter-protocol: Filter by protocol (tcp, udp, icmp, http, https, dns, ipv6)
--filter-ip: Filter by IP address
-o, --output: Export packets to a JSON file
-s, --summary: Show capture summary
--chart: Generate protocol distribution chart
--data-bytes: Bytes of packet data to capture (default: 60)
-v, --verbose: Show detailed packet information

Example
Capture 100 TCP packets and export to packets.json:
sudo python minishark.py -c 100 -f tcp -o packets.json

Testing
Run unit tests to verify functionality:
python -m unittest test_minishark.py

Tests cover packet parsing, filtering, and export functionality. Note: Some tests mock socket operations as raw socket access requires root privileges.
Development

Contributing: Fork the repo, create a feature branch, and submit a pull request.
Issues: Report bugs or suggest features via GitHub Issues.
License: MIT License (see LICENSE file).

Building the Project

Ensure dependencies are installed (pip install -r requirements.txt).
Run tests (python -m unittest test_minishark.py).
Execute minishark.py with desired options.

Contact

GitHub: pallab-js
Email: sonowalpallabjyoti@gmail.com


MiniShark is a personal project for learning network analysis. Contributions are welcome!