# 🦈 MiniShark - Lightweight Network Packet Analyzer

![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

MiniShark is a lightweight, cross-platform, command-line network packet analyzer. It provides real-time packet capture and analysis with a user-friendly interface, making it an ideal tool for network debugging, analysis, or educational purposes.

---

## Features

-   **Cross-Platform**: Works on both Linux and Windows.
-   **Robust Parsing**: Uses the powerful `scapy` library to reliably dissect a wide range of protocols.
-   **Multiple Output Formats**: Export captures to standard **JSON** for data analysis or **PCAP** for viewing in tools like Wireshark.
-   **Powerful Filtering**: Filter traffic by protocol (TCP, UDP, ICMP, ARP), IP address, or port number.
-   **Real-time Display**: View packets as they are captured, with color-coded protocols for easy identification.
-   **Memory Safe**: Includes a configurable memory limit to prevent excessive resource consumption during long captures.

---

## Prerequisites

Before you begin, ensure you have Python 3.7+ installed. You will also need to install the following Python libraries:

```bash
pip install scapy psutil