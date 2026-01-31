# PCAP Network Traffic Analyzer

A Python-based cybersecurity tool for analyzing network packet captures, 
detecting security threats, and investigating suspicious network activity.

## Overview

Built as part of Cyber Security coursework, this tool analyzes PCAP 
(Packet Capture) files to extract network traffic metadata, identify 
suspicious domains, detect malicious IP addresses, and investigate 
potential security incidents. The analyzer provides forensic capabilities 
for post-incident investigation.

## Features

### Core Analysis
- **Global Header Inspection**: Extract PCAP metadata (magic number, 
  version, snap length, link type)
- **DHCP Frame Analysis**: Parse DHCP packets for IP/MAC addresses, 
  hostnames, timestamps
- **Domain Detection**: Identify suspicious domains (`.top` TLDs)
- **Search Engine Forensics**: Discover search queries and keywords
- **Intrusion Detection**: Flag known malicious IP addresses

### Security Features
- **Malicious IP Detection**: Cross-reference against threat intelligence
- **Domain Reputation Check**: Identify high-risk TLDs
- **Network Forensics**: Timeline reconstruction of network activity
- **Threat Hunting**: Pattern matching for suspicious behavior

### Quality of Life
- Menu-driven CLI interface
- Comprehensive error handling
- Human-readable timestamp conversion
- Formatted MAC/IP address display
- Clear security alerts

## Tech Stack

- **Language**: Python 3.x
- **Core Libraries**: 
  - `struct` - Binary data parsing
  - `re` - Pattern matching (suspicious domains)
  - `time` - Timestamp conversion
- **File Format**: PCAP (Packet Capture)
- **Analysis Focus**: Network forensics, threat detection
## Future Enhancements
- [ ] Real-time packet capture (using Scapy)
- [ ] Automated report generation (PDF/HTML)
- [ ] Machine learning for anomaly detection
