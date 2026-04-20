```markdown
# Data Network Protocol Simulation (DNS + FTP)

## Overview

This project implements and analyzes core application-layer network protocols using the OMNeT++ simulation framework. It focuses on realistic behavior, packet-level inspection, and full-stack interaction of:

- **DNS (Domain Name System)**
- **FTP (File Transfer Protocol: RETR & STOR)**
- **Integrated DNS → FTP workflow (end-to-end simulation)**

The system includes caching, hierarchical resolution, TCP dual-channel communication, and full validation using Wireshark and OMNeT++ logs.

---

## Author

- **Iman Alizadeh Fakouri**
- Student Number: 401102134  
- Course: Data Network  
- Instructor: Dr. Pakravan  
- Date: February 26, 2026  

---

## Project Structure

```

.
├── dns/
│   ├── basic_resolution/
│   ├── caching/
│   ├── hierarchical_dns/
│   └── xml_database/
│
├── ftp/
│   ├── retr_download/
│   ├── stor_upload/
│   └── tcp_dual_channel/
│
├── integration/
│   ├── dns_to_ftp_handoff/
│   ├── ethernet_topology/
│   └── bonus_dns_xml/
│
├── results/
│   ├── wireshark/
│   ├── omnetpp_logs/
│   └── figures/
│
└── README.md

```

---

## 1. DNS Protocol Simulation

### Features

- Custom DNS client-server implementation (OMNeT++)
- UDP-based resolution (Port 53)
- XML-based DNS database
- TTL-based caching system
- ARP-based address resolution
- Error handling for invalid domains (NXDOMAIN)

---

### Key Scenarios

#### Basic DNS Resolution
- Client sends DNS query
- Server responds with IP + TTL (e.g., 5 seconds)
- Client caches result and automatically refreshes after expiration

#### Cache Expiration
- Cached entry expires after TTL
- Client re-queries server automatically

#### Non-Existent Domain
- Server returns error response (NXDOMAIN)
- Client aborts caching and stops retries

#### Hierarchical DNS
- Client → Local DNS → Root DNS
- Demonstrates caching efficiency:
  - First query: ~23 ms
  - Cached query: ~5 ms

---

## 2. FTP Protocol Simulation

### Architecture

FTP is implemented using a **dual-socket TCP model**:

- Control Channel: Port 21 (persistent)
- Data Channel: dynamic (Active Mode)

---

## 2.1 RETR (File Download)

### Flow

1. TCP handshake on control channel
2. USER authentication
3. PORT command (client listens on port 2020)
4. Server initiates data connection to client
5. File transfer over data channel
6. Server sends `226 Transfer complete`

### Key Idea

- Server actively opens data connection (Active Mode FTP)
- Verified using TCP packet traces

---

## 2.2 STOR (File Upload)

### Flow

1. Control connection established
2. Client sends STOR command
3. Server connects to client’s listening port (2020)
4. Client uploads file over data channel
5. Server acknowledges with `226`

### Validation

- File integrity verified (bit-exact match)
- Clean TCP connection teardown confirmed

---

## 3. Bonus: DNS + FTP Integration

### Goal

Simulate a real-world scenario:

> DNS resolves hostname → FTP uses resolved IP to transfer file

---

### Key Improvement

Unlike previous parts, this system:

- Removes static address resolution
- Implements real DNS-based service discovery
- Connects DNS output directly to FTP input

---

### Execution Flow

1. Client sends ARP request to discover DNS server
2. DNS query sent via UDP
3. DNS resolves:
```

fileserver.example.com → 10.0.0.3

```
4. DNS module triggers FTP module
5. FTP client automatically starts STOR process
6. File upload completes successfully

---

## Results

- Fully functional DNS resolution system
- Complete FTP Active Mode simulation
- Verified TCP/UDP/ARP behavior
- End-to-end protocol integration
- Real packet-level validation (Wireshark + OMNeT++)

---

## Technologies Used

- OMNeT++
- INET Framework
- TCP / UDP / ARP protocols
- Wireshark
- XML-based DNS database

---

## Key Learning Outcomes

- DNS architecture and caching behavior
- TCP handshake and state machine
- FTP Active Mode dual-channel design
- Network protocol integration techniques
- Packet-level debugging and analysis

---

## License

Academic project – Sharif University of Technology
```

---
