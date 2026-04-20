# Data Network Protocol Simulation (DNS + FTP)

## Overview

This project simulates core network protocols using OMNeT++. It includes DNS resolution, FTP file transfer, and an integrated scenario where DNS is used to trigger FTP operations.

---


## Features

### DNS Simulation
- UDP-based DNS queries
- XML-based domain database
- TTL caching mechanism
- Error handling for non-existent domains
- Hierarchical DNS (client → local → root)

### FTP Simulation
- TCP-based FTP (Active Mode)
- RETR (file download)
- STOR (file upload)
- Dual-channel architecture (control + data connection)

### Integration
- DNS resolves hostname
- FTP uses resolved IP automatically
- End-to-end file transfer simulation

---

## Tools Used
- OMNeT++
- INET Framework
- Wireshark
- TCP / UDP / ARP protocols

---

## Results

- Successful DNS resolution with caching
- Working FTP upload and download
- Verified packet-level behavior
- Full DNS-to-FTP integration

---

## License

Academic project – Sharif University of Technology
