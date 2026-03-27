# Network Internals in C - Learning Low-Level Networking

## Overview

This project is a hands-on learning journey into low-level network programming with C. The goal is to understand how networks operate at their core by directly interacting with hardware network interfaces, packets, and protocol stacks. Through implementing networking fundamentals from the ground up, this project develops a deep understanding of the mechanisms that make modern networks function.

This study focuses on the Data Link Layer (OSI Layer 2) and Network Layer (OSI Layer 3), building a foundation for creating custom network applications and, ultimately, a functional router implementation.


## Learning Goals

1. Understand Network Fundamentals - Learn how data frames move across physical network media and how they are processed at each layer of the network stack.

2. Master Low-Level Routines - Develop proficiency with kernel-level networking APIs, packet structures, and hardware interface programming using C.

3. Work with Real Network Hardware - Interact directly with network devices, capture live traffic, and manipulate network packets at the byte level.

4. Build Protocol Understanding - Implement basic protocol handlers (Ethernet, IP, ARP, ICMP) to understand how protocols work in practice.

5. Create a Custom Router - Apply learned concepts to design and implement a functional router application that can forward packets between network interfaces.


## Prerequisites

This project is developed and tested for Linux environments. To build and run the programs, you must have the following installed:

1. GNU Compiler Collection (GCC) or Clang
2. Linux kernel development headers (for socket definitions)
3. libpcap development library

### Installation

```bash
sudo apt-get update
sudo apt-get install build-essential libpcap-dev
```

## Building the Project

To compile the project, use the following command:

```bash
gcc main.c -o main -lpcap
```

## Execution

Since the programs access hardware network interfaces directly, they require administrative privileges to run:

```bash
sudo ./main
```

<!-- This will enumerate all available network interfaces on your system and display them. -->

<!-- ## Project Structure

main.c - Initial program that discovers and lists all network devices available on the system. -->

<!-- ## Development Roadmap

### Phase 1: Network Discovery (Current)
- Interface enumeration and device discovery
- Understanding network interface structures
- Basic hardware device listing

### Phase 2: Packet Capture and Analysis
- Implement a packet sniffer using libpcap
- Capture and display Ethernet frame headers
- Parse and display IP packet information
- Understand packet flow through interfaces

### Phase 3: Protocol Implementation
- Implement ARP (Address Resolution Protocol) handling
- Respond to ARP requests appropriately
- Understand MAC address resolution
- Implement basic ICMP echo (ping) functionality

### Phase 4: Traffic Filtering and Routing
- Filter incoming traffic based on source/destination IP addresses
- Implement basic routing table lookup
- Forward packets between network interfaces
- Handle IP fragmentation and reassembly

### Phase 5: Custom Router Application
- Combine all learned concepts into a functional router
- Implement multiple routing rules and policies
- Support static routing tables
- Integrate with Linux network stack

### Phase 6: Embedded Systems Port
- Port routing logic to the ESP32 microcontroller
- Work with LwIP (Lightweight IP) stack
- Optimize for resource-constrained environments
- Create wireless mesh network capabilities

## Key Concepts to Learn

OSI Model - Understanding how the seven-layer model applies to real network implementations.

Network Interfaces - How the kernel abstracts hardware network adapters and manages multiple interfaces.

Packet Structures - Understanding Ethernet frames, IP headers, and protocol encapsulation.

Socket Programming - Using raw sockets and packet sockets for low-level network access.

Kernel Networking - How to interact directly with the kernel to send and receive packets. -->


## Author

Eduardo

<!-- ## Last Updated

March 2026 -->