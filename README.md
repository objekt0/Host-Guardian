# Host-Guardian
A self healing, host based network protection agent designed to prevent ARP spoofing and Layer 2 MITM attacks.

## 🔍 Overview
Host Guardian:is a dedicated ANTI-ARP attacks protection program written in Python that use libraries like Sscapy and OS libraries to control kernel use to prevent sniffer attacks. It runs on both Windows and Linux platforms. automatically discovers the default gateway, enforces kernel-level static ARP locking, detects spoofing attempts, and safely recovers from network instability.

This project was developed as a learning and research exercise to deeply understand ARP behavior, MITM attacks, and practical defensive mechanisms.

Remember, "it's just for learning," so if there is any problem with the code, please let me know.
ا
## 🛡️ Key Features
- Automatic gateway discovery (IP & MAC)
- Static ARP enforcement (Linux & Windows)
- Spoofing detection (ARP replies monitoring)
- Self-healing safe rollback mechanism
- Periodic hardening & refresh
- Cross-platform support

## 📋 Requirements
-Python 3.x**
-Administrator / Root Privileges** (Required for ARP table modification)
-python Scapy library

## ⚙️ How It Works
1. Discovers the default gateway using OS routing tables
2. Resolves the gateway MAC via ARP
3. Applies kernel-level static ARP locking
4. Monitors ARP traffic for spoofing attempts
5. Automatically unlocks and recovers if connectivity is lost

## 🧪 Intended Use Cases
- Learning & research
- SOC / Blue Team environments
- Protecting sensitive hosts (Jump Boxes, forensic workstations)
- Demonstrating host-based network defense concepts
-of course you can use it as you like but this is sum idea and cases of use

## ⚠️ Limitations
- Designed for IPv4 networks only
- Does not protect against attacks beyond Layer 2
- Requires administrator/root privileges

## 📌 Project Status
This project is considered **feature-complete** and is no longer under active development.

## 🧠 Lessons Learned
- Practical ARP attack techniques and defenses
- Host-based enforcement vs network-based security
- Reliability considerations in defensive tooling

## 📄 License
MIT

