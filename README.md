# Network Packet Analyzer 🛡️
### Real Network Traffic Capture Tool — C++ OOP Project

**Developer:** Abdul Manan Abbasi  
**Language:** C++  
**IDE:** Visual Studio 2022  

---

## 📌 About This Project
A real-time network packet analyzer built in C++ using 
Object-Oriented Programming principles. Captures live 
network traffic using the Npcap library — similar to 
how Wireshark works.

---

## ⚙️ OOP Concepts Used
| Concept | Implementation |
|---|---|
| Abstraction | `Packet` abstract base class |
| Inheritance | `TCPPacket` and `UDPPacket` inherit from `Packet` |
| Polymorphism | `display()` and `isValid()` virtual functions |
| Encapsulation | Protected data with public getters |
| Composition | `RealCapture` contains Filter and Logger |

---

## 📁 Project Files
| File | Purpose |
|---|---|
| `Packet.h` | Abstract base class |
| `TCPPacket.h` | TCP packet implementation |
| `UDPPacket.h` | UDP packet implementation |
| `PacketFilter.h` | Filter by IP or Port |
| `PacketLogger.h` | Save packets to log.txt |
| `RealCapture.h` | Live capture using Npcap |
| `NetworkPacketAnalyzer.cpp` | Main entry point |

---

## 🚀 Features
- ✅ Real network traffic capture (TCP & UDP)
- ✅ Packet header validation
- ✅ Filter by IP address or port number
- ✅ Save captured packets to log file
- ✅ Live packet statistics

---

## 🔧 Requirements
- Windows 10/11 (64-bit)
- Visual Studio 2022
- [Npcap 1.88](https://npcap.com/#download)
- Npcap SDK 1.16
- Run Visual Studio as **Administrator**

---

## 📊 How It Works
1. Program lists all network interfaces
2. User selects Wi-Fi or Ethernet
3. Packets are captured in real-time
4. Raw bytes are parsed into TCP/UDP objects
5. User can filter, view stats, and save to file