#pragma once

// Npcap headers
#define HAVE_REMOTE
#include <pcap.h>

#include "TCPPacket.h"
#include "UDPPacket.h"
#include "PacketFilter.h"
#include "PacketLogger.h"
#include <vector>
#include <string>

// ── Ethernet + IP + TCP/UDP Header Structures ──
// Ye structs raw bytes ko readable format mein convert karte hain

#pragma pack(push, 1)  // No padding between fields

struct EthernetHeader {
    unsigned char  dest[6];    // Destination MAC
    unsigned char  src[6];     // Source MAC
    unsigned short type;       // Protocol type
};

struct IPHeader {
    unsigned char  verLen;     // Version + Header Length
    unsigned char  tos;        // Type of Service
    unsigned short totalLen;   // Total packet length
    unsigned short id;
    unsigned short flags;
    unsigned char  ttl;        // Time to live
    unsigned char  protocol;   // 6 = TCP, 17 = UDP
    unsigned short checksum;
    unsigned int   srcIP;      // Source IP (raw number)
    unsigned int   destIP;     // Dest IP (raw number)
};

struct TCPHeader {
    unsigned short srcPort;
    unsigned short destPort;
    unsigned int   seqNum;
    unsigned int   ackNum;
    unsigned char  dataOffset;
    unsigned char  flags;      // SYN=0x02, ACK=0x10, FIN=0x01
    unsigned short window;
    unsigned short checksum;
    unsigned short urgent;
};

struct UDPHeader {
    unsigned short srcPort;
    unsigned short destPort;
    unsigned short length;
    unsigned short checksum;
};

#pragma pack(pop)

// ── Helper: Raw IP number → "192.168.1.1" string ──
string ipToString(unsigned int ip) {
    unsigned char* bytes = (unsigned char*)&ip;
    return to_string(bytes[0]) + "." +
        to_string(bytes[1]) + "." +
        to_string(bytes[2]) + "." +
        to_string(bytes[3]);
}

// ── Helper: Raw bytes → readable hex string (for data preview) ──
string bytesToString(const unsigned char* data, int len) {
    string result = "";
    int show = min(len, 20);  // Only show first 20 bytes
    for (int i = 0; i < show; i++) {
        if (data[i] >= 32 && data[i] < 127)
            result += (char)data[i];  // Printable character
        else
            result += '.';            // Non-printable → dot
    }
    if (len > 20) result += "...";
    return result;
}

// ── Main Capture Class ──
class RealCapture {
private:
    pcap_t* handle;       // Npcap device handle
    PacketFilter    filter;
    PacketLogger    logger;
    vector<Packet*> captured;
    int             captureCount;

public:
    RealCapture() : handle(nullptr), captureCount(0) {}

    ~RealCapture() {
        if (handle) pcap_close(handle);
        for (int i = 0; i < captured.size(); i++)
            delete captured[i];
    }

    // ── Step 1: Show all available network interfaces ──
    bool listDevices() {
        pcap_if_t* allDevs;
        char errBuf[PCAP_ERRBUF_SIZE];

        if (pcap_findalldevs(&allDevs, errBuf) == -1) {
            cout << "Error finding devices: " << errBuf << "\n";
            return false;
        }

        cout << "\n=== Available Network Interfaces ===\n";
        int i = 1;
        for (pcap_if_t* d = allDevs; d != nullptr; d = d->next) {
            cout << i++ << ". " << d->name;
            if (d->description)
                cout << " (" << d->description << ")";
            cout << "\n";
        }

        pcap_freealldevs(allDevs);
        return true;
    }

    // ── Step 2: Open a specific network interface ──
    bool openDevice(int deviceNumber) {
        pcap_if_t* allDevs;
        char errBuf[PCAP_ERRBUF_SIZE];

        if (pcap_findalldevs(&allDevs, errBuf) == -1) {
            cout << "Error: " << errBuf << "\n";
            return false;
        }

        // Navigate to the selected device
        pcap_if_t* selected = allDevs;
        for (int i = 1; i < deviceNumber && selected != nullptr; i++)
            selected = selected->next;

        if (selected == nullptr) {
            cout << "Invalid device number!\n";
            pcap_freealldevs(allDevs);
            return false;
        }

        // Open it for capturing
        // 65536 = max packet size, 1 = promiscuous mode, 1000 = timeout ms
        handle = pcap_open_live(selected->name, 65536, 1, 1000, errBuf);

        if (handle == nullptr) {
            cout << "Could not open device: " << errBuf << "\n";
            cout << "TIP: Run Visual Studio as Administrator!\n";
            pcap_freealldevs(allDevs);
            return false;
        }

        cout << "Opened: " << selected->name << "\n";
        pcap_freealldevs(allDevs);
        return true;
    }

    // ── Step 3: Capture packets live ──
    void startCapture(int howMany) {
        if (handle == nullptr) {
            cout << "No device opened!\n";
            return;
        }

        cout << "\nCapturing " << howMany << " packets...\n";
        cout << "Press Ctrl+C to stop early.\n\n";

        struct pcap_pkthdr* header;
        const unsigned char* pktData;
        int result;
        int count = 0;

        while (count < howMany) {
            result = pcap_next_ex(handle, &header, &pktData);

            if (result == 0) continue;      // Timeout — try again
            if (result == -1) break;         // Error — stop
            if (result == -2) break;         // EOF — stop

            // Parse the raw packet bytes
            Packet* p = parsePacket(pktData, header->len);

            if (p != nullptr) {
                p->display();               // Show on screen
                captured.push_back(p);     // Save in list
                count++;
                cout << "[" << count << "/" << howMany << " captured]\n";
            }
        }

        cout << "\nCapture complete. Total: " << count << " packets\n";
    }

    // ── Step 4: Parse raw bytes into TCP/UDP packet objects ──
    Packet* parsePacket(const unsigned char* rawData, int totalLen) {

        // Skip Ethernet header (14 bytes)
        if (totalLen < 14) return nullptr;
        EthernetHeader* eth = (EthernetHeader*)rawData;

        // Check if it's an IP packet (type 0x0800)
        if (ntohs(eth->type) != 0x0800) return nullptr;

        // Read IP header
        IPHeader* ip = (IPHeader*)(rawData + 14);
        int ipHeaderLen = (ip->verLen & 0x0F) * 4;

        string srcIP = ipToString(ip->srcIP);
        string dstIP = ipToString(ip->destIP);
        int    pktSz = ntohs(ip->totalLen);

        // ── TCP Packet ──
        if (ip->protocol == 6) {
            TCPHeader* tcp = (TCPHeader*)(rawData + 14 + ipHeaderLen);

            int srcPort = ntohs(tcp->srcPort);
            int dstPort = ntohs(tcp->destPort);

            // Extract flags
            bool syn = (tcp->flags & 0x02) != 0;
            bool ack = (tcp->flags & 0x10) != 0;
            bool fin = (tcp->flags & 0x01) != 0;

            // Extract payload data
            int tcpHeaderLen = ((tcp->dataOffset >> 4) & 0xF) * 4;
            const unsigned char* payload = rawData + 14 + ipHeaderLen + tcpHeaderLen;
            int payloadLen = totalLen - 14 - ipHeaderLen - tcpHeaderLen;

            string dataStr = "";
            if (payloadLen > 0)
                dataStr = bytesToString(payload, payloadLen);

            return new TCPPacket(srcIP, dstIP, srcPort, dstPort,
                dataStr, pktSz, syn, ack, fin);
        }

        // ── UDP Packet ──
        else if (ip->protocol == 17) {
            UDPHeader* udp = (UDPHeader*)(rawData + 14 + ipHeaderLen);

            int srcPort = ntohs(udp->srcPort);
            int dstPort = ntohs(udp->destPort);
            int chksum = ntohs(udp->checksum);

            // Extract payload
            const unsigned char* payload = rawData + 14 + ipHeaderLen + 8;
            int payloadLen = totalLen - 14 - ipHeaderLen - 8;

            string dataStr = "";
            if (payloadLen > 0)
                dataStr = bytesToString(payload, payloadLen);

            return new UDPPacket(srcIP, dstIP, srcPort, dstPort,
                dataStr, pktSz, chksum);
        }

        return nullptr;  // Not TCP/UDP — skip
    }

    // ── Filter captured packets ──
    void filterByIP(string ip) {
        filter.setIP(ip);
        vector<Packet*> result = filter.applyFilter(captured);
        cout << "\n=== Filter Results: " << result.size() << " packets ===\n";
        for (int i = 0; i < result.size(); i++)
            result[i]->display();
        filter.clearFilter();
    }

    void filterByPort(int port) {
        filter.setPort(port);
        vector<Packet*> result = filter.applyFilter(captured);
        cout << "\n=== Filter Results: " << result.size() << " packets ===\n";
        for (int i = 0; i < result.size(); i++)
            result[i]->display();
        filter.clearFilter();
    }

    // ── Save to file ──
    void saveToFile() {
        logger.saveAll(captured);
        cout << "All packets saved to log.txt\n";
    }

    // ── Stats ──
    void showStats() {
        int tcp = 0, udp = 0, invalid = 0;
        for (int i = 0; i < captured.size(); i++) {
            if (captured[i]->getProtocol() == "TCP") tcp++;
            else udp++;
            if (!captured[i]->isValid()) invalid++;
        }
        cout << "\n=== Statistics ===\n";
        cout << "Total   : " << captured.size() << "\n";
        cout << "TCP     : " << tcp << "\n";
        cout << "UDP     : " << udp << "\n";
        cout << "Invalid : " << invalid << "\n";
    }

    int getCapturedCount() { return (int)captured.size(); }
};