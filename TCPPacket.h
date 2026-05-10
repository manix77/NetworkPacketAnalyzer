#pragma once
#include "Packet.h"

class TCPPacket : public Packet {
private:
    bool synFlag;
    bool ackFlag;
    bool finFlag;

public:
    // size parameter add kiya
    TCPPacket(string sIP, string dIP, int sPort, int dPort,
        string d, int size, bool syn, bool ack, bool fin)
        : Packet(sIP, dIP, sPort, dPort, d, size)
    {
        synFlag = syn;
        ackFlag = ack;
        finFlag = fin;
    }

    string getProtocol() { return "TCP"; }

    bool isValid() {
        if (sourceIP.empty() || destIP.empty()) return false;
        if (sourcePort < 0 || sourcePort > 65535) return false;
        if (destPort < 0 || destPort   > 65535) return false;
        return true;
    }

    void display() {
        cout << "\n--- TCP Packet ---\n";
        cout << "Source  : " << sourceIP << " : " << sourcePort << "\n";
        cout << "Dest    : " << destIP << " : " << destPort << "\n";
        cout << "Size    : " << packetSize << " bytes\n";
        cout << "Data    : " << data << "\n";
        cout << "Flags   : ";
        if (synFlag) cout << "[SYN] ";
        if (ackFlag) cout << "[ACK] ";
        if (finFlag) cout << "[FIN] ";
        cout << "\n";
        cout << "Valid   : " << (isValid() ? "YES" : "NO") << "\n";
    }
};