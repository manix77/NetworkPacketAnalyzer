#pragma once
#include "Packet.h"

class UDPPacket : public Packet {
private:
    int checksum;

public:
    // size parameter add kiya
    UDPPacket(string sIP, string dIP, int sPort, int dPort,
        string d, int size, int chk)
        : Packet(sIP, dIP, sPort, dPort, d, size)
    {
        checksum = chk;
    }

    string getProtocol() { return "UDP"; }

    bool isValid() {
        if (sourceIP.empty() || destIP.empty()) return false;
        if (sourcePort < 0 || sourcePort > 65535) return false;
        if (destPort < 0 || destPort   > 65535) return false;
        if (checksum < 0) return false;
        return true;
    }

    void display() {
        cout << "\n--- UDP Packet ---\n";
        cout << "Source   : " << sourceIP << " : " << sourcePort << "\n";
        cout << "Dest     : " << destIP << " : " << destPort << "\n";
        cout << "Size     : " << packetSize << " bytes\n";
        cout << "Data     : " << data << "\n";
        cout << "Checksum : " << checksum << "\n";
        cout << "Valid    : " << (isValid() ? "YES" : "NO") << "\n";
    }
};