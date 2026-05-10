#pragma once
#include "Packet.h"
#include <fstream>
#include <vector>

class PacketLogger {
private:
    ofstream logFile;  // File object

public:
    // Constructor — file kholo
    PacketLogger() {
        logFile.open("log.txt");
        cout << "Logger ready — log.txt mein save hoga\n";
    }

    // Destructor — file band karo
    ~PacketLogger() {
        logFile.close();
    }

    // Ek packet file mein likhna
    void savePacket(Packet* p) {
        logFile << "Protocol : " << p->getProtocol() << "\n";
        logFile << "Source   : " << p->getSourceIP()
            << ":" << p->getSourcePort() << "\n";
        logFile << "Dest     : " << p->getDestIP()
            << ":" << p->getDestPort() << "\n";
        logFile << "Valid    : " << (p->isValid() ? "YES" : "NO") << "\n";
        logFile << "---\n";
        cout << "Packet logged!\n";
    }

    // Saari packets save karo
    void saveAll(vector<Packet*> packets) {
        for (int i = 0; i < packets.size(); i++) {
            savePacket(packets[i]);
        }
    }
};