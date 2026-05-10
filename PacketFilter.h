#pragma once
#include "Packet.h"
#include <vector>

class PacketFilter {
private:
    string filterIP;   // Jis IP ko dhundhna hai
    int filterPort;    // Jis port ko dhundhna hai

public:
    // Shuru mein koi filter nahi
    PacketFilter() {
        filterIP = "";
        filterPort = -1;
    }

    void setIP(string ip) {
        filterIP = ip;
        cout << "Filter set — IP: " << ip << "\n";
    }

    void setPort(int port) {
        filterPort = port;
        cout << "Filter set — Port: " << port << "\n";
    }

    void clearFilter() {
        filterIP = "";
        filterPort = -1;
        cout << "Filters cleared!\n";
    }

    // Check karo — ye packet filter se match karta hai?
    bool check(Packet* p) {
        // IP filter laga hua hai
        if (filterIP != "") {
            if (p->getSourceIP() != filterIP &&
                p->getDestIP() != filterIP)
                return false; // Match nahi hua
        }
        // Port filter laga hua hai
        if (filterPort != -1) {
            if (p->getSourcePort() != filterPort &&
                p->getDestPort() != filterPort)
                return false;
        }
        return true; // Sab theek — packet pass!
    }

    // Poori list mein se filter karo
    vector<Packet*> applyFilter(vector<Packet*> packets) {
        vector<Packet*> result;
        for (int i = 0; i < packets.size(); i++) {
            if (check(packets[i]))
                result.push_back(packets[i]);
        }
        return result;
    }
};