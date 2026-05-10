#pragma once
#include <iostream>
#include <string>
using namespace std;

class Packet {
protected:
    string sourceIP;
    string destIP;
    int sourcePort;
    int destPort;
    string data;
    int packetSize;   // ← yeh add kiya

public:
    // 6 arguments wala constructor
    Packet(string sIP, string dIP, int sPort, int dPort,
        string d, int size) {
        sourceIP = sIP;
        destIP = dIP;
        sourcePort = sPort;
        destPort = dPort;
        data = d;
        packetSize = size;   // ← yeh add kiya
    }

    virtual void   display() = 0;
    virtual bool   isValid() = 0;
    virtual string getProtocol() = 0;

    string getSourceIP() { return sourceIP; }
    string getDestIP() { return destIP; }
    int getSourcePort() { return sourcePort; }
    int getDestPort() { return destPort; }
    int getSize() { return packetSize; }

    virtual ~Packet() {}
};