#include <iostream>
#include "RealCapture.h"
using namespace std;

int main() {

    cout << "======================================\n";
    cout << "   Real Network Packet Analyzer\n";
    cout << "   Abdul Manan Abbasi\n";
    cout << "======================================\n\n";

    cout << "IMPORTANT: Make sure Visual Studio is\n";
    cout << "running as Administrator!\n\n";

    RealCapture analyzer;

    // Step 1: Show available network interfaces
    if (!analyzer.listDevices()) {
        cout << "Npcap not found! Install Npcap first.\n";
        return 1;
    }

    // Step 2: User selects interface
    int deviceNum;
    cout << "\nEnter interface number to capture from: ";
    cin >> deviceNum;

    if (!analyzer.openDevice(deviceNum)) {
        return 1;
    }

    // Step 3: How many packets to capture
    int howMany;
    cout << "How many packets to capture? ";
    cin >> howMany;

    // Step 4: Start capture
    analyzer.startCapture(howMany);

    // Step 5: Menu for analysis
    int choice;
    do {
        cout << "\n--------- MENU ---------\n";
        cout << "1. Show Statistics\n";
        cout << "2. Filter by IP Address\n";
        cout << "3. Filter by Port Number\n";
        cout << "4. Save All to File\n";
        cout << "5. Capture More Packets\n";
        cout << "0. Exit\n";
        cout << "Enter your choice: ";
        cin >> choice;

        if (choice == 1) {
            analyzer.showStats();
        }
        else if (choice == 2) {
            string ip;
            cout << "Enter IP address to filter: ";
            cin >> ip;
            analyzer.filterByIP(ip);
        }
        else if (choice == 3) {
            int port;
            cout << "Enter port number: ";
            cin >> port;
            analyzer.filterByPort(port);
        }
        else if (choice == 4) {
            analyzer.saveToFile();
        }
        else if (choice == 5) {
            int more;
            cout << "How many more packets? ";
            cin >> more;
            analyzer.startCapture(more);
        }
        else if (choice == 0) {
            cout << "Exiting. Goodbye!\n";
        }
        else {
            cout << "Invalid choice!\n";
        }

    } while (choice != 0);

    return 0;
}