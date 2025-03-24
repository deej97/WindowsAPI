#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <tchar.h>
#include <psapi.h>
#include <iostream>
#include <fstream>
#include <map>
#include <vector>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

void LogSynSentConnections(const std::string& filename) {
    PMIB_TCPTABLE_OWNER_PID pTcpTable;
    DWORD dwSize = 0;
    DWORD dwRetVal;

    // Get the required buffer size
    GetExtendedTcpTable(nullptr, &dwSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    pTcpTable = (PMIB_TCPTABLE_OWNER_PID)malloc(dwSize);

    if (pTcpTable == nullptr) {
        std::cerr << "Error allocating memory" << std::endl;
        return;
    }

    // Retrieve TCP connection table
    if ((dwRetVal = GetExtendedTcpTable(pTcpTable, &dwSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)) == NO_ERROR) {
        std::ofstream outFile(filename);
        if (!outFile) {
            std::cerr << "Error opening log file" << std::endl;
            free(pTcpTable);
            return;
        }

        outFile << "PID\tProcess Name\tLocal Address\tLocal Port\tRemote Address\tRemote Port\n";

        for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++) {
            MIB_TCPROW_OWNER_PID row = pTcpTable->table[i];

            // Filter only SYN-SENT connections
            if (row.dwState == MIB_TCP_STATE_SYN_SENT) {
                DWORD pid = row.dwOwningPid;
                char processName[MAX_PATH] = "<Unknown>";

                // Open process to get the executable name
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
                if (hProcess) {
                    GetModuleBaseNameA(hProcess, nullptr, processName, MAX_PATH);
                    CloseHandle(hProcess);
                }

                char localAddr[INET_ADDRSTRLEN], remoteAddr[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &row.dwLocalAddr, localAddr, INET_ADDRSTRLEN);
                inet_ntop(AF_INET, &row.dwRemoteAddr, remoteAddr, INET_ADDRSTRLEN);

                outFile << pid << "\t" << processName << "\t"
                    << localAddr << "\t" << ntohs((u_short)row.dwLocalPort) << "\t"
                    << remoteAddr << "\t" << ntohs((u_short)row.dwRemotePort) << "\n";
            }
        }
        outFile.close();
    }
    else {
        std::cerr << "GetExtendedTcpTable failed with error: " << dwRetVal << std::endl;
    }

    free(pTcpTable);
}

int main() {
    LogSynSentConnections("syn_sent_connections.txt");
    std::cout << "SYN-SENT connections logged to syn_sent_connections.txt" << std::endl;
    return 0;
}
