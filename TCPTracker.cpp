
//logs active tcp connections for each process id using GetExtendedTcpTable and few other windows API.


#include <winsock2.h>
#include <ws2tcpip.h> 
#include <iphlpapi.h>
#include <iostream>
#include <fstream>
#include <map>
#include <vector>
#include <string>
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>


#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

using namespace std;

struct ConnectionInfo {
    string localAddr;
    string remoteAddr;
    DWORD pid;
};

// Convert wchar_t* to std::string
string WideStringToString(const wstring& wstr) {
    int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, NULL, 0, NULL, NULL);
    string str(sizeNeeded - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &str[0], sizeNeeded, NULL, NULL);
    return str;
}

// Get process name from PID
string GetProcessName(DWORD pid) {
    wchar_t processName[MAX_PATH] = L"<Unknown>";
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);

    if (hProcess) {
        HMODULE hMod;
        DWORD cbNeeded;
        if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
            GetModuleBaseNameW(hProcess, hMod, processName, MAX_PATH);
        }
        CloseHandle(hProcess);
    }
    return WideStringToString(processName);
}

// Convert DWORD IP address to string
string ConvertIP(DWORD ip) {
    struct in_addr addr;
    addr.S_un.S_addr = ip;
    char ipStr[INET_ADDRSTRLEN] = { 0 };
    InetNtopA(AF_INET, &addr, ipStr, INET_ADDRSTRLEN);
    return string(ipStr);
}

void LogConnections() {
    PMIB_TCPTABLE_OWNER_PID tcpTable;
    DWORD size = 0;

    if (GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == ERROR_INSUFFICIENT_BUFFER) {
        tcpTable = (MIB_TCPTABLE_OWNER_PID*)malloc(size);
        if (GetExtendedTcpTable(tcpTable, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
            map<DWORD, vector<ConnectionInfo>> processConnections;

            for (DWORD i = 0; i < tcpTable->dwNumEntries; i++) {
                MIB_TCPROW_OWNER_PID row = tcpTable->table[i];
                ConnectionInfo conn = { ConvertIP(row.dwLocalAddr), ConvertIP(row.dwRemoteAddr), row.dwOwningPid };
                processConnections[row.dwOwningPid].push_back(conn);
            }

            free(tcpTable);

            // Write to file
            ofstream logFile("connections.txt");
            if (logFile.is_open()) {
                for (const auto& entry : processConnections) {
                    DWORD pid = entry.first;
                    string processName = GetProcessName(pid);

                    logFile << "PID: " << pid << " | Process: " << processName << "\n";
                    logFile << "-------------------------------------\n";

                    for (const auto& conn : entry.second) {
                        logFile << "Local: " << conn.localAddr << " -> Remote: " << conn.remoteAddr << "\n";
                    }
                    logFile << "\n";
                }
                logFile.close();
                cout << "Connections logged to connections.txt\n";
            }
        }
    }
}

int main() {
    LogConnections();
    return 0;
}
