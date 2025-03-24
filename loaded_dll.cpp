// Tracks and logs all DLLs loaded by running processes using Windows API.
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <fstream>

#pragma comment(lib, "psapi.lib")
using namespace std;

void LogDllsForProcess(DWORD processID, std::ofstream& logFile) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
    if (hProcess == NULL) return;

    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        logFile << "Process ID: " << processID << "\n";
        for (int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            char dllPath[MAX_PATH];
            if (GetModuleFileNameExA(hProcess, hMods[i], dllPath, sizeof(dllPath))) {
                logFile << "   " << dllPath << "\n";
            }
        }
    }

    CloseHandle(hProcess);
}

void EnumerateProcesses() {
    DWORD processes[1024], cbNeeded;
    if (!EnumProcesses(processes, sizeof(processes), &cbNeeded)) return;

    int numProcesses = cbNeeded / sizeof(DWORD);
    ofstream logFile("dll_log.txt", ios::out);

    for (int i = 0; i < numProcesses; i++) {
        if (processes[i] != 0) {
            LogDllsForProcess(processes[i], logFile);
        }
    }

    logFile.close();
    cout << "DLL Injection Tracker Log saved in dll_log.txt\n";
}

int main() {
    cout << "Tracking DLL injections...\n";
    EnumerateProcesses();
    return 0;
}
