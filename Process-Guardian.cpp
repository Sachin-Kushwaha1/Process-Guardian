#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <map>
#include <set>
#include <string>

const std::set<std::string> WHITELIST = {
    "System", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe", "svchost.exe", "explorer.exe",
    "taskmgr.exe", "dwm.exe", "firefox.exe", "chrome.exe", "brave.exe"};

class ProcessMonitor
{
private:
    std::map<std::string, int> processInstances;

    std::string ConvertProcessName(const TCHAR *exeName)
    {
#ifdef UNICODE
        std::wstring ws(exeName);
        return std::string(ws.begin(), ws.end());
#else
        return std::string(exeName);
#endif
    }

    bool isWhitelisted(const std::string &processName)
    {
        return WHITELIST.find(processName) != WHITELIST.end();
    }

    void TerminateProcesses(const std::string &processName)
    {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE)
        {
            std::cerr << "Failed to take process snapshot.\n";
            return;
        }

        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(hSnapshot, &pe32))
        {
            do
            {
                if (ConvertProcessName(pe32.szExeFile) == processName)
                {
                    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);
                    if (hProcess)
                    {
                        if (TerminateProcess(hProcess, 1))
                        {
                            std::cout << "Terminated process: " << processName
                                      << " (PID: " << pe32.th32ProcessID << ").\n";
                        }
                        else
                        {
                            std::cerr << "Failed to terminate process: " << processName
                                      << " (PID: " << pe32.th32ProcessID << ").\n";
                        }
                        CloseHandle(hProcess);
                    }
                }
            } while (Process32Next(hSnapshot, &pe32));
        }

        CloseHandle(hSnapshot);
    }

public:
    void ScanProcesses()
    {
        processInstances.clear();
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE)
        {
            std::cerr << "Failed to take process snapshot.\n";
            return;
        }

        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        std::cout << "Scanning Processes...\n";

        if (Process32First(hSnapshot, &pe32))
        {
            do
            {
                std::string procName = ConvertProcessName(pe32.szExeFile);
                processInstances[procName]++;

                if (processInstances[procName] > 50 && !isWhitelisted(procName))
                {
                    std::cout << "Alert! Process " << procName
                              << " exceeded instance limit. Terminating...\n";
                    TerminateProcesses(procName);
                }
            } while (Process32Next(hSnapshot, &pe32));
        }

        CloseHandle(hSnapshot);
    }

    void StartMonitoring(unsigned int intervalMs = 1000)
    {
        while (true)
        {
            ScanProcesses();
            Sleep(intervalMs);
        }
    }
};

int main()
{
    ProcessMonitor monitor;
    monitor.StartMonitoring(); // You can also pass custom interval
    return 0;
}
